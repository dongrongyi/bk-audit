# -*- coding: utf-8 -*-
"""
TencentBlueKing is pleased to support the open source community by making
蓝鲸智云 - 审计中心 (BlueKing - Audit Center) available.
Copyright (C) 2023 THL A29 Limited,
a Tencent company. All rights reserved.
Licensed under the MIT License (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://opensource.org/licenses/MIT
Unless required applicable law or agreed to in writing,
software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
We undertake not to change the open source license (MIT license) applicable
to the current version of the project delivered to anyone in the future.
"""

import logging
from typing import List, Optional, Tuple

from django.conf import settings
from django.utils.translation import gettext_lazy
from rest_framework import serializers

from apps.feature.handlers import FeatureHandler
from services.web.risk.bksec.config import BkSecConfig
from services.web.risk.bksec.constants import BKSEC_FIELD_INITIAL_OWNER
from services.web.risk.bksec.contract import build_event_payload, build_plugin_constants
from services.web.risk.bksec.variables import build_risk_data
from services.web.risk.channels.base import ChannelRegistry, TicketChannel
from services.web.risk.models import Risk, TicketNode

logger = logging.getLogger("celery")


class BkSecChannel(TicketChannel):
    """
    BKSEC 安全工单下发通道

    承接原 preview_bk_sec_ticket / send_bk_sec_test_ticket / get_bk_sec_test_task_status
    中 BKSEC 专属的逻辑：配置解析、报文渲染、回调隔离守卫、预置套餐模板、失败特征翻译。
    """

    channel_type = "bk_sec"

    @staticmethod
    def _ensure_enabled() -> None:
        """
        后端 feature 硬拦截：BKSEC 未启用（开关关 / 必配环境变量缺失 / 内置套餐未就绪）时，
        阻断一切配置解析、预览、测试发送，防止前端隐藏后仍被 API 直接调用。
        """
        if not FeatureHandler("bksec").check():
            raise serializers.ValidationError(gettext_lazy("BKSEC 功能未启用或环境未就绪（请确认必配环境变量与内置发单套餐）"))

    def parse_config(self, channel_config: dict) -> BkSecConfig:
        self._ensure_enabled()
        try:
            return BkSecConfig.model_validate(channel_config)
        except ValueError as err:
            raise serializers.ValidationError(gettext_lazy("BKSEC 配置不合法：%s") % err)

    def render_preview(self, channel_config: dict, risk: Optional[Risk]) -> dict:
        config = self.parse_config(channel_config)
        # 样例风险单存在性由 resources 层（PreviewTicket.perform_request）统一校验，此处不再重复查询（P6）
        try:
            payload = build_event_payload(config, risk=risk)
        except Exception as err:  # NOCC:broad-except(预览即时报错，区别于正式发送的失败重试链路)
            raise serializers.ValidationError(gettext_lazy("字段模板渲染失败，请检查变量语法：%s") % err)
        risk_data = build_risk_data(risk)
        warnings = []
        if risk is not None and not (payload.get("fields", {}).get(BKSEC_FIELD_INITIAL_OWNER) or "").strip():
            warnings.append(gettext_lazy("初始责任人为空（该风险单无责任人且未配置安全接口人兜底），工单可能被 BKSEC 拒收，" "请到系统配置设置安全接口人或调整映射"))
        # 工单头（BKSEC 侧生成，发单前不存在）：后端 mock 占位，仅用于前端预览工单外观，
        # 非审计中心上报内容、不进入真实报文。发单后由 BKSEC 生成真实值。
        ticket_header = self._build_mock_ticket_header(risk, risk_data)
        return {
            "risk_type_id": config.risk_type_id,
            "risk_type_name": config.risk_type_name,
            "has_sample_risk": risk is not None,
            "ticket": payload,
            "ticket_header": ticket_header,
            "risk": risk_data,
            "risk_context_keys": list(risk_data.keys()),
            "warnings": warnings,
        }

    @staticmethod
    def _build_mock_ticket_header(risk: Optional[Risk], risk_data: dict) -> dict:
        """
        后端 mock 的 BKSEC 工单头占位（发单前这些字段尚不存在，由 BKSEC 侧生成）。

        仅取审计中心已有的 risk 真实数据做尽量贴近的占位；纯 BKSEC 产物（工单ID/状态/截止时间/
        责任人组织）用明确标注的占位文案，避免前端误以为这是真实上报值。
        """
        risk_id = getattr(risk, "risk_id", "") or ""
        return {
            "ticket_id": "MOCK-{}".format(risk_id),  # 占位：BKSEC 创建工单后生成真实ID
            "title": gettext_lazy("{}（安全工单）").format(risk_data.get("title", "")),  # 占位：BKSEC 按类型+risk_id 生成
            "submit_time": risk_data.get("event_time", ""),  # 近似：以风险首次发现时间占位
            "deadline": gettext_lazy("由 BKSEC 按 SLA 生成（预览占位）"),  # 占位：BKSEC 侧 SLA 计算
            "status": gettext_lazy("待 BKSEC 受理"),  # 占位：BKSEC 工单状态机初始态
            "current_operator_org": gettext_lazy("由 BKSEC 按责任人解析（预览占位）"),  # 占位：BKSEC 按责任人解析组织
        }

    def sync_test_config(self, channel_config: dict, risk: Risk) -> None:
        """
        测试发送前置：仅做「入参可提交性」校验，不再回写插件侧 Config。

        原实现会以样例风险单的 strategy_id 调 `sync_plugin_config` 落库到插件 Config 表。
        由于插件侧 `Config.update_or_create(strategy_id=...)` 幂等语义会直接覆盖同 strategy_id 的
        正式 Config——用户在策略编辑页修改配置后（未保存）点"发送测试工单"，会静默污染该策略
        的正式发单配置，此后正式发单会一直使用未保存的测试草稿，直至下次策略保存才恢复。

        产品语义（文档 5. failure_hint）明确"插件侧未配置该策略的发单配置（Config 表）"是允许
        的失败态，前端由轮询侧给出「先保存策略再测试」的处置指引，无需在测试路径写库。
        因此这里去除任何持久化副作用，只做本地合法性校验。
        """
        config = self.parse_config(channel_config)
        try:
            config.validate_for_submit()
        except ValueError as err:
            raise serializers.ValidationError(gettext_lazy("BKSEC 配置不合法：%s") % err)
        if not risk.strategy_id:
            raise serializers.ValidationError(gettext_lazy("样例风险单未关联策略（strategy_id 为空），请选择已绑定策略的风险单进行测试"))

    def render_test_constants(self, channel_config: dict, risk: Risk, test_receivers: List[str]) -> dict:
        config = self.parse_config(channel_config)
        try:
            config.validate_for_submit()
        except ValueError as err:
            raise serializers.ValidationError(gettext_lazy("BKSEC 配置不合法：%s") % err)
        # 测试接收人：BKSEC 当前仅取首个作为测试处理人（契约兼容单值 operator）
        test_operator = test_receivers[0] if test_receivers else ""
        try:
            return build_plugin_constants(config, risk=risk, test_operator=test_operator)
        except Exception as err:  # NOCC:broad-except(测试发送即时报错，便于定位配置问题)
            raise serializers.ValidationError(gettext_lazy("字段模板渲染失败，请检查变量语法：%s") % err)

    def validate_test_target(self, risk: Risk) -> None:
        # 回调隔离守卫（插件源码实证 2026-09-23）：插件 Callback 表按 risk_id 查找复用——
        # ① 风险存在进行中的正式派单 → 测试会复用其回调，测试工单办结会误触发正式节点完成；
        # ② 风险存在已完成的正式派单（Callback.is_finished）→ 测试被插件静默拦截（任务成功但未发单）。
        # 故该风险存在任何 AutoProcess 正式派单历史时拒绝测试发送，引导换一张风险单
        if TicketNode.objects.filter(risk_id=risk.risk_id, action="AutoProcess", is_test=False).exists():
            raise serializers.ValidationError(
                gettext_lazy("该风险单已有正式派单记录：插件的回调按风险单复用，在其上发送测试工单" "会干扰正式回调或被静默拦截，请选择一张未发送过正式工单的风险单进行测试")
            )

    def get_preset_pa_template_id(self) -> Optional[str]:
        return getattr(settings, "BKSEC_SOPS_TEMPLATE_ID", None) or None

    def resolve_failure_hints(self) -> List[Tuple[str, str]]:
        # 已知插件错误特征 → 处置指引（联调实证 2026-09-23）
        return [
            (
                "Config matching query does not exist",
                gettext_lazy("插件侧未配置该策略的发单配置（Config 表），请在插件 Admin 为对应 strategy_id 添加后重试"),
            ),
            (
                "业务或执行人校验失败",
                gettext_lazy("插件白名单未放行：请检查插件环境变量 BKAPP_EXECUTOR / BKAPP_BK_BIZ_ID"),
            ),
            (
                "Expecting value",
                gettext_lazy("插件参数格式错误：operator 须为 JSON 数组串、event_type/event_data/event_evidence 须为合法 JSON"),
            ),
        ]


# 模块导入即登记到注册表
ChannelRegistry.register(BkSecChannel())
