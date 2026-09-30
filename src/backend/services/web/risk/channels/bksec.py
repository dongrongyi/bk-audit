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

    def parse_config(self, channel_config: dict) -> BkSecConfig:
        try:
            return BkSecConfig.model_validate(channel_config)
        except ValueError as err:
            raise serializers.ValidationError(gettext_lazy("BKSEC 配置不合法：%s") % err)

    def render_preview(self, channel_config: dict, risk: Optional[Risk]) -> dict:
        config = self.parse_config(channel_config)
        risk_id = getattr(risk, "risk_id", None)
        if risk_id:
            risk = Risk.objects.filter(risk_id=risk_id).first()
            if risk is None:
                raise serializers.ValidationError(gettext_lazy("样例风险单不存在：%s") % risk_id)
        try:
            payload = build_event_payload(config, risk=risk)
        except Exception as err:  # NOCC:broad-except(预览即时报错，区别于正式发送的失败重试链路)
            raise serializers.ValidationError(gettext_lazy("字段模板渲染失败，请检查变量语法：%s") % err)
        risk_data = build_risk_data(risk)
        warnings = []
        if risk is not None and not (payload.get("fields", {}).get(BKSEC_FIELD_INITIAL_OWNER) or "").strip():
            warnings.append(gettext_lazy("初始责任人为空（该风险单无责任人且未配置安全接口人兜底），工单可能被 BKSEC 拒收，" "请到系统配置设置安全接口人或调整映射"))
        return {
            "risk_type_id": config.risk_type_id,
            "risk_type_name": config.risk_type_name,
            "has_sample_risk": risk is not None,
            "ticket": payload,
            "risk": risk_data,
            "risk_context_keys": list(risk_data.keys()),
            "warnings": warnings,
        }

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
        if TicketNode.objects.filter(risk_id=risk.risk_id, action="AutoProcess").exists():
            raise serializers.ValidationError(
                gettext_lazy("该风险单已有正式派单记录：插件的回调按风险单复用，在其上发送测试工单" "会干扰正式回调或被静默拦截，请选择一张未发送过正式工单的风险单进行测试")
            )

    def get_preset_pa_template_id(self) -> Optional[str]:
        return getattr(settings, "BKSEC_SOPS_TEMPLATE_ID", None) or None

    def resolve_failure_hints(self) -> List[Tuple[str, str]]:
        # 已知插件错误特征 → 处置指引（联调实证 2026-09-23）
        return [
            ("Config matching query does not exist", "插件侧未配置该策略的发单配置（Config 表），请在插件 Admin 为对应 strategy_id 添加后重试"),
            ("业务或执行人校验失败", "插件白名单未放行：请检查插件环境变量 BKAPP_EXECUTOR / BKAPP_BK_BIZ_ID"),
            ("Expecting value", "插件参数格式错误：operator 须为 JSON 数组串、event_type/event_data/event_evidence 须为合法 JSON"),
        ]


# 模块导入即登记到注册表
ChannelRegistry.register(BkSecChannel())
