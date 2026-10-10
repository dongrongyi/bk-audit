# -*- coding: utf-8 -*-
"""
TencentBlueKing is pleased to support the open source community by making
蓝鲸智云 - 审计中心 (BlueKing - Audit Center) available.
Copyright (C) 2023 THL A29 Limited,
a Tencent company. All rights reserved.
Licensed under the MIT License (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://opensource.org/licenses/MIT
Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
We undertake not to change the open source license (MIT license) applicable
to the current version of the project delivered to anyone in the future.
"""

import logging
from typing import List, Optional, Tuple

from django.utils.translation import gettext_lazy
from rest_framework import serializers

from apps.feature.handlers import FeatureHandler
from services.web.risk.bksec.config import BkSecConfig
from services.web.risk.bksec.constants import BKSEC_FIELD_INITIAL_OWNER
from services.web.risk.bksec.contract import build_event_payload, build_plugin_constants
from services.web.risk.bksec.variables import build_risk_data
from services.web.risk.models import Risk, TicketNode
from services.web.strategy_v2.models import Strategy

logger = logging.getLogger("celery")


def ensure_bksec_enabled() -> None:
    """
    后端 feature 硬拦截：BKSEC 未启用（开关关 / 必配环境变量缺失 / 内置套餐未就绪）时，
    阻断一切配置解析、预览、测试发送，防止前端隐藏后仍被 API 直接调用。
    """
    if not FeatureHandler("bksec").check():
        raise serializers.ValidationError(gettext_lazy("BKSEC 功能未启用或环境未就绪（请确认 BKAPP_FEATURE_BKSEC 开关、必配环境变量与内置发单套餐）"))


def parse_bksec_config(config_dict: dict) -> BkSecConfig:
    """解析并校验 BKSEC 配置（启用态硬拦截 + pydantic 解析）。"""
    ensure_bksec_enabled()
    try:
        return BkSecConfig.model_validate(config_dict)
    except ValueError as err:
        raise serializers.ValidationError(gettext_lazy("BKSEC 配置不合法：%s") % err)


def render_bksec_preview(config: BkSecConfig, risk: Optional[Risk]) -> dict:
    """渲染工单预览（按配置 + 样例风险单渲染报文，不实际发送）。"""
    ensure_bksec_enabled()
    try:
        payload = build_event_payload(config, risk=risk)
    except Exception as err:  # NOCC:broad-except(预览即时报错，区别于正式发送的失败重试链路)
        raise serializers.ValidationError(gettext_lazy("字段模板渲染失败，请检查变量语法：%s") % err)
    risk_data = build_risk_data(risk)
    warnings = []
    if risk is not None and not (payload.get("fields", {}).get(BKSEC_FIELD_INITIAL_OWNER) or "").strip():
        warnings.append(gettext_lazy("初始责任人为空（该风险单无责任人且未配置安全接口人兜底），工单可能被 BKSEC 拒收，请到系统配置设置安全接口人或调整映射"))
    # 工单头（BKSEC 侧生成，发单前不存在）：后端 mock 占位，仅用于前端预览工单外观，
    # 非审计中心上报内容、不进入真实报文。发单后由 BKSEC 生成真实值。
    ticket_header = _build_mock_ticket_header(risk, risk_data)
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


def _build_mock_ticket_header(risk: Optional[Risk], risk_data: dict) -> dict:
    """
    后端 mock 的 BKSEC 工单头占位（发单前这些字段尚不存在，由 BKSEC 侧生成）。

    仅取审计中心已有的 risk 真实数据做尽量贴近的占位；纯 BKSEC 产物（工单ID/状态/截止时间/
    责任人组织）用明确标注的占位文案，避免前端误以为这是真实上报值。
    """
    risk_id = getattr(risk, "risk_id", "") or ""
    return {
        "ticket_id": "MOCK-{}".format(risk_id),  # 占位：BKSEC 创建工单后生成真实ID
        "title": "{}（安全工单）".format(risk_data.get("title", "")),  # 占位：BKSEC 按类型+risk_id 生成
        "submit_time": risk_data.get("event_time", ""),  # 近似：以风险首次发现时间占位
        "deadline": "由 BKSEC 按 SLA 生成（预览占位）",  # 占位：BKSEC 侧 SLA 计算
        "status": "待 BKSEC 受理",  # 占位：BKSEC 工单状态机初始态
        "current_operator_org": "由 BKSEC 按责任人解析（预览占位）",  # 占位：BKSEC 按责任人解析组织
    }


def sync_bksec_test_config(strategy: Strategy, config: BkSecConfig) -> None:
    """
    测试发送前置：兜底同步插件侧 Config。

    测试发送直接走 SOPS 真实通道，插件执行阶段才读取其侧 Config（按 strategy_id 复用）。
    若用户未保存策略（或上次保存后改过配置）就直接测试，插件侧可能尚无对应 Config，
    导致任务异步执行时静默失败。故在发送前主动同步一次，确保插件侧 Config 与本次入参一致。

    同步失败（接口不可达 / 插件拒绝）直接阻断测试发送并给出可操作提示，
    而非等到异步执行阶段才暴露。
    """
    try:
        config.validate_for_submit()
    except ValueError as err:
        raise serializers.ValidationError(gettext_lazy("BKSEC 配置不合法：%s") % err)
    from services.web.risk.bksec.rules import sync_plugin_config

    success, message = sync_plugin_config(strategy, config)
    if not success:
        raise serializers.ValidationError(gettext_lazy("测试前插件配置同步失败，无法发送测试工单：%s") % message)


def render_bksec_test_constants(config: BkSecConfig, risk: Risk, test_receivers: List[str]) -> dict:
    """渲染测试发送的插件入参常量。"""
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


def validate_bksec_test_target(risk: Risk) -> None:
    """
    回调隔离守卫（插件源码实证 2026-09-23）：插件 Callback 表按 risk_id 查找复用——
    ① 风险存在进行中的正式派单 → 测试会复用其回调，测试工单办结会误触发正式节点完成；
    ② 风险存在已完成的正式派单（Callback.is_finished）→ 测试被插件静默拦截（任务成功但未发单）。
    故该风险存在任何 AutoProcess 正式派单历史时拒绝测试发送，引导换一张风险单
    """
    if TicketNode.objects.filter(risk_id=risk.risk_id, action="AutoProcess").exists():
        raise serializers.ValidationError(
            gettext_lazy("该风险单已有正式派单记录：插件的回调按风险单复用，在其上发送测试工单会干扰正式回调或被静默拦截，请选择一张未发送过正式工单的风险单进行测试")
        )


def bksec_failure_hints() -> List[Tuple[str, str]]:
    """已知插件错误特征 → 处置指引（联调实证 2026-09-23）。"""
    return [
        ("Config matching query does not exist", "插件侧未配置该策略的发单配置（Config 表），请在插件 Admin 为对应 strategy_id 添加后重试"),
        ("业务或执行人校验失败", "插件白名单未放行：请检查插件环境变量 BKAPP_EXECUTOR / BKAPP_BK_BIZ_ID"),
        ("Expecting value", "插件参数格式错误：operator 须为 JSON 数组串、event_type/event_data/event_evidence 须为合法 JSON"),
    ]
