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

import datetime
import json
import logging
from typing import Any, List, Optional

from django.conf import settings
from django.utils import timezone
from django.utils.translation import gettext_lazy

from apps.meta.models import GlobalMetaConfig
from apps.meta.utils.saas import get_saas_url
from services.web.risk.bksec.constants import BKSEC_RENDER_EVENT_LIMIT
from services.web.risk.constants import SECURITY_PERSON_KEY
from services.web.risk.models import Risk

logger = logging.getLogger("celery")

TIME_DISPLAY_FORMAT = "%Y-%m-%d %H:%M:%S"


def display_value(value: Any) -> str:
    """
    渲染为字符串：列表用分号拼接、字典转 JSON、时间格式化
    """
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        if isinstance(value, list) and not any(isinstance(v, (dict, list)) for v in value):
            return ";".join(display_value(v) for v in value)
        return json.dumps(value, ensure_ascii=False, default=str)
    if isinstance(value, datetime.datetime):
        return value.astimezone(tz=timezone.get_default_timezone()).strftime(TIME_DISPLAY_FORMAT)
    return str(value)


class EventFieldValues(list):
    """
    事件字段跨事件取值列表

    直接渲染时取最后一条事件的值（与事件调查报告语义一致），
    作为聚合函数入参时是完整取值列表。
    """

    def __str__(self) -> str:
        return display_value(self[-1]) if self else ""


class EventNamespace:
    """
    事件命名空间：{{ event.字段 }} 或 {{ 聚合函数(event.字段) }}

    - 直接取（{{ event.username }}）：默认渲染最后一条事件的值（与事件调查报告语义一致）
    - 聚合（{{ count(event.event_id) }} 等）：对关联的全部事件统计，见 AGGREGATION_FUNCTIONS
    """

    def __init__(self, events: List[dict]):
        object.__setattr__(self, "_events", events or [])

    def __getattr__(self, name: str) -> EventFieldValues:
        events = object.__getattribute__(self, "_events")
        return EventFieldValues(display_value(ev.get(name, "")) for ev in events)


class RiskNamespace:
    """
    风险命名空间：{{ risk.xxx }}，未定义字段渲染为空串
    """

    def __init__(self, data: dict):
        object.__setattr__(self, "_data", data or {})

    def __getattr__(self, name: str) -> Any:
        data = object.__getattribute__(self, "_data")
        return data.get(name, "")


def _numeric(values: EventFieldValues) -> List[float]:
    result = []
    for v in values:
        try:
            result.append(float(v))
        except (TypeError, ValueError):
            continue
    return result


# 聚合函数实现（语法与事件调查报告一致：{{ count(event.xxx) }}）
AGGREGATION_FUNCTIONS = {
    "first": lambda v: display_value(v[0]) if v else "",
    "latest": lambda v: display_value(v[-1]) if v else "",
    "count": lambda v: len(v),
    "count_distinct": lambda v: len({str(i) for i in v}),
    "list": lambda v: ";".join(display_value(i) for i in v),
    "list_distinct": lambda v: ";".join(display_value(i) for i in dict.fromkeys(str(i) for i in v)),
    "sum": lambda v: sum(_numeric(v)) if _numeric(v) else "",
    "avg": lambda v: (lambda nums: sum(nums) / len(nums))(_numeric(v)) if _numeric(v) else "",
    "max": lambda v: max(_numeric(v)) if _numeric(v) else "",
    "min": lambda v: min(_numeric(v)) if _numeric(v) else "",
}


def load_security_person() -> List[str]:
    """
    安全接口人（无责任人风险的发单兜底，决策 D4）
    """
    persons = GlobalMetaConfig.get(config_key=SECURITY_PERSON_KEY) or []
    return [p for p in persons if p]


def load_risk_events(risk: Risk, limit: int = BKSEC_RENDER_EVENT_LIMIT) -> List[dict]:
    """
    加载风险关联事件（用于事件变量渲染），查询失败时降级为空列表
    """
    try:
        from services.web.risk.handlers.event import EventHandler

        strategy = getattr(risk, "strategy", None)
        namespace = getattr(strategy, "namespace", "") if strategy else ""
        if not namespace:
            return []
        start_time = risk.event_time.strftime(TIME_DISPLAY_FORMAT)
        end_time = (risk.event_end_time or timezone.now()).strftime(TIME_DISPLAY_FORMAT)
        response = EventHandler.search_event(
            namespace=namespace,
            start_time=start_time,
            end_time=end_time,
            page=1,
            page_size=limit,
            raw_event_id=risk.raw_event_id,
            strategy_id=str(risk.strategy_id),
        )
        events = response.get("list", []) if isinstance(response, dict) else []
        # 事件按时间升序，保证 latest/默认取值语义正确
        return sorted(events, key=lambda ev: str(ev.get("event_time", "")))
    except Exception as err:  # NOCC:broad-except(渲染降级)
        logger.exception("[BkSecRender] Load events failed, risk_id=%s err=%s", getattr(risk, "risk_id", ""), err)
        return []


# 风险变量展示元数据（单一事实源）：
# key 集合必须与 build_risk_data 的输出键严格一致（由测试 TestRiskVariableMetaSync 校验），
# 防止渲染引擎使用的变量与可用变量清单漂移。
RISK_VARIABLE_META = {
    "risk_id": (gettext_lazy("风险ID"), "R-20260101-0001"),
    "title": (gettext_lazy("风险标题"), "异常登录风险"),
    "event_content": (gettext_lazy("风险描述"), "检测到异常登录行为"),
    "risk_level": (gettext_lazy("风险等级"), "high"),
    "risk_hazard": (gettext_lazy("风险危害"), "可能导致数据泄露"),
    "risk_guidance": (gettext_lazy("处理指引"), "请及时修改密码"),
    "risk_tags": (gettext_lazy("风险标签"), "高危"),
    "risk_label": (gettext_lazy("风险标记"), "normal"),
    "status": (gettext_lazy("处理状态"), "NEW"),
    "rule_id": (gettext_lazy("处理规则"), "100"),
    "strategy_id": (gettext_lazy("策略ID"), "1001"),
    "strategy_name": (gettext_lazy("策略名称"), "离线策略审计"),
    "strategy_rule_id": (gettext_lazy("发现规则ID"), "200"),
    "raw_event_id": (gettext_lazy("原始事件ID"), "evt-001"),
    "origin_operator": (gettext_lazy("原始责任人"), "admin"),
    "operator": (gettext_lazy("责任人"), "admin"),
    "current_operator": (gettext_lazy("当前处理人"), "admin"),
    "notice_users": (gettext_lazy("关注人"), "follower"),
    "event_type": (gettext_lazy("风险类型"), "账号安全"),
    "event_source": (gettext_lazy("风险数据源"), "bkm"),
    "event_time": (gettext_lazy("首次发现时间"), "2026-01-01 00:00:00"),
    "event_end_time": (gettext_lazy("最后发现时间"), "2026-01-01 00:10:00"),
    "last_operate_time": (gettext_lazy("最后一次处理时间"), "2026-01-02 00:00:00"),
    "security_person": (gettext_lazy("安全接口人"), "sec_admin"),
    "risk_url": (gettext_lazy("风险单链接"), "https://audit.example.com/risk-manage/detail/R-001"),
}


def build_risk_data(risk: Optional[Risk]) -> dict:
    """
    构建风险变量数据（risk.*，键集合以 RISK_VARIABLE_META 为准）
    """
    if risk is None:
        return {}
    strategy = getattr(risk, "strategy", None)
    return {
        "risk_id": risk.risk_id,
        "title": risk.title or "",
        "event_content": risk.event_content or "",
        "raw_event_id": risk.raw_event_id or "",
        "strategy_id": risk.strategy_id,
        "strategy_name": getattr(strategy, "strategy_name", "") if strategy else "",
        "strategy_rule_id": getattr(risk, "strategy_rule_id", "") or "",
        "risk_level": risk.risk_level or "",
        "risk_hazard": risk.risk_hazard or "",
        "risk_guidance": risk.risk_guidance or "",
        "risk_tags": display_value(risk.get_tag_names()) if hasattr(risk, "get_tag_names") else "",
        "status": risk.status or "",
        "risk_label": risk.risk_label or "",
        "rule_id": risk.rule_id or "",
        "operator": display_value(risk.operator),
        "current_operator": display_value(risk.current_operator),
        "notice_users": display_value(risk.notice_users),
        "origin_operator": display_value(risk.origin_operator),
        "event_type": display_value(risk.event_type),
        "event_source": risk.event_source or "",
        "event_time": display_value(risk.event_time),
        "event_end_time": display_value(risk.event_end_time),
        "last_operate_time": display_value(risk.last_operate_time),
        # 无责任人时以安全接口人兜底，模板可写 {{ risk.operator or risk.security_person }}
        "security_person": ";".join(load_security_person()),
        "risk_url": "{}/risk-manage/detail/{}".format(get_saas_url(settings.APP_CODE), risk.risk_id),
    }


def build_render_context(risk: Optional[Risk] = None, events: Optional[List[dict]] = None) -> dict:
    """
    构建 BKSEC 字段渲染上下文：risk / event 命名空间 + 聚合函数

    预览、测试发送、正式发送共用，保证三处渲染结果一致。
    """
    if events is None and risk is not None:
        events = load_risk_events(risk)
    context = {
        "risk": RiskNamespace(build_risk_data(risk)),
        "event": EventNamespace(events or []),
    }
    context.update(AGGREGATION_FUNCTIONS)
    return context
