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
import re
from typing import List, Optional

from django.utils import timezone

from services.web.risk.bksec.config import BkSecConfig
from services.web.risk.bksec.constants import (
    BKSEC_ACTION_DEFAULT,
    BKSEC_EVENT_FIELD_FIELDS,
    BKSEC_EVENT_FIELD_IS_TEST,
    BKSEC_EVENT_FIELD_RISK_ID,
    BKSEC_EVENT_FIELD_RISK_TYPE,
    BKSEC_EVENT_FIELD_SOURCE,
    BKSEC_EVENT_FIELD_TEST_OPERATOR,
    BKSEC_EVENT_SOURCE_VALUE,
    BKSEC_FIELD_INITIAL_OWNER,
    BKSEC_ONCE_TASK_DEFAULT,
    BKSEC_ONCE_TASK_TEST,
    BKSEC_OPERATOR_TEMPLATE,
    BKSEC_PARAM_ACTION,
    BKSEC_PARAM_EVENT_DATA,
    BKSEC_PARAM_EVENT_TYPE,
    BKSEC_PARAM_ONCE_TASK,
    BKSEC_PARAM_OPERATOR,
    BKSEC_PLUGIN_STANDARD_FIELDS,
)
from services.web.risk.bksec.renderer import render_value
from services.web.risk.bksec.variables import (
    TIME_DISPLAY_FORMAT,
    build_render_context,
    load_security_person,
)
from services.web.risk.models import Risk

logger = logging.getLogger("celery")


def build_event_payload(
    config: BkSecConfig,
    risk: Optional[Risk] = None,
    events: Optional[List[dict]] = None,
    test_operator: str = "",
) -> dict:
    """
    构建上报 BKSEC 的事件体（测试发送 / 预览展示用；正式发送走 SOPS 契约常量）

    结构集中在此处。
    1. risk_access 的 unique_keys 形如 ["extra.ceshi"]，提示 CUSTOM(source_type) 字段
       在事件体中嵌套于 extra 下、COMMON 字段在顶层，届时按 source_type 分组组装；
    2. 当前扁平 fields 结构仅为占位
    """
    context = build_render_context(risk=risk, events=events)
    fields = {}
    for mapping in config.field_mappings:
        if mapping.key:
            fields[mapping.key] = render_value(mapping.value, context)
    # 决策 D4：初始责任人为空时以安全接口人兜底
    if not fields.get(BKSEC_FIELD_INITIAL_OWNER):
        fields[BKSEC_FIELD_INITIAL_OWNER] = ";".join(load_security_person())
    # 测试发送：以指定处理人覆盖初始责任人，保证测试单只发给测试接收人（E3 客户端侧隔离）
    if test_operator:
        fields[BKSEC_FIELD_INITIAL_OWNER] = test_operator
    payload = {
        BKSEC_EVENT_FIELD_RISK_TYPE: config.risk_type_id,
        BKSEC_EVENT_FIELD_FIELDS: fields,
        BKSEC_EVENT_FIELD_SOURCE: BKSEC_EVENT_SOURCE_VALUE,
    }
    if risk is not None:
        payload[BKSEC_EVENT_FIELD_RISK_ID] = risk.risk_id
    if test_operator:
        payload[BKSEC_EVENT_FIELD_IS_TEST] = True
        payload[BKSEC_EVENT_FIELD_TEST_OPERATOR] = test_operator
    return payload


def _wrap_json_escape(template_value: str) -> str:
    """
    给模板值中的每个 {{ expr }} 表达式包 json_escape 过滤器。

    事件字段映射的 value 会被序列化进 ${event_data} 的 JSON 模板串（build_pa_params）。
    运行时整串渲染时，变量值若含双引号/反斜杠/换行会破坏 JSON 结构。
    json_escape 保证值在 JSON 字符串字面量内安全（R1 转义缺陷修复）。
    """
    return re.sub(r"\{\{(.+?)\}\}", r"{{\1 | json_escape}}", template_value)


def build_pa_params(config: BkSecConfig) -> dict:
    """
    生成自动创建处理规则的 pa_params（字段级契约，对接 SOPS 插件「审计中心WeSec发单」入参）

    - 标准入参 → {"field": 风险字段, "value": ""}（AutoProcess 现成取值机制；
      两键并存、空者填 ""，与存量 pa_params 格式约定一致，避免 value 为空时
      AutoProcess 走 getattr(risk, None) 崩溃）
    - ${event_type} → BKSEC 风险类型（P1 确认）
    - ${event_data} → 策略页字段映射序列化的模板串（发送时渲染，P2）
    - ${operator} → 兜底模板（决策 D4）
    - ${action}/${once_task} → 插件控制参数默认值（P4 待确认）
    """
    params = {param: {"field": field, "value": ""} for param, field in BKSEC_PLUGIN_STANDARD_FIELDS.items()}
    params[BKSEC_PARAM_EVENT_TYPE] = {"field": "", "value": config.risk_type_id}
    params[BKSEC_PARAM_EVENT_DATA] = {
        "field": "",
        "value": json.dumps(
            {m.key: _wrap_json_escape(m.value) for m in config.field_mappings if m.key},
            ensure_ascii=False,
        ),
    }
    params[BKSEC_PARAM_OPERATOR] = {"field": "", "value": BKSEC_OPERATOR_TEMPLATE}
    params[BKSEC_PARAM_ACTION] = {"field": "", "value": BKSEC_ACTION_DEFAULT}
    params[BKSEC_PARAM_ONCE_TASK] = {"field": "", "value": BKSEC_ONCE_TASK_DEFAULT}
    return params


def build_plugin_constants(config: BkSecConfig, risk: Optional[Risk] = None, test_operator: str = "") -> dict:
    """
    构造插件的最终入参常量（测试发送/预览用；正式发送走 pa_params → AutoProcess 同构渲染）

    返回与 SOPS create_task(constants) 直接对接的字段级常量。
    """
    context = build_render_context(risk=risk)
    constants: dict = {}
    # 标准入参：取风险字段值（时间字段与 AutoProcess 一致格式化）
    for param, field in BKSEC_PLUGIN_STANDARD_FIELDS.items():
        value = getattr(risk, field, "") if risk is not None else ""
        if isinstance(value, datetime.datetime):
            value = value.astimezone(tz=timezone.get_default_timezone()).strftime(TIME_DISPLAY_FORMAT)
        elif isinstance(value, (dict, list)):
            value = json.dumps(value, ensure_ascii=False, default=str)
        constants[param] = value
    # BKSEC 风险类型（P1）
    constants[BKSEC_PARAM_EVENT_TYPE] = config.risk_type_id
    # 动态字段：渲染 field_mappings（测试发送覆盖初始责任人，空值兜底安全接口人）
    fields = {}
    for mapping in config.field_mappings:
        if mapping.key:
            fields[mapping.key] = render_value(mapping.value, context)
    if test_operator:
        fields[BKSEC_FIELD_INITIAL_OWNER] = test_operator
    elif not fields.get(BKSEC_FIELD_INITIAL_OWNER):
        fields[BKSEC_FIELD_INITIAL_OWNER] = ";".join(load_security_person())
    constants[BKSEC_PARAM_EVENT_DATA] = json.dumps(fields, ensure_ascii=False)
    # 责任人（D4 兜底）：模板经 tojson 自足产出数组串，满足插件 json.loads 契约
    constants[BKSEC_PARAM_OPERATOR] = render_value(BKSEC_OPERATOR_TEMPLATE, context)
    if test_operator:
        constants[BKSEC_PARAM_OPERATOR] = json.dumps([test_operator], ensure_ascii=False)
    # 插件控制参数：测试发送用"否"豁免单次去重（样例风险单的 raw_event_id 可能已被正式发送占用）
    constants[BKSEC_PARAM_ACTION] = BKSEC_ACTION_DEFAULT
    constants[BKSEC_PARAM_ONCE_TASK] = BKSEC_ONCE_TASK_TEST if test_operator else BKSEC_ONCE_TASK_DEFAULT
    return constants


def render_event_constant(template_json: str, risk: Optional[Risk] = None) -> str:
    """
    渲染事件契约常量（AutoProcess 正式发送时调用），返回最终事件 JSON 字符串
    """
    rendered = render_value(template_json, build_render_context(risk=risk))
    # 初始责任人兜底（渲染后仍为空时补安全接口人）——仅事件体(dict)适用；
    # operator 等其它契约常量渲染结果为 JSON 数组(list)，不在此处理
    try:
        payload = json.loads(rendered)
        if isinstance(payload, dict):
            fields = payload.get(BKSEC_EVENT_FIELD_FIELDS) or {}
            if not fields.get(BKSEC_FIELD_INITIAL_OWNER):
                fields[BKSEC_FIELD_INITIAL_OWNER] = ";".join(load_security_person())
                payload[BKSEC_EVENT_FIELD_FIELDS] = fields
                rendered = json.dumps(payload, ensure_ascii=False)
    except (ValueError, TypeError):
        logger.exception("[BkSecContract] Rendered payload is not valid json, keep origin")
    return rendered
