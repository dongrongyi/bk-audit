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

from django.utils.translation import gettext_lazy

# SOPS 插件「审计中心WeSec发单」(v1.0.0) 入参契约：
# 12 个固定入参经模板变量化为常量，pa_params 按字段级映射构造。
# 报文组装/token/调用 BKSEC 均封装在插件内部（P3）。
# 插件入参 → 填法：
#   ${risk_id}/${event_content}/${event_evidence}/${event_time}/${event_source}/${strategy_id}/${raw_event_id}
#     → 风险字段映射（{"field": xxx}，AutoProcess 现成机制）
#   ${event_type} → BKSEC 风险类型（P1 已确认承担路由语义；push_events 文档显示类型凭证为
#     token 且插件无独立 token 入参——传 token 的可能性上升，id vs token 联测定论，暂用 risk_type_id）
#   ${event_data} → 动态字段：策略页 field_mappings 渲染后的 JSON
#     （P2 已确认：push_events 的 extra(Object) 即本参数落点，结构零调整）
#   ${operator} → 责任人（无责任人时安全接口人兜底，决策 D4）
#   ${action}/${once_task} → 插件控制参数。线值为英文码（非表单中文枚举），
#     已由插件 detail 接口的表单定义实证（2026-09-22）：
#     action ∈ {"callback"(回调), "poll"(轮询)}；once_task ∈ {"yes"(是), "no"(否)}，默认 no
BKSEC_PARAM_EVENT_TYPE = "${event_type}"
BKSEC_PARAM_EVENT_DATA = "${event_data}"
BKSEC_PARAM_OPERATOR = "${operator}"
BKSEC_PARAM_ACTION = "${action}"
BKSEC_PARAM_ONCE_TASK = "${once_task}"
# - action：插件提交事件后获取 BKSEC 工单结果的方式
#   默认 poll（轮询）：自包含、不依赖 WeSec→SOPS 回调可达性，时延对本场景无影响
# - once_task：单次发单（按 raw_event_id 去重）；
#   正式发送用 yes（同一风险不重复建单），测试发送用 no（样例风险单的
#   raw_event_id 可能已被正式发送占用，yes 会拦截测试）
BKSEC_ACTION_DEFAULT = "poll"
BKSEC_ONCE_TASK_DEFAULT = "yes"
BKSEC_ONCE_TASK_TEST = "no"
# event_type 传 risk_access 的数字 id（存量值为数字串 "56"，与 risk_access.id 形态一致）
BKSEC_EVENT_TYPE_FORMAT = "id"
# 插件标准入参 → Risk 模型字段（event_type/event_data/operator 被征用，不走此表）
BKSEC_PLUGIN_STANDARD_FIELDS = {
    "${risk_id}": "risk_id",
    "${event_content}": "event_content",
    "${event_evidence}": "event_evidence",
    "${event_time}": "event_time",
    "${event_source}": "event_source",
    "${strategy_id}": "strategy_id",
    "${raw_event_id}": "raw_event_id",
}
# operator 兜底模板（D4：无责任人时取安全接口人）。
# 注意：push_events 文档 operator 为"用户名"（String、单数）——按字面保守取首个执行人，
# 完整责任人名单由 extra.operator（初始责任人）承载。⚠️ 待环境就绪后单变量验证：
# ①信封是否支持多人（逗号/分号），若支持则去掉 .split 取完整名单；
# ②此前"执行人校验失败"的真实原因（operator 数组与 event_type 空值两嫌疑未隔离）。
BKSEC_OPERATOR_TEMPLATE = "{{ (risk.operator or risk.security_person).split(';')[0] }}"

# 预置处理套餐
BKSEC_PRESET_PA_NAME = gettext_lazy("【内置】BKSEC安全工单发单")
BKSEC_PRESET_PA_DESCRIPTION = gettext_lazy("策略 BKSEC 安全工单发单内置套餐，由系统维护，请勿删除或停用")

# 自动规则保留优先级段（结构性保证：启用 BKSEC 的发单规则恒高于一切手动规则，与创建先后无关）：
#   [BKSEC_RULE_PRIORITY_BASE, +∞) 专属自动规则；手动规则的优先级来源须排除本段（创建时 max 只统计段下值）
# 评审定论（2026-09）：不使用"当前 max+N"（相对值会被后来规则压过），改用保留段
BKSEC_RULE_PRIORITY_BASE = 9000

# 自动创建的处理规则
BKSEC_AUTO_RULE_NAME = gettext_lazy("【自动】策略 %s BKSEC发单")
# 自动规则置顶优先级间隔（在当前最大值上叠加，保证策略级规则优先命中）
# 必填字段 key（需求文档指定：所有类型两个必填字段 target/operator；
# 需求原文「风险资产信息(target)」「初始责任人(operator)，首次为空时默认 {{operator}}」）
BKSEC_FIELD_RISK_ASSET = "target"
BKSEC_FIELD_INITIAL_OWNER = "operator"
BKSEC_REQUIRED_FIELDS = [BKSEC_FIELD_RISK_ASSET, BKSEC_FIELD_INITIAL_OWNER]

# 事件体附加字段
BKSEC_EVENT_FIELD_RISK_TYPE = "risk_type"
BKSEC_EVENT_FIELD_FIELDS = "fields"
BKSEC_EVENT_FIELD_RISK_ID = "risk_id"
BKSEC_EVENT_FIELD_SOURCE = "source"
BKSEC_EVENT_SOURCE_VALUE = "bk-audit"
BKSEC_EVENT_FIELD_IS_TEST = "is_test"
BKSEC_EVENT_FIELD_TEST_OPERATOR = "test_operator"

# 查询类接口缓存
BKSEC_RISK_TYPES_CACHE_KEY = "bksec:risk_access:list"
BKSEC_RISK_TYPE_CACHE_KEY = "bksec:risk_access:{risk_type_id}"
BKSEC_CACHE_TIMEOUT = 300

# 渲染上下文加载事件的上限（预览与发单共用）
BKSEC_RENDER_EVENT_LIMIT = 100
