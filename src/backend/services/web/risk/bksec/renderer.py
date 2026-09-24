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

import json
import logging
from typing import List, Optional

from core.render import jinja2_environment
from services.web.risk.bksec.variables import build_render_context
from services.web.risk.models import Risk

logger = logging.getLogger("celery")


def _json_escape_filter(value):
    """
    Jinja2 过滤器：将值转为 JSON 字符串字面量内容（不含外层引号）。

    用途：build_pa_params 生成 ${event_data} 模板时，给每个 {{ expr }} 包此过滤器，
    保证模板渲染后仍是合法 JSON——防止用户配置的值包含双引号/反斜杠/换行时
    破坏 event_data 的 JSON 结构（R1 转义缺陷修复）。
    """
    if value is None:
        return ""
    return json.dumps(str(value))[1:-1]


def render_value(template: str, context: dict) -> str:
    """
    渲染字段值模板
    - 风险变量：{{ risk.risk_id }}、{{ risk.operator }}
    - 事件变量（直接取）：{{ event.username }}，默认取最后一条事件的该字段值
    - 事件变量（聚合）：{{ count(event.event_id) }}，
      聚合函数为count / count_distinct / first / latest / list / list_distinct / sum / avg / max / min，
      作用于该风险单关联的全部事件
    """
    if not isinstance(template, str) or "{{" not in template:
        return template if isinstance(template, str) else ""
    env = jinja2_environment(autoescape=False)
    env.filters["json_escape"] = _json_escape_filter
    try:
        return env.from_string(template).render(**context).strip()
    except Exception as err:  # NOCC:broad-except(渲染失败需明确可见)
        logger.exception("[BkSecRender] Render failed, template=%s err=%s", template, err)
        raise


def render_for_risk(template: str, risk: Optional[Risk], events: Optional[List[dict]] = None) -> str:
    """
    以指定风险单为上下文渲染模板（预览 / 测试发送 / 正式发送共用入口）
    """
    return render_value(template, build_render_context(risk=risk, events=events))
