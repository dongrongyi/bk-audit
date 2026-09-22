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
import logging

from bk_resource import api
from bk_resource.base import Resource
from django.conf import settings
from django.core.cache import cache
from django.shortcuts import get_object_or_404
from django.utils.translation import gettext_lazy
from rest_framework import serializers

from services.web.risk.bksec.config import BkSecConfig
from services.web.risk.bksec.constants import (
    BKSEC_CACHE_TIMEOUT,
    BKSEC_REQUIRED_FIELDS,
    BKSEC_RISK_TYPE_CACHE_KEY,
)
from services.web.risk.bksec.contract import build_event_payload, build_plugin_constants
from services.web.risk.bksec.variables import (
    AGGREGATION_FUNCTIONS,
    RISK_VARIABLE_META,
    build_risk_data,
)
from services.web.risk.constants import EventBasicField
from services.web.risk.models import Risk

logger = logging.getLogger("celery")


class BkSecResourceMeta(Resource):
    tags = ["BkSec"]


def _normalize_risk_type(raw: dict) -> dict:
    """
    归一化 BKSEC 风险类型结构
    """
    return {
        "risk_type_id": str(raw.get("id", "")),
        "name": raw.get("name", ""),
        "is_formal": bool(raw.get("is_formal", False)),
        "desc": raw.get("desc", ""),
    }


def _normalize_risk_type_detail(raw: dict) -> dict:
    """
    归一化 BKSEC 风险类型详情

    风险资产信息/初始责任人——必填
    """
    fields = raw.get("risk_access_fields", []) or []
    normalized_fields = []
    for f in fields:
        key = f.get("key", "")
        normalized_fields.append(
            {
                "key": key,
                "name": f.get("name", ""),
                "type": f.get("storage_type", "string"),
                "source_type": f.get("source_type", ""),
                "unique": bool(f.get("unique", False)),
                "sequence": f.get("sequence", 0),
                "required": key in BKSEC_REQUIRED_FIELDS,
            }
        )
    # 按 sequence 排序，与 BKSEC 侧展示顺序一致
    normalized_fields.sort(key=lambda x: x["sequence"] or 0)
    return {**_normalize_risk_type(raw), "fields": normalized_fields}


class ListBkSecRiskTypes(BkSecResourceMeta):
    """
    查询 BKSEC 风险类型列表（策略页下拉）

    按 BKSEC_PROJECT_ID 项目维度过滤（必填），默认只返回正式（is_formal）类型。
    """

    name = gettext_lazy("查询BKSEC风险类型列表")

    class RequestSerializer(serializers.Serializer):
        name__icontains = serializers.CharField(label=gettext_lazy("名称模糊搜索"), required=False, allow_blank=True)
        is_formal = serializers.CharField(label=gettext_lazy("是否正式"), required=False, allow_blank=True)

    def perform_request(self, validated_request_data):
        if not settings.BKSEC_PROJECT_ID:
            raise serializers.ValidationError(gettext_lazy("未配置 BKSEC 项目（BKAPP_BKSEC_PROJECT_ID），无法查询风险类型"))
        params = {
            "page": 1,
            "page_size": 100,
            "project_id": settings.BKSEC_PROJECT_ID,
            "is_formal": validated_request_data.get("is_formal", "true"),
        }
        if validated_request_data.get("name__icontains"):
            params["name__icontains"] = validated_request_data["name__icontains"]
        result = api.bk_sec.risk_access_list(**params)
        items = result.get("results", []) or []
        return [_normalize_risk_type(item) for item in items if isinstance(item, dict)]


class RetrieveBkSecRiskType(BkSecResourceMeta):
    """
    查询 BKSEC 风险类型详情（含工单字段 schema）
    """

    name = gettext_lazy("查询BKSEC风险类型详情")

    class RequestSerializer(serializers.Serializer):
        risk_type_id = serializers.CharField(label=gettext_lazy("风险类型ID"), required=True)

    def perform_request(self, validated_request_data):
        cache_key = BKSEC_RISK_TYPE_CACHE_KEY.format(risk_type_id=validated_request_data["risk_type_id"])
        detail = cache.get(cache_key)
        if detail is None:
            detail = api.bk_sec.risk_access_retrieve(id=validated_request_data["risk_type_id"])
            detail = _normalize_risk_type_detail(detail or {})
            cache.set(cache_key, detail, timeout=BKSEC_CACHE_TIMEOUT)
        return detail


class ListBkSecVariables(BkSecResourceMeta):
    """
    查询 BKSEC 字段可用变量列表（引用变量弹窗：风险字段 / 事件字段）
    """

    name = gettext_lazy("查询BKSEC可用变量")

    class RequestSerializer(serializers.Serializer):
        strategy_id = serializers.IntegerField(label=gettext_lazy("策略ID"), required=False, allow_null=True)

    def perform_request(self, validated_request_data):
        # 风险变量：遍历单一事实源 RISK_VARIABLE_META（与渲染引擎 build_risk_data 的键集合一致，测试校验防漂移）
        risk_variables = [
            {
                "group": "risk",
                "key": "risk.%s" % key,
                "name": str(label),
                "sample": sample,
                "insert": "{{ risk.%s }}" % key,
            }
            for key, (label, sample) in RISK_VARIABLE_META.items()
        ]
        # 事件变量 = 事件基本字段（EventBasicField，与 ListEventFieldsByStrategy 同源）+ 策略扩展字段
        event_variables = [
            {
                "group": "event",
                "key": "event.%s" % field_name,
                "name": str(label),
                "sample": "",
                "insert": "{{ event.%s }}" % field_name,
                "aggregations": [
                    {"name": func, "insert": "{{{{ {}(event.{}) }}}}".format(func, field_name)}
                    for func in AGGREGATION_FUNCTIONS
                ],
            }
            for field_name, label in EventBasicField.choices
        ]
        basic_field_names = {field_name for field_name, _ in EventBasicField.choices}
        strategy_id = validated_request_data.get("strategy_id")
        if strategy_id:
            from services.web.strategy_v2.models import Strategy

            strategy = Strategy.objects.filter(strategy_id=strategy_id).first()
            # 策略事件拓展字段（key 取 display_name，与事件调查报告的变量引用语法一致）
            for cfg in (getattr(strategy, "event_data_field_configs", None) or []) if strategy else []:
                display_name = cfg.get("display_name") or cfg.get("field_name")
                field_name = cfg.get("field_name")
                if not display_name or field_name in basic_field_names:
                    continue
                event_variables.append(
                    {
                        "group": "event",
                        "key": "event.%s" % display_name,
                        "name": str(display_name),
                        "sample": "",
                        # 默认插入为最后一条事件取值；聚合写法由前端按需选择
                        "insert": "{{ event.%s }}" % display_name,
                        "aggregations": [
                            {"name": func, "insert": "{{{{ {}(event.{}) }}}}".format(func, display_name)}
                            for func in AGGREGATION_FUNCTIONS
                        ],
                    }
                )
        return {"risk_variables": risk_variables, "event_variables": event_variables}


class PreviewBkSecTicket(BkSecResourceMeta):
    """
    预览 BKSEC 工单（按当前配置 + 指定样例风险单渲染，不实际发送）
    """

    name = gettext_lazy("预览BKSEC工单")

    class RequestSerializer(serializers.Serializer):
        bksec_config = serializers.DictField(label=gettext_lazy("BKSEC配置"), required=True)
        risk_id = serializers.CharField(
            label=gettext_lazy("样例风险单ID"), required=False, allow_blank=True, allow_null=True
        )

    def perform_request(self, validated_request_data):
        try:
            config = BkSecConfig.model_validate(validated_request_data["bksec_config"])
        except ValueError as err:
            raise serializers.ValidationError(gettext_lazy("BKSEC 配置不合法：%s") % err)
        risk = None
        risk_id = validated_request_data.get("risk_id")
        if risk_id:
            risk = Risk.objects.filter(risk_id=risk_id).first()
            if risk is None:
                raise serializers.ValidationError(gettext_lazy("样例风险单不存在：%s") % risk_id)
        try:
            payload = build_event_payload(config, risk=risk)
        except Exception as err:  # NOCC:broad-except(预览即时报错，区别于正式发送的失败重试链路)
            raise serializers.ValidationError(gettext_lazy("字段模板渲染失败，请检查变量语法：%s") % err)
        # 风险快照：供前端组装预览头部区块（工单标题/等级/关注人/当前责任人/发现时间等；
        # 工单ID、提单时间、处理截止时间由前端按需求规则生成）
        risk_data = build_risk_data(risk)
        return {
            "risk_type_id": config.risk_type_id,
            "risk_type_name": config.risk_type_name,
            "has_sample_risk": risk is not None,
            "ticket": payload,
            "risk": risk_data,
            # 供前端渲染变量空值提示
            "risk_context_keys": list(risk_data.keys()),
        }


class SendBkSecTestTicket(BkSecResourceMeta):
    """
    发送 BKSEC 测试工单（经 SOPS 真实通道推送，仅发给指定处理人，不影响正式派单）

    测试结果即生产路径的验证；任务状态由前端轮询 SOPS 状态接口获取。
    """

    name = gettext_lazy("发送BKSEC测试工单")

    class RequestSerializer(serializers.Serializer):
        bksec_config = serializers.DictField(label=gettext_lazy("BKSEC配置"), required=True)
        test_operator = serializers.CharField(label=gettext_lazy("测试处理人"), required=True)
        # 测试发送必须指定样例风险单：不传则所有 {{ risk.xxx }} 渲染为空，测试单大量字段为空、失去验证意义
        risk_id = serializers.CharField(label=gettext_lazy("样例风险单ID"), required=True)

    def perform_request(self, validated_request_data):
        try:
            config = BkSecConfig.model_validate(validated_request_data["bksec_config"])
            config.validate_for_submit()
        except ValueError as err:
            raise serializers.ValidationError(gettext_lazy("BKSEC 配置不合法：%s") % err)
        risk = get_object_or_404(Risk, risk_id=validated_request_data["risk_id"])
        # 确保预置套餐就绪（依赖 BKSEC_SOPS_TEMPLATE_ID 环境变量）
        from services.web.risk.bksec.rules import ensure_preset_pa

        pa = ensure_preset_pa()
        if pa is None:
            raise serializers.ValidationError(gettext_lazy("预置发单套餐未就绪（未配置 BKSEC_SOPS_TEMPLATE_ID），无法发送测试工单"))
        # 渲染插件入参常量（初始责任人已被测试处理人覆盖）
        try:
            constants = build_plugin_constants(config, risk=risk, test_operator=validated_request_data["test_operator"])
        except Exception as err:  # NOCC:broad-except(测试发送即时报错，便于定位配置问题)
            raise serializers.ValidationError(gettext_lazy("字段模板渲染失败，请检查变量语法：%s") % err)
        # 经预置套餐模板创建并启动测试任务（与正式发送同一通道、同一入参结构）
        result = api.bk_sops.create_task(
            name="【测试】{}_{}".format(pa.name, int(datetime.datetime.now().timestamp() * 1000)),
            constants=constants,
            bk_biz_id=settings.DEFAULT_BK_BIZ_ID,
            template_id=pa.sops_template_id,
        )
        api.bk_sops.start_task(task_id=result["task_id"], bk_biz_id=settings.DEFAULT_BK_BIZ_ID)
        logger.info(
            "[BkSecTestTicket] SOPS task started, task_id=%s risk_type=%s test_operator=%s risk_id=%s",
            result.get("task_id"),
            config.risk_type_id,
            validated_request_data["test_operator"],
            risk.risk_id,
        )
        return {"task": result, "constants": constants}


class GetBkSecTestTaskStatus(BkSecResourceMeta):
    """
    查询 BKSEC 测试任务状态（透传 SOPS 任务状态，供前端轮询至终态）
    """

    name = gettext_lazy("查询BKSEC测试任务状态")

    class RequestSerializer(serializers.Serializer):
        task_id = serializers.CharField(label=gettext_lazy("SOPS任务ID"), required=True)

    def perform_request(self, validated_request_data):
        return api.bk_sops.get_task_status(
            task_id=validated_request_data["task_id"], bk_biz_id=settings.DEFAULT_BK_BIZ_ID
        )
