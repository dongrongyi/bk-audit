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

import datetime
import logging

from bk_resource import api
from bk_resource.base import Resource
from django.conf import settings
from django.shortcuts import get_object_or_404
from django.utils.translation import gettext_lazy
from rest_framework import serializers

from apps.sops.constants import SOPSTaskStatus
from services.web.risk.bksec.constants import (
    BKSEC_CACHE_TIMEOUT,
    BKSEC_RISK_TYPE_CACHE_KEY,
)
from services.web.risk.bksec.variables import (
    _normalize_risk_type,
    _normalize_risk_type_detail,
)
from services.web.risk.channels.base import ChannelRegistry
from services.web.risk.models import Risk

logger = logging.getLogger("celery")


class BkSecResourceMeta(Resource):
    tags = ["BkSec"]


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
        from django.core.cache import cache

        cache_key = BKSEC_RISK_TYPE_CACHE_KEY.format(risk_type_id=validated_request_data["risk_type_id"])
        detail = cache.get(cache_key)
        if detail is None:
            detail = api.bk_sec.risk_access_retrieve(id=validated_request_data["risk_type_id"])
            detail = _normalize_risk_type_detail(detail or {})
            cache.set(cache_key, detail, timeout=BKSEC_CACHE_TIMEOUT)
        return detail


class PreviewTicket(BkSecResourceMeta):
    """
    预览工单（按当前通道配置 + 指定样例风险单渲染，不实际发送）

    通道无关：具体渲染逻辑由 channel 参数指定的通道适配实现（如 bk_sec）。
    """

    name = gettext_lazy("预览工单")

    class RequestSerializer(serializers.Serializer):
        channel = serializers.CharField(label=gettext_lazy("下发通道类型"), required=True)
        channel_config = serializers.DictField(label=gettext_lazy("通道专属配置"), required=True)
        risk_id = serializers.CharField(
            label=gettext_lazy("样例风险单ID"), required=False, allow_blank=True, allow_null=True
        )

    def perform_request(self, validated_request_data):
        ch = ChannelRegistry.get(validated_request_data["channel"])
        risk = None
        risk_id = validated_request_data.get("risk_id")
        if risk_id:
            risk = Risk.objects.filter(risk_id=risk_id).first()
            if risk is None:
                raise serializers.ValidationError(gettext_lazy("样例风险单不存在：%s") % risk_id)
        return ch.render_preview(validated_request_data["channel_config"], risk)


class SendTestTicket(BkSecResourceMeta):
    """
    发送测试工单（经 SOPS 真实通道推送，仅发给指定接收人，不影响正式派单）

    测试结果即生产路径的验证；任务状态由前端轮询 get_task_status 接口获取。
    通道无关：具体常量构造、前置守卫、套餐模板均由 channel 适配实现。
    """

    name = gettext_lazy("发送测试工单")

    class RequestSerializer(serializers.Serializer):
        channel = serializers.CharField(label=gettext_lazy("下发通道类型"), required=True)
        channel_config = serializers.DictField(label=gettext_lazy("通道专属配置"), required=True)
        test_receivers = serializers.ListField(
            label=gettext_lazy("测试接收人"), child=serializers.CharField(), required=True
        )
        # 测试发送必须指定样例风险单：不传则所有 {{ risk.xxx }} 渲染为空，测试单大量字段为空、失去验证意义
        risk_id = serializers.CharField(label=gettext_lazy("样例风险单ID"), required=True)

    def perform_request(self, validated_request_data):
        ch = ChannelRegistry.get(validated_request_data["channel"])
        risk = get_object_or_404(Risk, risk_id=validated_request_data["risk_id"])
        # 通道前置守卫（如 BKSEC 的回调隔离）
        ch.validate_test_target(risk)
        # 渲染插件入参常量
        constants = ch.render_test_constants(
            validated_request_data["channel_config"], risk, validated_request_data["test_receivers"]
        )
        # 确保预置套餐就绪（依赖通道提供的模板 ID 环境变量）
        template_id = ch.get_preset_pa_template_id()
        if not template_id:
            raise serializers.ValidationError(gettext_lazy("预置发单套餐未就绪（未配置套餐模板 ID），无法发送测试工单"))
        pa = self._ensure_preset_pa(template_id)
        if pa is None:
            raise serializers.ValidationError(gettext_lazy("预置发单套餐未就绪，无法发送测试工单"))
        # 经预置套餐模板创建并启动测试任务（与正式发送同一通道、同一入参结构）。
        # 注意：插件侧错误（Config 缺失/白名单/参数格式）发生在 SOPS 异步执行阶段，
        # 此处只能捕获 SOPS 调用自身的失败（网络/鉴权），插件错误由 get_task_status 轮询侧转换提示
        try:
            result = api.bk_sops.create_task(
                name="【测试】{}_{}".format(pa.name, int(datetime.datetime.now().timestamp() * 1000)),
                constants=constants,
                bk_biz_id=settings.DEFAULT_BK_BIZ_ID,
                template_id=pa.sops_template_id,
            )
            api.bk_sops.start_task(task_id=result["task_id"], bk_biz_id=settings.DEFAULT_BK_BIZ_ID)
        except Exception as err:  # NOCC:broad-except(SOPS 调用失败转友好提示)
            logger.exception("[SendTestTicket] SOPS task create/start failed, risk_id=%s", risk.risk_id)
            raise serializers.ValidationError(gettext_lazy("SOPS 测试任务创建/启动失败：%s") % err)
        logger.info(
            "[SendTestTicket] SOPS task started, task_id=%s channel=%s risk_id=%s",
            result.get("task_id"),
            validated_request_data["channel"],
            risk.risk_id,
        )
        return {"task": result, "constants": constants}

    @staticmethod
    def _ensure_preset_pa(template_id):
        """
        获取/自愈预置发单套餐（通用层，仅按模板 ID 维护内置套餐；
        通道专属的模板 ID 由 channel.get_preset_pa_template_id 提供）
        """
        from services.web.risk.bksec.constants import (
            BKSEC_PRESET_PA_DESCRIPTION,
            BKSEC_PRESET_PA_NAME,
        )
        from services.web.risk.models import ProcessApplication

        pa = ProcessApplication.objects.filter(is_builtin=True).order_by("-id").first()
        try:
            template_id = int(template_id)
        except (TypeError, ValueError):
            logger.exception("[SendTestTicket] Invalid preset pa template_id: %s", template_id)
            return pa
        if pa is None:
            pa = ProcessApplication.objects.create(
                name=str(BKSEC_PRESET_PA_NAME),
                sops_template_id=template_id,
                need_approve=False,
                description=str(BKSEC_PRESET_PA_DESCRIPTION),
                is_enabled=True,
                is_builtin=True,
            )
            logger.info("[SendTestTicket] Preset process application created, id=%s template=%s", pa.id, template_id)
            return pa
        if pa.sops_template_id != template_id or not pa.is_enabled:
            pa.sops_template_id = template_id
            pa.need_approve = False
            pa.is_enabled = True
            pa.save(update_fields=["sops_template_id", "need_approve", "is_enabled"])
        return pa


class GetTaskStatus(BkSecResourceMeta):
    """
    查询测试任务状态（透传 SOPS 任务状态，供前端轮询至终态）

    通道无关：失败时附带的可操作失败提示（failure_hint）由对应通道提供已知错误特征映射。
    注意：插件侧错误（如 Config 缺失）发生在 SOPS 异步执行阶段，create_task 时刻无法感知，
    只能在本接口（轮询）侧转换。
    """

    name = gettext_lazy("查询测试任务状态")

    GENERIC_HINT = "任务执行失败，详情请查看 SOPS 任务执行记录"

    class RequestSerializer(serializers.Serializer):
        task_id = serializers.CharField(label=gettext_lazy("SOPS任务ID"), required=True)
        channel = serializers.CharField(label=gettext_lazy("下发通道类型"), required=False, allow_blank=True)

    def perform_request(self, validated_request_data):
        status = api.bk_sops.get_task_status(
            task_id=validated_request_data["task_id"], bk_biz_id=settings.DEFAULT_BK_BIZ_ID
        )
        result = dict(status)
        if result.get("state") in SOPSTaskStatus.get_failed_status():
            hints = []
            channel_type = validated_request_data.get("channel")
            if channel_type:
                hints = ChannelRegistry.get(channel_type).resolve_failure_hints()
            result["failure_hint"] = self._build_failure_hint(validated_request_data["task_id"], hints)
        return result

    def _build_failure_hint(self, task_id: str, hints: list) -> str:
        # 尽力取节点错误详情做特征匹配，取不到则回退通用指引
        detail_text = ""
        try:
            node_data = api.bk_sops.get_node_data(task_id=task_id, bk_biz_id=settings.DEFAULT_BK_BIZ_ID)
            detail_text = str(node_data)
        except Exception:  # NOCC:broad-except(详情获取失败不影响状态返回)
            logger.warning("[GetTaskStatus] Fetch node data failed, task_id=%s", task_id)
        for pattern, hint in hints:
            if pattern in detail_text:
                return hint
        return self.GENERIC_HINT
