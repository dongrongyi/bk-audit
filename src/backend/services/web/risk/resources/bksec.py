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
from rest_framework.settings import api_settings

from apps.sops.constants import SOPSTaskStatus
from services.web.risk.bksec.rules import load_bksec_config
from services.web.risk.bksec.service import (
    bksec_failure_hints,
    ensure_bksec_enabled,
    parse_bksec_config,
    render_bksec_preview,
    render_bksec_test_constants,
    sync_bksec_test_config,
    validate_bksec_test_target,
)
from services.web.risk.bksec.variables import _normalize_risk_type
from services.web.risk.constants import TicketNodeStatus
from services.web.risk.models import Risk, TicketNode
from services.web.strategy_v2.models import Strategy

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
        from apps.feature.handlers import FeatureHandler

        if not FeatureHandler("bksec").check():
            return []
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


class PreviewTicket(BkSecResourceMeta):
    """
    预览工单（按 BKSEC 配置 + 指定样例风险单渲染，不实际发送）

    配置来源二选一（用于支持保存前预览）：
    - 传 bksec_config：用前端当前表单配置（未保存也可预览）；
    - 传 strategy_id：反查该策略已保存的 bksec_config。
    """

    name = gettext_lazy("预览工单")

    class RequestSerializer(serializers.Serializer):
        strategy_id = serializers.IntegerField(label=gettext_lazy("策略ID"), required=False, allow_null=True)
        bksec_config = serializers.DictField(label=gettext_lazy("BKSEC工单配置"), required=False)
        risk_id = serializers.CharField(
            label=gettext_lazy("样例风险单ID"), required=False, allow_blank=True, allow_null=True
        )

    def perform_request(self, validated_request_data):
        config_dict = validated_request_data.get("bksec_config")
        if config_dict:
            config = parse_bksec_config(config_dict)
        else:
            strategy_id = validated_request_data.get("strategy_id")
            if not strategy_id:
                raise serializers.ValidationError(gettext_lazy("预览需提供策略ID（strategy_id）或 BKSEC 工单配置（bksec_config）"))
            strategy = get_object_or_404(Strategy, strategy_id=strategy_id)
            config = load_bksec_config(strategy)
            if config is None:
                raise serializers.ValidationError(gettext_lazy("该策略未配置 BKSEC 安全工单"))
        risk = None
        risk_id = validated_request_data.get("risk_id")
        if risk_id:
            risk = Risk.objects.filter(risk_id=risk_id).first()
            if risk is None:
                raise serializers.ValidationError(gettext_lazy("样例风险单不存在：%s") % risk_id)
        return render_bksec_preview(config, risk)


class SendTestTicket(BkSecResourceMeta):
    """
    发送测试工单（经 SOPS 真实通道推送，仅发给指定接收人，不影响正式派单）

    测试结果即生产路径的验证；任务状态由前端轮询 get_task_status 接口获取。
    配置从风险单反查已保存的策略 BKSEC 配置（测的就是已保存那份）。
    """

    name = gettext_lazy("发送测试工单")

    class RequestSerializer(serializers.Serializer):
        test_receivers = serializers.ListField(
            label=gettext_lazy("测试接收人"), child=serializers.CharField(), required=True
        )
        # 测试发送必须指定样例风险单：不传则所有 {{ risk.xxx }} 渲染为空，测试单大量字段为空、失去验证意义
        risk_id = serializers.CharField(label=gettext_lazy("样例风险单ID"), required=True)

    def perform_request(self, validated_request_data):
        # 后端 feature 硬拦截（前端隐藏后仍可能被 API 直接调用）
        ensure_bksec_enabled()
        risk = get_object_or_404(Risk, risk_id=validated_request_data["risk_id"])
        # 测试发送发生在保存之后：从风险单反查已保存的策略 BKSEC 配置（测的就是已保存那份）
        strategy = Strategy.objects.filter(strategy_id=risk.strategy_id).first()
        if strategy is None:
            raise serializers.ValidationError(gettext_lazy("该风险单未关联策略，无法发送测试工单"))
        config = load_bksec_config(strategy)
        if config is None or not config.enabled:
            raise serializers.ValidationError(gettext_lazy("该风险单关联的策略未启用 BKSEC 安全工单"))
        # 回调隔离守卫（插件 Callback 表按风险单复用）
        validate_bksec_test_target(risk)
        # 测试发送前置：兜底同步插件侧 Config（确保插件侧与已保存配置一致）
        sync_bksec_test_config(strategy, config)
        # 渲染插件入参常量
        constants = render_bksec_test_constants(config, risk, validated_request_data["test_receivers"])
        # 确保预置套餐就绪（复用正式路径的套餐自愈逻辑）
        if not settings.BKSEC_SOPS_TEMPLATE_ID:
            raise serializers.ValidationError(gettext_lazy("预置发单套餐未就绪（未配置套餐模板 ID），无法发送测试工单"))
        from services.web.risk.bksec.rules import ensure_preset_pa

        pa = ensure_preset_pa()
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
        # 生成执行记录（is_test=True，与正式单结构一致；风险详情页过滤、处理套餐执行记录可见）
        task_name = "【测试】{}_{}".format(pa.name, int(datetime.datetime.now().timestamp() * 1000))
        TicketNode.objects.create(
            risk_id=risk.risk_id,
            operator="test",
            current_operator=[],
            action="AutoProcess",
            timestamp=datetime.datetime.now().timestamp(),
            time=datetime.datetime.now().strftime(api_settings.DATETIME_FORMAT),
            process_result={
                "task": result,
                "status": api.bk_sops.get_task_status(task_id=result["task_id"], bk_biz_id=settings.DEFAULT_BK_BIZ_ID),
                "pa_id": pa.id,
                "pa_name": pa.name,
                "task_name": task_name,
                "trigger": "test",
            },
            status=TicketNodeStatus.RUNNING,
            is_test=True,
        )
        logger.info(
            "[SendTestTicket] SOPS task started, task_id=%s risk_id=%s",
            result.get("task_id"),
            risk.risk_id,
        )
        return {"task": result, "constants": constants}


class GetTaskStatus(BkSecResourceMeta):
    """
    查询测试任务状态（透传 SOPS 任务状态，供前端轮询至终态）

    失败时附带可操作的失败提示（failure_hint），由已知插件错误特征映射翻译。
    注意：插件侧错误（如 Config 缺失）发生在 SOPS 异步执行阶段，create_task 时刻无法感知，
    只能在本接口（轮询）侧转换。
    """

    name = gettext_lazy("查询测试任务状态")

    GENERIC_HINT = "任务执行失败，详情请查看 SOPS 任务执行记录"

    class RequestSerializer(serializers.Serializer):
        task_id = serializers.CharField(label=gettext_lazy("SOPS任务ID"), required=True)

    def perform_request(self, validated_request_data):
        status = api.bk_sops.get_task_status(
            task_id=validated_request_data["task_id"], bk_biz_id=settings.DEFAULT_BK_BIZ_ID
        )
        result = dict(status)
        # 测试单执行记录状态同步（一次性发送，无轮询任务，由前端查询时更新）
        if result.get("state") in SOPSTaskStatus.get_finished_status():
            node = (
                TicketNode.objects.filter(
                    is_test=True,
                    status=TicketNodeStatus.RUNNING,
                    process_result__task__task_id=str(validated_request_data["task_id"]),
                )
                .order_by("-timestamp")
                .first()
            )
            if node:
                node.process_result["status"] = result
                node.status = TicketNodeStatus.FINISHED
                node.save(update_fields=["process_result", "status"])
        if result.get("state") in SOPSTaskStatus.get_failed_status():
            result["failure_hint"] = self._build_failure_hint(validated_request_data["task_id"], bksec_failure_hints())
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
