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
software distributed under the License is distributed on
an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
either express or implied. See the License for the
specific language governing permissions and limitations under the License.
We undertake not to change the open source license (MIT license) applicable
to the current version of the project delivered to anyone in the future.
"""

import abc
import datetime
from typing import Optional

from django.db import transaction
from django.db.models import Count, Q
from django.shortcuts import get_object_or_404
from django.utils.translation import gettext, gettext_lazy
from rest_framework import serializers

from apps.audit.resources import AuditMixinResource
from apps.meta.constants import OrderTypeChoices
from apps.permission.handlers.actions import ActionEnum
from apps.permission.handlers.resource_types import ResourceEnum
from apps.sops.constants import SOPSTaskStatus
from services.web.risk.constants import ApproveTicketFields, RiskStatus
from services.web.risk.models import ProcessApplication, Risk, RiskRule, TicketNode
from services.web.risk.serializers import (
    CreateProcessApplicationsReqSerializer,
    ListAllProcessApplicationsReqSerializer,
    ListProcessApplicationsReqSerializer,
    ListRiskResponseSerializer,
    PAExecutionRecordInfoSerializer,
    ProcessApplicationsInfoSerializer,
    RiskRuleInfoSerializer,
    ToggleProcessApplicationReqSerializer,
    UpdateProcessApplicationsReqSerializer,
)
from services.web.scene.constants import ResourceVisibilityType
from services.web.scene.filters import BindingMetadataHelper, SceneScopeFilter


class ProcessApplicationMeta(AuditMixinResource, abc.ABC):
    tags = ["ProcessApplication"]


class ListProcessApplications(ProcessApplicationMeta):
    name = gettext_lazy("获取处理套餐列表")
    RequestSerializer = ListProcessApplicationsReqSerializer
    ResponseSerializer = ProcessApplicationsInfoSerializer
    many_response_data = True
    audit_action = ActionEnum.LIST_PA

    def perform_request(self, validated_request_data):
        # 场景过滤
        scene_id = validated_request_data.pop("scene_id", None)
        order_field = validated_request_data.pop("order_field", "-created_at")
        # 构造筛选条件
        q = Q()
        for key, val in validated_request_data.items():
            _q = Q()
            for item in val:
                _q |= Q(**{key: item})
            q &= _q
        # 场景过滤
        # 筛选数据（SceneScopeFilter 会处理 scene_id 过滤，未指定时返回全部）
        process_applications = SceneScopeFilter.filter_queryset(
            queryset=ProcessApplication.objects.filter(q),
            scene_id=scene_id,
            resource_type=ResourceVisibilityType.PROCESS_APPLICATION,
            pk_field="id",
        ).order_by("-is_enabled", order_field)
        # 获取关联的规则
        rule_map = {
            item["pa_id"]: item["count"]
            for item in RiskRule.load_latest_rules()
            .filter(pa_id__in=process_applications.values("id"))
            .values("pa_id")
            .annotate(count=Count("pa_id"))
            .order_by()
        }
        for pa in process_applications:
            setattr(pa, "rule_count", rule_map.get(pa.id, 0))
        return process_applications


class ListAllProcessApplications(ProcessApplicationMeta):
    name = gettext_lazy("获取所有处理套餐列表")
    RequestSerializer = ListAllProcessApplicationsReqSerializer
    audit_action = ActionEnum.LIST_PA

    def perform_request(self, validated_request_data):
        # 风险处理人不一定有处理套餐相关 action 权限，但风险单展示需要按场景加载套餐名称。
        scene_id = validated_request_data["scene_id"]
        process_applications = ProcessApplication.objects.all()
        process_applications = SceneScopeFilter.filter_queryset(
            queryset=process_applications,
            scene_id=scene_id,
            resource_type=ResourceVisibilityType.PROCESS_APPLICATION,
            pk_field="id",
        )
        return [
            {"id": pa.id, "name": pa.name, "sops_template_id": pa.sops_template_id, "is_enabled": pa.is_enabled}
            for pa in process_applications
        ]


class CreateProcessApplication(ProcessApplicationMeta):
    name = gettext_lazy("创建处理套餐")
    RequestSerializer = CreateProcessApplicationsReqSerializer
    ResponseSerializer = ProcessApplicationsInfoSerializer
    audit_action = ActionEnum.CREATE_PA

    @transaction.atomic
    def perform_request(self, validated_request_data):
        scene_id = validated_request_data.pop("scene_id", None)
        pa = ProcessApplication.objects.create(**validated_request_data)
        # 创建 ResourceBinding 关联（scene_id 必传，序列化器已校验）
        BindingMetadataHelper.create_resource_binding(
            resource_id=str(pa.id),
            resource_type=ResourceVisibilityType.PROCESS_APPLICATION,
            scene_id=scene_id,
        )
        return pa


def _reject_builtin_edit(pa: ProcessApplication) -> None:
    """
    内置套餐（BKSEC 发单）禁止编辑/启停：

    参数由策略配置生成并挂在自动规则上，套餐本身不承载配置；
    修改 need_approve/sops_template_id 等会破坏发送契约。
    """
    if pa.is_builtin:
        raise serializers.ValidationError(
            gettext("内置套餐【%s】由系统维护，不支持编辑或启停；如需调整 SOPS 模板请修改 BKSEC_SOPS_TEMPLATE_ID 环境变量") % pa.name
        )


class UpdateProcessApplication(ProcessApplicationMeta):
    name = gettext_lazy("更新处理套餐")
    RequestSerializer = UpdateProcessApplicationsReqSerializer
    ResponseSerializer = ProcessApplicationsInfoSerializer
    audit_action = ActionEnum.EDIT_PA

    def perform_request(self, validated_request_data):
        pa = get_object_or_404(ProcessApplication, id=validated_request_data["id"])
        _reject_builtin_edit(pa)
        for key, val in validated_request_data.items():
            setattr(pa, key, val)
        pa.save()
        return pa


class ListRiskByPA(ProcessApplicationMeta):
    name = gettext_lazy("获取处理套餐命中的风险")
    ResponseSerializer = ListRiskResponseSerializer
    many_response_data = True
    audit_action = ActionEnum.LIST_RISK
    audit_resource_type = ResourceEnum.RISK

    def perform_request(self, validated_request_data):
        # 获取处理套餐实例
        pa = get_object_or_404(ProcessApplication, id=validated_request_data["id"])
        # 获取规则列表
        rules = RiskRule.objects.filter(pa_id=pa.id)
        # 拼接筛选条件
        q = Q()
        for rule in rules:
            q |= Q(rule_id=rule.rule_id, rule_version=rule.version)
        qs = Risk.load_authed_risks(action=ActionEnum.LIST_RISK)
        risks = Risk.annotated_queryset(qs).exclude(status=RiskStatus.CLOSED).filter(q)
        return risks


class ListRuleByPA(ProcessApplicationMeta):
    name = gettext_lazy("获取处理套餐关联的规则")
    ResponseSerializer = RiskRuleInfoSerializer
    many_response_data = True
    audit_action = ActionEnum.LIST_RULE

    def perform_request(self, validated_request_data):
        # 获取处理套餐实例
        pa = get_object_or_404(ProcessApplication, id=validated_request_data["id"])
        # 获取规则列表
        order_field = validated_request_data.get("order_field", "-created_at")
        order_field = (
            f"-{order_field}" if validated_request_data.get("order_type") == OrderTypeChoices.DESC else order_field
        )
        return RiskRule.load_latest_rules().filter(pa_id=pa.id).order_by("-is_enabled", order_field)


class ListPAExecutionRecords(ProcessApplicationMeta):
    """
    获取处理套餐执行记录（执行记录侧滑：套餐页看全部/单套餐，风险入口按风险ID筛选）

    数据链路：TicketNode(action=AutoProcess) → Risk(rule_id) → RiskRule(pa_id) → 套餐
    """

    name = gettext_lazy("获取处理套餐执行记录")
    ResponseSerializer = PAExecutionRecordInfoSerializer
    many_response_data = True
    audit_action = ActionEnum.LIST_PA

    @staticmethod
    def _parse_sops_time(value) -> Optional[datetime.datetime]:
        """解析 SOPS 状态里的时间字段（源格式或 ISO 格式，均可能出现在 JSONField 回读值中）"""
        if not value or not isinstance(value, str):
            return None
        value = value.strip()
        for fmt in ("%Y-%m-%d %H:%M:%S %z", "%Y-%m-%d %H:%M:%S"):
            try:
                return datetime.datetime.strptime(value, fmt)
            except ValueError:
                continue
        try:
            return datetime.datetime.fromisoformat(value)
        except ValueError:
            return None

    @classmethod
    def _calc_duration(cls, status_info: dict) -> Optional[int]:
        """耗时（秒）：SOPS 任务实际 start_time/finish_time 之差；未结束/缺失返回 None"""
        start = cls._parse_sops_time(status_info.get("start_time"))
        finish = cls._parse_sops_time(status_info.get("finish_time"))
        if start and finish:
            return int((finish - start).total_seconds())
        return None

    class RequestSerializer(serializers.Serializer):
        id = serializers.IntegerField(label=gettext_lazy("套餐ID"), required=False, allow_null=True)
        risk_id = serializers.CharField(label=gettext_lazy("风险ID"), required=False, allow_blank=True, allow_null=True)
        scene_id = serializers.IntegerField(label=gettext_lazy("场景ID"), required=False, allow_null=True)

    def perform_request(self, validated_request_data):
        pa_id = validated_request_data.get("id")
        risk_id = validated_request_data.get("risk_id")
        scene_id = validated_request_data.get("scene_id")
        nodes = TicketNode.objects.filter(action="AutoProcess")
        # 套餐筛选 / 场景范围：套餐 → 规则 → 风险 → 执行节点
        if pa_id or scene_id:
            pa_queryset = ProcessApplication.objects.all()
            if pa_id:
                pa_queryset = pa_queryset.filter(id=pa_id)
            if scene_id:
                pa_queryset = SceneScopeFilter.filter_queryset(
                    queryset=pa_queryset,
                    scene_id=scene_id,
                    resource_type=ResourceVisibilityType.PROCESS_APPLICATION,
                    pk_field="id",
                )
            rule_ids = RiskRule.objects.filter(pa_id__in=pa_queryset.values("id")).values("rule_id")
            nodes = nodes.filter(risk_id__in=Risk.objects.filter(rule_id__in=rule_ids).values("risk_id"))
        # 风险入口：按风险 ID 筛选
        if risk_id:
            nodes = nodes.filter(risk_id=risk_id)
        nodes = nodes.order_by("-timestamp")
        # 批量装配：风险信息 + 套餐信息
        risk_map = {
            risk["risk_id"]: risk
            for risk in Risk.objects.filter(risk_id__in=[n.risk_id for n in nodes]).values(
                "risk_id", "title", "status", "rule_id"
            )
        }
        rule_pa_map = {}
        for item in RiskRule.objects.filter(
            rule_id__in={r["rule_id"] for r in risk_map.values() if r["rule_id"]}
        ).values("rule_id", "pa_id"):
            rule_pa_map.setdefault(item["rule_id"], item["pa_id"])
        pa_name_map = {
            pa["id"]: pa["name"]
            for pa in ProcessApplication.objects.filter(id__in=set(rule_pa_map.values())).values("id", "name")
        }
        records = []
        for node in nodes:
            risk = risk_map.get(node.risk_id, {})
            process_result = node.process_result or {}
            # 套餐归属：优先取执行时快照（手动分派/规则改绑套餐均正确），历史节点无快照时走规则链路兜底
            pa_id_of_record = process_result.get("pa_id") or rule_pa_map.get(risk.get("rule_id"))
            state = (process_result.get("status") or {}).get("state", "")
            if state in SOPSTaskStatus.get_success_status():
                result = "success"
            elif state in SOPSTaskStatus.get_failed_status():
                result = "failed"
            elif state:
                result = "running"
            else:
                result = "unknown"
            records.append(
                {
                    "id": node.id,
                    "risk_id": node.risk_id,
                    "risk_title": risk.get("title") or "",
                    "risk_status": risk.get("status") or "",
                    "pa_id": pa_id_of_record or 0,
                    "pa_name": process_result.get("pa_name") or pa_name_map.get(pa_id_of_record, ""),
                    "operator": node.operator,
                    "time": node.time,
                    "sops_task_id": str((process_result.get("task") or {}).get("task_id", "") or ""),
                    "sops_state": state,
                    "result": result,
                    "task_name": process_result.get("task_name") or "",
                    "trigger": process_result.get("trigger") or "",
                    "duration": self._calc_duration(process_result.get("status") or {}),
                }
            )
        return records


class ToggleProcessApplication(ProcessApplicationMeta):
    name = gettext_lazy("启停处理套餐")
    RequestSerializer = ToggleProcessApplicationReqSerializer
    audit_action = ActionEnum.EDIT_PA

    def perform_request(self, validated_request_data):
        pa = get_object_or_404(ProcessApplication, id=validated_request_data["id"])
        _reject_builtin_edit(pa)
        pa.is_enabled = validated_request_data["is_enabled"]
        pa.save(update_fields=["is_enabled"])


class ApproveBuildInFields(ProcessApplicationMeta):
    name = gettext_lazy("审批内置字段")

    def perform_request(self, validated_request_data):
        return [
            {"id": getattr(ApproveTicketFields, f).key, "name": getattr(ApproveTicketFields, f).key}
            for f in dir(ApproveTicketFields)
            if not f.startswith("_") and f not in ["RISK_LEVEL", "DESCRIPTION"]
        ]
