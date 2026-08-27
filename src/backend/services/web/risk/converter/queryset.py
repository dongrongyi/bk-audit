# -*- coding: utf-8 -*-

import operator
from functools import reduce

from django.db.models import Q
from iam.contrib.converter.queryset import PathEqDjangoQuerySetConverter
from iam.eval.constants import KEYWORD_BK_IAM_PATH, OP

from services.web.scene.constants import ResourceVisibilityType
from services.web.scene.models import ResourceBindingScene

# IAM 路径中场景前缀标识
_SCENE_PATH_PREFIX = "/scene,"


def _parse_resource_id(value: str) -> str:
    """从 IAM path 值中提取 resource_id

    支持格式：'/scene,100001/' → '100001', '/strategy,123/' → '123'
    """
    return value[1:-1].split(",")[1]


class RiskPathEqDjangoQuerySetConverter(PathEqDjangoQuerySetConverter):
    """Risk 的 IAM 策略 → Django Q 转换器

    支持两种 IAM 路径：
    - /scene,{scene_id}/  → 场景绑定的策略产生的风险 ∪ 分派到该场景的风险（RISK 绑定）
    - /strategy,{strategy_id}/  → 直接匹配 strategy_id（兼容旧路径）
    """

    def __init__(self):
        key_mapping = {
            "risk.id": "risk_id",
            "risk.risk_id": "risk_id",
        }
        super().__init__(key_mapping)

    def convert(self, data):
        """重写 convert，拦截 _bk_iam_path_ 路径做场景/策略分发处理"""
        op = data.get("op")

        # 非叶子节点（AND/OR），走默认递归
        if op in (OP.AND, OP.OR):
            return super().convert(data)

        field = data.get("field", "")
        value = data.get("value", "")

        # 仅对 _bk_iam_path_ 字段做特殊处理
        if field == f"risk.{KEYWORD_BK_IAM_PATH}":
            return self._convert_path(value)

        # 其他字段走默认流程
        return super().convert(data)

    @staticmethod
    def _get_scene_strategy_ids(scene_id: str) -> list:
        """场景绑定的策略 ID（int，与 Risk.strategy_id 类型对齐）"""
        bound_strategy_ids = ResourceBindingScene.objects.filter(
            binding__resource_type=ResourceVisibilityType.STRATEGY,
            scene_id=scene_id,
            scene__is_deleted=False,
        ).values_list("binding__resource_id", flat=True)
        int_ids = []
        for sid in bound_strategy_ids:
            try:
                int_ids.append(int(sid))
            except (TypeError, ValueError):
                continue
        return int_ids

    @staticmethod
    def _get_scene_risk_ids(scene_id: str) -> list:
        """分派到该场景的风险 ID（RISK 绑定 resource_id 与 Risk.risk_id 同为 str）"""
        return list(
            ResourceBindingScene.objects.filter(
                binding__resource_type=ResourceVisibilityType.RISK,
                scene_id=scene_id,
                scene__is_deleted=False,
            ).values_list("binding__resource_id", flat=True)
        )

    def _convert_path(self, value) -> Q:
        """根据路径值判断是场景路径还是策略路径，返回对应的 Q 对象"""
        if isinstance(value, (list, tuple)):
            if not value:
                return Q(pk__in=[])
            return reduce(operator.or_, [self._convert_path(v) for v in value])

        if value.startswith(_SCENE_PATH_PREFIX):
            # /scene,{scene_id}/ → 场景下风险 = 场景绑定策略的风险 ∪ 分派到该场景的风险（RISK 绑定单轨制）。
            # 全局策略为 platform_binding、不在场景的策略集合内，仅按策略反查会漏掉已分派风险，导致场景授权失效。
            scene_id = _parse_resource_id(value)
            scene_q = Q(strategy_id__in=self._get_scene_strategy_ids(scene_id))
            scene_q |= Q(risk_id__in=self._get_scene_risk_ids(scene_id))
            return scene_q

        # 兼容旧路径：/strategy,{strategy_id}/
        strategy_id = _parse_resource_id(value)
        try:
            return Q(strategy_id=int(strategy_id))
        except (TypeError, ValueError):
            return Q(strategy_id=strategy_id)
