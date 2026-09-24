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
from typing import Optional

from django.db import transaction

from services.web.risk.bksec.config import BkSecConfig
from services.web.risk.bksec.constants import (
    BKSEC_AUTO_RULE_NAME,
    BKSEC_PRESET_PA_DESCRIPTION,
    BKSEC_PRESET_PA_NAME,
    BKSEC_RULE_PRIORITY_BASE,
)
from services.web.risk.bksec.contract import build_pa_params
from services.web.risk.models import ProcessApplication, RiskRule
from services.web.scene.constants import ResourceVisibilityType
from services.web.scene.filters import BindingMetadataHelper
from services.web.scene.models import ResourceBindingScene
from services.web.strategy_v2.constants import StrategyStatusChoices
from services.web.strategy_v2.models import Strategy

logger = logging.getLogger("celery")


def load_bksec_config(strategy: Optional[Strategy]) -> Optional[BkSecConfig]:
    """
    解析策略的 BKSEC 配置
    """
    if not strategy:
        return None
    raw = strategy.bksec_config
    if not raw:
        return None
    try:
        return BkSecConfig.model_validate(raw)
    except Exception as err:  # NOCC:broad-except(配置解析降级)
        logger.exception("[BkSecRule] Invalid bksec_config, strategy_id=%s err=%s", strategy.strategy_id, err)
        return None


def is_bksec_enabled(strategy: Optional[Strategy]) -> bool:
    config = load_bksec_config(strategy)
    return bool(config and config.enabled)


def ensure_preset_pa() -> Optional[ProcessApplication]:
    """
    获取/修复 预置 BKSEC 发单处理套餐

    1. 套餐不存在 + 配置了 BKSEC_SOPS_TEMPLATE_ID	自动创建一个预置处理套餐（名称“【内置】BKSEC安全工单发单”、指向该模板、need_approve=False、启用、打内置标记）
    2. 套餐存在，但sops模板 ID 与环境变量不一致 / 被停用	自愈：按环境变量校正模板 ID、强制启用（换模板只需改环境变量，下次保存策略自动生效）
    3. 未配置环境变量	返回内置处理套餐，无内置处理套餐时返回友好报错提示
    """
    from django.conf import settings

    pa = ProcessApplication.objects.filter(is_builtin=True).order_by("-id").first()
    template_id = settings.BKSEC_SOPS_TEMPLATE_ID
    if not template_id:
        return pa
    try:
        template_id = int(template_id)
    except (TypeError, ValueError):
        logger.exception("[BkSecRule] Invalid BKSEC_SOPS_TEMPLATE_ID: %s", settings.BKSEC_SOPS_TEMPLATE_ID)
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
        logger.info("[BkSecRule] Preset process application created, id=%s template=%s", pa.id, template_id)
        return pa
    if pa.sops_template_id != template_id or not pa.is_enabled:
        pa.sops_template_id = template_id
        pa.need_approve = False
        pa.is_enabled = True
        pa.save(update_fields=["sops_template_id", "need_approve", "is_enabled"])
    return pa


def _load_strategy_scene_id(strategy: Strategy) -> Optional[int]:
    """
    返回策略归属场景（处理规则需要绑定到策略所在场景）
    """
    return (
        ResourceBindingScene.objects.filter(
            scene__is_deleted=False,
            binding__resource_type=ResourceVisibilityType.STRATEGY,
            binding__resource_id=str(strategy.strategy_id),
        )
        .values_list("scene_id", flat=True)
        .first()
    )


def _is_platform_strategy(strategy_id: int) -> bool:
    """
    是否平台/全局策略（PLATFORM_BINDING）
    """
    from services.web.scene.constants import BindingType
    from services.web.scene.models import ResourceBinding

    return ResourceBinding.objects.filter(
        resource_type=ResourceVisibilityType.STRATEGY,
        resource_id=str(strategy_id),
        binding_type=BindingType.PLATFORM_BINDING,
    ).exists()


def _next_rule_id() -> int:
    latest = RiskRule.objects.order_by("-rule_id").first()
    return (latest.rule_id or 0) + 1 if latest else 1


def _top_priority() -> int:
    """
    自动规则优先级：保留段内取值（结构性最高，手动规则恒低于本段）
    """
    latest = RiskRule.objects.filter(priority_index__gte=BKSEC_RULE_PRIORITY_BASE).order_by("-priority_index").first()
    return (latest.priority_index + 1) if latest else BKSEC_RULE_PRIORITY_BASE


def _latest_auto_rule(strategy_id: int) -> Optional[RiskRule]:
    return RiskRule.objects.filter(auto_strategy_id=strategy_id).order_by("-version").first()


def _build_rule_fields(strategy: Strategy, config: BkSecConfig, pa_id: int) -> dict:
    return {
        "name": str(BKSEC_AUTO_RULE_NAME) % strategy.strategy_id,
        "scope": [{"field": "strategy_id", "operator": "=", "value": [strategy.strategy_id]}],
        "pa_id": pa_id,
        "pa_params": build_pa_params(config),
        # 评审定论：审计风险闭环由人工判定，BKSEC 工单办结（SOPS 任务成功）不自动关风险——
        # 复用既有"成功不关单"路径：任务完成后风险转 AWAIT_PROCESS、处理人转节点处理人/安全责任人
        "auto_close_risk": False,
    }


def _create_rule_version(strategy: Strategy, fields: dict, rule_id: Optional[int] = None) -> RiskRule:
    """
    创建启用的规则新版本（仅内容变更时调用）。
    """
    if rule_id:
        latest = RiskRule.objects.filter(rule_id=rule_id).order_by("-version").first()
        instance = RiskRule.objects.create(
            **fields,
            rule_id=rule_id,
            version=(latest.version + 1) if latest else 1,
            priority_index=_top_priority(),
            created_at=latest.created_at if latest else None,
            created_by=latest.created_by if latest else "",
            auto_strategy_id=strategy.strategy_id,
            is_enabled=True,
        )
        return instance
    with transaction.atomic():
        instance = RiskRule.objects.create(
            **fields,
            version=1,
            is_enabled=True,
            auto_strategy_id=strategy.strategy_id,
        )
        instance.rule_id = instance.id or _next_rule_id()
        instance.priority_index = _top_priority()
        instance.save(update_fields=["rule_id", "priority_index"])
        # 绑定到策略所在场景
        scene_id = _load_strategy_scene_id(strategy)
        if scene_id:
            BindingMetadataHelper.create_resource_binding(
                resource_id=str(instance.rule_id),
                resource_type=ResourceVisibilityType.RISK_RULE,
                scene_id=scene_id,
            )
    return instance


def _toggle_rule(rule: Optional[RiskRule], is_enabled: bool) -> None:
    """
    原地切换启停
    """
    if rule and rule.is_enabled != is_enabled:
        rule.is_enabled = is_enabled
        rule.save(update_fields=["is_enabled"])
        logger.info("[BkSecRule] Auto rule toggled, rule_id=%s enabled=%s", rule.rule_id, is_enabled)


def _strategy_alive(strategy: Strategy) -> bool:
    """
    策略是否处于启用态（非停用、非草稿）
    """
    return strategy.status not in (StrategyStatusChoices.DISABLED, StrategyStatusChoices.DRAFT)


@transaction.atomic
def sync_bksec_rule(strategy: Strategy, strategy_alive: Optional[bool] = None) -> Optional[RiskRule]:
    """
    策略保存后自动同步处理规则：
        1. 无处理规则时新建
        2. 有处理规则时
            2.1 启停状态有变更：根据策略的bksec配置状态更新处理规则的启停状态
            2.2 内容有变更：创建启用的新版本

    规则生效条件 = bksec_config.enabled AND 策略启用态。
    strategy_alive：显式覆盖策略存活判断——ToggleStrategy 的启停经 celery 异步落库，
    调用瞬间 strategy.status 仍是旧值，须由调用方传入方向（True=启用 / False=停用）。
    """
    config = load_bksec_config(strategy)
    latest = _latest_auto_rule(strategy.strategy_id)
    alive = _strategy_alive(strategy) if strategy_alive is None else strategy_alive
    # 未启用（配置关 或 策略停用）→ 原地停用已有规则
    if not (config and config.enabled and alive):
        _toggle_rule(latest, is_enabled=False)
        return None
    # 启用 → 平台策略不支持，跳过并告警
    if _is_platform_strategy(strategy.strategy_id):
        logger.warning(
            "[BkSecRule] Platform strategy is out of BKSEC scope, skip rule sync, strategy_id=%s",
            strategy.strategy_id,
        )
        return None
    # 启用 → 确保预置套餐存在
    pa = ensure_preset_pa()
    if pa is None:
        logger.warning(
            "[BkSecRule] Preset process application missing (BKSEC_SOPS_TEMPLATE_ID unset?), "
            "skip rule sync, strategy_id=%s",
            strategy.strategy_id,
        )
        return None
    fields = _build_rule_fields(strategy, config, pa.id)
    # 幂等：内容一致 → 仅原地确保启用
    if latest and all(getattr(latest, k) == v for k, v in fields.items()):
        _toggle_rule(latest, is_enabled=True)
        # Config 同步：即使规则内容未变，插件侧凭证/配方可能更新（如用户改了 target_type）
        sync_plugin_config(strategy, config)
        return latest
    # 内容变化/首次 → 创建启用的新版本
    instance = _create_rule_version(strategy, fields, rule_id=latest.rule_id if latest else None)
    logger.info(
        "[BkSecRule] Auto rule synced, strategy_id=%s rule_id=%s version=%s",
        strategy.strategy_id,
        instance.rule_id,
        instance.version,
    )
    # 方案 1：规则同步成功后，顺带同步插件 Config（失败仅告警，不阻断）
    sync_plugin_config(strategy, config)
    return instance


def disable_bksec_rule(strategy_id: int) -> None:
    """
    停用策略的自动发单规则
    """
    _toggle_rule(_latest_auto_rule(strategy_id), is_enabled=False)


def sync_plugin_config(strategy: Strategy, config: BkSecConfig) -> None:
    """
    同步插件 Config（方案 1）：调插件 upsert API 写入 Config 记录。

    凭证现取现推（token 不落审计中心库，避免序列化泄露）。
    失败上报监控平台（BkSecConfigSyncFailedEvent，与资产同步异常同机制），不阻断策略保存。
    """
    from django.conf import settings

    from services.web.common.monitor import BkSecConfigSyncFailedEvent

    api_url = getattr(settings, "BKSEC_PLUGIN_CONFIG_API_URL", None)
    if not api_url:
        logger.warning("[BkSecPluginConfig] BKSEC_PLUGIN_CONFIG_API_URL not set, skip plugin config sync")
        return

    # 凭证：从 risk_access detail 现取（data_id = risk_type_id）
    try:
        from bk_resource import api

        detail = api.bk_sec.risk_access_retrieve.perform_request({"id": config.risk_type_id})
        token = (detail or {}).get("token", "")
    except Exception as err:  # NOCC:broad-except(凭证获取失败上报监控)
        logger.warning("[BkSecPluginConfig] Fetch risk_access failed, skip: %s", err)
        BkSecConfigSyncFailedEvent(
            context={"strategy_id": str(strategy.strategy_id), "stage": "fetch_token", "error": str(err)},
        ).report()
        return

    plugin_config = {
        "raw_data": {
            "data_id": int(config.risk_type_id) if config.risk_type_id.isdigit() else config.risk_type_id,
            "token": token,
            "target_type": config.target_type,
            "source_type": "bk-audit",
        },
        "operator": {"field_path": "operator"},
        "target": {"field_path": "event_data.target"},
        "risk_evidence": {"display_fields": []},
        "custom_data": {"fields": []},
    }

    import requests as _requests

    try:
        resp = _requests.post(
            api_url,
            json={"strategy_id": str(strategy.strategy_id), "config": plugin_config},
            headers={"Content-Type": "application/json"},
            timeout=10,
        )
        result = resp.json()
        if result.get("result"):
            logger.info("[BkSecPluginConfig] Synced, strategy_id=%s", strategy.strategy_id)
        else:
            logger.warning("[BkSecPluginConfig] Upsert rejected: %s", result.get("message"))
            BkSecConfigSyncFailedEvent(
                context={
                    "strategy_id": str(strategy.strategy_id),
                    "stage": "upsert_rejected",
                    "error": str(result.get("message")),
                },
            ).report()
    except Exception as err:  # NOCC:broad-except(插件不可达上报监控，不阻断策略保存)
        logger.warning("[BkSecPluginConfig] Sync failed, strategy_id=%s err=%s", strategy.strategy_id, err)
        BkSecConfigSyncFailedEvent(
            context={"strategy_id": str(strategy.strategy_id), "stage": "api_unreachable", "error": str(err)},
        ).report()
