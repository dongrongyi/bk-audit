# -*- coding: utf-8 -*-
"""
数据迁移：为存量 Risk 建立 ResourceBinding(RISK) + ResourceBindingScene 记录。

背景：
- 本项目历史上 Risk 的场景归属通过 `strategy_id → ResourceBinding(STRATEGY) → ResourceBindingScene`路径反查得到。
- 新特性引入全局策略后，Risk 的场景归属变为运行时决定（DispatchRule.target_scene_id），策略侧的 binding 不再能唯一表达"这条 Risk 属于哪个场景"。
- 决策：Risk 使用 ResourceBinding 单轨制记录自身场景归属

本迁移要做的：
- 遍历存量 Risk，通过其 strategy_id 查到该策略绑定的 scene_id
- 为每条 Risk 创建 ResourceBinding(resource_type=risk) + ResourceBindingScene 记录（幂等）
- 找不到 scene_id 的孤儿 Risk（策略已删/无绑定）跳过，保留 NULL 场景归属

执行方式（端到端分批，内存有界）：
- keyset 分页（risk_id 升序游标）逐批扫描 Risk，每批内完成 查重 → 建 binding → 建场景关联 后立即释放，
  不再全量累积 existing_risk_ids / to_create_by_scene（大表下全量容器有 OOM 风险）；
- 迁移不包整体事务（atomic = False，与 0027 一致）：MySQL 纯 DML 迁移本就不会整体包裹，
  显式声明固定该语义；中途失败时因幂等设计可直接重跑续传。

风险的场景归属通过 scene.ResourceBinding(resource_type=RISK) + ResourceBindingScene 建立，写入路径按策略类型分散到不同节点
- 场景策略：create_risk 创建 Risk 后立即写（scene_id 来自 strategy 的 ResourceBindingScene）
- 全局策略 direct：分派规则匹配、dispatch_rule 写回后写（scene_id 来自 DispatchRule.target_scene）
- 全局策略 after_confirm：confirmer 确认后写（PENDING_CONFIRM 阶段不建 binding）
"""

from django.db import migrations
from django.db.models import Count, Max, Q
from django.db.models.functions import Length

# 分批处理：扫描/查重/写入均按该批量进行，保证内存上界
BATCH_SIZE = 5000
# resource_type / binding_type 直接使用字符串常量，避免 apps.get_model 无法拿到 TextChoices
RESOURCE_TYPE_RISK = "risk"
RESOURCE_TYPE_STRATEGY = "strategy"
BINDING_TYPE_SCENE = "scene_binding"
# 进度日志间隔（批数）
PROGRESS_LOG_INTERVAL = 20
# 存储契约防御：Risk.risk_id 声明为 max_length=255，ResourceBinding.resource_id 仅 64。
# 当前 risk_id 由 generate_risk_id() 定长生成（14 位时间戳 + 6 位小数秒 = 20 字符），常规不会超限；
# 但为防未来 ID 规则变化/外部导入产生长 ID（严格模式 DataError、非严格模式截断错绑），
# 写入前做长度检查，超长 ID 跳过并显式告警，不中断迁移（与幂等重跑语义兼容）。
RESOURCE_ID_MAX_LENGTH = 64


def forwards(apps, schema_editor):
    """为存量 Risk 反查 strategy 场景，keyset 逐批补建 RISK 绑定（幂等、内存有界、可断点重跑）。"""
    Risk = apps.get_model("risk", "Risk")
    ResourceBinding = apps.get_model("scene", "ResourceBinding")
    ResourceBindingScene = apps.get_model("scene", "ResourceBindingScene")

    print("[forwards] 开始为存量 Risk 建立 RISK 场景绑定", flush=True)

    # 0. preflight：发布前数据体检——输出存量 risk_id 最大长度与超长数量，超长则高亮告警
    #    （仅一条聚合查询；批内仍会逐条防御，此处用于提前暴露规模、辅助决策是否需要先做数据治理。
    #    注意：CharField 未默认注册 length transform，需显式 annotate Length()）
    preflight = Risk.objects.annotate(risk_id_length=Length("risk_id")).aggregate(
        max_risk_id_length=Max("risk_id_length"),
        oversize_count=Count("risk_id", filter=Q(risk_id_length__gt=RESOURCE_ID_MAX_LENGTH)),
    )
    print(
        f"[forwards][preflight] MAX(CHAR_LENGTH(risk_id)) = {preflight['max_risk_id_length']}，"
        f"长度 > {RESOURCE_ID_MAX_LENGTH} 的存量风险 = {preflight['oversize_count']} 条",
        flush=True,
    )
    if preflight["oversize_count"]:
        print(
            f"[forwards][preflight][WARN] 存在超长 risk_id（> {RESOURCE_ID_MAX_LENGTH}），"
            "对应风险将被跳过（不建 RISK 绑定，场景视图不可见）；"
            "请先执行数据治理或扩容 ResourceBinding.resource_id 后重跑本迁移",
            flush=True,
        )

    # 1. 一次性拉取 strategy_id -> scene_id 映射（量级 = 策略数，可全量驻留内存）
    strategy_scene_map = {
        str(strategy_id): scene_id
        for strategy_id, scene_id in ResourceBindingScene.objects.filter(
            binding__resource_type=RESOURCE_TYPE_STRATEGY,
            binding__binding_type=BINDING_TYPE_SCENE,
            scene__is_deleted=False,
        ).values_list("binding__resource_id", "scene_id")
    }
    print(f"[forwards] 加载 strategy->scene 映射 {len(strategy_scene_map)} 条", flush=True)

    if not strategy_scene_map:
        print("[forwards] 无策略场景绑定，跳过 Risk 绑定回填", flush=True)
        return

    # 2. keyset 分页逐批扫描 Risk：每批内 查重 -> 分组 -> 写入 -> 释放
    #    游标字段用主键 risk_id（CharField，排序与比较使用同一排序规则，分页一致）
    total_scanned = 0
    skipped_existing = 0
    skipped_no_strategy_binding = 0
    skipped_too_long = 0
    created_binding_total = 0
    created_scene_total = 0
    batch_index = 0
    last_risk_id = ""

    while True:
        batch = list(
            Risk.objects.exclude(strategy_id__isnull=True)
            .filter(risk_id__gt=last_risk_id)
            .order_by("risk_id")
            .values_list("risk_id", "strategy_id")[:BATCH_SIZE]
        )
        if not batch:
            break
        last_risk_id = batch[-1][0]
        total_scanned += len(batch)
        batch_index += 1

        # 2.1 批内查重：已有 RISK 绑定的风险跳过（幂等，支持失败后重跑续传）
        existing_risk_ids = set(
            ResourceBinding.objects.filter(
                resource_type=RESOURCE_TYPE_RISK,
                resource_id__in=[risk_id for risk_id, _ in batch],
            ).values_list("resource_id", flat=True)
        )

        # 2.2 批内按目标场景分组
        to_create_by_scene = {}  # scene_id -> [risk_id, ...]，仅本批，处理完随批释放
        for risk_id, strategy_id in batch:
            if risk_id in existing_risk_ids:
                skipped_existing += 1
                continue
            # 存储契约防御：超长 risk_id 写入 ResourceBinding.resource_id(64) 会
            # 严格模式 DataError / 非严格模式截断错绑，跳过并计数，汇总时显式告警
            if len(risk_id) > RESOURCE_ID_MAX_LENGTH:
                skipped_too_long += 1
                continue
            scene_id = strategy_scene_map.get(str(strategy_id))
            if scene_id is None:
                skipped_no_strategy_binding += 1
                continue
            to_create_by_scene.setdefault(scene_id, []).append(risk_id)

        # 2.3 写入：先建 ResourceBinding，再取回主键建 ResourceBindingScene
        for scene_id, risk_id_list in to_create_by_scene.items():
            ResourceBinding.objects.bulk_create(
                [
                    ResourceBinding(
                        resource_type=RESOURCE_TYPE_RISK,
                        resource_id=risk_id,
                        binding_type=BINDING_TYPE_SCENE,
                    )
                    for risk_id in risk_id_list
                ],
                batch_size=BATCH_SIZE,
                ignore_conflicts=True,
            )
            # 取回本批 binding id（含幂等重跑时已存在、本次跳过未建的行）
            binding_pairs = list(
                ResourceBinding.objects.filter(
                    resource_type=RESOURCE_TYPE_RISK,
                    resource_id__in=risk_id_list,
                ).values_list("id", "resource_id")
            )
            created_binding_total += len(binding_pairs)

            # 建场景关联前过滤已存在的（batch 范围内查重，代价有界）
            existing_scene_binding_ids = set(
                ResourceBindingScene.objects.filter(
                    binding_id__in=[binding_id for binding_id, _ in binding_pairs],
                    scene_id=scene_id,
                ).values_list("binding_id", flat=True)
            )
            scene_rows = [
                ResourceBindingScene(binding_id=binding_id, scene_id=scene_id)
                for binding_id, _ in binding_pairs
                if binding_id not in existing_scene_binding_ids
            ]
            if scene_rows:
                ResourceBindingScene.objects.bulk_create(
                    scene_rows,
                    batch_size=BATCH_SIZE,
                    ignore_conflicts=True,
                )
                created_scene_total += len(scene_rows)

        if batch_index % PROGRESS_LOG_INTERVAL == 0:
            print(
                f"[forwards] 进度：已扫描 {total_scanned} 条；累计 binding={created_binding_total}, "
                f"scene_link={created_scene_total}",
                flush=True,
            )

    print(
        f"[forwards] 扫描完成：Risk {total_scanned} 条；新建/复用 RISK 绑定 {created_binding_total} 条，"
        f"新增场景关联 {created_scene_total} 条；已存在跳过 {skipped_existing} 条，"
        f"孤儿 Risk（策略无场景绑定）跳过 {skipped_no_strategy_binding} 条，"
        f"超长 risk_id（> {RESOURCE_ID_MAX_LENGTH}，存储契约不兼容）跳过 {skipped_too_long} 条",
        flush=True,
    )
    if skipped_too_long:
        print(
            f"[forwards][WARN] 存在 {skipped_too_long} 条超长 risk_id 未建绑定（场景视图不可见），"
            "请执行数据治理（收敛 risk_id 长度）或扩容 ResourceBinding.resource_id 后重跑本迁移",
            flush=True,
        )
    print("[forwards] 数据迁移完成", flush=True)


def backwards(apps, schema_editor):
    """
    回滚：noop（声明为不可逆）。

    本迁移为存量 Risk 回填 ResourceBinding(resource_type=risk)，但创建时未打任何
    可区分标记；0060 上线后业务运行时（场景策略 create_risk、全局策略 direct /
    after_confirm 确认后）也会持续写入同类型 binding，两者无法可靠区分。

    因此若在此执行全量删除会误删 0060 之后业务新建的有效绑定，并级联清空
    ResourceBindingScene / ResourceBindingSystem，导致线上回滚后全量 Risk 丢失
    场景归属。

    改为 noop：回滚不删除任何 RISK binding。保留的数据对回退后的老代码无害——
    老代码通过 strategy_id -> ResourceBinding(STRATEGY) -> ResourceBindingScene
    反查场景归属，并不依赖 resource_type=risk 的 binding。
    """
    print(
        "[backwards] 0060 为存量和运行时混合绑定，无法精准识别本迁移创建记录，"
        "回滚不删除任何 RISK binding（不可逆）。如需回滚请走数据恢复流程。",
        flush=True,
    )


class Migration(migrations.Migration):
    """
    存量 Risk 场景绑定回填（keyset 逐批、幂等、不包整体事务）。
    """

    # 大表回填：显式关闭整体事务，配合批内幂等实现断点重跑；
    # MySQL 纯 DML 迁移本就不会整体包裹，此处声明固定语义（与 0027 一致）
    atomic = False

    dependencies = [
        ("risk", "0059_add_multi_rule_fields"),
        ("strategy_v2", "0027_migrate_rules_data"),
        ("scene", "0013_alter_resourcebinding_visibility_type"),
    ]

    operations = [
        migrations.RunPython(forwards, backwards),
    ]
