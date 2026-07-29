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

from bk_resource import resource
from bk_resource.settings import bk_resource_settings
from blueapps.contrib.celery_tools.periodic import periodic_task
from blueapps.utils.logger import logger_celery
from celery.schedules import crontab
from django.conf import settings
from django.db import transaction

from core.lock import lock
from services.web.scene.constants import (
    SCENE_PERMISSION_GRANT_MAX_RETRY,
    SYNC_SCENE_PERMISSION_PERIODIC_TASK_MINUTE,
)
from services.web.scene.models import Scene, ScenePermissionApplication
from services.web.scene.permission import _do_grant, apply_ticket_result
from services.web.scene.resources import SceneResource


# ==================== 场景成员同步（原有任务，每 10 分钟）====================


@periodic_task(run_every=crontab(minute="*/10"), time_limit=settings.DEFAULT_CACHE_LOCK_TIMEOUT)
@lock(load_lock_name=lambda **kwargs: "celery:sync_scene_members_from_iam")
def sync_scene_members_from_iam():
    """定时同步场景成员（从 IAM 刷新到本地 DB）"""

    success_count = 0
    fail_count = 0

    for scene in Scene.objects.all().only(
        "scene_id",
        "name",
        "managers",
        "users",
        "iam_manager_group_id",
        "iam_viewer_group_id",
    ):
        try:
            SceneResource._refresh_scene_members_from_iam(scene)
            success_count += 1
        except Exception as err:  # pylint: disable=broad-except
            fail_count += 1
            logger_celery.exception(
                "[sync_scene_members_from_iam] 同步场景成员失败, scene_id=%s, error=%s",
                scene.scene_id,
                err,
            )

    logger_celery.info(
        "[sync_scene_members_from_iam] finished, success_count=%s, fail_count=%s",
        success_count,
        fail_count,
    )


# ==================== 场景权限申请审批状态同步（新增任务，每 10 分钟）====================


@periodic_task(
    run_every=crontab(minute=SYNC_SCENE_PERMISSION_PERIODIC_TASK_MINUTE),
    queue="default",
    time_limit=settings.DEFAULT_CACHE_LOCK_TIMEOUT,
)
@lock(lock_name="celery:sync_scene_permission_status")
def sync_scene_permission_status():
    """轮询 ITSM V4 审批状态 + 重试 GRANT_FAILED 授权。

    阶段一：同步 PENDING 单的 ITSM 状态（审批通过则触发授权）
    阶段二：重试 GRANT_FAILED（审批已通过、仅授权失败），retry_count < MAX 才重试
    """
    operator = bk_resource_settings.PLATFORM_AUTH_ACCESS_USERNAME

    # 阶段一：同步 PENDING
    # select_related("scene") 避免 _do_grant 访问 application.scene 时 N+1 查询
    pending_qs = (
        ScenePermissionApplication.objects.select_related("scene")
        .filter(status=ScenePermissionApplication.Status.PENDING)
        .exclude(itsm_sn="")
    )
    for application in pending_qs:
        try:
            with transaction.atomic():
                application = (
                    ScenePermissionApplication.objects.select_for_update()
                    .select_related("scene")
                    .get(id=application.id)
                )
                if application.status != ScenePermissionApplication.Status.PENDING:
                    continue  # 并发已被处理
                ticket = resource.itsm.get_system_ticket_list(sn=application.itsm_sn)
                if not ticket:
                    continue  # 查不到，跳过等下次
                apply_ticket_result(application, ticket, operator=operator)
                application.save()
        except Exception as err:  # pylint: disable=broad-except
            logger_celery.exception(
                "[sync_scene_permission_status] PENDING 单 %s 失败: %s", application.id, err
            )

    # 阶段二：重试授权失败（审批已通过、仅授权失败），retry_count < MAX 才重试
    failed_qs = (
        ScenePermissionApplication.objects.select_related("scene")
        .filter(
            status=ScenePermissionApplication.Status.APPROVED,
            grant_status=ScenePermissionApplication.GrantStatus.FAILED,
            retry_count__lt=SCENE_PERMISSION_GRANT_MAX_RETRY,
        )
        .exclude(itsm_sn="")
    )
    for application in failed_qs:
        try:
            with transaction.atomic():
                application = (
                    ScenePermissionApplication.objects.select_for_update()
                    .select_related("scene")
                    .get(id=application.id)
                )
                if application.grant_status != ScenePermissionApplication.GrantStatus.FAILED:
                    continue
                _do_grant(application, operator=operator)
                application.save()
        except Exception as err:  # pylint: disable=broad-except
            # _do_grant 内部已 catch 异常并自增 retry_count；
            # 此处仅兜底 get/save 等基础设施异常，不重复计数（下个周期自然重试）
            logger_celery.exception(
                "[sync_scene_permission_status] 授权失败重试 %s 失败: %s", application.id, err
            )
