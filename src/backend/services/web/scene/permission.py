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

from typing import Optional, Union

from blueapps.utils.logger import logger
from bk_resource.settings import bk_resource_settings
from django.utils.translation import gettext
from django.utils import timezone

from apps.meta.handlers.iam_group import IAMGroupManager
from apps.permission.constants import IAMV4Role
from apps.permission.handlers.resource_types import ResourceEnum
from apps.permission.handlers.service import PermissionService
from services.web.scene.constants import ITSMV4TicketStatus, SCENE_ROLE_TO_IAM_V4_ROLE, SceneRole
from services.web.scene.models import Scene, ScenePermissionApplication


def grant_scene_role(scene: Scene, role: str, username: str, operator: Optional[str] = None) -> dict:
    """授予场景角色（V3/V4 自适应）。仅授予单人，不影响其他成员。

    :param scene: Scene 实例
    :param role: SceneRole.MANAGER / SceneRole.USER
    :param username: 被授权人
    :param operator: 操作人（用于 IAM 审计）
    :return: {"success": bool, "method": str, ...}
    """
    operator = operator or bk_resource_settings.PLATFORM_AUTH_ACCESS_USERNAME

    # ---- V4：授 role ----
    if IAMGroupManager.is_v4_backend():
        role_id = SCENE_ROLE_TO_IAM_V4_ROLE[role]
        # 幂等：已有该 role 则跳过
        if username in IAMGroupManager.get_scene_role_members(role_id, str(scene.scene_id)):
            logger.info("[grant_scene_role] %s 已有 %s on scene %s，跳过", username, role_id, scene.scene_id)
            return {"success": True, "method": "v4_role_grant", "skipped": True}
        service = PermissionService(username=operator)
        service.grant_instance_permission(
            role_id=role_id,
            subject={"type": "user", "id": username},
            resources=[ResourceEnum.SCENE.create_instance(str(scene.scene_id))],
            operator=operator,
        )
        logger.info("[grant_scene_role] V4 授权成功 %s -> %s on scene %s", username, role_id, scene.scene_id)
        return {"success": True, "method": "v4_role_grant"}

    # ---- V3：加用户组成员 ----
    group_id = scene.iam_manager_group_id if role == SceneRole.MANAGER else scene.iam_viewer_group_id
    if not group_id:
        logger.warning("[grant_scene_role] V3 场景 %s 用户组未创建", scene.scene_id)
        return {"success": False, "error": gettext("场景用户组未创建")}
    IAMGroupManager.add_group_members(group_id=group_id, members=[username])
    logger.info("[grant_scene_role] V3 加组成员 %s -> group %s", username, group_id)
    return {"success": True, "method": "v3_group_add", "group_id": group_id}


def apply_ticket_result(
    application: ScenePermissionApplication, ticket_data: dict, operator: Optional[str] = None
) -> None:
    """根据 ITSM 工单结果推进申请状态。【轮询 / 未来 callback 共用入口】

    :param application: 申请单（调用方负责加锁/事务）
    :param ticket_data: ITSM 工单数据 {"status": "finished", "approve_result": True, ...}
    :param operator: 授权操作人
    """
    itsm_status = ticket_data.get("status", "")
    application.itsm_status = itsm_status

    # ① 审批通过 → 授权
    if itsm_status == ITSMV4TicketStatus.FINISHED and ticket_data.get("approve_result"):
        _do_grant(application, operator=operator)
    # ② 审批驳回（finished 但未通过）
    elif itsm_status == ITSMV4TicketStatus.FINISHED:
        application.reject_reason = _extract_reject_reason(ticket_data)
        _set_terminal(application, ScenePermissionApplication.Status.REJECTED)
    # ③ 被终止
    elif itsm_status == ITSMV4TicketStatus.TERMINATED:
        application.reject_reason = _extract_reject_reason(ticket_data)
        _set_terminal(application, ScenePermissionApplication.Status.REJECTED)
    # ④ 申请人撤单
    elif itsm_status == ITSMV4TicketStatus.REVOKED:
        _set_terminal(application, ScenePermissionApplication.Status.REVOKED)
    # running / draft → 保持 PENDING，不动


def _extract_reject_reason(ticket_data: dict) -> str:
    """从 ITSM 工单数据中提取拒绝/驳回理由（字段名按 ITSM V4 实际返回适配）。"""
    for key in ("opinion", "comment", "reject_reason", "remarks", "approve_result_remark"):
        value = ticket_data.get(key)
        if value:
            return str(value)
    return ""


def _do_grant(application: ScenePermissionApplication, operator: Optional[str] = None) -> None:
    """执行授权。成功→APPROVED；失败→GRANT_FAILED(retry_count++)。"""
    try:
        result = grant_scene_role(
            scene=application.scene,
            role=application.role,
            username=application.applicant,
            operator=operator,
        )
        if result.get("success"):
            application.status = ScenePermissionApplication.Status.APPROVED
            application.grant_method = result.get("method", "")
            application.grant_error = ""
            application.retry_count = 0
            application.finished_at = timezone.now()
        else:
            application.status = ScenePermissionApplication.Status.GRANT_FAILED
            application.grant_error = result.get("error", "unknown")
            application.retry_count += 1
            # 不设 finished_at：仍在重试中，非终态
    except Exception as err:  # pylint: disable=broad-except
        logger.exception("[_do_grant] 申请单 %s 授权失败: %s", application.id, err)
        application.status = ScenePermissionApplication.Status.GRANT_FAILED
        application.grant_error = str(err)
        application.retry_count += 1
        # 不设 finished_at：仍在重试中，非终态


def _set_terminal(
    application: ScenePermissionApplication, status: Union[str, ScenePermissionApplication.Status]
) -> None:
    application.status = status
    application.finished_at = timezone.now()


def get_scene_managers(scene: Scene) -> list:
    """获取场景管理员（V4 真相源优先，本地缓存兜底）。"""
    if IAMGroupManager.is_v4_backend():
        managers = IAMGroupManager.get_scene_role_members(IAMV4Role.SCENE_ADMIN, str(scene.scene_id))
        if managers:
            return managers
    return list(scene.managers or [])


def already_has_role(scene: Scene, role: str, username: str) -> bool:
    """检查用户是否已拥有指定场景角色（V3/V4 自适应）。"""
    if IAMGroupManager.is_v4_backend():
        role_id = SCENE_ROLE_TO_IAM_V4_ROLE[role]
        return username in IAMGroupManager.get_scene_role_members(role_id, str(scene.scene_id))
    group_id = scene.iam_manager_group_id if role == SceneRole.MANAGER else scene.iam_viewer_group_id
    if not group_id:
        return False
    members = IAMGroupManager.get_all_group_members(group_id=group_id)
    return username in [m["id"] for m in members if m.get("type") == "user"]
