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

import abc
from typing import Dict, List, Optional, Tuple

from services.web.risk.models import Risk


class TicketChannel(abc.ABC):
    """
    工单下发通道抽象

    把"下游系统差异"收敛到可插拔的 channel 适配层：通用的预览 / 测试发送 / 状态轮询接口
    只依赖本契约，不感知具体下游（BKSEC / WeSec / 自定义 SOPS 套餐等）。

    通道专属配置（如 BKSEC 的 bksec_config 结构）由通道自己解析，
    通用接口层只透传 dict，不对内部结构做强校验。
    """

    # 通道类型标识（入参 channel 的取值），子类必须定义
    channel_type: str = ""

    @abc.abstractmethod
    def parse_config(self, channel_config: dict) -> object:
        """
        解析并校验通道专属配置

        :param channel_config: 通用接口透传的 dict（结构由通道自定）
        :return: 通道内部配置对象（如 BkSecConfig）
        :raises ValueError: 配置不合法时抛出，由通用接口转 ValidationError
        """
        raise NotImplementedError

    @abc.abstractmethod
    def render_preview(self, channel_config: dict, risk: Optional[Risk]) -> dict:
        """
        渲染预览报文

        :return: {ticket, risk(快照), risk_context_keys, warnings} 等预览所需结构
        """
        raise NotImplementedError

    @abc.abstractmethod
    def render_test_constants(self, channel_config: dict, risk: Risk, test_receivers: List[str]) -> dict:
        """
        渲染测试发送的 SOPS 任务常量

        :param test_receivers: 测试接收人列表（泛化自原 BKSEC 单值 test_operator）
        :return: SOPS create_task(constants) 直接使用的常量 dict
        """
        raise NotImplementedError

    @abc.abstractmethod
    def validate_test_target(self, risk: Risk) -> None:
        """
        测试发送前置校验（如 BKSEC 的回调隔离守卫）

        不抛异常即通过；校验失败抛 serializers.ValidationError 或 ValueError。
        """
        raise NotImplementedError

    def sync_test_config(self, channel_config: dict, risk: Risk) -> None:
        """
        测试发送前置：兜底同步下游侧配置（如 BKSEC 同步插件侧 Config）。

        默认空实现——仅 BKSEC 这类"下游异步执行阶段才读取自身配置"的通道需要。
        需要此能力的通道应覆盖本方法：在测试发送前主动把本次 channel_config 同步到下游，
        确保下游侧配置与本次入参一致（后续改配置再测，直接更新同一主键的配置即可）。
        同步失败抛 serializers.ValidationError 直接阻断测试发送。
        """
        return None

    @abc.abstractmethod
    def get_preset_pa_template_id(self) -> Optional[str]:
        """
        返回预置套餐模板 ID（如 BKSEC 读 BKSEC_SOPS_TEMPLATE_ID）

        返回 None 表示未配置，通用接口据此拒绝测试发送。
        """
        raise NotImplementedError

    @abc.abstractmethod
    def resolve_failure_hints(self) -> List[Tuple[str, str]]:
        """
        返回该通道的失败特征 → 处置提示映射

        用于在任务状态轮询（失败时）做已知错误特征翻译，提升联调可观测性。
        """
        raise NotImplementedError


class ChannelRegistry:
    """
    通道注册表（简单工厂）

    各通道在模块导入时调用 register 登记，通用接口按入参 channel 取实例。
    """

    _registry: Dict[str, TicketChannel] = {}

    @classmethod
    def register(cls, channel: TicketChannel) -> None:
        if not channel.channel_type:
            raise ValueError("channel_type 不可为空")
        cls._registry[channel.channel_type] = channel

    @classmethod
    def get(cls, channel_type: str) -> TicketChannel:
        instance = cls._registry.get(channel_type)
        if instance is None:
            from rest_framework import serializers

            raise serializers.ValidationError("不支持的下发通道类型：%s" % channel_type)
        return instance

    @classmethod
    def all_types(cls) -> List[str]:
        return list(cls._registry.keys())
