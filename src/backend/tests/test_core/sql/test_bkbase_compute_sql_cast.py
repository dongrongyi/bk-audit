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
from django.test import SimpleTestCase

from core.sql.builder.builder import BKBaseQueryBuilder
from core.sql.builder.generator import BkBaseComputeSqlGenerator
from core.sql.constants import FieldType, Operator
from core.sql.model import Condition, Field, SqlConfig, Table, WhereCondition


class TestBkBaseComputeSqlScalarCast(SimpleTestCase):
    """BKBase 计算任务 SQL 对数值/时间标量列应显式 CAST，规避引擎隐式转换问题"""

    def setUp(self):
        self.query_builder = BKBaseQueryBuilder()
        self.table = Table(table_name="t_double_test")

    def _build_where_sql(self, field_type, raw_name="batch_gap_ratio", filter_value="2000.0", operator=Operator.GTE):
        field = Field(
            table="t_double_test",
            raw_name=raw_name,
            display_name=raw_name,
            field_type=field_type,
        )
        condition = WhereCondition(condition=Condition(field=field, operator=operator, filter=filter_value))
        config = SqlConfig(from_table=self.table, where=condition, select_fields=[field])
        return str(BkBaseComputeSqlGenerator(self.query_builder).generate(config))

    def test_double_scalar_column_is_cast(self):
        """double 标量列比较应生成 CAST(... AS DOUBLE)，且字面量保持 double 形态"""
        sql = self._build_where_sql(FieldType.DOUBLE)
        self.assertIn("CAST(`t_double_test`.`batch_gap_ratio` AS DOUBLE)", sql)
        self.assertIn(">=2000.0", sql)

    def test_float_scalar_column_is_cast(self):
        self.assertIn("CAST(`t_double_test`.`batch_gap_ratio` AS FLOAT)", self._build_where_sql(FieldType.FLOAT))

    def test_int_scalar_column_is_cast(self):
        self.assertIn(
            "CAST(`t_double_test`.`batch_gap_ratio` AS INT)", self._build_where_sql(FieldType.INT, filter_value="1")
        )

    def test_long_scalar_column_is_cast(self):
        self.assertIn(
            "CAST(`t_double_test`.`batch_gap_ratio` AS BIGINT)", self._build_where_sql(FieldType.LONG, filter_value="1")
        )

    def test_timestamp_scalar_column_is_cast(self):
        self.assertIn(
            "CAST(`t_double_test`.`batch_gap_ratio` AS BIGINT)",
            self._build_where_sql(FieldType.TIMESTAMP, filter_value="1690000000000"),
        )

    def test_string_scalar_column_not_cast(self):
        """字符串标量列不应被 CAST"""
        sql = self._build_where_sql(FieldType.STRING, raw_name="game_name", filter_value="demo", operator=Operator.EQ)
        self.assertNotIn("CAST(", sql)
        self.assertIn("game_name", sql)

    def test_between_operator_also_cast(self):
        """BETWEEN 数值比较同样应 cast 字段侧"""
        field = Field(
            table="t_double_test",
            raw_name="all_money",
            display_name="all_money",
            field_type=FieldType.DOUBLE,
        )
        condition = WhereCondition(
            condition=Condition(field=field, operator=Operator.BETWEEN, filters=["100.0", "2000.0"])
        )
        config = SqlConfig(from_table=self.table, where=condition, select_fields=[field])
        sql = str(BkBaseComputeSqlGenerator(self.query_builder).generate(config))
        self.assertIn("CAST(`t_double_test`.`all_money` AS DOUBLE)", sql)
