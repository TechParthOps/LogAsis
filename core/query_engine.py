"""Structured query engine for LogAsis.

Compiles query representations into index operations. Supports EXACT, CONTAINS,
PREFIX, REGEX, RANGE, TIME_RANGE, AND, OR, NOT, IN, GROUP, COUNT, DISTINCT,
SORT, and TOP_K operations.

The LLM may produce a JSON query plan that is validated and compiled here.
The LLM never generates executable code.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from core.event_index import EventIndex


@dataclass
class QueryCondition:
    field: str
    operator: str
    value: Any = None
    value2: Any = None


@dataclass
class QueryPlan:
    operation: str = "AND"
    conditions: list[QueryCondition] = field(default_factory=list)
    sub_plans: list["QueryPlan"] = field(default_factory=list)
    limit: int | None = None
    sort_field: str | None = None
    sort_desc: bool = True
    group_field: str | None = None
    time_start: datetime | None = None
    time_end: datetime | None = None


class QueryEngine:
    """Execute structured queries against the EventIndex.

    All operations compile into index lookups where possible. No full DataFrame
    scans are performed when indexed operations can resolve the query.
    """

    VALID_OPERATORS = {
        "EXACT", "CONTAINS", "PREFIX", "REGEX", "RANGE",
        "TIME_RANGE", "AND", "OR", "NOT", "IN",
        "GROUP", "COUNT", "DISTINCT", "SORT", "TOP_K",
    }

    def __init__(self, index: EventIndex):
        self.index = index

    def execute(self, plan: QueryPlan | dict[str, Any]) -> dict[str, Any]:
        if isinstance(plan, dict):
            plan = self.compile(plan)
        if plan is None:
            return {"positions": [], "count": 0, "error": "Invalid query plan"}

        op = plan.operation.upper()

        if op == "AND":
            return self._execute_and(plan)
        elif op == "OR":
            return self._execute_or(plan)
        elif op == "NOT":
            return self._execute_not(plan)
        elif op == "EXACT":
            return self._execute_exact(plan)
        elif op == "CONTAINS":
            return self._execute_contains(plan)
        elif op == "PREFIX":
            return self._execute_prefix(plan)
        elif op == "REGEX":
            return self._execute_regex(plan)
        elif op == "RANGE":
            return self._execute_range(plan)
        elif op == "TIME_RANGE":
            return self._execute_time_range(plan)
        elif op == "IN":
            return self._execute_in(plan)
        elif op == "COUNT":
            return self._execute_count(plan)
        elif op == "DISTINCT":
            return self._execute_distinct(plan)
        elif op == "GROUP":
            return self._execute_group(plan)
        elif op == "SORT":
            return self._execute_sort(plan)
        elif op == "TOP_K":
            return self._execute_top_k(plan)
        else:
            return {"positions": [], "count": 0, "error": f"Unsupported operation: {op}"}

    def compile(self, raw: dict[str, Any]) -> QueryPlan | None:
        if not isinstance(raw, dict):
            return None
        op = str(raw.get("operation", "AND")).upper()
        if op not in self.VALID_OPERATORS:
            return None

        plan = QueryPlan(operation=op)

        if op in ("AND", "OR"):
            for sub in raw.get("conditions", []):
                if isinstance(sub, dict):
                    sub_plan = self.compile(sub)
                    if sub_plan:
                        plan.sub_plans.append(sub_plan)
            for sub in raw.get("sub_plans", []):
                if isinstance(sub, dict):
                    sub_plan = self.compile(sub)
                    if sub_plan:
                        plan.sub_plans.append(sub_plan)
        elif op == "NOT":
            sub = raw.get("condition") or raw.get("sub_plan")
            if isinstance(sub, dict):
                sub_plan = self.compile(sub)
                if sub_plan:
                    plan.sub_plans.append(sub_plan)
        elif op in ("EXACT", "CONTAINS", "PREFIX", "REGEX", "RANGE", "IN"):
            plan.conditions = [QueryCondition(
                field=str(raw.get("field", "")),
                operator=op,
                value=raw.get("value"),
                value2=raw.get("value2"),
            )]
        elif op == "TIME_RANGE":
            plan.time_start = self._parse_time_value(raw.get("start"))
            plan.time_end = self._parse_time_value(raw.get("end"))
        elif op == "COUNT":
            sub = raw.get("condition") or raw.get("sub_plan")
            if isinstance(sub, dict):
                sub_plan = self.compile(sub)
                if sub_plan:
                    plan.sub_plans.append(sub_plan)
        elif op == "DISTINCT":
            plan.conditions = [QueryCondition(
                field=str(raw.get("field", "")),
                operator="DISTINCT",
                value=raw.get("value"),
            )]
        elif op == "GROUP":
            plan.group_field = str(raw.get("field", ""))
            sub = raw.get("condition") or raw.get("sub_plan")
            if isinstance(sub, dict):
                sub_plan = self.compile(sub)
                if sub_plan:
                    plan.sub_plans.append(sub_plan)
        elif op == "SORT":
            plan.sort_field = str(raw.get("field", ""))
            plan.sort_desc = bool(raw.get("descending", True))
            sub = raw.get("condition") or raw.get("sub_plan")
            if isinstance(sub, dict):
                sub_plan = self.compile(sub)
                if sub_plan:
                    plan.sub_plans.append(sub_plan)
        elif op == "TOP_K":
            plan.limit = int(raw.get("limit", 10))
            plan.sort_field = str(raw.get("field", ""))
            plan.sort_desc = bool(raw.get("descending", True))
            sub = raw.get("condition") or raw.get("sub_plan")
            if isinstance(sub, dict):
                sub_plan = self.compile(sub)
                if sub_plan:
                    plan.sub_plans.append(sub_plan)

        if raw.get("limit") is not None:
            plan.limit = int(raw["limit"])
        if raw.get("sort_field"):
            plan.sort_field = str(raw["sort_field"])
        if raw.get("sort_desc") is not None:
            plan.sort_desc = bool(raw["sort_desc"])
        if raw.get("group_field"):
            plan.group_field = str(raw["group_field"])

        return plan

    def _execute_and(self, plan: QueryPlan) -> dict[str, Any]:
        if not plan.sub_plans and not plan.conditions:
            return {"positions": list(self.index.all_positions()), "count": self.index.size}

        position_sets: list[set[int]] = []
        for sub in plan.sub_plans:
            result = self.execute(sub)
            positions = set(result.get("positions", []))
            if not positions and result.get("count", 0) == 0:
                return {"positions": [], "count": 0}
            position_sets.append(positions)

        for cond in plan.conditions:
            positions = self._condition_positions(cond)
            if not positions:
                return {"positions": [], "count": 0}
            position_sets.append(positions)

        if not position_sets:
            return {"positions": [], "count": 0}

        result = position_sets[0]
        for s in position_sets[1:]:
            result = result & s
        return self._finalize(sorted(result), plan)

    def _execute_or(self, plan: QueryPlan) -> dict[str, Any]:
        position_sets: list[set[int]] = []
        for sub in plan.sub_plans:
            result = self.execute(sub)
            position_sets.append(set(result.get("positions", [])))
        for cond in plan.conditions:
            position_sets.append(self._condition_positions(cond))

        if not position_sets:
            return {"positions": [], "count": 0}

        result: set[int] = set()
        for s in position_sets:
            result.update(s)
        return self._finalize(sorted(result), plan)

    def _execute_not(self, plan: QueryPlan) -> dict[str, Any]:
        if not plan.sub_plans:
            return {"positions": [], "count": 0, "error": "NOT requires a sub-plan"}
        inner = self.execute(plan.sub_plans[0])
        inner_positions = set(inner.get("positions", []))
        all_positions = set(self.index.all_positions())
        result = all_positions - inner_positions
        return self._finalize(sorted(result), plan)

    def _execute_exact(self, plan: QueryPlan) -> dict[str, Any]:
        if not plan.conditions:
            return {"positions": [], "count": 0}
        positions = self._condition_positions(plan.conditions[0])
        return self._finalize(positions, plan)

    def _execute_contains(self, plan: QueryPlan) -> dict[str, Any]:
        if not plan.conditions:
            return {"positions": [], "count": 0}
        positions = self._condition_positions(plan.conditions[0])
        return self._finalize(positions, plan)

    def _execute_prefix(self, plan: QueryPlan) -> dict[str, Any]:
        if not plan.conditions:
            return {"positions": [], "count": 0}
        positions = self._condition_positions(plan.conditions[0])
        return self._finalize(positions, plan)

    def _execute_regex(self, plan: QueryPlan) -> dict[str, Any]:
        if not plan.conditions:
            return {"positions": [], "count": 0}
        positions = self._condition_positions(plan.conditions[0])
        return self._finalize(positions, plan)

    def _execute_range(self, plan: QueryPlan) -> dict[str, Any]:
        if not plan.conditions:
            return {"positions": [], "count": 0}
        positions = self._condition_positions(plan.conditions[0])
        return self._finalize(positions, plan)

    def _execute_time_range(self, plan: QueryPlan) -> dict[str, Any]:
        if plan.time_start and plan.time_end:
            positions = self.index.timestamp_range(plan.time_start, plan.time_end)
        else:
            positions = list(self.index.all_positions())
        return self._finalize(positions, plan)

    def _execute_in(self, plan: QueryPlan) -> dict[str, Any]:
        if not plan.conditions:
            return {"positions": [], "count": 0}
        cond = plan.conditions[0]
        values = cond.value if isinstance(cond.value, (list, tuple, set)) else [cond.value]
        all_positions: set[int] = set()
        for val in values:
            all_positions.update(self.index.exact(cond.field, val))
        return self._finalize(sorted(all_positions), plan)

    def _execute_count(self, plan: QueryPlan) -> dict[str, Any]:
        if plan.sub_plans:
            inner = self.execute(plan.sub_plans[0])
            count = inner.get("count", len(inner.get("positions", [])))
        else:
            count = self.index.size
        return {"positions": [], "count": int(count), "aggregation": "count"}

    def _execute_distinct(self, plan: QueryPlan) -> dict[str, Any]:
        if not plan.conditions:
            return {"positions": [], "count": 0}
        field = plan.conditions[0].field
        values = self.index.distinct_values(field)
        return {"positions": [], "count": len(values), "values": values, "aggregation": "distinct"}

    def _execute_group(self, plan: QueryPlan) -> dict[str, Any]:
        if plan.sub_plans:
            inner = self.execute(plan.sub_plans[0])
            positions = set(inner.get("positions", []))
        else:
            positions = None
        field = plan.group_field or ""
        counts = self.index.facet_counts(field, positions)
        return {"positions": [], "count": len(counts), "groups": counts, "aggregation": "group"}

    def _execute_sort(self, plan: QueryPlan) -> dict[str, Any]:
        if plan.sub_plans:
            inner = self.execute(plan.sub_plans[0])
            positions = inner.get("positions", [])
        else:
            positions = list(self.index.all_positions())
        if plan.sort_field:
            decorated = []
            for pos in positions:
                event = self.index.get_event(pos)
                val = ""
                if event:
                    val = str(event.get(plan.sort_field, ""))
                decorated.append((val, pos))
            decorated.sort(key=lambda x: x[0], reverse=plan.sort_desc)
            positions = [pos for _, pos in decorated]
        return self._finalize(positions, plan)

    def _execute_top_k(self, plan: QueryPlan) -> dict[str, Any]:
        if plan.sub_plans:
            inner = self.execute(plan.sub_plans[0])
            positions = inner.get("positions", [])
        else:
            positions = list(self.index.all_positions())
        if plan.sort_field:
            decorated = []
            for pos in positions:
                event = self.index.get_event(pos)
                val = ""
                if event:
                    val = str(event.get(plan.sort_field, ""))
                decorated.append((val, pos))
            decorated.sort(key=lambda x: x[0], reverse=plan.sort_desc)
            positions = [pos for _, pos in decorated]
        limit = plan.limit or 10
        return {"positions": positions[:limit], "count": min(len(positions), limit)}

    def _condition_positions(self, cond: QueryCondition) -> set[int]:
        op = cond.operator.upper()
        field = cond.field

        if op == "EXACT":
            return set(self.index.exact(field, cond.value))
        elif op == "CONTAINS":
            return set(self.index.field_candidates(field, str(cond.value or "")))
        elif op == "PREFIX":
            values = self.index.prefix_values(field, str(cond.value or ""))
            positions: set[int] = set()
            for val in values:
                positions.update(self.index.exact(field, val))
            return positions
        elif op == "REGEX":
            return self._regex_positions(field, str(cond.value or ""))
        elif op == "RANGE":
            return self._range_positions(field, cond.value, cond.value2)
        else:
            return set()

    def _regex_positions(self, field: str, pattern: str) -> set[int]:
        if field not in self.index._field_values:
            return set()
        try:
            compiled = re.compile(pattern, re.IGNORECASE)
        except re.error:
            return set()
        positions: set[int] = set()
        for value, rows in self.index._field_values[field].items():
            if compiled.search(value):
                positions.update(rows)
        return positions

    def _range_positions(self, field: str, low: Any, high: Any) -> set[int]:
        if field not in self.index._field_values:
            return set()
        positions: set[int] = set()
        for value, rows in self.index._field_values[field].items():
            try:
                numeric = float(value)
                if (low is None or numeric >= float(low)) and (high is None or numeric <= float(high)):
                    positions.update(rows)
            except (ValueError, TypeError):
                continue
        return positions

    def _finalize(self, positions: list[int], plan: QueryPlan) -> dict[str, Any]:
        result = {"positions": positions, "count": len(positions)}
        if plan.limit is not None and plan.limit > 0:
            result["positions"] = positions[:plan.limit]
            result["count"] = len(result["positions"])
        return result

    @staticmethod
    def _parse_time_value(value: Any) -> datetime | None:
        if isinstance(value, datetime):
            return value
        if not value:
            return None
        text = str(value).strip()
        try:
            return datetime.fromisoformat(text.replace("Z", "+00:00"))
        except (ValueError, TypeError):
            pass
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
            try:
                return datetime.strptime(text, fmt)
            except (ValueError, TypeError):
                continue
        return None
