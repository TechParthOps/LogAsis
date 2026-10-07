from __future__ import annotations

"""Deterministic evidence/entity graph for a LogAsis case.

The graph is an investigation aid: it makes provenance and relationships visible
without inferring compromise, attribution, or causation that is not present in
the supplied evidence.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class CaseGraphEngine:
    """Build a stable, explainable graph from a CaseIntelligence report."""

    TEMPORAL_EDGE_SECONDS = 300

    NODE_TYPES = ("case", "evidence", "ip", "user", "process", "event", "action")

    @staticmethod
    def _norm(value: Any) -> str:
        return str(value or "").strip()

    @classmethod
    def _node(cls, node_id: str, node_type: str, label: str, **extra: Any) -> dict[str, Any]:
        node = {
            "id": node_id,
            "type": node_type,
            "label": label,
        }
        node.update(extra)
        return node

    @staticmethod
    def _parse_time(value: Any) -> datetime | None:
        if not value:
            return None
        try:
            text = str(value).strip().replace("Z", "+00:00")
            dt = datetime.fromisoformat(text)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except (TypeError, ValueError):
            return None

    @classmethod
    def build(cls, report: dict[str, Any]) -> dict[str, Any]:
        case_id = cls._norm(report.get("case_id")) or "UNKNOWN"
        nodes: dict[str, dict[str, Any]] = {}
        edges: dict[str, dict[str, Any]] = {}

        def add_node(node_id: str, node_type: str, label: str, **extra: Any) -> str:
            if node_id not in nodes:
                nodes[node_id] = cls._node(node_id, node_type, label, **extra)
            return node_id

        def add_edge(source: str, target: str, edge_type: str, label: str, **extra: Any) -> str:
            edge_id = f"E:{source}>{target}:{edge_type}"
            if edge_id not in edges:
                edge = {
                    "id": edge_id,
                    "source": source,
                    "target": target,
                    "type": edge_type,
                    "label": label,
                }
                edge.update(extra)
                edges[edge_id] = edge
            return edge_id

        case_node = add_node(
            f"CASE:{case_id}",
            "case",
            case_id,
            title=cls._norm(report.get("title")),
            status=cls._norm(report.get("status")) or "New",
            priority=cls._norm(report.get("priority")) or "MEDIUM",
        )

        timeline = list(report.get("timeline", []) or [])
        evidence_nodes: list[tuple[dict[str, Any], str]] = []

        for index, event in enumerate(timeline):
            evidence_id = cls._norm(event.get("evidence_id")) or f"UNNAMED-{index + 1}"
            evidence_node = add_node(
                f"EVIDENCE:{evidence_id}",
                "evidence",
                evidence_id,
                timestamp=cls._norm(event.get("timestamp")),
                event_type=cls._norm(event.get("event_type")),
                priority=cls._norm(event.get("priority")) or "MEDIUM",
                line=cls._norm(event.get("line")),
                source_ip=cls._norm(event.get("source_ip")),
                username=cls._norm(event.get("username")),
                process_name=cls._norm(event.get("process_name")),
                action=cls._norm(event.get("action")),
            )
            add_edge(case_node, evidence_node, "contains", "case evidence")
            evidence_nodes.append((event, evidence_node))

            entities = (
                ("source_ip", "ip", "source IP"),
                ("username", "user", "username"),
                ("process_name", "process", "process"),
                ("event_type", "event", "event type"),
                ("action", "action", "action"),
            )
            for field, node_type, edge_label in entities:
                value = cls._norm(event.get(field))
                if not value:
                    continue
                # Lowercase only the internal key; retain original display label.
                key_value = value.lower()
                entity_node = add_node(
                    f"{node_type.upper()}:{key_value}",
                    node_type,
                    value,
                )
                add_edge(evidence_node, entity_node, "observed", edge_label)

        # Deterministic temporal context between evidence records.
        temporal_links = 0
        for i, (left, left_id) in enumerate(evidence_nodes):
            left_time = cls._parse_time(left.get("timestamp"))
            if left_time is None:
                continue
            for right, right_id in evidence_nodes[i + 1:]:
                right_time = cls._parse_time(right.get("timestamp"))
                if right_time is None:
                    continue
                try:
                    seconds = abs((left_time - right_time).total_seconds())
                except TypeError:
                    continue
                if seconds <= cls.TEMPORAL_EDGE_SECONDS:
                    add_edge(
                        left_id,
                        right_id,
                        "temporal",
                        "within investigation window",
                        seconds=round(seconds, 3),
                    )
                    temporal_links += 1

        # Preserve already-computed deterministic correlation relationships.
        relationship_links = 0
        for relationship in report.get("relationships", []) or []:
            a = cls._norm(relationship.get("evidence_a"))
            b = cls._norm(relationship.get("evidence_b"))
            if not a or not b:
                continue
            source = f"EVIDENCE:{a}"
            target = f"EVIDENCE:{b}"
            if source not in nodes or target not in nodes:
                continue
            add_edge(
                source,
                target,
                "correlation",
                "deterministic correlation",
                score=relationship.get("score", 0),
                reasons=list(relationship.get("reasons", []) or []),
            )
            relationship_links += 1

        ordered_nodes = sorted(nodes.values(), key=lambda item: (item["type"], item["id"]))
        ordered_edges = sorted(edges.values(), key=lambda item: item["id"])

        identity_types = {"ip", "user"}
        identity_nodes = sum(1 for node in ordered_nodes if node["type"] in identity_types)
        summary = {
            "node_count": len(ordered_nodes),
            "edge_count": len(ordered_edges),
            "evidence_count": sum(1 for node in ordered_nodes if node["type"] == "evidence"),
            "identity_entity_count": identity_nodes,
            "temporal_link_count": temporal_links,
            "correlation_link_count": relationship_links,
        }

        return {
            "case_id": case_id,
            "title": cls._norm(report.get("title")),
            "nodes": ordered_nodes,
            "edges": ordered_edges,
            "summary": summary,
            "limitations": [
                "Graph edges represent observed or deterministic contextual relationships in the supplied case evidence.",
                "The graph does not establish causation, common ownership, malicious intent, or compromise from temporal or entity relationships.",
                "The graph is limited to evidence currently linked to the case.",
            ],
        }



    @classmethod
    def build_investigation_chain(cls, graph: dict[str, Any]) -> dict[str, Any]:
        """Build a chronological, evidence-backed investigation chain.

        This is deliberately a *potential investigation chain*, not an attack
        chain. Ordering and links come only from recorded timestamps and graph
        edges; no compromise or causation is inferred.
        """
        evidence = [
            node for node in graph.get("nodes", [])
            if node.get("type") == "evidence"
        ]

        def sort_key(node: dict[str, Any]):
            parsed = cls._parse_time(node.get("timestamp"))
            return (
                parsed.isoformat() if parsed else "9999-12-31T23:59:59+00:00",
                str(node.get("id", "")),
            )

        evidence = sorted(evidence, key=sort_key)
        edges = list(graph.get("edges", []) or [])
        edge_map: dict[tuple[str, str], list[dict[str, Any]]] = {}
        for edge in edges:
            edge_map.setdefault(
                (str(edge.get("source", "")), str(edge.get("target", ""))), []
            ).append(edge)
            edge_map.setdefault(
                (str(edge.get("target", "")), str(edge.get("source", ""))), []
            ).append(edge)

        steps = []
        for index, node in enumerate(evidence, start=1):
            context = []
            for key, label in (
                ("event_type", "Event"),
                ("source_ip", "Source IP"),
                ("username", "User"),
                ("process_name", "Process"),
                ("action", "Action"),
            ):
                value = node.get(key)
                if value:
                    context.append({"field": key, "label": label, "value": str(value)})

            # Entity values are stored on evidence nodes in some callers and
            # can also be recovered from graph edges.
            if not context:
                prefix = str(node.get("id", ""))
                related = [
                    e for e in edges
                    if e.get("source") == prefix or e.get("target") == prefix
                ]
                for edge in related:
                    target = edge.get("target") if edge.get("source") == prefix else edge.get("source")
                    match = next((n for n in graph.get("nodes", []) if n.get("id") == target), None)
                    if match and match.get("type") in {"ip", "user", "process", "event", "action"}:
                        context.append({
                            "field": match.get("type"),
                            "label": match.get("type").replace("_", " ").title(),
                            "value": str(match.get("label", "")),
                        })

            links_to_next = []
            if index < len(evidence):
                next_id = evidence[index]["id"]
                links_to_next = [
                    {
                        "type": edge.get("type", ""),
                        "label": edge.get("label", ""),
                        "details": edge.get("reasons", []) or (
                            [f"{edge.get('seconds')}s"] if edge.get("seconds") is not None else []
                        ),
                    }
                    for edge in edge_map.get((node.get("id"), next_id), [])
                    if edge.get("type") in {"temporal", "correlation"}
                ]

            steps.append({
                "step": index,
                "evidence_id": node.get("label") or node.get("id"),
                "timestamp": node.get("timestamp", ""),
                "priority": node.get("priority", "MEDIUM"),
                "event_type": node.get("event_type", ""),
                "context": context,
                "links_to_next": links_to_next,
            })

        return {
            "case_id": graph.get("case_id", "UNKNOWN"),
            "steps": steps,
            "step_count": len(steps),
            "assessment": (
                "The evidence shows temporally or deterministically related activity "
                "within the supplied case. These relationships are investigation leads; "
                "they do not establish causation, malicious intent, or successful compromise."
            ),
            "limitations": [
                "The chain is chronological and evidence-backed; it is not an inferred attack path.",
                "Temporal proximity and deterministic correlation do not establish causation.",
                "Absence of an event from this chain does not prove that the event did not occur.",
            ],
        }


    @classmethod
    def build_relationship_explorer(cls, graph: dict[str, Any]) -> list[dict[str, Any]]:
        """Return deterministic, analyst-readable evidence-to-evidence relationships.

        This view intentionally does not change the graph's existing edge set.
        It derives pairwise relationships from fields already present on the
        evidence nodes and from existing temporal/correlation edges.
        """
        evidence = sorted(
            [n for n in graph.get("nodes", []) if n.get("type") == "evidence"],
            key=lambda n: (str(n.get("timestamp") or "9999"), str(n.get("id", ""))),
        )
        edges = list(graph.get("edges", []) or [])
        edge_by_pair: dict[frozenset[str], list[dict[str, Any]]] = {}
        for edge in edges:
            if edge.get("type") not in {"temporal", "correlation"}:
                continue
            a, b = str(edge.get("source", "")), str(edge.get("target", ""))
            if a.startswith("EVIDENCE:") and b.startswith("EVIDENCE:"):
                edge_by_pair.setdefault(frozenset((a, b)), []).append(edge)

        fields = (
            ("source_ip", "IP", "SAME_SOURCE_IP"),
            ("username", "User", "SAME_USER"),
            ("process_name", "Process", "SAME_PROCESS"),
            ("event_type", "Event", "SAME_EVENT_TYPE"),
            ("action", "Action", "SAME_ACTION"),
        )
        results: list[dict[str, Any]] = []
        for i, left in enumerate(evidence):
            for right in evidence[i + 1:]:
                shared = []
                for field, label, rel_type in fields:
                    a, b = cls._norm(left.get(field)), cls._norm(right.get(field))
                    if a and b and a.lower() == b.lower():
                        shared.append({
                            "type": rel_type,
                            "label": f"Same {label.lower()}",
                            "field": field,
                            "value": a,
                        })

                pair_edges = edge_by_pair.get(
                    frozenset((str(left.get("id")), str(right.get("id")))), []
                )
                for edge in pair_edges:
                    if edge.get("type") == "temporal":
                        shared.append({
                            "type": "TEMPORAL",
                            "label": "Temporal proximity",
                            "seconds": edge.get("seconds"),
                        })
                    elif edge.get("type") == "correlation":
                        shared.append({
                            "type": "CORRELATION",
                            "label": "Deterministic correlation",
                            "score": edge.get("score", 0),
                            "reasons": list(edge.get("reasons", []) or []),
                        })

                if not shared:
                    continue

                types = {item["type"] for item in shared}
                if "CORRELATION" in types:
                    strength = "MEDIUM"
                elif any(t in types for t in {"SAME_SOURCE_IP", "SAME_USER"}):
                    strength = "MEDIUM"
                else:
                    strength = "LOW"

                results.append({
                    "id": f"R:{left.get('id')}->{right.get('id')}",
                    "source": left.get("label") or left.get("id"),
                    "source_id": left.get("id"),
                    "target": right.get("label") or right.get("id"),
                    "target_id": right.get("id"),
                    "strength": strength,
                    "relationships": shared,
                    "interpretation": (
                        "The records share one or more observed attributes or "
                        "deterministic temporal/correlation context. This is a "
                        "triage relationship, not proof that the same actor, "
                        "cause, or incident produced both records."
                    ),
                    "limitation": (
                        "Relationship strength reflects observable context only; "
                        "it does not establish common ownership, causation, "
                        "malicious intent, or compromise."
                    ),
                })

        return sorted(
            results,
            key=lambda item: (
                {"MEDIUM": 0, "LOW": 1}.get(item.get("strength"), 2),
                str(item.get("source_id", "")),
                str(item.get("target_id", "")),
            ),
        )

    @staticmethod
    def export_json(path: str | Path, graph: dict[str, Any]) -> Path:
        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(
            json.dumps(graph, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        return destination
