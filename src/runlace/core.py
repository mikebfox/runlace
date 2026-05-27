"""Core trace normalization, redaction, and report formatting."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
import math
import re
from typing import Any, Iterable

SEVERITY_ORDER = {"info": 1, "warning": 2, "error": 3}
FAIL_ORDER = {"never": 99, "info": 1, "warning": 2, "error": 3}

SECRET_KEY_RE = re.compile(
    r"(api[_-]?key|authorization|bearer|credential|passwd|password|private[_-]?key|secret|session|token)",
    re.IGNORECASE,
)
SAFE_METRIC_KEYS = {
    "completion_tokens",
    "gen_ai.usage.completion_tokens",
    "gen_ai.usage.input_tokens",
    "gen_ai.usage.output_tokens",
    "gen_ai.usage.prompt_tokens",
    "gen_ai.usage.total_tokens",
    "input_tokens",
    "output_tokens",
    "prompt_tokens",
    "tokens",
    "total_tokens",
}
SECRET_VALUE_PATTERNS = (
    re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.DOTALL),
)


@dataclass(frozen=True)
class RunlaceOptions:
    """Analysis knobs used by both the library and CLI."""

    max_gap_ms: int = 30_000
    max_repeat: int = 4
    token_budget: int | None = None
    cost_budget: float | None = None


@dataclass(frozen=True)
class Finding:
    """A deterministic finding emitted by runlace."""

    rule_id: str
    severity: str
    message: str
    span_id: str | None = None
    evidence: str | None = None
    fix: str | None = None

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "message": self.message,
        }
        if self.span_id is not None:
            payload["span_id"] = self.span_id
        if self.evidence is not None:
            payload["evidence"] = self.evidence
        if self.fix is not None:
            payload["fix"] = self.fix
        return payload


@dataclass
class TimelineSpan:
    """A normalized unit of agent work."""

    span_id: str
    name: str
    kind: str = "event"
    parent_id: str | None = None
    start_ms: int | None = None
    end_ms: int | None = None
    duration_ms: int | None = None
    status: str = "ok"
    attributes: dict[str, Any] = field(default_factory=dict)
    line: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "span_id": self.span_id,
            "parent_id": self.parent_id,
            "name": self.name,
            "kind": self.kind,
            "start_ms": self.start_ms,
            "end_ms": self.end_ms,
            "duration_ms": self.duration_ms,
            "status": self.status,
            "attributes": self.attributes,
            "line": self.line,
        }


@dataclass(frozen=True)
class TraceReport:
    """Analysis result returned by runlace."""

    spans: tuple[TimelineSpan, ...]
    findings: tuple[Finding, ...]
    redactions: int
    totals: dict[str, int]

    @property
    def ok(self) -> bool:
        return self.totals.get("error", 0) == 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "spans": [span.to_dict() for span in self.spans],
            "findings": [finding.to_dict() for finding in self.findings],
            "redactions": self.redactions,
            "totals": self.totals,
        }


def analyze_jsonl(source: str, options: RunlaceOptions | None = None) -> TraceReport:
    """Analyze JSONL agent trace text."""

    opts = options or RunlaceOptions()
    spans: list[TimelineSpan] = []
    findings: list[Finding] = []
    open_spans: dict[str, TimelineSpan] = {}
    redactions = 0

    for line_no, line in enumerate(source.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            raw = json.loads(line)
        except json.JSONDecodeError as exc:
            findings.append(
                Finding(
                    "RL006",
                    "error",
                    "Trace line is not valid JSON.",
                    span_id=f"line:{line_no}",
                    evidence=f"{exc.msg} at column {exc.colno}",
                    fix="Write one JSON object per line or remove non-JSON log output before analysis.",
                )
            )
            continue
        if not isinstance(raw, dict):
            findings.append(
                Finding(
                    "RL006",
                    "error",
                    "Trace line must be a JSON object.",
                    span_id=f"line:{line_no}",
                    evidence=type(raw).__name__,
                    fix="Wrap primitive values in an event object with a timestamp and name.",
                )
            )
            continue

        sanitized, count = _redact(raw)
        redactions += count
        normalized = _normalize_record(sanitized, line_no)

        if normalized["shape"] == "span":
            spans.append(normalized["span"])
            continue

        phase = normalized["phase"]
        span = normalized["span"]
        if phase == "start":
            open_spans[span.span_id] = span
        elif phase == "end":
            started = open_spans.pop(span.span_id, None)
            if started is None:
                findings.append(
                    Finding(
                        "RL007",
                        "warning",
                        "End event did not match a previous start event.",
                        span_id=span.span_id,
                        evidence=span.name,
                        fix="Keep stable span ids across start and end rows.",
                    )
                )
                spans.append(span)
            else:
                spans.append(_merge_started_span(started, span))
        else:
            spans.append(span)

    for span in open_spans.values():
        findings.append(
            Finding(
                "RL001",
                "warning",
                "Span started but never ended.",
                span_id=span.span_id,
                evidence=span.name,
                fix="Emit a matching end event or write complete span records.",
            )
        )
        spans.append(span)

    spans.sort(key=lambda span: (_sort_time(span), span.line, span.span_id))
    findings.extend(_inspect_spans(spans, opts, redactions))
    findings.sort(key=lambda item: (-SEVERITY_ORDER[item.severity], item.rule_id, item.span_id or ""))
    totals = _count_findings(findings)
    return TraceReport(tuple(spans), tuple(findings), redactions, totals)


def should_fail(report: TraceReport, threshold: str = "error") -> bool:
    """Return whether a report should fail a CI gate."""

    if threshold not in FAIL_ORDER:
        raise ValueError(f"Unknown threshold: {threshold}")
    required = FAIL_ORDER[threshold]
    return any(SEVERITY_ORDER[finding.severity] >= required for finding in report.findings)


def format_text_report(report: TraceReport) -> str:
    """Format a compact human-readable report."""

    highest = _highest_severity(report.findings)
    parts = [
        f"runlace: {highest} - {len(report.spans)} span(s), {len(report.findings)} finding(s), {report.redactions} redaction(s)"
    ]

    if report.findings:
        parts.append("")
        for finding in report.findings:
            location = f" at {finding.span_id}" if finding.span_id else ""
            parts.append(f"{finding.severity.upper()} {finding.rule_id}{location}: {finding.message}")
            if finding.evidence:
                parts.append(f"  evidence: {finding.evidence}")
            if finding.fix:
                parts.append(f"  fix: {finding.fix}")

    if report.spans:
        parts.append("")
        parts.append("Timeline")
        base = min((_sort_time(span) for span in report.spans), default=0)
        children = _children_by_parent(report.spans)
        roots = [span for span in report.spans if not span.parent_id or span.parent_id not in children["__all_ids__"]]
        for span in roots:
            _append_span(parts, span, children, base, depth=0)

    return "\n".join(parts)


def _normalize_record(record: dict[str, Any], line_no: int) -> dict[str, Any]:
    if _looks_like_complete_span(record):
        return {"shape": "span", "span": _span_from_complete_record(record, line_no)}
    return {"shape": "event", **_span_from_event_record(record, line_no)}


def _looks_like_complete_span(record: dict[str, Any]) -> bool:
    return bool(
        _first_present(record, ("span_id", "spanId", "id"))
        and _first_present(record, ("start_time", "startTime", "startTimeUnixNano"))
        and (
            _first_present(record, ("end_time", "endTime", "endTimeUnixNano", "duration_ms", "durationMs"))
            is not None
        )
    )


def _span_from_complete_record(record: dict[str, Any], line_no: int) -> TimelineSpan:
    attrs = _attributes(record)
    span_id = str(_first_present(record, ("span_id", "spanId", "id")))
    parent_id = _optional_str(_first_present(record, ("parent_span_id", "parentSpanId", "parent_id", "parent")))
    start_ms = _parse_time_ms(_first_present(record, ("start_time", "startTime", "startTimeUnixNano", "timestamp", "ts", "time")))
    end_ms = _parse_time_ms(_first_present(record, ("end_time", "endTime", "endTimeUnixNano")))
    duration_ms = _parse_int(_first_present(record, ("duration_ms", "durationMs", "duration")))
    if duration_ms is None and start_ms is not None and end_ms is not None:
        duration_ms = max(0, end_ms - start_ms)
    if end_ms is None and start_ms is not None and duration_ms is not None:
        end_ms = start_ms + duration_ms

    name = _span_name(record, attrs)
    return TimelineSpan(
        span_id=span_id,
        parent_id=parent_id,
        name=name,
        kind=_span_kind(record, attrs),
        start_ms=start_ms,
        end_ms=end_ms,
        duration_ms=duration_ms,
        status=_status(record, attrs),
        attributes=attrs,
        line=line_no,
    )


def _span_from_event_record(record: dict[str, Any], line_no: int) -> dict[str, Any]:
    attrs = _attributes(record)
    event_name = str(_first_present(record, ("event", "type", "kind", "name")) or "event")
    phase = _phase(record, event_name)
    timestamp = _parse_time_ms(_first_present(record, ("timestamp", "ts", "time", "created_at")))
    span_id = str(
        _first_present(record, ("span_id", "spanId", "id", "tool_call_id", "call_id"))
        or f"line:{line_no}"
    )
    duration_ms = _parse_int(_first_present(record, ("duration_ms", "durationMs", "duration")))
    end_ms = timestamp if phase == "end" else None
    if phase == "instant":
        end_ms = timestamp
    if phase == "start" and duration_ms is not None and timestamp is not None:
        end_ms = timestamp + duration_ms
        phase = "instant"

    span = TimelineSpan(
        span_id=span_id,
        parent_id=_optional_str(_first_present(record, ("parent_span_id", "parentSpanId", "parent_id", "parent"))),
        name=_event_span_name(record, event_name),
        kind=_event_kind(record, event_name),
        start_ms=timestamp if phase != "end" else None,
        end_ms=end_ms,
        duration_ms=duration_ms,
        status=_status(record, attrs),
        attributes=attrs,
        line=line_no,
    )
    return {"phase": phase, "span": span}


def _merge_started_span(started: TimelineSpan, ended: TimelineSpan) -> TimelineSpan:
    attrs = {**started.attributes, **ended.attributes}
    start_ms = started.start_ms
    end_ms = ended.end_ms
    duration_ms = ended.duration_ms
    if duration_ms is None and start_ms is not None and end_ms is not None:
        duration_ms = max(0, end_ms - start_ms)
    return TimelineSpan(
        span_id=started.span_id,
        parent_id=started.parent_id or ended.parent_id,
        name=started.name if started.name != "event" else ended.name,
        kind=started.kind if started.kind != "event" else ended.kind,
        start_ms=start_ms,
        end_ms=end_ms,
        duration_ms=duration_ms,
        status=ended.status if ended.status != "ok" else started.status,
        attributes=attrs,
        line=started.line,
    )


def _inspect_spans(spans: Iterable[TimelineSpan], options: RunlaceOptions, redactions: int) -> list[Finding]:
    findings: list[Finding] = []
    span_list = list(spans)

    if redactions:
        findings.append(
            Finding(
                "RL005",
                "warning",
                "Sensitive trace data was redacted before rendering.",
                evidence=f"{redactions} value(s)",
                fix="Avoid recording secrets, credentials, full prompts, and raw tool arguments in traces.",
            )
        )

    for span in span_list:
        if _is_error(span):
            findings.append(
                Finding(
                    "RL002",
                    "error",
                    "Span ended with an error status.",
                    span_id=span.span_id,
                    evidence=span.name,
                    fix="Inspect the failed tool, model, or agent step before replaying the run.",
                )
            )

    previous: TimelineSpan | None = None
    for span in span_list:
        if previous and previous.end_ms is not None and span.start_ms is not None:
            gap = span.start_ms - previous.end_ms
            if gap > options.max_gap_ms:
                findings.append(
                    Finding(
                        "RL003",
                        "warning",
                        "Trace contains a long idle gap between spans.",
                        span_id=span.span_id,
                        evidence=f"{gap} ms after {previous.span_id}",
                        fix="Check for blocked tools, retries hidden by wrappers, or missing telemetry rows.",
                    )
                )
        previous = span

    findings.extend(_repeat_findings(span_list, options.max_repeat))

    tokens = _sum_numeric_attributes(span_list, ("tokens", "total_tokens", "gen_ai.usage.total_tokens"))
    if options.token_budget is not None and tokens > options.token_budget:
        findings.append(
            Finding(
                "RL009",
                "warning",
                "Trace exceeded the configured token budget.",
                evidence=f"{tokens} token(s) > {options.token_budget}",
                fix="Inspect long prompts, repeated tool calls, or unexpected retries.",
            )
        )

    cost = _sum_numeric_attributes(span_list, ("cost", "total_cost", "gen_ai.usage.cost"))
    if options.cost_budget is not None and cost > options.cost_budget:
        findings.append(
            Finding(
                "RL010",
                "warning",
                "Trace exceeded the configured cost budget.",
                evidence=f"{cost:.6g} > {options.cost_budget:.6g}",
                fix="Inspect model selection, retries, and tool loops before widening the budget.",
            )
        )

    return findings


def _repeat_findings(spans: list[TimelineSpan], max_repeat: int) -> list[Finding]:
    if max_repeat < 2:
        return []
    findings: list[Finding] = []
    last_key: tuple[str, str] | None = None
    count = 0
    first_span_id = ""
    for span in spans:
        key = (span.kind, span.name)
        if key == last_key:
            count += 1
        else:
            if last_key and count >= max_repeat:
                findings.append(_repeat_finding(first_span_id, last_key, count))
            last_key = key
            count = 1
            first_span_id = span.span_id
    if last_key and count >= max_repeat:
        findings.append(_repeat_finding(first_span_id, last_key, count))
    return findings


def _repeat_finding(span_id: str, key: tuple[str, str], count: int) -> Finding:
    kind, name = key
    return Finding(
        "RL004",
        "warning",
        "Trace contains repeated adjacent spans.",
        span_id=span_id,
        evidence=f"{kind}:{name} repeated {count} time(s)",
        fix="Check for agent loops, retry storms, or a missing stop condition.",
    )


def _redact(value: Any, key: str | None = None) -> tuple[Any, int]:
    if key and key.lower() not in SAFE_METRIC_KEYS and SECRET_KEY_RE.search(key):
        return "<redacted:key>", 1
    if isinstance(value, dict):
        redacted: dict[str, Any] = {}
        count = 0
        for child_key, child_value in value.items():
            clean, child_count = _redact(child_value, str(child_key))
            redacted[str(child_key)] = clean
            count += child_count
        return redacted, count
    if isinstance(value, list):
        items = []
        count = 0
        for item in value:
            clean, child_count = _redact(item)
            items.append(clean)
            count += child_count
        return items, count
    if isinstance(value, str):
        clean = value
        count = 0
        for pattern in SECRET_VALUE_PATTERNS:
            clean, replacements = pattern.subn("<redacted:secret>", clean)
            count += replacements
        return clean, count
    return value, 0


def _attributes(record: dict[str, Any]) -> dict[str, Any]:
    attrs = record.get("attributes")
    if isinstance(attrs, dict):
        result = {str(key): value for key, value in attrs.items()}
    else:
        result = {}
    for key in ("tool", "model", "agent", "status", "error", "tokens", "total_tokens", "cost", "total_cost"):
        if key in record and key not in result:
            result[key] = record[key]
    return result


def _span_name(record: dict[str, Any], attrs: dict[str, Any]) -> str:
    name = _first_present(record, ("name", "span_name", "spanName"))
    if name is not None:
        return str(name)
    for key in ("gen_ai.tool.name", "tool", "gen_ai.agent.name", "agent", "gen_ai.request.model", "model"):
        if key in attrs:
            return str(attrs[key])
    operation = attrs.get("gen_ai.operation.name")
    return str(operation or "span")


def _event_span_name(record: dict[str, Any], event_name: str) -> str:
    for key in ("tool", "model", "agent"):
        value = record.get(key)
        if value:
            return str(value)
    clean = re.sub(r"\.(start|end|finish|finished|complete|completed)$", "", event_name, flags=re.IGNORECASE)
    clean = re.sub(r"_(start|end|finish|finished|complete|completed)$", "", clean, flags=re.IGNORECASE)
    return clean or "event"


def _span_kind(record: dict[str, Any], attrs: dict[str, Any]) -> str:
    kind = _first_present(record, ("kind", "span_kind", "spanKind"))
    if kind is not None and str(kind).lower() not in {"client", "server", "internal", "producer", "consumer"}:
        return str(kind).lower()
    operation = str(attrs.get("gen_ai.operation.name") or "").lower()
    if "tool" in operation:
        return "tool"
    if "agent" in operation:
        return "agent"
    if "model" in operation or "chat" in operation or "completion" in operation:
        return "model"
    if "gen_ai.tool.name" in attrs or "tool" in attrs:
        return "tool"
    if "gen_ai.agent.name" in attrs or "agent" in attrs:
        return "agent"
    if "gen_ai.request.model" in attrs or "model" in attrs:
        return "model"
    return "span"


def _event_kind(record: dict[str, Any], event_name: str) -> str:
    lowered = event_name.lower()
    if "tool" in record or "tool" in lowered:
        return "tool"
    if "model" in record or "llm" in lowered or "completion" in lowered:
        return "model"
    if "agent" in record or "agent" in lowered:
        return "agent"
    return "event"


def _phase(record: dict[str, Any], event_name: str) -> str:
    phase = str(record.get("phase") or "").lower()
    lowered = event_name.lower()
    if phase in {"start", "begin", "started"} or lowered.endswith((".start", "_start", ":start")):
        return "start"
    if phase in {"end", "finish", "finished", "complete", "completed"} or lowered.endswith(
        (".end", "_end", ":end", ".finish", "_finish", ".complete", "_complete")
    ):
        return "end"
    return "instant"


def _status(record: dict[str, Any], attrs: dict[str, Any]) -> str:
    status = _first_present(record, ("status", "status_code", "statusCode"))
    if isinstance(status, dict):
        status = _first_present(status, ("code", "status_code", "message"))
    status = status if status is not None else attrs.get("status")
    error = record.get("error") or attrs.get("error")
    if error and str(error).lower() not in {"false", "none", "null", "0"}:
        return "error"
    if status is None:
        return "ok"
    text = str(status).lower()
    if text in {"ok", "success", "succeeded", "unset", "0"}:
        return "ok"
    if text in {"error", "err", "failed", "failure", "exception", "2"}:
        return "error"
    return text


def _is_error(span: TimelineSpan) -> bool:
    if span.status.lower() == "error":
        return True
    value = span.attributes.get("error")
    return bool(value and str(value).lower() not in {"false", "none", "null", "0"})


def _first_present(mapping: dict[str, Any], keys: Iterable[str]) -> Any:
    for key in keys:
        if key in mapping and mapping[key] is not None:
            return mapping[key]
    return None


def _optional_str(value: Any) -> str | None:
    if value is None or value == "":
        return None
    return str(value)


def _parse_time_ms(value: Any) -> int | None:
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)):
        numeric = float(value)
        if numeric > 10_000_000_000_000_000:
            return int(numeric / 1_000_000)
        if numeric > 10_000_000_000_000:
            return int(numeric / 1_000)
        if numeric > 10_000_000_000:
            return int(numeric)
        return int(numeric * 1000)
    text = str(value).strip()
    if text.isdigit():
        return _parse_time_ms(int(text))
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return int(parsed.timestamp() * 1000)


def _parse_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(number):
        return None
    return int(number)


def _sort_time(span: TimelineSpan) -> int:
    for value in (span.start_ms, span.end_ms):
        if value is not None:
            return value
    return 0


def _sum_numeric_attributes(spans: list[TimelineSpan], keys: tuple[str, ...]) -> float:
    total = 0.0
    for span in spans:
        for key in keys:
            if key in span.attributes:
                try:
                    total += float(span.attributes[key])
                except (TypeError, ValueError):
                    pass
                break
    return total


def _count_findings(findings: Iterable[Finding]) -> dict[str, int]:
    totals = {"info": 0, "warning": 0, "error": 0}
    for finding in findings:
        totals[finding.severity] = totals.get(finding.severity, 0) + 1
    return totals


def _highest_severity(findings: Iterable[Finding]) -> str:
    highest = "ok"
    current = 0
    for finding in findings:
        order = SEVERITY_ORDER[finding.severity]
        if order > current:
            highest = finding.severity
            current = order
    return highest


def _children_by_parent(spans: Iterable[TimelineSpan]) -> dict[str, list[TimelineSpan]]:
    children: dict[str, list[TimelineSpan]] = {}
    ids = set()
    for span in spans:
        ids.add(span.span_id)
        if span.parent_id:
            children.setdefault(span.parent_id, []).append(span)
    children["__all_ids__"] = list(ids)  # type: ignore[assignment]
    return children


def _append_span(
    parts: list[str],
    span: TimelineSpan,
    children: dict[str, list[TimelineSpan]],
    base_ms: int,
    depth: int,
) -> None:
    offset = max(0, _sort_time(span) - base_ms) / 1000
    duration = f"{span.duration_ms / 1000:.3f}s" if span.duration_ms is not None else "open"
    indent = "  " * depth
    parts.append(f"{offset:8.3f}s {indent}{span.kind}:{span.name} [{span.status}] {duration}")
    for child in sorted(children.get(span.span_id, []), key=lambda item: (_sort_time(item), item.line, item.span_id)):
        _append_span(parts, child, children, base_ms, depth + 1)
