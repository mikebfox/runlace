"""Local-first summaries and safety checks for AI agent JSONL traces."""

from .core import (
    Finding,
    RunlaceOptions,
    TimelineSpan,
    TraceReport,
    analyze_jsonl,
    format_text_report,
    should_fail,
)

__all__ = [
    "Finding",
    "RunlaceOptions",
    "TimelineSpan",
    "TraceReport",
    "analyze_jsonl",
    "format_text_report",
    "should_fail",
]

__version__ = "0.1.0"
