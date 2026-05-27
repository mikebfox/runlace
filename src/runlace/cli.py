"""Command-line interface for runlace."""

from __future__ import annotations

import argparse
import json
import sys

from .core import RunlaceOptions, analyze_jsonl, format_text_report, should_fail


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="runlace",
        description="Summarize and safety-check AI agent JSONL traces locally.",
    )
    parser.add_argument("trace", nargs="?", default="-", help="JSONL trace path, or '-' for stdin.")
    parser.add_argument("--format", choices=("text", "json"), default="text", help="Output format.")
    parser.add_argument(
        "--fail-on",
        choices=("info", "warning", "error", "never"),
        default="error",
        help="Exit with status 1 when findings meet this severity.",
    )
    parser.add_argument("--max-gap-ms", type=int, default=30_000, help="Warn on idle gaps above this size.")
    parser.add_argument("--max-repeat", type=int, default=4, help="Warn when adjacent spans repeat this many times.")
    parser.add_argument("--token-budget", type=int, help="Warn when total token attributes exceed this value.")
    parser.add_argument("--cost-budget", type=float, help="Warn when total cost attributes exceed this value.")
    args = parser.parse_args(argv)

    try:
        source = _read_trace(args.trace)
    except OSError as exc:
        parser.error(str(exc))

    report = analyze_jsonl(
        source,
        RunlaceOptions(
            max_gap_ms=args.max_gap_ms,
            max_repeat=args.max_repeat,
            token_budget=args.token_budget,
            cost_budget=args.cost_budget,
        ),
    )

    if args.format == "json":
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    else:
        print(format_text_report(report))

    return 1 if should_fail(report, args.fail_on) else 0


def _read_trace(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read()


if __name__ == "__main__":
    raise SystemExit(main())
