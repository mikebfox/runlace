# runlace

`runlace` turns local AI-agent JSONL traces into a compact, redacted timeline with deterministic safety checks.

Agent observability is moving toward OpenTelemetry GenAI conventions, but many teams still debug agent runs from raw JSONL: custom loop logs, CLI traces, local harness output, or exported span rows. Those files are useful, but they are noisy and often contain prompt fragments, tool arguments, credentials, retry storms, and gaps that are hard to review before attaching the trace to an issue.

`runlace` keeps that workflow local. It reads JSONL, folds start/end rows or OTel-like span rows into a timeline, redacts sensitive values before rendering, and reports the problems that usually matter during incident review.

## Why this exists

Recent AI-agent tooling trends point in the same direction:

- Agent traces need to show model calls, tool calls, retries, and parent-child relationships, not just application logs.
- OpenTelemetry GenAI conventions are converging, but many traces are still exported as local JSONL first.
- Prompt and tool-call content can contain secrets, customer data, or raw credentials, so trace sharing needs redaction by default.
- Small teams often need a CI artifact or issue attachment, not a hosted observability platform.

`runlace` is intentionally narrow: it is an offline trace reviewer, not an SDK, collector, dashboard, or LLM judge.

## Install

The package is not published to PyPI yet. Once the public GitHub repository is available, install it with:

```sh
python3 -m pip install "git+https://github.com/mikebfox/runlace.git"
```

For local development from a checkout:

```sh
python3 -m pip install -e .
```

Requires Python 3.10 or newer.

## CLI usage

Summarize a trace:

```sh
runlace trace.jsonl
```

Read from stdin:

```sh
cat trace.jsonl | runlace -
```

Use JSON output for CI or an issue artifact:

```sh
runlace trace.jsonl --format json
```

Fail on warnings:

```sh
runlace trace.jsonl --fail-on warning
```

Tighten loop and budget checks:

```sh
runlace trace.jsonl --max-gap-ms 10000 --max-repeat 3 --token-budget 20000 --cost-budget 2.50
```

Example input:

```jsonl
{"ts":"2026-05-27T10:00:00Z","event":"agent.start","id":"run","agent":"triage"}
{"ts":"2026-05-27T10:00:01Z","event":"tool.start","id":"call-1","parent":"run","tool":"github.search"}
{"ts":"2026-05-27T10:00:03Z","event":"tool.end","id":"call-1","status":"ok"}
{"ts":"2026-05-27T10:00:04Z","event":"agent.end","id":"run","status":"ok"}
```

Example output:

```text
runlace: ok - 2 span(s), 0 finding(s), 0 redaction(s)

Timeline
   0.000s agent:triage [ok] 4.000s
   1.000s   tool:github.search [ok] 2.000s
```

## Library usage

```python
from runlace import RunlaceOptions, analyze_jsonl, format_text_report, should_fail

source = """
{"span_id":"root","name":"invoke_agent","start_time":"2026-05-27T10:00:00Z","end_time":"2026-05-27T10:00:02Z","status":"ok"}
{"span_id":"tool-1","parent_span_id":"root","name":"execute_tool search","start_time":"2026-05-27T10:00:01Z","end_time":"2026-05-27T10:00:02Z","status":"error"}
""".strip()

report = analyze_jsonl(
    source,
    RunlaceOptions(max_gap_ms=10_000, max_repeat=3, token_budget=20_000),
)

print(format_text_report(report))

if should_fail(report, "warning"):
    raise SystemExit(1)
```

## Input shape

`runlace` accepts one JSON object per line. It understands complete span records:

```json
{
  "span_id": "tool-1",
  "parent_span_id": "root",
  "name": "execute_tool github.search",
  "start_time": "2026-05-27T10:00:01Z",
  "end_time": "2026-05-27T10:00:02Z",
  "status": "ok",
  "attributes": {
    "gen_ai.operation.name": "execute_tool",
    "gen_ai.tool.name": "github.search"
  }
}
```

It also understands loose start/end event rows:

```json
{"ts":"2026-05-27T10:00:01Z","event":"tool.start","id":"tool-1","parent":"root","tool":"github.search"}
{"ts":"2026-05-27T10:00:02Z","event":"tool.end","id":"tool-1","status":"ok"}
```

Timestamps may be ISO-8601 strings, Unix seconds, Unix milliseconds, microseconds, or nanoseconds.

## API and options

### `analyze_jsonl(source, options=None)`

Returns a `TraceReport` with:

- `spans`: normalized timeline spans.
- `findings`: deterministic findings with rule id, severity, evidence, and fix.
- `redactions`: number of redacted values.
- `totals`: finding counts by severity.
- `ok`: true when no error findings were emitted.

### `RunlaceOptions`

- `max_gap_ms`: warn when adjacent spans have a larger idle gap. Default: `30000`.
- `max_repeat`: warn when adjacent spans with the same kind and name repeat this many times. Default: `4`.
- `token_budget`: optional total token budget warning.
- `cost_budget`: optional total cost budget warning.

### `format_text_report(report)`

Formats the findings and timeline for terminal output or issue comments.

### `should_fail(report, threshold)`

Returns whether a report should fail a gate. Thresholds: `info`, `warning`, `error`, `never`.

## Checks

- `RL001`: span started but never ended.
- `RL002`: span ended with an error status.
- `RL003`: long idle gap between spans.
- `RL004`: repeated adjacent spans that may indicate an agent loop or retry storm.
- `RL005`: sensitive trace data was redacted before rendering.
- `RL006`: invalid JSONL input.
- `RL007`: end event without a matching start event.
- `RL009`: configured token budget exceeded.
- `RL010`: configured cost budget exceeded.

Sensitive keys and values are redacted recursively before rendering. Key matches include token, secret, password, authorization, credential, session, private key, and API key terms. Value matches include common GitHub, OpenAI-style, AWS access key, and private-key patterns.

## Design notes

`runlace` does not instrument applications. It intentionally starts after a run has produced JSONL so teams can use it with any agent framework, shell wrapper, OpenTelemetry exporter, or local debug artifact.

The parser is permissive because trace formats are still moving. The output is conservative: it keeps ordering deterministic, redacts before formatting, and never calls an external service.

## Development

```sh
python3 -m pip install -e .
python3 -m unittest discover -s tests -v
python3 -m compileall -q src
```

## License

MIT
