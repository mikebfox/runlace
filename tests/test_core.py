from __future__ import annotations

import json
import unittest

from runlace import RunlaceOptions, analyze_jsonl, format_text_report, should_fail


class AnalyzeJsonlTests(unittest.TestCase):
    def test_folds_start_end_events_into_timeline(self) -> None:
        source = "\n".join(
            [
                json.dumps(
                    {
                        "ts": "2026-05-27T10:00:00Z",
                        "event": "agent.start",
                        "id": "run",
                        "agent": "triage",
                    }
                ),
                json.dumps(
                    {
                        "ts": "2026-05-27T10:00:01Z",
                        "event": "tool.start",
                        "id": "tool-1",
                        "parent": "run",
                        "tool": "github.search",
                    }
                ),
                json.dumps(
                    {
                        "ts": "2026-05-27T10:00:03Z",
                        "event": "tool.end",
                        "id": "tool-1",
                        "status": "ok",
                    }
                ),
                json.dumps(
                    {
                        "ts": "2026-05-27T10:00:04Z",
                        "event": "agent.end",
                        "id": "run",
                        "status": "ok",
                    }
                ),
            ]
        )

        report = analyze_jsonl(source)

        self.assertTrue(report.ok)
        self.assertEqual(len(report.spans), 2)
        self.assertEqual(report.spans[0].span_id, "run")
        self.assertEqual(report.spans[0].duration_ms, 4000)
        self.assertEqual(report.spans[1].parent_id, "run")
        self.assertEqual(report.totals["error"], 0)
        self.assertIn("agent:triage", format_text_report(report))

    def test_reports_invalid_json_and_unclosed_span(self) -> None:
        source = "\n".join(
            [
                '{"ts":"2026-05-27T10:00:00Z","event":"tool.start","id":"lookup","tool":"search"}',
                "not json",
            ]
        )

        report = analyze_jsonl(source)

        self.assertFalse(report.ok)
        self.assertTrue(should_fail(report, "warning"))
        self.assertEqual({finding.rule_id for finding in report.findings}, {"RL001", "RL006"})

    def test_redacts_sensitive_trace_attributes(self) -> None:
        source = json.dumps(
            {
                "trace_id": "t1",
                "span_id": "s1",
                "name": "execute_tool github.create_issue",
                "start_time": "2026-05-27T10:00:00Z",
                "end_time": "2026-05-27T10:00:01Z",
                "attributes": {
                    "gen_ai.operation.name": "execute_tool",
                    "gen_ai.tool.name": "github.create_issue",
                    "api_key": "sk-abcdefghijklmnopqrstuvwxyz",
                    "request": "token ghp_abcdefghijklmnopqrstuvwx123456",
                },
            }
        )

        report = analyze_jsonl(source)

        self.assertEqual(report.redactions, 2)
        self.assertEqual(report.totals["warning"], 1)
        rendered = json.dumps(report.to_dict())
        self.assertNotIn("sk-abcdefghijklmnopqrstuvwxyz", rendered)
        self.assertNotIn("ghp_abcdefghijklmnopqrstuvwx123456", rendered)
        self.assertIn("<redacted:key>", rendered)

    def test_detects_repeats_long_gaps_and_budget(self) -> None:
        rows = []
        for index in range(4):
            rows.append(
                {
                    "ts": f"2026-05-27T10:00:0{index}Z",
                    "event": "tool.call",
                    "id": f"tool-{index}",
                    "tool": "search",
                    "tokens": 400,
                }
            )
        rows.append(
            {
                "ts": "2026-05-27T10:02:00Z",
                "event": "model.call",
                "id": "model",
                "model": "gpt-test",
            }
        )
        source = "\n".join(json.dumps(row) for row in rows)

        report = analyze_jsonl(source, RunlaceOptions(max_gap_ms=10_000, max_repeat=4, token_budget=1000))

        rule_ids = {finding.rule_id for finding in report.findings}
        self.assertIn("RL003", rule_ids)
        self.assertIn("RL004", rule_ids)
        self.assertIn("RL009", rule_ids)


if __name__ == "__main__":
    unittest.main()
