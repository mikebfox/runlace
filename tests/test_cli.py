from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


class CliTests(unittest.TestCase):
    def test_cli_json_smoke(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            trace_path = Path(tmp) / "trace.jsonl"
            trace_path.write_text(
                json.dumps(
                    {
                        "span_id": "s1",
                        "name": "invoke_agent",
                        "start_time": "2026-05-27T10:00:00Z",
                        "end_time": "2026-05-27T10:00:01Z",
                        "status": "ok",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            env = dict(os.environ)
            env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src")

            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "runlace.cli",
                    str(trace_path),
                    "--format",
                    "json",
                    "--fail-on",
                    "never",
                ],
                check=False,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["spans"][0]["name"], "invoke_agent")


if __name__ == "__main__":
    unittest.main()
