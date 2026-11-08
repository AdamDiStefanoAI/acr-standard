"""The upgrade shell must reject candidate inputs before stopping live services."""

import os
import subprocess
from pathlib import Path

import pytest


@pytest.mark.parametrize("failure", ["export", "compile", "database", "none"])
def test_preflight_precedes_cutover_and_cleans_its_volume(tmp_path, failure):
    script = Path(__file__).parents[1] / "scripts/upgrade_compose.sh"
    docker = tmp_path / "docker"
    docker.write_text(
        "#!/usr/bin/env python3\n"
        "import json, os, sys\n"
        "args = sys.argv[1:]\n"
        "with open(os.environ['CALLS'], 'a') as stream: stream.write(json.dumps(args) + '\\n')\n"
        "if args[:2] == ['volume', 'create']: print('synthetic-preflight-volume')\n"
        "failure = os.environ['FAILURE']\n"
        "if failure == 'export' and '/preflight' in args: sys.exit(23)\n"
        "if failure == 'compile' and 'check' in args: sys.exit(24)\n"
        "if failure == 'database' and 'preflight' in args: sys.exit(25)\n"
    )
    docker.chmod(0o755)
    calls_file = tmp_path / "calls.jsonl"
    result = subprocess.run(
        ["sh", str(script)],
        env={
            **os.environ,
            "PATH": str(tmp_path) + os.pathsep + os.environ["PATH"],
            "CALLS": str(calls_file),
            "FAILURE": failure,
            "ACR_GATEWAY_IMAGE": "test-only:candidate",
            "SERVICE_OPERATOR_API_KEY": "test-key",
            "OPERATOR_API_KEYS_JSON": '{"test-key":{"roles":["auditor"]}}',
        },
        capture_output=True,
        text=True,
    )
    import json

    calls = [json.loads(line) for line in calls_file.read_text().splitlines()]
    removals = [c for c in calls if c[:2] == ["volume", "rm"]]
    assert removals == [["volume", "rm", "synthetic-preflight-volume"]]
    stops = [i for i, c in enumerate(calls) if c[:2] == ["compose", "stop"]]
    if failure == "none":
        assert result.returncode == 0, result.stderr
        compilation = next(i for i, c in enumerate(calls) if "check" in c)
        database_check = next(i for i, c in enumerate(calls) if "preflight" in c)
        assert len(stops) == 1 and compilation < database_check < stops[0]
    else:
        assert result.returncode in {23, 24, 25}
        assert not stops
        assert not any(c[:2] == ["compose", "up"] for c in calls)
