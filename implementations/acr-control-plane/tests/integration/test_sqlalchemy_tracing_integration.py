"""Real asyncpg query-span regression against the disposable integration stack."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


def test_postgres_query_emits_database_span() -> None:
    # Integration conftest selects the disposable database and requires opt-in.
    env = {
        **os.environ,
        "OTEL_SDK_DISABLED": "false",
        "OTEL_TRACES_SAMPLER": "always_on",
        "ACR_TRACING_TEST_DATABASE_URL": os.environ["DATABASE_URL"],
    }
    probe = Path(__file__).resolve().parents[1] / "helpers/sqlalchemy_tracing_probe.py"
    result = subprocess.run(
        [sys.executable, str(probe), "async"],
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert '"database": "postgresql"' in result.stdout
    assert '"query_spans": 1' in result.stdout
