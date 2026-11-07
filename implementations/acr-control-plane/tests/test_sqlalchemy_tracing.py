"""Verify real query spans, not just successful package imports or HTTP responses."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest


@pytest.mark.parametrize("mode", ["sync", "async"])
def test_sqlite_query_emits_database_span(mode: str) -> None:
    env = {**os.environ, "OTEL_SDK_DISABLED": "false", "OTEL_TRACES_SAMPLER": "always_on"}
    env.pop("ACR_TRACING_TEST_DATABASE_URL", None)
    result = subprocess.run(
        [sys.executable, str(Path(__file__).parent / "helpers/sqlalchemy_tracing_probe.py"), mode],
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert '"query_spans": 1' in result.stdout
