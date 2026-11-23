"""Unit checks for the WS6 benchmark harness's math and workload table.

The harness itself runs against a live stack (CI: acr-benchmark.yml);
these tests pin the pieces that must not drift silently — the
percentile convention published in docs/benchmarks.md and the expected
decision of every workload, including the observe-mode would-be
expectations.
"""

import importlib.util
from pathlib import Path

import pytest


@pytest.fixture(scope="module")
def harness():
    path = Path(__file__).parents[1] / "scripts/benchmark_harness.py"
    spec = importlib.util.spec_from_file_location("benchmark_harness_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_percentile_nearest_rank(harness):
    values = list(range(1, 101))  # 1..100, already sorted
    assert harness.percentile(values, 50) == 50
    assert harness.percentile(values, 95) == 95
    assert harness.percentile(values, 99) == 99
    assert harness.percentile(values, 100) == 100


def test_percentile_small_samples(harness):
    assert harness.percentile([10.0], 50) == 10.0
    assert harness.percentile([10.0], 99) == 10.0
    assert harness.percentile([1.0, 2.0, 3.0], 50) == 2.0
    assert harness.percentile([], 50) is None


def test_workload_expected_decisions(harness):
    assert harness.WORKLOADS["allow"]["expected_decision"] == "allow"
    assert harness.WORKLOADS["allow"]["expected_status"] == 200
    assert harness.WORKLOADS["deny"]["expected_decision"] == "deny"
    assert harness.WORKLOADS["deny"]["expected_status"] == 403
    assert harness.WORKLOADS["escalate"]["expected_decision"] == "escalate"
    assert harness.WORKLOADS["escalate"]["expected_status"] == 202


def test_observe_workloads_wrap_enforce_templates(harness):
    # Observe responds 200/allow in both cases; the comparable signal is
    # would_be_decision, which must mirror the underlying enforce probe.
    for name, underlying in (("observe_allow", "allow"), ("observe_deny", "deny")):
        template = harness.OBSERVE_WORKLOADS[name]
        assert template["expected_decision"] == "allow"
        assert template["expected_status"] == 200
        assert template["expected_would_be"] == underlying
        assert template["tool_name"] == harness.WORKLOADS[underlying]["tool_name"]
        assert template["parameters"] == harness.WORKLOADS[underlying]["parameters"]
