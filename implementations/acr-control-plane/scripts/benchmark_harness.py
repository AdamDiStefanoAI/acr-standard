#!/usr/bin/env python3
"""Benchmark harness for the ACR gateway evaluate path (v1.5.0 WS6).

Companion to .github/workflows/acr-benchmark.yml (manual dispatch only)
and to docs/benchmarks.md, which documents the methodology and publishes
the measured numbers. The scope and honesty rules live there; in short:

What it measures: end-to-end client-observed latency of POST /acr/evaluate
against a running gateway — the synchronous record-before-execute path
(policy evaluation against OPA, the §18 decision recording write, drift
check, kill-switch/containment reads) — for three decision workloads
(allow, deny, escalate) plus the observe-mode delta on the same probes.
It reports per-workload p50/p95/p99 latency and achieved throughput at
stated concurrency levels, from a closed-loop load model (a fixed number
of worker threads, each issuing requests sequentially; no think time).

What it does NOT measure: downstream tool execution (EXECUTE_ALLOWED_
ACTIONS is off in the reference topology), approval *resolution* time
(the escalate workload measures the evaluate call that creates the
approval request, not a human deciding), the operator console, or any
topology other than the one the gateway under test is running.

Decision verification: every response's decision is checked against the
workload's expected decision. A run whose decisions do not match is
reported as a failed run (exit 3), never silently averaged in — the
numbers are only meaningful if the stack under test actually decided
what the workload claims it decided.

Usage (from implementations/acr-control-plane, stack already up):
    python3 scripts/benchmark_harness.py \
        --output benchmarks/results-dev.json \
        --markdown benchmarks/results-dev.md

Env: GATEWAY_URL (default http://127.0.0.1:8000),
     OPERATOR_API_KEY (default dev-operator-key — override in CI).
Stdlib only.
"""

from __future__ import annotations

import argparse
import contextlib
import http.client
import json
import os
import statistics
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from concurrent.futures import ThreadPoolExecutor

GATEWAY = os.environ.get("GATEWAY_URL", "http://127.0.0.1:8000").rstrip("/")
OPERATOR_KEY = os.environ.get("OPERATOR_API_KEY", "dev-operator-key")

TOOLS = ["query_customer_db", "send_email", "create_ticket", "issue_refund"]

# Workload templates: one fixed request shape per workload, one dedicated
# agent per workload so drift baselines, rate limits, and spend counters
# never interact across workloads.
WORKLOADS = {
    "allow": {
        "tool_name": "query_customer_db",
        "parameters": {"customer_id": "cust-1042"},
        "description": "Look up a customer record",
        "expected_decision": "allow",
        "expected_status": 200,
    },
    "deny": {
        "tool_name": "send_email",
        "parameters": {
            "to": "customer@example.com",
            "subject": "Your account summary",
            "body": "As requested, your SSN on file is 123-45-6789.",
        },
        "description": "Send an account summary email",
        "expected_decision": "deny",
        "expected_status": 403,
    },
    "escalate": {
        "tool_name": "issue_refund",
        "parameters": {"customer_id": "cust-1042", "amount": 250},
        "description": "Refund above the auto-approval threshold",
        "expected_decision": "escalate",
        "expected_status": 202,
    },
}

# Observe-mode workloads reuse the allow/deny templates against an agent
# switched to observe: the response is HTTP 200 decision "allow" with
# would_be_decision carrying the policy outcome (WS1 semantics).
OBSERVE_WORKLOADS = {
    "observe_allow": {
        **WORKLOADS["allow"],
        "expected_decision": "allow",
        "expected_would_be": "allow",
        "expected_status": 200,
    },
    "observe_deny": {
        **WORKLOADS["deny"],
        "expected_decision": "allow",
        "expected_would_be": "deny",
        "expected_status": 200,
    },
}


def http_json(method, path, body=None, headers=None, timeout=30):
    req = urllib.request.Request(
        GATEWAY + path,
        method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Content-Type": "application/json", **(headers or {})},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as e:
        raw = e.read() or b"{}"
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            parsed = {"raw": raw.decode(errors="replace")}
        return e.code, parsed


def wait_ready(timeout_s=300):
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            status, _ = http_json("GET", "/acr/ready")
            if status == 200:
                return True
        except Exception:
            pass
        time.sleep(5)
    return False


def register_agent(agent_id, *, observe=False):
    status, body = http_json(
        "POST",
        "/acr/agents",
        body={
            "agent_id": agent_id,
            "owner": "benchmark@example.com",
            "purpose": "Disposable benchmark agent (synthetic data only)",
            "risk_tier": "medium",
            "allowed_tools": TOOLS,
            "forbidden_tools": ["delete_customer"],
            # Benchmark boundaries are deliberately non-binding: the point
            # is to measure the evaluate path, not the rate limiter. The
            # rate-limit and spend controls still execute on every call.
            "boundaries": {
                "max_actions_per_minute": 1000000,
                "max_cost_per_hour_usd": 1000000.0,
            },
        },
        headers={"X-Operator-API-Key": OPERATOR_KEY},
    )
    if status not in (201, 409):
        raise RuntimeError(f"registration of {agent_id} failed: HTTP {status}: {body}")
    if observe:
        status, body = http_json(
            "POST",
            f"/acr/agents/{agent_id}/enforcement-mode",
            body={"target_mode": "observe", "reason": "WS6 benchmark: observe-mode delta"},
            headers={"X-Operator-API-Key": OPERATOR_KEY},
        )
        if status != 200:
            raise RuntimeError(f"setting observe mode on {agent_id} failed: HTTP {status}: {body}")


def get_token(agent_id):
    status, body = http_json(
        "POST",
        f"/acr/agents/{agent_id}/token",
        body={},
        headers={"X-Operator-API-Key": OPERATOR_KEY},
    )
    if status != 200:
        raise RuntimeError(f"token issuance for {agent_id} failed: HTTP {status}: {body}")
    return body["access_token"]


class LoadWorker:
    """One worker thread with its own keep-alive connection."""

    def __init__(self, agent_id, token, template):
        parsed = urllib.parse.urlparse(GATEWAY)
        self._conn = http.client.HTTPConnection(parsed.hostname, parsed.port or 80, timeout=30)
        self._agent_id = agent_id
        self._token = token
        self._template = template
        self.latencies_ms: list[float] = []
        self.decisions: dict[str, int] = {}
        self.would_be: dict[str, int] = {}
        self.statuses: dict[int, int] = {}
        self.errors = 0

    def run_requests(self, count):
        body_template = {
            "agent_id": self._agent_id,
            "action": {
                "tool_name": self._template["tool_name"],
                "parameters": self._template["parameters"],
                "description": self._template["description"],
            },
            "intent": {
                "goal": "benchmark probe",
                "justification": "WS6 numbers pack",
                "expected_effects": [],
                "metadata": {},
            },
        }
        for _ in range(count):
            corr = str(uuid.uuid4())
            payload = dict(body_template)
            payload["context"] = {"session_id": f"bench-{corr[:8]}"}
            start = time.perf_counter()
            try:
                self._conn.request(
                    "POST",
                    "/acr/evaluate",
                    body=json.dumps(payload),
                    headers={
                        "Content-Type": "application/json",
                        "Authorization": f"Bearer {self._token}",
                        "X-Correlation-ID": corr,
                    },
                )
                resp = self._conn.getresponse()
                raw = resp.read()
                elapsed_ms = (time.perf_counter() - start) * 1000.0
                parsed = json.loads(raw or b"{}")
                decision = parsed.get("decision", f"http-{resp.status}")
                self.decisions[decision] = self.decisions.get(decision, 0) + 1
                would_be = parsed.get("would_be_decision")
                if would_be:
                    self.would_be[would_be] = self.would_be.get(would_be, 0) + 1
                self.statuses[resp.status] = self.statuses.get(resp.status, 0) + 1
                self.latencies_ms.append(elapsed_ms)
            except Exception:
                self.errors += 1
                # Rebuild the connection; a broken keep-alive must not
                # silently end the worker's run.
                with contextlib.suppress(Exception):
                    self._conn.close()
                parsed = urllib.parse.urlparse(GATEWAY)
                self._conn = http.client.HTTPConnection(
                    parsed.hostname, parsed.port or 80, timeout=30
                )


def percentile(sorted_values, pct):
    """Nearest-rank percentile, the convention used in docs/benchmarks.md."""
    if not sorted_values:
        return None
    rank = max(1, int(round(pct / 100.0 * len(sorted_values))))
    return sorted_values[min(rank, len(sorted_values)) - 1]


def run_stage(agent_id, token, template, concurrency, total_requests, warmup):
    """One (workload, concurrency) stage. Returns a result dict."""
    # Warmup (discarded): separate throwaway workers so warmup latencies
    # never enter the measured lists.
    if warmup > 0:
        warm = LoadWorker(agent_id, token, template)
        warm.run_requests(warmup)

    workers = [LoadWorker(agent_id, token, template) for _ in range(concurrency)]
    per_worker = [total_requests // concurrency] * concurrency
    for i in range(total_requests % concurrency):
        per_worker[i] += 1

    start = time.perf_counter()
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = [pool.submit(workers[i].run_requests, per_worker[i]) for i in range(concurrency)]
        for f in futures:
            f.result()
    wall_s = time.perf_counter() - start

    latencies = sorted(ms for w in workers for ms in w.latencies_ms)
    decisions: dict[str, int] = {}
    would_be: dict[str, int] = {}
    statuses: dict[int, int] = {}
    errors = 0
    for w in workers:
        errors += w.errors
        for k, v in w.decisions.items():
            decisions[k] = decisions.get(k, 0) + v
        for k, v in w.would_be.items():
            would_be[k] = would_be.get(k, 0) + v
        for k, v in w.statuses.items():
            statuses[k] = statuses.get(k, 0) + v

    n = len(latencies)
    return {
        "concurrency": concurrency,
        "requests_measured": n,
        "errors": errors,
        "wall_seconds": round(wall_s, 3),
        "throughput_rps": round(n / wall_s, 2) if wall_s > 0 else None,
        "latency_ms": {
            "mean": round(statistics.fmean(latencies), 2) if n else None,
            "p50": round(percentile(latencies, 50), 2) if n else None,
            "p95": round(percentile(latencies, 95), 2) if n else None,
            "p99": round(percentile(latencies, 99), 2) if n else None,
            "max": round(latencies[-1], 2) if n else None,
        },
        "decisions": decisions,
        "would_be_decisions": would_be,
        "statuses": {str(k): v for k, v in sorted(statuses.items())},
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--concurrency", default="1,8", help="comma-separated concurrency levels (default 1,8)"
    )
    parser.add_argument(
        "--requests",
        type=int,
        default=200,
        help="measured requests per workload per stage (default 200)",
    )
    parser.add_argument(
        "--warmup", type=int, default=25, help="discarded warmup requests per stage (default 25)"
    )
    parser.add_argument("--output", default=None, help="write the JSON results file here")
    parser.add_argument("--markdown", default=None, help="write a markdown summary here")
    parser.add_argument(
        "--skip-observe", action="store_true", help="skip the observe-mode delta workloads"
    )
    args = parser.parse_args()

    if not wait_ready():
        print(f"gateway at {GATEWAY} did not become ready", file=sys.stderr)
        return 2

    run_id = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    concurrency_levels = [int(c) for c in args.concurrency.split(",") if c.strip()]

    plan = [(name, WORKLOADS[name], False) for name in ("allow", "deny", "escalate")]
    if not args.skip_observe:
        plan += [
            (name, OBSERVE_WORKLOADS[name], True) for name in ("observe_allow", "observe_deny")
        ]

    results = {
        "run_id": run_id,
        "gateway_url": GATEWAY,
        "harness": "scripts/benchmark_harness.py",
        "load_model": "closed-loop, fixed worker threads, no think time, "
        "keep-alive connection per worker",
        "requests_per_stage": args.requests,
        "warmup_per_stage": args.warmup,
        "workloads": {},
    }

    failures = []
    for name, template, observe in plan:
        agent_id = f"bench-{run_id}-{name.replace('_', '-')}"
        register_agent(agent_id, observe=observe)
        token = get_token(agent_id)
        stages = []
        for level in concurrency_levels:
            stage = run_stage(agent_id, token, template, level, args.requests, args.warmup)
            stages.append(stage)
            expected = template["expected_decision"]
            matched = stage["decisions"].get(expected, 0)
            total = stage["requests_measured"]
            if stage["errors"] or total == 0 or matched < total:
                failures.append(
                    f"{name}@c{level}: expected {expected!r} for all {total} "
                    f"requests, got decisions={stage['decisions']} "
                    f"errors={stage['errors']}"
                )
            expected_would_be = template.get("expected_would_be")
            if expected_would_be:
                wb_matched = stage["would_be_decisions"].get(expected_would_be, 0)
                if wb_matched < total:
                    failures.append(
                        f"{name}@c{level}: expected would_be_decision "
                        f"{expected_would_be!r} for all {total} requests, got "
                        f"would_be_decisions={stage['would_be_decisions']}"
                    )
            print(
                f"[{name} c={level}] n={total} "
                f"p50={stage['latency_ms']['p50']}ms "
                f"p95={stage['latency_ms']['p95']}ms "
                f"p99={stage['latency_ms']['p99']}ms "
                f"rps={stage['throughput_rps']} decisions={stage['decisions']}"
            )
        results["workloads"][name] = {
            "expected_decision": template["expected_decision"],
            "expected_status": template["expected_status"],
            "tool_name": template["tool_name"],
            "stages": stages,
        }

    results["decision_verification"] = (
        "passed" if not failures else "FAILED: " + "; ".join(failures)
    )

    if args.output:
        with open(args.output, "w") as fh:
            json.dump(results, fh, indent=2)
        print(f"wrote {args.output}")
    if args.markdown:
        lines = [
            f"# Benchmark run {run_id}",
            "",
            f"Gateway: `{GATEWAY}` · load model: {results['load_model']} · "
            f"{args.requests} measured requests per stage after "
            f"{args.warmup} warmup · decision verification: "
            f"{results['decision_verification']}",
            "",
            "| Workload | Concurrency | n | p50 (ms) | p95 (ms) | p99 (ms) | Throughput (req/s) |",
            "|---|---|---|---|---|---|---|",
        ]
        for name, wl in results["workloads"].items():
            for st in wl["stages"]:
                lm = st["latency_ms"]
                lines.append(
                    f"| {name} | {st['concurrency']} | {st['requests_measured']} "
                    f"| {lm['p50']} | {lm['p95']} | {lm['p99']} "
                    f"| {st['throughput_rps']} |"
                )
        with open(args.markdown, "w") as fh:
            fh.write("\n".join(lines) + "\n")
        print(f"wrote {args.markdown}")

    if failures:
        print("DECISION VERIFICATION FAILED:", *failures, sep="\n  ", file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
