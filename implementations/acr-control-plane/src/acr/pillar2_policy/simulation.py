"""Pillar 2: Policy simulation against recorded traffic (v1.5.0 WS2).

Answers the change-control question — "what would this bundle have done
to our actual traffic?" — before a policy change is promoted:

- Retained evaluation inputs (pillar4_observability.input_retention,
  opt-in, redacted before storage) are replayed OFFLINE against a
  candidate policy bundle with the OPA binary. No gateway, no approvals,
  no telemetry, no decision writes: the only durable output is the
  simulation run record itself.
- Each replayed input's simulated decision is derived with the same
  rules the live path uses (engine.parse_opa_result, plus the gateway's
  output-filter decision step), then diffed against the decision that
  was actually recorded for that evaluation.
- Coverage is reported honestly: decisions in the window whose inputs
  were never retained (retention off at the time) or have been purged
  are counted as missing, never silently skipped.

A run is recorded durably (policy_simulations) because it is evidence:
the WS2 promotion gate in policy_studio.releases relies on the run's
bundle hash matching the exact bundle an activation would distribute.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import uuid
from collections import Counter
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace

import structlog
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from acr.common.errors import PolicyEngineError, PolicyValidationError
from acr.common.time import utcnow
from acr.config import settings
from acr.db.models import (
    EvaluationInputRecord,
    PolicyDecisionRecord,
    PolicyReleaseRecord,
    PolicySimulationRecord,
)
from acr.pillar2_policy.engine import canonical_tool_name, parse_opa_result
from acr.pillar2_policy.models import PolicyEvaluationResult
from acr.pillar2_policy.output_filter import filter_parameters
from acr.policy_studio.distribution import RuntimeBundleArtifact, build_active_runtime_bundle

logger = structlog.get_logger(__name__)

_SAMPLE_LIMIT = 20


# ── Report models ─────────────────────────────────────────────────────────────


class SimulationFlipSample(BaseModel):
    correlation_id: str
    agent_id: str
    tool_name: str | None
    recorded_decision: str
    simulated_decision: str
    # The deciding rule for the simulated outcome: the first deny reason
    # for a simulated deny (deny reasons are what the engine exposes),
    # otherwise the simulated decision kind.
    rule: str
    reason: str | None = None
    # The stored evaluation input — already redacted before storage;
    # simulation never re-derives it from anywhere else.
    input: dict


class SimulationReport(BaseModel):
    run_id: str
    actor: str
    created_at: datetime
    bundle_label: str | None
    bundle_sha256: str
    window_start: datetime
    window_end: datetime
    decisions_in_window: int
    inputs_available: int
    inputs_missing: int
    evaluations_replayed: int
    unchanged_count: int
    # Keys are "<recorded>-><simulated>", e.g. "allow->deny".
    flip_counts: dict[str, int] = Field(default_factory=dict)
    flips_by_rule: dict[str, int] = Field(default_factory=dict)
    samples: list[SimulationFlipSample] = Field(default_factory=list)
    result_hash: str


# ── Candidate bundle construction ─────────────────────────────────────────────


async def _active_releases(db: AsyncSession) -> list[PolicyReleaseRecord]:
    # Local copy of policy_studio.releases.list_active_policy_releases:
    # releases.py imports this module for the promotion gate, so importing
    # it back would be circular.
    from sqlalchemy import desc

    result = await db.execute(
        select(PolicyReleaseRecord)
        .where(PolicyReleaseRecord.activation_status == "active")
        .order_by(PolicyReleaseRecord.agent_id, desc(PolicyReleaseRecord.version))
    )
    return list(result.scalars().all())


async def build_candidate_bundle(
    db: AsyncSession, *, agent_id: str, rego_policy: str
) -> RuntimeBundleArtifact:
    """The runtime bundle that would be distributed if this policy were
    activated for its agent: current active releases with the candidate
    substituted for its agent.

    The candidate is built with the same placeholder identity
    (release_id="candidate", version=0) that release validation has
    always used, so a simulation run and the promotion gate compute the
    bundle hash over byte-identical archives.
    """
    active = await _active_releases(db)
    candidate = SimpleNamespace(
        agent_id=agent_id,
        release_id="candidate",
        version=0,
        activated_at=None,
        rego_policy=rego_policy,
    )
    records = [item for item in active if item.agent_id != agent_id] + [candidate]
    return await asyncio.to_thread(
        build_active_runtime_bundle,
        records,
        extensions=settings.policy_extension_dir or None,
    )


async def build_release_candidate_bundle(
    db: AsyncSession, release_id: str
) -> tuple[RuntimeBundleArtifact, PolicyReleaseRecord]:
    result = await db.execute(
        select(PolicyReleaseRecord).where(PolicyReleaseRecord.release_id == release_id)
    )
    record = result.scalar_one_or_none()
    if record is None:
        raise PolicyValidationError(f"Policy release '{release_id}' not found")
    artifact = await build_candidate_bundle(
        db, agent_id=record.agent_id, rego_policy=record.rego_policy
    )
    return artifact, record


# ── Offline evaluation ────────────────────────────────────────────────────────


def _opa_binary() -> str:
    # Same lookup the bundle compiler uses (policy_studio.compiler):
    # OPA_BINARY env var, else `opa` on PATH. Simulation requires the
    # binary for the same reason bundle validation does.
    configured = os.environ.get("OPA_BINARY", "opa")
    executable = shutil.which(configured)
    if executable is None:
        raise PolicyEngineError(
            "OPA binary unavailable for policy simulation. Install OPA 0.70 "
            "on PATH or set OPA_BINARY."
        )
    return executable


def _canonicalized(manifest: dict, action: dict) -> tuple[dict, dict]:
    """Mirror of the live engine's input canonicalization (engine.evaluate_policy
    applies the same transform before calling OPA; replay must too)."""
    action_copy = dict(action)
    if action_copy.get("tool_name") is not None:
        action_copy["tool_name"] = canonical_tool_name(action_copy["tool_name"])
    manifest_copy = dict(manifest)
    for key in ("allowed_tools", "forbidden_tools"):
        tools = manifest_copy.get(key)
        if isinstance(tools, list):
            manifest_copy[key] = [canonical_tool_name(t) for t in tools]
    return manifest_copy, action_copy


def _eval_bundle_once(executable: str, bundle_path: Path, evaluation_input: dict) -> dict:
    """Run one input through the candidate bundle; return the raw data.acr value.

    The bundle is passed as the archive file itself, the same form the
    bundle compiler validates (policy_studio.compiler): the archive's
    .manifest carries per-file Rego versions that a plain directory
    extraction does not preserve reliably.
    """
    manifest, action = _canonicalized(
        evaluation_input.get("agent") or {}, evaluation_input.get("action") or {}
    )
    safe_context = {
        "actions_this_minute": 0,
        "hourly_spend_usd": 0.0,
        **(evaluation_input.get("context") or {}),
    }
    # The OPA CLI binds the --input file's content to `input` directly
    # (unlike the HTTP API, which wraps it in an "input" key).
    opa_input = {"agent": manifest, "action": action, "context": safe_context}
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", prefix="acr-sim-input-", delete=False
    ) as handle:
        json.dump(opa_input, handle)
        input_path = handle.name
    try:
        result = subprocess.run(
            [
                executable,
                "eval",
                "--bundle",
                str(bundle_path),
                "--input",
                input_path,
                "--format",
                "json",
                "data.acr",
            ],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    finally:
        Path(input_path).unlink(missing_ok=True)
    if result.returncode:
        detail = (result.stderr or result.stdout).strip()[:2000]
        raise PolicyEngineError(f"OPA simulation evaluation failed: {detail}")
    document = json.loads(result.stdout)
    results = document.get("result") or []
    if not results:
        # Undefined data.acr: the live engine treats a missing result as
        # empty, and parse_opa_result denies by default. Mirror that.
        return {}
    value = results[0].get("expressions", [{}])[0].get("value")
    return value if isinstance(value, dict) else {}


def simulated_final_decision(
    result: PolicyEvaluationResult, evaluation_input: dict, *, correlation_id: str = "simulation"
) -> str:
    """The gateway's decision derivation, minus the gateway.

    Mirrors gateway.router steps [5]-[6]: a policy modify is applied to
    the action (a modify that changes the tool name is a deny), then the
    output filter runs, and an allow the filter had to redact becomes a
    modify. Everything here is local and deterministic.
    """
    final = result.final_decision
    effective_action = dict(evaluation_input.get("action") or {})
    if final == "modify":
        if result.modified_action is not None:
            candidate_tool_name = result.modified_action.get(
                "tool_name", effective_action.get("tool_name")
            )
            if candidate_tool_name != effective_action.get("tool_name"):
                return "deny"
            effective_action.update(result.modified_action)
        elif result.modified_parameters is not None:
            effective_action["parameters"] = result.modified_parameters
    filter_result = filter_parameters(
        str(effective_action.get("tool_name") or ""),
        effective_action.get("parameters") or {},
        correlation_id,
    )
    if final == "allow" and filter_result.was_modified:
        return "modify"
    return final


def _deciding_rule(result: PolicyEvaluationResult, simulated: str) -> str:
    if simulated == "deny":
        for decision in result.decisions:
            if decision.decision == "deny" and decision.reason:
                return decision.reason
        return "deny"
    return simulated


def _replay_all(bundle_bytes: bytes, items: list[dict]) -> list[dict]:
    """Replay every item against the bundle. Sync; callers run it in a
    thread so the event loop is not blocked on subprocesses."""
    executable = _opa_binary()
    outcomes: list[dict] = []
    with tempfile.TemporaryDirectory(prefix="acr-sim-bundle-") as directory:
        bundle_path = Path(directory) / "candidate.tar.gz"
        bundle_path.write_bytes(bundle_bytes)
        for item in items:
            raw = _eval_bundle_once(executable, bundle_path, item["input"])
            parsed = parse_opa_result(raw, elapsed_ms=0)
            simulated = simulated_final_decision(
                parsed, item["input"], correlation_id=item["correlation_id"]
            )
            outcomes.append(
                {
                    "correlation_id": item["correlation_id"],
                    "simulated_decision": simulated,
                    "rule": _deciding_rule(parsed, simulated),
                    "reason": parsed.reason,
                }
            )
    return outcomes


# ── Recorded-decision reconstruction ──────────────────────────────────────────


def recorded_final_decision(rows: list[PolicyDecisionRecord]) -> str:
    """The final decision the gateway issued for one evaluation.

    Decision rows are per-rule; all policy rows of one evaluation carry
    the evaluation's final decision, with one exception: when the output
    filter redacted an allowed action, the gateway appends an
    'acr-output-modify' row and the issued decision is 'modify'.
    """
    for row in rows:
        if row.policy_id == "acr-output-modify":
            return "modify"
    return rows[0].decision


# ── Running a simulation ──────────────────────────────────────────────────────


async def run_simulation(
    db: AsyncSession,
    *,
    actor: str,
    window_start: datetime,
    window_end: datetime,
    bundle_bytes: bytes,
    bundle_label: str | None,
) -> PolicySimulationRecord:
    """Replay retained inputs in [window_start, window_end] against a bundle
    and durably record the run. Reads decisions/inputs; writes only the
    simulation record. The caller owns the transaction."""
    bundle_sha256 = hashlib.sha256(bundle_bytes).hexdigest()

    rows_result = await db.execute(
        select(PolicyDecisionRecord)
        .where(
            PolicyDecisionRecord.created_at >= window_start,
            PolicyDecisionRecord.created_at <= window_end,
        )
        .order_by(PolicyDecisionRecord.created_at, PolicyDecisionRecord.sequence)
    )
    by_correlation: dict[str, list[PolicyDecisionRecord]] = {}
    for row in rows_result.scalars().all():
        by_correlation.setdefault(row.correlation_id, []).append(row)
    decisions_in_window = len(by_correlation)

    inputs_by_correlation: dict[str, EvaluationInputRecord] = {}
    if by_correlation:
        inputs_result = await db.execute(
            select(EvaluationInputRecord).where(
                EvaluationInputRecord.correlation_id.in_(list(by_correlation))
            )
        )
        for record in inputs_result.scalars().all():
            if record.state == "retained" and record.payload is not None:
                inputs_by_correlation[record.correlation_id] = record
    inputs_available = len(inputs_by_correlation)
    inputs_missing = decisions_in_window - inputs_available

    items = [
        {
            "correlation_id": correlation_id,
            "input": inputs_by_correlation[correlation_id].payload,
            "recorded_decision": recorded_final_decision(rows),
            "agent_id": rows[0].agent_id,
            "tool_name": rows[0].tool_name,
        }
        for correlation_id, rows in by_correlation.items()
        if correlation_id in inputs_by_correlation
    ]
    outcomes = await asyncio.to_thread(_replay_all, bundle_bytes, items)
    outcome_by_correlation = {o["correlation_id"]: o for o in outcomes}

    flip_counts: Counter[str] = Counter()
    flips_by_rule: Counter[str] = Counter()
    samples: list[SimulationFlipSample] = []
    unchanged = 0
    for item in items:
        outcome = outcome_by_correlation[item["correlation_id"]]
        simulated = outcome["simulated_decision"]
        recorded = item["recorded_decision"]
        if simulated == recorded:
            unchanged += 1
            continue
        flip_counts[f"{recorded}->{simulated}"] += 1
        flips_by_rule[outcome["rule"]] += 1
        if len(samples) < _SAMPLE_LIMIT:
            samples.append(
                SimulationFlipSample(
                    correlation_id=item["correlation_id"],
                    agent_id=item["agent_id"],
                    tool_name=item["tool_name"],
                    recorded_decision=recorded,
                    simulated_decision=simulated,
                    rule=outcome["rule"],
                    reason=outcome["reason"],
                    input=item["input"],
                )
            )

    created_at = utcnow()
    run_id = f"sim-{uuid.uuid4()}"
    result_hash = hashlib.sha256(
        json.dumps(
            {
                "bundle_sha256": bundle_sha256,
                "window_start": window_start.isoformat(),
                "window_end": window_end.isoformat(),
                "decisions_in_window": decisions_in_window,
                "inputs_available": inputs_available,
                "inputs_missing": inputs_missing,
                "unchanged_count": unchanged,
                "flip_counts": dict(flip_counts),
                "flips_by_rule": dict(flips_by_rule),
                "sample_correlation_ids": [s.correlation_id for s in samples],
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()

    report = SimulationReport(
        run_id=run_id,
        actor=actor,
        created_at=created_at,
        bundle_label=bundle_label,
        bundle_sha256=bundle_sha256,
        window_start=window_start,
        window_end=window_end,
        decisions_in_window=decisions_in_window,
        inputs_available=inputs_available,
        inputs_missing=inputs_missing,
        evaluations_replayed=len(items),
        unchanged_count=unchanged,
        flip_counts=dict(sorted(flip_counts.items())),
        flips_by_rule=dict(sorted(flips_by_rule.items())),
        samples=samples,
        result_hash=result_hash,
    )
    record = PolicySimulationRecord(
        run_id=run_id,
        actor=actor,
        bundle_label=bundle_label,
        bundle_sha256=bundle_sha256,
        window_start=window_start,
        window_end=window_end,
        decisions_in_window=decisions_in_window,
        inputs_available=inputs_available,
        inputs_missing=inputs_missing,
        report=report.model_dump(mode="json"),
        result_hash=result_hash,
        created_at=created_at,
    )
    db.add(record)
    await db.flush()
    logger.info(
        "policy_simulation_complete",
        run_id=run_id,
        actor=actor,
        bundle_sha256=bundle_sha256,
        decisions_in_window=decisions_in_window,
        inputs_available=inputs_available,
        inputs_missing=inputs_missing,
        flips=sum(flip_counts.values()),
    )
    return record


async def get_simulation(db: AsyncSession, run_id: str) -> PolicySimulationRecord | None:
    result = await db.execute(
        select(PolicySimulationRecord).where(PolicySimulationRecord.run_id == run_id)
    )
    return result.scalar_one_or_none()


# ── Promotion gate ────────────────────────────────────────────────────────────


def simulation_gate_applies() -> bool:
    """The gate binds only when there is retained traffic to simulate
    against: retention on (deployment opt-in) and the gate itself on."""
    return bool(
        settings.evaluation_input_retention_enabled and settings.policy_simulation_gate_enabled
    )


async def assert_promotion_gate(
    db: AsyncSession, *, simulation_report_id: str | None, bundle_sha256: str
) -> PolicySimulationRecord:
    """Require a recorded simulation of exactly the bundle being promoted."""
    if not simulation_report_id:
        raise PolicyValidationError(
            "Policy simulation gate: activating a managed release while "
            "evaluation-input retention is on requires a simulation report. "
            "Run a simulation for this release and pass its run id."
        )
    record = await get_simulation(db, simulation_report_id)
    if record is None:
        raise PolicyValidationError(
            f"Policy simulation gate: simulation report '{simulation_report_id}' not found"
        )
    if record.bundle_sha256 != bundle_sha256:
        raise PolicyValidationError(
            "Policy simulation gate: simulation report "
            f"'{simulation_report_id}' covers bundle {record.bundle_sha256}, "
            f"not the bundle being activated ({bundle_sha256})"
        )
    return record


# ── Human-readable summary ────────────────────────────────────────────────────


def render_markdown_summary(report: dict) -> str:
    """Render the stored report dict as a Markdown summary. Rendered from
    the same data as the JSON export, never from a second source."""
    lines = [
        f"# Policy simulation {report['run_id']}",
        "",
        f"- Actor: {report['actor']}",
        f"- Run at: {report['created_at']}",
        f"- Bundle: {report.get('bundle_label') or '(unlabeled)'} "
        f"(sha256 {report['bundle_sha256']})",
        f"- Window: {report['window_start']} to {report['window_end']}",
        f"- Result hash: {report['result_hash']}",
        "",
        "## Coverage",
        "",
        f"- Decisions in window: {report['decisions_in_window']}",
        f"- Inputs available for replay: {report['inputs_available']}",
        f"- Inputs missing (never retained or purged): {report['inputs_missing']}",
        f"- Evaluations replayed: {report['evaluations_replayed']}",
        "",
        "## Outcome",
        "",
        f"- Unchanged: {report['unchanged_count']}",
    ]
    flip_counts = report.get("flip_counts") or {}
    if flip_counts:
        lines.append(f"- Flipped: {sum(flip_counts.values())}")
        lines += ["", "### Flips by direction", ""]
        for key in sorted(flip_counts):
            lines.append(f"- {key}: {flip_counts[key]}")
        flips_by_rule = report.get("flips_by_rule") or {}
        if flips_by_rule:
            lines += ["", "### Flips by deciding rule", ""]
            for rule in sorted(flips_by_rule):
                lines.append(f"- {rule}: {flips_by_rule[rule]}")
    else:
        lines.append("- Flipped: 0")
    samples = report.get("samples") or []
    if samples:
        lines += ["", "## Sample flipped cases", ""]
        for sample in samples:
            lines.append(
                f"- `{sample['correlation_id']}` agent `{sample['agent_id']}` "
                f"tool `{sample.get('tool_name')}`: {sample['recorded_decision']} -> "
                f"{sample['simulated_decision']} (rule: {sample['rule']})"
            )
    if report["inputs_missing"]:
        lines += [
            "",
            "> Coverage note: some decisions in this window have no retained "
            "input (retention was off, or the input has been purged). They "
            "are counted above and were NOT replayed; this report does not "
            "speak for them.",
        ]
    lines.append("")
    return "\n".join(lines)
