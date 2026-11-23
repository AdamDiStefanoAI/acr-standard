"""Pillar 4: Runtime evidence package generator (v1.5.0 WS3).

Generates, from LIVE records for a window, the runtime half of the
evidence set described in docs/compliance/evidence-package.md: agent
inventory, policy releases, decision records, approvals, containment
events, drift, observe and simulation summaries, telemetry integrity
results, and the framework control mapping — bound by a hash-chained
manifest and shipped with a standalone verifier
(verify_evidence_package.py, standard library only) so an auditor can
check the package without trusting, or even installing, ACR.

Payload decision (deliberate, documented in the package README):
retained evaluation inputs are NEVER included as payloads. The package
carries their metadata and payload hashes only, so a package can be
handed to an external reviewer without re-exporting the very payloads
retention redaction exists to protect. Approval parameters are likewise
represented by hash, not value. Decision records, manifests, and policy
release metadata are control-plane records, not customer payloads, and
are included in full.

Release/deployment evidence the generator cannot produce (signed
images, build provenance, CI scan output, deployment configuration) is
listed in the package README as externally supplied, keeping the
generator and docs/compliance/evidence-package.md in agreement.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import zipfile
from dataclasses import dataclass
from datetime import datetime
from importlib import resources
from pathlib import Path
from typing import Any

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from acr.common.time import utcnow
from acr.config import settings
from acr.db.models import (
    AgentRecord,
    ApprovalRequestRecord,
    ContainmentActionRecord,
    DriftBaselineVersionRecord,
    DriftMetricRecord,
    EvaluationInputRecord,
    PolicyDecisionRecord,
    PolicyReleaseRecord,
    PolicySimulationRecord,
    TelemetryEventRecord,
)
from acr.pillar4_observability.integrity import canonical_json_bytes, verify_event_chain

logger = structlog.get_logger(__name__)

_ZERO_HASH = "0" * 64

_PACKAGE_README = """# ACR Runtime Evidence Package

Generated from live control-plane records for the window stated in
MANIFEST.json. Verify it with the bundled standalone script (Python
standard library only, no ACR installation required):

    python3 verify_package.py [package-dir-or-zip]

## Contents

- summary.json — counts and rates for the window; the verifier
  reconciles these against the data files.
- agents.json — agent inventory and manifests as recorded at window end
  (credential material is never included).
- policy-releases.json — policy release metadata active in the window,
  including artifact hashes (policy source is distributed through the
  policy bundle, not this package).
- decisions.jsonl / decisions.csv — the decision records for the
  window, full and index forms.
- approvals.json — approval records. Action parameters are represented
  by SHA-256 hash, not value.
- containment-events.json — containment actions in the window.
- drift.json — drift metric samples and governed baseline versions.
- evaluation-inputs.json — retained-input METADATA only (hashes and
  state). Payloads are never exported: retention redaction exists to
  protect them, and a package must not undo it.
- observe-summary.json — observe-mode (would-be) decision summary.
- simulations.json — policy simulation runs recorded in the window.
- telemetry-integrity.json — per-correlation telemetry chain
  verification results (hashes and verdicts, not event payloads).
- control-mapping.md — the framework control mapping, embedded from
  docs/compliance/control-mapping.md.
- MANIFEST.json — every file's SHA-256, hash-chained, with generation
  metadata. verify_package.py re-checks all of it.

## Not generated here

Release and deployment evidence is supplied by the release process and
the deployment, not generated from runtime records: signed container
images and build provenance, the signed release compliance package, CI
security scan / SBOM / dependency audit output, failure/load/DR
validation reports, production configuration (from the secret manager),
network policy, deployment manifests, and backup/restore logs. Process
evidence (identity governance, change approvals, vulnerability and
incident management, external assessments) is likewise external. See
docs/compliance/evidence-package.md.
"""


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


def _json_bytes(payload: Any) -> bytes:
    return json.dumps(payload, indent=2, sort_keys=True).encode() + b"\n"


def _control_mapping_bytes() -> bytes:
    """The framework control mapping, embedded in every package.

    Source of truth is docs/compliance/control-mapping.md; release
    builds copy it into the package as acr/_compliance/control-mapping.md
    (pyproject force-include), and source checkouts read the doc
    directly. If neither is available the generator fails loudly rather
    than shipping a package that silently lacks the mapping.
    """
    packaged = resources.files("acr").joinpath("_compliance", "control-mapping.md")
    if packaged.is_file():
        return packaged.read_bytes()
    repo_doc = Path(__file__).resolve().parents[3] / "docs" / "compliance" / "control-mapping.md"
    if repo_doc.is_file():
        return repo_doc.read_bytes()
    raise RuntimeError(
        "control-mapping.md is not available (neither packaged resource nor repo doc); "
        "refusing to generate an evidence package without the framework mapping"
    )


def _verifier_bytes() -> bytes:
    return Path(__file__).with_name("verify_evidence_package.py").read_bytes()


def _agent_dict(record: AgentRecord) -> dict[str, Any]:
    return {
        "agent_id": record.agent_id,
        "owner": record.owner,
        "purpose": record.purpose,
        "risk_tier": record.risk_tier,
        "allowed_tools": record.allowed_tools,
        "forbidden_tools": record.forbidden_tools,
        "data_access": record.data_access,
        "boundaries": record.boundaries,
        "is_active": record.is_active,
        "version": record.version,
        "parent_agent_id": record.parent_agent_id,
        "capabilities": record.capabilities,
        "lifecycle_state": record.lifecycle_state,
        "health_status": record.health_status,
        "enforcement_mode": record.enforcement_mode,
        "last_heartbeat_at": _iso(record.last_heartbeat_at),
        "created_at": _iso(record.created_at),
        "updated_at": _iso(record.updated_at),
    }


def _decision_dict(record: PolicyDecisionRecord) -> dict[str, Any]:
    return {
        "id": str(record.id),
        "correlation_id": record.correlation_id,
        "agent_id": record.agent_id,
        "policy_id": record.policy_id,
        "decision": record.decision,
        "enforcement_mode": record.enforcement_mode,
        "reason": record.reason,
        "tool_name": record.tool_name,
        "latency_ms": record.latency_ms,
        "sequence": record.sequence,
        "created_at": _iso(record.created_at),
    }


def _approval_dict(record: ApprovalRequestRecord) -> dict[str, Any]:
    snapshot = record.authorization_snapshot or {}
    return {
        "request_id": record.request_id,
        "correlation_id": record.correlation_id,
        "agent_id": record.agent_id,
        "tool_name": record.tool_name,
        "parameters_sha256": _sha256_bytes(canonical_json_bytes(record.parameters or {})),
        "description": record.description,
        "risk_tier": record.risk_tier,
        "approval_queue": record.approval_queue,
        "status": record.status,
        "decision": record.decision,
        "decided_by": record.decided_by,
        "decision_reason": record.decision_reason,
        "sla_minutes": record.sla_minutes,
        "expires_at": _iso(record.expires_at),
        "decided_at": _iso(record.decided_at),
        "created_at": _iso(record.created_at),
        "request_payload_hash": record.request_payload_hash,
        "authorization_policy_identity": snapshot.get("policy_identity"),
        "authorization_manifest_hash": snapshot.get("manifest_hash"),
    }


async def collect_package_files(
    db: AsyncSession,
    *,
    window_start: datetime,
    window_end: datetime,
) -> dict[str, bytes]:
    """Build every package data file (everything except MANIFEST.json)."""
    in_window = lambda column: (column >= window_start, column <= window_end)  # noqa: E731

    agents = list(
        (
            await db.execute(
                select(AgentRecord)
                .where(AgentRecord.created_at <= window_end)
                .order_by(AgentRecord.agent_id)
            )
        )
        .scalars()
        .all()
    )
    decisions = list(
        (
            await db.execute(
                select(PolicyDecisionRecord)
                .where(*in_window(PolicyDecisionRecord.created_at))
                .order_by(
                    PolicyDecisionRecord.agent_id,
                    PolicyDecisionRecord.sequence,
                    PolicyDecisionRecord.created_at,
                )
            )
        )
        .scalars()
        .all()
    )
    approvals = list(
        (
            await db.execute(
                select(ApprovalRequestRecord)
                .where(*in_window(ApprovalRequestRecord.created_at))
                .order_by(ApprovalRequestRecord.created_at)
            )
        )
        .scalars()
        .all()
    )
    containment = list(
        (
            await db.execute(
                select(ContainmentActionRecord)
                .where(*in_window(ContainmentActionRecord.created_at))
                .order_by(ContainmentActionRecord.created_at)
            )
        )
        .scalars()
        .all()
    )
    releases = [
        record
        for record in (
            await db.execute(
                select(PolicyReleaseRecord)
                .where(PolicyReleaseRecord.created_at <= window_end)
                .order_by(PolicyReleaseRecord.agent_id, PolicyReleaseRecord.version)
            )
        )
        .scalars()
        .all()
        if record.activation_status == "active"
        or window_start <= record.created_at <= window_end
        or (record.activated_at is not None and window_start <= record.activated_at <= window_end)
    ]
    inputs = list(
        (
            await db.execute(
                select(EvaluationInputRecord)
                .where(*in_window(EvaluationInputRecord.retained_at))
                .order_by(EvaluationInputRecord.retained_at)
            )
        )
        .scalars()
        .all()
    )
    simulations = list(
        (
            await db.execute(
                select(PolicySimulationRecord)
                .where(*in_window(PolicySimulationRecord.created_at))
                .order_by(PolicySimulationRecord.created_at)
            )
        )
        .scalars()
        .all()
    )
    drift_metrics = list(
        (
            await db.execute(
                select(DriftMetricRecord)
                .where(*in_window(DriftMetricRecord.created_at))
                .order_by(DriftMetricRecord.created_at)
            )
        )
        .scalars()
        .all()
    )
    baseline_versions = list(
        (
            await db.execute(
                select(DriftBaselineVersionRecord)
                .where(*in_window(DriftBaselineVersionRecord.created_at))
                .order_by(DriftBaselineVersionRecord.created_at)
            )
        )
        .scalars()
        .all()
    )

    # ── Decisions: JSONL + CSV index ──────────────────────────────────────
    decision_dicts = [_decision_dict(record) for record in decisions]
    decisions_jsonl = "".join(
        json.dumps(item, sort_keys=True) + "\n" for item in decision_dicts
    ).encode()
    csv_buffer = io.StringIO()
    csv_writer = csv.DictWriter(
        csv_buffer,
        fieldnames=[
            "id",
            "correlation_id",
            "agent_id",
            "policy_id",
            "decision",
            "enforcement_mode",
            "tool_name",
            "sequence",
            "latency_ms",
            "reason",
            "created_at",
        ],
    )
    csv_writer.writeheader()
    for item in decision_dicts:
        csv_writer.writerow({key: item.get(key) for key in csv_writer.fieldnames})
    decisions_csv = csv_buffer.getvalue().encode()

    # ── Observe summary (all agents, observe rows only) ───────────────────
    observe_rows = [d for d in decision_dicts if d["enforcement_mode"] == "observe"]
    observe_counts: dict[str, int] = {}
    tool_counts: dict[str, dict[str, int]] = {}
    for item in observe_rows:
        observe_counts[item["decision"]] = observe_counts.get(item["decision"], 0) + 1
        if item["decision"] in ("deny", "escalate"):
            entry = tool_counts.setdefault(
                item["tool_name"] or "(unknown)", {"deny_count": 0, "escalate_count": 0}
            )
            entry["deny_count" if item["decision"] == "deny" else "escalate_count"] += 1
    observe_summary = {
        "window_start": _iso(window_start),
        "window_end": _iso(window_end),
        "total_decisions": len(observe_rows),
        "counts_by_decision": observe_counts,
        "top_blocked_tools": [
            {"tool_name": name, **counts}
            for name, counts in sorted(
                tool_counts.items(),
                key=lambda kv: (-(kv[1]["deny_count"] + kv[1]["escalate_count"]), kv[0]),
            )[:10]
        ],
        "samples": observe_rows[-20:],
    }

    # ── Telemetry integrity (verdicts and hashes, never payloads) ─────────
    correlation_ids = sorted({d["correlation_id"] for d in decision_dicts})
    integrity_results = []
    if correlation_ids:
        event_rows = list(
            (
                await db.execute(
                    select(TelemetryEventRecord)
                    .where(TelemetryEventRecord.correlation_id.in_(correlation_ids))
                    .order_by(TelemetryEventRecord.correlation_id, TelemetryEventRecord.created_at)
                )
            )
            .scalars()
            .all()
        )
        by_correlation: dict[str, list[dict]] = {}
        for row in event_rows:
            by_correlation.setdefault(row.correlation_id, []).append(row.payload)
        for correlation_id in correlation_ids:
            events = by_correlation.get(correlation_id, [])
            if events:
                verdict = verify_event_chain(events)
                integrity_results.append({"correlation_id": correlation_id, **verdict})
            else:
                integrity_results.append(
                    {
                        "correlation_id": correlation_id,
                        "chain_valid": False,
                        "verified_events": 0,
                        "signed_events": 0,
                        "root_event_sha256": None,
                        "invalid_reasons": ["no telemetry events persisted"],
                    }
                )

    # ── Summary (the verifier reconciles these counts) ────────────────────
    counts = {
        "agents": len(agents),
        "policy_releases": len(releases),
        "decisions": len(decision_dicts),
        "decisions_csv_rows": len(decision_dicts),
        "approvals": len(approvals),
        "containment_events": len(containment),
        "evaluation_inputs": len(inputs),
        "simulations": len(simulations),
        "drift_metrics": len(drift_metrics),
        "telemetry_correlations": len(integrity_results),
    }
    by_decision: dict[str, int] = {}
    by_mode: dict[str, int] = {}
    for item in decision_dicts:
        by_decision[item["decision"]] = by_decision.get(item["decision"], 0) + 1
        by_mode[item["enforcement_mode"]] = by_mode.get(item["enforcement_mode"], 0) + 1
    total = len(decision_dicts) or 1
    summary = {
        "window_start": _iso(window_start),
        "window_end": _iso(window_end),
        "counts": counts,
        "decisions_by_outcome": by_decision,
        "decisions_by_enforcement_mode": by_mode,
        "decision_rates": {
            outcome: round(count / total, 6) for outcome, count in by_decision.items()
        },
        "approvals_by_status": _count_by(approvals, "status"),
        "approvals_by_decision": _count_by(approvals, "decision"),
        "containment_by_action": _count_by(containment, "action_type"),
        "telemetry_chains_valid": sum(1 for r in integrity_results if r["chain_valid"]),
        "telemetry_chains_invalid": sum(1 for r in integrity_results if not r["chain_valid"]),
    }

    files: dict[str, bytes] = {
        "README.md": _PACKAGE_README.encode(),
        "summary.json": _json_bytes(summary),
        "agents.json": _json_bytes([_agent_dict(record) for record in agents]),
        "policy-releases.json": _json_bytes(
            [
                {
                    "release_id": r.release_id,
                    "draft_id": r.draft_id,
                    "agent_id": r.agent_id,
                    "version": r.version,
                    "name": r.name,
                    "template": r.template,
                    "manifest": r.manifest,
                    "status": r.status,
                    "activation_status": r.activation_status,
                    "artifact_uri": r.artifact_uri,
                    "artifact_sha256": r.artifact_sha256,
                    "active_bundle_uri": r.active_bundle_uri,
                    "publish_backend": r.publish_backend,
                    "published_by": r.published_by,
                    "activated_by": r.activated_by,
                    "activated_at": _iso(r.activated_at),
                    "simulation_report_id": r.simulation_report_id,
                    "rollback_from_release_id": r.rollback_from_release_id,
                    "created_at": _iso(r.created_at),
                }
                for r in releases
            ]
        ),
        "decisions.jsonl": decisions_jsonl,
        "decisions.csv": decisions_csv,
        "approvals.json": _json_bytes([_approval_dict(record) for record in approvals]),
        "containment-events.json": _json_bytes(
            [
                {
                    "id": str(r.id),
                    "agent_id": r.agent_id,
                    "action_type": r.action_type,
                    "tier": r.tier,
                    "reason": r.reason,
                    "drift_score": r.drift_score,
                    "operator_id": r.operator_id,
                    "correlation_id": r.correlation_id,
                    "created_at": _iso(r.created_at),
                }
                for r in containment
            ]
        ),
        "evaluation-inputs.json": _json_bytes(
            [
                {
                    "correlation_id": r.correlation_id,
                    "agent_id": r.agent_id,
                    "payload_sha256": r.payload_sha256,
                    "recorded_decision": r.recorded_decision,
                    "enforcement_mode": r.enforcement_mode,
                    "state": r.state,
                    "retained_at": _iso(r.retained_at),
                    "expires_at": _iso(r.expires_at),
                    "purged_at": _iso(r.purged_at),
                    "payload_included": False,
                }
                for r in inputs
            ]
        ),
        "observe-summary.json": _json_bytes(observe_summary),
        "simulations.json": _json_bytes(
            [
                {
                    "run_id": r.run_id,
                    "actor": r.actor,
                    "bundle_label": r.bundle_label,
                    "bundle_sha256": r.bundle_sha256,
                    "window_start": _iso(r.window_start),
                    "window_end": _iso(r.window_end),
                    "decisions_in_window": r.decisions_in_window,
                    "inputs_available": r.inputs_available,
                    "inputs_missing": r.inputs_missing,
                    "result_hash": r.result_hash,
                    "report": r.report,
                    "created_at": _iso(r.created_at),
                }
                for r in simulations
            ]
        ),
        "drift.json": _json_bytes(
            {
                "metrics": [
                    {
                        "agent_id": r.agent_id,
                        "correlation_id": r.correlation_id,
                        "tool_name": r.tool_name,
                        "action_type": r.action_type,
                        "policy_denied": r.policy_denied,
                        "latency_ms": r.latency_ms,
                        "created_at": _iso(r.created_at),
                    }
                    for r in drift_metrics
                ],
                "baseline_versions": [
                    {
                        "baseline_version_id": r.baseline_version_id,
                        "agent_id": r.agent_id,
                        "status": r.status,
                        "sample_count": r.sample_count,
                        "window_days": r.window_days,
                        "created_by": r.created_by,
                        "approved_by": r.approved_by,
                        "activated_by": r.activated_by,
                        "created_at": _iso(r.created_at),
                    }
                    for r in baseline_versions
                ],
            }
        ),
        "telemetry-integrity.json": _json_bytes(integrity_results),
        "control-mapping.md": _control_mapping_bytes(),
        "verify_package.py": _verifier_bytes(),
    }
    return files


def _count_by(records: list, attribute: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for record in records:
        key = str(getattr(record, attribute))
        counts[key] = counts.get(key, 0) + 1
    return counts


def build_manifest(
    files: dict[str, bytes],
    *,
    actor: str,
    window_start: datetime,
    window_end: datetime,
    generated_at: datetime | None = None,
) -> dict[str, Any]:
    """Hash-chain every file: each entry carries the previous entry's
    hash, so reordering, dropping, or editing an entry breaks the chain
    the bundled verifier recomputes."""
    entries = []
    previous = _ZERO_HASH
    for path in sorted(files):
        entry_core = {
            "path": path,
            "sha256": _sha256_bytes(files[path]),
            "previous_entry_sha256": previous,
        }
        entry_hash = _sha256_bytes(canonical_json_bytes(entry_core))
        entries.append({**entry_core, "entry_sha256": entry_hash})
        previous = entry_hash
    return {
        "package_type": "acr-runtime-evidence-package",
        "acr_version": settings.acr_version,
        "generated_at": _iso(generated_at or utcnow()),
        "generated_by": actor,
        "window_start": _iso(window_start),
        "window_end": _iso(window_end),
        "file_count": len(entries),
        "entries": entries,
        "chain_head_sha256": previous,
    }


def _zip_bytes(files: dict[str, bytes], manifest: dict[str, Any]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, mode="w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(files):
            info = zipfile.ZipInfo(path, date_time=(1980, 1, 1, 0, 0, 0))
            info.external_attr = 0o644 << 16
            archive.writestr(info, files[path])
        info = zipfile.ZipInfo("MANIFEST.json", date_time=(1980, 1, 1, 0, 0, 0))
        info.external_attr = 0o644 << 16
        archive.writestr(info, _json_bytes(manifest))
    return buffer.getvalue()


@dataclass(frozen=True)
class EvidencePackageArtifact:
    filename: str
    content_type: str
    bytes_data: bytes
    sha256: str
    chain_head_sha256: str
    file_count: int


async def generate_evidence_package(
    db: AsyncSession,
    *,
    actor: str,
    window_start: datetime,
    window_end: datetime,
) -> EvidencePackageArtifact:
    files = await collect_package_files(db, window_start=window_start, window_end=window_end)
    manifest = build_manifest(files, actor=actor, window_start=window_start, window_end=window_end)
    bytes_data = _zip_bytes(files, manifest)
    # Package generation is an audited operator action.
    logger.info(
        "evidence_package_generated",
        actor=actor,
        window_start=_iso(window_start),
        window_end=_iso(window_end),
        file_count=manifest["file_count"],
        chain_head_sha256=manifest["chain_head_sha256"],
        package_sha256=_sha256_bytes(bytes_data),
    )
    stamp = window_start.strftime("%Y%m%d")
    return EvidencePackageArtifact(
        filename=f"acr-evidence-package-{stamp}.zip",
        content_type="application/zip",
        bytes_data=bytes_data,
        sha256=_sha256_bytes(bytes_data),
        chain_head_sha256=manifest["chain_head_sha256"],
        file_count=manifest["file_count"],
    )


async def write_evidence_package(
    db: AsyncSession,
    *,
    actor: str,
    window_start: datetime,
    window_end: datetime,
    output: Path,
) -> dict[str, Any]:
    """CLI form: write the package as a .zip file or an extracted directory."""
    files = await collect_package_files(db, window_start=window_start, window_end=window_end)
    manifest = build_manifest(files, actor=actor, window_start=window_start, window_end=window_end)
    logger.info(
        "evidence_package_generated",
        actor=actor,
        window_start=_iso(window_start),
        window_end=_iso(window_end),
        file_count=manifest["file_count"],
        chain_head_sha256=manifest["chain_head_sha256"],
        output=str(output),
    )
    if output.suffix == ".zip":
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(_zip_bytes(files, manifest))
    else:
        output.mkdir(parents=True, exist_ok=True)
        for path, data in files.items():
            target = output / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        (output / "MANIFEST.json").write_bytes(_json_bytes(manifest))
    return {
        "output": str(output),
        "file_count": manifest["file_count"],
        "chain_head_sha256": manifest["chain_head_sha256"],
    }
