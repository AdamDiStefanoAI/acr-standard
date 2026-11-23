#!/usr/bin/env python3
"""Standalone verifier for an ACR evidence package (v1.5.0 WS3).

Uses ONLY the Python standard library and no ACR code: an auditor can
run this against an extracted package (or the .zip itself) on a machine
with nothing installed but Python 3.11+.

    python3 verify_package.py [package-dir-or-zip]

Checks, in order:
  1. MANIFEST.json parses and carries the required generation metadata.
  2. The set of files present is exactly the set the manifest lists
     (plus MANIFEST.json itself): nothing missing, nothing smuggled in.
  3. Every listed file's SHA-256 matches its manifest entry.
  4. The manifest's hash chain is intact: each entry links to the
     previous entry's hash, entry hashes recompute, and the recorded
     chain head matches the final entry — so entries cannot be
     reordered, dropped, or edited without detection.
  5. Internal consistency: the counts in summary.json equal the actual
     row counts of the data files, and the observe summary reconciles
     against the decision extract.

Exit code 0 on a clean package; 1 with a specific message otherwise.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import sys
import zipfile
from pathlib import Path

ZERO_HASH = "0" * 64


def fail(message: str) -> int:
    print(f"ERROR: {message}", file=sys.stderr)
    return 1


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_json_bytes(payload) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def load_package(source: Path) -> dict[str, bytes]:
    files: dict[str, bytes] = {}
    if source.is_file() and zipfile.is_zipfile(source):
        with zipfile.ZipFile(source) as archive:
            for name in archive.namelist():
                if not name.endswith("/"):
                    files[name] = archive.read(name)
        return files
    if source.is_dir():
        for path in sorted(source.rglob("*")):
            if path.is_file():
                files[path.relative_to(source).as_posix()] = path.read_bytes()
        return files
    raise ValueError(f"package source '{source}' is neither a directory nor a zip file")


def count_jsonl(data: bytes) -> int:
    return sum(1 for line in data.decode("utf-8").splitlines() if line.strip())


def main(argv: list[str]) -> int:
    source = Path(argv[1]) if len(argv) > 1 else Path(__file__).resolve().parent
    try:
        files = load_package(source)
    except (ValueError, OSError, zipfile.BadZipFile) as exc:
        return fail(str(exc))

    if "MANIFEST.json" not in files:
        return fail("MANIFEST.json is missing from the package")
    try:
        manifest = json.loads(files["MANIFEST.json"])
    except json.JSONDecodeError as exc:
        return fail(f"MANIFEST.json is not valid JSON: {exc}")

    for field in ("package_type", "generated_at", "generated_by", "window_start", "window_end"):
        if not manifest.get(field):
            return fail(f"MANIFEST.json is missing required metadata field '{field}'")
    entries = manifest.get("entries")
    if not isinstance(entries, list) or not entries:
        return fail("MANIFEST.json carries no file entries")

    listed = [entry.get("path") for entry in entries]
    if len(set(listed)) != len(listed):
        return fail("MANIFEST.json lists a file more than once")
    present = set(files) - {"MANIFEST.json"}
    if set(listed) != present:
        missing = sorted(set(listed) - present)
        extra = sorted(present - set(listed))
        if missing:
            return fail(f"file listed in MANIFEST.json is missing from the package: {missing[0]}")
        return fail(f"file present in the package is not listed in MANIFEST.json: {extra[0]}")

    previous = ZERO_HASH
    for entry in entries:
        path = entry["path"]
        actual_hash = sha256_bytes(files[path])
        if actual_hash != entry.get("sha256"):
            return fail(f"sha256 mismatch for '{path}': file content does not match the manifest")
        if entry.get("previous_entry_sha256") != previous:
            return fail(
                f"hash chain broken at '{path}': previous-entry link does not match "
                "(entries may have been reordered, dropped, or edited)"
            )
        entry_core = {
            "path": path,
            "sha256": entry["sha256"],
            "previous_entry_sha256": previous,
        }
        expected_entry_hash = sha256_bytes(canonical_json_bytes(entry_core))
        if entry.get("entry_sha256") != expected_entry_hash:
            return fail(f"hash chain broken at '{path}': entry hash does not recompute")
        previous = expected_entry_hash
    if manifest.get("chain_head_sha256") != previous:
        return fail("hash chain broken: MANIFEST.json chain head does not match the final entry")

    # ── Internal consistency: summary counts vs the data itself ──────────
    try:
        summary = json.loads(files["summary.json"])
        counts = summary["counts"]
        decisions = [
            json.loads(line)
            for line in files["decisions.jsonl"].decode("utf-8").splitlines()
            if line.strip()
        ]
        csv_rows = list(csv.DictReader(io.StringIO(files["decisions.csv"].decode("utf-8"))))
        approvals = json.loads(files["approvals.json"])
        containment = json.loads(files["containment-events.json"])
        agents = json.loads(files["agents.json"])
        releases = json.loads(files["policy-releases.json"])
        inputs = json.loads(files["evaluation-inputs.json"])
        simulations = json.loads(files["simulations.json"])
        drift = json.loads(files["drift.json"])
        observe = json.loads(files["observe-summary.json"])
    except (KeyError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        return fail(f"package data files are unreadable or incomplete: {exc}")

    checks = [
        ("decisions", len(decisions)),
        ("decisions_csv_rows", len(csv_rows)),
        ("approvals", len(approvals)),
        ("containment_events", len(containment)),
        ("agents", len(agents)),
        ("policy_releases", len(releases)),
        ("evaluation_inputs", len(inputs)),
        ("simulations", len(simulations)),
        ("drift_metrics", len(drift.get("metrics", []))),
    ]
    for name, actual in checks:
        expected = counts.get(name)
        if expected != actual:
            return fail(
                f"internal inconsistency: summary.json counts {expected!r} for '{name}' "
                f"but the data files contain {actual}"
            )
    observe_rows = sum(1 for d in decisions if d.get("enforcement_mode") == "observe")
    if observe.get("total_decisions") != observe_rows:
        return fail(
            "internal inconsistency: observe-summary.json total does not match the "
            "observe-mode rows in decisions.jsonl"
        )

    print(
        f"Evidence package verification passed: {len(entries)} files, "
        f"chain head {previous}, {len(decisions)} decisions, "
        f"{len(approvals)} approvals, {len(containment)} containment events."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
