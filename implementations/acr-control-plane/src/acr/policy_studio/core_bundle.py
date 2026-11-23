"""Release-owned policy resources, reproducible bundles, and loaded-core identity.

The identity detects accidental missing/mixed/stale policy modules. OPA and its
configuration remain trusted: this is not remote attestation against malicious OPA.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import ntpath
import os
import re
import tarfile
from importlib.resources import files
from pathlib import Path

from acr.policy_studio.compiler import file_rego_version, validate_bundle

CORE_FILES = ("common.rego", "content_safety.rego")
CONTRACT_VERSION = 3
_RESERVED = re.compile(r"\b(?:core_identity|__acr_core_files|operator_identity|studio_identity)\b")


def canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def core_sources() -> dict[str, bytes]:
    root = files("acr.policy_studio").joinpath("core")
    return {name: root.joinpath(name).read_bytes() for name in CORE_FILES}


def core_identity() -> dict:
    digests = {name: hashlib.sha256(body).hexdigest() for name, body in core_sources().items()}
    identity = {"contract_version": CONTRACT_VERSION, "files": digests}
    return {**identity, "core_id": hashlib.sha256(canonical_json(identity)).hexdigest()}


def managed_core_files() -> dict[str, bytes]:
    identity = core_identity()
    result = {}
    for name, body in core_sources().items():
        # Each source owns its own marker; removing/mixing modules cannot leave
        # an independent manifest claiming a complete matching core.
        marker = (
            f"\n__acr_core_files[{json.dumps(name)}] := {json.dumps(identity['files'][name])}\n"
        )
        result[f"bundle/{name}"] = body + marker.encode()
    result["bundle/core_identity.rego"] = (
        "package acr\nimport future.keywords.if\n"
        f'core_identity := {{"core_id": "{identity["core_id"]}", '
        f'"contract_version": {CONTRACT_VERSION}, "files": __acr_core_files}}\n'
    ).encode()
    return result


def _windows_canonical_form(text: str) -> str:
    """Canonical string form of a resolved Windows path, for comparison.

    Path.resolve() on Windows does not promise one string form per file: a
    path reached through the Kubernetes projection symlink chain can come
    back with an extended-length prefix (\\\\?\\C:\\... or \\\\?\\UNC\\...)
    while the same file reached directly comes back plain, and the two
    spellings then compare unequal as strings. Strip the extended-length
    prefixes and normalize with ntpath semantics (dot segments collapsed,
    separators unified, case folded) so equivalent spellings of one file
    produce one form. ntpath is used explicitly so this transformation is
    identical on every host and unit-testable from Linux.
    """
    if text.startswith("\\\\?\\UNC\\"):
        text = "\\\\" + text[len("\\\\?\\UNC\\") :]
    elif text.startswith("\\\\?\\"):
        text = text[len("\\\\?\\") :]
    return ntpath.normcase(ntpath.normpath(text))


_MAX_SYMLINK_EXPANSIONS = 40


def _expand_symlink_chain(path: Path) -> Path:
    """Expand every symlink component of a path by walking it manually.

    Path.resolve() cannot be trusted to do this on every platform: on
    Windows it expanded the visible file symlink of the Kubernetes
    projection layout (mount\\custom.rego -> mount\\..data\\custom.rego)
    but left the intermediate ..data directory symlink unexpanded, so one
    file produced two different resolved strings (..data vs ..2026) and
    the backing-file identity check failed. Walk the path prefix by
    prefix instead: whenever a prefix is a symlink, splice in its target
    (a relative target resolves against the link's parent directory) and
    rescan from the start of the spliced portion, so a chain of links
    (visible file -> ..data -> timestamped backing directory -> file)
    expands fully on every platform. The expansion cap bounds symlink
    loops; a component whose target cannot be read is left as-is.
    """
    parts = list(path.parts)
    expansions = 0
    index = 0
    while index < len(parts):
        candidate = Path(*parts[: index + 1])
        if not os.path.islink(candidate):
            index += 1
            continue
        try:
            target = os.readlink(candidate)
        except OSError:
            index += 1
            continue
        expansions += 1
        if expansions > _MAX_SYMLINK_EXPANSIONS:
            break
        target_path = Path(target)
        if not target_path.is_absolute():
            target_path = Path(*parts[:index]) / target_path
        parts = list(target_path.parts) + parts[index + 1 :]
        index = 0
    return Path(*parts)


def _canonical_path(path: Path) -> str:
    """The fully expanded path as a comparable string, canonicalized per OS.

    Symlink components are expanded by _expand_symlink_chain rather than
    Path.resolve(), whose expansion of intermediate directory symlinks is
    unreliable on Windows (see _expand_symlink_chain); resolve() is applied
    to the expanded path only to absolutize it and collapse any dot
    segments a relative link target introduced, in a chain-free path where
    lexical and physical normalization agree.
    """
    text = str(_expand_symlink_chain(path).resolve())
    if os.name == "nt":
        return _windows_canonical_form(text)
    return text


def _same_file(first: Path, second: Path) -> bool:
    """Whether two paths name the same filesystem object.

    Identity is accepted from either of two independent signals, because on
    Windows each can fail on its own for the Kubernetes projection layout
    (a visible symlink -> ..data -> timestamped backing directory): the
    stat-based check can raise or disagree across the symlink chain, and
    resolved path strings can differ in form for one file. The signals are
    stat identity (device + inode/file index) and equality of the canonical
    paths, where canonicalization expands every symlink component manually
    (see _expand_symlink_chain) before the per-OS form normalization (see
    _windows_canonical_form). Two genuinely different files satisfy
    neither: their stat identities differ and their expanded locations
    differ.
    """
    try:
        if os.path.samefile(first, second):
            return True
    except OSError:
        pass
    return _canonical_path(first) == _canonical_path(second)


def validate_extension(source: str, *, name: str) -> None:
    if _RESERVED.search(source):
        raise ValueError(f"Extension {name} uses reserved core identity names")
    # The aggregate owns acr only. Reject unsupported packages instead of
    # silently loading policies outside the bundle's declared root.
    packages = re.findall(r"(?m)^\s*package\s+([^\s#]+)", source)
    if len(packages) != 1 or not (packages[0] == "acr" or packages[0].startswith("acr.")):
        raise ValueError(f"Extension {name} must declare package acr or an acr subpackage")


def extension_files(directory: str | Path | None) -> dict[str, bytes]:
    if directory is None:
        return {}
    # Lexically normalize the root as given (unified separators, no dot
    # segments) so the relative-path classification below is computed from the
    # same canonical form on every platform; entry paths come from rglob over
    # this root, so they inherit the normalization.
    root = Path(os.path.normpath(directory))
    if not root.is_dir():
        raise ValueError(f"Extension directory does not exist: {root}")
    sources = core_sources()
    result = {}
    # Rego-only is an explicit migration boundary. Silently dropping OPA data
    # documents can turn an operator deny into allow while identities still match.
    # Inspect every file, including Kubernetes projection backing files, before
    # selecting the visible Rego entries for the aggregate.
    projected = (root / "..data").is_symlink()
    backing = (root / "..data").resolve() if projected else None
    if backing is not None and (
        backing.parent != root.resolve()
        or not backing.is_dir()
        or not backing.name.startswith("..")
    ):
        raise ValueError(
            "Unsupported Kubernetes projection target; expected a backing directory within the policy root"
        )
    for path in sorted(root.rglob("*")):
        if not path.resolve().is_relative_to(root.resolve()):
            raise ValueError(f"Policy symlink escapes extension directory: {path}")
        relative = path.relative_to(root)
        is_backing = backing is not None and relative.parts[0] == backing.name
        if projected and any(part.startswith("..") for part in relative.parts):
            recognized_backing = is_backing and not any(
                part.startswith("..") for part in relative.parts[1:]
            )
            if path != root / "..data" and not recognized_backing:
                raise ValueError(f"Unrecognized hidden operator policy entry: {path}")
        if path.is_dir():
            if path.is_symlink() and not (projected and path == root / "..data"):
                raise ValueError(f"Policy directory symlink is not supported: {path}")
            continue
        if not path.is_file():
            raise ValueError(f"Unsupported operator policy entry: {path}")
        if path.name == ".gitkeep":
            continue
        if path.suffix != ".rego":
            raise ValueError(
                f"Unsupported operator policy data or file: {path}; only .rego files "
                "and .gitkeep are supported. Convert data-dependent policies explicitly "
                "before migration; do not discard their data documents."
            )
        if path.name.endswith("_test.rego"):
            raise ValueError(
                f"Unsupported test-suffix operator policy: {path}; filenames do not prove "
                "a module is test-only. Review and rename runtime modules explicitly, "
                "or use migration to omit byte-identical reviewed stock tests."
            )
        if is_backing:
            visible = root.joinpath(*relative.parts[1:])
            # Identity is the whole check: _same_file accepts only the same
            # filesystem object (by stat) or the same canonical resolved
            # location, so a missing or different visible entry still refuses.
            # Gating on visible.is_file() first would short-circuit the
            # identity proof on platforms where stat follows the projection
            # symlink chain differently than resolve() does.
            if not _same_file(visible, path):
                raise ValueError(
                    f"Unmapped Kubernetes policy backing file: {path} "
                    f"(visible counterpart {visible} canonicalizes to "
                    f"{_canonical_path(visible)!r}, backing file to "
                    f"{_canonical_path(path)!r})"
                )
            continue  # Only the verified backing copy of a visible file is deduplicated.
        payload = path.read_bytes()
        if path.name in CORE_FILES:
            if payload != sources[path.name]:
                raise ValueError(
                    f"Modified legacy core file {path}; extract local changes into an extension "
                    "and remove the old core copy before upgrading"
                )
            continue
        validate_extension(payload.decode(), name=str(path))
        result[f"bundle/extensions/{path.relative_to(root).as_posix()}"] = payload
    return result


def deterministic_archive(payloads: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    # gzip's timestamp and original filename must not depend on wall clock/path.
    with (
        gzip.GzipFile(fileobj=buffer, mode="wb", mtime=0, filename="") as compressed,
        tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as archive,
    ):
        for name, payload in sorted(payloads.items()):
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            info.mode = 0o644
            archive.addfile(info, io.BytesIO(payload))
    return buffer.getvalue()


def operator_identity(directory: str | Path | None = None) -> str:
    return extension_identity(extension_files(directory))


def extension_identity(payloads: dict[str, bytes]) -> str:
    digests = {
        name: hashlib.sha256(body).hexdigest()
        for name, body in payloads.items()
        if name.startswith("bundle/extensions/")
    }
    return hashlib.sha256(canonical_json(digests)).hexdigest()


def assemble_bundle(
    payloads: dict[str, bytes], *, studio_identity: str | None = None
) -> tuple[bytes, dict]:
    identity = core_identity()
    operator = extension_identity(payloads)
    # Empty Studio set is also explicit, so legacy bundles cannot authorize resume.
    studio = studio_identity or hashlib.sha256(canonical_json([])).hexdigest()
    payloads = {
        **payloads,
        "bundle/studio_identity.rego": f'package acr\nstudio_identity := "{studio}"\n'.encode(),
        "bundle/operator_identity.rego": f'package acr\noperator_identity := "{operator}"\n'.encode(),
    }
    hashes = {name: hashlib.sha256(body).hexdigest() for name, body in sorted(payloads.items())}
    revision = hashlib.sha256(canonical_json(hashes)).hexdigest()
    versions = {
        name: file_rego_version(body) for name, body in payloads.items() if name.endswith(".rego")
    }
    manifest = {
        "revision": revision,
        "roots": ["acr", "acr_studio"],
        "rego_version": 0,
        "file_rego_versions": versions,
    }
    archive = deterministic_archive({**payloads, ".manifest": canonical_json(manifest)})
    validate_bundle(archive)
    return archive, {
        "core": identity,
        "operator_identity": operator,
        "revision": revision,
        "files": hashes,
        "sha256": hashlib.sha256(archive).hexdigest(),
    }


def opa_config(gateway_url: str, *, authenticated: bool = True) -> dict:
    service = {"url": gateway_url.rstrip("/")}
    if authenticated:
        service["headers"] = {"X-Operator-API-Key": "${ACR_BUNDLE_API_KEY}"}
    return {
        "services": {"acr_control_plane": service},
        "bundles": {
            "acr_active_runtime": {
                "service": "acr_control_plane",
                "resource": f"/acr/policy-bundles/{core_identity()['core_id']}/active.tar.gz",
                "polling": {"min_delay_seconds": 2, "max_delay_seconds": 5},
            }
        },
    }


def export_bundle(
    output: Path,
    extensions: Path | None = None,
    *,
    gateway_url: str = "http://localhost:8000",
    authenticated: bool = True,
    replace: bool = False,
) -> dict:
    payloads = {**managed_core_files(), **extension_files(extensions)}
    archive, manifest = assemble_bundle(payloads)
    output.mkdir(parents=True, exist_ok=True)
    artifacts = {
        "bundle.tar.gz": archive,
        "manifest.json": canonical_json(manifest) + b"\n",
        "opa-config.yaml": canonical_json(opa_config(gateway_url, authenticated=authenticated))
        + b"\n",
    }
    # Never silently replace a prior release or operator artifact.
    for name, payload in artifacts.items():
        target = output / name
        if not replace and target.exists() and target.read_bytes() != payload:
            raise ValueError(
                f"Refusing to overwrite different artifact: {target}; use a fresh directory"
            )
    for name, payload in artifacts.items():
        target = output / name
        if replace or not target.exists():
            temporary = output / f".{name}.{os.getpid()}.tmp"
            try:
                temporary.write_bytes(payload)
                os.replace(temporary, target)
            finally:
                temporary.unlink(missing_ok=True)
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    export = commands.add_parser("export")
    export.add_argument("--output", type=Path, required=True)
    export.add_argument("--extensions", type=Path)
    export.add_argument("--gateway-url", default="http://localhost:8000")
    export.add_argument("--no-auth", action="store_true")
    export.add_argument(
        "--replace", action="store_true", help="Replace only generated output files"
    )
    commands.add_parser("identity")
    args = parser.parse_args()
    try:
        result = (
            export_bundle(
                args.output,
                args.extensions,
                gateway_url=args.gateway_url,
                authenticated=not args.no_auth,
                replace=args.replace,
            )
            if args.command == "export"
            else core_identity()
        )
    except ValueError as exc:
        parser.error(str(exc))
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
