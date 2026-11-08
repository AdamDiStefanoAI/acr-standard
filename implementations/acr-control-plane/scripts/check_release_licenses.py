"""Fail closed if release artifacts omit or alter the project's license.

Run from any directory. Uses only the standard library and, for --image, Docker.
Image checks start only Python, with networking disabled, as the image's user.
"""

from __future__ import annotations

import argparse
import hashlib
import subprocess
import tarfile
import zipfile
from pathlib import Path

IMPLEMENTATION = Path(__file__).resolve().parents[1]

IMAGE_PROBE = """
import hashlib
import importlib.metadata
import pathlib
import sys

expected = sys.argv[1]
def check(data, location):
    if hashlib.sha256(data).hexdigest() != expected:
        raise SystemExit(f"Project LICENSE missing or changed: {location}")

check(pathlib.Path('/app/LICENSE').read_bytes(), '/app/LICENSE')
dist = importlib.metadata.distribution('acr-control-plane')
licenses = [p for p in dist.files or [] if str(p).endswith('.dist-info/licenses/LICENSE')]
if len(licenses) != 1:
    raise SystemExit('Expected exactly one installed project LICENSE')
check(dist.locate_file(licenses[0]).read_bytes(), str(licenses[0]))
print('PASS: image LICENSE and installed wheel LICENSE match source')
"""


def source_license(implementation: Path = IMPLEMENTATION) -> bytes:
    """Keep the complete repository license and the implementation attribution."""
    canonical = (implementation.parents[1] / "LICENSE").read_bytes()
    license_bytes = (implementation / "LICENSE").read_bytes()
    if not canonical or not license_bytes.startswith(canonical):
        raise ValueError("Implementation LICENSE must contain the complete repository LICENSE")
    if b"Copyright 2026 ACR Framework Contributors" not in license_bytes:
        raise ValueError("Implementation LICENSE must retain its existing copyright notice")
    return license_bytes


def check_distributions(directory: Path, expected: bytes) -> None:
    wheels = sorted(directory.glob("*.whl"))
    sdists = sorted(directory.glob("*.tar.gz"))
    if len(wheels) != 1 or len(sdists) != 1:
        raise ValueError("Expected exactly one wheel and one source distribution")
    with zipfile.ZipFile(wheels[0]) as wheel:
        licenses = [p for p in wheel.namelist() if p.endswith(".dist-info/licenses/LICENSE")]
        if len(licenses) != 1 or wheel.read(licenses[0]) != expected:
            raise ValueError("Wheel LICENSE is missing, duplicated, or differs from source")
    with tarfile.open(sdists[0], "r:gz") as sdist:
        licenses = [
            p
            for p in sdist.getmembers()
            if len(Path(p.name).parts) == 2 and Path(p.name).name == "LICENSE"
        ]
        if len(licenses) != 1 or not licenses[0].isfile():
            raise ValueError("Source distribution must contain one regular root LICENSE")
        extracted = sdist.extractfile(licenses[0])
        if extracted is None or extracted.read() != expected:
            raise ValueError("Source distribution LICENSE differs from source")
    print("PASS: wheel and source distribution LICENSE match source")


def check_image(image: str, expected: bytes) -> None:
    subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "--entrypoint",
            "python",
            image,
            "-c",
            IMAGE_PROBE,
            hashlib.sha256(expected).hexdigest(),
        ],
        check=True,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dist-dir", type=Path)
    parser.add_argument("--image", action="append", default=[])
    args = parser.parse_args()
    expected = source_license()
    print(f"PASS: complete source LICENSE sha256={hashlib.sha256(expected).hexdigest()}")
    if args.dist_dir is not None:
        check_distributions(args.dist_dir, expected)
    for image in args.image:
        check_image(image, expected)


if __name__ == "__main__":
    main()
