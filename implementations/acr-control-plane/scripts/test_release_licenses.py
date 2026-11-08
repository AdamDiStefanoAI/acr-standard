"""Regression tests for the release gate. Run with standard-library unittest."""

from __future__ import annotations

import hashlib
import io
import subprocess
import tarfile
import tempfile
import unittest
import warnings
import zipfile
from pathlib import Path
from unittest.mock import Mock, patch

from check_release_licenses import IMAGE_PROBE, check_distributions, check_image, source_license


class ReleaseLicenseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.expected = b"Complete license and attribution\n"

    def artifacts(self, wheel_bytes=None, sdist_bytes=None, *, omit=None, duplicate=None):
        with zipfile.ZipFile(self.root / "acr_control_plane-1.3.1-py3-none-any.whl", "w") as wheel:
            if omit != "wheel":
                name = "acr_control_plane-1.3.1.dist-info/licenses/LICENSE"
                wheel.writestr(name, self.expected if wheel_bytes is None else wheel_bytes)
                if duplicate == "wheel":
                    with warnings.catch_warnings():
                        warnings.simplefilter("ignore", UserWarning)
                        wheel.writestr(name, self.expected)
        with tarfile.open(self.root / "acr_control_plane-1.3.1.tar.gz", "w:gz") as sdist:
            if omit != "sdist":
                data = self.expected if sdist_bytes is None else sdist_bytes
                entry = tarfile.TarInfo("acr_control_plane-1.3.1/LICENSE")
                entry.size = len(data)
                sdist.addfile(entry, io.BytesIO(data))
                if duplicate == "sdist":
                    sdist.addfile(entry, io.BytesIO(data))

    def test_valid_distributions(self):
        self.artifacts()
        check_distributions(self.root, self.expected)

    def test_missing_or_altered_licenses_fail(self):
        for kwargs in (
            {"omit": "wheel"},
            {"omit": "sdist"},
            {"wheel_bytes": b""},
            {"sdist_bytes": b"abridged"},
            {"duplicate": "wheel"},
            {"duplicate": "sdist"},
        ):
            with self.subTest(kwargs=kwargs):
                self.artifacts(**kwargs)
                with self.assertRaises(ValueError):
                    check_distributions(self.root, self.expected)

    def test_missing_artifacts_fail(self):
        with self.assertRaises(ValueError):
            check_distributions(self.root, self.expected)

    def test_stale_extra_artifacts_fail(self):
        self.artifacts()
        (self.root / "old.whl").write_bytes(b"old")
        with self.assertRaises(ValueError):
            check_distributions(self.root, self.expected)

    def test_source_preserves_full_license_and_notice(self):
        implementation = self.root / "implementations" / "acr-control-plane"
        implementation.mkdir(parents=True)
        (self.root / "LICENSE").write_bytes(b"Canonical terms\n")
        path = implementation / "LICENSE"
        for content in (b"abridged", b"Canonical terms\n"):
            path.write_bytes(content)
            with self.assertRaises(ValueError):
                source_license(implementation)
        complete = b"Canonical terms\nCopyright 2026 ACR Framework Contributors\n"
        path.write_bytes(complete)
        self.assertEqual(source_license(implementation), complete)

    def test_repository_source_license(self):
        self.assertTrue(source_license())

    def probe(self, *, app_bytes=None, wheel_bytes=None, files=None):
        dist = Mock()
        dist.files = (
            [Path("acr_control_plane-1.3.1.dist-info/licenses/LICENSE")] if files is None else files
        )
        dist.locate_file.return_value.read_bytes.return_value = (
            self.expected if wheel_bytes is None else wheel_bytes
        )
        digest = hashlib.sha256(self.expected).hexdigest()
        with (
            patch("sys.argv", ["-c", digest]),
            patch("importlib.metadata.distribution", return_value=dist),
            patch(
                "pathlib.Path.read_bytes",
                return_value=self.expected if app_bytes is None else app_bytes,
            ),
        ):
            exec(IMAGE_PROBE, {})

    def test_valid_image_probe(self):
        self.probe()

    def test_image_probe_rejects_changed_license(self):
        for kwargs in (
            {"app_bytes": b""},
            {"wheel_bytes": b"abridged"},
            {"files": []},
            {"files": [Path("a.dist-info/licenses/LICENSE"), Path("b.dist-info/licenses/LICENSE")]},
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(SystemExit):
                self.probe(**kwargs)

    def test_image_probe_fails_on_missing_file(self):
        with (
            patch("sys.argv", ["-c", "expected-digest"]),
            patch("pathlib.Path.read_bytes", side_effect=FileNotFoundError),
            self.assertRaises(FileNotFoundError),
        ):
            exec(IMAGE_PROBE, {"__name__": "__main__"})

    def test_image_check_preserves_runtime_user_and_disables_network(self):
        with patch("check_release_licenses.subprocess.run") as run:
            check_image("acr-gateway:test", self.expected)
        command = run.call_args.args[0]
        self.assertEqual(
            command[:8],
            [
                "docker",
                "run",
                "--rm",
                "--network",
                "none",
                "--entrypoint",
                "python",
                "acr-gateway:test",
            ],
        )
        self.assertNotIn("--user", command)
        self.assertTrue(run.call_args.kwargs["check"])

    def test_image_check_propagates_failure(self):
        with (
            patch(
                "check_release_licenses.subprocess.run",
                side_effect=subprocess.CalledProcessError(1, "docker"),
            ),
            self.assertRaises(subprocess.CalledProcessError),
        ):
            check_image("acr-gateway:test", self.expected)


if __name__ == "__main__":
    unittest.main()
