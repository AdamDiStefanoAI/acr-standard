"""Installed CLI contract, without gateway access."""

import subprocess
from importlib.metadata import version


def test_installed_version() -> None:
    result = subprocess.run(["acr", "--version"], capture_output=True, text=True, check=True)
    assert result.stdout.strip() == f"acr {version('acr-control-plane')}"
    assert result.stderr == ""


def test_help() -> None:
    result = subprocess.run(["acr", "--help"], capture_output=True, text=True, check=True)
    assert "--version" in result.stdout
    assert "--help" in result.stdout


def test_unknown_option_is_an_error() -> None:
    result = subprocess.run(["acr", "--unknown"], capture_output=True, text=True, check=False)
    assert result.returncode == 2
