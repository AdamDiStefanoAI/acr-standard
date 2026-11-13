"""Small installed-package diagnostic CLI; does not contact external services."""

import argparse
from importlib.metadata import version


def main() -> None:
    """Report the installed distribution version using standard CLI conventions."""
    parser = argparse.ArgumentParser(prog="acr", description="ACR control-plane utilities")
    parser.add_argument(
        "--version", action="version", version=f"acr {version('acr-control-plane')}"
    )
    parser.parse_args()
