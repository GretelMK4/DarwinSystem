"""Shared helpers for the simulations: where the repo is, how to start a server, where results go."""
import sys

from darwin.results import ROOT, RESULTS_DIR, results_path  # noqa: F401  (re-exported)

__all__ = ["ROOT", "RESULTS_DIR", "results_path", "server_cmd"]


def server_cmd(module: str) -> list:
    """Command line that runs a Darwin server module. Start it with cwd=ROOT."""
    return [sys.executable, "-m", module]
