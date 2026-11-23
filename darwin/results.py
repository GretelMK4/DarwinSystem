"""Where simulation results and logs are written: ./results by default (not tracked by git), or $DARWIN_RESULTS."""
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULTS_DIR = os.environ.get("DARWIN_RESULTS", os.path.join(ROOT, "results"))


def results_path(name: str) -> str:
    os.makedirs(RESULTS_DIR, exist_ok=True)
    return os.path.join(RESULTS_DIR, name)
