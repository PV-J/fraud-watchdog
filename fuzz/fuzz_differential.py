# fuzz/fuzz_differential.py
import json, subprocess, os, hashlib

SNAPSHOT_FILE = "fuzz/snapshots/v0.4.json"

def capture_snapshot():
    """Run all scenarios, save results as JSON."""
    from scenarios import SCENARIOS
    from helpers import build_context, make_watchdog

    results = {}
    for key, scn in SCENARIOS.items():
        wd = make_watchdog()
        ctx = build_context(scn)
        passed, reason = wd.evaluate(ctx)
        results[key] = {
            "state": wd.state,
            "passed": passed,
            "reason": reason,
            "checks": wd.check_results,
        }
        wd.reset()
    return results

def test_differential():
    """Current output must match v0.4 snapshot (unless intentionally changed)."""
    if not os.path.exists(SNAPSHOT_FILE):
        # First run: create the snapshot
        os.makedirs(os.path.dirname(SNAPSHOT_FILE), exist_ok=True)
        with open(SNAPSHOT_FILE, "w") as f:
            json.dump(capture_snapshot(), f, indent=2)
        return  # skip on first run

    with open(SNAPSHOT_FILE) as f:
        old = json.load(f)
    new = capture_snapshot()

    for key in old:
        assert new[key]["state"] == old[key]["state"], \
            f"{key}: state changed {old[key]['state']} → {new[key]['state']}"
        assert new[key]["passed"] == old[key]["passed"], \
            f"{key}: passed changed"
