import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(__file__))

from hypothesis import settings, HealthCheck
from scenarios import SCENARIOS
from watchdog import TransactionWatchdog, TxnContext, UserProfile, load_rules
from datetime import datetime, timedelta

settings.register_profile(
    "fast",
    max_examples=100,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)
settings.register_profile(
    "full",
    max_examples=5000,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)
settings.load_profile(os.environ.get("HYPOTHESIS_PROFILE", "fast"))   

# --- helpers (unchanged) ---
def build_context(scn: dict) -> TxnContext:
    ...

#def make_watchdog() -> TransactionWatchdog:
    #return TransactionWatchdog(user=UserProfile()) from scenarios import SCENARIOS
def make_watchdog() -> TransactionWatchdog:
    return TransactionWatchdog(user=UserProfile())     
from watchdog import TransactionWatchdog, TxnContext, UserProfile, load_rules
from datetime import datetime, timedelta

def build_context(scn: dict) -> TxnContext:
    base = datetime(2026, 11, 16, scn.get("hour", 12), 0, 0)
    events = [(action, base + timedelta(seconds=off)) for action, off in scn["events"]]
    return TxnContext(
        now=base + timedelta(seconds=scn["events"][-1][1]),
        last_txn_time=(base + timedelta(seconds=scn["last_txn_offset_sec"]))
                       if scn.get("last_txn_offset_sec") is not None else None,
        last_scam_alert_time=(base + timedelta(seconds=scn["last_scam_alert_offset_sec"]))
                             if scn.get("last_scam_alert_offset_sec") is not None else None,
        events=events,
        screen_on=scn.get("screen_on", True),
        touch_active=scn.get("touch_active", True),
        no_overlay=scn.get("no_overlay", True),
        target_vpa=scn.get("target_vpa", ""),
        txn_count_this_hour=scn.get("txn_count_this_hour", 1),
        linked_txns=scn.get("linked_txns"),
    )

def make_watchdog() -> TransactionWatchdog:
    return TransactionWatchdog(user=UserProfile())