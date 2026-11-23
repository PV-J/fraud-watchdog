"""
fraud-watchdog — fuzz validation/helper
Default state: BLOCKED. Must pass ALL checks to proceed.
Auth: PV-J 
v0.4 21/11/26
v0.5 22/11/26
"""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from scenarios import SCENARIOS
from watchdog import TransactionWatchdog, TxnContext, UserProfile, load_rules
from datetime import datetime, timedelta

def build_context(scn: dict) -> TxnContext:
    base = datetime(2026, 11, 16, scn.get("hour", 12), 0, 0)
    events = [(action, base + timedelta(seconds=off)) for action, off in scn["events"]]
    now = base + timedelta(seconds=scn["events"][-1][1]) if scn["events"] else base
    return TxnContext(
        now=now,
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
        geo_distance_km=scn.get("geo_distance_km", 0.0),
        device_id=scn.get("device_id", ""),
        known_devices=scn.get("known_devices", set()),
        txn_amount=scn.get("txn_amount", 0.0),
        mcc=scn.get("mcc", ""),
        expected_mccs=scn.get("expected_mccs", set()),
        suspicious_mccs=scn.get("suspicious_mccs", set()),
    )   

def make_watchdog() -> TransactionWatchdog:
    return TransactionWatchdog(user=UserProfile())