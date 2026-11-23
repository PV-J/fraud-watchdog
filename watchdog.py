"""
fraud-watchdog — PLC-style fail-safe temporal gate for payments.
Default state: BLOCKED. Must pass ALL checks to proceed.
Auth:PV-J 30/9/26
Modified on 1/10/26
v0.4 21/11/26
v0.5 22/11/26

"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import List, Tuple, Optional

import yaml
import os

def load_rules(path=None):
    if path is None:
        path = os.path.join(os.path.dirname(__file__), "rules", "default.yml")
    with open(path) as f:
        return yaml.safe_load(f)

@dataclass
class UserProfile:
    """Learned normal patterns for a user."""
    normal_hours: set = field(default_factory=lambda: set(range(8, 22)))
    max_txn_per_hour: int = 5
    trusted_vpas: set = field(default_factory=set)


@dataclass
class TxnContext:
    """Everything the watchdog needs to evaluate a transaction."""
    now: datetime
    last_txn_time: Optional[datetime]
    last_scam_alert_time: Optional[datetime]
    events: List[Tuple[str, datetime]]  # [(action, timestamp), ...]
    screen_on: bool = True
    touch_active: bool = True
    no_overlay: bool = True
    target_vpa: str = ""
    txn_count_this_hour: int = 1
    linked_txns: list[tuple[str, float, float]] | None = None # Phase 3 network velocity watchdog
    # --- Check 8: Geolocation ---
    geo_distance_km: float = 0.0       # haversine distance from last known location
     # --- Check 9: Device ---
    device_id: str = ""
    known_devices: set = field(default_factory=set)
    txn_amount: float = 0.0
    # --- Check 10: MCC ---
    mcc: str = ""
    expected_mccs: set = field(default_factory=set)
    suspicious_mccs: set = field(default_factory=set)


class TransactionWatchdog:
    """
    PLC-inspired fail-safe gate.
    All checks are AND-gated. Any single failure → TRIP (hard block).
    """

    # --- Configurable thresholds (override via rules.yaml later) ---
    MIN_SECONDS_BETWEEN_TXNS = 30
    MIN_SCAM_PROXIMITY = 300  # 5 minutes
    MIN_DWELL = {
        "open_app": 2,
        "select_contact": 3,
        "enter_amount": 5,
        "verify": 2,
        "confirm": 30,
    }
    EXPECTED_SEQUENCE = ["open_app", "select_contact", "enter_amount", "verify", "confirm"]

    # Phase 3 Network velocity watchdog 

    def __init__(self, user: UserProfile, rules: dict = None):
        if rules is None:
            rules = load_rules()
        self.user = user
        self.state = "SAFE"
        self.fault_reason = None
        self.tripped_checks = []
        self.warnings = []

        w = rules["watchdog"]

        # Validate normal_hours
        nh = w["normal_hours"]
        if not isinstance(nh, (list, tuple)) or len(nh) != 2:
            raise ValueError(f"normal_hours must be [start, end], got: {nh!r}")

        # Validate trip_normal_hours
        tnh = w["trip_normal_hours"]
        if not isinstance(tnh, (list, tuple)) or len(tnh) != 2:
            raise ValueError(f"trip_normal_hours must be [start, end], got: {tnh!r}")
        if not (isinstance(tnh[0], int) and isinstance(tnh[1], int)):
            raise ValueError(f"trip_normal_hours must be integers, got: {tnh!r}")
        if tnh[1] - tnh[0] > 48:
            raise ValueError(f"trip_normal_hours range too wide: {tnh!r}")


        # WARN thresholds (suspicious → payment proceeds with friction)
        self.MIN_SECONDS_BETWEEN_TXNS = w["min_seconds_between_txns"]
        self.MIN_SCAM_PROXIMITY = w["min_scam_proximity_sec"]
        self.MAX_TXN_PER_HOUR = w["max_txn_per_hour"]
        self.NORMAL_HOURS = set(range(nh[0], nh[1]))
        self.NETWORK_MIN_LINKED = w["network_min_linked"]
        self.NETWORK_FORWARD_MAX_SEC = w["network_forward_max_sec"]

        # TRIP thresholds (confirmed threat → hard block)
        self.TRIP_SECONDS_BETWEEN_TXNS = w["trip_seconds_between_txns"]
        self.TRIP_SCAM_PROXIMITY = w["trip_scam_proximity_sec"]
        self.TRIP_MAX_TXN_PER_HOUR = w["trip_max_txn_per_hour"]
        self.TRIP_NORMAL_HOURS = set(range(w["trip_normal_hours"][0], w["trip_normal_hours"][1]))
        self.TRIP_NETWORK_MIN_LINKED = w["trip_network_min_linked"]
        self.TRIP_NETWORK_FORWARD_MAX_SEC = w["trip_network_forward_max_sec"]

        # Dwell + sequence (binary — no soft/hard distinction)
        self.MIN_DWELL = rules["dwell_min"]
        self.EXPECTED_SEQUENCE = rules["expected_sequence"]

         # Check 8: Geolocation
        self.GEO_WARN_KM = w["geo_warn_km"]
        self.GEO_TRIP_KM = w["geo_trip_km"]

        # Check 9: Device
        self.DEVICE_WARN_AMOUNT = w["device_warn_amount"]
        self.DEVICE_TRIP_AMOUNT = w["device_trip_amount"]

        # Check 10: MCC
        self.EXPECTED_MCCS = set(w.get("expected_mccs", []))
        self.SUSPICIOUS_MCCS = set(w.get("suspicious_mccs", []))
 

    # --- WATCHDOG TIMERS ---

    def _check_velocity(self, ctx: TxnContext) -> bool:
        if ctx.last_txn_time is None:
            return True
        delta = (ctx.now - ctx.last_txn_time).total_seconds()
        if delta < self.TRIP_SECONDS_BETWEEN_TXNS:
            self._trip("VELOCITY_WATCHDOG",
                    f"Only {delta:.0f}s since last txn (trip < {self.TRIP_SECONDS_BETWEEN_TXNS}s)")
            return False
        elif delta < self.MIN_SECONDS_BETWEEN_TXNS:
            self._warn("VELOCITY_WATCHDOG",
                    f"Only {delta:.0f}s since last txn (warn < {self.MIN_SECONDS_BETWEEN_TXNS}s)")
        return True


    def _check_time_of_day(self, ctx: TxnContext) -> bool:
        if ctx.now.hour not in self.TRIP_NORMAL_HOURS:
            self._trip("TIME_OF_DAY_WATCHDOG",
                    f"Unusual hour: {ctx.now.hour}:00 (outside trip window)")
            return False
        elif ctx.now.hour not in self.NORMAL_HOURS:
            self._warn("TIME_OF_DAY_WATCHDOG",
                    f"Unusual hour: {ctx.now.hour}:00 (outside normal window)")
        return True


    def _check_scam_proximity(self, ctx: TxnContext) -> bool:
        if ctx.last_scam_alert_time is None:
            return True
        delta = (ctx.now - ctx.last_scam_alert_time).total_seconds()
        if delta < self.TRIP_SCAM_PROXIMITY:
            self._trip("SCAM_PROXIMITY_WATCHDOG",
                    f"Payment within {delta:.0f}s of scam alert (trip < {self.TRIP_SCAM_PROXIMITY}s)")
            return False
        elif delta < self.MIN_SCAM_PROXIMITY:
            self._warn("SCAM_PROXIMITY_WATCHDOG",
                    f"Payment within {delta:.0f}s of scam alert (warn < {self.MIN_SCAM_PROXIMITY}s)")
        return True


    def _check_txn_count(self, ctx: TxnContext) -> bool:
        if ctx.txn_count_this_hour > self.TRIP_MAX_TXN_PER_HOUR:
            self._trip("TXN_COUNT_WATCHDOG",
                    f"{ctx.txn_count_this_hour} txns this hour (trip > {self.TRIP_MAX_TXN_PER_HOUR})")
            return False
        elif ctx.txn_count_this_hour > self.MAX_TXN_PER_HOUR:
            self._warn("TXN_COUNT_WATCHDOG",
                    f"{ctx.txn_count_this_hour} txns this hour (warn > {self.MAX_TXN_PER_HOUR})")
        return True


    # --- SEQUENCE INTERLOCK ---

    def _check_action_sequence(self, ctx: TxnContext) -> bool: 
        if not ctx.events:
            return True  # no events → nothing to sequence-check
        actual_order = [e[0] for e in ctx.events]
        cycle_len = len(self.EXPECTED_SEQUENCE)

        # Check order — chunk into cycles
        for i in range(0, len(actual_order), cycle_len):
            chunk = actual_order[i:i + cycle_len]
            if chunk != self.EXPECTED_SEQUENCE:
                self._trip("SEQUENCE_VIOLATION",
                        f"Wrong order: {chunk}")
                return False

        # Check dwell times between consecutive steps
        
        # print(f"  [DEBUG] events count = {len(ctx.events)}") 
        for i in range(len(ctx.events) - 1):
            action = ctx.events[i][0]
            dwell = (ctx.events[i + 1][1] - ctx.events[i][1]).total_seconds()
            #if action == "confirm":
            #    print(f"  DEBUG: confirm → next, dwell={dwell}s, min={self.MIN_DWELL.get('confirm')}")
            if action in self.MIN_DWELL and dwell < self.MIN_DWELL[action]:
                self._trip("DWELL_TIME_VIOLATION",
                        f"{action} → next in {dwell:.1f}s (min {self.MIN_DWELL[action]}s)")
                return False     
        return True
    

    # --- HEARTBEAT ---

    def _check_heartbeat(self, ctx: TxnContext) -> bool:
        if not (ctx.screen_on and ctx.touch_active and ctx.no_overlay):
            signals = []
            if not ctx.screen_on:
                signals.append("screen_off")
            if not ctx.touch_active:
                signals.append("no_touch")
            if not ctx.no_overlay:
                signals.append("overlay_detected")
            self._trip("HEARTBEAT_LOSS", f"Presence signal lost: {', '.join(signals)}")
            return False
        return True


    
    # New field in TxnContext (or a parallel dataclass):
    # linked_txns: list of (upi_id, receipt_sec, forward_sec)
    # e.g., [("A@upi", 0, 45), ("B@upi", 10, 55), ("C@upi", 20, 70), ...]

    # Rule logic 

    def _check_network_velocity(self, ctx: TxnContext) -> bool:
        if not ctx.linked_txns:
            return True
        fast_forwarders = sum(
            1 for _, receipt, forward in ctx.linked_txns
            if (forward - receipt) <= self.NETWORK_FORWARD_MAX_SEC
        )
        trip_forwarders = sum(
            1 for _, receipt, forward in ctx.linked_txns
            if (forward - receipt) <= self.TRIP_NETWORK_FORWARD_MAX_SEC
        )
        if trip_forwarders >= self.TRIP_NETWORK_MIN_LINKED:
            self._trip("NETWORK_VELOCITY_WATCHDOG",
                    f"{trip_forwarders} linked IDs forwarded within "
                    f"{self.TRIP_NETWORK_FORWARD_MAX_SEC}s (trip min {self.TRIP_NETWORK_MIN_LINKED})")
            return False
        elif fast_forwarders >= self.NETWORK_MIN_LINKED:
            self._warn("NETWORK_VELOCITY_WATCHDOG",
                    f"{fast_forwarders} linked IDs forwarded within "
                    f"{self.NETWORK_FORWARD_MAX_SEC}s (warn min {self.NETWORK_MIN_LINKED})")
        return True

    def _check_geolocation(self, ctx: TxnContext) -> bool:
        if ctx.geo_distance_km == 0.0:
            return True  # no geo data → skip
        if ctx.geo_distance_km > self.GEO_TRIP_KM:
            self._trip("GEO_MISMATCH_WATCHDOG",
                    f"Device {ctx.geo_distance_km:.0f}km from last known location (trip > {self.GEO_TRIP_KM}km)")
            return False
        elif ctx.geo_distance_km > self.GEO_WARN_KM:
            self._warn("GEO_MISMATCH_WATCHDOG",
                    f"Device {ctx.geo_distance_km:.0f}km from last known location (warn > {self.GEO_WARN_KM}km)")
        return True

    def _check_device(self, ctx: TxnContext) -> bool:
        if not ctx.device_id or not ctx.known_devices:
            return True  # no device data → skip
        if ctx.device_id in ctx.known_devices:
            return True  # known device → OK
        # New device
        if ctx.txn_amount > self.DEVICE_TRIP_AMOUNT:
            self._trip("DEVICE_ANOMALY_WATCHDOG",
                    f"New device, amount ₹{ctx.txn_amount:,.0f} (trip > ₹{self.DEVICE_TRIP_AMOUNT:,.0f})")
            return False
        elif ctx.txn_amount > self.DEVICE_WARN_AMOUNT:
            self._warn("DEVICE_ANOMALY_WATCHDOG",
                    f"New device, amount ₹{ctx.txn_amount:,.0f} (warn > ₹{self.DEVICE_WARN_AMOUNT:,.0f})")
        return True

    def _check_mcc(self, ctx: TxnContext) -> bool:
        if not ctx.mcc:
            return True  # no MCC data → skip
        if ctx.mcc in self.SUSPICIOUS_MCCS:
            self._trip("MCC_ANOMALY_WATCHDOG",
                    f"MCC {ctx.mcc} is in suspicious set (trip)")
            return False
        if ctx.mcc not in self.EXPECTED_MCCS:
            self._warn("MCC_ANOMALY_WATCHDOG",
                    f"MCC {ctx.mcc} not in expected set (warn)")
        return True
    
    # --- MAIN GATE (AND logic, like a PLC rung) ---

    def evaluate(self, ctx: TxnContext) -> Tuple[bool, str]:
        self.state = "EVALUATING"
        self.tripped_checks = []
        self.warnings = []
        self.fault_reason = None
        self.check_results = {}

        checks = [
            ("velocity",         self._check_velocity),
            ("time_of_day",      self._check_time_of_day),
            ("scam_proximity",   self._check_scam_proximity),
            ("txn_count",        self._check_txn_count),
            ("sequence",         self._check_action_sequence),
            ("heartbeat",        self._check_heartbeat),
            ("network_velocity", self._check_network_velocity),
            ("geolocation",      self._check_geolocation),       # ← new
            ("device",           self._check_device),            # ← new
            ("mcc",              self._check_mcc),               # ← new
        ]

        for name, fn in checks:
            before_trip = len(self.tripped_checks)
            before_warn = len(self.warnings)
            fn(ctx)
            if len(self.tripped_checks) > before_trip:
                self.check_results[name] = self.tripped_checks[-1]
            elif len(self.warnings) > before_warn:
                self.check_results[name] = self.warnings[-1]
            else:
                self.check_results[name] = "OK"

        if self.tripped_checks:
            self.state = "TRIPPED"
            reasons = "; ".join(self.tripped_checks)
            self.fault_reason = reasons
            return False, f"BLOCKED: {reasons}"
        elif self.warnings:
            self.state = "WARNED"
            reasons = "; ".join(self.warnings)
            return True, f"⚠️ WARNING: {reasons} — Authorized with caution."
        else:
            self.state = "AUTHORIZED"
            return True, "[ALL CHECKS] OK — Transaction authorized."

            
    

    # --- INTERNAL ---

    def _trip(self, code: str, detail: str):
        msg = f"[{code}] {detail}"
        self.tripped_checks.append(msg)
        self.fault_reason = msg if self.fault_reason is None else self.fault_reason + " | " + msg

    def _warn(self, code: str, detail: str):
        msg = f"[{code}] {detail}"
        self.warnings.append(msg)

    def reset(self):
        self.state = "SAFE"
        self.fault_reason = None
        self.tripped_checks = []
        self.warnings = []



# ============================================================
# DEMO: Run scam scenarios
# ============================================================

def run_demo():
    t0 = datetime(2026, 9, 30, 14, 0, 0)  # 2:00 PM
    user = UserProfile()
    wd = TransactionWatchdog(user)

    print("=" * 60)
    print("  FRAUD-WATCHDOG — PLC-Style Temporal Gate")
    print("=" * 60)

    # --- SCENARIO 1: Digital Arrest Scam (SHOULD TRIP) ---
    print("\n📞 SCENARIO 1: Digital Arrest Scam")
    print("-" * 40)
    scam_alert = t0 - timedelta(minutes=2)  # Scam call 2 min ago
    events = [
        ("open_app",       t0),
        ("select_contact", t0 + timedelta(seconds=1)),   # too fast
        ("enter_amount",   t0 + timedelta(seconds=2)),   # too fast
        ("verify",         t0 + timedelta(seconds=3)),   # too fast
        ("confirm",        t0 + timedelta(seconds=4)),   # 4s total cycle
    ]
    ctx = TxnContext(
        now=t0 + timedelta(seconds=4),
        last_txn_time=t0 - timedelta(seconds=10),  # txn 10s ago
        last_scam_alert_time=scam_alert,           # scam alert 2 min ago
        events=events,
        target_vpa="victim@upi",
    )
    passed, reason = wd.evaluate(ctx)
    print(f"  Result: {'✅ PASS' if passed else '🚫 TRIPPED'}")
    print(f"  Reason: {reason}")
    wd.reset()

    # --- SCENARIO 2: Legit Payment (SHOULD PASS) ---
    print("\n💳 SCENARIO 2: Legit Payment to Trusted Contact")
    print("-" * 40)
    events = [
        ("open_app",       t0),
        ("select_contact", t0 + timedelta(seconds=3)),
        ("enter_amount",   t0 + timedelta(seconds=8)),
        ("verify",         t0 + timedelta(seconds=14)),
        ("confirm",        t0 + timedelta(seconds=17)),
    ]
    ctx = TxnContext(
        now=t0 + timedelta(seconds=17),
        last_txn_time=t0 - timedelta(hours=2),  # last txn 2 hours ago
        last_scam_alert_time=None,              # no scam alert
        events=events,
        target_vpa="shop@upi",
    )
    passed, reason = wd.evaluate(ctx)
    print(f"  Result: {'✅ PASS' if passed else '🚫 TRIPPED'}")
    print(f"  Reason: {reason}")
    wd.reset()

    # --- SCENARIO 3: Overlay Attack (SHOULD TRIP) ---
    print("\n🔒 SCENARIO 3: Malware Overlay During Payment")
    print("-" * 40)
    events = [
        ("open_app",       t0),
        ("select_contact", t0 + timedelta(seconds=4)),
        ("enter_amount",   t0 + timedelta(seconds=10)),
        ("verify",         t0 + timedelta(seconds=15)),
        ("confirm",        t0 + timedelta(seconds=18)),
    ]
    ctx = TxnContext(
        now=t0 + timedelta(seconds=18),
        last_txn_time=None,
        last_scam_alert_time=None,
        events=events,
        no_overlay=False,  # ← overlay detected!
    )
    passed, reason = wd.evaluate(ctx)
    print(f"  Result: {'✅ PASS' if passed else '🚫 TRIPPED'}")
    print(f"  Reason: {reason}")
    wd.reset()

    # --- SCENARIO 4: Late Night Rush (SHOULD TRIP) ---
    print("\n🌙 SCENARIO 4: 3 AM Transaction (Outside Normal Hours)")
    print("-" * 40)
    late_night = datetime(2026, 9, 30, 3, 0, 0)
    events = [
        ("open_app",       late_night),
        ("select_contact", late_night + timedelta(seconds=4)),
        ("enter_amount",   late_night + timedelta(seconds=10)),
        ("verify",         late_night + timedelta(seconds=15)),
        ("confirm",        late_night + timedelta(seconds=18)),
    ]
    ctx = TxnContext(
        now=late_night + timedelta(seconds=18),
        last_txn_time=None,
        last_scam_alert_time=None,
        events=events,
    )
    passed, reason = wd.evaluate(ctx)
    print(f"  Result: {'✅ PASS' if passed else '🚫 TRIPPED'}")
    print(f"  Reason: {reason}")
    wd.reset()

    print("\n" + "=" * 60)
    print("  All scenarios evaluated. State machine:")
    print("  SAFE → EVALUATING → TRIPPED / WARNED / AUTHORIZED → SAFE (reset)")
    print("=" * 60)


if __name__ == "__main__":
    run_demo()   