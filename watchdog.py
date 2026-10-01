"""
fraud-watchdog — PLC-style fail-safe temporal gate for payments.
Default state: BLOCKED. Must pass ALL checks to proceed.
Auth:PV-J 30/9/26
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import List, Tuple, Optional


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
    }
    EXPECTED_SEQUENCE = ["open_app", "select_contact", "enter_amount", "verify", "confirm"]

    def __init__(self, user: UserProfile):
        self.user = user
        self.state = "SAFE"
        self.fault_reason: Optional[str] = None
        self.tripped_checks: List[str] = []

    # --- WATCHDOG TIMERS ---

    def _check_velocity(self, ctx: TxnContext) -> bool:
        if ctx.last_txn_time is None:
            return True
        delta = (ctx.now - ctx.last_txn_time).total_seconds()
        if delta < self.MIN_SECONDS_BETWEEN_TXNS:
            self._trip("VELOCITY_WATCHDOG",
                       f"Only {delta:.0f}s since last txn (min {self.MIN_SECONDS_BETWEEN_TXNS}s)")
            return False
        return True

    def _check_time_of_day(self, ctx: TxnContext) -> bool:
        if ctx.now.hour not in self.user.normal_hours:
            self._trip("TIME_OF_DAY_WATCHDOG",
                       f"Unusual hour: {ctx.now.hour}:00")
            return False
        return True

    def _check_scam_proximity(self, ctx: TxnContext) -> bool:
        if ctx.last_scam_alert_time is None:
            return True
        delta = (ctx.now - ctx.last_scam_alert_time).total_seconds()
        if delta < self.MIN_SCAM_PROXIMITY:
            self._trip("SCAM_PROXIMITY_WATCHDOG",
                       f"Payment within {delta:.0f}s of scam alert — HARD BLOCK")
            return False
        return True

    def _check_txn_count(self, ctx: TxnContext) -> bool:
        if ctx.txn_count_this_hour > self.user.max_txn_per_hour:
            self._trip("TXN_COUNT_WATCHDOG",
                       f"{ctx.txn_count_this_hour} txns this hour (max {self.user.max_txn_per_hour})")
            return False
        return True

    # --- SEQUENCE INTERLOCK ---

    def _check_action_sequence(self, ctx: TxnContext) -> bool:
        actual_order = [e[0] for e in ctx.events]

        # Check order
        if actual_order != self.EXPECTED_SEQUENCE:
            self._trip("SEQUENCE_VIOLATION",
                       f"Wrong order: {actual_order}")
            return False

        # Check dwell times between consecutive steps
        for i in range(len(ctx.events) - 1):
            action = ctx.events[i][0]
            dwell = (ctx.events[i + 1][1] - ctx.events[i][1]).total_seconds()
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

    # --- MAIN GATE (AND logic, like a PLC rung) ---

    def evaluate(self, ctx: TxnContext) -> Tuple[bool, str]:
        """
        All checks must pass. Any failure → BLOCK.
        Returns (passed: bool, reason: str)
        """
        self.state = "EVALUATING"
        self.tripped_checks = []
        self.fault_reason = None

        checks = [
            ("velocity",       self._check_velocity),
            ("time_of_day",    self._check_time_of_day),
            ("scam_proximity", self._check_scam_proximity),
            ("txn_count",      self._check_txn_count),
            ("sequence",       self._check_action_sequence),
            ("heartbeat",      self._check_heartbeat),
        ]

        all_passed = True
        for name, fn in checks:
            if not fn(ctx):
                all_passed = False
                # Continue checking all (report all faults, like a PLC fault summary)

        if all_passed:
            self.state = "AUTHORIZED"
            return True, "All watchdogs passed. Transaction authorized."
        else:
            self.state = "TRIPPED"
            reasons = "; ".join(self.tripped_checks)
            self.fault_reason = reasons
            return False, f"BLOCKED: {reasons}"

    # --- INTERNAL ---

    def _trip(self, code: str, detail: str):
        msg = f"[{code}] {detail}"
        self.tripped_checks.append(msg)
        self.fault_reason = msg if self.fault_reason is None else self.fault_reason + " | " + msg

    def reset(self):
        """Reset to safe state after a trip (like PLC reset after fault clear)."""
        self.state = "SAFE"
        self.fault_reason = None
        self.tripped_checks = []


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
    print("  SAFE → EVALUATING → TRIPPED / AUTHORIZED → SAFE (reset)")
    print("=" * 60)


if __name__ == "__main__":
    run_demo()   