"""
fraud-watchdog — CLI demo runner.
Usage:
    python demo.py                    # Run all scenarios
    python demo.py --scenario digital_arrest   # Run one
Auth: PVJ/1/10/26
"""

import argparse
from datetime import datetime, timedelta

from watchdog import TransactionWatchdog, TxnContext, UserProfile
from scenarios import SCENARIOS


def run_scenario(key: str):
    s = SCENARIOS[key]
    base_time = datetime(2026, 10, 1, s["hour"], 0, 0)

    user = UserProfile()
    wd = TransactionWatchdog(user)

    events = [(action, base_time + timedelta(seconds=offset))
              for action, offset in s["events"]]

    last_txn = (base_time + timedelta(seconds=s["last_txn_offset_sec"])) \
        if s["last_txn_offset_sec"] is not None else None

    last_scam = (base_time + timedelta(seconds=s["last_scam_alert_offset_sec"])) \
        if s["last_scam_alert_offset_sec"] is not None else None

    ctx = TxnContext(
        now=base_time + timedelta(seconds=s["events"][-1][1]),
        last_txn_time=last_txn,
        last_scam_alert_time=last_scam,
        events=events,
        screen_on=s["screen_on"],
        touch_active=s["touch_active"],
        no_overlay=s["no_overlay"],
        target_vpa="test@upi",
        txn_count_this_hour=s.get("txn_count_this_hour", 1),
    )

    passed, reason = wd.evaluate(ctx)

    # --- Output ---
    icon = "✅" if passed else "🚫"
    status = "PASS" if passed else "TRIPPED"
    print(f"\n{'─' * 55}")
    print(f"  {icon} {s['name']}")
    print(f"  {'─' * 40}")
    print(f"  {s['description']}")
    print(f"  Result:  {status}")
    print(f"  Reason:  {reason}")

    # Verify expected outcome
    expected = s["expected"]
    actual = "PASS" if passed else "TRIPPED"
    if actual != expected:
        print(f"  ⚠️  MISMATCH! Expected {expected}, got {actual}")

    # Verify expected faults
    if not passed:
        for fault in s["expected_faults"]:
            if fault not in reason:
                print(f"  ⚠️  Missing expected fault: {fault}")

    wd.reset()
    return passed


def main():
    parser = argparse.ArgumentParser(description="fraud-watchdog CLI demo")
    parser.add_argument("--scenario", type=str, default=None,
                        help=f"Run one scenario: {', '.join(SCENARIOS.keys())}")
    args = parser.parse_args()

    print("=" * 55)
    print("  FRAUD-WATCHDOG v0.1")
    print("  PLC-Style Temporal Gate for Payments")
    print("=" * 55)

    if args.scenario:
        if args.scenario not in SCENARIOS:
            print(f"\n  Unknown scenario: {args.scenario}")
            print(f"  Available: {', '.join(SCENARIOS.keys())}")
            return
        run_scenario(args.scenario)
    else:
        for key in SCENARIOS:
            run_scenario(key)

    print(f"\n{'=' * 55}")
    print(f"  {len(SCENARIOS)} scenarios evaluated.")
    print(f"  State machine: SAFE → EVALUATING → TRIPPED/AUTHORIZED → SAFE")
    print(f"{'=' * 55}")


if __name__ == "__main__":
    main()   