## Updated `demo_video.py`

"""
fraud-watchdog — CLI demo runner (VIDEO VERSION)
2-line compact output for screen recording.

Usage:
    python demo_video.py                    # Run all scenarios
    python demo_video.py --scenario digital_arrest   # Run one
Author: P_VJ/7/10/26
"""

import argparse
from datetime import datetime, timedelta

from watchdog import TransactionWatchdog, TxnContext, UserProfile
from scenarios import SCENARIOS
import os
if os.name == "nt":
    os.system("")  # enables ANSI color in Windows console 

VIDEO_ORDER = [
    "digital_arrest",
    "otp_phishing",
    "velocity_burst",
    "screen_off_replay",
    "late_night_rush",
    "overlay_attack",
    "legit_payment",
    "elderly_user_slow",
]

# Short reason labels per scenario (for video display)
REASON_LABELS = {
    "digital_arrest":    "[VELOCITY]  Duress {dur}s — no human types this fast",
    "otp_phishing":      "[VELOCITY]  SMS→Payment {dur}s — OTP race, no time to verify",
    "velocity_burst":    "[VELOCITY]  5 rapid txns / {dur}s — mule account pattern",
    "overlay_attack":    "[CONTEXT]  Overlay detected mid-payment — UI spoofing",
    "screen_off_replay": "[SEQUENCE]  Resume after screen-off — no re-auth, replay risk",
    "late_night_rush":   "[CONTEXT]   {dur}s burst at 3 AM — outside active window",
    "legit_payment":     "[PASS]      {dur}s — trusted VPA, normal pace, no fault",
    "elderly_user_slow": "[PASS]      {dur}s — slow but consistent, legitimate user",
}   

def run_scenario(key: str, num: int = 1):
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

    # --- Output (2 lines per scenario) ---
    status = "PASS" if passed else "TRIPPED"
    icon = "✅" if passed else "🚫"

    offsets = [off for _, off in s["events"]]
    seq_dur = max(offsets) - min(offsets)

    color = "\033[92m" if passed else "\033[91m"  # green / red
    reset = "\033[0m"
    dim   = "\033[90m"  # light gray for reason line
    
    # print(f"  {color}{icon} {s['name']}  [{status}]{reset}")
    print(f" {color} {num} {color}  {s['name']}  [{status}]") 
    
    label = REASON_LABELS.get(key, "{dur}s")
    print(f"     {dim}{label.format(dur=f'{seq_dur:.1f}')}{reset}")   

    wd.reset()
    return reason, passed  # only returns one value (bool)


def main():
    parser = argparse.ArgumentParser(description="fraud-watchdog CLI demo (video)")
    parser.add_argument("--scenario", type=str, default=None,
                        help=f"Run one scenario: {', '.join(SCENARIOS.keys())}")
    args = parser.parse_args()

    print("  FRAUD-WATCHDOG v0.1")
    print("  PLC-Style Temporal Gate")
    print("─" * 55)

    if args.scenario:
        if args.scenario not in SCENARIOS:
            print(f"\n  Unknown scenario: {args.scenario}")
            print(f"  Available: {', '.join(SCENARIOS.keys())}")
            return
        run_scenario(args.scenario)
    else:
        run_results = {}
        # for key in VIDEO_ORDER:
            # run_results[key] = run_scenario(key)
        for i, key in enumerate(VIDEO_ORDER, 1):
            run_results[key] = run_scenario(key, i)   
        
        tripped = sum(1 for v in run_results.values() if not v)
        passed = len(run_results) - tripped
        print("─" * 55)
        print(f"  {tripped} TRIPPED / {passed} PASS")
        print("  No ML. No GPU. ~300+ lines. Runs on a ₹6,000 phone.")


if __name__ == "__main__":
    main()