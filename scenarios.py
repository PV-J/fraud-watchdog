"""
fraud-watchdog — Scam scenario definitions.
Each scenario is a dict that can be fed to demo.py.
Auth: P-VJ/1/10/26
"""

SCENARIOS = {

    "digital_arrest": {
        "name": "Digital Arrest Scam",
        "axis": "VELOCITY",
        "description": "Caller claims CBI/police, demands immediate transfer. User panics and confirms in 4 seconds.",
        "events": [
            ("open_app",       0),
            ("select_contact", 1),
            ("enter_amount",   2),
            ("verify",         3),
            ("confirm",        4),
        ],
        "last_txn_offset_sec": -10,
        "last_scam_alert_offset_sec": -120,
        "screen_on": True,
        "touch_active": True,
        "no_overlay": True,
        "hour": 14,
        "expected": "TRIPPED",
        "expected_faults": ["VELOCITY_WATCHDOG", "SCAM_PROXIMITY_WATCHDOG", "DWELL_TIME_VIOLATION"],
    },

    "legit_payment": {
        "name": "Legit Payment to Trusted Contact",
        "axis": "NONE",
        "description": "Normal payment to a shop. User takes their time. No scam alerts.",
        "events": [
            ("open_app",       0),
            ("select_contact", 3),
            ("enter_amount",   8),
            ("verify",         14),
            ("confirm",        17),
        ],
        "last_txn_offset_sec": -7200,
        "last_scam_alert_offset_sec": None,
        "screen_on": True,
        "touch_active": True,
        "no_overlay": True,
        "hour": 14,
        "expected": "PASS",
        "expected_faults": [],
    },

    "overlay_attack": {
        "name": "Malware Overlay During Payment",
        "axis": "CONTEXT",
        "description": "Malware creates a fake PIN entry overlay. User types PIN into the overlay, not the real app.",
        "events": [
            ("open_app",       0),
            ("select_contact", 4),
            ("enter_amount",   10),
            ("verify",         15),
            ("confirm",        18),
        ],
        "last_txn_offset_sec": None,
        "last_scam_alert_offset_sec": None,
        "screen_on": True,
        "touch_active": True,
        "no_overlay": False,
        "hour": 14,
        "expected": "TRIPPED",
        "expected_faults": ["HEARTBEAT_LOSS"],
    },

    "late_night_rush": {
        "name": "3 AM Transaction (Outside Normal Hours)",
        "axis": "CONTEXT",
        "description": "User (or attacker with phone) attempts transfer at 3 AM. Outside learned normal hours (8 AM – 10 PM).",
        "events": [
            ("open_app",       0),
            ("select_contact", 4),
            ("enter_amount",   10),
            ("verify",         15),
            ("confirm",        18),
        ],
        "last_txn_offset_sec": None,
        "last_scam_alert_offset_sec": None,
        "screen_on": True,
        "touch_active": True,
        "no_overlay": True,
        "hour": 3,
        "expected": "TRIPPED",
        "expected_faults": ["TIME_OF_DAY_WATCHDOG"],
    },

    "otp_phishing": {
        "name": "OTP Phishing — Rapid SMS Response",
        "axis": "VELOCITY",
        "description": "User receives fake 'bank verification' SMS, immediately opens app and enters OTP. 2 min after scam SMS.",
        "events": [
            ("open_app",       0),
            ("select_contact", 1),
            ("enter_amount",   3),
            ("verify",         5),
            ("confirm",        6),
        ],
        "last_txn_offset_sec": None,
        "last_scam_alert_offset_sec": -110,
        "screen_on": True,
        "touch_active": True,
        "no_overlay": True,
        "hour": 11,
        "expected": "TRIPPED",
        "expected_faults": ["SCAM_PROXIMITY_WATCHDOG", "DWELL_TIME_VIOLATION"],
    },

    "velocity_burst": {
        "name": "Rapid Fire Transfers (Mule Account Pattern)",
        "axis": "VELOCITY",
        "description": "7th transaction in the same hour. Classic mule account behaviour.",
        "events": [
            ("open_app",       0),
            ("select_contact", 4),
            ("enter_amount",   9),
            ("verify",         14),
            ("confirm",        17),
        ],
        "last_txn_offset_sec": -45,
        "last_scam_alert_offset_sec": None,
        "screen_on": True,
        "touch_active": True,
        "no_overlay": True,
        "hour": 15,
        "txn_count_this_hour": 7,
        "expected": "TRIPPED",
        "expected_faults": ["TXN_COUNT_WATCHDOG"],
    },

    "screen_off_replay": {
        "name": "Screen-Off Replay Attack",
        "axis": "SEQUENCE",
        "description": "Attacker replays a captured transaction while screen is off (phone in pocket).",
        "events": [
            ("open_app",       0),
            ("select_contact", 2),
            ("enter_amount",   6),
            ("verify",         10),
            ("confirm",        13),
        ],
        "last_txn_offset_sec": None,
        "last_scam_alert_offset_sec": None,
        "screen_on": False,
        "touch_active": False,
        "no_overlay": True,
        "hour": 14,
        "expected": "TRIPPED",
        "expected_faults": ["HEARTBEAT_LOSS"],
    },

    "elderly_user_slow": {
        "name": "Elderly User — Slow but Legit",
        "axis": "NONE",
        "description": "65-year-old takes 45 seconds to select a contact. All dwells are long. Should PASS.",
        "events": [
            ("open_app",       0),
            ("select_contact", 45),
            ("enter_amount",   90),
            ("verify",         120),
            ("confirm",        135),
        ],
        "last_txn_offset_sec": -86400,
        "last_scam_alert_offset_sec": None,
        "screen_on": True,
        "touch_active": True,
        "no_overlay": True,
        "hour": 10,
        "expected": "PASS",
        "expected_faults": [],
    },
    # --- Nov 2026 ---

    "mdr_threshold_qr_split": {
        "name": "MDR Threshold QR Split",
        "axis": "SEQUENCE",
        "description": "Merchant QR encodes ₹1999 + ₹1999 to stay under ₹2000 MDR threshold. Second scan goes to a different (scammer) UPI ID.",
        "events": [
            ("open_app",       0),
            ("scan_qr",        3),
            ("confirm",        6),
            ("scan_qr",        10),
            ("confirm",        13),
        ],
        "last_txn_offset_sec": None,
        "last_scam_alert_offset_sec": None,
        "screen_on": True,
        "touch_active": True,
        "no_overlay": True,
        "hour": 19,
        "expected": "TRIPPED",
        "expected_faults": ["SEQUENCE_VIOLATION"],
    },

    "diwali_bonus_fake_qr": {
        "name": "Festive ₹8000 Diwali Bonus Fake QR",
        "axis": "SEQUENCE",
        "description": "WhatsApp forward promises ₹8000 Diwali bonus. User scans QR, enters UPI PIN. Money goes to mule.",
        "events": [
            ("open_app",       0),
            ("scan_qr",        2),
            ("enter_amount",   3),
            ("verify",         7),
            ("confirm",        9),
        ],
        "last_txn_offset_sec": None,
        "last_scam_alert_offset_sec": -60,
        "screen_on": True,
        "touch_active": True,
        "no_overlay": True,
        "hour": 20,
        "expected": "TRIPPED",
        "expected_faults": ["SCAM_PROXIMITY_WATCHDOG"],
    },

    "mule_velocity_burst": {
        "name": "Mule Velocity Burst (₹500cr Network Pattern)",
        "axis": "VELOCITY",
        "description": "17 linked UPI IDs each receive ₹15K and forward within 90s. 4 cycles in one hour. Mumbai Police case Nov 2026.",
        "events": [
            ("open_app",       0),
            ("select_contact", 2),
            ("enter_amount",   4),
            ("verify",         7),
            ("confirm",        9),
        ],
        "last_txn_offset_sec": -30,
        "last_scam_alert_offset_sec": None,
        "screen_on": True,
        "touch_active": True,
        "no_overlay": True,
        "hour": 16,
        "txn_count_this_hour": 8,
        "expected": "TRIPPED",
        "expected_faults": ["TXN_COUNT_WATCHDOG"],
    },

    "busy_legit_hour": {
            "name": "Busy Legit Hour (5 txns, boundary test)",
    "description": (
        "User makes 5 legitimate transactions in one hour: "
        "groceries ₹450, fuel ₹2000, pharmacy ₹320, cab ₹380, "
        "movie tickets ₹600. Normal dwells, no scam alerts, "
        "all contacts whitelisted. Should PASS at exactly max_txn=5."
    ),
    "events": [
        # Txn 1: Groceries
        ("open_app",       0),
        ("select_contact",  8),
        ("enter_amount",   14),
        ("verify",         19),
        ("confirm",        23),
        # Txn 2: Fuel (75s gap)
        ("open_app",       97),
        ("select_contact", 105),
        ("enter_amount",   111),
        ("verify",         116),
        ("confirm",        120),
        # Txn 3: Pharmacy (70s gap)
        ("open_app",      189),
        ("select_contact", 197),
        ("enter_amount",  203),
        ("verify",        208),
        ("confirm",       212),
        # Txn 4: Cab (72s gap)
        ("open_app",      283),
        ("select_contact", 291),
        ("enter_amount",  297),
        ("verify",        302),
        ("confirm",       306),
        # Txn 5: Movie tickets (68s gap)
        ("open_app",      373),
        ("select_contact", 381),
        ("enter_amount",  387),
        ("verify",        392),
        ("confirm",       396),
    ],
    "txn_count_this_hour": 5,
    "last_txn_offset_sec": 45,
    #"scam_alert_seconds_ago": None,
    "last_scam_alert_offset_sec" : None,
    "hour": 14,
    "screen_on": True,
    "touch_active": True,
    "no_overlay": True,
    "expected": "PASS",
    "expected_faults": [],
    },

# Phase 3 network velocity watchdog scenario

    "mule_network_velocity": {
        "name": "Mule Network Velocity (17-ID Relay)",
        "description": (
            "17 linked UPI IDs each receive ₹15K and forward within 90s. "
            "14 of 17 forward in <90s. Classic mule relay cluster."
        ),
        "expected": "TRIPPED",
        "expected_faults": ["NETWORK_VELOCITY_WATCHDOG"],
        "events": [
            ("open_app", 0), ("select_contact", 8), ("enter_amount", 14),
            ("verify", 19), ("confirm", 23),
        ],
        "hour": 15,
        "txn_count_this_hour": 2,
        "last_txn_offset_sec": -100,
        "last_scam_alert_offset_sec": None,
        "screen_on": True,
        "touch_active": True,
        "no_overlay": True,
        "linked_txns": [
            ("mule01@upi", 0,   45),
            ("mule02@upi", 10,  55),
            ("mule03@upi", 20,  60),
            ("mule04@upi", 30,  75),
            ("mule05@upi", 40,  80),
            ("mule06@upi", 50,  90),
            ("mule07@upi", 60,  100),
            ("mule08@upi", 70,  110),
            ("mule09@upi", 80,  120),
            ("mule10@upi", 90,  130),
            ("mule11@upi", 100, 140),
            ("mule12@upi", 110, 150),
            ("mule13@upi", 120, 200),  # 80s gap — still <90
            ("mule14@upi", 130, 210),  # 80s gap — still <90
            ("mule15@upi", 140, 350),  # 210s — SLOW, doesn't count
            ("mule16@upi", 150, 400),  # 250s — SLOW
            ("mule17@upi", 160, 500),  # 340s — SLOW
        ],
    },

    "rapid_reopen_replay": {
        "name": "Rapid Re-open (5s after confirm)",
        "description": (
            "Attacker (or buggy automation) re-opens the payment flow "
            "5 seconds after the previous confirm. Well under the 30s "
            "minimum inter-transaction cooldown."
        ),
        "expected": "TRIPPED",
        "expected_faults": ["DWELL_TIME_VIOLATION"],
        "events": [
            ("open_app",       0),
            ("select_contact",  8),
            ("enter_amount",   14),
            ("verify",         19),
            ("confirm",        23),
            # Re-open after only 5s (min is 30s)
            ("open_app",       28),
            ("select_contact", 36),
            ("enter_amount",   42),
            ("verify",         47),
            ("confirm",        51),
        ],
        "hour": 11,
        "txn_count_this_hour": 2,
        "last_txn_offset_sec": -100,
        "last_scam_alert_offset_sec": None,
        "screen_on": True,
        "touch_active": True,
        "no_overlay": True,
    },




}   