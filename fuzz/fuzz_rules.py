import yaml, tempfile, os
from hypothesis import given, settings, strategies as st
from watchdog import load_rules, TransactionWatchdog, UserProfile
# from conftest import build_context, SCENARIOS
from helpers import SCENARIOS, build_context, make_watchdog 

def corrupted_rules():
    return st.tuples(
        st.sampled_from(["watchdog", "dwell_min"]),
        st.sampled_from([
            "min_seconds_between_txns", "min_scam_proximity_sec",
            "max_txn_per_hour", "normal_hours",
            "network_min_linked", "network_forward_max_sec",
            "open_app", "select_contact", "enter_amount", "verify", "confirm",
        ]),
        st.one_of(
            st.integers(min_value=-10**9, max_value=10**9),
            st.floats(allow_nan=True, allow_infinity=True),
            st.text(max_size=100),
            st.none(),
            st.lists(st.integers(), max_size=5),
        ),
    )

@given(corr=corrupted_rules())
@settings(max_examples=2000, deadline=None)
def test_corrupt_rules_no_crash(corr):
    section, key, value = corr
    base = {
        "watchdog": {
            "min_seconds_between_txns": 30, "min_scam_proximity_sec": 300,
            "max_txn_per_hour": 5, "normal_hours": [8, 22],
            "network_min_linked": 5, "network_forward_max_sec": 90,
        },
        "dwell_min": {"open_app": 2, "select_contact": 3,
                       "enter_amount": 5, "verify": 2, "confirm": 30},
        "expected_sequence": ["open_app", "select_contact", "enter_amount", "verify", "confirm"],
    }
    base[section][key] = value

    with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
        yaml.dump(base, f)
        path = f.name
    try:
        rules = load_rules(path)
        wd = TransactionWatchdog(user=UserProfile(), rules=rules)
        # Must still evaluate without unhandled exception
        ctx = build_context(SCENARIOS["rapid_reopen_replay"])
        wd.evaluate(ctx)
    except (ValueError, TypeError, KeyError, AttributeError,ImportError):
        pass  # clean rejection acceptable
    finally:
        os.unlink(path)