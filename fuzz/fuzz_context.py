import pytest
from hypothesis import given, settings, strategies as st
from helpers import SCENARIOS, build_context, make_watchdog 

ACTIONS = ["open_app", "select_contact", "enter_amount", "verify", "confirm"]

def event_stream():
    return st.lists(
        st.tuples(
            st.sampled_from(ACTIONS + ["unknown", "open_app"]),
            st.floats(min_value=-50, max_value=300, allow_nan=False),
        ),
        min_size=0, max_size=30,
    )

def scenario_dict():
    return st.fixed_dictionaries({
        "events": event_stream(),
        "hour": st.integers(min_value=0, max_value=23),
        "txn_count_this_hour": st.integers(min_value=0, max_value=50),
        "last_txn_offset_sec": st.one_of(
            st.none(), st.floats(min_value=-3600, max_value=-1, allow_nan=False)),
        "last_scam_alert_offset_sec": st.one_of(
            st.none(), st.floats(min_value=-3600, max_value=0, allow_nan=False)),
        "screen_on": st.booleans(),
        "touch_active": st.booleans(),
        "no_overlay": st.booleans(),
        "target_vpa": st.just(""),
        "linked_txns": st.one_of(
            st.none(),
            st.lists(
                st.tuples(
                    st.from_regex(r"[a-z]{2,10}@[a-z]{2,10}", fullmatch=True),
                    st.floats(min_value=0, max_value=120, allow_nan=False),
                    st.floats(min_value=0, max_value=120, allow_nan=False),
                ), min_size=0, max_size=20),
        ),
    })

@given(scn=scenario_dict())
@settings(max_examples=3000, deadline=None)
def test_no_crash(scn):
    wd = make_watchdog()
    ctx = build_context(scn)
    passed, reason = wd.evaluate(ctx)
    assert isinstance(passed, bool)
    assert isinstance(reason, str)
    assert wd.state in ("AUTHORIZED", "WARNED", "TRIPPED")
    wd.reset()
    assert wd.state == "SAFE"

@settings(max_examples=1000, deadline=None)

def benign_scenario():
    """Directly construct a benign scenario (no filtering needed)."""
    return st.tuples(
        st.integers(min_value=8, max_value=21), # hour: normal
        st.integers(min_value=1, max_value=3), # txn_count_this_hour
        st.floats(min_value=5, max_value=30, allow_nan=False), # dwell open_app → select_contact
        st.floats(min_value=5, max_value=30, allow_nan=False), # dwell select_contact → enter_amount
        st.floats(min_value=5, max_value=30, allow_nan=False), # dwell enter_amount → verify
        st.floats(min_value=30, max_value=120, allow_nan=False), # dwell verify → confirm (≥30)
    ).map(lambda t: {
        "hour": t[0],
        "txn_count_this_hour": t[1],
        "last_txn_offset_sec": None,
        "last_scam_alert_offset_sec": None,
        "screen_on": True,
        "touch_active": True,
        "no_overlay": True,
        "target_vpa": "",
        "linked_txns": None,
        "events": [
            ("open_app", 0),
            ("select_contact", t[2]),
            ("enter_amount", t[2] + t[3]),
            ("verify", t[2] + t[3] + t[4]),
            ("confirm", t[2] + t[3] + t[4] + t[5]),
        ],
    })

@given(scn=benign_scenario())
@settings(deadline=None)
def test_benign_passes(scn):
    wd = make_watchdog()
    ctx = build_context(scn)
    passed, reason = wd.evaluate(ctx)
    assert passed, f"Benign tripped: {reason}"   



# 14 scenarios as regression seeds


@pytest.mark.parametrize("key", list(SCENARIOS.keys()))
def test_known_scenarios(key):
    scn = SCENARIOS[key]
    wd = make_watchdog()
    ctx = build_context(scn)
    passed, reason = wd.evaluate(ctx)
    actual = "PASS" if passed else "TRIPPED"
    assert actual == scn["expected"], f"{key}: Expected {scn['expected']}, got {actual}: {reason}"
    if not passed:
        for fault in scn.get("expected_faults", []):
            assert fault in reason, f"{key}: Missing fault {fault} in: {reason}"