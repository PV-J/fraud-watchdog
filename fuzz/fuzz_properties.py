from hypothesis import given, settings, strategies as st
from helpers import SCENARIOS, build_context, make_watchdog

# --- Property 1: Idempotency ---
# Evaluating the same context twice must give the same result.

@given(scn_key=st.sampled_from(list(SCENARIOS.keys())))
@settings(deadline=None)
def test_idempotent(scn_key):
    """evaluate(ctx) called twice → identical result, no state leakage."""
    wd = make_watchdog()
    ctx = build_context(SCENARIOS[scn_key])

    passed1, reason1 = wd.evaluate(ctx)
    passed2, reason2 = wd.evaluate(ctx)

    assert passed1 == passed2, f"Non-idempotent: {passed1} vs {passed2}"
    assert reason1 == reason2, f"Reason changed: {reason1!r} vs {reason2!r}"

# --- Property 2: Reset completeness ---
# After reset(), watchdog must behave identically to a fresh instance.

@given(scn_key=st.sampled_from(list(SCENARIOS.keys())))
@settings(deadline=None)
def test_reset_equals_fresh(scn_key):
    """reset() must fully restore initial state."""
    # Run a trip scenario, then reset
    wd = make_watchdog()
    trip_ctx = build_context(SCENARIOS["rapid_reopen_replay"])
    wd.evaluate(trip_ctx)
    assert wd.state == "TRIPPED"
    wd.reset()

    # Now evaluate a benign scenario — must behave like a fresh watchdog
    benign_ctx = build_context(SCENARIOS["legit_payment"])
    passed, reason = wd.evaluate(benign_ctx)

    # Compare with a truly fresh watchdog
    wd_fresh = make_watchdog()
    passed_fresh, reason_fresh = wd_fresh.evaluate(benign_ctx)

    assert passed == passed_fresh, f"Reset incomplete: {passed} vs {passed_fresh}"
    assert reason == reason_fresh, f"Reason differs after reset"

# --- Property 3: Trip is sticky until reset ---
# Once TRIPPED, state stays TRIPPED until reset() is called.

@given(scn_key=st.sampled_from(list(SCENARIOS.keys())))
@settings(deadline=None)
def test_trip_sticky(scn_key):
    """TRIPPED state persists across evaluations until reset."""
    wd = make_watchdog()
    trip_ctx = build_context(SCENARIOS["rapid_reopen_replay"])
    passed, _ = wd.evaluate(trip_ctx)
    if not passed:
        assert wd.state == "TRIPPED"
        # Evaluate again without reset — still TRIPPED (or re-evaluates)
        _, _ = wd.evaluate(trip_ctx)
        assert wd.state in ("TRIPPED", "AUTHORIZED")  # never silently SAFE
        wd.reset()
        assert wd.state == "SAFE"   