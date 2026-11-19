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

# --- Property 4: Monotonicity (severity never downgrades on re-eval) ---

@given(scn_key=st.sampled_from(list(SCENARIOS.keys())))
@settings(deadline=None)
def test_monotonicity_severity(scn_key):
    """Re-evaluating the same context must never downgrade severity."""
    wd = make_watchdog()
    ctx = build_context(SCENARIOS[scn_key])
    passed1, _ = wd.evaluate(ctx)
    state1 = wd.state
    wd.reset()

    passed2, _ = wd.evaluate(ctx)
    state2 = wd.state

    assert state1 == state2, f"Severity changed: {state1} → {state2}"
    assert passed1 == passed2


# --- Property 5: WARN is non-blocking ---

@given(scn_key=st.sampled_from(list(SCENARIOS.keys())))
@settings(deadline=None)
def test_warned_is_non_blocking(scn_key):
    """WARNED state must return passed=True (payment can proceed)."""
    wd = make_watchdog()
    ctx = build_context(SCENARIOS[scn_key])
    passed, reason = wd.evaluate(ctx)

    if wd.state == "WARNED":
        assert passed, "WARNED must be non-blocking (passed=True)"
        assert "WARNING" in reason
    elif wd.state == "TRIPPED":
        assert not passed
    elif wd.state == "AUTHORIZED":
        assert passed
