from hypothesis import settings
from hypothesis.stateful import RuleBasedStateMachine, rule, invariant, initialize
# from conftest import build_context, make_watchdog, SCENARIOS
from helpers import SCENARIOS, build_context, make_watchdog 

class WatchdogStateTest(RuleBasedStateMachine):
    @initialize()
    def setup(self):
        self.wd = make_watchdog()

    @rule()
    def eval_benign(self):
        ctx = build_context(SCENARIOS["legit_payment"])
        passed, _ = self.wd.evaluate(ctx)
        assert passed
        assert self.wd.state == "AUTHORIZED"
        self.wd.reset()

    @rule()
    def eval_trip(self):
        ctx = build_context(SCENARIOS["rapid_reopen_replay"])
        passed, reason = self.wd.evaluate(ctx)
        assert not passed
        assert self.wd.state == "TRIPPED"
        assert "DWELL_TIME_VIOLATION" in reason
        self.wd.reset()

    @rule()
    def double_reset(self):
        self.wd.reset()
        self.wd.reset()  # must not raise

    @rule()
    def eval_while_tripped(self):
        """Evaluating without reset — should still work (idempotent)."""
        ctx = build_context(SCENARIOS["rapid_reopen_replay"])
        self.wd.evaluate(ctx)
        # Second eval without reset — must not crash
        passed, _ = self.wd.evaluate(ctx)
        assert isinstance(passed, bool)

    @invariant()
    def valid_state(self):
        assert self.wd.state in ("SAFE", "EVALUATING", "TRIPPED", "AUTHORIZED")

TestState = WatchdogStateTest.TestCase
TestState.settings = settings(max_examples=500)