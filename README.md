# fraud-watchdog
A PLC never allows a hard fault with a soft response.

**fraud-watchdog** is a deterministic temporal interlock for UPI payments. No ML. No GPU. No black box. Every decision is a named rule with a hard verdict.
## Why
UPI lost ₹485 Cr to fraud in H1 FY25. Current detection is probabilistic and post-authorization — by the time a risk score flags a transaction, the money is already gone.
In industrial control (PLC/OT), this was solved 50 years ago: if a signal arrives at the wrong time or in the wrong order, the machine **stops**. No score. No probability. Hard stop.
fraud-watchdog applies that logic to payments.

## The 8 Scenarios

| # | Scenario | Verdict |
|---|----------|---------|
| 1 | Digital Arrest Scam | TRIPPED |
| 2 | Legit Payment to Trusted Contact | PASS |
| 3 | Malware Overlay During Payment | TRIPPED |
| 4 | 3 AM Transaction (Outside Normal Hours) | TRIPPED |
| 5 | OTP Phishing — Fast Sequence After SMS | TRIPPED |
| 6 | Rapid Fire Transfers (Mule Account Pattern) | TRIPPED |
| 7 | Screen-Off Replay Attack | TRIPPED |
| 8 | Elderly User — Slow but Legit | PASS |

Scenarios 2 & 8 are **false-positive guards**: the interlock must not fault on legitimate operation.
## How It Works
Four primitives, all deterministic:
- **Dwell time** — minimum time between sequential actions (you can't select a contact in 1 second)
- **Sequence interlock** — events must arrive in a defined order; wrong order = fault
- **Proximity watchdog** — if a scam-relevant event (alert, SMS, call) occurred within N seconds, block
- **Heartbeat** — screen-off / overlay / missed heartbeat = abort mid-flow

Each rule is a named function. Each verdict is logged with the rule name and the triggering timestamp. No score. No probability.
## Run It
```bash
git clone https://github.com/PV-J/fraud-watchdog
cd fraud-watchdog
python demo.py
```
All 8 scenarios run. Output shows the rule that fired and the verdict.
## Specs
- ~300+ lines of Python (core engine)
-  No dependencies beyond stdlib- Runs on any device with Python 3.9+
-  Decision latency: <50ms per rule
-  License: Apache 2.0
## Roadmap
| Phase | Focus | Status |
|-------|-------|--------|
| 1 | **v0.1** — Core watchdog, 8 scenarios, CLI demo, pytest suite| Done |
| 2 | **v0.2** — Community scenarios (12+), configurable profiles,
      `--repeat` determinism test| In progress |
| 3 | **v0.3** — `temporal_attestation` schema, TEE attestation format,
      protocol proposal for UPI ReqPay message| Planned |
| 4 | **v1.0** — Android/Kotlin heartbeat module, 20+ scenarios,
      production-ready API | Drafting |
## Protocol Extension (v0.3)
A `temporal_attestation` field for the UPI ReqPay message.Schema, TEE signature format, and verification rules will be documented here at v0.3.   
## Why PLC?
A PLC is the most safety-critical software running on Earth. It controls reactors, trains, power grids. Its design philosophy is:
1. **Deterministic** — same input, same output, every time
2. **Auditable** — every decision is logged with a rule name
3. **Fail-safe** — if uncertain, stop. Don't guess.
4. **No hidden state** — if you can't see the state, you can't trust the decision

UPI fraud detection violates all four. fraud-watchdog restores them.

*Solo project. No team. No funding. No VC. Just an engineer who got tiredof reading fraud news.*

##
Auth: PV-J/30/9/26
##
