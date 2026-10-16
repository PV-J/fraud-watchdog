# fraud-watchdog
UPI moves money irreversibly — a hard result — but detects fraud with a soft response: a probability score, after the transfer. This is architecturally incoherent. A PLC never allows a hard fault with a soft response. fraud-watchdog is a deterministic temporal interlock for payments — No ML, No GPU, No black box, runs on a ₹6,000 phone.Every decision is a named rule with a hard verdict.

## Why
UPI lost ₹485 Cr to fraud in H1 FY25. Current detection is probabilistic and post-authorization — by the time a risk score flags a transaction, the money is already gone.
In industrial control (PLC/OT), this was solved 50 years ago: if a signal arrives at the wrong time or in the wrong order, the machine **stops**. No score. No probability. Hard stop.
fraud-watchdog applies that logic to payments.

## Why PLC?
A PLC is the most safety-critical software running on Earth. It controls reactors, trains, power grids. Its design philosophy is:
1. **Deterministic** — same input, same output, every time
2. **Auditable** — every decision is logged with a rule name
3. **Fail-safe** — if uncertain, stop. Don't guess.
4. **No hidden state** — if you can't see the state, you can't trust the decision

UPI fraud detection violates all four. fraud-watchdog restores them.

## Architecture  
```
┌─────────────────────────────────────────────────────────────┐
│  UPI APP (Normal World — can be compromised)                │
│                                                             │
│  • Collects user intent (amount, VPA, confirm)              │
│  • MUST call attestation engine before sending ReqPay       │
│  • CANNOT forge, skip, or modify the attestation            │
└──────────────────────────┬──────────────────────────────────┘
                           │  (mandatory API call)
                           ▼
┌─────────────────────────────────────────────────────────────┐
│  TEE / TRUST ZONE (Secure World — hardware-isolated)        │
│                                                             │
│  ┌───────────────────────────────────────────────────────┐  │
│  │  TEMPORAL ATTESTATION ENGINE (this library)           │  │
│  │                                                       │  │
│  │  1. Ingests timestamped event log                     │  │
│  │     (app_open, sms_received, payment_confirm,         │  │
│  │      screen_off, call_active, etc.)                   │  │
│  │                                                       │  │
│  │  2. Applies 3 deterministic checks:                   │  │
│  │     • VELOCITY  — dwell times, txn rate               │  │
│  │     • SEQUENCE  — required event order                │  │
│  │     • CONTEXT   — time-of-day, device state           │  │
│  │                                                       │  │
│  │  3. Outputs signed verdict:                           │  │
│  │     { "verdict": "PASS" | "TRIP",                     │  │
│  │       "signature": TEE_private_key_sign(...) }        │  │
│  └───────────────────────────────────────────────────────┘  │
│                                                             │
│  Hardware guarantee:                                        │
│  • App cannot read/write TEE memory                         │
│  • Signing key never leaves TEE silicon                     │
│  • TEE clock is tamper-resistant                            │
└──────────────────────────┬──────────────────────────────────┘
                           │  (signed attestation attached)
                           ▼
┌─────────────────────────────────────────────────────────────┐
│  UPI PROTOCOL (ReqPay message)                              │
│                                                             │
│  ReqPay {                                                   │
│    ...existing fields...                                    │
│    temporal_attestation: <signed blob>   ← MANDATORY        │
│  }                                                          │
│                                                             │
│  Missing or invalid signature → NPCI switch REJECTS         │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│  NPCI SWITCH (verifier)                                     │
│                                                             │
│  1. Verify TEE signature                                    │
│  2. Check verdict: PASS → proceed / TRIP → reject + alert   │
│                                                             │
│  Deterministic. Same attestation → same result. Always.     │
└─────────────────────────────────────────────────────────────┘```

### Why TEE? (The Hard Guarantee)

| PLC concept                        | Phone equivalent                | Why it's hard                                  |
|------------------------------------|---------------------------------|------------------------------------------------|
| Interlock relay (physical)         | TEE hardware isolation          | App cannot bypass — no software path around it |
| Hard fault → immediate trip        | `verdict: TRIP` → NPCI rejects  | Binary, not a score                            |
| Interlock runs below PLC software  | Engine runs below the app       | Malware in app layer is irrelevant             |
| Same fault → same trip, every time | Same attestation → same verdict | Deterministic, auditable, reproducible         |

### Current Status (v0.1)

The temporal attestation engine (3-axis checks) is implemented and tested in this repo. The TEE integration and `temporal_attestation` protocol fieldare the v0.3 deliverable.

```
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
| 2 | **v0.2** — Community scenarios (12+), configurable profiles,`--repeat` determinism test| In progress |
| 3 | **v0.3** — `temporal_attestation` schema, TEE attestation format, protocol proposal for UPI ReqPay message| Planned |
| 4 | **v1.0** — Android/Kotlin heartbeat module, 20+ scenarios, production-ready API | Drafting |

## Protocol Extension (v0.3)
A `temporal_attestation` field for the UPI ReqPay message.Schema, TEE signature format, and verification rules will be documented here at v0.3.  

*Solo project. No team. No funding. No VC. Just an engineer who got tired of reading fraud news.*

## Demo

<video src="demo_video.mp4" controls width="100%"></video> 

##
Auth: PV-J/30/9/26
##
