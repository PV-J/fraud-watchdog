# temporal_attestation — Proposed UPI ReqPay Field (v0.3)

## 1. Where It Lives

A new **mandatory** field in the UPI ReqPay message, signed by the device TEE
before the payment is submitted to the NPCI switch.

```
ReqPay {
  ...existing fields (vpa, amount, ref_no, etc.)...
  temporal_attestation: <signed blob>   ← NEW
}
```

If the field is **missing** or the **signature is invalid** → the switch
**rejects** the payment at network level. No settlement. No beneficiary debit.

---

## 2. JSON Schema

```json
{
  "schema_version": "1.0",
  "device": {
    "tee_id": "sha256:ab3f...c9d2",
    "os": "android_14",
    "secure_boot": true
  },
  "session": {
    "session_id": "uuid:v4",
    "app_open_ts": 1760688000.000,
    "first_event_ts": 1760688001.240,
    "last_event_ts": 1760688018.510,
    "total_duration_ms": 17270
  },
  "event_log": {
    "count": 7,
    "hash": "sha256:4e2a...f81b",
    "events": [
      {"type": "app_open",        "ts": 1760688000.000},
      {"type": "sms_received",    "ts": 1760688001.240},
      {"type": "enter_amount",    "ts": 1760688005.800},
      {"type": "select_vpa",      "ts": 1760688010.100},
      {"type": "confirm_tap",     "ts": 1760688014.300},
      {"type": "biometric_auth",  "ts": 1760688016.000},
      {"type": "payment_submit",  "ts": 1760688018.510}
    ]
  },
  "checks": {
    "velocity": {
      "status": "PASS",
      "min_dwell_ms": 2000,
      "max_txn_per_hour": 5,
      "violation": null
    },
    "sequence": {
      "status": "PASS",
      "required_order": ["app_open", "enter_amount", "select_vpa",
                         "confirm_tap", "biometric_auth", "payment_submit"],
      "violation": null
    },
    "context": {
      "status": "PASS",
      "active_window": {"start": "08:00", "end": "22:00", "tz": "IST"},
      "device_state": {"screen_on": true, "call_active": false,
                        "overlay_detected": false},
      "violation": null
    }
  },
  "verdict": "PASS",
  "verdict_detail": "All 3 axes clear. No fault.",
  "signature": {
    "algorithm": "ECDSA_P256",
    "key_id": "tee_key_2026_001",
    "signed_payload": "sha256:9c1d...a4e7",
    "signature": "MEUCIQDx...k9fZ"
  },
  "nonce": "random:32bytes",
  "issued_at": 1760688018.510
}
```

### Field Notes

| Field | Purpose |
|-------|---------|
| `device.tee_id` | Unique TEE instance identifier. The switch maintains a registry. |
| `event_log.hash` | SHA-256 of the full event array. Tamper-evident. |
| `event_log.events` | Timestamped event sequence. Max 20 events (privacy cap). |
| `checks.*.violation` | `null` if PASS. If TRIP: `{"code": "DWELL_TIME_VIOLATION", "detail": "..."}` |
| `verdict` | **Binary.** `"PASS"` or `"TRIP"`. No score. No probability. |
| `nonce` | 32 random bytes. Prevents replay (see §5). |
| `issued_at` | TEE clock timestamp. Used for clock skew check (see §6). |

---

## 3. TEE Signature Format

```
signed_payload = SHA-256(
    schema_version
  + device.tee_id
  + session.session_id
  + event_log.hash
  + verdict
  + nonce
  + issued_at
)

signature = ECDSA_P256_sign(
    key = TEE_private_key[tee_id],
    data = signed_payload
)
```

- **Key generation:** Done once at device provisioning. Private key
  never leaves TEE silicon.
- **Public key:** Registered with the sitch at device onboarding. Stored in
  the switch operator's `tee_id → public_key` registry.
- **Verification:** the switch looks up `tee_id` → retrieves public key →
  verifies `signature` against `signed_payload`.

---

## 4. Proposed Switch-Side Verification (4 Steps)

The following is a reference verification flow. The actual
implementation is at the discretion of the switch operator. 

```
1. LOOKUP    tee_id → public_key (from registry)
2. VERIFY    ECDSA_verify(public_key, signed_payload, signature)
             → fail → REJECT
3. CHECK     verdict == "TRIP"?
             → yes  → REJECT + log + alert bank fraud team
             → no   → proceed
4. REPLAY    nonce in last-10-minutes window?
             → yes  → REJECT (replay attack)
             → no   → accept, add nonce to window
```

**Total verification time: < 1 ms** (ECDSA P-256 verify on commodity
server hardware). Negligible impact on the switch throughput.

---

## 5. Replay Prevention

| Attack | Defence |
|--------|---------|
| Attacker captures a valid PASS attestation, resubmits later | `nonce` is single-use. The switch maintains a 10-min sliding window of seen nonces. |
| Attacker replays within the same 10-min window | `issued_at` + `session_id` must match the original payment's `ref_no`. |
| Attacker forges a new attestation | ECDSA signature fails (no private key). |

---

## 6. Clock Skew Handling

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| Max allowed skew | **±500 ms** | TEE clock syncs via NTP at boot + every 30 min. 500 ms covers network jitter. |
| If `issued_at` differs from the switch clock by > 500 ms | **REJECT** (clock not synced, or tampered) |
| Event timestamps are **relative** to `app_open_ts` | The 3-axis checks use **deltas**, not absolute times. A 200 ms global shift doesn't change any dwell time. |

---

## 7. Privacy

- `event_log.events` contains **event types and timestamps only**. No VPA,
  no amount, no phone number, no location.
- Max 20 events per session (oldest dropped).
- `event_log` is **not stored** by the switch after verification. Only the
  `hash` and `verdict` are logged for audit.
- The TEE engine processes events **on-device**. The raw event log never
  leaves the phone. Only the signed verdict is transmitted.

---

## 8. Migration Path

| Phase | Mode | What happens on TRIP |
|-------|------|---------------------|
| **Phase 1** (advisory) | Log only | Payment proceeds. TRIP is logged. Bank fraud team alerted. No user impact. |
| **Phase 2** (selective block) | Block high-risk | TRIP on VELOCITY + SCAM_PROXIMITY → block. Other TRIPs → log only. |
| **Phase 3** (full enforcement) | Block all | Any TRIP → payment rejected. User sees: *"Payment blocked by security check. Contact your bank."* |

Phase 1 runs for **3 months** to measure false positive rate in production.
Target: < 0.01% of legitimate payments blocked.

---

## 9. Reference Implementation

The 3-axis check engine (velocity, sequence, context) is implemented and
tested in this repo:

```bash
git clone https://github.com/YOURNAME/fraud-watchdog
python demo.py
```

8 scenarios. 6 tripped. 2 passed. Deterministic. `--repeat 10000` for
proof.
```

---