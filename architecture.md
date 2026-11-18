# Architecture (Internal Software)

This document describes the **internal software layers** of the watchdog.
The system-level deployment view (TEE, NPCI Switch, UPI Protocol) is in [README.md](README.md).


## Overview

UPI Fraud-Watchdog is a PLC-inspired fail-safe gate.
All layers are synchronous, single-threaded, and stateful per evaluation cycle.

```mermaid
graph TD
    L5[Layer 5: Presentation<br/>demo.py, scenarios.py]
    L4[Layer 4: Evaluation Engine<br/>TransactionWatchdog]
    L3[Layer 3: Rules / Config<br/>rules/default.yml]
    L2[Layer 2: Context Assembly<br/>TxnContext, UserProfile]
    L1[Layer 1: Data Ingestion<br/>Payment app, NPCI, OS sensors]

    L5 --> L4
    L4 --> L3
    L4 --> L2
    L2 --> L1
```

## Layer 1: Data Ingestion

| Input | Source | Format |
|-------|--------|--------|
| Action events | Payment app foreground log | `[(action, timestamp), ...]` |
| UPI payload | NPCI / PSP API | VPA, amount, txn ref, MCC |
| Device signals | OS sensors | `screen_on`, `touch_active`, `no_overlay` |
| Linked transactions | Internal ledger | `[(vpa, receipt_sec, forward_sec), ...]` |
| User profile | Offline ML (future) | `normal_hours`, `max_txn_per_hour`, `trusted_vpAs` |

> See `data_sources.md` for trust levels and failure modes.

## Layer 2: Context Assembly

**`TxnContext`** — the single struct the watchdog consumes.

| Field | Type | Source |
|-------|------|--------|
| `now` | `datetime` | Last event timestamp |
| `last_txn_time` | `Optional[datetime]` | Previous confirmed txn |
| `last_scam_alert_time` | `Optional[datetime]` | Scam detection module |
| `events` | `List[Tuple[str, datetime]]` | Action sequence |
| `screen_on` | `bool` | OS sensor |
| `touch_active` | `bool` | OS sensor |
| `no_overlay` | `bool` | OS sensor |
| `target_vpa` | `str` | UPI payload |
| `txn_count_this_hour` | `int` | Internal counter |
| `linked_txns` | `Optional[List[Tuple[str, float, float]]]` | Ledger |

**`UserProfile`** — learned normalcy (Phase 5+).

| Field | Type | Default |
|-------|------|---------|
| `normal_hours` | `set[int]` | `{8..21}` |
| `max_txn_per_hour` | `int` | `5` |
| `trusted_vpAs` | `set[str]` | `∅` |

## Layer 3: Rules / Configuration

**File:** `rules/default.yml`

| Section | Keys | Purpose |
|---------|------|---------|
| `watchdog` | `min_seconds_between_txns`, `min_scam_proximity_sec`, `max_txn_per_hour`, `normal_hours`, `network_min_linked`, `network_forward_max_sec` | Global thresholds |
| `dwell_min` | `open_app`, `select_contact`, `enter_amount`, `verify`, `confirm` | Per-step minimum dwell (seconds) |
| `expected_sequence` | list of 5 actions | Required action order |

**Loading:** `load_rules(path)` → `yaml.safe_load` → passed to `TransactionWatchdog.__init__`.

**Validation:** Corrupt values raise `ValueError` (covered by `fuzz_rules.py`).

## Layer 4: Evaluation Engine

**Class:** `TransactionWatchdog`

### State Machine

```mermaid
stateDiagram-v2
    [*] --> SAFE
    SAFE --> EVALUATING : evaluate()
    EVALUATING --> AUTHORIZED : all checks pass
    EVALUATING --> TRIPPED : any check fails
    AUTHORIZED --> SAFE : reset()
    TRIPPED --> SAFE : reset()
```

### Check Pipeline (AND-gated)

| # | Check | Method | Trips on |
|---|-------|--------|----------|
| 1 | Velocity | `_check_velocity` | Δt < `min_seconds_between_txns` |
| 2 | Time of day | `_check_time_of_day` | `now.hour ∉ normal_hours` |
| 3 | Scam proximity | `_check_scam_proximity` | Δt < `min_scam_proximity_sec` |
| 4 | Txn count | `_check_txn_count` | count > `max_txn_per_hour` |
| 5 | Sequence + Dwell | `_check_action_sequence` | Wrong order OR dwell < min |
| 6 | Heartbeat | `_check_heartbeat` | Any presence signal lost |
| 7 | Network velocity | `_check_network_velocity` | ≥N linked IDs forwarded in window |

**Logic:** All 7 must pass → `AUTHORIZED`. Any single failure → `TRIPPED`.
All checks run (no short-circuit) → full fault report.

### Output

```python
evaluate(ctx) → (passed: bool, reason: str)
# passed=True:  "[VELOCITY] OK  [SEQUENCE] OK  ... — Transaction authorized."
# passed=False: "BLOCKED: [CODE] detail | [CODE] detail"
```

## Layer 5: Presentation

**File:** `demo.py`

- CLI: `python demo.py --scenario <key>` or bare (runs all 14)
- Prints per-check ✓/✗ table
- Verifies expected outcome + expected faults
- Resets watchdog after each scenario

## File Map

| File | Layer | Responsibility |
|------|-------|----------------|
| `demo.py` | 5 | CLI runner, display |
| `scenarios.py` | 5 | 14 test scenarios (dict) |
| `watchdog.py` | 4 | `TransactionWatchdog`, `TxnContext`, `UserProfile`, `load_rules` |
| `rules/default.yml` | 3 | Thresholds, dwell, sequence |
| `fuzz/` | 4 | Hypothesis fuzz suite (21 tests) |

## Design Decisions

| Decision | Rationale |
|----------|-----------|
| AND-gate (no short-circuit) | PLC fault-summary pattern — report ALL faults, not just first |
| State machine (not just return) | Supports sticky-trip, reset semantics, future async |
| Rules in YAML (not code) | Operator-tunable without redeploy; fuzzable |
| `TxnContext` as single struct | Decouples watchdog from data sources; enables fuzzing |
| No ML in v0.4 | Deterministic, explainable, testable; ML in Phase 5 |
```
