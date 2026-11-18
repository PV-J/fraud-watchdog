# Data Sources

## 1. Transaction Events
- **Source:** Payment app instrumentation (foreground activity log)
- **Fields:** action, timestamp
- **Trust level:** Medium (can be spoofed by automation)
- **Edge cases:** empty stream, out-of-order timestamps, duplicate events

## 2. UPI Payload (NPCI)
- **Source:** PSP / NPCI API
- **Fields:** VPA (pa), amount (am), txn ref (tr), MCC (mc), currency (cu), mode
- **Trust level:** High (NPCI-validated)
- **Edge cases:** malformed VPA, negative/zero amount, >35 char txn ref

## 3. Device / Presence Signals
- **Source:** OS-level sensors (screen state, touch, overlay detection)
- **Fields:** screen_on, touch_active, no_overlay
- **Trust level:** Medium (rooted devices can fake)
- **Edge cases:** all-false (bot), partial loss

## 4. Network / Linked Transactions
- **Source:** Internal ledger (Phase 3)
- **Fields:** linked VPAs, receipt_sec, forward_sec
- **Trust level:** Medium (depends on ledger accuracy)
- **Edge cases:** empty list, circular references, >100 linked IDs

## 5. User Profile (Learned)
- **Source:** Historical behaviour (offline ML)
- **Fields:** normal_hours, max_txn_per_hour, trusted_vpAs
- **Trust level:** Low initially (cold-start), improves over time
- **Edge cases:** new user (empty profile), profile drift

## 6. Rules (YAML)
- **Source:** `rules/default.yml` (operator-configured)
- **Trust level:** High (version-controlled, reviewed)
- **Edge cases:** malformed values (covered by fuzz_rules.py) 

## 7. Fuzz Coverage
| Source | Fuzzed by | Status |
|--------|-----------|--------|
| 1. Transaction Events | `fuzz_context.py::test_no_crash` | ✅ |
| 2. UPI Payload | — | ⬜ |
| 3. Device / Presence Signals | `fuzz_context.py` (screen_on, touch_active, no_overlay) | ✅ |
| 4. Network / Linked Transactions | `fuzz_context.py` (linked_txns) | ✅ |
| 5. User Profile | — | ⬜ |
| 6. Rules (YAML) | `fuzz_rules.py` | ✅ |

