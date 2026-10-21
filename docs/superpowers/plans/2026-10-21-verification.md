# Verification — the intelligence layer (Task 25)

Run on 2026-10-21 against the `worktree-intelligence-layer` branch. This is
**offline verification only**: nothing here touches the live fleet, and no live
acceptance is claimed. The deployment acceptance in
`2026-10-21-intelligence-layer.md` Step 4 remains the operator's step after a
deploy.

## 1. Full suite and parity

| Check | Command | Result |
|---|---|---|
| Offline suite | `./test.sh` | **1240 checks, 0 failed** |
| Parity | `python3 tools/parity.py --check tests/fixtures/parity-baseline.json` | **parity OK: 96 rows identical** |

## 2. Mutation sweep

Each mutation was applied to a throwaway copy (`/tmp/mut-<guard>`, `.git` and
`frontend/node_modules` excluded), the owning suite was run from that copy, and
the copy was deleted. The worktree was never mutated. Rows 1–8 were measured
before the two new tests below (the intelligence suite then had 230 checks);
mutations 2 and 9 were re-run afterwards and show 234.

| # | Guard | Mutation applied | Owning suite | Failing check(s) | Proof |
|---|---|---|---|---|---|
| 1 | ungranted view filter | `run_cycle` builds a `ModuleView` for every module with a synthetic `{"observe": True}` grant (observe filter dropped) | intelligence | `the reference analyzer ran and recorded its run` (230 checks, 1 failed) | **PASS** |
| 2 | additive-only auto | `write_authoring_change` refuses only `silencing`/`invalid`, so `modification` is applied for `intelligence:auto` | intelligence | `the auto path refuses a modification`; `no modification was written` (234 checks, 2 failed). The new `test_a_modification_cannot_be_applied_by_the_auto_path` is what catches it. | **PASS** |
| 3 | label/OID identity | `authorize._row_identity` returns `("device",)` / `("check",)` (label, OID and device dropped) | intelligence | *none for the named check alone* — 230/0 when only `_row_identity` is mutated. Removing the second layer (`changed & _IDENTITY_FIELDS`) too turns the suite red: run aborts with `SettingsError` in `test_a_revert_restores_the_recorded_before_and_is_audited`, and `renamed label is silencing, not cosmetic` / `changed OID is silencing, not cosmetic` both fail | **FAIL as literally specified; PASS for the guard as a whole** |
| 4 | widening past failure | `authorize._widens` returns `False` immediately | intelligence | `a widening that turns a failing observation OK is silencing`; `a state expected moved onto a failing value is silencing` (230 checks, 2 failed) | **PASS** |
| 5 | destructive approval | `actions.allowed` restored to the legacy `policy.get("destructive")` branch (no human-approval requirement) | remediation | `full authority alone cannot run a destructive action`; `an approved proposal admits a destructive action`; `a destructive action is still refused without approval`; `and it no longer grants a destructive action` (141 checks, 4 failed) | **PASS** |
| 6 | one model call | `run_cycle` calls `advise_views` once per module and counts each call | intelligence | `the cycle records exactly one model call and its tokens` and 6 more (230 checks, 7 failed) | **PASS** |
| 7 | secret redaction | `advise_views` skips its redaction pass | intelligence | *none* — 230/0, because `pack_views` already redacts where the pack is built. Removing the redaction in **both** `advise_views` and `pack_views.dump` turns it red: `the canary line reached the pack and was redacted`; `the canary community and key are absent from the request`; `the key and the canary community are in no request field`; `a quoted, non-ASCII secret is redacted in BOTH forms` (230 checks, 4 failed) | **FAIL as literally specified; PASS for the guard as a whole** |
| 8 | endOfMibView | `snmp._decode` `0x82` branch removed | snmp | run aborts with `SnmpError: unsupported value tag 0x82` in `test_walk_follows_getnext_and_stops_cleanly` (exit 1; later checks do not run) | **PASS** (caught, as an uncaught error rather than a named FAIL) |
| 9 | next-epoch execution | `run_cycle` calls `heal.consider_nominations` at the end of the cycle | intelligence | `a model cycle makes ZERO heal.attempt calls`; `the cycle instead writes the nomination as a durable pending row`; `the nominated action did not run in the cycle that wrote it` (234 checks, 3 failed). `test_a_model_cycle_never_calls_heal_attempt` now runs with `MONITOR_REMEDIES=1`, so the call would genuinely execute rather than no-op. | **PASS** |

Supplementary probe for #2, before the test was added: with the mutated write
path, a modification (`SNMP_TIMEOUT_S` 1 → 2, actor `intelligence:auto`) was
**APPLIED**; on the unmutated tree the same call is **REFUSED** (`refused:
modification requires human approval`). That proved the guard existed and the
suite did not observe its removal through this path. The new
`test_a_modification_cannot_be_applied_by_the_auto_path` drives a band change
(a modification with no failing observation) through that exact path and is
what turned mutation #2 red.

Supplementary probe for #3: with only `_row_identity` mutated the named check
still passes, because identity changes are also caught by the
`changed & set(_IDENTITY_FIELDS)` branch: a label or OID change is still
`silencing`. The mutation therefore removes one of two layers, not the guard.

Supplementary probe for #7: the same shape — `pack_views` redacts at build
time, so `advise_views`' second pass is defense in depth and its removal alone
is invisible to the suite.

## 3. Frontend

| Check | Result |
|---|---|
| `npm --prefix frontend test` | 10 files, **58 tests passed** |
| `npm --prefix frontend run build` | `tsc -b && vite build`, 56 modules, built in 618 ms |
| `git status --short app/static` | **empty** — the committed `app/static` matches the source |

## 4. Docs

- `docs/architecture.md` — corrected the stale remediation-defaults bullet:
  `MONITOR_REMEDIES` defaults off, `SENTINEL_REMEDIATION` defaults on, and every
  module's authority starts `off`.
- `tests/test_intelligence.py` — two test changes closing gaps found by the
  sweep: `test_a_modification_cannot_be_applied_by_the_auto_path` (new) and
  `test_a_model_cycle_never_calls_heal_attempt` (now `MONITOR_REMEDIES=1`, with
  a "the action did not run" assertion). Suite total 1236 → 1240.
- This file.

## Open findings

1. **Defense in depth, not independent proofs.** The label/OID identity guard
   lives in two places (`_row_identity`'s set algebra and the
   `changed & _IDENTITY_FIELDS` branch), and secret redaction lives in two
   (`pack_views.dump` and `advise_views`' second pass). The suite proves each
   pair only in combination: removing one layer alone stays green, removing
   both reds. That is correct behaviour — the property is enforced — but neither
   inner layer is independently proven, so a future edit that removed the outer
   one would make the suite depend on a layer nothing exercises alone.
2. Two mutations (identity, endOfMibView) are caught as uncaught exceptions that
   abort the suite rather than as named `[FAIL]` lines. The suite exits non-zero,
   so the proof holds; the failure is simply louder than the harness's report.
