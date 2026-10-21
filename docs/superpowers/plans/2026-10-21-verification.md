# Verification — the intelligence layer (Task 25)

Run on 2026-10-21 against the `worktree-intelligence-layer` branch. This is
**offline verification only**: nothing here touches the live fleet, and no live
acceptance is claimed. The deployment acceptance in
`2026-10-21-intelligence-layer.md` Step 4 remains the operator's step after a
deploy.

## 1. Full suite and parity

| Check | Command | Result |
|---|---|---|
| Offline suite | `./test.sh` | **1236 checks, 0 failed** |
| Parity | `python3 tools/parity.py --check tests/fixtures/parity-baseline.json` | **parity OK: 96 rows identical** |

## 2. Mutation sweep

Each mutation was applied to a throwaway copy (`/tmp/mut-<guard>`, `.git` and
`frontend/node_modules` excluded), the owning suite was run from that copy, and
the copy was deleted. The worktree was never mutated.

| # | Guard | Mutation applied | Owning suite | Failing check(s) | Proof |
|---|---|---|---|---|---|
| 1 | ungranted view filter | `run_cycle` builds a `ModuleView` for every module with a synthetic `{"observe": True}` grant (observe filter dropped) | intelligence | `the reference analyzer ran and recorded its run` (230 checks, 1 failed) | **PASS** |
| 2 | additive-only auto | `write_authoring_change` refuses only `silencing`/`invalid`, so `modification` is applied for `intelligence:auto` | intelligence | *none* — 230 checks, 0 failed | **FAIL — not reproduced** |
| 3 | label/OID identity | `authorize._row_identity` returns `("device",)` / `("check",)` (label, OID and device dropped) | intelligence | *none for the named check alone* — 230/0 when only `_row_identity` is mutated. Removing the second layer (`changed & _IDENTITY_FIELDS`) too turns the suite red: run aborts with `SettingsError` in `test_a_revert_restores_the_recorded_before_and_is_audited`, and `renamed label is silencing, not cosmetic` / `changed OID is silencing, not cosmetic` both fail | **FAIL as literally specified; PASS for the guard as a whole** |
| 4 | widening past failure | `authorize._widens` returns `False` immediately | intelligence | `a widening that turns a failing observation OK is silencing`; `a state expected moved onto a failing value is silencing` (230 checks, 2 failed) | **PASS** |
| 5 | destructive approval | `actions.allowed` restored to the legacy `policy.get("destructive")` branch (no human-approval requirement) | remediation | `full authority alone cannot run a destructive action`; `an approved proposal admits a destructive action`; `a destructive action is still refused without approval`; `and it no longer grants a destructive action` (141 checks, 4 failed) | **PASS** |
| 6 | one model call | `run_cycle` calls `advise_views` once per module and counts each call | intelligence | `the cycle records exactly one model call and its tokens` and 6 more (230 checks, 7 failed) | **PASS** |
| 7 | secret redaction | `advise_views` skips its redaction pass | intelligence | *none* — 230/0, because `pack_views` already redacts where the pack is built. Removing the redaction in **both** `advise_views` and `pack_views.dump` turns it red: `the canary line reached the pack and was redacted`; `the canary community and key are absent from the request`; `the key and the canary community are in no request field`; `a quoted, non-ASCII secret is redacted in BOTH forms` (230 checks, 4 failed) | **FAIL as literally specified; PASS for the guard as a whole** |
| 8 | endOfMibView | `snmp._decode` `0x82` branch removed | snmp | run aborts with `SnmpError: unsupported value tag 0x82` in `test_walk_follows_getnext_and_stops_cleanly` (exit 1; later checks do not run) | **PASS** (caught, as an uncaught error rather than a named FAIL) |
| 9 | next-epoch execution | `run_cycle` calls `heal.consider_nominations` at the end of the cycle, with the process switch forced on so the call is not a no-op | intelligence | `a model cycle makes ZERO heal.attempt calls`; `the cycle instead writes the nomination as a durable pending row` (230 checks, 2 failed) | **PASS** |

Supplementary probe for #2: with the mutated write path, a modification
(`SNMP_TIMEOUT_S` 1 → 2, actor `intelligence:auto`) is **APPLIED**; on the
unmutated tree the same call is **REFUSED** (`refused: modification requires
human approval`). The guard exists and works; the suite does not observe its
removal through this path. Mutating `authorize.may_auto_apply` itself instead
does go red (`a tightening is a modification, never auto-applied`, `and it is
never auto-applied`), so only the *policy* function is covered by a test, not
the write path's use of it.

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
- This file.

## Open findings

1. **The `intelligence:auto` write path is not directly covered.** Nothing in
   the suite drives a `modification` through `settingsapi.write_authoring_change`
   as `intelligence:auto`; the classifier-level rule is tested twice
   (`may_auto_apply`), the enforcement site once would not be missed. A future
   edit that dropped the call there would ship silently. This is the one
   mutation the sweep could not reproduce.
2. Two guards are defense in depth (redaction in `advise_views`, label/OID in
   `_row_identity`): the suite proves the outer layer, so a mutation of only the
   inner one stays green. That is correct behaviour — the guard as a whole is
   load-bearing — but the inner layers are not independently proven.
3. Two mutations (identity, endOfMibView) are caught as uncaught exceptions that
   abort the suite rather than as named `[FAIL]` lines. The suite exits non-zero,
   so the proof holds; the failure is simply louder than the harness's report.
