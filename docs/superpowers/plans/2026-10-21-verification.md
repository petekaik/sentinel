# Verification — the intelligence layer (Task 25)

Run on 2026-10-21 against the `worktree-intelligence-layer` branch. This is
**offline verification only**: nothing here touches the live fleet, and no live
acceptance is claimed. The deployment acceptance in
`2026-10-21-intelligence-layer.md` Step 4 remains the operator's step after a
deploy.

## 1. Full suite and parity

| Check | Command | Result |
|---|---|---|
| Offline suite | `./test.sh` | **1263 checks, 0 failed** (1241 before the review fixes) |
| Parity | `python3 tools/parity.py --check tests/fixtures/parity-baseline.json` | **parity OK: 96 rows identical** |

## 2. Mutation sweep

Each mutation was applied to a throwaway copy (`/tmp/mut-<guard>`, `.git` and
`frontend/node_modules` excluded), the owning suite was run from that copy, and
the copy was deleted. The worktree was never mutated. Rows 1–8 were measured
before the new tests below (the intelligence suite then had 230 checks);
mutations 2 and 9 were re-run afterwards and show 235.

| # | Guard | Mutation applied | Owning suite | Failing check(s) | Proof |
|---|---|---|---|---|---|
| 1 | ungranted view filter | `run_cycle` builds a `ModuleView` for every module with a synthetic `{"observe": True}` grant (observe filter dropped) | intelligence | `the reference analyzer ran and recorded its run` (230 checks, 1 failed) | **PASS** |
| 2 | additive-only auto | `write_authoring_change` refuses only `silencing`/`invalid`, so `modification` is applied for `intelligence:auto` | intelligence | `the auto path refuses a modification`; `no modification was written` (235 checks, 2 failed). The new `test_a_modification_cannot_be_applied_by_the_auto_path` asserts the refusal message names **`modification`**. A SILENCING refusal from a different cause would pass a bare "human" test while never reaching the additive-only gate; an INVALID one carries no "human" and would not. | **PASS** |
| 3 | label/OID identity | **combined** mutation: `_row_identity` returns `("device",)` / `("check",)` **and** the `changed & _IDENTITY_FIELDS` branch is disabled | intelligence | suite exits 1 — aborts in `test_a_revert_restores_the_recorded_before_and_is_audited` with `SettingsError: refused: modification requires human approval (row changed on ('check',))`. The named check `test_a_label_or_oid_change_is_an_identity_change`, run directly against the same mutated copy, fails 2/2 (`renamed label is silencing, not cosmetic`, `changed OID is silencing, not cosmetic`) | **PASS (combined mutation). The single-layer mutation is EXPECTED-GREEN: the second layer still catches it.** |
| 4 | widening past failure | `authorize._widens` returns `False` immediately | intelligence | `a widening that turns a failing observation OK is silencing`; `a state expected moved onto a failing value is silencing` (230 checks, 2 failed) | **PASS** |
| 5 | destructive approval | `actions.allowed` restored to the legacy `policy.get("destructive")` branch (no human-approval requirement) | remediation | `full authority alone cannot run a destructive action`; `an approved proposal admits a destructive action`; `a destructive action is still refused without approval`; `and it no longer grants a destructive action` (141 checks, 4 failed) | **PASS** |
| 6 | one model call | `run_cycle` calls `advise_views` once per module and counts each call | intelligence | `the cycle records exactly one model call and its tokens` and 6 more (230 checks, 7 failed) | **PASS** |
| 7 | secret redaction | **combined** mutation: `advise_views` skips its redaction pass **and** `pack_views.dump` stops calling `redact` | intelligence | `the canary line reached the pack and was redacted`; `the canary community and key are absent from the request`; `the key and the canary community are in no request field`; `a quoted, non-ASCII secret is redacted in BOTH forms` — 230/4. `pack_views`' own redaction is proven directly by the canary test at `tests/test_intelligence.py:1841`, which calls `pack_views` without `advise_views` (that is why the `advise_views` pass alone can be removed). | **PASS (combined mutation). The single-layer mutation is EXPECTED-GREEN: `pack_views` redacts first.** |
| 8 | endOfMibView | `snmp._decode` `0x82` branch removed | snmp | run aborts with `SnmpError: unsupported value tag 0x82` in `test_walk_follows_getnext_and_stops_cleanly` (exit 1; later checks do not run) | **PASS** (caught, as an uncaught error rather than a named FAIL) |
| 9 | next-epoch execution | `run_cycle` calls `heal.consider_nominations` at the end of the cycle | intelligence | `a model cycle makes ZERO heal.attempt calls`; `the cycle instead writes the nomination as a durable pending row`; `the nominated action did not run in the cycle that wrote it` (235 checks, 3 failed). `test_a_model_cycle_never_calls_heal_attempt` now runs with `MONITOR_REMEDIES=1` and asserts `cfg.remedies_enabled is True`, so a plumbing break cannot make it vacuous. | **PASS** |

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
`silencing`. That single-layer mutation therefore removes one of two layers,
not the guard; the combined mutation above is the proof.

Supplementary probe for #7: the same shape — `pack_views` redacts at build
time, so `advise_views`' second pass is defense in depth and its removal alone
is invisible to the suite. The combined mutation above is the proof, and
`pack_views` also has the canary test that calls it directly.

## 3. Frontend

| Check | Result |
|---|---|
| `npm --prefix frontend test` | 10 files, **60 tests passed** (58 before the review fixes) |
| `npm --prefix frontend run build` | `tsc -b && vite build`, 56 modules, built in 634 ms |
| `git status --short app/static` | the committed build matches the source; the previous asset was replaced |

## 4. Docs

- `docs/architecture.md` — corrected the stale remediation-defaults bullet:
  `MONITOR_REMEDIES` defaults off, `SENTINEL_REMEDIATION` defaults on, and every
  module's authority starts `off`.
- `tests/test_intelligence.py` — test changes closing gaps found by the sweep:
  `test_a_modification_cannot_be_applied_by_the_auto_path` (new; the refusal
  must name `modification`) and `test_a_model_cycle_never_calls_heal_attempt`
  (now `MONITOR_REMEDIES=1`, asserts the switch is really on, and asserts the
  action did not run). Suite total 1236 → 1241.
- This file.

## Open findings

1. **Defense in depth, not independent proofs.** The label/OID identity guard
   lives in two places (`_row_identity`'s set algebra and the
   `changed & _IDENTITY_FIELDS` branch), and secret redaction lives in two
   (`pack_views.dump` and `advise_views`' second pass). The suite proves each
   pair only in combination: removing one layer alone stays green (by design —
   the other layer catches it), removing both reds. `pack_views`' redaction is
   also exercised directly by its canary test; `_row_identity`'s label/OID is
   not. A future edit that removed the outer layer would leave the suite
   depending on a path nothing exercises alone — worth remembering when either
   file is refactored.
2. Two mutations (identity, endOfMibView) are caught as uncaught exceptions that
   abort the suite rather than as named `[FAIL]` lines. The suite exits non-zero,
   so the proof holds; the failure is simply louder than the harness's report.

## 5. Final whole-branch review — the eight findings (2026-10-21)

The review findings and the fixes are recorded in
`.superpowers/sdd/2026-10-21-intelligence-layer/final-fix-report.md`. Two acceptance
statements changed and must not be read as shipped:

- **`author=auto` is RESERVED, so the auto-add acceptance step is DEFERRED.** The level
  still parses, but startup refuses a stored/`.env` `auto`, `write_grant` refuses to
  write one with `author=auto is reserved in this delivery; no unattended producer
  exists — use propose`, and the SPA offers only `off`/`propose` (a stored `auto` is shown
  disabled with the same reason). There is therefore **no production producer** for an
  automatically applied additive change in this delivery. The apply/revert substrate and
  its tests are kept as the follow-up's base; the **Revert** surface is exercised by
  tests only.
- The intelligence cycle now records **granted vs read**: a granted module whose view
  cannot be built produces `status=partial` (amber on the page, banner on the Overview)
  with the module named in the detail and in the cycle notes, and the API exposes
  `granted_not_read` and the unattributed series. A broken view is no longer a green
  cycle.
