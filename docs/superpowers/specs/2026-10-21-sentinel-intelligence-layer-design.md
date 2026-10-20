# Sentinel — the intelligence layer: grants, discovery, authoring, analysis

**Date:** 2026-10-21
**Status:** design approved in conversation; awaiting spec review
**Repo:** `sentinel`
**Branch:** `worktree-intelligence-layer`
**Builds on:** `docs/superpowers/specs/2026-10-19-sentinel-module-platform-design.md` and
`docs/superpowers/specs/2026-10-20-settings-spa-snmp-design.md`

---

## 1. Why

Sentinel can already observe, store, grade and (when an operator enables it) execute a
narrow set of remedies. What it cannot do is the thing the operator actually asked for:
*help run the ecosystem*. Three questions remain harder than they should be:

1. **Monitor it easily.** Adding three SNMP devices by hand took an hour: walk, read what
   answers, pick OIDs, name them, invent a band. The platform has settings and dynamic
   checks, but nothing that turns a walk into candidate rows.
2. **See that something is wrong.** The board shows incidents and check status. It does
   not say *why* a row is wrong, what changed lately, or what the pattern means.
3. **Do something about it, safely.** Proposals and the authority ladder exist, but
   nothing connects an analysis to a proposal, and there is no way to say "this module may
   advise, this one may author, this one may act, and this one may not be read at all".

The intelligence layer closes those three gaps **without becoming a second monitoring
system**. It is one platform capability with a grant matrix, a scoped read API, and no
ability to grade, resolve, silence or execute on its own authority. The remediation
engine remains the only executor.

### Decisions taken in brainstorming

| Question | Decision |
|---|---|
| Which readers do the grants govern? | **All of them.** One layer; statistical and model backends are both gated. |
| How is authoring levelled? | **`off → propose → auto`.** `auto` applies only provably additive changes. |
| How far does the destructive invariant reach? | **Every path.** No unattended destructive execution from any source. |
| First model wire format | **OpenAI-compatible chat completions** (`/v1/chat/completions`), local Ollama or hosted. |
| Discovery review | **Review sheet in the SPA**, one audited human write. |

---

## 2. Goals and non-goals

**Goals**

- A per-module, per-lane grant matrix declared by each module, granted by the operator,
  enforced where data is read, where proposals are created, and where actions execute.
- Two invariants enforced structurally, above the matrix, at every tier:
  1. the intelligence may never silence its own evidence;
  2. destructive actions are human-approved at every tier.
- One intelligence cycle per cadence, with **one logical model call** across all granted
  modules, bounded and budgeted per module.
- Deterministic discovery that turns an SNMP walk into reviewable candidate check rows,
  with no model in the path.
- An authoring lane that proposes check sets, labels, bands and diagnoses, each falsifiable
  by a real poll or measurement before it can be applied.
- Anomaly detection over stored history, statistics first; a measured experiment decides
  whether anything beyond statistics ships.
- Full visibility in the SPA: grants, last cycle, per-module budget use, insights,
  proposals, and errors that cannot read as green.
- No regression: `./test.sh` (972 checks), the parity baseline, and existing module
  contracts stay green.

**Non-goals**

- A model in the poll path or the execution path. The model runs after evidence is durable
  and its output is validated data.
- One model or one prompt per module. One call, many module views.
- Model hosting in the image, or a new runtime dependency. Python stdlib only; Node remains
  a development tool for the committed SPA build.
- Automatic destructive execution, by any setting, from any source.
- The intelligence changing its own grants, the global switch, platform keys, secrets, or
  any check result. It writes insights, proposals, and (only at `author=auto`) additive
  module settings.
- Counter-rate semantics in SNMP. Discovery names counters as not-yet-checkable rather
  than inventing a meaningless gauge band; this remains the carried-forward open item from
  the SNMP spec.
- SNMP v3 and per-vendor profiles, as before.
- A machine-learning model that does not beat the measured statistical baseline.

---

## 3. Architecture

### 3.1 The layer is a platform capability, not a Module

A Module has targets, checks, preload and I/O. The intelligence layer has none of those:
it reads what the store already recorded and produces insights and proposals. It therefore
lives at the platform level:

```
app/intelligence_layer.py     the cycle: grants, views, backends, validation, persistence
app/intelligence.py           the deterministic reference analyzer (existing, retargeted)
app/analyzer.py               anomaly detectors over one module view (phase 4)
app/llm_advisor.py            the OpenAI-compatible model backend (transport implemented)
app/authorize.py              the pure classifier for invariant 1 and the auto decision
app/module_view.py            the scoped, bounded, read-only snapshot for one module
```

`app/advisors.py` keeps the `Advisor`/`Insight` types and the `Snapshot` primitives the
views build on. `app/heal.py` stays the only executor.

The module-facing advisor hook stays `Module.advisors()`; a module-declared advisor is a
deterministic analyzer and is automatically scoped to that module's view. An LLM is never
declared per module.

### 3.2 The cycle

```
run_cycle(cfg, conn, ctx) -> CycleResult
```

1. **Global switch.** `SENTINEL_INTELLIGENCE=0` stops the cycle and records that it was
   switched off. The default is `1`, but with no grants the cycle reads nothing and says so.
2. **Grants.** Resolve every discovered module's grant. A module without `observe` is not
   read, not viewed, and not named to a backend.
3. **Views.** Build one `ModuleView` per observing module, each bounded by its per-module
   budget. A view failure is isolated to that module.
4. **Deterministic analysis.** Run the reference analyzer (and, in phase 4, the anomaly
   detectors) over each view. These are pure functions of stored data; no network.
5. **Model call.** If a model backend is selected and configured, assemble **one** request
   from all views and make **one** HTTP call. No per-module call, no retry inside the cycle
   (the next cycle is the retry).
6. **Validation and persistence.** Every output item is validated against the grants, the
   view it cites, the output schema and the invariants before it becomes an insight or a
   proposal. Invalid items are dropped and counted, never silently accepted.
7. **Records.** Write one `intelligence_cycle` row and one `intelligence_usage` row per
   module; write the existing `advisor_run` rows for the deterministic and model backends.
   Any failure becomes `status=error` with a redacted detail, plus a
   `ctx.module_errors["intelligence"]` entry so the SPA banner names it.

The collector calls this in the existing post-evidence advisor slot. The epoch's own
`duration_ms` is measured before advisors run, as today, so a slow model call cannot
lengthen the recorded epoch. The deterministic half is offline-capable; the model half is
attempted only when configured and its failure changes nothing about grading.

At the same post-evidence seam, **before** the cycle, `heal.consider_nominations()`
(phase 5) applies eligible action nominations written by the *previous* cycle. That is the
only path by which a model nomination can reach the executor, so no model call and no
action execution ever share a cycle.

### 3.3 What the intelligence may write

| Surface | May the intelligence write it? |
|---|---|
| `insight` (via the runner) | yes, when the module grants `observe` |
| `proposal` (via the runner) | yes, per lane: authoring kinds need `author`, action kinds need `remediate` |
| module non-secret settings (additive only) | yes, only at `author=auto`, only when `authorize` says additive |
| secret settings (`SNMP_COMMUNITIES`, future credentials) | **never**; excluded from views and from the authoring write path |
| grants, `SENTINEL_INTELLIGENCE`, platform keys | **never**; platform-owned |
| `check_run`, `incident`, `threshold_override`, `remedy` | **never**; no write path exists in the view or runner for these |
| action execution | only through `heal.attempt`, after every existing gate (phase 5) |

The runner holds the only store connection. Backends receive a view object with read
methods and no connection, no cursor and no write path — the same rule the existing
`Snapshot` already states, now enforced per module.

---

## 4. The grant matrix

### 4.1 Lanes

| Lane | Value | Means |
|---|---|---|
| `observe` | `true` / `false` | the module's view may be built and its data read; insights may be emitted |
| `author` | `off` / `propose` / `auto` | may propose changes to the module's non-secret settings, check rows, labels and bands; `auto` additionally applies **additive** changes without a human |
| `remediate` | `true` / `false` | may nominate the module's declared actions for that module's confirmed incidents; the existing `<MODULE>_AUTHORITY` ladder decides execution, and destructive actions always become proposals |

An ungranted module is not read at all. This is enforced at view construction — the only
place reads happen — not by filtering results afterwards.

The operator's example matrix is therefore: `remediate=true` plus `FLEET_AUTHORITY=full`
for the fleet, `observe` only for system, `observe` plus `author=propose` for SNMP, and no
grant for anything else.

### 4.2 Declaration

`Module` gains one member:

```python
Module(..., intelligence=("observe", "author", "remediate"))
```

Default `("observe",)`. It declares which lanes are **meaningful** for the module, not what
is granted. Discovery refuses a module that declares an unknown lane, or `remediate` with
no declared actions: a lane that can never do anything would read as a working grant.

Initial declarations:

| Module | Declares |
|---|---|
| `fleet` | observe, author, remediate (it has settings and `state_mount_cycle` / `transcode_restart`) |
| `system` | observe, author |
| `snmp` | observe, author |

### 4.3 Grant storage

One value per module, stored in the existing settings table with a **module-unique bare
key**, the same shape as `<ID>_ENABLED`:

```
module = "snmp"
key    = "SNMP_INTELLIGENCE"
value  = {"observe": true, "author": "propose", "remediate": false,
          "budget": {"rows": 500, "bytes": 32768, "tokens": 2000}}
```

- Env fallback is the same key (`SNMP_INTELLIGENCE`), a JSON string.
- Default for every module, when neither the store nor `.env` has a value:
  `{"observe": false, "author": "off", "remediate": false}` with the default budget.
- `_INTELLIGENCE` becomes a **reserved key suffix**: no module may declare it, exactly as
  `SENTINEL_LLM_*` is reserved. The write path special-cases it like `<ID>_ENABLED`.
- The JSON is validated on write and on startup: unknown lanes refused; `author` must be
  one of the three levels; a lane not declared by the module refused; budgets are positive
  integers; an unknown key refused (no silent normalisation).
- A grant naming an unknown module id, or an unsupported lane, is a **startup error** when
  the collector or `deploy.sh` starts — the same loud-failure rule as a misspelt
  `SENTINEL_MODULES`. A malformed value in the DB overlay is a per-cycle error with no
  grant, because the write path cannot produce one and a hand-edited row must not grant
  or deny silently.

The existing `setting_change` audit row is the grant audit: every write records old/new
JSON and the actor. No second table.

### 4.4 Precedence and application

UI (stored grant) > `.env` > default, resolved by the existing
`Config.reload_settings` overlay. A write applies on the next cycle; the SPA states that.
The grant is reloaded at the start of each `run_cycle`, so no restart is needed.

---

## 5. The two invariants

Both are correctness requirements: every other intelligence failure is caught by one poll,
these two hide the poll. They sit **above** the matrix: no grant, level, per-action
override or approval-time option can waive them.

### 5.1 Invariant 1 — the intelligence may never silence its own evidence

`app/authorize.py` is the one classifier. It is pure and it is used by every writer of an
authoring change.

A change is a proposed **full effective value** for one or more of a module's non-secret
settings (full values, not patches: a patch is ambiguous about what it leaves behind).

```
classify(change, module, view, ctx) -> additive | modification | silencing | invalid
```

| Class | Definition | Allowed at `author=auto`? |
|---|---|---|
| `additive` | row identities after ⊃ before; no existing row changed or removed; no band, expected value or subject touched | **yes**, applied and audited |
| `modification` | an existing row's band, expected value, unit or metadata changes, with no coverage loss | no; human proposal |
| `silencing` | a row or device is removed or disabled; a subject identity changes (label, device name, OID); or a band/expected change would turn an observation that is non-OK in the window into OK | **never**; human proposal at every level |
| `invalid` | fails the module's own `validate_settings`, an undeclared key, a secret setting, or a payload the diff cannot read | not stored |

Rules that make the identity test honest:

- **A label is an identity.** The incident key is `(target, check_id, subject)` and the SNMP
  subject is `<device>:<label>`. Changing a label is a removal of the old subject plus an
  addition of a new one, and is therefore `silencing`, not a cosmetic edit.
- **OID changes are identity changes** for the same reason; changing `ifIndex` because the
  device renumbered is exactly the failure this catches.
- **Widening past a failing value** is measured, not guessed: the view supplies the
  observations for the affected series; if any value that grades non-OK under the current
  band grades OK under the proposed band, the change is `silencing`.
- **No observations is not a licence to widen automatically.** A band change with no
  failing observation is `modification`, which is still proposal-only. `auto` is reserved
  for additions.
- **`expected` on a state check** is a band in disguise: changing it so a currently failing
  value passes is `silencing`.

Every authoring change writes a `proposal` row, including an auto-applied one: it is
inserted directly as `executed` by a dedicated store helper (actor `intelligence:auto`,
`decided_at` and `executed_at` set), not by claiming the human approval path.
`mark_proposal_executed` stays state-guarded to `approved`, so an unclaimed row cannot skip
the claim. The proposal payload carries the classification, the before/after diff, the
evidence the change would affect, and a `requires_human` flag (true for `modification` and
`silencing`). This gives one inbox, one audit trail, and a revert path.

`threshold_change` proposals are always human-approved and never reach the auto path; the
classifier labels them `modification` or `silencing` for display only.

The intelligence has no write path to `incident`, `check_run`, `threshold_override` or
`remedy`: it cannot dismiss, resolve or hide a row, and the SPA always renders the raw
check status beside any insight. It cannot write a grant, a secret or a platform key —
none is a declared non-secret module setting, and the authoring write path accepts only
those.

Approval re-runs `classify` and the module's `validate_settings` against the **current**
settings before applying. A proposal whose diff no longer applies is refused and left
pending. A human approval of a `silencing` change is allowed — that is what human approval
means — but it is recorded as such.

### 5.2 Invariant 2 — destructive actions are human-approved at every tier

The ladder keeps its five levels for non-destructive actions. Destructive actions are
**never** executed by an automatic path:

- `actions.allowed()` gains one rule, after the existing gates:

  ```
  if action.danger == "destructive" and not policy.approved:
      return False, "destructive action requires human approval"
  ```

- `actions.approval_policy()` is the **only** constructor that sets `approved=True`. On an
  execution path it is called only by `ctl.approve_proposal` / the SPA's approve route.
  `heal.consider()` calls it solely to ask whether a proposal *could* be approved — which
  is what writes the proposal — and never passes that policy to `attempt()`.
- `<MODULE>_ALLOW_DESTRUCTIVE` no longer grants anything. It is removed from
  `Config.authority()`. If it is present in `.env`, `Config.describe()` and the collector's
  startup print a warning that it is no longer honoured — an accepted-and-ignored setting
  is a lie, and a silent no-op is worse. It is removed from the docs and the SPA.
- A destructive action still appears in the approvals inbox with its danger, dry-run output
  and evidence. Approval executes it once, through `heal.attempt`, with the same resource
  locks, cooldown, attempt cap and verify-by-OK.

This applies to the incident engine and the intelligence alike. The matrix has no setting
that changes it.

---

## 6. The module view

`ModuleView` is the scoped snapshot. It exposes the existing read methods with the same
signatures, so advisor code does not branch on view type:

```
check_runs(limit=None)
samples(limit=None)
sample_keys(since, limit=None)
sample_series(since, target, metric, limit=None)
sample_stats(since, target, metric, pct=95)
incidents(since, limit=None)
logs(target, since, limit=None)
specs            # deep copy of this module's specs only
module_settings  # this module's non-secret settings only
```

The existing `thresholds(specs)` and `settings(values)` copy helpers remain.

Ownership rules, all derived from the contract the platform already has:

| Data | Owner |
|---|---|
| `check_run`, `incident` | `module.owned_check_ids(mod, ctx)` |
| sample series | the module whose spec has that `metric`; if none, the single module that declares the target; otherwise **unattributable** |
| logs | a module that declares the journal host in its `targets` (the fleet declares `cubox-1`/`cubox-2`) |
| settings | the module's own declared non-secret settings |
| specs from the `config` platform file | no module; excluded from every view |

Unattributable series and platform-owned specs are counted and named in the cycle record.
A module that is newly granted reports `available_days` from **its own** rows, even when
the store holds years of another module's history — the window-honesty rule, now per module.

The view enforces the budget on every read: row caps, per-series caps and a byte cap are the
same mechanism `Snapshot` already uses, resized from the grant's `budget` object. A read
that hits a cap records a truncation, and an analyzer must not reason from a truncated
series (the existing rule, carried over).

---

## 7. The model backend

### 7.1 Transport

`llm_advisor.py` implements the OpenAI-compatible chat-completions wire format with
`urllib.request`:

```
POST <SENTINEL_LLM_ENDPOINT>/v1/chat/completions
Authorization: Bearer <SENTINEL_LLM_KEY>    # omitted when no key is set (local Ollama)
Content-Type: application/json
{"model": ..., "temperature": 0,
 "messages": [{"role": "system", "content": ...}, {"role": "user", "content": ...}]}
```

`SENTINEL_LLM_PROVIDER` must be `openai` (the only provider in this delivery); any other
value is a configuration error with a clear message, not an empty cycle. The key stays
`.env`-only, is never a DB setting, never appears in a URL, a log, an insight, a proposal,
a traceback or the manifest, and is redacted from every exception string. A canary-key test
asserts each of those surfaces.

### 7.2 One call, many modules

The request is assembled once:

```
system: role and constraints (never claim success, no grading changes, no destructive
        actions, output must be the JSON schema, evidence must cite ids you were given)
user:   one pack per granted module, in module order:
          module id, title, window (requested/available), budgets and truncations,
          check rows (status, subject, detail, newest first, capped),
          numeric series summaries (count, span, p50/p95, latest — not raw rows),
          live incidents (state, subject, detail, first/last seen),
          recent log lines for a module that owns them (byte-capped),
          non-secret settings and threshold bands,
          discovered OID candidates when the module is snmp and discovery ran
```

Per-module budgets are enforced while packing (`rows`, `bytes`, estimated `tokens`). If the
sum exceeds `SENTINEL_INTELLIGENCE_MODEL_MAX_TOKENS`, every module's share is reduced
proportionally in a deterministic order and the reduction is recorded in `intelligence_usage`.
A module with no data contributes a short "no data in window" block, so the model knows it
was granted and empty rather than absent.

**Redaction before packing.** Every known secret value in the effective configuration
(the SNMP community map, the write token, the model key, any future `secret` setting) is
replaced with `[redacted]` wherever it appears in free text — log lines, check details,
error strings. A canary secret planted in a captured log line asserts the redaction, so a
future text source cannot quietly become an egress path.

The output schema:

```json
{"insights": [{"module", "kind", "title", "body", "target", "check_id",
               "subject", "severity", "confidence", "evidence"}],
 "proposals": [{"module", "kind", "payload", "rationale"}]}
```

Validation, item by item:

- `module` must be granted the lane the item needs; an item naming an ungranted or unknown
  module is dropped and counted (the model was never given that module's data, so this is a
  model error, not a platform leak).
- `evidence` must cite check ids, subjects or OIDs the module owns and that appear in the
  view. A citation that does not resolve is dropped; a fabricated incident key is never
  accepted.
- `kind` must be one this delivery supports; unknown kinds are dropped and counted.
- Strings are length-bounded; item counts are bounded per module; `confidence` is clamped.
- Every proposal goes through `authorize.classify` before it is stored.
- **Model-authored changes are always proposals, even when additive.** `author=auto` applies
  additions produced by the deterministic discoverer, whose inputs are measured values and
  a known-OID table. Text that arrived over SNMP, in a log line or in a check detail is
  untrusted input, and letting it drive an unattended settings write is prompt injection
  with a write credential. This narrows the `auto` carve-out; it does not violate it.

### 7.3 Failure is visible

A transport error, a non-JSON body, a schema violation, or an overrun sets the cycle's
`status` to `error` (or `budget`) with a redacted detail, writes nothing from the model,
and leaves the deterministic insights intact. `ctx.module_errors["intelligence"]` carries
the reason to the SPA banner. A configured-but-unreachable model is never an empty green
cycle. There is no automatic retry inside the cycle; the next cadence is the retry.

---

## 8. Deterministic discovery (phase 2)

### 8.1 The command

`snmp.discover` is an operator command, declared by the SNMP module:

```
Command(id="discover", danger="read_only",
        args=[Arg("device", choices=<configured device names>),
              Arg("max_oids", default="2000", required=False),
              Arg("samples", default="3", required=False)],
        resources=["snmp:device:<device>"], timeout_s=90)
```

It runs on a **configured** device, so the community never travels in argv or the audit
row. Adding a brand-new device is the review sheet's "new device" form: it writes the
device row (address + community into the secret map) through the normal settings API as a
human write, then offers discovery. That keeps the credential out of process arguments and
shell history entirely.

### 8.2 The walk

`snmp.py` gains `walk(host, community, root, port, timeout, max_oids)` using GETNEXT, with
the v2c `endOfMibView` tag (`0x82`) terminating cleanly. The command walks
`1.3.6.1.2.1` (MIB-II) and `1.3.6.1.4.1` (enterprise) under a total OID cap and the command
timeout, and reports truncation rather than pretending the tree ended. Requests are still
one OID at a time; GETBULK remains a later optimization.

### 8.3 Candidate generation

Candidates come from a small, checked-in table of known objects plus a conservative rule
for the rest:

| Source | Suggested row |
|---|---|
| `ifOperStatus.<i>` | `state`, `expected` = 1 (up), label `Interface <ifName/ifDescr/ifAlias>[<i>]` |
| `ifAdminStatus.<i>` | `state`, `expected` = 1 (up) |
| `sysUpTime`, `hrSystemUptime` | not emitted as a check; uptime is not a health band |
| `hrProcessorLoad`, load-average scalars, net-snmp memory scalars | `gauge`, direction and unit from the table |
| Ubiquiti per-SSID up-count, channel-utilisation | `gauge` / `state` from the table where known |
| any other numeric scalar | candidate with `confidence="low"`, `label` = OID, no suggested band; the operator supplies direction and band |
| monotonic counters (`ifInOctets`, `ifOutOctets`, `ifHC*`) | listed as **not checkable in this phase**; the report says counter-rate support is out of scope |
| strings, opaque values | not candidates |

Indexed tables are resolved to a human label by reading the name column at the same index;
an unresolvable index is reported, not silently skipped. This is the "prefer labels a human
can verify" rule from the device reality: ifIndex and VAP indices move on reconfiguration,
and a check against the wrong index fails loudly. A currently-down interface is therefore
flagged in the review sheet as "observed down", not silently made green by expecting the
observed value.

### 8.4 Band suggestions

A band is never loosened to fit an observation — that would be silencing by construction.

- **Known OID.** The checked-in table carries direction, unit and a **starting band** (for
  example `hrProcessorLoad`: high_is_good, green 70, amber 90; free-memory rows are
  expressed against the observed total). The command shows the observed value beside it.
  If the observation is already outside the starting band, the candidate is flagged
  "observed value is already outside the band — review before adding"; the band is not
  widened.
- **Unknown OID.** No band is suggested. A gauge row cannot be added until the operator
  supplies direction, green and amber (the module's existing validation requires them).
- **Repeated samples.** `samples` reads (default 3, bounded) report an observed min/max and
  identify monotonic counters; they do not invent a band.

Every candidate carries the observed value, its type, the number of observations and the
table rule that produced it. Nothing is added until a human (or, later, the deterministic
authoring lane) writes it.

### 8.5 Review and apply

- `POST /api/v1/modules/snmp/discover` `{device, max_oids, samples}` returns candidates.
  Token-gated, bounded, synchronous, and it changes nothing.
- The SPA review sheet shows device, OID, observed value/type, label, kind, direction,
  suggested band, confidence and a checkbox. Rows are editable. "Add selected" sends one
  request.
- `POST /api/v1/modules/snmp/discover/apply` `{device, rows}` merges the selected rows into
  the **current effective** `SNMP_DEVICES` / `SNMP_CHECKS`, validates the whole result with
  the module's existing cross-field rules, and writes it as one human settings change
  (`actor="operator"`). A row that fails validation refuses the whole write, naming the
  field; no partial application.
- The same generator is exposed to the authoring lane. Unattended, it emits a `check_set`
  proposal; at `author=auto` only high-confidence known-OID additions may apply, and only
  when `authorize` classifies them additive.

---

## 9. The authoring lane (phase 3)

`author` turns analysis and discovery into changes. Two proposal kinds are added to the
existing `action` and `threshold_change`:

| Kind | Payload | Applied by |
|---|---|---|
| `check_set` | `{settings: {SNMP_DEVICES: [...], SNMP_CHECKS: [...]}}` — full proposed values | `settingsapi.write_settings` after re-validation |
| `settings_change` | `{settings: {<key>: value}}` — non-secret keys only | the same |

Threshold changes keep their existing kind and approval path. The reference analyzer's
suggestions continue to become `threshold_change` proposals through the cycle runner (the
existing collector seam, now fed by the module view), only for modules that grant
`observe`; `author` is required for the model to propose them, because proposing a band is
authoring.

Every proposal carries a machine-readable `diff` and `classification` in `payload_json`.
The SPA renders the diff: removed rows in red, changed values side by side, added rows in
green, and the classification badge. `silencing` and `modification` proposals are marked
"requires human" and cannot be auto-applied by any code path.

Auto-applied additive changes are visible in two places: the proposal inbox (state
`executed`, actor `intelligence:auto`) and a "recent automatic changes" list with a revert
button. Revert is a new human settings write that restores the previous effective value;
it is audited like any other write.

---

## 10. Anomaly detection (phase 4, measured)

The baseline is the existing reference analyzer: window p95 outside the band, SQL-computed.
Phase 4 adds candidate detectors and a harness that decides whether any of them ships.

Candidates, all stdlib and bounded:

- **Robust z-score.** Per series: median and MAD over the window (MAD scaled by 1.4826);
  flag the latest reading when `|x − median| / scale > k`, with minimum sample count and
  span. Resistant to the spikes that make a mean meaningless.
- **Time-of-day buckets.** When the window spans at least seven days, compare the current
  hour's readings with the same hour's distribution across days; a daily load curve does
  not look like an anomaly every evening.
- **Level shift.** Compare the median of the last six hours with the median of the prior
  window; flag a step beyond a robust and relative threshold. This catches the failure mode
  a static band hides: a metric that is "healthy" but has halved.

Each insight states the statistic, the window, the sample count, the bucket, and the
estimate of how unusual the value is. Anomalies are insights only: they never change a
check's status, never resolve an incident, and can only *propose* a band (human approval).

**The experiment.** `scripts/score-anomaly.py` replays the stored history offline:

- per series, train on the first 80% of the window and score the remainder;
- positives are minutes where a check on the same target/metric was non-OK, plus incident
  windows (a proxy, stated as such);
- compare precision/recall and false-alarm rate against the p95 baseline at matched alert
  volume;
- report by series class (level, counter-derived, state) rather than one aggregate.

The deliverable is **either** a detector that beats the baseline with a stated margin on
the live store, enabled by default for granted modules, **or** a written null result in
this document's successor and in the operator docs, with nothing enabled. No stdlib
"ML from scratch" is written unless the harness proves it wins.

---

## 11. Remediation integration (phase 5)

The existing engine already acts on confirmed incidents whose checks match a declared
action trigger. The intelligence's remediation lane adds diagnosis-driven selection without
adding a second executor.

- With `remediate=true`, the model may emit an `action` proposal naming an `action_id` and
  an `incident_key` it saw in the module's view. Both must resolve to a live, open incident
  and a declared action whose trigger matches it. A fabricated or stale key is dropped and
  counted.
- **The model never executes in its own cycle.** A nomination is durable data: the runner
  writes an action proposal and, when the ladder permits automatic execution, marks its
  payload `auto_execute: true`. A dedicated `heal.consider_nominations()` runs at the
  **next** epoch's post-evidence seam, after the incident engine and before the next model
  call. It considers only proposals still `pending` (never a human rejection or expiry),
  re-checks that the incident is still open and that its `(target, check_id, subject)` ran
  in that epoch (the freshness gate), then calls `heal.attempt()` with
  `cfg.authority(module)` — never `actions.approval_policy()`. A nomination whose evidence
  did not recur is expired and left for a human. This is one cycle of latency and keeps
  the model out of the execution path entirely.
- The ladder decides the marking:
  - `off` / `advisory` → no action proposal; the diagnosis insight stands;
  - `propose` → a pending proposal without `auto_execute`;
  - `scoped` → `auto_execute` only if the action id is in `<MODULE>_ALLOW`;
  - `full` → `auto_execute` for any **non-destructive** declared action;
  - destructive → `actions.allowed()` refuses without `approved`, so it never receives
    `auto_execute` and is **always** a human proposal (invariant 2).
- `heal.attempt()` remains the only executor. The intelligence never calls an action's
  `run()` and never bypasses the resource locks, dry run, cooldown, attempt cap or
  verify-by-OK. A nomination the ladder refuses records the reason in `intelligence_usage`.
- The deterministic discoverer is not a model; its additive auto-apply is a settings write
  through the settings API and is not affected by this deferral.
- With `remediate=false`, the intelligence may still diagnose the incident under
  `observe`, but it cannot produce an action proposal or trigger anything.

---

## 12. Store, configuration, API and SPA

### 12.1 Store (additive, idempotent)

```sql
CREATE TABLE IF NOT EXISTS intelligence_cycle (
    id            INTEGER PRIMARY KEY,
    ts            REAL    NOT NULL,
    status        TEXT    NOT NULL,   -- ok | error | budget | skipped
    duration_ms   INTEGER,
    modules_granted TEXT  NOT NULL,   -- JSON list
    modules_read    TEXT  NOT NULL,   -- JSON list
    model_calls   INTEGER NOT NULL DEFAULT 0,
    tokens_in     INTEGER,
    tokens_out    INTEGER,
    detail        TEXT    NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS intelligence_usage (
    cycle_id  INTEGER NOT NULL,
    module    TEXT    NOT NULL,
    rows_read INTEGER NOT NULL DEFAULT 0,
    bytes_read INTEGER NOT NULL DEFAULT 0,
    insights  INTEGER NOT NULL DEFAULT 0,
    proposals INTEGER NOT NULL DEFAULT 0,
    dropped   INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (cycle_id, module)
);
```

No change to `proposal`: classification, diff and `requires_human` live in `payload_json`.
No change to `incident`, `check_run`, `threshold_override` or `remedy`.

### 12.2 Configuration

| Key | Default | Meaning |
|---|---|---|
| `SENTINEL_INTELLIGENCE` | `1` | layer master switch (`.env`-only, shown read-only in the SPA, like `MONITOR_REMEDIES`); with no grants it reads nothing and says so |
| `SENTINEL_INTELLIGENCE_INTERVAL_S` | advisor interval (300) | cycle cadence |
| `SENTINEL_INTELLIGENCE_BUDGET_MS` | `30000` | wall-clock budget; overrun is recorded, not killed |
| `SENTINEL_INTELLIGENCE_MODEL_MAX_TOKENS` | `16000` | total input estimate cap; shares are reduced deterministically |
| `<ID>_INTELLIGENCE` | all off | the grant JSON (store override wins over `.env`) |
| `SENTINEL_LLM_PROVIDER` | empty | must be `openai` when set |
| `SENTINEL_LLM_ENDPOINT` | empty | base URL; the client appends `/v1/chat/completions` |
| `SENTINEL_LLM_KEY` | empty | credential; `.env` only, never a DB setting |
| `SENTINEL_LLM_MODEL` | empty | model name |
| `SENTINEL_ADVISORS` | `reference` | backend selection; `none` selects no backend; `llm` must be named explicitly |

`SENTINEL_ADVISORS` keeps its meaning: it selects which backends run. The intelligence
cycle is the runner around them. Configuring a model never puts it on the default path.
`SENTINEL_INTELLIGENCE=0` is the one switch that stops the cycle entirely. It is
`.env`-only; the SPA shows its state and the per-module grants are the editable surface.
`.env.example` gains every new key with a generic value.

### 12.3 API

Reads (existing cache rules: `no-store`):

| Endpoint | Content |
|---|---|
| `GET /api/v1/intelligence` | global switch, backend configured (no secret values), per-module grants and supported lanes, last cycle, per-module usage, unattributable/unread counts, recent errors |
| `GET /api/v1/modules` | each manifest gains `intelligence: {supported, grant}` |
| `GET /api/v1/proposals` | existing, plus the new kinds with `classification` and `requires_human` |

Writes (Bearer token, constant-time compare, no LAN bypass):

| Endpoint | Body | Effect |
|---|---|---|
| `PUT /api/v1/modules/<id>/intelligence` | `{observe, author, remediate, budget?}` | validate against declared lanes, store the grant, audit |
| `DELETE /api/v1/modules/<id>/intelligence` | — | remove the override; the default (all off) applies |
| `POST /api/v1/modules/snmp/discover` | `{device, max_oids?, samples?}` | run the walk; returns candidates; changes nothing |
| `POST /api/v1/modules/snmp/discover/apply` | `{device, rows}` | one validated human settings write |
| `POST /api/v1/intelligence/revert/<proposal_id>` | — | restore the previous effective value of an auto-applied change; one audited human write |

The existing approve/reject routes handle the new proposal kinds through the same
`ctl` functions; no second approval path.

### 12.4 SPA

A new **Intelligence** page, plus small additions elsewhere:

- **Intelligence:** master switch state (read-only; set in `.env`); backend
  configured/model (never the key); last cycle status, duration and error; the grant grid (rows = modules, columns = observe,
  author level, remediate; unsupported lanes disabled with the reason); per-module budget
  use and items dropped; unattributable series; a "no modules granted" empty state that
  explains nothing is being read.
- **Module detail:** grant badges; for SNMP, a Discover button opening the review sheet.
- **Proposals:** render `check_set`/`settings_change` diffs; badge `silencing` and
  "requires human"; approve/reject; a "recent automatic changes" list with revert.
- **Overview:** a banner when the last intelligence cycle errored or was over budget.
- **Settings:** unchanged; grants live on the Intelligence page because they are not
  module settings.

The SPA remains a committed build (`npm ci && npm run build` → `app/static/`); the runtime
never invokes Node. Tests cover the grant grid, the review sheet, the diff rendering and
the token gate.

---

## 13. Compatibility and migration

- Existing endpoints, module contracts, settings precedence and the remediation ladder for
  non-destructive actions are unchanged.
- **Grants default to nothing.** After upgrade the intelligence reads no module until the
  operator grants one. This is the explicit default the rule requires, and it is visible:
  `--showconf`, the Intelligence page and the cycle detail all say "no modules granted".
  It is not a silent green.
- `<MODULE>_ALLOW_DESTRUCTIVE` is no longer honoured; a `.env` carrying it produces a
  startup warning and a `--showconf` line. Docs and SPA remove the control.
- `SENTINEL_ADVISORS=none` still disables all backends. The reference analyzer's existing
  tests are retargeted to the module view; its output shape and honest-window rules are
  unchanged.
- Store changes are additive and idempotent, so an image rollback still reads the store;
  the old image simply ignores the new tables and the grant rows.
- Parity (`tools/parity.py`, 96 rows) covers check verdicts, which the intelligence cannot
  change. It must stay byte-identical.
- No new Python dependency; `urllib.request`, `json`, `statistics`/`math` only.

---

## 14. Phases and acceptance

Each phase deploys alone and rolls back to the previous image.

### Phase 1 — Grants, scoped views, and both invariants

Module lane declaration; grant resolution, validation, storage, write API and audit;
`ModuleView` with per-module ownership and budgets; the cycle skeleton with the reference
analyzer retargeted; the SPA grant grid and Intelligence page; `authorize.classify`;
invariant 2 in `actions`/`heal`/`ctl`; the `ALLOW_DESTRUCTIVE` deprecation warning and the
ladder table/docs update that removes it; the intelligence tables.

**Acceptance:** an operator sets grants in the SPA and sees them on the next cycle; an
ungranted module's check rows and samples are never read (instrumented view test, not a
result filter); a `silencing` payload is a pending proposal at `author=auto`; a destructive
action does not execute at `full` even with the legacy switch set; `./test.sh` and parity
are green.

### Phase 2 — Deterministic discovery

`walk()`; the known-OID table; candidate generation with resolved labels and starting
bands; the SNMP command; the review sheet and the apply endpoint; counter rows reported as
out of scope.

**Acceptance:** add a device, discover it, review the candidates, add selected rows; the
next epoch shows reachability and OID rows; pulling the device reds the reachability row
and greys the OID rows; the credential never appears in argv, the audit row, the response or
a log.

### Phase 3 — Model backend and authoring

OpenAI-compatible client; one-call packing with per-module budgets; schema validation and
drop counting; `check_set`/`settings_change` proposals; auto-additive for the deterministic
discoverer only; diff rendering and revert; failure banner.

**Acceptance:** one request for N granted modules; an ungranted module never appears in the
request; a canary secret never appears in the request, a log, an insight, a proposal, the
DB or a traceback; an additive auto change is applied and audited; a silencing change is a
pending proposal; a transport failure shows a banner and no model output.

### Phase 4 — Anomaly detection, measured

Detectors; the replay/scoring harness; the decision.

**Acceptance:** the harness produces a reproducible comparison on real history; either the
winning detector is enabled for granted modules with evidence-bearing insights, or a
written null result ships and nothing is enabled.

### Phase 5 — Remediation integration and docs

Model-nominated actions under `remediate`; ladder integration through `heal.attempt`;
destructive always proposed; the intelligence page's remediation view; operator docs and
the runbook.

**Acceptance:** with `full`, a nominated non-destructive action on a confirmed incident
executes through every gate **on the next epoch**, never in the model's cycle; with
`propose`, it becomes a proposal; a fabricated incident or action id is dropped and
counted; a nomination whose incident cleared before the next epoch is expired, not
executed; a destructive action is always a human proposal; the runbook explains every
level.

---

## 15. Testing and mutation

The suite stays offline and deterministic. A fake OpenAI-compatible server counts requests
and can return malformed JSON, a 500, a slow body or an echoed canary.

**Grants and views**

- default grant reads nothing; each lane independently grants its reads;
- an ungranted module's check ids, sample series and logs are absent from the view
  (instrumented store: fail the test if a query names them);
- `available_days` is computed from the module's own rows;
- a grant naming an unsupported lane, an unknown module, an unknown key or a bad level is
  refused at write and at startup;
- a secret setting is absent from the view and refused on the authoring write path.

**Invariant 1**

- `additive` applies at `auto`; `modification` and `silencing` never apply at any level;
- a removed check row, a disabled device, a changed label/OID, and a band that turns a
  currently failing observation green are each `silencing`;
- a label change is not cosmetic: the incident key proves it;
- approval re-validates against current settings and refuses a stale diff;
- mutation: remove each classification branch in a scratch copy and the suite goes red.

**Invariant 2**

- `full` plus the legacy `ALLOW_DESTRUCTIVE=1` executes nothing and writes a proposal;
- only an approved proposal executes a destructive action, exactly once;
- the eligibility check in `heal.consider()` never reaches `heal.attempt()` with an
  approved policy — instrument the call and fail if it does;
- a model cycle makes zero executor calls; a nomination executes only at the next epoch's
  post-evidence seam, and only while its incident still has fresh evidence;
- mutation: restore the old switch branch and the suite goes red.

**Model and authoring**

- exactly one request per cycle across N modules;
- no ungranted module's data in the request;
- canary key and canary community absent from request, logs, insights, proposals, DB and
  traceback; a canary secret planted in a log line is `[redacted]` in the request;
- malformed/partial output drops items and counts them, never a silent green;
- model-authored additive changes are proposals, not auto-applied;
- a fabricated incident/action citation is dropped.

**Discovery**

- walk termination on `endOfMibView`, the OID cap and the timeout;
- indexed-table labels resolve through `ifName`/`ifDescr` and an unresolvable index is
  reported;
- the fake agent rejects a varbind without the mandatory NULL (the existing fake does; the
  spec keeps that assertion because a kinder fake already shipped a real bug once);
- counters are reported as not checkable, not given a meaningless band;
- apply validates the whole merged settings and writes nothing on a partial failure.

**Frontend**

- grant grid, unsupported-lane disablement, token gate, diff rendering, empty state;
- build succeeds; no Node at runtime.

**Mutation obligation.** Every new guard is reverted in a scratch copy and the suite must go
red, including: the ungranted-view filter, each invariant branch, the one-call assertion,
the secret redaction and the `endOfMibView` terminator. A test that cannot fail is not
evidence.

---

## 16. Risks and open items

| Risk | Mitigation |
|---|---|
| Grants default off and the fleet looks unmonitored | Explicit empty state on every surface; docs; one-write enablement |
| The reference analyzer's contract changes | Retarget to `ModuleView`, keep output and window honesty, update its tests; parity covers checks only |
| Sample attribution is ambiguous | Spec-metric ownership first, unique-target fallback, otherwise excluded and counted — never guessed |
| Model output is untrusted text | Strict schema, view-resolved citations, no auto-apply for model-authored changes, no execution without a real incident and the ladder |
| Prompt injection through SNMP strings or logs | Same as above; the model never sees a secret and cannot write one |
| One call gets too large | Per-module caps, deterministic proportional reduction, recorded truncation; the model is optional |
| A model failure hides behind a green board | Cycle error row plus banner; deterministic analysis still runs |
| Discovery invents a band from one sample | Starting bands come from a checked-in table, never from the observation; unknown OIDs get no band and cannot be added without operator input |
| `ALLOW_DESTRUCTIVE` removal surprises a deployment | Startup and `--showconf` warning; documented; no silent no-op |
| Counter-rate support is still missing | Stated as out of scope; discovery says so rather than shipping a bad gauge |

**Open items carried forward:** SNMP v3; vendor profiles; counter-rate metrics; a separate
process for the model call if its latency ever matters to the operator; extending the
review sheet to other protocols once a second settings-driven module needs discovery.
