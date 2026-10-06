# The dashboard on a phone, and publishing it

Status: **design, approved 2026-10-06. Not built.**

Scope: `app/web.py`'s presentation layer, plus a new proxy stack that publishes
the monitor on a public hostname. Every honesty rule in `docs/architecture.md`
survives unchanged — this document changes how the page is *arranged* and *who
can reach it*, not what any number means.

---

## 1. Why

The dashboard is the only dead-man switch in the design — there is no push
notification by operator decision — and it is currently a console. It renders
79 rows on every load because the store's honesty rules require that an absent
row be visible rather than omitted, and that is correct. What it is not is
readable on a phone, where the thing you opened it to check is below the fold
behind a great deal of material you did not open it for.

Three further facts pushed this design:

- **The page has no secure context.** It is reached at `http://198.51.100.11:8787`
  on the container's own macvlan address. iOS will not install a web app and
  will not run a service worker without HTTPS, so *every* PWA goal is gated on
  the TLS decision, not on any UI work.
- **"All green" and "all grey" look identical.** A page where all 79 checks
  returned UNKNOWN has the same layout as a healthy one; only a 5px left border
  differs. That is the design's central rule — an absent answer is not a good
  answer — invisible at a glance.
- **The title contradicts the platform.** `<h1>` reads "CuBox fleet monitor"
  while `CLAUDE.md` is emphatic that the CuBox fleet is tenant #1 and targets are
  plugins. The first line on the page disagrees with the first line of the brief.

## 2. Goals

1. A phone can answer, in about five seconds and without scrolling, **is the
   monitor itself live, and is anything wrong.**
2. Every check remains represented on the page even when the list is collapsed,
   so no honesty rule is traded for readability.
3. The page updates itself without a second renderer.
4. It installs to an iOS home screen and opens standalone.
5. It is reachable from anywhere, behind a real authentication gate.

## 3. Non-goals

- **No service worker.** iOS installs to the home screen without one, so a
  service worker here would exist only to cache — and caching is the one thing
  the design forbids (see §7). Revisit only if a custom offline page is wanted
  over Safari's own error.
- **No push notifications.** Operator decision, unchanged.
- **No client-side renderer.** See §6.
- **No light theme.** A status board read at night; stated as a choice rather
  than left as an omission.
- **No `api_version` bump.** Every change here is additive or presentation-only.

---

## 4. The page

### 4.1 Layout

One column, mobile-first, **no viewport fork** — the same document on the phone
and on the Mac, with the wrong-rows grid going two-up when there is width. A
desktop-only variant would be a second layout to keep in step for no gain.

```
┌───────────────────────────────┐
│ sentinel                      │
│ Watching Storage-NAS,         │
│ Backup-NAS, cubox-1, cubox-2  │
│                               │
│ 12s ago                 180s  │
│ ▓░░░░░░░░░░░░░░░░░░░░░░░░░░░  │   freshness hero
├───────────────────────────────┤
│ FAIL                          │
│ 2 checks are red, 1 is amber  │   verdict band, full-bleed
├───────────────────────────────┤
│ ▏▏▎▏▏▏▏▏▏▏▎▏▏▏▏▏▏▏▏▏▏▏▏▏▏▏▏▏ │   tally strip
├───────────────────────────────┤
│ What's wrong                  │
│ ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━┓ │
│ ┃ FAIL   cubox-1            ┃ │
│ ┃ state_save_age_min        ┃ │
│ ┃ 38.2 hours — the state…   ┃ │
│ ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━┛ │
│ ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━┓ │
│ ┃ AMBER  cubox-2            ┃ │
│ ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━┛ │
├───────────────────────────────┤
│ ▸ All 79 checks               │
│ ▸ 1 live incident             │
│ ▸ Informational (2)           │
│ ▸ Evidence — what this        │
│   render read                 │
└───────────────────────────────┘
```

### 4.2 The freshness hero

**The age of the last collection, drawn against the stale threshold.** Not a
score, and not a bare number: the margin you actually have is the decision the
operator is making, and the domain's own unit is poll intervals. The page
already carries `interval`, `last_age_s` and `stale_after_s`, so this is a div
with a width percentage — no new data.

| `staleness` | Hero shows | Bar |
|---|---|---|
| `fresh` | `12s ago` with `180s` as the scale end | filled to `last_age_s / stale_after_s`, green |
| `lagging` | same, amber | amber |
| `stale` | same, red; the existing red banner still degrades the document | full, red |
| `none` | `never` in place of the age | no bar — an empty bar would read as "0s ago" |

The bar is `role="img"` with an `aria-label` stating the age and the threshold,
because a width-percentage div carries nothing to a screen reader.

### 4.3 The verdict band

Full-bleed, one line of state and one line of reason, driven by the same
three-valued logic as `/api/status.json`. It never renders a boolean, and it
must never render green over a grey board: the copy for the zero-colour case is
in §4.6.

### 4.4 The tally strip

**One segment per check, in stable order, grouped by target with a small gap
between groups.** This is the one memorable element and the design's boldness
budget is spent here.

It exists for three reasons:

1. **"All green" and "all grey" become different shapes.** This is the whole
   point — it is the honesty rule made visible in one glance, and it is not
   achievable with any amount of type or colour tuning on a list.
2. **It shows where.** Grouped by target, a red cluster reads as "the problem is
   in cubox-2" without any scanning.
3. **It remains complete under collapse**, so progressive disclosure hides no
   check — every one of the 79 is still on the page.

Specification:

- **Membership is exactly the verdict-bearing rows** — `tiles + extra + others`,
  the same set `_verdict_items` already uses for the API's counts.
  **Informational rows are excluded**, because they carry no colour by operator
  ruling: putting temperature in as a grey segment would make a perfectly
  healthy board look partly unknown, collapsing "no colour by ruling" into
  "UNKNOWN" — the exact confusion the strip exists to remove.
- That means the strip has fewer segments than the all-checks list has rows, and
  **the two numbers must never appear unlabelled next to each other.** The
  section summary reads `All 79 checks`, and the strip's label reads
  `77 graded: 74 green, 2 amber, 1 red, 0 unknown`. Two counts, each naming what
  it counts.
- Order is the same order the page already iterates — the check registry
  (`checks.expand`), then the collector-emitted `extra` rows — so the strip and
  the list can never disagree about membership.
- Segments carry the RAG colour of that check's status. `unknown` is
  `--unknown`, deliberately colourless.
- **It is an indicator, not a control.** At roughly 5px per segment on a 390px
  phone the segments are far below any tap target, and they do not pretend
  otherwise: no pointer cursor, no hover state, no title tooltips promising
  navigation. Navigation is the list below.
- Each segment is a `<span>` with an `aria-label`; the strip as a whole carries a
  summary label naming the counts, so the strip is not 79 anonymous nodes.
- On very narrow widths the strip wraps by target group rather than shrinking
  segments below visibility.

### 4.5 Progressive disclosure

Native `<details>`/`<summary>`. No JavaScript, no library, no custom accordion.

| Section | Default | Summary text |
|---|---|---|
| What's wrong | **open, always visible** — not a `<details>` | — |
| All checks | closed | `All 79 checks` — the count is in the summary, so a collapsed list still says how much is behind it |
| Live incidents | closed when zero, open when non-zero | `1 live incident` / `No live incident` |
| Informational | closed | `Informational (2)` |
| Thresholds with no check behind them | closed, **present only when non-empty** | names the count |
| Evidence — what this render read | closed | row counts stay inside; the *summary* states the table count |

Rules:

- **Collapsing never removes a row from the document.** The rows are rendered
  inside the `<details>`; shut is a presentation state, not an omission. This is
  the term on which the whole disclosure is acceptable, and it is asserted by a
  test (§9).
- A section with nothing in it and a section with unknown content must not share
  a summary. `No live incident` and `1 live incident` are different strings for
  that reason.

### 4.6 Copy

- `<h1>`: `sentinel`. Subtitle: `Watching Storage-NAS, Backup-NAS, cubox-1,
  cubox-2.` — a sentence, not a run of middle-dot fragments.
- Section headings become sentence case. The current tracked-out ALL-CAPS
  eyebrows are a generated-page tell and carry no information.
- The zero-red/amber block states which of the three cases it is, and never
  collapses them:
  - rows are red or amber → list them;
  - no colour at all → `No check reported a colour. This is UNKNOWN, not a
    clean fleet.`
  - some green, some grey → `No check is red or amber. 64 reported green; 15
    reported nothing and are UNKNOWN.` The grey count is never folded away.

### 4.7 Colour and type

**The page is monochrome until something is wrong.** The only saturated pixels
on the document are rows that are fail or warn. RAG here is domain semantics —
a tally light, the actual language of broadcast monitoring — not a decorative
accent, which is why it survives a brief that says not to reach for one.

| Token | Value | Role |
|---|---|---|
| `--bg` | `#0e1216` | cool slate ground |
| `--panel` | `#161c22` | tiles, collapsed rows |
| `--line` | `#232c35` | rules and borders |
| `--fg` | `#e6edf3` | body text |
| `--dim` | `#8b949e` | secondary text |
| `--ok` | `#3fb950` | green |
| `--warn` | `#e3b341` | amber |
| `--fail` | `#f85149` | red |
| `--unknown` | `#7d8590` | the fourth state, deliberately colourless |

**Type: the existing system mono stack, unchanged.** One family. No webfont —
a network fetch for typography on the one page that has to be trustworthy is a
dependency this design cannot afford, and fixed-width digits matter where
numbers sit in columns.

**Colour is never the only channel.** Every coloured row prints its status word
and every strip segment carries a label; a reader who cannot separate the
greens from the reds loses nothing. Visible keyboard focus and
`prefers-reduced-motion` are part of the quality floor, not extras.

---

## 5. The reactive layer

**Vanilla JavaScript, roughly 25 lines, no framework, no build step, and no
second renderer.**

On `interval` seconds, re-fetch `/` and swap the rendered container's contents.
Open `<details>` elements are restored by id after the swap, as is scroll
position. The server stays the only renderer in the system — a client-side tile
renderer would be a second implementation of `render_html` that must be kept
identical forever, which is item 7's shape and has already cost this project
twice.

Two failure modes are designed in, because both are the stale-sample defect
(commit `ecf1489`) wearing new clothes:

- **The fetch fails.** The banner must flip to UNKNOWN and say the monitor could
  not be reached. It must never keep displaying a green page it can no longer
  vouch for — a page that goes on asserting health after it has stopped being
  able to check is precisely the false green the whole design exists to prevent.
- **The swap brings a stale page.** That page already carries its own red
  degradation banner, and it arrives stating its own age, so nothing extra is
  needed — but nothing may suppress it either.

Polling is paused on `visibilitychange` when the page is hidden, so a phone in a
pocket is not polling all night. **No SSE and no websockets**: one small poll per
60-second epoch, through a proxy, is the right shape and the only one that
survives every intermediary in this design.

The ids the script depends on are a real integration seam — renaming a container
in `render_html` would silently stop the page updating, with no error anywhere.
That coupling is guarded by a test (§9).

---

## 6. The PWA shell

**The `no-store` contract protects observations, not the app shell.** That
distinction is the entire justification for the split, and it is principled
rather than a loophole: an icon served from cache is not a claim about the
fleet, whereas a cached status document is a false green.

- **New static endpoints** — `/manifest.webmanifest` and `/icons/*.png` — served
  with a caching header. They are constants of the image.
- **Unchanged and still `no-store`** — `/`, `/api/status.json`, `/api/state.json`
  and `/healthz`. Nothing an observation flows through becomes cacheable. The
  existing test that asserts this across every path stays as it is, and gains a
  guard (§9) so the shell exception cannot grow.
- **Head tags**: `manifest`, `apple-touch-icon` pointing at a 180×180 PNG (iOS
  does not accept SVG here), `theme-color`, and the `apple-mobile-web-app-*` set
  for standalone display and a title of `sentinel`.
- **Icons are committed repo assets**, not generated at runtime. Generating a
  PNG in the standard library is possible and is not worth the code.
- **No service worker.** §3.

---

## 7. Publishing

The monitor keeps its macvlan address and continues to publish no host port.

```
  internet
     │  DNS: <hostname> → home IP (DDNS)
     ▼
  ┌──────────────────────────┐
  │ nginx-proxy-manager      │   TLS termination, Let's Encrypt via DNS-01
  │  forward-auth ───────────┼──▶ authelia :9091   (passkeys, in-memory sessions)
  └────────────┬─────────────┘
               │  container → container, same eth1 macvlan
               ▼
        198.51.100.11:8787  sentinel
```

- **NPM joins the same `eth1` macvlan network** the other eleven services on
  Storage-NAS use, and reaches the monitor container-to-container. This is the
  arrangement the existing compose file already assumes and explains.
- **Let's Encrypt by DNS-01**, so port 80 is never opened for a challenge. This
  requires a DNS provider API token — an operator prerequisite, not a code one.
- **NPM's own admin interface is never exposed.** It is a control plane for the
  edge; it does not belong on the edge.
- **Sentinel is left as it is.** No auth code is written in `app/`. The
  container cannot distinguish an NPM request from any other, and does not need
  to: it is reachable only from the LAN by construction.

### 7.1 Access control

Authelia, single user, WebAuthn enrolled from the phone's Face ID, sessions in
memory (a single instance, so no Redis — one container, not two). NPM performs
forward-auth.

| Rule | Effect |
|---|---|
| `^/healthz$` | **bypass, from anywhere** |
| `/api/status.json`, `/api/state.json` from the LAN CIDR | bypass |
| everything else | `two_factor` from the internet |

Two consequences, both deliberate:

- **The documented `curl` integration keeps working.** `docs/architecture.md`
  publishes `curl -s http://198.51.100.11:8787/api/status.json` as the way an
  integrator reads the contract, and the whole point of a versioned document is
  that a script reads it. An interactive session gate would break every script
  that uses it, so the API bypasses **from the LAN only** — the public hostname
  gets no weaker a door than the rest of the site.
- **`/healthz` stays unauthenticated, and this is the important one.** If
  Authelia is down the operator is locked out, and the single question they need
  answered is whether their *login* is broken or the *monitor* is dead. One line
  — `collector fresh (last collection 12s ago)` — answers it without a session.
  It discloses one word about the fleet, and it buys back the ability to
  distinguish the two failures that this design's whole purpose is to keep
  apart.

### 7.2 A consequence to record

The monitor's public hostname is a new dependency in the path of the only
dead-man switch. If the proxy stack fails, the page is unreachable and the
failure is indistinguishable, from the phone, from a dead collector — which is
why §7.1's `/healthz` bypass exists. It is mitigation, not a fix, and it belongs
in the accepted-risks list rather than in a footnote.

---

## 8. What does not change

Unchanged, and each for a reason already recorded in the code:

- `Cache-Control: no-store` on every observation path, for every response code
  including 503.
- UNKNOWN as a first-class outcome; `value=None` can only ever produce UNKNOWN.
- The registry — not the store — driving the check list, so a check that never
  ran appears as `no result stored for this epoch`.
- The staleness banner degrading the whole document rather than one tile.
- Row counts in the footer.
- Informational rows excluded from every verdict and every tally, counted
  separately.
- `api_version` at **2**, with `build_state` as the single source both the page
  and the API derive from.

---

## 9. Testing

The offline suite is the only guard, and every guard here is mutation-tested —
reverted in a scratch copy to watch the suite go red, because a test that cannot
fail is not evidence.

| Test | Fails if |
|---|---|
| The tally strip renders exactly one segment per check in the registered order | a check is dropped from the strip, or the strip and the list disagree about membership |
| Informational rows produce no strip segment, and the strip and the all-checks summary each state their own count | an informational row is drawn as grey, or one number is read as the other |
| A board that is entirely UNKNOWN renders a strip class distinct from an all-green board | the "all grey looks all green" defect returns |
| Every check appears in the HTML while its `<details>` is closed | disclosure starts omitting rows |
| The shell endpoints carry a caching header **and it is the only place one appears** | someone adds a cache header to an observation path |
| `/`, both APIs and `/healthz` still carry `no-store` (existing, kept) | the dead-man switch's mechanism is weakened |
| Every freshness state (`fresh`/`lagging`/`stale`/`none`) renders its own hero and no other | the hero stops tracking the staleness it is supposed to lead with |
| The container ids the reactive script looks up are the ids `render_html` emits | a rename silently stops the page updating |
| No status is conveyed by colour alone — every coloured row contains its status word | an accessibility regression |
| The three zero-red/amber cases render three different strings | the green/grey collapse returns |

The reactive script's fetch-failure branch cannot be exercised without a
headless browser, which the offline suite deliberately does not have. It is
guarded by keeping the branch tiny and inspectable, and by the id-coupling test
above; that limitation is stated rather than papered over.

---

## 10. Deferred, with the condition that would revive each

- **Service worker** — add when a custom offline page is preferred to Safari's
  own error. It must not cache any observation path.
- **A continuously-reported tuner-refusal age** — carried over from the previous
  change: `TvhLogSignals` grades only when the age is bad, so the healthy path
  shows `--`. Independent of this design.
- **A light theme** — add if the board is ever read outdoors.
- **A second user** — the access-control table above is written for one; adding
  a second is an Authelia user entry and one NPM rule, not a redesign.

## 11. Order of work

1. Page presentation (layout, hero, band, strip, disclosure, copy) — no
   behaviour change, independently deployable.
2. Shell assets and head tags — installable, but only once step 3 lands an
   origin iOS considers secure.
3. Reactive layer.
4. Proxy stack: NPM, DNS-01, Authelia, access rules.
5. Verification on the phone: install, sign in with a passkey, confirm a stale
   board degrades, confirm a failed fetch reads UNKNOWN.

Steps 1 and 3 are testable offline and in the existing suite. Step 4 is
operational and is verified on the NAS, not in the suite.
