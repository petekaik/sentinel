# Dashboard on a phone, and publishing it — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the dashboard readable at a glance on a phone, installable to an iOS home screen, and reachable from the internet behind a passkey gate — without weakening a single honesty rule.

**Architecture:** All page changes are inside `app/web.py`'s presentation layer and add no behaviour to `build_state`/`build_status`. New shell assets (manifest, icons) move into a new `app/shell.py` that owns the one deliberate exception to `no-store`. The reactive layer is ~25 lines of vanilla JS that re-fetches the page and swaps the DOM, so the server stays the only renderer. Publishing is a separate `proxy/` stack (nginx-proxy-manager + Authelia) that sentinel's own deploy never ships.

**Tech Stack:** Python 3.12 standard library only. No new dependencies, no build step, no framework, no service worker.

**Spec:** `docs/superpowers/specs/2026-10-06-dashboard-ux-and-publishing-design.md`

## Global Constraints

- **Python standard library only.** No `requirements.txt`, no new dependency, no CDN script. `./test.sh` runs `py_compile` over every `.py` file in the tree before anything else.
- **The test harness is not pytest.** A suite is a module exposing `TESTS = (fn, ...)`; each `fn(results)` calls `results.check(name, ok, detail)`. A failing check is a `False`, not an exception. Register new test functions in that module's `TESTS` tuple. New suites must also be added to `SUITES` in `tests/run_all.py`.
- **Every test has a non-vacuous half.** If a test asserts "grey is not green" it must also assert that a stored OK renders green, so a page reduced to a stub cannot pass it.
- **`no-store` on every observation path, and only there.** `/`, `/api/status.json`, `/api/state.json`, `/healthz`, `/no/such/path` and every error response carry `Cache-Control: no-store, no-cache, must-revalidate, max-age=0` plus `Pragma: no-cache` and `Expires: 0`. The caching header goes on `/manifest.webmanifest` and `/icons/*` and **nowhere else**.
- **`api_version` stays 2.** No key added to, removed from, or re-typed on `/api/status.json`.
- **One layout. No viewport fork.** The same document on a phone and on the Mac.
- **Colour is never the only channel.** Every coloured row prints its status word; every strip segment carries a label.
- **These strings are asserted by the existing suite and must survive every task below.** Weakening any of them without deliberately editing the test is a regression:
  - `NO COLLECTION HAS EVER BEEN RECORDED`
  - `banner ok` / `banner red` / `banner none` (the class names)
  - `STALE`, `AS IT WAS`, and the literal `past the 3 poll intervals (180s)`
  - `tile green`, `pill grey`, and the rendered text `>unknown<`
  - `no result is stored for the newest epoch`
  - `collector_run` (the row-count table)
- **Commit directly to `main`.** This repo has no remote and is not pushed. Do not create a feature branch.

## Review Focus

Five input classes the spec implies but no task's tests naturally reach. Each is
pinned by a test, named here with the task that owns the code:

1. **A status string the build does not recognise** (`"green"`, `"OK"`). `_status()` maps it to UNKNOWN, and the strip must draw it colourless rather than green on the strength of looking like green. *Pinned in Task 3.*
2. **An age past the threshold.** The bar must clamp at 100%, not overflow its track. *Pinned in Task 1.*
3. **`staleness == "none"`** — `last_age_s` is `None` while `stale_after_s` is a real number. Any division by `last_age_s`, or any bar drawn at all, is wrong: an empty track reads as "0s ago", which is the opposite of "never collected". *Pinned in Task 1.*
4. **A stale page whose stored rows are green.** The band must read UNKNOWN, not OK — and a board that is part green and part unknown must state the unknown count rather than let the green stand for the whole board. *Pinned in Task 2.*
5. **A zero-length selection** — no verdict-bearing rows at all. The strip must render an empty container with a label saying 0, not a malformed bar or a division by zero. *Pinned in Task 3.*

---

## Task 1: The freshness hero

The age of the last collection, drawn against the stale threshold, becomes the first thing on the page. The three degradation banners keep their exact classes and sentences — this task adds the hero above them and does not reword them.

**Files:**
- Modify: `app/web.py` — `_age` (:514-521), and the banner block in `render_html` (:535-562)
- Test: `tests/test_dashboard.py` — add a function and register it in `TESTS` (:943-955)

**Interfaces:**
- Consumes: `state["staleness"]`, `state["last_age_s"]`, `state["stale_after_s"]`, `state["last"]`
- Produces: `web._span(seconds) -> str` (a duration, no "ago"), `web._freshness(state) -> str` (one `<div class='hero <state>'>`)

- [ ] **Step 1: Write the failing test**

Add to `tests/test_dashboard.py`, above the `TESTS` tuple:

```python
# ---------------------------------------------------------------------------
# 8. The freshness hero leads, and tracks the state it leads with
# ---------------------------------------------------------------------------


def test_the_freshness_hero_tracks_the_staleness_it_leads_with(results):
    """Four states, four heroes, and the bar drawn in poll intervals."""
    tmpdir = tempfile.mkdtemp()
    try:
        d = Dash(tmpdir, interval=60)          # stale_after_s == 180
        d.epoch()
        fresh = d.html()
        d.epoch(age_s=60 * 2)
        lagging = d.html()
        d.epoch(age_s=60 * web.STALE_INTERVALS + 1)
        stale = d.html()
        never = Dash(os.path.join(tmpdir, "empty")).html()

        for name, html in (("fresh", fresh), ("lagging", lagging),
                           ("stale", stale), ("none", never)):
            present = [s for s in ("fresh", "lagging", "stale", "none")
                       if "hero %s" % s in html]
            results.check(
                "the %s board renders exactly one hero state, and it is %s"
                % (name, name),
                present == [name],
                "hero states found on the %s page: %s -- the hero exists to lead "
                "with the staleness, so a hero that does not track it is worse "
                "than no hero" % (name, present))

        # THE BAR IS DRAWN IN POLL INTERVALS, so these are exact: `state_at`
        # pins `now` against the stored ts and the arithmetic is a division.
        for age, want, why in (
                (0, "width:0.0%", "an age of zero leaves the track empty"),
                (90, "width:50.0%",
                 "half of the 180s threshold fills exactly half the track"),
                (181, "width:100.0%",
                 "an age PAST the threshold clamps at 100% -- a bar that "
                 "overflows its track is a bar that cannot be read")):
            html = web.render_html(d.state_at(age), d.cfg)
            results.check(
                "at age %ds the bar is %s (%s)" % (age, want, why),
                want in html,
                "expected %r in the hero; the rendered hero was:\n%s"
                % (want, html[html.find("class='hero"):][:300]))

        results.check(
            "a board with no collection ever draws NO bar and says 'never'",
            "class='hero none" in never and "hbar" not in never,
            "staleness=none drew a bar -- an empty track reads as '0s ago', "
            "which is the one thing 'never collected' is not")

        results.check(
            "the hero states the age and the threshold it is measured against",
            "stale at 3.0 min" in fresh and "class=hage" in fresh,
            "the hero does not state the threshold the bar is drawn against, so "
            "the bar has no scale and its length means nothing:\n%s"
            % fresh[fresh.find("class='hero"):][:300])

        # NON-VACUOUS HALF: the degradation sentences still exist, unchanged.
        results.check(
            "the hero did not replace the staleness banners it sits above",
            "banner red" in stale and "AS IT WAS" in stale
            and "NO COLLECTION HAS EVER BEEN RECORDED" in never,
            "the hero displaced the sentences that degrade the whole document")
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
```

Register it:

```python
TESTS = (test_empty_store_is_loud,
         test_a_sample_from_an_older_epoch_is_not_shown_as_current,
         test_stale_says_so_and_cannot_also_be_ok,
         test_unknown_is_never_green,
         test_unrecognised_status_is_grey_not_green,
         test_no_result_renders_unknown_with_a_reason,
         test_nothing_is_cached,
         test_collector_rows_are_visible,
         test_informational_rows_carry_no_colour,
         test_status_api_is_three_valued,
         test_status_api_is_a_stable_contract,
         test_the_freshness_hero_tracks_the_staleness_it_leads_with)
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `./test.sh dashboard`
Expected: FAIL on `the fresh board renders exactly one hero state` (`hero states found on the fresh page: []`), plus the bar assertions. Every other check still passes.

- [ ] **Step 3: Extract `_span` from `_age`, so the threshold and the age are formatted by one function**

Replace `_age` at `app/web.py:514-521` with:

```python
def _span(seconds):
    """A duration, without the "ago". For thresholds and scales.

    Extracted rather than typed a second time: `_age` and the hero's scale end
    must agree about what "3.0 min" means, and two formatters drift.
    """
    if seconds < 90:
        return "%.0fs" % seconds
    if seconds < 5400:
        return "%.1f min" % (seconds / 60.0)
    return "%.1f h" % (seconds / 3600.0)


def _age(seconds):
    if seconds is None:
        return "never"
    return _span(seconds) + " ago"
```

- [ ] **Step 4: Add `_freshness`**

Insert immediately after `_age`:

```python
def _freshness(state):
    """The hero: the age of the last collection, against the stale threshold.

    WHY THE AGE AND NOT THE VERDICT. This is a dead-man switch, so the first
    question is never "how is the fleet" but "is this page still being told
    anything". Everything below the hero is only as current as this number, and
    a page that leads with a verdict is a page that leads with a claim it may no
    longer be able to make.

    The bar is drawn in POLL INTERVALS because that is the unit the threshold is
    actually stated in -- "three intervals" -- and reading the margin off a
    number is arithmetic the operator should not have to do at 2am.
    """
    st = state["staleness"]
    if st == "none":
        # NO BAR, deliberately. A track at 0% reads as "0s ago", and "never
        # collected" is the opposite of that.
        return ("<div class='hero none'><div class=hage>never</div>"
                "<div class=hsub>no collection has ever been recorded</div>"
                "</div>")
    age = state["last_age_s"]
    limit = state["stale_after_s"]
    pct = max(0.0, min(100.0, 100.0 * age / limit)) if limit else 100.0
    return ("<div class='hero %s'><div class=hage>%s</div>"
            "<div class=hscale><span>current</span><span>stale at %s</span></div>"
            "<div class=hbar role=img aria-label='last collection %s, stale past "
            "%s'><i style='width:%.1f%%'></i></div></div>"
            % (st, _esc(_age(age)), _esc(_span(limit)), _esc(_age(age)),
               _esc(_span(limit)), pct))
```

- [ ] **Step 5: Call it, above the banners**

In `render_html`, immediately before the `# ---- the staleness banner, FIRST` comment at `app/web.py:535`, insert:

```python
    # ---- the hero: how current this page is --------------------------------
    a(_freshness(state))
```

Leave the whole banner block below it exactly as it is.

- [ ] **Step 6: Add the hero's CSS**

In the `CSS` string, insert after the `.sub` rule (`app/web.py:464`):

```css
.hero { padding:14px 0 4px; }
.hero .hage { font-size:38px; line-height:1.05; font-weight:600;
              letter-spacing:-.02em; }
.hero.fresh .hage { color:var(--fg); }
.hero.lagging .hage { color:var(--warn); }
.hero.stale .hage, .hero.none .hage { color:var(--fail); }
.hero .hsub { font-size:12.5px; color:var(--dim); margin-top:2px; }
.hero .hscale { display:flex; justify-content:space-between;
                font-size:10.5px; color:var(--dim); margin:9px 0 4px; }
.hero .hbar { height:6px; border-radius:3px; background:#1b2229;
              border:1px solid var(--line); overflow:hidden; }
.hero .hbar i { display:block; height:100%; background:var(--green); }
.hero.lagging .hbar i { background:var(--warn); }
.hero.stale .hbar i { background:var(--fail); }
```

Add the tokens this needs to `:root` (`app/web.py:454-455`) — later tasks use the rest:

```css
:root { --bg:#0e1216; --panel:#161c22; --fg:#e6edf3; --dim:#8b949e;
        --line:#232c35; --ok:#3fb950; --warn:#e3b341; --fail:#f85149;
        --unknown:#7d8590;
        --green:var(--ok); --amber:var(--warn); --red:var(--fail);
        --grey:var(--unknown); }
```

`--green`/`--amber`/`--red`/`--grey` are kept as aliases because the rest of the
stylesheet already uses them; they are removed in Task 5 once nothing refers to
them.

- [ ] **Step 7: Run the test to verify it passes**

Run: `./test.sh dashboard`
Expected: PASS, 0 failed.

- [ ] **Step 8: Mutation-test the bar's clamp**

In a scratch copy, change `min(100.0, ...)` to `100.0 * age / limit` and run `./test.sh dashboard`. Expected: FAIL on `at age 181s the bar is width:100.0%`. Revert the change.

- [ ] **Step 9: Run the whole suite**

Run: `./test.sh`
Expected: 0 failed across all five suites.

- [ ] **Step 10: Commit**

```bash
git add app/web.py tests/test_dashboard.py
git commit -m "Lead the dashboard with how current it is, not with a verdict

The age of the last collection is the first question about a dead-man
switch, and everything below it is only as current as that number. The
hero draws the age against the stale threshold in poll intervals, which
is the unit the threshold is stated in, so the margin is read rather
than computed.

No bar for staleness=none: a track at 0% reads as '0s ago', and never
collected is the opposite. The bar clamps at 100%, and the clamp is
mutation-tested. The three degradation banners are untouched -- the hero
sits above them.

Co-Authored-By: Claude Code <noreply@anthropic.com>"
```

---

## Task 2: The verdict band, with staleness dominating it

**Files:**
- Modify: `app/web.py` — add two functions after `_rag_counts` (:301-305); call from `render_html`
- Test: `tests/test_dashboard.py`

**Interfaces:**
- Consumes: `_verdict(items)`, `_verdict_items(state)`, `_rag_counts(items)`, `state["staleness"]`
- Produces: `web._band_verdict(state) -> (verdict:str, why:str)`, `web._verdict_band(state) -> str`

- [ ] **Step 1: Write the failing test**

```python
# ---------------------------------------------------------------------------
# 9. The band, and the three ways of having no colour
# ---------------------------------------------------------------------------


def test_the_band_never_says_ok_on_a_stale_or_colourless_page(results):
    """Staleness dominates the band, and the three empty cases differ."""
    tmpdir = tempfile.mkdtemp()
    try:
        d = Dash(tmpdir, interval=60)
        d.epoch()
        targets = [(c.target, c.id) for c in registry_instances(d.cfg)
                   if c.spec and not getattr(c, "informational", False)]
        for target, cid in targets:
            d.check(target, cid, store.Status.OK, "fine (test)")
        fresh = d.html()
        results.check(
            "a fresh all-green board bands OK",
            "band ok" in fresh,
            "the band did not read ok on a fresh board where every check is OK "
            "-- if this is wrong the assertions below prove nothing")

        # STALE, with every stored row still green. This is the dangerous one.
        d.epoch(age_s=60 * web.STALE_INTERVALS + 1)
        for target, cid in targets:
            d.check(target, cid, store.Status.OK, "fine (test)")
        stale = d.html()
        results.check(
            "a stale page whose stored rows are green bands UNKNOWN, not OK",
            "band unknown" in stale and "band ok" not in stale,
            "the band read OK beside the red STALE banner -- the coloured rows "
            "describe the fleet as it WAS, and a green band on them is the false "
            "green this page exists to prevent")

        # NO COLOUR AT ALL: nothing graded, nothing green.
        e = Dash(os.path.join(tmpdir, "grey"))
        e.epoch()
        grey = e.html()
        results.check(
            "a board with no coloured row bands UNKNOWN and says so in words",
            "band unknown" in grey
            and "nothing reported a colour" in grey,
            "a page where no check reported a colour did not say so plainly")

        # SOME GREEN, SOME GREY. The verdict stays ok -- that is the platform's
        # existing rule and not this design's business -- but the grey count
        # must be stated at the top, never folded away behind the green one.
        g = Dash(os.path.join(tmpdir, "mixed"))
        g.epoch()
        g.check(targets[0][0], targets[0][1], store.Status.OK, "fine (test)")
        mixed = g.html()
        band = mixed[mixed.find("class='band"):][:220]
        results.check(
            "a partly-unknown board states the grey count in the band itself",
            "band ok" in mixed and "reported nothing" in band,
            "the band on a board with 1 green and %d unknown rows reads %r -- so "
            "'we could not ask' is presented as if it were the same as 'it "
            "answered green', which is the collapse this project is built "
            "against" % (len(targets) - 1, band))

        # THE THIRD CASE: rows ARE red or amber, so they are listed and neither
        # empty-case sentence appears. All three cases must be three strings.
        r = Dash(os.path.join(tmpdir, "red"))
        r.epoch()
        r.check(targets[0][0], targets[0][1], store.Status.FAIL,
                "38.2 hours, past the limit (test)")
        r.check(targets[1][0], targets[1][1], store.Status.WARN, "near (test)")
        red = r.html()
        results.check(
            "a board with red and amber rows lists them and prints no empty note",
            "No check reported a colour" not in red
            and "reported nothing" not in red
            and "38.2 hours, past the limit (test)" in red
            and "band fail" in red,
            "the red/amber case did not render as the list -- the three "
            "zero-colour cases are three different documents and this one is "
            "not an empty note")
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
```

Register `test_the_band_never_says_ok_on_a_stale_or_colourless_page` in `TESTS`.

- [ ] **Step 2: Run the test to verify it fails**

Run: `./test.sh dashboard`
Expected: FAIL on all four checks — `band ok` does not appear anywhere yet.

- [ ] **Step 3: Implement**

Insert after `_rag_counts` (`app/web.py:305`):

```python
def _band_verdict(state):
    """The band's verdict and its reason. Staleness DOMINATES, exactly as it
    does in `build_status`.

    WITHOUT THIS BRANCH THE BAND IS A LIAR. A page past three poll intervals
    still carries the last epoch's coloured rows, and every one of them
    describes the fleet as it was. A band reading OK above the red STALE banner
    is the false green this page exists to prevent, and the API already refuses
    it -- the page must not be the weaker of the two readers.
    """
    if state["staleness"] in ("none", "stale"):
        return "unknown", ("the last collection is too old to say anything about "
                           "now, whatever the rows below still read")
    items = _verdict_items(state)
    verdict, _why = _verdict(items)
    n = _rag_counts(items)
    if verdict == "fail":
        why = "%d checks are red, %d amber" % (n["red"], n["amber"])
    elif verdict == "warn":
        why = "%d amber, and nothing red" % n["amber"]
    elif verdict == "ok":
        why = "%d checks green, none red or amber" % n["green"]
        if n["grey"]:
            # THE BAND MUST NOT LET A READER BELIEVE THE BOARD IS FULLY KNOWN.
            # The verdict is still ok -- that is the platform's existing rule
            # and changing it is not this design's business -- but a board where
            # 15 checks could not be asked is not the same board as one where 15
            # answered green, and the band is what a phone reads first.
            #
            # This sentence and the section note below it overlap deliberately.
            # Two honest statements on a monitoring page beat one folded-away
            # count, and the note is where the counts are spelled out.
            why += "; %d reported nothing" % n["grey"]
    else:
        why = "nothing reported a colour"
    return verdict, why


def _verdict_band(state):
    verdict, why = _band_verdict(state)
    return ("<div class='band %s'><div class=bst>%s</div>"
            "<div class=bwhy>%s</div></div>"
            % (verdict, _esc(verdict.upper()), _esc(why)))
```

In `render_html`, insert directly after `a(_freshness(state))`:

```python
    # ---- the band: the verdict, with staleness dominating it ----------------
    a(_verdict_band(state))
```

- [ ] **Step 4: Add the "what's wrong" section with its three empty cases**

This is the block that carries the spec's §4.6 copy. Insert after `_verdict_band`:

```python
def _whats_wrong(state):
    """The graded rows that are actually a problem, or the honest statement
    that there are none.

    THE THREE EMPTY CASES ARE THREE DIFFERENT SENTENCES. "No check is red" and
    "no check reported anything" are not the same fact, and a page that renders
    one string for both collapses "we could not ask" into "it is fine" -- which
    is the collapse this whole project is built to prevent.
    """
    items = _verdict_items(state)
    n = _rag_counts(items)
    flagged = [i for i in items if _status(i["status"]).rag in ("red", "amber")]
    if flagged:
        flagged.sort(key=lambda i: (0 if _status(i["status"]).rag == "red" else 1,
                                    i["target"], i["check_id"]))
        out = []
        for it in flagged:
            rag = _status(it["status"]).rag
            out.append(
                "<div class='wcard %s'><div class=wtop>"
                "<span class='pill %s'>%s</span>"
                "<span class=wt>%s</span>"
                "<span class=wc>%s</span></div>"
                "<div class=wd>%s</div></div>"
                % (rag, rag, _esc(it["status"]), _esc(it["target"]),
                   _esc(it["title"]), _esc(it["detail"])))
        return "".join(out)
    if n["green"] == 0:
        return ("<div class=note>No check reported a colour. This is UNKNOWN, "
                "not a clean fleet.</div>")
    if n["grey"]:
        return ("<div class=note>No check is red or amber. %d reported green; "
                "%d reported nothing and are UNKNOWN.</div>"
                % (n["green"], n["grey"]))
    return "<div class=note>No check is red or amber.</div>"


def _whats_wrong_section(state):
    n = len([i for i in _verdict_items(state)
             if _status(i["status"]).rag in ("red", "amber")])
    return ("<h2>%s</h2>%s"
            % (_esc("What's wrong (%d)" % n if n else "What's wrong"),
               _whats_wrong(state)))
```

In `render_html`, insert after `a(_verdict_band(state))`:

```python
    a(_whats_wrong_section(state))
```

- [ ] **Step 5: Add CSS for the band and the cards**

Append to `CSS`:

```css
.band { padding:11px 13px; border-radius:5px; margin:12px 0 0;
        border:1px solid var(--line); border-left-width:6px; }
.band .bst { font-size:19px; font-weight:700; letter-spacing:.01em; }
.band .bwhy { font-size:12.5px; color:var(--dim); margin-top:1px; }
.band.ok { border-left-color:var(--ok); background:#101a12; }
.band.warn { border-left-color:var(--warn); background:#1d1a10; }
.band.fail { border-left-color:var(--fail); background:#1f1113; }
.band.unknown { border-left-color:var(--unknown); background:var(--panel); }
.band.ok .bst { color:#8fdc9f; }
.band.warn .bst { color:#e8c46a; }
.band.fail .bst { color:#ff9d99; }
.band.unknown .bst { color:#a8b0bd; }
.wcard { border:1px solid var(--line); border-left-width:5px; border-radius:5px;
         padding:10px 12px; background:var(--panel); margin:7px 0; }
.wcard.red { border-left-color:var(--red); }
.wcard.amber { border-left-color:var(--amber); }
.wcard .wtop { display:flex; flex-wrap:wrap; gap:8px; align-items:baseline; }
.wcard .wt { font-size:13px; }
.wcard .wc { font-size:11.5px; color:var(--dim); }
.wcard .wd { font-size:12px; color:var(--dim); margin-top:5px;
             overflow-wrap:anywhere; }
```

- [ ] **Step 6: Run the test to verify it passes**

Run: `./test.sh dashboard`
Expected: PASS, 0 failed.

- [ ] **Step 7: Mutation-test the staleness branch**

In a scratch copy, delete the `if state["staleness"] in ("none", "stale")` branch from `_band_verdict` and run `./test.sh dashboard`. Expected: FAIL on `a stale page whose stored rows are green bands UNKNOWN, not OK`. Revert.

- [ ] **Step 8: Run the whole suite**

Run: `./test.sh`
Expected: 0 failed.

- [ ] **Step 9: Commit**

```bash
git add app/web.py tests/test_dashboard.py
git commit -m "Give the band staleness dominance, and split the empty cases

A page past three poll intervals still carries the last epoch's coloured
rows and every one of them describes the fleet as it was, so a band
reading OK above the red STALE banner is the false green this page
exists to prevent. build_status already refuses it; the page was the
weaker of the two readers. The band now takes the same branch.

The empty cases are three sentences, not one: no red is not the same
fact as nothing reported, and rendering one string for both is the
collapse the whole project is built against.

Co-Authored-By: Claude Code <noreply@anthropic.com>"
```

---

## Task 3: The tally strip

**Files:**
- Modify: `app/web.py` — add `_tally_strip` after `_whats_wrong_section`; call from `render_html`
- Test: `tests/test_dashboard.py`

**Interfaces:**
- Consumes: `_verdict_items(state)`, `_rag_counts(items)`, `_status(x).rag`
- Produces: `web._tally_strip(state) -> str`; each segment is `<span class='seg <rag>' aria-label='<target> <check_id>: <status>'>`

- [ ] **Step 1: Write the failing test**

```python
# ---------------------------------------------------------------------------
# 10. The tally strip
# ---------------------------------------------------------------------------


def test_the_strip_makes_all_grey_a_different_shape_from_all_green(results):
    """Membership, informational exclusion, and the grey/green distinction."""
    tmpdir = tempfile.mkdtemp()
    try:
        d = Dash(tmpdir)
        d.epoch()
        targets = [(c.target, c.id) for c in registry_instances(d.cfg)
                   if c.spec and not getattr(c, "informational", False)]

        for target, cid in targets:
            d.check(target, cid, store.Status.UNKNOWN, "not observed (test)")
        grey_strip = web._tally_strip(d.state())
        results.check(
            "an all-UNKNOWN board's strip has a segment per check and none green",
            grey_strip.count("class='seg ") == len(targets)
            and "seg green" not in grey_strip and "seg grey" in grey_strip,
            "segments=%d expected=%d green-present=%s"
            % (grey_strip.count("class='seg "), len(targets),
               "seg green" in grey_strip))

        # NON-VACUOUS HALF: a stored OK must produce green segments.
        d.epoch()
        for target, cid in targets:
            d.check(target, cid, store.Status.OK, "fine (test)")
        state = d.state()
        green_strip = web._tally_strip(state)
        results.check(
            "an all-OK board's strip is green, so the check above can fail",
            "seg green" in green_strip and "seg grey" not in green_strip,
            "the strip did not go green on a board where every check is OK")

        results.check(
            "the strip's label states its own count, per colour",
            ("%d graded:" % len(web._verdict_items(state))) in green_strip
            and "0 unknown" in green_strip,
            "the strip does not state what it is counting:\n%s"
            % green_strip[:300])

        # THE SEGMENT ORDER IS THE REGISTRY'S OWN, so the strip and the list
        # cannot disagree about what they are showing.
        got = [s.split("'")[0] for s in green_strip.split("class='seg ")[1:]]
        want = [web._status(i["status"]).rag for i in web._verdict_items(state)]
        results.check(
            "the strip's segments are the page's own rows, in the page's order",
            got == want,
            "strip order %r != row order %r -- the strip reordered the checks, "
            "so the two can disagree about what they are showing"
            % (got[:8], want[:8]))

        # AN UNRECOGNISED STATUS STRING. `_status` maps anything it does not
        # know to UNKNOWN, so the strip must not draw it as a colour that
        # carries a meaning it does not have.
        u = Dash(os.path.join(tmpdir, "bogus"))
        u.epoch()
        u.check(targets[0][0], targets[0][1], "OK", "shouted (test)")
        bogus = web._tally_strip(u.state())
        results.check(
            "a status string the build does not recognise is drawn unknown",
            "class='seg grey" in bogus and "class='seg green" not in bogus,
            "the status 'OK' produced: %s -- a status with no meaning here must "
            "never be drawn as a colour that has one, and it must not be drawn "
            "green on the strength of looking like green"
            % bogus[bogus.find("class=strip"):][:240])

        # THE LABEL IS NOT THE LIST'S COUNT. Informational rows are excluded,
        # so the strip has fewer segments than the all-checks list has rows and
        # the two numbers must each say what they count.
        info = [c.id for c in registry_instances(d.cfg)
                if getattr(c, "informational", False)]
        if info:
            results.check(
                "no informational row is drawn as a segment",
                all((" %s:" % cid) not in green_strip for cid in info),
                "an informational row reached the strip -- drawing a colourless "
                "row grey collapses 'no colour by ruling' into UNKNOWN, which is "
                "the confusion the strip exists to remove")

        # A ZERO-LENGTH SELECTION: no verdict-bearing rows at all.
        empty = web._tally_strip({"tiles": [], "extra": [], "others": [],
                                  "informational": [], "incidents": []})
        results.check(
            "a board with no verdict-bearing row renders an empty strip, not a "
            "broken one",
            "class='seg " not in empty and "0 graded checks" in empty,
            "a zero-length selection produced: %r" % empty[:200])
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
```

Register it in `TESTS`.

- [ ] **Step 2: Run the test to verify it fails**

Run: `./test.sh dashboard`
Expected: FAIL — `AttributeError: module 'web' has no attribute '_tally_strip'`.

- [ ] **Step 3: Implement**

```python
def _tally_strip(state):
    """One segment per verdict-bearing check, grouped by target.

    WHY THIS EXISTS AT ALL. "All green" and "all grey" render identically today,
    differing only in the colour of a 5px left border, so the rule this project
    cares about most -- an absent answer is not a good answer -- is invisible at
    a glance. As a strip they are different shapes.

    INFORMATIONAL ROWS ARE EXCLUDED. They carry no colour by operator ruling, so
    drawing a temperature reading as a grey segment would make a perfectly
    healthy board look partly unknown -- collapsing "no colour by ruling" into
    UNKNOWN, which is the exact confusion this strip exists to remove. The
    consequence is that the strip has fewer segments than the all-checks list
    has rows, so every count here names what it counts.

    GROUPED, NOT LISTED: a red cluster is how you read "the problem is in
    cubox-2" without scanning. The grouping is a gap inserted wherever the
    target CHANGES in the order the page already iterates -- the strip keeps the
    registry's own order rather than imposing a new one, so the strip and the
    all-checks list cannot disagree about membership even if the registry's
    ordering changes, and no sort is needed to achieve it.

    IT IS AN INDICATOR, NOT A CONTROL. At 5px per segment on a 390px phone these
    are far below any tap target and they do not pretend otherwise: no cursor,
    no hover, no title promising navigation.
    """
    items = _verdict_items(state)
    n = _rag_counts(items)
    label = ("%d graded: %d green, %d amber, %d red, %d unknown"
             % (len(items), n["green"], n["amber"], n["red"], n["grey"]))
    out, group, seen = [], [], None
    for it in items:
        if seen is not None and it["target"] != seen:
            out.append("<span class=seg-group>%s</span>" % "".join(group))
            group = []
        seen = it["target"]
        group.append("<span class='seg %s' aria-label='%s %s: %s'></span>"
                     % (_status(it["status"]).rag, _esc(it["target"]),
                        _esc(it["check_id"]), _esc(it["status"])))
    if group:
        out.append("<span class=seg-group>%s</span>" % "".join(group))
    return ("<div class=strip role=img aria-label='%s'>%s</div>"
            % (_esc(label), "".join(out)))
```

In `render_html`, insert after `a(_whats_wrong_section(state))`:

```python
    # ---- the strip: one segment per graded check, grouped by target --------
    a(_tally_strip(state))
```

- [ ] **Step 4: Add the strip's CSS**

Append to `CSS`:

```css
.strip { display:flex; flex-wrap:wrap; gap:8px; margin:13px 0 2px; }
.strip .seg-group { display:flex; gap:1px; }
.strip .seg { width:5px; height:20px; border-radius:1px; display:block; }
.strip .seg.green { background:var(--green); }
.strip .seg.amber { background:var(--amber); }
.strip .seg.red { background:var(--red); }
.strip .seg.grey { background:#39424d; }
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `./test.sh dashboard`
Expected: PASS, 0 failed.

- [ ] **Step 6: Mutation-test the informational exclusion**

In a scratch copy, change `_verdict_items(state)` inside `_tally_strip` to `state["tiles"] + state["extra"] + state["others"] + state["informational"]` and run `./test.sh dashboard`. Expected: FAIL on `no informational row is drawn as a segment`. Revert.

- [ ] **Step 7: Run the whole suite**

Run: `./test.sh`
Expected: 0 failed.

- [ ] **Step 8: Commit**

```bash
git add app/web.py tests/test_dashboard.py
git commit -m "Draw the graded checks as a strip, so all-grey is not all-green

All green and all grey rendered identically, differing only in the
colour of a 5px left border, so the rule this project cares about most
was invisible at a glance. As a strip of one segment per check they are
different shapes, and grouped by target a red cluster reads as 'the
problem is in cubox-2' without scanning.

Informational rows are excluded, because a colourless row drawn grey
would collapse 'no colour by ruling' into UNKNOWN. The strip therefore
has fewer segments than the all-checks list has rows, so every count
names what it counts.

Co-Authored-By: Claude Code <noreply@anthropic.com>"
```

---

## Task 4: Progressive disclosure

Everything below the strip moves behind native `<details>`. Nothing is removed from the document — shut is a presentation state.

**Files:**
- Modify: `app/web.py` — add `_details`, `_disclosure`; rewrap the sections in `render_html` (:574-680)
- Test: `tests/test_dashboard.py`

**Interfaces:**
- Produces: `web._details(sid:str, summary:str, body:str, open_:bool=False) -> str`. The `sid` becomes `id='sec-<sid>'`, which is the seam Task 7's script restores disclosure by. The ids this task emits are `incidents`, `checks`, `informational`, `thresholds`, `evidence`.

- [ ] **Step 1: Write the failing test**

```python
# ---------------------------------------------------------------------------
# 11. Disclosure hides nothing
# ---------------------------------------------------------------------------


def test_a_closed_section_still_renders_every_row(results):
    """Collapsed is a presentation state, not an omission."""
    tmpdir = tempfile.mkdtemp()
    try:
        d = Dash(tmpdir)
        d.epoch()
        targets = [(c.target, c.id) for c in registry_instances(d.cfg)]
        for target, cid in targets:
            d.check(target, cid, store.Status.OK, "fine (test)")

        state, html = d.state(), d.html()
        results.check(
            "every check in the registry appears in the HTML",
            all(cid in html for _target, cid in targets),
            "a check is missing from the document entirely -- collapsing must "
            "hide presentation, never rows")
        results.check(
            "the page uses native <details>, so disclosure needs no script",
            html.count("<details") == html.count("</details>")
            and html.count("<details") >= 4,
            "details open=%d close=%d -- expected at least four balanced "
            "sections" % (html.count("<details"), html.count("</details>")))
        results.check(
            "every section carries the id the refresh restores it by",
            all(("id='sec-%s'" % s) in html
                for s in ("incidents", "checks", "evidence")),
            "a section lost its id, so the refresh cannot restore whether it "
            "was open -- and restoring by position instead would shift every "
            "section after one that appears or disappears")

        # The counts live in the SUMMARIES, so a shut section still says how
        # much is behind it.
        summary_texts = [html[m:m + 120] for m in
                         [i for i in range(len(html))
                          if html.startswith("<summary", i)]]
        joined = " ".join(summary_texts)
        want_all = (len(state["extra"]) + len(state["tiles"])
                    + len(state["others"]) + len(state["informational"]))
        results.check(
            "the all-checks summary states its own count",
            ("All %d checks" % want_all) in joined,
            "summaries found: %r -- a collapsed list that does not say how many "
            "rows it holds reads as an empty one" % joined[:300])
        results.check(
            "the evidence summary is present, so row counts are not lost",
            "Evidence" in joined,
            "the row-count section lost its summary: %r" % joined[:300])
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
```

Register it in `TESTS`.

- [ ] **Step 2: Run the test to verify it fails**

Run: `./test.sh dashboard`
Expected: FAIL on `the page uses native <details>` (0 open) and on both summary checks.

- [ ] **Step 3: Implement the primitive**

```python
def _details(sid, summary, body, open_=False):
    """A native disclosure. No script, no framework, no custom accordion.

    `<details>` is the platform's own answer and it works with a keyboard, a
    screen reader and a thumb without anything from us.

    The id is not decoration: the reactive layer restores which sections were
    open after it swaps the DOM, and it does that BY ID, so a section appearing
    or disappearing between renders does not shift every section after it.
    """
    return ("<details id='sec-%s'%s><summary>%s</summary>%s</details>"
            % (_esc(sid), " open" if open_ else "", _esc(summary), body))
```

- [ ] **Step 4: Rewrap the sections**

In `render_html`, cut the existing blocks for incidents (:574-593), the tiles grid (:595-609), "All checks by target" (:611-628), informational (:630-647) and thresholds-with-no-check (:649-659), and the evidence footer (:661-671). Keep each block's own rendering code exactly as it is — this step changes only what wraps it.

Build each block into a local string, then emit. Each `_details` call is its own
statement so there is nothing clever to get wrong:

```python
    # ---- everything else, behind native disclosure -------------------------
    #
    # ORDER IS BY HOW LIKELY IT IS TO BE THE REASON THE PAGE WAS OPENED, and each
    # summary states its own count so a shut section still says how much is
    # behind it. A collapsed list that does not say how many rows it holds reads
    # as an empty one -- which is the same defect as an absent row reading as
    # fine, one level up.
    n = len(state["incidents"])
    if n:
        a(_details("incidents", "%d live incident%s" % (n, "" if n == 1 else "s"),
                   incidents_html, open_=True))
    else:
        a(_details("incidents", "No live incident", incidents_html))

    all_rows = (len(state["extra"]) + len(state["tiles"]) + len(state["others"])
                + len(state["informational"]))
    a(_details("checks", "All %d checks" % all_rows, tiles_and_checks_html))

    if state["informational"]:
        a(_details("informational",
                   "Informational (%d) — not health metrics by ruling"
                   % len(state["informational"]), informational_html))

    if state["deferred"] or state["unclaimed"]:
        a(_details("thresholds",
                   "Thresholds with no check behind them (%d)"
                   % (len(state["deferred"]) + len(state["unclaimed"])),
                   deferred_html))

    a(_details("evidence",
               "Evidence — %d row counts from this render"
               % len(state["counts"]["tables"]), evidence_html))
```

`incidents_html` keeps the existing block's own rendering, including its existing
empty-case note — that note is already a full sentence rather than a bare label,
which is the property §4.5 requires. Only the *summary* differs between the two
branches, which is the point: `No live incident` and `1 live incident` must never
be the same string.

- [ ] **Step 5: Add the disclosure CSS**

Append to `CSS`:

```css
details { margin:9px 0; border-top:1px solid var(--line); padding-top:8px; }
summary { cursor:pointer; font-size:13px; color:var(--fg); padding:5px 0;
          list-style:none; }
summary::-webkit-details-marker { display:none; }
summary::before { content:"▸ "; color:var(--dim); }
details[open] > summary::before { content:"▾ "; }
summary:focus-visible { outline:2px solid #6cb6ff; outline-offset:2px; }
```

- [ ] **Step 6: Run the test to verify it passes**

Run: `./test.sh dashboard`
Expected: PASS, 0 failed. Every earlier test still passes — the rows are all still in the HTML, only their wrapper changed.

- [ ] **Step 7: Mutation-test the "hides nothing" guarantee**

In a scratch copy, move the tiles grid OUT of the details body and render it only when `state["tiles"]` is non-empty *and* drop it otherwise — no. Simpler mutation that matches the guarantee: in the all-checks block, render only the rows whose status is not green. Run `./test.sh dashboard`. Expected: FAIL on `every check in the registry appears in the HTML`. Revert.

- [ ] **Step 8: Run the whole suite**

Run: `./test.sh`
Expected: 0 failed.

- [ ] **Step 9: Commit**

```bash
git add app/web.py tests/test_dashboard.py
git commit -m "Put everything below the strip behind native disclosure

The page opened on 79 rows because an absent row reads as 'fine', and
that rule is right, so the fix is not to render fewer rows but to make
the ones you did not open the page for not the first thing you scroll
past. Every summary states its own count, so a shut section still says
how much is behind it -- a collapsed list that does not say how many
rows it holds reads as an empty one.

A test asserts every registered check is still in the HTML while the
sections are closed, because that is the term on which any of this is
acceptable.

Co-Authored-By: Claude Code <noreply@anthropic.com>"
```

---

## Task 5: Tokens, type, headings and naming

**Files:**
- Modify: `app/web.py` — the `CSS` string, the header block in `render_html` (:527-534), and the `h2` headings
- Test: `tests/test_dashboard.py`

**Interfaces:**
- Produces: the final `:root` token set; no `--green`/`--amber`/`--red`/`--grey` aliases left

- [ ] **Step 1: Write the failing test**

```python
# ---------------------------------------------------------------------------
# 12. Naming, and colour that is never the only channel
# ---------------------------------------------------------------------------


def test_the_page_names_the_platform_and_never_colours_alone(results):
    """The title, the tokens, and four states all saying their own word."""
    tmpdir = tempfile.mkdtemp()
    try:
        d = Dash(tmpdir)
        d.epoch()
        html = d.html()
        results.check(
            "the page is titled sentinel, not named after tenant #1",
            "<h1>sentinel</h1>" in html and "CuBox fleet monitor" not in html,
            "the <h1> still names the first adapter as if it were the platform, "
            "which CLAUDE.md is explicit that it is not")

        results.check(
            "the old colour aliases are gone from the stylesheet",
            "--green:" not in html.split("</style>")[0],
            "the stylesheet still defines --green/--amber/--red/--grey as well "
            "as the role tokens, so there are two names for one colour and they "
            "will drift")

        results.check(
            "no webfont is fetched for the one page that has to be trustworthy",
            "@font-face" not in html and "fonts.googleapis" not in html
            and "fonts.gstatic" not in html,
            "the page pulls a font over the network -- a typography dependency "
            "on the page whose whole job is to be believable when the network "
            "is the thing that is broken")

        # FOUR STATES, FOUR WORDS. Each state's own word is in the document, so
        # a reader who cannot separate the colours loses nothing. The markers
        # are the ACTUAL markup each state renders in -- a tile prints its word
        # after the value; the coloured rows print it as the pill's text.
        for (target, cid), status in zip(
                [(c.target, c.id) for c in registry_instances(d.cfg)
                 if c.spec and not getattr(c, "informational", False)][:4],
                (store.Status.OK, store.Status.WARN, store.Status.FAIL,
                 store.Status.UNKNOWN)):
            d.check(target, cid, status, "state (test)")
        html = d.html()
        results.check(
            "every coloured state also prints its status word",
            all(marker in html for marker in (
                "&middot; ok<", ">warn<", ">fail<", ">unknown<")),
            "a state is conveyed by colour alone -- a reader who cannot "
            "separate the greens from the reds loses that row's outcome "
            "entirely")
        results.check(
            "the four states are drawn as four different colour classes",
            all(c in html for c in ("tile green", "pill amber", "pill red",
                                    "pill grey")),
            "the states are not distinctly coloured, so the word assertions "
            "above prove nothing about the colours")
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
```

Register it in `TESTS`.

- [ ] **Step 2: Run the test to verify it fails**

Run: `./test.sh dashboard`
Expected: FAIL on the `<h1>` check and on the alias check.

- [ ] **Step 3: Fix the title and subtitle**

Replace `render_html`'s header block (:531-533) with:

```python
    a("<h1>sentinel</h1>")
    # THE TARGET LIST IS DERIVED, NOT TYPED. §4.6's subtitle names the four
    # tenants, and writing those four names here as a literal would be a CuBox
    # literal in the presentation layer -- the one thing CLAUDE.md says the page
    # must not become, stale the moment a second adapter lands.
    watched = sorted({r["target"] for r in
                      state["tiles"] + state["extra"] + state["others"]
                      + state["informational"]})
    a("<div class=sub>Watching %s. Refreshed on every load, and nothing here "
      "is cached.</div>" % _esc(", ".join(watched) or "nothing yet"))
```

Add to the same test, so a literal that drifts is caught:

```python
        want_watched = ", ".join(sorted(
            {r["target"] for r in d.state()["tiles"] + d.state()["extra"]
             + d.state()["others"] + d.state()["informational"]}))
        results.check(
            "the subtitle names the targets the page is actually watching",
            want_watched in html and "Watching" in html,
            "the subtitle does not name the rows' own targets, so it is either "
            "a stale literal or empty -- expected %r" % want_watched)
```

- [ ] **Step 4: Drop the aliases**

Delete the `--green:var(--ok); ...` four lines added in Task 1 from `:root`, and replace every remaining `var(--green)`, `var(--amber)`, `var(--red)`, `var(--grey)` in `CSS` with `var(--ok)`, `var(--warn)`, `var(--fail)`, `var(--unknown)`. `--bg` becomes `#0e1216` and `--fg`/`--dim`/`--line` take the spec's values; `--panel` stays.

- [ ] **Step 5: Sentence-case the headings**

Replace every `<h2>` label that is currently uppercase-by-CSS with plain sentence case, and drop `text-transform:uppercase` / `letter-spacing` from the `h2` rule:

```css
h2 { font-size:15px; font-weight:600; color:var(--fg); margin:22px 0 8px;
     border-bottom:1px solid var(--line); padding-bottom:5px; }

/* The only motion this page has is the refresh swap and the disclosure
   opening. A reader who asked for none still gets a page that updates -- it
   just stops moving while it does. */
@media (prefers-reduced-motion: reduce) {
  * { transition:none !important; animation:none !important;
      scroll-behavior:auto !important; }
}
```

The tracked-out ALL-CAPS eyebrow is a generated-page tell and carries no information the sentence does not.

- [ ] **Step 6: Run the test to verify it passes**

Run: `./test.sh dashboard`
Expected: PASS, 0 failed.

- [ ] **Step 7: Mutation-test the colour-alone guard**

In a scratch copy, change the pill renderer to emit `<span class='pill %s'></span>` with the status word removed and run `./test.sh dashboard`. Expected: FAIL on `the unknown state is written in words, not only coloured` (and the four existing tests that assert `>unknown<`). Revert.

- [ ] **Step 8: Run the whole suite**

Run: `./test.sh`
Expected: 0 failed.

- [ ] **Step 9: Commit**

```bash
git add app/web.py tests/test_dashboard.py
git commit -m "Name the platform on the page, and drop the stylesheet's aliases

The <h1> read 'CuBox fleet monitor' while CLAUDE.md is emphatic that the
fleet is tenant #1 and targets are plugins, so the first line of the page
disagreed with the first line of the brief. It now reads sentinel.

The colour aliases go too: --green and --ok as two names for one value is
two things to keep in step for nothing. The tracked-out ALL-CAPS section
eyebrows become sentence case, which is a generated-page tell rather than
information. A test asserts every state is also written in words, so no
status is conveyed by colour alone.

Co-Authored-By: Claude Code <noreply@anthropic.com>"
```

---

## Task 6: The shell — manifest, icons, and the one caching exception

**Files:**
- Create: `app/shell.py`
- Create: `app/icons/icon-180.png`, `app/icons/icon-512.png`
- Modify: `app/web.py` — `_send` (:703-719), `do_GET` (:721-756), the head of `render_html` (:527-529)
- Test: `tests/test_dashboard.py`

**Interfaces:**
- Produces: `shell.ASSETS -> dict[str, tuple[str, str]]` (url path → (file path, content type)), `shell.CACHE_CONTROL -> str`, `shell.manifest() -> str`, `shell.read(relpath) -> bytes`
- Consumes: nothing

- [ ] **Step 1: Write the failing test**

```python
# ---------------------------------------------------------------------------
# 13. The shell, and the ONE place a cache header is allowed
# ---------------------------------------------------------------------------


def _get_bytes(url):
    """The body as BYTES. `_get` decodes utf-8 with "replace", which is right
    for the HTML and the JSON and destroys a PNG -- comparing a decoded image
    against its magic bytes would test the decoder, not the file.
    """
    try:
        with urllib.request.urlopen(url, timeout=10) as r:
            return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()


def test_the_app_shell_may_cache_and_nothing_else_may(results):
    """Manifest and icons cache; every observation path still does not."""
    tmpdir = tempfile.mkdtemp()
    try:
        d = Dash(tmpdir)
        d.epoch()
        httpd, base = _serve(d.cfg)
        try:
            for path in web.shell.ASSETS:
                code, hdrs, body = _get(base + path)
                results.check(
                    "%s is served, and cacheable" % path,
                    code == 200 and hdrs.get("Cache-Control") == web.shell.CACHE_CONTROL,
                    "code=%s Cache-Control=%r -- the app shell is a constant of "
                    "the image, so caching it is not a claim about the fleet"
                    % (code, hdrs.get("Cache-Control")))

            # THE GUARD THAT MATTERS: the exception must not grow.
            for path in ("/", "/api/status.json", "/api/state.json", "/healthz"):
                code, hdrs, body = _get(base + path)
                results.check(
                    "%s did NOT gain a cache header" % path,
                    hdrs.get("Cache-Control") == CACHE
                    and hdrs.get("Cache-Control") != web.shell.CACHE_CONTROL,
                    "Cache-Control=%r -- an observation path became cacheable, "
                    "and a cached 200 while the collector is dead is a false "
                    "GREEN" % hdrs.get("Cache-Control"))

            code, hdrs, body = _get(base + "/manifest.webmanifest")
            try:
                man = json.loads(body)
                ok_man = (man["name"] == "sentinel" and man["display"] == "standalone"
                          and len(man["icons"]) >= 2)
            except Exception as exc:                     # noqa: BLE001
                ok_man, man = False, {"error": str(exc)}
            results.check(
                "the manifest installs as a standalone app called sentinel",
                ok_man, "manifest=%r" % man)

            # PNG magic, so a truncated or wrong file is caught here rather than
            # on the phone.
            for path in [p for p in web.shell.ASSETS if p.endswith(".png")]:
                code, hdrs, raw = _get_bytes(base + path)
                results.check(
                    "%s is a real, complete PNG" % path,
                    code == 200 and raw[:8] == b"\x89PNG\r\n\x1a\n"
                    and raw[-12:-8] == b"IEND",
                    "code=%s first8=%r last12=%r -- iOS will not accept an SVG "
                    "here, and a truncated file falls back to a screenshot "
                    "without saying so" % (code, raw[:8], raw[-12:]))
        finally:
            httpd.shutdown()
            httpd.server_close()

        html = d.html()
        results.check(
            "the page links the shell and the iOS home-screen tags",
            "rel=manifest" in html and "apple-touch-icon" in html
            and "apple-mobile-web-app-capable" in html,
            "the head is missing one of the tags iOS needs to install it")
        results.check(
            "there is no service worker, deliberately",
            "serviceWorker" not in html and "sw.js" not in html,
            "a service worker appeared -- iOS installs without one, so it would "
            "exist only to cache, which is the one thing no-store forbids")
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
```

Add `import web.shell` — the suite already imports `web`, so reference it as `web.shell`; add `import shell` to the imports at :45-49 to be safe.

Register the test in `TESTS`.

- [ ] **Step 2: Run the test to verify it fails**

Run: `./test.sh dashboard`
Expected: FAIL with `ModuleNotFoundError: No module named 'shell'` from the import, then attribute errors.

- [ ] **Step 3: Author the two icons, once**

§6 is explicit that **the icons are committed repo assets and are not generated at
runtime** — an image-generating step in the request path would be code to
maintain for a file that never changes. That is what the snippet below respects:
it is an **authoring step**, run once from the repo root, whose output is two
files that get committed. Nothing of it stays in the tree, nothing runs at
runtime, and no generator is imported by anything.

**If you have two square PNGs to hand, drop them in as
`app/icons/icon-180.png` and `app/icons/icon-512.png` and skip the snippet
entirely** — that is the better outcome, and the rest of this task only cares
that the files exist, are PNG, and are the right size.

```bash
mkdir -p app/icons && python3 - <<'PY'
import struct, zlib

BG = (0x0e, 0x12, 0x16)
SEGS = [(0x3f, 0xb9, 0x50), (0x3f, 0xb9, 0x50), (0x3f, 0xb9, 0x50),
        (0xe3, 0xb3, 0x41), (0xf8, 0x51, 0x49)]

def png(size, path):
    """A square icon: the tally-strip mark on the page's own ground.

    Square, not rounded: iOS applies its own corner mask and a pre-rounded
    icon gets rounded twice.
    """
    w = size
    seg_w = max(2, round(w * 0.122))
    seg_h = seg_w
    gap = max(1, round(w * 0.033))
    total = len(SEGS) * seg_w + (len(SEGS) - 1) * gap
    x0 = (w - total) // 2
    y0 = (w - seg_h) // 2
    rows = []
    for y in range(w):
        row = bytearray([0])
        for x in range(w):
            px = BG
            if y0 <= y < y0 + seg_h:
                for i, col in enumerate(SEGS):
                    sx = x0 + i * (seg_w + gap)
                    if sx <= x < sx + seg_w:
                        px = col
                        break
            row += bytes(px)
        rows.append(bytes(row))
    raw = b"".join(rows)

    def chunk(tag, data):
        return (struct.pack(">I", len(data)) + tag + data
                + struct.pack(">I", zlib.crc32(tag + data) & 0xffffffff))

    out = (b"\x89PNG\r\n\x1a\n"
           + chunk(b"IHDR", struct.pack(">IIBBBBB", w, w, 8, 2, 0, 0, 0))
           + chunk(b"IDAT", zlib.compress(raw, 9))
           + chunk(b"IEND", b""))
    with open(path, "wb") as fh:
        fh.write(out)
    print("%s %d bytes" % (path, len(out)))

png(180, "app/icons/icon-180.png")
png(512, "app/icons/icon-512.png")
PY
```

Expected: two files written, both a few hundred to a few thousand bytes.

- [ ] **Step 4: Write `app/shell.py`**

```python
"""The app shell: the manifest and the icons, and the ONE caching exception.

WHY THIS FILE EXISTS SEPARATELY FROM web.py, AND WHY IT IS NOT A LOOPHOLE

`web.py`'s whole contract is that nothing in the response path is cacheable: a
cached 200 served while the collector is dead is a false GREEN, and that page is
the only dead-man switch there is. So the header is the mechanism.

That rule is about OBSERVATIONS. An icon is not an observation -- it is a
constant of the image, it says nothing about the fleet, and serving it from a
cache cannot make anyone believe something untrue. Keeping the exception in its
own module, with its own name, is what stops it from spreading: there is exactly
one place that may answer with a cache header, and this is it.

WHAT IS NOT HERE: A SERVICE WORKER. iOS installs to the home screen without one,
so a service worker would exist only to cache -- and the only thing worth
caching on this page is the thing that must never be cached.
"""

import json
import os

# A day. The icons change only when the image does, and a redeploy that renames
# them gets a new URL in the manifest rather than a stale body.
CACHE_CONTROL = "public, max-age=86400"

_HERE = os.path.dirname(os.path.abspath(__file__))

# url path -> (file beside this module, content type). Adding an entry here is
# adding a cacheable response, so it is deliberately one line per asset and
# deliberately a short list.
ASSETS = {
    "/manifest.webmanifest": (None, "application/manifest+json"),
    "/icons/icon-180.png": ("icons/icon-180.png", "image/png"),
    "/icons/icon-512.png": ("icons/icon-512.png", "image/png"),
}


def read(relpath):
    """The bytes of a shell asset. Raises OSError, which the caller renders."""
    with open(os.path.join(_HERE, relpath), "rb") as fh:
        return fh.read()


def manifest():
    """The web app manifest.

    The theme colour and the background match the page's own --bg. They are two
    literals in two files on purpose: this one is a constant of the image and
    the other is the stylesheet's own token, and a shared import between them
    would couple the shell to the renderer for one hex value.
    """
    return json.dumps({
        "name": "sentinel",
        "short_name": "sentinel",
        "start_url": "/",
        "scope": "/",
        "display": "standalone",
        "background_color": "#0e1216",
        "theme_color": "#0e1216",
        "icons": [
            {"src": "/icons/icon-180.png", "sizes": "180x180",
             "type": "image/png"},
            {"src": "/icons/icon-512.png", "sizes": "512x512",
             "type": "image/png", "purpose": "any maskable"},
        ],
    }, indent=1)


def asset(relpath):
    """The body and content type for one asset, manifest included.

    Returns (bytes, ctype). Raises OSError for a file the image does not carry,
    which must render as a 500 rather than as an empty 200.
    """
    rel, ctype = ASSETS[relpath]
    if rel is None:
        return manifest().encode("utf-8"), ctype
    return read(rel), ctype
```

- [ ] **Step 5: Route it, and add the second sender**

In `app/web.py`, add `import shell` beside the other imports (:45-47). Change `_send` to take the cache header as an argument, defaulting to the observation rule:

```python
    def _send(self, code, body, ctype, cache=None):
        raw = body if isinstance(body, bytes) else body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        # THE DEAD-MAN SWITCH DEPENDS ON THESE LINES, and `cache` is the ONE
        # documented way past them: the app shell is a constant of the image and
        # not an observation, so an icon may be cached and nothing that carries
        # a reading may be. See shell.py.
        self.send_header("Cache-Control", cache or OBSERVATION_CACHE)
        if cache is None:
            # HTTP/1.0 belt-and-braces, for the observation rule only. With
            # Cache-Control present these are ignored (RFC 7234 s5.4), so
            # sending them beside the shell's max-age=86400 would put a
            # contradiction in the response that changes nothing -- and a
            # response nobody can read at a glance is one people stop reading.
            self.send_header("Pragma", "no-cache")
            self.send_header("Expires", "0")
        self.end_headers()
        try:
            self.wfile.write(raw)
        except (BrokenPipeError, ConnectionResetError):
            # KEPT FROM THE ORIGINAL, and not decoration: an iOS client that
            # backgrounds mid-poll resets the connection, and losing the whole
            # dashboard thread to a reset would take the dead-man switch with it.
            pass
```

with, at module level beside `API_VERSION`:

```python
# The observation rule, named so that the shell exception is visibly an
# exception rather than a second literal that happens to differ.
OBSERVATION_CACHE = "no-store, no-cache, must-revalidate, max-age=0"
```

and in `do_GET`, between `cfg = self.cfg` (:723) and the `try:` that opens the
store (:724) — **before** the database is touched, deliberately:

```python
        # THE SHELL IS ANSWERED BEFORE THE STORE IS OPENED. It is a constant of
        # the image, so it must still serve when the database cannot be opened
        # -- the icon is what makes the installed app look like an app, and that
        # does not stop being true during an outage.
        if path in shell.ASSETS:
            try:
                body, ctype = shell.asset(path)
            except OSError as exc:                    # noqa: BLE001 - rendered
                self._send(500, "shell asset %s is missing from the image: %s\n"
                           % (path, exc), "text/plain; charset=utf-8")
                return
            self._send(200, body, ctype, cache=shell.CACHE_CONTROL)
            return
```

Note the `Pragma`/`Expires` headers: they are harmless on the shell (they only
apply when `Cache-Control` is absent or unparseable) and keeping them means one
sender, not two.

- [ ] **Step 6: Add the head tags**

Replace the first three lines of `render_html` (:527-529) with:

```python
    a("<!doctype html><meta charset=utf-8>")
    a("<meta name=viewport content='width=device-width,initial-scale=1,"
      "viewport-fit=cover'>")
    a("<title>sentinel</title>")
    a("<link rel=manifest href=/manifest.webmanifest>")
    a("<link rel=apple-touch-icon href=/icons/icon-180.png>")
    a("<meta name=apple-mobile-web-app-capable content=yes>")
    a("<meta name=apple-mobile-web-app-title content=sentinel>")
    a("<meta name=apple-mobile-web-app-status-bar-style content=black-translucent>")
    a("<meta name=theme-color content='#0e1216'>")
    a("<style>%s</style>" % CSS)
```

- [ ] **Step 7: Run the test to verify it passes**

Run: `./test.sh dashboard`
Expected: PASS, 0 failed.

- [ ] **Step 8: Mutation-test the exception's boundary**

In a scratch copy, pass `cache=shell.CACHE_CONTROL` for the `/api/status.json` route as well and run `./test.sh dashboard`. Expected: FAIL on `the status API did NOT gain a cache header` and on the existing `test_nothing_is_cached`. Revert.

- [ ] **Step 9: Run the whole suite**

Run: `./test.sh`
Expected: 0 failed.

- [ ] **Step 10: Commit**

```bash
git add app/shell.py app/icons app/web.py tests/test_dashboard.py
git commit -m "Add the app shell, and name the one caching exception

The no-store contract is about observations: a cached 200 while the
collector is dead is a false GREEN. An icon is not an observation -- it
is a constant of the image, it says nothing about the fleet, and serving
it from a cache cannot make anyone believe something untrue. Putting the
exception in its own module with its own name is what stops it from
spreading, and a test asserts every observation path still refuses to
cache so the exception cannot grow.

No service worker. iOS installs without one, so it would exist only to
cache, and the only thing here worth caching is the thing that must
never be cached. The shell is answered before the store is opened, so
the installed app still looks like an app during an outage.

Co-Authored-By: Claude Code <noreply@anthropic.com>"
```

---

## Task 7: The reactive layer

**Files:**
- Modify: `app/web.py` — add `REFRESH_JS` beside `CSS`; a `<div id=live>` wrapper in `render_html`; a script tag before `</div>`
- Test: `tests/test_dashboard.py`

**Interfaces:**
- Produces: `web.REFRESH_JS -> str`; the document must contain `<div id=live>` wrapping everything the script replaces, and a `<script id=refresh>`
- Consumes: `state["interval"]` for the poll period, and the `id='sec-<sid>'` ids Task 4 emits — the script restores which sections were open **by id**, so those two tasks are coupled by that string. Renaming an id on either side stops the restore working, silently; Task 4's test and this task's test together are what catches it.

- [ ] **Step 1: Write the failing test**

```python
# ---------------------------------------------------------------------------
# 14. The reactive layer, and the seam it depends on
# ---------------------------------------------------------------------------


def test_the_refresh_script_has_the_hooks_it_looks_for(results):
    """The ids are an integration seam, and a rename would fail silently."""
    tmpdir = tempfile.mkdtemp()
    try:
        d = Dash(tmpdir)
        d.epoch()
        html = d.html()
        results.check(
            "the page carries the container the script swaps",
            "id=live" in html or 'id="live"' in html,
            "the script replaces #live, and the renderer does not emit it -- "
            "the page would simply stop updating, with no error anywhere")
        results.check(
            "the page carries the script",
            "id=refresh" in html or 'id="refresh"' in html,
            "no refresh script on the page")
        results.check(
            "the script re-fetches the SERVER's render, not a client-side one",
            "fetch('/')" in html or 'fetch("/")' in html,
            "the script does not re-fetch the page -- a client-side renderer "
            "would be a second render_html to keep identical forever")
        results.check(
            "a failed fetch is rendered as UNKNOWN, never as the stale page",
            "cannot reach the monitor" in html,
            "the script has no failure branch, so a page that can no longer "
            "check would go on asserting health -- which is the false green "
            "this whole design exists to prevent")
        results.check(
            "the poll period comes from the configured interval",
            ("%d" % (d.cfg.interval * 1000)) in html,
            "the script does not use the configured interval")
        results.check(
            "polling stops when the page is hidden",
            "visibilitychange" in html,
            "a phone in a pocket would poll all night")
        # THE SEAM THAT WOULD FAIL SILENTLY. The script restores disclosure by
        # id, so the renderer's ids and the script's lookup must agree; if
        # either is renamed the page keeps working and quietly loses the state.
        results.check(
            "the script restores disclosure by the ids the renderer emits",
            "d.id" in html and "id='sec-checks'" in html
            and "d.open = true" in html,
            "the script does not snapshot and restore by id, so an open section "
            "snaps shut every interval -- or reopens the wrong one")
        results.check(
            "the scroll position survives the swap",
            "scrollY" in html and "scrollTo" in html,
            "the page jumps to the top every interval, so reading anything "
            "below the fold is impossible")
        results.check(
            "reduced motion is respected",
            "prefers-reduced-motion" in html,
            "the page animates for a reader who asked it not to")
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
```

Register it in `TESTS`.

- [ ] **Step 2: Run the test to verify it fails**

Run: `./test.sh dashboard`
Expected: FAIL on every check — no script exists yet.

- [ ] **Step 3: Implement**

Add beside `CSS` in `app/web.py`:

```python
# THE REACTIVE LAYER, AND WHY IT RE-FETCHES THE PAGE
#
# The obvious implementation is a client-side renderer that fetches
# /api/status.json and patches the tiles. It is also a SECOND render_html that
# has to be kept identical to the first one forever, which is item 7's shape and
# has already cost this project twice. So the script fetches `/` and swaps the
# DOM: the server stays the only thing that knows how to draw this page.
#
# TWO FAILURE MODES ARE DESIGNED IN, because both are the stale-sample defect in
# new clothes. If the fetch fails, the banner flips to UNKNOWN naming the
# monitor as unreachable -- a page that has stopped being able to check must not
# go on asserting health. If the swap brings a stale page, that page carries its
# own red banner and arrives stating its own age.
REFRESH_JS = """
(function () {
  var el = document.getElementById('live');
  var ms = %d;
  var timer = null;

  function snapshot() {
    // BY ID, NOT BY POSITION. The incidents section appears and disappears as
    // incidents open and resolve, so an index shifts and the wrong section
    // reopens -- a bug that only shows up on the one day it matters.
    var ids = [];
    el.querySelectorAll('details').forEach(function (d) {
      if (d.open && d.id) { ids.push(d.id); }
    });
    return ids;
  }

  function restore(ids) {
    ids.forEach(function (id) {
      var d = el.querySelector('#' + CSS.escape(id));
      if (d) { d.open = true; }
    });
  }

  function unreachable() {
    var b = el.querySelector('.band');
    if (b) {
      b.className = 'band unknown';
      b.innerHTML = '<div class=bst>UNKNOWN</div><div class=bwhy>' +
                    'cannot reach the monitor, so this page cannot say ' +
                    'anything about the fleet</div>';
    }
  }

  function tick() {
    if (document.hidden) { return; }
    fetch('/', {cache: 'no-store'}).then(function (r) {
      if (!r.ok) { throw new Error('http ' + r.status); }
      return r.text();
    }).then(function (text) {
      var doc = new DOMParser().parseFromString(text, 'text/html');
      var fresh = doc.getElementById('live');
      if (!fresh) { throw new Error('no #live in the response'); }
      var prev = snapshot();
      var y = window.scrollY;
      el.innerHTML = fresh.innerHTML;
      restore(prev);
      window.scrollTo(0, y);
    }).catch(unreachable);
  }

  function arm() {
    if (timer) { clearInterval(timer); }
    timer = document.hidden ? null : setInterval(tick, ms);
  }

  document.addEventListener('visibilitychange', function () {
    if (!document.hidden) { tick(); }
    arm();
  });
  arm();
})();
"""
```

- [ ] **Step 4: Wrap the document and emit the script**

In `render_html`, change the opening wrapper so everything after the `<div class=wrap>`'s header is inside `<div id=live>`:

```python
    a("<div class=wrap>")
    a("<div id=live>")
```

and close it after the last section, before the closing `</div>` of `.wrap`:

```python
    a("</div>")                                   # #live
    a("<script id=refresh>%s</script>" % (REFRESH_JS % (cfg.interval * 1000)))
    a("</div>")                                   # .wrap
```

The header (`<h1>`, subtitle) stays outside `#live` so it never flickers.

- [ ] **Step 5: Run the test to verify it passes**

Run: `./test.sh dashboard`
Expected: PASS, 0 failed.

- [ ] **Step 6: Mutation-test the failure branch**

In a scratch copy, delete `unreachable()`'s call — change `.catch(unreachable)` to `.catch(function () {})` — and run `./test.sh dashboard`. Expected: FAIL on `a failed fetch is rendered as UNKNOWN, never as the stale page`. Revert.

- [ ] **Step 7: Check it by hand before trusting the tests**

The suite cannot run this script. On the Mac, with the container reachable:

```bash
# the page loads and the script is present
curl -s http://198.51.100.11:8787/ | grep -c "id=live\|id=refresh"
```

Then open the page in a browser, click a `<details>` open, and confirm it is
still open after two intervals. Then stop the container and confirm the band
flips to UNKNOWN rather than staying green. **This step is not optional** — the
offline suite can only assert the script's hooks exist, which is a real guard
against a silent rename but not a substitute for watching it work.

- [ ] **Step 8: Run the whole suite**

Run: `./test.sh`
Expected: 0 failed.

- [ ] **Step 9: Commit**

```bash
git add app/web.py tests/test_dashboard.py
git commit -m "Make the page update itself without a second renderer

The obvious implementation patches tiles from /api/status.json, and it
is also a second render_html to keep identical to the first forever --
item 7's shape, which has already cost this project twice. So the script
re-fetches / and swaps the DOM and the server stays the only thing that
knows how to draw the page.

Both failure modes are handled because both are the stale-sample defect
in new clothes: a failed fetch flips the band to UNKNOWN naming the
monitor as unreachable, so a page that can no longer check does not go
on asserting health. Polling stops when the page is hidden, open
sections survive the swap, and reduced motion is respected.

The suite asserts the ids the script depends on, because a rename would
otherwise stop the page updating with no error anywhere. It cannot run
the script, which is stated in the test rather than papered over.

Co-Authored-By: Claude Code <noreply@anthropic.com>"
```

---

## Task 8: The publishing stack

A separate stack. Sentinel's `deploy.sh` never ships it.

**Files:**
- Create: `proxy/compose.yml`
- Create: `proxy/authelia/configuration.yml`, `proxy/authelia/users.yml`
- Create: `docs/publishing.md`
- Modify: `deploy.sh` — add `proxy/` to the rsync excludes
- Test: `tests/test_proxy_config.py`, registered in `tests/run_all.py`

**Interfaces:**
- Produces: nothing consumed by the other tasks

- [ ] **Step 1: Write the failing test**

Create `tests/test_proxy_config.py`:

```python
"""The publishing stack's config: the two deliberate holes, and nothing else.

THIS SUITE DOES NOT RUN THE STACK. It cannot -- the suite is offline and the
stack is three containers on a NAS. What it guards is the pair of access-control
decisions that are EASY TO TIDY AWAY AND EXPENSIVE TO LOSE:

  * /healthz stays unauthenticated, so a broken login can be told apart from a
    dead monitor. Close that hole and the one question this design exists to
    keep answerable stops being answerable.
  * /api/* bypasses from the LAN only, so the curl integration the architecture
    doc documents keeps working. Break it and every script silently starts
    reading an HTML login page instead of JSON.

A text assertion is weaker than a behavioural one and this says so; what it can
do is fail loudly when the rule is deleted, which is the failure mode that
matters here.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import Results                      # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
MONITOR = os.path.dirname(HERE)


def _read(*parts):
    with open(os.path.join(MONITOR, *parts)) as fh:
        return fh.read()


def test_the_proxy_keeps_its_two_deliberate_holes(results):
    authelia = _read("proxy", "authelia", "configuration.yml")
    compose = _read("proxy", "compose.yml")

    results.check(
        "the health probe bypasses authentication from anywhere",
        "^/healthz$" in authelia and "bypass" in authelia,
        "the /healthz bypass is gone -- if Authelia is down the operator is "
        "locked out, and this is the only way to tell a broken login from a "
        "dead monitor")
    results.check(
        "the API bypasses authentication only from the LAN",
        "198.51.100.0/24" in authelia and "api" in authelia,
        "the /api bypass is gone or is not scoped to the LAN -- the "
        "architecture doc publishes `curl .../api/status.json` as the way an "
        "integrator reads the contract")
    results.check(
        "everything else needs two factors",
        "two_factor" in authelia,
        "no rule requires two factors, so the passkey gate is not in force")
    results.check(
        "the proxy and the auth service are both declared",
        "nginx-proxy-manager" in compose and "authelia" in compose,
        "one of the two services is missing from the compose file")
    results.check(
        "the proxy manager's own admin interface is not published",
        "81:81" not in compose and "443:443" not in compose,
        "the admin interface or 443 is published on a host port -- the control "
        "plane for the edge does not belong on the edge")
    results.check(
        "sentinel's own deploy does not ship this stack",
        "proxy" in _read("deploy.sh"),
        "deploy.sh does not exclude proxy/, so a sentinel deploy would rsync a "
        "second stack's config onto the NAS")
```

Add to `tests/run_all.py`:

```python
import test_proxy_config as proxy_tests             # noqa: E402
```

and to `SUITES`:

```python
    ("proxy/ -- the publishing stack's access rules (offline, text-level)",
     proxy_tests.TESTS),
```

and at the bottom of the new file:

```python
TESTS = (test_the_proxy_keeps_its_two_deliberate_holes,)
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `./test.sh proxy`
Expected: FAIL with `FileNotFoundError: .../proxy/authelia/configuration.yml`.

- [ ] **Step 3: Write `proxy/compose.yml`**

```yaml
# The publishing stack: nginx-proxy-manager terminating TLS, Authelia gating it.
#
# THIS IS NOT SENTINEL'S STACK AND SENTINEL'S DEPLOY DOES NOT SHIP IT. It is a
# separate compose file for a separate concern -- reachability -- and sentinel's
# container is unchanged by it: it still holds its own macvlan address and still
# publishes no host port. The proxy reaches it container-to-container.
#
# ON THE SAME eth1 MACVLAN AS EVERYTHING ELSE ON THE NAS, because that is how
# the other eleven services there are addressed and because it is the only way
# to reach 198.51.100.11:8787 -- sentinel is not on the host's own interface.
services:

  nginx-proxy-manager:
    image: jc21/nginx-proxy-manager:2.12.3
    container_name: npm
    restart: unless-stopped
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
    # NO `ports:` ON PURPOSE. NPM publishes nothing on the host: the LAN
    # reaches it at its own macvlan address, and the internet reaches it through
    # the router's port-forward to that address. A host port would put the
    # admin interface on the NAS's own interface as well.
    volumes:
      - ${PROXY_DATA:-/share/CACHEDEV1_DATA/Programs/sentinel/proxy}/data:/data
      - ${PROXY_DATA:-/share/CACHEDEV1_DATA/Programs/sentinel/proxy}/letsencrypt:/etc/letsencrypt
    networks:
      eth1:
        ipv4_address: ${PROXY_IPV4:-198.51.100.20}

  authelia:
    image: authelia/authelia:4.38.10
    container_name: authelia
    restart: unless-stopped
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
    volumes:
      - ./authelia:/config:ro
    environment:
      - TZ=${TZ:-Europe/Helsinki}
      # DOMAIN is substituted into the Authelia config, which needs it for the
      # cookie domain and the WebAuthn RP id. Without it here the config's
      # `${DOMAIN}` resolves to nothing and every passkey is bound to an empty
      # hostname.
      - DOMAIN=${DOMAIN:?set this in .env}
      # THE THREE SECRETS ARRIVE BY ENV CONVENTION, not by explicit reference:
      # Authelia reads AUTHELIA_SESSION_SECRET, AUTHELIA_STORAGE_ENCRYPTION_KEY
      # and AUTHELIA_IDENTITY_VALIDATION_RESET_PASSWORD_JWT_SECRET by name, so
      # the config file neither holds them nor mentions them. That is one fewer
      # place for a secret to be written down.
      - AUTHELIA_SESSION_SECRET=${AUTHELIA_SESSION_SECRET:?set this in .env}
      - AUTHELIA_IDENTITY_VALIDATION_RESET_PASSWORD_JWT_SECRET=${AUTHELIA_IDENTITY_VALIDATION_RESET_PASSWORD_JWT_SECRET:?set this in .env}
      - AUTHELIA_STORAGE_ENCRYPTION_KEY=${AUTHELIA_STORAGE_ENCRYPTION_KEY:?set this in .env}
    networks:
      eth1:
        ipv4_address: ${AUTHELIA_IPV4:-198.51.100.21}

networks:
  eth1:
    external: true
    name: eth1
```

- [ ] **Step 4: Write `proxy/authelia/configuration.yml`**

```yaml
# Authelia: one user, passkeys, and the two access rules that are deliberate.
#
# WHY EACH HOLE EXISTS IS IN docs/publishing.md. The short version: /healthz
# must stay open so a broken login can be told apart from a dead monitor, and
# /api/* must bypass from the LAN so the documented curl integration keeps
# reading JSON instead of an HTML login page. Neither is an oversight, and
# tests/test_proxy_config.py fails if either is deleted.

theme: dark

server:
  host: 0.0.0.0
  port: 9091

log:
  level: info

# Sessions in memory: this is a single instance, so there is nothing to share
# them with and no Redis to run on a NAS that already has sixteen containers.
session:
  name: authelia_session
  expiration: 1d
  inactivity: 12h
  cookies:
    - domain: ${DOMAIN}
      authelia_url: https://${DOMAIN}
      default_redirection_url: https://${DOMAIN}

storage:
  # A local SQLite file, on the container's own filesystem. Authelia needs a
  # store for its WebAuthn device registrations, and one file beside the config
  # is smaller than a second service.
  local:
    path: /config/db.sqlite3

notifier:
  # No SMTP: there is one user and no password reset flow to notify about. The
  # passkeys ARE the second factor, so a mail path would be unused surface.
  filesystem:
    filename: /config/notifications.txt

authentication_backend:
  file:
    path: /config/users.yml
    password:
      algorithm: argon2id

access_control:
  default_policy: deny
  rules:
    # THE ONE UNPROTECTED ENDPOINT, AND IT IS DELIBERATE.
    #
    # If this service is down the operator is locked out, and the only question
    # left is whether the LOGIN is broken or the MONITOR is dead -- the two
    # failures this whole design exists to keep apart. One line of text, naming
    # whether the collector is fresh, answers it without a session.
    #
    # It discloses one word about the fleet. That is the trade, and it is made
    # in the open rather than by accident.
    - domain: ${DOMAIN}
      resources:
        - "^/healthz$"
      policy: bypass

    # THE LAN KEEPS ITS SCRIPTS. docs/architecture.md publishes
    # `curl .../api/status.json` as the way an integrator reads the contract,
    # and the point of a versioned document is that a script reads it. An
    # interactive session gate would break every script that uses it -- so the
    # API bypasses FROM THE LAN ONLY. From the internet it is two_factor like
    # everything else; the public hostname gets no weaker a door.
    #
    # THE TWO PATHS ARE NAMED, NOT MATCHED BY WILDCARD. `^/api/[a-z]+\.json$`
    # would be shorter and would silently open any /api/*.json that is ever
    # added -- a door that widens without anyone deciding it should. The rule
    # names exactly what §7.1 approves.
    - domain: ${DOMAIN}
      resources:
        - "^/api/status\\.json$"
        - "^/api/state\\.json$"
      networks:
        - 198.51.100.0/24
      policy: bypass

    # Everything else, from anywhere.
    - domain: ${DOMAIN}
      policy: two_factor

regulation:
  max_retries: 3
  find_time: 2m
  ban_time: 5m

totp:
  issuer: sentinel

webauthn:
  display_name: sentinel
  attestation_conveyance_preference: indirect
  # The RP id is the bare hostname, so a passkey is bound to the domain and not
  # to a path -- iOS shows it in Keychain under this name.
  rp_id: ${DOMAIN}
```

- [ ] **Step 5: Write `proxy/authelia/users.yml`**

```yaml
# One user. The hash is argon2id and is generated ON THE NAS with:
#
#   docker run --rm authelia/authelia:4.38.10 \
#     authelia crypto hash generate argon2 --password 'the password you chose'
#
# It is deliberately not in this repo. This file is a TEMPLATE that the operator
# copies to the NAS and fills in, exactly as .env.example is -- a real hash in
# version control is a credential in version control, and this tree is a git
# repo.
users:
  operator:
    displayname: Operator
    # REPLACE THIS with the output of the command above.
    password: "$argon2id$v=19$m=65536,t=3,p=4$REPLACE$REPLACE"
    email: operator@example.invalid
    groups:
      - admins
```

- [ ] **Step 6: Run the test to verify it passes**

Run: `./test.sh proxy`
Expected: PASS, 0 failed.

- [ ] **Step 7: Add the rsync exclusion**

In `deploy.sh`, find the rsync `--exclude` list (it excludes `data/`, `.env`,
`ssh/`, `.git/`, `docs/`, `tests/`) and add `--exclude 'proxy/'` with a one-line
comment: the publishing stack is a separate concern and a sentinel deploy must
not ship a second stack's config to the NAS.

- [ ] **Step 8: Write `docs/publishing.md`**

The runbook. It must state, in this order:

1. **Prerequisite:** a DDNS hostname resolving to the home IP, and a DNS provider
   API token for the DNS-01 challenge. Port 80 is never opened.
2. **Deploy:** copy `proxy/` to the NAS, generate the three `AUTHELIA_*` secrets
   and the password hash on the NAS, fill `users.yml`, `docker compose -f
   proxy/compose.yml up -d`.
3. **NPM:** add a proxy host for the hostname → `198.51.100.11:8787`, with a
   Let's Encrypt DNS-01 certificate, and forward-auth pointed at
   `http://198.51.100.21:9091/api/verify?rd=https://${DOMAIN}`.
4. **Enroll the passkey:** sign in once, register Face ID, then Add to Home
   Screen. The installed app opens standalone and the passkey is what the phone
   offers.
5. **Verify the two holes:** `curl -s https://<hostname>/healthz` returns the
   one-line collector state **without** a session, and
   `curl -s http://198.51.100.11:8787/api/status.json` from the NAS still returns
   JSON.
6. **The accepted risk, stated rather than buried:** the public hostname is a new
   dependency in the path of the only dead-man switch. If this stack fails, the
   page is unreachable and, from the phone, indistinguishable from a dead
   collector — which is what the `/healthz` bypass mitigates and does not fix.

- [ ] **Step 9: Run the whole suite**

Run: `./test.sh`
Expected: 0 failed, across six suites.

- [ ] **Step 10: Commit**

```bash
git add proxy docs/publishing.md deploy.sh tests/test_proxy_config.py tests/run_all.py
git commit -m "Add the publishing stack, with its two deliberate holes

nginx-proxy-manager terminates TLS by DNS-01 so port 80 never opens,
Authelia gates it with passkeys, and sessions are in memory because
there is one user and no second instance to share them with.

Two access rules are deliberate and a test fails if either is deleted.
/healthz stays unauthenticated, because if Authelia is down the operator
is locked out and the only question left is whether the login is broken
or the monitor is dead -- the two failures this design exists to keep
apart. /api/* bypasses from the LAN only, because the architecture doc
publishes curl against it and a session gate would break every script
that reads the contract.

The stack is separate from sentinel's own and its deploy excludes it.
The accepted risk -- that the proxy is now a dependency in the path of
the only dead-man switch -- is written down rather than buried.

Co-Authored-By: Claude Code <noreply@anthropic.com>"
```

---

## Final verification

- [ ] **Run the whole suite**: `./test.sh` → 0 failed.
- [ ] **Deploy and look at it on the phone**: `./deploy.sh`, then open the
      dashboard, Add to Home Screen, and confirm it opens standalone with the
      icon.
- [ ] **Confirm the honest paths by hand**, since the suite cannot: stop the
      collector and watch the hero go red and the band go UNKNOWN; open a
      `<details>`, wait two intervals, confirm it is still open; kill the
      container and confirm the band reads UNKNOWN rather than staying green.
- [ ] **Confirm nothing regressed in the container log**: `./deploy.sh --status`
      and `./deploy.sh --logs`, expecting 0 errors per epoch and no new
      `log_parse_failures`.
