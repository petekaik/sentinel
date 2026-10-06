"""Dashboard contract tests. NO NETWORK to the fleet -- asserted by the server.

The dashboard is the ONLY dead-man switch this design has (no push notification
was chosen), so its contract is not "looks reasonable" but "is incapable of
showing a clean fleet while measuring nothing". That is a property, and a
property needs a test that can FAIL -- which is why several checks below assert
the EXISTENCE of the healthy path as well as the loudness of the unhealthy one.
A page that renders everything grey passes "UNKNOWN is never green" trivially,
and a test suite that only asserted that would go green on a dashboard that had
been reduced to a stub. So: `test_unknown_is_never_green` also proves that a
stored OK renders green, and `test_no_result_renders_unknown` also proves that a
stored result renders ITS OWN verdict. Item 26: a test that cannot fail is worse
than no test.

THE STORE IS WRITTEN BY DIFFERENT CODE THAN THE PAGE READS. These tests use
`store.record_check` / `record_collector_run` directly rather than running
`collect.py`, so an agreement between writer and reader here is not a
restatement of one rule typed twice (item 45).

THE ONE SERVER THAT BINDS A PORT BINDS LOOPBACK ONLY. `web.serve()` binds
0.0.0.0; these tests must not, because the machine running them is on the fleet's
own LAN and an exposed copy of a monitoring page is not something a test should
be able to create by accident. Each server is a fresh `web.Handler` subclass
bound to 127.0.0.1 on port 0, and the loopback address is ASSERTED rather than
assumed -- the same class of check as everything else here.

Fixtures: none. The dashboard's input is the incident/check tables, and those are
constructed in-process; there is no captured artefact to drift from.
"""

import json
import os
import shutil
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import CHECKS_CONF, Results  # noqa: E402

import checks                 # noqa: E402
import config as config_mod   # noqa: E402
import store                  # noqa: E402
import thresholds             # noqa: E402
import web                    # noqa: E402

CACHE = "no-store, no-cache, must-revalidate, max-age=0"


def make_cfg(db_path, interval=60):
    return config_mod.Config(env={
        "CUBOX_IDS": "cubox-1,cubox-2",
        "MONITOR_DB": db_path,
        "MONITOR_CHECKS": CHECKS_CONF,
        "MONITOR_INTERVAL": str(interval),
    })


class Dash:
    """A store and a config, with no collector in the loop."""

    def __init__(self, tmpdir, interval=60):
        self.cfg = make_cfg(os.path.join(tmpdir, "monitor.sqlite"), interval)
        self.conn = store.connect(self.cfg.db_path)
        store.init(self.conn)
        self.seq = 0

    def epoch(self, age_s=0, errors=0, checks_run=0, note=None):
        """Record one collector_run, optionally backdated by `age_s`."""
        seq = store.next_epoch_seq(self.conn)
        store.record_collector_run(self.conn, seq, 12, checks_run, errors, note)
        if age_s:
            self.conn.execute(
                "UPDATE collector_run SET ts = ? WHERE epoch_seq = ?",
                (time.time() - age_s, seq))
        self.seq = seq
        return seq

    def check(self, target, check_id, status, detail="", seq=None):
        store.record_check(self.conn, seq if seq is not None else self.seq,
                           target, check_id, status, detail)

    def state(self):
        return web.build_state(self.cfg, self.conn)

    def state_at(self, age_s):
        """build_state with an EXPLICIT `now`, `age_s` after the last collection.

        The staleness boundaries are strict comparisons on a difference, so a
        test that backdates a row and then lets the page read the wall clock is
        measuring scheduling jitter rather than the predicate -- a boundary case
        passes or fails on a few milliseconds of Python. Pinning `now` is what
        makes "exactly 3 intervals is NOT stale" a statement about the code.
        """
        # THE NEWEST EPOCH, not MAX(ts). `build_state` reads the last collection
        # by `epoch_seq`, and a backdated history makes the two disagree: the
        # newest epoch carries the SMALLEST ts, so MAX(ts) picks an older row
        # than the one the page renders. Then "age_s after the last collection"
        # is a lie -- an age of 0 would render as the backdate of some earlier
        # epoch, and the bar's arithmetic would measure the gap between two
        # epochs instead of the age the caller asked for.
        #
        # `state["last"]` IS that row, so the selection is REUSED rather than
        # re-typed here: a second copy of the query agrees with any bug in the
        # first, and `MAX(ts)` was exactly that bug.
        ts = self.state()["last"]["ts"]
        return web.build_state(self.cfg, self.conn, now=ts + age_s)

    def html(self):
        return web.render_html(self.state(), self.cfg)


def registry_instances(cfg):
    return checks.expand(checks.registry(*checks.all_modules()), cfg.cubox_ids)


class _Server(ThreadingHTTPServer):
    """A real server, minus one reverse-DNS lookup.

    `HTTPServer.server_bind` calls `socket.getfqdn(host)` to fill `server_name`,
    and on a machine whose resolver does not answer for 127.0.0.1 that call
    BLOCKS -- measured at 35 seconds for the first server here, which is a
    thirty-five-second stall in a suite that otherwise runs in 0.1 s. Only the
    cosmetic `server_name` is affected; the socket, the protocol version, the
    headers and every assertion below are the real thing. `web.serve()` is
    untouched: this is the test's own server class.
    """

    def server_bind(self):
        import socketserver
        socketserver.TCPServer.server_bind(self)
        self.server_name = "127.0.0.1"
        self.server_port = self.server_address[1]


def _serve(cfg):
    """A real HTTP server, on 127.0.0.1 only. Returns (httpd, base_url).

    Per-server subclass rather than setting `web.Handler.cfg`: a class attribute
    on the shared handler would be a shared mutable across servers, and the
    broken-database server below runs with a DIFFERENT config.

    The request log is silenced HERE ONLY. In the container it is the only
    request log there is, and web.py deliberately keeps it; in a test suite it
    buries the PASS/FAIL lines it exists to print.
    """
    handler = type("DashTestHandler", (web.Handler,),
                   {"cfg": cfg, "log_message": lambda *a: None})
    httpd = _Server(("127.0.0.1", 0), handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, "http://127.0.0.1:%d" % httpd.server_address[1]


def _get(url):
    """(code, headers, body). HTTPError is a result here, not an exception."""
    try:
        with urllib.request.urlopen(url, timeout=10) as r:
            return r.status, dict(r.headers), r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode("utf-8", "replace")


# ---------------------------------------------------------------------------
# 1. An empty store must be LOUD
# ---------------------------------------------------------------------------


def test_empty_store_is_loud(results):
    """Never-collected must read as 'knows nothing', never as 'fine'."""
    tmpdir = tempfile.mkdtemp()
    try:
        d = Dash(tmpdir)
        state = d.state()
        html = d.html()

        results.check(
            "a store with no collector_run is 'none', not 'fresh'",
            state["staleness"] == "none" and state["last"] is None,
            "staleness=%r" % state["staleness"])
        results.check(
            "the empty store says NO COLLECTION HAS EVER BEEN RECORDED",
            "NO COLLECTION HAS EVER BEEN RECORDED" in html,
            "the page did not say it. Every other surface on this page can be "
            "empty and look calm; this sentence is the only thing standing "
            "between 'the monitor is dead' and 'the fleet is fine'.")
        results.check(
            "the empty store shows no green banner",
            "banner ok" not in html,
            "a green banner is rendered for a monitor that has never collected")
        results.check(
            "the empty store shows no green tile",
            "tile green" not in html,
            "a tile rendered green from an empty store")

        # The check list comes from the REGISTRY, not from the store, so an empty
        # store still shows every check -- grey, with the reason.
        tiles = len(state["tiles"]) + len(state["others"]) + len(state["informational"])
        results.check(
            "every registered check is on the page even with an empty store",
            tiles >= 60 and len(state["missing"]) == tiles,
            "%d rows, %d missing -- expected the whole registry (64 checks) to be "
            "present and reported missing rather than absent"
            % (tiles, len(state["missing"])))
        results.check(
            "'0 rows' is reported as a row count, not as no problems",
            state["counts"]["tables"]["collector_run"] == 0
            and "collector_run" in html,
            "row counts: %s" % state["counts"]["tables"])
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


# ---------------------------------------------------------------------------
# 2. Staleness degrades the whole page
# ---------------------------------------------------------------------------


def test_stale_says_so_and_cannot_also_be_ok(results):
    """A stale store is RED, and the boundary is where the code says it is."""
    tmpdir = tempfile.mkdtemp()
    try:
        interval = 60
        d = Dash(tmpdir, interval=interval)
        d.epoch()

        for age, want, why in (
                (interval * 1.5, "fresh",
                 "exactly 1.5 intervals is the last fresh poll"),
                (interval * 1.5 + 1, "lagging",
                 "one second past 1.5 intervals is lagging"),
                (interval * web.STALE_INTERVALS, "lagging",
                 "exactly %d intervals is NOT yet stale -- the threshold is a "
                 "strict >, so the boundary poll must not raise the alarm"
                 % web.STALE_INTERVALS),
                (interval * web.STALE_INTERVALS + 1, "stale",
                 "one second past %d intervals is stale" % web.STALE_INTERVALS)):
            got = d.state_at(age)["staleness"]
            results.check(
                "at age %ds the page is %r (%s)" % (age, want, why),
                got == want, "staleness=%r, expected %r" % (got, want))

        # The rendered page, at the state a stopped collector produces.
        d.epoch(age_s=interval * web.STALE_INTERVALS + 1)
        state, html = d.state(), d.html()
        results.check(
            "past %d intervals the page is stale" % web.STALE_INTERVALS,
            state["staleness"] == "stale",
            "staleness=%r" % state["staleness"])
        results.check(
            "the stale page says so in the red banner and says what it means",
            "banner red" in html and "STALE" in html and "AS IT WAS" in html,
            "the stale banner is missing or does not state that the rows below "
            "describe the fleet as it was")
        results.check(
            "a stale page cannot also carry the green banner",
            "banner ok" not in html,
            "both banners are on the page, so a reader skimming for colour sees "
            "green on a monitor that has stopped")
        results.check(
            "the stale page names the number of intervals that count as current",
            "past the %d poll intervals (180s)" % web.STALE_INTERVALS in html,
            "the banner does not say what the threshold is, so the reader cannot "
            "tell a stale page from a wrongly-stale one")
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


# ---------------------------------------------------------------------------
# 3. UNKNOWN is never green -- and OK still is
# ---------------------------------------------------------------------------


def test_unknown_is_never_green(results):
    """Grey is not green, and green still works. Both halves, one test."""
    tmpdir = tempfile.mkdtemp()
    try:
        d = Dash(tmpdir)
        d.epoch()
        targets = [(c.target, c.id) for c in registry_instances(d.cfg)
                   if c.spec and not getattr(c, "informational", False)]
        results.check("the registry has metric checks to colour", len(targets) > 20,
                      "only %d spec-bearing non-informational checks" % len(targets))

        for target, cid in targets:
            d.check(target, cid, store.Status.UNKNOWN,
                    "not observed this epoch (test)")

        state, html = d.state(), d.html()
        tally = web._tally(state)
        results.check(
            "an all-UNKNOWN store tallies ZERO green",
            tally["green"] == 0 and tally["grey"] >= len(targets),
            "tally=%s for %d UNKNOWN checks" % (tally, len(targets)))
        results.check(
            "no tile renders green while every check is UNKNOWN",
            "tile green" not in html,
            "a green tile exists on a page where nothing was observed")
        results.check(
            "the grey verdicts are rendered as grey",
            "pill grey" in html and ">unknown<" in html,
            "the UNKNOWN rows are not rendered as grey pills")
        results.check(
            "grey is not folded into red either",
            tally["red"] == 0 and tally["amber"] == 0,
            "tally=%s -- UNKNOWN must not share a branch with FAIL or WARN, in "
            "either direction" % tally)

        # The contrast, so this test can fail: a stored OK must render GREEN.
        # Without this half, a dashboard that rendered everything grey would pass
        # every assertion above.
        d.epoch()
        for target, cid in targets:
            d.check(target, cid, store.Status.OK, "measured within threshold (test)")
        state, html = d.state(), d.html()
        tally = web._tally(state)
        results.check(
            "a stored OK DOES render green (so the test above can fail)",
            tally["green"] == len(targets) and "tile green" in html,
            "tally=%s for %d OK checks -- if this is zero, the grey assertions "
            "above proved nothing" % (tally, len(targets)))
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


# ---------------------------------------------------------------------------
# 4. A status string the code does not understand
# ---------------------------------------------------------------------------


def test_unrecognised_status_is_grey_not_green(results):
    """An unreadable status must land on UNKNOWN. The tempting fix is OK."""
    tmpdir = tempfile.mkdtemp()
    try:
        d = Dash(tmpdir)
        d.epoch()
        # Something a future version might write, or a hand edit, or a truncated
        # write. `Status("green")` would raise, and a bare except returning OK
        # would turn a corrupt row into a healthy one.
        d.check("storage", "media_volume_used_pct", "green",
                "a status string this build does not know (test)")
        d.check("cubox-1", "mem_available_mb", "OK", "wrong case (test)")

        results.check(
            "an unrecognised status string maps to UNKNOWN",
            web._status("green") is store.Status.UNKNOWN
            and web._status("OK") is store.Status.UNKNOWN
            and web._status(None) is store.Status.UNKNOWN,
            "_status folded an unreadable value onto something other than "
            "UNKNOWN -- and the only dangerous destination is OK")
        html = d.html()
        results.check(
            "the row renders grey and shows the raw string, not a colour",
            "pill grey" in html and ">green<" in html,
            "the corrupt row is not rendered as grey with its raw value visible")
        results.check(
            "no tile renders green off the corrupt status",
            "tile green" not in html,
            "a corrupt status produced a green tile")
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


# ---------------------------------------------------------------------------
# 5. A check that never ran
# ---------------------------------------------------------------------------


def test_no_result_renders_unknown_with_a_reason(results):
    """A check the store has never seen is UNKNOWN, never absent."""
    tmpdir = tempfile.mkdtemp()
    try:
        d = Dash(tmpdir)
        d.epoch()
        d.check("cubox-1", "mem_available_mb", store.Status.OK, "812 MB (test)")

        state = d.state()
        by_id = {(t["target"], t["check_id"]): t for t in state["tiles"]}
        ran = by_id[("cubox-1", "mem_available_mb")]
        never = by_id[("cubox-2", "mem_available_mb")]

        results.check(
            "the check that ran carries its own stored verdict",
            ran["has_result"] and ran["status"] == "ok",
            "cubox-1 mem_available_mb: has_result=%s status=%r (this half exists "
            "so the assertion below is not trivially true)"
            % (ran["has_result"], ran["status"]))
        results.check(
            "the check that never ran is UNKNOWN, not absent",
            never["has_result"] is False and never["status"] == "unknown"
            and "no result is stored" in never["detail"],
            "cubox-2 mem_available_mb: has_result=%s status=%r detail=%r"
            % (never["has_result"], never["status"], never["detail"]))
        html = d.html()
        results.check(
            "the reason is on the page in words",
            "no result is stored for the newest epoch" in html,
            "the page shows the missing check without saying why it is grey")
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


# ---------------------------------------------------------------------------
# 6. Nothing is cached
# ---------------------------------------------------------------------------


def test_nothing_is_cached(results):
    """Every response carries no-store -- through a real server, real headers."""
    tmpdir = tempfile.mkdtemp()
    try:
        d = Dash(tmpdir)
        d.epoch()
        httpd, base = _serve(d.cfg)
        try:
            results.check(
                "the test server is bound to loopback only",
                httpd.server_address[0] == "127.0.0.1",
                "bound to %r -- a test must not expose a page on the LAN"
                % (httpd.server_address,))
            for path, ctype in (("/", "text/html"),
                                ("/api/status.json", "application/json"),
                                ("/api/state.json", "application/json"),
                                ("/healthz", "text/plain"),
                                ("/no/such/path", "text/plain")):
                code, hdrs, body = _get(base + path)
                results.check(
                    "%s carries Cache-Control: no-store" % path,
                    hdrs.get("Cache-Control") == CACHE
                    and hdrs.get("Pragma") == "no-cache"
                    and hdrs.get("Expires") == "0",
                    "Cache-Control=%r Pragma=%r Expires=%r -- a cached 200 while "
                    "the collector is dead is a false GREEN, and this page is the "
                    "only dead-man switch there is"
                    % (hdrs.get("Cache-Control"), hdrs.get("Pragma"),
                       hdrs.get("Expires")))
                results.check(
                    "%s answered with the right shape" % path,
                    hdrs.get("Content-Type", "").startswith(ctype)
                    and (code == 200 or (path == "/no/such/path" and code == 404)),
                    "code=%s content-type=%r" % (code, hdrs.get("Content-Type")))

            code, hdrs, body = _get(base + "/api/state.json")
            try:
                parsed = json.loads(body)
                ok_json = parsed["staleness"] == "fresh"
            except Exception as exc:                      # noqa: BLE001
                ok_json, parsed = False, {"error": str(exc)}
            results.check("the API returns the same state model as the page",
                          ok_json, "staleness=%r" % parsed.get("staleness"))

            # The status API, through the same real socket and real headers. Its
            # `verdict` is the field an integrator would branch on, so it gets
            # the same treatment as everything else here: assert the shape, and
            # assert it is one of the four, not merely present.
            code, hdrs, body = _get(base + "/api/status.json")
            try:
                parsed = json.loads(body)
                ok_status = (parsed["api_version"] == web.API_VERSION
                             and parsed["verdict"] in ("ok", "warn", "fail",
                                                       "unknown"))
            except Exception as exc:                      # noqa: BLE001
                ok_status, parsed = False, {"error": str(exc)}
            results.check(
                "the status API answers over HTTP with a versioned verdict",
                ok_status and code == 200,
                "code=%s parsed=%r" % (code, parsed))
        finally:
            httpd.shutdown()
            httpd.server_close()

        # A database that cannot be opened is 503 with the sentence that says
        # what it is not, and it carries the same no-cache headers -- an error
        # page cached by a proxy would outlive the outage. The path's PARENT is
        # absent, so nothing here can accidentally create the file first.
        broken_cfg = make_cfg(os.path.join(tmpdir, "no-such-dir", "monitor.sqlite"))
        httpd, base = _serve(broken_cfg)
        try:
            code, hdrs, body = _get(base + "/")
            results.check(
                "an unopenable database is 503 and says it is NOT 'no problems'",
                code == 503 and "not 'no problems'" in body
                and "no data at all" in body,
                "code=%s body=%r" % (code, body[:200]))
            results.check(
                "the 503 carries no-store too",
                hdrs.get("Cache-Control") == CACHE,
                "Cache-Control=%r" % hdrs.get("Cache-Control"))
            code, hdrs, body = _get(base + "/api/status.json")
            results.check(
                "an unopenable database is NOT a 200 on the status API",
                code == 503 and "not 'no problems'" in body,
                "code=%s body=%r -- an API that answers 200 with a well-formed "
                "document while it cannot read its own store is a false GREEN "
                "delivered straight to whatever integrates with it"
                % (code, body[:200]))
        finally:
            httpd.shutdown()
            httpd.server_close()
            shutil.rmtree(tmpdir + "-missing", ignore_errors=True)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


# ---------------------------------------------------------------------------
# 7. The rows the registry does not own
# ---------------------------------------------------------------------------


def test_collector_rows_are_visible(results):
    """`host_unreachable` is not a Check class, and must never be dropped."""
    tmpdir = tempfile.mkdtemp()
    try:
        d = Dash(tmpdir)
        d.epoch()
        # EXACTLY what collect.py writes on a sustained outage: no Check class
        # owns this id, so a renderer built only from the registry would lose the
        # single most important row on the fleet.
        d.check("cubox-1", "host_unreachable", store.Status.FAIL,
                "cubox-1 could not be collected for 3 consecutive polls: no route "
                "to host (test)")
        d.check("cubox-1", "journal_capture", store.Status.UNKNOWN,
                "journal cursor not advanced (test)")

        state = d.state()
        extra = {(e["target"], e["check_id"]): e for e in state["extra"]}
        results.check(
            "a collector-emitted row lands in `extra`, marked as the collector's",
            extra.get(("cubox-1", "host_unreachable"), {}).get("from") == "collector",
            "extra rows: %s" % sorted(extra))
        results.check(
            "the collector's FAIL keeps its severity",
            extra.get(("cubox-1", "host_unreachable"), {}).get("status") == "fail",
            "status=%r" % extra.get(("cubox-1", "host_unreachable"), {})
            .get("status"))
        html = d.html()
        results.check(
            "the row and its provenance are both on the page",
            "host_unreachable" in html and "(collector)" in html
            and "journal_capture" in html,
            "the collector's rows are not rendered -- this is the 'we cannot see "
            "cubox-1' row, and losing it is the failure this whole component "
            "exists to prevent")
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


# ---------------------------------------------------------------------------
# 8. Informational is not a health verdict
# ---------------------------------------------------------------------------


def test_informational_rows_carry_no_colour(results):
    """The operator's 'temperature is FYI' ruling, as a machine-checked rule."""
    tmpdir = tempfile.mkdtemp()
    try:
        d = Dash(tmpdir)
        d.epoch()
        info = [(c.target, c.id) for c in registry_instances(d.cfg)
                if getattr(c, "informational", False)]
        results.check(
            "the registry still declares an informational check",
            len(info) >= 2,
            "no check declares `informational` -- the CuBoxes have no active "
            "cooling, temperature is not actionable, and a colour on that row "
            "implies an action that does not exist. If this is intentional, the "
            "ruling has changed and this test is the record of it.")
        # Deliberately recorded as OK: the exclusion must bite even on the
        # verdict that would otherwise be the greenest number on the page. The
        # READING comes from `sample` and the VERDICT from `check_run` -- two
        # tables, which is the point of storing raw observations beside verdicts,
        # so a test that only wrote one of them would be testing half a row.
        for target, cid in info:
            d.check(target, cid, store.Status.OK, "48.2 C (test)")
            store.record_sample(d.conn, d.seq, target, "temperature", 48.2,
                                None, text="48.2 C (test)")

        state = d.state()
        tally = web._tally(state)
        results.check(
            "an OK informational row is not counted as green",
            tally["green"] == 0 and tally["informational"] == len(info),
            "tally=%s with %d informational OK rows" % (tally, len(info)))
        results.check(
            "informational rows are not RAG tiles",
            all(not t["informational"] for t in state["tiles"])
            and len(state["informational"]) == len(info),
            "%d tiles, %d informational" % (len(state["tiles"]),
                                            len(state["informational"])))
        html = d.html()
        results.check(
            "the page says the count is excluded rather than leaving it to be added up",
            "0 green" in html and "informational, no colour assigned" in html,
            "the tally line does not name the excluded count")
        results.check(
            "the informational reading renders with no trailing space",
            ">48.2<" in html,
            "the reading cell is not exactly the value -- a unit-less reading "
            "was rendered as '48.2 ' and every grep for it then misses")
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)



# ---------------------------------------------------------------------------
# 10. A reading is not shown beside a verdict from another epoch
# ---------------------------------------------------------------------------


def test_a_sample_from_an_older_epoch_is_not_shown_as_current(results):
    """The number beside a verdict must come from the epoch that verdict is from.

    MEASURED 2026-10-06, on the live dashboard. `TvhLogSignals` grades the
    tuner-refusal age only when that age is BAD; when it is old it falls through
    to its pairing tests and returns a plain `ok` -- and a check that does not
    grade writes no sample (nothing calls `res.metric`). The page asked for the
    NEWEST sample for the metric regardless of epoch, so a green row read
    `23.795 hours` from a sample ten days older than the verdict beside it, with
    nothing on the page saying how old that number was.

    That is the same failure as a green row over an empty one, wearing a number:
    data-shaped, so nobody questions it. The reading and the verdict are two
    tables -- the point of storing raw observations beside verdicts -- and they
    are only meaningful together when they are the same epoch's.

    Both halves are asserted. A test that only checked "no stale number" would
    pass on a page that had stopped showing numbers at all.
    """
    tmpdir = tempfile.mkdtemp()
    try:
        d = Dash(tmpdir)

        def tile():
            return {(t["target"], t["check_id"]): t
                    for t in d.state()["tiles"]}[("storage", "tvh_log_signals")]

        # Epoch 1: the check GRADED, so it wrote both a verdict and a sample.
        d.epoch()
        d.check("storage", "tvh_log_signals", store.Status.WARN, "23.8 hours")
        store.record_sample(d.conn, d.seq, "storage", "tvh_tuner_refusal_h",
                            23.795, "hours", None)
        results.check(
            "a graded epoch shows the sample written in that same epoch",
            tile()["value"] == 23.795,
            "value=%r -- this half exists so the assertion below cannot pass "
            "trivially on a page that shows no numbers at all"
            % (tile()["value"],))

        # Epoch 2: the same check returns OK WITHOUT grading -- the fall-through
        # path -- so this epoch writes no sample of its own.
        d.epoch()
        d.check("storage", "tvh_log_signals", store.Status.OK, "no live fault")

        t = tile()
        results.check(
            "an epoch that did not grade shows NO reading, not the last one",
            t["status"] == "ok" and t["value"] is None,
            "status=%r value=%r unit=%r -- the tile is showing a sample from an "
            "older epoch beside this epoch's verdict"
            % (t["status"], t["value"], t["unit"]))
        results.check(
            "the page prints the absent reading rather than the stale figure",
            "23.795" not in d.html(),
            "the ten-day-old number is still on the page beside a current verdict")
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

# ---------------------------------------------------------------------------
# 9. The status API -- three-valued, not a boolean
# ---------------------------------------------------------------------------


def test_status_api_is_three_valued(results):
    """The API's verdict must be incapable of saying 'fine' about no data.

    A `{"healthy": true}` flag is the obvious API and it is a lie: `false` cannot
    distinguish "the fleet is broken" from "we cannot see the fleet", which is the
    collapse this project has paid for four times. So every one of the four
    verdicts is asserted reachable -- INCLUDING `ok`, because a test that only
    asserted the grey cases would pass on an endpoint hardcoded to `unknown`.
    """
    tmpdir = tempfile.mkdtemp()
    try:
        interval = 60
        d = Dash(tmpdir, interval=interval)
        targets = [(c.target, c.id) for c in registry_instances(d.cfg)
                   if c.spec and not getattr(c, "informational", False)]

        def all_of(status, detail):
            """A fresh epoch in which every verdict-bearing check says `status`.

            A NEW EPOCH PER STAGE, deliberately: two rows for the same
            (target, check_id) inside one epoch would make the renderer's choice
            between them depend on row order, and this test would then be
            measuring SQLite's return order rather than the verdict logic.
            """
            d.epoch()
            for target, cid in targets:
                d.check(target, cid, status, detail)

        # (a) An empty store. Nothing has ever been collected.
        st = web.build_status(d.cfg, d.conn)
        results.check(
            "an empty store is `unknown`, never `ok`",
            st["verdict"] == "unknown" and st["collector"]["epoch_seq"] is None,
            "verdict=%r reason=%r" % (st["verdict"], st["verdict_reason"]))

        # (b) Fresh and all green -> ok. The contrast half.
        all_of(store.Status.OK, "within threshold (test)")
        st = web.build_status(d.cfg, d.conn)
        results.check(
            "a fresh, all-green fleet IS `ok` (so the grey cases below can fail)",
            st["verdict"] == "ok" and st["counts"]["green"] == len(targets),
            "verdict=%r counts=%s for %d OK checks -- if this is not `ok`, every "
            "assertion about `unknown` in this test proved nothing"
            % (st["verdict"], st["counts"], len(targets)))

        # (c) ONE RED among the green -> fail. Severity is not a vote.
        d.check("cubox-1", "mem_available_mb", store.Status.FAIL,
                "71 MB available (test)")
        st = web.build_status(d.cfg, d.conn)
        results.check(
            "one RED outvotes every green row: the verdict is `fail`",
            st["verdict"] == "fail" and st["counts"]["red"] == 1,
            "verdict=%r counts=%s -- a majority vote would bury a single real "
            "fault behind healthy neighbours" % (st["verdict"], st["counts"]))
        results.check(
            "the failing row is listed in `worst` with its identity and detail",
            any(w["target"] == "cubox-1" and w["check_id"] == "mem_available_mb"
                and w["status"] == "fail" and w["detail"] for w in st["worst"]),
            "worst=%r" % st["worst"])
        results.check(
            "the reason names the count that drove the verdict",
            "RED" in st["verdict_reason"],
            "verdict_reason=%r" % st["verdict_reason"])

        # (d) AMBER is its own verdict, not green and not red.
        all_of(store.Status.WARN, "60 % used (test)")
        st = web.build_status(d.cfg, d.conn)
        results.check(
            "an all-AMBER fleet is `warn` -- not `ok` and not `fail`",
            st["verdict"] == "warn" and st["counts"]["amber"] == len(targets),
            "verdict=%r counts=%s" % (st["verdict"], st["counts"]))

        # (e) A fresh collector whose every check answered `unknown`. This is the
        # case a boolean gets exactly wrong, and it is not hypothetical: it is
        # what the fleet looks like while a credential or a mount is broken.
        all_of(store.Status.UNKNOWN, "not observed this epoch (test)")
        st = web.build_status(d.cfg, d.conn)
        results.check(
            "a fresh fleet of NOTHING BUT grey is `unknown`, never `ok`",
            st["verdict"] == "unknown" and st["counts"]["grey"] >= len(targets)
            and st["counts"]["green"] == 0 and st["counts"]["red"] == 0
            and st["counts"]["amber"] == 0,
            "verdict=%r counts=%s with %d recorded grey rows -- grey is counted "
            "with >= because the verdict also covers the spec-less checks, which "
            "this selection does not name"
            % (st["verdict"], st["counts"], len(targets)))
        results.check(
            "the grey reason says nothing is known rather than implying health",
            "nothing is known" in st["verdict_reason"],
            "verdict_reason=%r" % st["verdict_reason"])

        # (f) THE ONE THAT MATTERS MOST. Every stored row says ok; the collector
        # stopped. A stale document describes the fleet as it WAS, so the verdict
        # cannot be ok however green the rows are.
        all_of(store.Status.OK, "within threshold (test)")
        ts = d.conn.execute(
            "SELECT MAX(ts) AS ts FROM collector_run").fetchone()["ts"]
        st = web.build_status(d.cfg, d.conn,
                              now=ts + interval * web.STALE_INTERVALS + 1)
        results.check(
            "an ALL-GREEN but STALE store is `unknown`, not `ok`",
            st["verdict"] == "unknown"
            and st["counts"]["green"] == len(targets)
            and st["collector"]["staleness"] == "stale",
            "verdict=%r staleness=%r green=%s -- a stopped collector leaves every "
            "row green forever, which is precisely how a dead monitor looks like "
            "a healthy fleet"
            % (st["verdict"], st["collector"]["staleness"], st["counts"]["green"]))
        results.check(
            "the stale reason says the data describes the past",
            "as it was" in st["verdict_reason"],
            "verdict_reason=%r" % st["verdict_reason"])

        # (g) The boundary is the page's own, so the two surfaces cannot drift:
        # at exactly 3 intervals the data is still current and the verdict is the
        # real one; one second later it is not.
        st = web.build_status(d.cfg, d.conn, now=ts + interval * web.STALE_INTERVALS)
        results.check(
            "at exactly %d intervals the verdict is still the real one" %
            web.STALE_INTERVALS,
            st["verdict"] == "ok" and st["collector"]["staleness"] == "lagging",
            "verdict=%r staleness=%r -- the stale threshold is a strict >, so the "
            "boundary poll must not be voided"
            % (st["verdict"], st["collector"]["staleness"]))
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


# ---------------------------------------------------------------------------
# 10. The status API is a contract, and its caps are visible
# ---------------------------------------------------------------------------


def test_status_api_is_a_stable_contract(results):
    """Stable keys, per-host verdicts, a visible cap, and no silent truncation."""
    tmpdir = tempfile.mkdtemp()
    try:
        d = Dash(tmpdir)
        targets = [(c.target, c.id) for c in registry_instances(d.cfg)
                   if c.spec and not getattr(c, "informational", False)]
        info = [(c.target, c.id) for c in registry_instances(d.cfg)
                if getattr(c, "informational", False)]

        d.epoch()
        for target, cid in targets:
            d.check(target, cid, store.Status.OK, "within threshold (test)")
        st = web.build_status(d.cfg, d.conn)

        required = ("api_version", "generated_at", "generated_at_iso", "verdict",
                    "verdict_reason", "collector", "counts", "hosts", "worst",
                    "worst_truncated", "incidents", "informational",
                    "monitor_defects")
        missing = [k for k in required if k not in st]
        results.check(
            "every documented key is present",
            not missing,
            "missing %s -- an integration keyed on one of these would break on a "
            "change nobody announced" % missing)
        results.check(
            "the document declares its own version",
            st["api_version"] == web.API_VERSION and isinstance(web.API_VERSION, int),
            "api_version=%r (module says %r) -- without it an integrator cannot "
            "tell an additive change from a breaking one"
            % (st.get("api_version"), web.API_VERSION))
        results.check(
            "the timestamp is both machine and human readable",
            isinstance(st["generated_at"], float)
            and st["generated_at_iso"].endswith("Z"),
            "generated_at=%r iso=%r" % (st["generated_at"],
                                        st["generated_at_iso"]))
        results.check(
            "the four verdicts are the only ones this API can emit",
            st["verdict"] in ("ok", "warn", "fail", "unknown"),
            "verdict=%r" % st["verdict"])
        results.check(
            "a non-verdict count is named apart from the verdicts",
            set(("green", "amber", "red", "grey", "informational",
                 "checks_total", "checks_without_result", "worst_total",
                 "worst_truncated")) <= set(st["counts"]),
            "counts=%s -- `informational` must be its own key, never added into "
            "green, or the API reports a health number that includes a "
            "thermometer" % sorted(st["counts"]))

        # PER HOST. An integrator asking "which box" must not have to filter.
        #
        # The GREEN count is asserted exactly and the CHECK count with `>=`: the
        # per-host rollup covers every verdict-bearing row on that host, which
        # includes the spec-less checks this test's `targets` selection
        # deliberately does not name. Asserting equality on `checks` here would
        # be this test restating the renderer's row selection -- item 45's
        # mistake -- instead of measuring the verdict.
        cube1 = [t for t, c in targets if t == "cubox-1"]
        results.check(
            "each CuBox has its own verdict, and its green count is exact",
            st["hosts"].get("cubox-1", {}).get("verdict") == "ok"
            and st["hosts"].get("cubox-2", {}).get("verdict") == "ok"
            and st["hosts"]["cubox-1"]["counts"]["green"] == len(cube1)
            and st["hosts"]["cubox-1"]["checks"] >= len(cube1),
            "hosts=%s (%d spec-bearing cubox-1 checks recorded OK)"
            % ({k: v["verdict"] for k, v in st["hosts"].items()}, len(cube1)))

        # A host with rows but no OBSERVATIONS is unknown per host too. Recorded
        # in a second epoch so the first host's rows are not overwritten.
        d.epoch()
        for target, cid in targets:
            d.check(target, cid, store.Status.UNKNOWN, "not observed (test)")
        d.check("cubox-2", "mem_available_mb", store.Status.FAIL,
                "71 MB available (test)")
        st = web.build_status(d.cfg, d.conn)
        results.check(
            "a per-host verdict is three-valued too, and RED still outranks",
            st["hosts"]["cubox-1"]["verdict"] == "unknown"
            and st["hosts"]["cubox-2"]["verdict"] == "fail",
            "hosts=%s -- a per-host rollup that reported `ok` for a box nothing "
            "was observed on would be the same defect one level down"
            % {k: v["verdict"] for k, v in st["hosts"].items()})

        # THE CAP IS VISIBLE. A silent truncation reads as a complete list, which
        # is item 72's shape: a report that says everything is covered while
        # having dropped most of it.
        d.epoch()
        for target, cid in targets:
            d.check(target, cid, store.Status.FAIL, "everything is broken (test)")
        st = web.build_status(d.cfg, d.conn)
        results.check(
            "more failures than the cap: the list is capped AND says so",
            len(st["worst"]) == web.WORST_LIMIT
            and st["worst_truncated"] is True
            and st["counts"]["worst_total"] == len(targets)
            and st["counts"]["worst_truncated"] is True,
            "%d listed, truncated=%r, total=%s of %d -- an integrator must be "
            "able to tell a truncated list from a complete one"
            % (len(st["worst"]), st["worst_truncated"],
               st["counts"]["worst_total"], len(targets)))
        results.check(
            "the cap keeps the RED rows, not an arbitrary prefix",
            all(w["status"] == "fail" for w in st["worst"]),
            "statuses in worst: %s" % sorted({w["status"] for w in st["worst"]}))

        # INFORMATIONAL IS NOT A VERDICT, asserted through the API rather than
        # the page. Only informational rows are recorded, and they are recorded
        # OK: the verdict must still be `unknown`, because a thermometer reading
        # is not a health statement about the fleet.
        d.epoch()
        for target, cid in info:
            d.check(target, cid, store.Status.OK, "48.2 C (test)")
        st = web.build_status(d.cfg, d.conn)
        results.check(
            "informational rows never reach the verdict",
            st["verdict"] == "unknown" and len(st["informational"]) == len(info)
            and st["counts"]["green"] == 0
            and st["counts"]["informational"] == len(info),
            "verdict=%r counts=%s with %d informational OK rows -- the operator "
            "ruled temperature is FYI on a box with no active cooling"
            % (st["verdict"], st["counts"], len(info)))
        results.check(
            "the informational rows are still available to a consumer",
            all(r["value"] is None or isinstance(r["value"], (int, float))
                for r in st["informational"])
            and all("check_id" in r and "target" in r for r in st["informational"]),
            "informational=%r" % st["informational"])

        # MONITOR DEFECTS ARE NAMED AS THE MONITOR'S, not the fleet's.
        results.check(
            "an unclaimed threshold is reported under `monitor_defects`",
            isinstance(st["monitor_defects"]["unclaimed_thresholds"], list),
            "monitor_defects=%r" % st["monitor_defects"])
        results.check(
            "a check with no stored result is counted, not omitted",
            st["counts"]["checks_without_result"] >= 1
            and st["counts"]["checks_total"] > 0,
            "counts=%s -- '0 rows' must never be presentable as '0 problems'"
            % {k: st["counts"][k] for k in ("checks_total",
                                            "checks_without_result")})
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


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
        # The brief's `Dash(os.path.join(tmpdir, "empty"))` needs the directory
        # to exist first: sqlite will not create a database in a missing path,
        # and the empty-store board is the whole point of this case.
        os.makedirs(os.path.join(tmpdir, "empty"), exist_ok=True)
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
            # THE BAR'S CONTENT, not its attribute spelling. `class=hbar` alone
            # is a check that can pass while a bar is on the page: re-quote the
            # attribute (`class='hbar'`) in a later edit and the substring is
            # absent while the element is not. The fill is what a drawn bar
            # always has, so `"<i style='width:"` is asserted too. `class=hbar`,
            # not `hbar`, for the other half: the hero's stylesheet rule
            # (`.hero .hbar`) is inlined into every page, so a bare `hbar` is
            # satisfied by the CSS that defines the bar this check exists to
            # prove absent.
            "class='hero none" in never and "class=hbar" not in never
            and "<i style='width:" not in never,
            "staleness=none drew a bar -- an empty track reads as '0s ago', "
            "which is the one thing 'never collected' is not")

        results.check(
            "the hero states the age and the threshold it is measured against",
            "stale at 3.0 min" in fresh and "class=hage" in fresh,
            "the hero does not state the threshold the bar is drawn against, so "
            "the bar has no scale and its length means nothing:\n%s"
            % fresh[fresh.find("class='hero"):][:300])

        # THE BAR IS AN IMAGE TO A SCREEN READER, which is the whole reason it
        # is a `role=img` div rather than a plain element: the fill's length is
        # the reading, and a length is not text. Delete the `aria-label` and the
        # bar announces nothing, so the one thing the role exists for is gone.
        results.check(
            "the bar carries its reading as text for a screen reader",
            "role=img" in fresh and "aria-label='last collection" in fresh,
            "a role=img element with no accessible name is an image a screen "
            "reader reads as nothing at all; the bar was:\n%s"
            % fresh[fresh.find("class=hbar"):][:300])

        # NON-VACUOUS HALF: the degradation sentences still exist, unchanged.
        results.check(
            "the hero did not replace the staleness banners it sits above",
            "banner red" in stale and "AS IT WAS" in stale
            and "NO COLLECTION HAS EVER BEEN RECORDED" in never,
            "the hero displaced the sentences that degrade the whole document")
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


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


def main():
    results = Results()
    print("dashboard contract tests (loopback-only server, no fleet access)")
    for fn in TESTS:
        fn(results)
    return results.report("")


if __name__ == "__main__":
    sys.exit(main())
