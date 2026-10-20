"""Dashboard contract tests: the model, the API, and the served shell.

The dashboard is the ONLY dead-man switch this design has (no push notification
was chosen), so its contract is not "looks reasonable" but "is incapable of
showing a clean fleet while measuring nothing". That is a property, and a
property needs a test that can FAIL -- which is why several checks below assert
the EXISTENCE of the healthy path as well as the loudness of the unhealthy one.
A board that renders everything grey passes "UNKNOWN is never green" trivially,
and a suite that only asserted that would go green on an API that had been
reduced to a stub. So: `test_unknown_is_never_green` also proves that a stored
OK renders green, and `test_no_result_renders_unknown_with_a_reason` also proves
that a stored result carries ITS OWN verdict. Item 26: a test that cannot fail
is worse than no test.

THE SERVER-RENDERED PAGE IS GONE. `web.render_html`, its stylesheet and its
refresh script were removed when `/` became the committed React build in
`app/static/` (built by `scripts/build-frontend.sh`, committed, served by
stdlib Python). What survives here is every property that lives in the MODEL or
the HTTP headers: verdicts, colour counts, staleness, incidents, module
disablement, the no-cache rule, and the shell's own headers. The rendered-markup
assertions moved to the frontend's suite as its pages land, and the two
behaviours that were only ever asserted through markup -- the shell's mobile
safe-area contract and its refusal to fetch a webfont -- are asserted against
the files that now own them (`frontend/src/styles.css`, `app/static/index.html`).

THE STORE IS WRITTEN BY DIFFERENT CODE THAN THE API READS. These tests use
`store.record_check` / `record_collector_run` directly rather than running
`collect.py`, so an agreement between writer and reader here is not a
restatement of one rule typed twice (item 45).

THE ONE SERVER THAT BINDS A PORT BINDS LOOPBACK ONLY. `web.serve()` binds
0.0.0.0; these tests must not, because the machine running them is on the
fleet's own LAN and an exposed copy of a monitoring page is not something a test
should be able to create by accident. Each server is a fresh `web.Handler`
subclass bound to 127.0.0.1 on port 0, and the loopback address is ASSERTED
rather than assumed -- the same class of check as everything else here.

Fixtures: none. The dashboard's input is the incident/check tables, and those are
constructed in-process; there is no captured artefact to drift from.
"""

import json
import os
import shutil
import struct
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import CHECKS_CONF, Results                     # noqa: E402

import checks                 # noqa: E402
import config as config_mod   # noqa: E402
import modules as module_loader  # noqa: E402
import store                  # noqa: E402
import thresholds             # noqa: E402
import web                    # noqa: E402
import shell                  # noqa: E402

CACHE = "no-store, no-cache, must-revalidate, max-age=0"

HERE = os.path.dirname(os.path.abspath(__file__))
STATIC = os.path.join(HERE, "..", "app", "static")
STYLES = os.path.join(HERE, "..", "frontend", "src", "styles.css")


def make_cfg(db_path, interval=60, **extra):
    env = {
        "CUBOX_IDS": "cubox-1,cubox-2",
        "MONITOR_DB": db_path,
        "MONITOR_CHECKS": CHECKS_CONF,
        "MONITOR_INTERVAL": str(interval),
    }
    env.update(extra)
    return config_mod.Config(env=env)


class Dash:
    """A store and a config, with no collector in the loop."""

    def __init__(self, tmpdir, interval=60, **extra):
        self.cfg = make_cfg(os.path.join(tmpdir, "monitor.sqlite"), interval,
                            **extra)
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

    def status(self, now=None):
        return web.build_status(self.cfg, self.conn, now=now)

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
        # than the one the API describes. Then "age_s after the last collection"
        # is a lie. `state["last"]` IS that row, so the selection is REUSED
        # rather than re-typed here.
        ts = self.state()["last"]["ts"]
        return web.build_state(self.cfg, self.conn, now=ts + age_s)


def registry_instances(cfg):
    """Every check the API will report: all enabled modules, expanded.

    Derived from discovery rather than the fleet registry, because the model is
    built from discovery too. With one module the two agreed by accident; they
    diverge the moment a second module is discovered (the system module), and a
    suite that drove only the fleet would leave the others unobserved and then
    compare its own short list against the model's longer one.
    """
    mods = module_loader.discover_enabled(cfg)
    classes = checks.registry(
        *([c for m in mods for c in m.check_classes()]
          + list(checks.platform_modules())))
    # AND THE SETTINGS-DRIVEN INSTANCES, for the same reason: `build_state` now
    # reports them, so a class-only list here would measure a different model
    # than the one being served (and count it short).
    ctx = checks.Context(cfg, {}, {}, modules=mods)
    out = checks.expand(classes, checks.expansion_targets(mods))
    for m in mods:
        out.extend(m.check_instances(ctx))
    return out


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


def _hashed_asset():
    """One real file from the committed build, by name."""
    assets = os.path.join(STATIC, "assets")
    names = sorted(os.listdir(assets)) if os.path.isdir(assets) else []
    for name in names:
        if not name.startswith("."):
            return "/assets/" + name
    return None


# ---------------------------------------------------------------------------
# 1. An empty store must be LOUD
# ---------------------------------------------------------------------------


def test_empty_store_is_loud(results):
    """Never-collected must read as 'knows nothing', never as 'fine'."""
    tmpdir = tempfile.mkdtemp()
    try:
        d = Dash(tmpdir)
        state = d.state()
        st = d.status()

        results.check(
            "a store with no collector_run is 'none', not 'fresh'",
            state["staleness"] == "none" and state["last"] is None,
            "staleness=%r" % state["staleness"])
        # THE SENTENCE IS THE API'S, and the SPA renders it. "no collection has
        # ever been recorded" must not share a branch with "the last one is too
        # old": the second asserts a collection that was never made.
        results.check(
            "the empty store says NO COLLECTION HAS EVER BEEN RECORDED",
            st["verdict"] == "unknown"
            and "no collection has ever been recorded" in st["verdict_reason"],
            "verdict=%r reason=%r -- every other surface can be empty and look "
            "calm; this sentence is the only thing standing between 'the "
            "monitor is dead' and 'the fleet is fine'"
            % (st["verdict"], st["verdict_reason"]))
        results.check(
            "the empty store cannot report a green count",
            st["counts"]["green"] == 0 and st["counts"]["checks_total"] > 0,
            "counts=%s -- a green count here is a healthy board over no data"
            % (st["counts"],))

        # The check list comes from the REGISTRY, not from the store, so an empty
        # store still reports every check -- grey, with the reason.
        tiles = len(state["tiles"]) + len(state["others"]) + len(state["informational"])
        results.check(
            "every registered check is in the model even with an empty store",
            tiles >= 60 and len(state["missing"]) == tiles,
            "%d rows, %d missing -- expected the whole registry (64 checks) to be "
            "present and reported missing rather than absent"
            % (tiles, len(state["missing"])))
        results.check(
            "'0 rows' is reported as a row count, not as no problems",
            state["counts"]["tables"]["collector_run"] == 0
            and state["counts"]["tables"]["check_run"] == 0,
            "row counts: %s" % state["counts"]["tables"])
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


# ---------------------------------------------------------------------------
# 2. Staleness degrades the whole document
# ---------------------------------------------------------------------------


def test_stale_says_so_and_cannot_also_be_ok(results):
    """A stale store is UNKNOWN, and the boundary is where the code says it is."""
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
                "at age %ds the model is %r (%s)" % (age, want, why),
                got == want, "staleness=%r, expected %r" % (got, want))

        # The state a stopped collector produces, through the API the SPA reads.
        d.epoch(age_s=interval * web.STALE_INTERVALS + 1)
        state, st = d.state(), d.status()
        results.check(
            "past %d intervals the model is stale" % web.STALE_INTERVALS,
            state["staleness"] == "stale",
            "staleness=%r" % state["staleness"])
        # THE BANNER'S BEHAVIOUR, re-expressed against the contract. There is
        # one verdict field, so "stale cannot also be ok" is a property of the
        # value, not of two banners that might both be drawn.
        results.check(
            "a stale store's verdict is UNKNOWN and says the rows are historical",
            st["verdict"] == "unknown" and "as it was" in st["verdict_reason"],
            "verdict=%r reason=%r -- the rows below describe the fleet as it "
            "WAS, and a verdict of ok on them is the false green this service "
            "exists to prevent" % (st["verdict"], st["verdict_reason"]))
        results.check(
            "the stale reason names the threshold that counts as current",
            str(state["stale_after_s"]) in st["verdict_reason"]
            and state["stale_after_s"] == interval * web.STALE_INTERVALS,
            "reason=%r stale_after_s=%r -- without the number, a reader cannot "
            "tell a stale board from a wrongly-stale one"
            % (st["verdict_reason"], state["stale_after_s"]))
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

        counts = web.build_status(d.cfg, d.conn)["counts"]
        results.check(
            "an all-UNKNOWN store tallies ZERO green",
            counts["green"] == 0 and counts["grey"] >= len(targets),
            "counts=%s for %d UNKNOWN checks" % (counts, len(targets)))
        results.check(
            "grey is not folded into red or amber either",
            counts["red"] == 0 and counts["amber"] == 0,
            "counts=%s -- UNKNOWN must not share a branch with FAIL or WARN, in "
            "either direction" % counts)

        # The contrast, so this test can fail: a stored OK must count GREEN.
        # Without this half, an API that reported everything grey would pass
        # every assertion above.
        d.epoch()
        for target, cid in targets:
            d.check(target, cid, store.Status.OK, "measured within threshold (test)")
        counts = web.build_status(d.cfg, d.conn)["counts"]
        results.check(
            "a stored OK DOES count green (so the test above can fail)",
            counts["green"] == len(targets),
            "counts=%s for %d OK checks -- if this is zero, the grey assertions "
            "above proved nothing" % (counts, len(targets)))
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
        # The row keeps its RAW value in the model (so the SPA can show what the
        # store actually says) and the COLOUR is unknown -- which is the RAG
        # pill's contract, asserted where the colour is decided.
        state = d.state()
        by_key = {(t["target"], t["check_id"]): t for t in state["tiles"]}
        corrupt = by_key[("storage", "media_volume_used_pct")]
        results.check(
            "the corrupt row is grey and keeps its raw string",
            corrupt["status"] == "green"
            and web._status(corrupt["status"]) is store.Status.UNKNOWN
            and web._status(corrupt["status"]).rag == "grey",
            "status=%r rag=%r" % (corrupt["status"],
                                  web._status(corrupt["status"]).rag))
        results.check(
            "no row counts green off the corrupt status",
            web.build_status(d.cfg, d.conn)["counts"]["green"] == 0,
            "a corrupt status produced a green count")
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
        results.check(
            "the reason travels with the row, in words the SPA can render",
            "no result is stored for the newest epoch" in never["detail"],
            "the missing check is grey with no explanation: %r" % never["detail"])
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


# ---------------------------------------------------------------------------
# 6. Nothing that carries a reading is cached
# ---------------------------------------------------------------------------


def test_nothing_is_cached(results):
    """Every observation path carries no-store -- through a real server."""
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
                                ("/modules/fleet", "text/html")):
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
                    code == 200 and hdrs.get("Content-Type", "").startswith(ctype),
                    "code=%s content-type=%r" % (code, hdrs.get("Content-Type")))

            # THE SHELL'S OWN HEADER. `default-src 'self'` is the SPA's whole
            # third-party policy; without it a compromised dependency could load
            # anything, and with inline script present it would need
            # 'unsafe-inline', which this asserts it does not.
            code, hdrs, body = _get(base + "/")
            results.check(
                "the shell is served with the no-inline, same-origin CSP",
                hdrs.get("Content-Security-Policy") == web.SHELL_CSP
                == "default-src 'self'",
                "Content-Security-Policy=%r" % hdrs.get("Content-Security-Policy"))

            # THE HASHED BUNDLE IS THE ONE CACHEABLE THING, because its name is
            # its digest: a cached copy can never describe different bytes.
            asset = _hashed_asset()
            results.check(
                "the committed build has a hashed asset to serve",
                asset is not None, "no files under app/static/assets")
            if asset:
                code, hdrs, body = _get(base + asset)
                results.check(
                    "%s is served immutable" % asset,
                    code == 200 and hdrs.get("Cache-Control") == web.ASSET_CACHE
                    and "immutable" in hdrs.get("Cache-Control", ""),
                    "code=%s Cache-Control=%r"
                    % (code, hdrs.get("Cache-Control")))
                results.check(
                    "a hashed asset has no-store nowhere near it",
                    hdrs.get("Cache-Control") != CACHE,
                    "the bundle was served no-store -- caching it is safe and "
                    "not caching it re-downloads 264 KB on every page view")

            # AN API PATH NEVER FALLS THROUGH TO THE SHELL. Otherwise
            # `/api/typo` answers HTML with 200 and a fetch() parses it.
            code, hdrs, body = _get(base + "/api/typo")
            results.check(
                "an unknown API path is a 404, not the SPA",
                code == 404 and "<div id=\"root\">" not in body,
                "code=%s body=%r" % (code, body[:120]))

            # A NORMALISED PATH MUST NOT BORROW THE ASSET CACHE. Measured:
            # before the flat-name guard, `/assets/../index.html` served the
            # SHELL with `immutable`, which caches the pointer to the current
            # bundle forever -- the exact staleness the design refuses.
            code, hdrs, body = _get(base + "/assets/../index.html")
            results.check(
                "an asset path that normalises out of assets/ is refused",
                code == 404 and hdrs.get("Cache-Control") != web.ASSET_CACHE,
                "code=%s Cache-Control=%r -- the shell was served as an "
                "immutable asset"
                % (code, hdrs.get("Cache-Control")))

            code, hdrs, body = _get(base + "/api/state.json")
            try:
                parsed = json.loads(body)
                ok_json = parsed["staleness"] == "fresh"
            except Exception as exc:                      # noqa: BLE001
                ok_json, parsed = False, {"error": str(exc)}
            results.check("the API returns the same state model as the shell",
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

        # A DATABASE THAT CANNOT BE OPENED. The SPA is a constant of the image,
        # so it STILL LOADS -- that is what lets the browser render the
        # outage -- while every observation path is a loud 503 that says it is
        # not "no problems". An error page cached by a proxy would outlive the
        # outage, so the 503 carries no-store too. The path's PARENT is absent,
        # so nothing here can accidentally create the file first.
        broken_cfg = make_cfg(os.path.join(tmpdir, "no-such-dir", "monitor.sqlite"))
        httpd, base = _serve(broken_cfg)
        try:
            for path in ("/", "/modules/fleet"):
                code, hdrs, body = _get(base + path)
                results.check(
                    "%s still serves the SPA during a database outage" % path,
                    code == 200 and 'id="root"' in body
                    and hdrs.get("Cache-Control") == CACHE
                    and hdrs.get("Content-Security-Policy") == web.SHELL_CSP,
                    "code=%s cache=%r csp=%r -- a shell that 503s leaves the "
                    "browser showing plaintext, which is a dead-man switch that "
                    "cannot say what is wrong"
                    % (code, hdrs.get("Cache-Control"),
                       hdrs.get("Content-Security-Policy")))
            asset = _hashed_asset()
            if asset:
                code, hdrs, body = _get(base + asset)
                results.check(
                    "a hashed asset still serves during a database outage",
                    code == 200 and hdrs.get("Cache-Control") == web.ASSET_CACHE,
                    "code=%s cache=%r -- the bundle is a constant of the image "
                    "and an outage must not stop a loaded page fetching its CSS"
                    % (code, hdrs.get("Cache-Control")))
            code, hdrs, body = _get(base + "/api/status.json")
            results.check(
                "an unopenable database is NOT a 200 on the status API",
                code == 503 and "not 'no problems'" in body
                and "no data at all" in body,
                "code=%s body=%r -- an API that answers 200 with a well-formed "
                "document while it cannot read its own store is a false GREEN "
                "delivered straight to whatever integrates with it"
                % (code, body[:200]))
            results.check(
                "the 503 carries no-store too",
                hdrs.get("Cache-Control") == CACHE,
                "Cache-Control=%r" % hdrs.get("Cache-Control"))
            code, hdrs, body = _get(base + "/healthz")
            results.check(
                "the health probe is 503 during an outage, not 200",
                code == 503 and "not 'no problems'" in body,
                "code=%s -- healthz asserting anything while the store cannot be "
                "read is the false green one layer out" % code)
        finally:
            httpd.shutdown()
            httpd.server_close()
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
        # owns this id, so a model built only from the registry would lose the
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
        results.check(
            "both collector rows are present with their provenance",
            "journal_capture" in {e[1] for e in extra}
            and all(e["from"] == "collector" for e in extra.values()),
            "the collector's rows are missing -- this is the 'we cannot see "
            "cubox-1' row, and losing it is the failure this whole component "
            "exists to prevent")
        results.check(
            "the collector's FAIL drives the verdict",
            web.build_status(d.cfg, d.conn)["verdict"] == "fail",
            "a red collector row did not reach the verdict")
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
        # verdict that would otherwise be the greenest number on the board. The
        # READING comes from `sample` and the VERDICT from `check_run` -- two
        # tables, which is the point of storing raw observations beside verdicts,
        # so a test that only wrote one of them would be testing half a row.
        for target, cid in info:
            d.check(target, cid, store.Status.OK, "48.2 C (test)")
            store.record_sample(d.conn, d.seq, target, "temperature", 48.2,
                                None, text="48.2 C (test)")

        state = d.state()
        st = d.status()
        results.check(
            "an OK informational row is not counted as green",
            st["counts"]["green"] == 0
            and st["counts"]["informational"] == len(info),
            "counts=%s with %d informational OK rows -- a thermometer reading is "
            "not a health statement" % (st["counts"], len(info)))
        results.check(
            "informational rows are not RAG tiles",
            all(not t["informational"] for t in state["tiles"])
            and len(state["informational"]) == len(info),
            "%d tiles, %d informational" % (len(state["tiles"]),
                                            len(state["informational"])))
        results.check(
            "the reading and its unit are separate fields, never one string",
            any(i["value"] == 48.2 for i in state["informational"])
            and all(i["unit"] == i["unit"].strip()
                    and (i["value"] is None
                         or isinstance(i["value"], (int, float)))
                    for i in state["informational"]),
            "readings=%r -- a unit-less reading concatenated at the source is "
            "'48.2 ' and every grep for it then misses"
            % [(i["value"], i["unit"]) for i in state["informational"]])
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


# ---------------------------------------------------------------------------
# 9. Remedy attempts and the command audit are in the model
# ---------------------------------------------------------------------------


def test_remedy_attempts_and_command_history_are_in_the_model(results):
    """A remedy attempt and an operator command must both be reachable.

    WHY BOTH HALVES ARE ASSERTED ON THE ATTEMPT COUNT. An incident's
    `remedy_attempts` is the only statement that something was TRIED and did not
    clear it -- and the obvious renderer appends that sentence to every row, or
    to none. So one incident is given an attempt and one is not, and the
    assertion is that the count is on exactly the one that earned it.

    The command audit is the other half: commands are the only part of the
    platform that changes the fleet, and an audit nobody can read from the
    operator's own surface is an audit that only answers a question asked with a
    shell on the NAS.
    """
    tmpdir = tempfile.mkdtemp()
    try:
        d = Dash(tmpdir)
        d.epoch()
        key = store.incident_key("cubox-1", "disk_free_gb", "mnt")
        for _ in range(store.CONFIRM_POLLS):
            d.seq += 1
            store.sync_incident(d.conn, d.seq, "cubox-1", "disk_free_gb",
                                "mnt", store.Status.FAIL, "full")
            store.sync_incident(d.conn, d.seq, "cubox-2", "disk_free_gb",
                                "mnt", store.Status.FAIL, "full on cubox-2")
        store.note_remedy_attempt(d.conn, key, "restart did not clear it")
        store.record_command_run(d.conn, module="fleet", command="serial_status",
                                 actor="operator", argv={}, dry_run=0,
                                 exit_status=0, output="ok", duration_ms=1)
        state = d.state()
        st = d.status()
        results.check(
            "an incident with attempts and a command run are both present",
            any(i["remedy_attempts"] == 1 for i in state["incidents"])
            and len(state["command_runs"]) == 1,
            "incidents=%r command_runs=%r"
            % (state["incidents"], state.get("command_runs")))

        by_target = {i["target"]: i for i in st["incidents"]}
        results.check(
            "the attempt count is on the incident that has it, and only there",
            by_target["cubox-1"]["remedy_attempts"] == 1
            and by_target["cubox-2"]["remedy_attempts"] == 0,
            "attempts=%r -- a count on a row where no remedy ran says a remedy "
            "was attempted when it was not"
            % {t: i["remedy_attempts"] for t, i in by_target.items()})
        results.check(
            "the command audit is in the model, additively",
            state["command_runs"][0]["command"] == "serial_status",
            "command_runs=%r -- the operator's own actions are only reachable "
            "over ssh" % (state.get("command_runs"),))

        store.latch_remedy(d.conn, key, "still full")
        latched = {i["target"]: i for i in
                   web.build_status(d.cfg, d.conn)["incidents"]}
        results.check(
            "a latched incident says so, and is distinguishable from a retry",
            latched["cubox-1"]["remedy_latched"]
            and latched["cubox-1"]["remedy_attempts"] == 2
            and not latched["cubox-2"]["remedy_latched"],
            "cubox-1=%r -- a latched row waiting on a human must not read as "
            "automatic" % (latched.get("cubox-1"),))
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
    grade writes no sample. The page asked for the NEWEST sample for the metric
    regardless of epoch, so a green row read `23.795 hours` from a sample ten
    days older than the verdict beside it.

    Both halves are asserted. A test that only checked "no stale number" would
    pass on a model that had stopped reporting numbers at all.
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
            "trivially on a model that shows no numbers at all"
            % (tile()["value"],))

        # Epoch 2: the same check returns OK WITHOUT grading -- the fall-through
        # path -- so this epoch writes no sample of its own.
        d.epoch()
        d.check("storage", "tvh_log_signals", store.Status.OK, "no live fault")

        t = tile()
        results.check(
            "an epoch that did not grade shows NO reading, not the last one",
            t["status"] == "ok" and t["value"] is None,
            "status=%r value=%r unit=%r -- the row is showing a sample from an "
            "older epoch beside this epoch's verdict"
            % (t["status"], t["value"], t["unit"]))
        results.check(
            "the stale figure is nowhere in the served model",
            "23.795" not in json.dumps(d.state(), default=str),
            "the ten-day-old number is still in the document beside a current "
            "verdict")
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


# ---------------------------------------------------------------------------
# 11. The status API -- three-valued, not a boolean
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
            (target, check_id) inside one epoch would make the reader's choice
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

        # (g) The boundary is the model's own, so the two surfaces cannot drift:
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
# 12. The status API is a contract, and its caps are visible
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
        # be this test restating the reader's row selection -- item 45's mistake
        # -- instead of measuring the verdict.
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
        # the model's sections. Only informational rows are recorded, and they
        # are recorded OK: the verdict must still be `unknown`, because a
        # thermometer reading is not a health statement about the fleet.
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
# 13. The verdict, and the ways of having no colour
# ---------------------------------------------------------------------------


def test_the_verdict_distinguishes_stale_from_never_collected(results):
    """Staleness dominates, and "never collected" is not "too old".

    Re-expressed from the rendered band. The band used to be a second reader of
    the same rule, and having two readers was how a false green could survive on
    one surface and not the other. There is one verdict field now; these are the
    distinctions it must preserve.
    """
    tmpdir = tempfile.mkdtemp()
    try:
        d = Dash(tmpdir, interval=60)
        d.epoch()
        targets = [(c.target, c.id) for c in registry_instances(d.cfg)
                   if c.spec and not getattr(c, "informational", False)]
        for target, cid in targets:
            d.check(target, cid, store.Status.OK, "fine (test)")
        st = d.status()
        results.check(
            "a fresh all-green board is ok",
            st["verdict"] == "ok" and st["counts"]["green"] == len(targets),
            "verdict=%r counts=%s -- if this is wrong the assertions below "
            "prove nothing" % (st["verdict"], st["counts"]))

        # STALE, with every stored row still green. This is the dangerous one.
        d.epoch(age_s=60 * web.STALE_INTERVALS + 1)
        for target, cid in targets:
            d.check(target, cid, store.Status.OK, "fine (test)")
        st = d.status()
        results.check(
            "a stale board whose stored rows are green is UNKNOWN, not OK",
            st["verdict"] == "unknown" and st["counts"]["green"] == len(targets),
            "verdict=%r green=%s -- the coloured rows describe the fleet as it "
            "WAS, and an ok verdict on them is the false green this service "
            "exists to prevent" % (st["verdict"], st["counts"]["green"]))

        # NEVER COLLECTED, WHICH IS NOT THE SAME FACT AS TOO OLD. Both are
        # UNKNOWN, so a test asserting only the verdict could never catch the two
        # collapsing into one sentence. The REASON is what has to differ.
        os.makedirs(os.path.join(tmpdir, "never"), exist_ok=True)
        v = Dash(os.path.join(tmpdir, "never"))
        never = v.status()
        results.check(
            "a board that has never collected does not claim a collection went "
            "stale",
            never["verdict"] == "unknown"
            and "ever been recorded" in never["verdict_reason"]
            and "too old" not in never["verdict_reason"]
            and never["verdict_reason"] != st["verdict_reason"],
            "reason=%r -- it reaches the right verdict but gives the STALE "
            "reason, asserting a collection that was never made"
            % never["verdict_reason"])

        # NO COLOUR AT ALL: nothing graded, nothing green.
        os.makedirs(os.path.join(tmpdir, "grey"), exist_ok=True)
        e = Dash(os.path.join(tmpdir, "grey"))
        e.epoch()
        grey = e.status()
        results.check(
            "a board with no coloured row is UNKNOWN and says nothing is known",
            grey["verdict"] == "unknown"
            and "nothing is known" in grey["verdict_reason"],
            "reason=%r" % grey["verdict_reason"])

        # SOME GREEN, SOME GREY. The verdict stays ok -- the platform's existing
        # rule -- but the grey count must be carried, never folded away behind
        # the green one. That is what the band's extra sentence used to say.
        os.makedirs(os.path.join(tmpdir, "mixed"), exist_ok=True)
        g = Dash(os.path.join(tmpdir, "mixed"))
        g.epoch()
        g.check(targets[0][0], targets[0][1], store.Status.OK, "fine (test)")
        mixed = g.status()
        results.check(
            "a partly-unknown board carries the grey count beside the green one",
            mixed["verdict"] == "ok" and mixed["counts"]["green"] == 1
            and mixed["counts"]["grey"] == (
                mixed["counts"]["checks_total"]
                - mixed["counts"]["informational"] - 1),
            "verdict=%r counts=%s -- 'we could not ask' presented as if it were "
            "the same as 'it answered green' is the collapse this project is "
            "built against" % (mixed["verdict"], mixed["counts"]))

        # THE THIRD CASE: rows ARE red or amber, so the verdict is fail and the
        # worst list names them.
        os.makedirs(os.path.join(tmpdir, "red"), exist_ok=True)
        r = Dash(os.path.join(tmpdir, "red"))
        r.epoch()
        r.check(targets[0][0], targets[0][1], store.Status.FAIL,
                "38.2 hours, past the limit (test)")
        r.check(targets[1][0], targets[1][1], store.Status.WARN, "near (test)")
        red = r.status()
        results.check(
            "a board with red and amber rows is fail and lists them",
            red["verdict"] == "fail" and red["counts"]["red"] == 1
            and red["counts"]["amber"] == 1
            and any("38.2 hours" in w["detail"] for w in red["worst"]),
            "verdict=%r counts=%s worst=%r" % (red["verdict"], red["counts"],
                                               red["worst"]))
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


# ---------------------------------------------------------------------------
# 14. The newest epoch read uses an index
# ---------------------------------------------------------------------------


def test_the_newest_epoch_read_uses_an_index(results):
    """The dead-man switch cannot take ten seconds to answer.

    WHY THIS IS A TEST RATHER THAN A COMMENT ON THE INDEX. The query is CORRECT
    either way; what changes is how long the page takes, and that failure has no
    symptom in any output this suite otherwise reads. Measured on the live store
    2026-10-07 at 807,263 `check_run` rows and 425 MB: 5.8 s for this one
    statement, build_state at 10-14 s -- slower than the container's own 5 s
    healthcheck, so a monitor collecting perfectly reported as a dead one.

    THE PLAN, NOT A STOPWATCH, is what makes the assertion deterministic:
    `SCAN check_run` is what SQLite says when it has no usable index, on a table
    of any size -- measured on an empty store as well as a populated one, since
    a timing threshold here would be a test that fails on a busy NAS instead of
    on a missing index.

    THE SQL IS IMPORTED, NOT RE-TYPED: `web.NEWEST_EPOCH_SQL` is the statement
    build_state runs, so this cannot stay green while guarding a different query
    than the one that got slow (items 84, 58).
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = make_cfg(os.path.join(tmpdir, "monitor.sqlite"))
        conn = store.connect(cfg.db_path)
        store.init(conn)
        plan = [r[3] for r in
                conn.execute("EXPLAIN QUERY PLAN " + web.NEWEST_EPOCH_SQL)]
        conn.close()
    results.check(
        "the newest-epoch read is an indexed lookup, not a full scan",
        not any(p.startswith("SCAN check_run") for p in plan),
        "the store has no index on check_run(epoch_seq) that the newest-epoch "
        "read can use, so the query every dashboard request runs scans the whole "
        "table -- plan: %r. It stays correct and gets slower with every epoch, "
        "which is why nothing else notices: the page takes seconds to answer, "
        "and a live monitor then reads as a dead one" % (plan,))


# ---------------------------------------------------------------------------
# 15. A pending incident is not on the board
# ---------------------------------------------------------------------------


def test_a_pending_incident_is_not_on_the_board(results):
    """`pending` owns its key but is not an incident (measured 2026-10-19).

    The dashboard selected incidents with LIVE_SQL, so a row with ONE bad poll
    9.4 days earlier was rendered as a RED live incident while the verdict, the
    colour counts and `store.live_incidents` all excluded it -- and `--dismiss`
    could not even name it. Two questions, two lists (CONFIRMED_STATES); the
    board asks the second one.
    """
    tmpdir = tempfile.mkdtemp()
    try:
        d = Dash(tmpdir)
        d.epoch()
        seen = []
        for _ in range(store.CONFIRM_POLLS):
            d.seq += 1
            state = store.sync_incident(d.conn, d.seq, "storage",
                                        "tvh_response_ms", "tvh-http",
                                        store.Status.FAIL, "one failed probe")
            seen.append((state, len(d.state()["incidents"])))

        results.check(
            "pending is off the board; only a confirmed row is on it",
            seen[:-1] == [("pending", 0)] * (store.CONFIRM_POLLS - 1)
            and seen[-1] == ("open", 1),
            "state and board count per poll: %r. A `pending` row has not "
            "reached CONFIRM_POLLS, is deleted outright if the condition "
            "clears, and is not an incident -- showing it as a RED one makes "
            "the page disagree with its own verdict and puts a row on the "
            "board that no operator surface can close." % (seen,))
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


# ---------------------------------------------------------------------------
# 16. Modules: enabled, disabled, and the counts they own
# ---------------------------------------------------------------------------


def test_each_enabled_module_is_named_with_its_tiles(results):
    tmpdir = tempfile.mkdtemp()
    try:
        d = Dash(tmpdir)
        d.epoch()
        targets = [(c.target, c.id) for c in registry_instances(d.cfg)
                   if c.spec and not getattr(c, "informational", False)]
        for target, cid in targets:
            d.check(target, cid, store.Status.OK, "fine (test)")
        state = d.state()

        results.check(
            "the enabled modules are listed with their order and titles",
            [m["id"] for m in state["modules"]] == ["fleet", "system", "snmp"]
            and state["modules"][0]["title"] == "CuBox fleet"
            and state["modules"][1]["title"] == "System resources"
            and state["modules"][2]["title"] == "Network devices"
            and all(m["enabled"] for m in state["modules"]),
            "modules=%r -- the model must name what is on"
            % (state["modules"],))
        fleet_tiles = [t for t in state["tiles"] if t["module"] == "fleet"]
        results.check(
            "each enabled module has tiles, and they carry their module id",
            bool(fleet_tiles)
            and {t["module"] for t in state["tiles"]} == {"fleet", "system"},
            "fleet tiles=%d, modules on tiles: %r"
            % (len(fleet_tiles),
               sorted({t["module"] for t in state["tiles"]})))
        results.check(
            "no disabled module is reported when nothing is disabled",
            state["disabled_modules"] == [],
            "a board with every module enabled claims one is disabled: %r"
            % (state["disabled_modules"],))
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def test_a_disabled_module_is_loud_and_has_no_tiles(results):
    """A disabled module must be stated, and must not leave a green section."""
    tmpdir = tempfile.mkdtemp()
    try:
        d = Dash(tmpdir, FLEET_ENABLED="0", SYSTEM_ENABLED="0",
                 SNMP_ENABLED="0")
        d.epoch()
        state = d.state()
        st = d.status()

        results.check(
            "the model separates enabled from disabled modules",
            state["modules"] == []
            and [m["id"] for m in state["disabled_modules"]]
            == ["fleet", "system", "snmp"],
            "modules=%r disabled=%r -- a disabled module that simply vanishes "
            "reads exactly like one that never existed"
            % (state["modules"], state["disabled_modules"]))
        # RE-EXPRESSED FROM THE DISABLED NOTE. The fact the note carried is in
        # the model: the module is off (above) and its checks are absent, so a
        # consumer can state both without a second source.
        results.check(
            "no tile is reported for a disabled module",
            all(t["module"] not in ("fleet", "system") for t in state["tiles"])
            and "mem_available_mb" not in {t["check_id"]
                                           for t in state["tiles"]},
            "a check from a disabled module still reports a tile: %r"
            % (state["tiles"][:3],))
        results.check(
            "a wholly disabled fleet does not band green",
            st["verdict"] == "unknown",
            "verdict=%r -- platform-only checks are not a clean fleet "
            "(SpecCoverage alone returns OK on an empty audit)"
            % (st["verdict"],))
        rows = {r["check_id"]: r for r in
                state["tiles"] + state["extra"] + state["others"]}
        results.check(
            "the platform's own rows still run and are grey, not absent",
            "modules_enabled" in rows
            and web._status(rows["modules_enabled"]["status"]).rag == "grey",
            "the platform's checks vanished with the module -- then nothing at "
            "all would be measuring the disablement (rows: %s)"
            % sorted(rows)[:8])
        results.check(
            "the API payload carries the module lists, additively",
            st["modules"] == []
            and [m["id"] for m in st["disabled_modules"]]
            == ["fleet", "system", "snmp"],
            "the status API dropped the module lists")
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


# ---------------------------------------------------------------------------
# 17. Insights and proposals
# ---------------------------------------------------------------------------


def test_insights_and_proposals_are_additive_and_empty_safe(results):
    """Recommendations and Approvals are additive, and empty is still a key.

    An absent section reads as a healthy one, so the EMPTY case must carry its
    own list and its count; the populated case must name the insight, the
    rationale and the expiry. An expired proposal is annotated expired even
    though the collector has not swept the row -- the dashboard opens the store
    read-only and cannot run the sweep itself.
    """
    tmpdir = tempfile.mkdtemp()
    try:
        d = Dash(tmpdir)
        d.epoch()
        state = d.state()
        results.check(
            "build_state exposes additive insight and proposal keys",
            state.get("insights") == [] and state.get("proposals") == []
            and "tiles" in state and "incidents" in state,
            "keys=%r -- additive means existing consumers are unaffected"
            % (sorted(state),))
        results.check(
            "empty Recommendations and Approvals are still present and counted",
            len(state["insights"]) == 0 and len(state["proposals"]) == 0
            and state["remedies_enabled"] in (True, False),
            "an empty list that vanishes cannot be told from a broken query")

        store.record_insight(
            d.conn, advisor="reference", module="platform",
            kind="threshold_suggestion", severity="notable",
            title="cubox-1 mem: p95 outside the band",
            body="Proposed band moved by at most 10.")
        store.record_proposal(
            d.conn, module="fleet", kind="action",
            payload={"action_id": "transcode_restart",
                     "incident_key": "cubox-1|c|s"},
            rationale="worker stalled for six hours",
            expires_at=time.time() + 3600)
        store.record_proposal(
            d.conn, module="fleet", kind="action",
            payload={"action_id": "transcode_restart",
                     "incident_key": "cubox-2|c|s"},
            rationale="this one lapsed",
            expires_at=time.time() - 5)

        state = d.state()
        results.check(
            "insights and pending proposals appear in the model",
            len(state["insights"]) == 1 and len(state["proposals"]) == 2,
            "insights=%r proposals=%r"
            % (state["insights"], state["proposals"]))
        results.check(
            "the insight's title reaches the consumer",
            state["insights"][0]["title"] == "cubox-1 mem: p95 outside the band",
            "insights=%r" % (state["insights"],))
        results.check(
            "each proposal carries its rationale and an expiry",
            all(p["rationale"] for p in state["proposals"])
            and all(p["expires_at"] for p in state["proposals"]),
            "proposals=%r -- a proposal without its rationale is an id nobody "
            "can decide" % (state["proposals"],))
        expired = {p["rationale"]: p["expired"] for p in state["proposals"]}
        results.check(
            "an expired proposal is annotated expired, not left actionable",
            expired == {"worker stalled for six hours": False,
                        "this one lapsed": True},
            "expired flags=%r -- the row is still pending in the store, and the "
            "surface must not present a lapsed authority as actionable"
            % (expired,))
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def test_the_empty_approvals_queue_names_the_engine_switch(results):
    """"Nothing pending" and "nothing could execute" are different facts.

    The inbox was identical with MONITOR_REMEDIES on and off, so an operator
    looking at an empty queue could not tell whether the fleet needed no
    decision or the execution engine was simply switched off.
    """
    tmpdir = tempfile.mkdtemp()
    try:
        off = Dash(tmpdir, MONITOR_REMEDIES="0")
        off.epoch()
        off_state = off.state()

        on = Dash(tmpdir, MONITOR_REMEDIES="1")
        on.epoch()
        on_state = on.state()

        results.check(
            "build_state exposes the execution switch",
            off_state.get("remedies_enabled") is False
            and on_state.get("remedies_enabled") is True,
            "off=%r on=%r" % (off_state.get("remedies_enabled"),
                              on_state.get("remedies_enabled")))
        # THE SWITCH TRAVELS IN THE CONTRACT, so the SPA can say WHY the queue is
        # empty without a second endpoint -- which is the whole point: the note
        # it replaced was a server-side sentence the client could not vary.
        results.check(
            "the status API exposes it too, additively",
            web.build_status(off.cfg, off.conn)["remedies_enabled"] is False
            and web.build_status(on.cfg, on.conn)["remedies_enabled"] is True,
            "an integrator cannot tell an empty queue from a disabled engine")
        results.check(
            "both empty queues have no proposals to mis-sort",
            off_state["proposals"] == [] and on_state["proposals"] == [],
            "off=%r on=%r" % (off_state["proposals"], on_state["proposals"]))
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


# ---------------------------------------------------------------------------
# 18. The shell: cache, CSP, and the one place a cache header is allowed
# ---------------------------------------------------------------------------


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
                # THE TYPE MUST AGREE WITH THE FORMAT, NOT MERELY WITH ITSELF.
                # An earlier form compared the header against
                # `web.shell.ASSETS[path][1]` -- and that compares the table to
                # the table, because the route reads that same entry, so a
                # declaration that is simply WRONG moved both sides and stayed
                # green. Measured: mutating the manifest's type to `text/plain`
                # left the suite green. The type is asserted against the FILE.
                ctype = hdrs.get("Content-Type", "")
                if path.endswith(".png"):
                    kind_ok = ctype == "image/png"
                else:
                    kind_ok = "json" in ctype
                results.check(
                    "%s is served as the format it actually is" % path,
                    code == 200 and kind_ok,
                    "Content-Type=%r for %s -- a PNG must arrive as an image and "
                    "the manifest as JSON, or the browser refuses the asset and "
                    "nothing anywhere says so" % (ctype, path))

            # THE GUARD THAT MATTERS: the exception must not grow.
            for path in ("/", "/api/status.json", "/api/state.json", "/healthz",
                         "/modules"):
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
            # on the phone. THE IEND SLICE IS [-8:-4], NOT [-12:-8]: a PNG ends
            # with the IEND chunk's 4-byte LENGTH, its 4-byte TYPE, then its
            # 4-byte CRC -- so the last twelve bytes are `\0\0\0\0` `IEND`
            # `<crc>` and the type is the middle quarter.
            declared = ({i["src"]: i.get("sizes") for i in man.get("icons", [])}
                        if isinstance(man, dict) else {})
            for path in [p for p in web.shell.ASSETS if p.endswith(".png")]:
                code, hdrs, raw = _get_bytes(base + path)
                results.check(
                    "%s is a real, complete PNG" % path,
                    code == 200 and raw[:8] == b"\x89PNG\r\n\x1a\n"
                    and raw[-8:-4] == b"IEND",
                    "code=%s first8=%r last8=%r -- iOS will not accept an SVG "
                    "here, and a truncated file falls back to a screenshot "
                    "without saying so" % (code, raw[:8], raw[-8:]))
                w, h = (struct.unpack(">II", raw[16:24]) if len(raw) >= 24
                        else (0, 0))
                results.check(
                    "%s is the size the manifest declares" % path,
                    code == 200 and w > 0
                    and declared.get(path) == "%dx%d" % (w, h),
                    "the manifest declares %r for this path and the file's own "
                    "IHDR says %dx%d -- iOS trusts the declaration, so a "
                    "mismatch is rescaled or ignored without saying so"
                    % (declared.get(path), w, h))

            # THE ORDERING THAT MAKES THE SHELL WORTH ANYTHING. The shell branch
            # sits ahead of the store precisely so the installed app still looks
            # like an app during an outage; move that branch one statement down
            # and every check above still passes.
            #
            # BOTH HALVES ARE LOAD-BEARING. The shell answering 200 alone would
            # pass vacuously the day this config stops being unopenable, so the
            # guard also asserts an observation path does NOT answer under it.
            broken = make_cfg(os.path.join(tmpdir, "no-such-dir", "monitor.sqlite"))
            httpd2, base2 = _serve(broken)
            try:
                for path in web.shell.ASSETS:
                    code, hdrs, body = _get(base2 + path)
                    results.check(
                        "%s is served while the store cannot be opened" % path,
                        code == 200
                        and hdrs.get("Cache-Control") == web.shell.CACHE_CONTROL,
                        "code=%s Cache-Control=%r -- the app shell is a constant "
                        "of the image, so an outage must not stop it being served"
                        % (code, hdrs.get("Cache-Control")))
                # THE SHELL ANSWERS AND THE OBSERVATION PATH DOES NOT. Both
                # halves are load-bearing: the shell answering alone would pass
                # vacuously the day this config stops being unopenable, so the
                # guard also asserts an observation path does NOT answer under
                # it -- the same two-sided shape as the cache mutation.
                code, _h, _b = _get(base2 + "/")
                results.check(
                    "the SPA shell is served while the store cannot be opened",
                    code == 200,
                    "code=%s -- the shell is a constant of the image, so an "
                    "outage must not stop it loading" % code)
                code, _h, _b = _get(base2 + "/api/status.json")
                results.check(
                    "an observation path does NOT answer under the same config",
                    code != 200,
                    "code=%s -- if this answers 200 then the store was opened "
                    "after all, and the check above proves nothing about ordering"
                    % code)
            finally:
                httpd2.shutdown()
                httpd2.server_close()
        finally:
            httpd.shutdown()
            httpd.server_close()

        # THE SHELL ITSELF. Re-expressed from the rendered `<head>`: the file
        # that ships is the one iOS installs, so the tags and the container the
        # SPA mounts on are asserted where they now live.
        with open(os.path.join(STATIC, "index.html"), encoding="utf-8") as fh:
            index = fh.read()
        results.check(
            "the shell links the manifest and mounts the SPA on #root",
            'rel="manifest"' in index and 'href="/manifest.webmanifest"' in index
            and 'id="root"' in index,
            "the built shell is missing the manifest link or the mount point")
        results.check(
            "the shell is titled Sentinel",
            "<title>Sentinel</title>" in index,
            "the title is not the platform's name")
        # THE MANIFEST DOES NOT SUBSTITUTE FOR THESE. iOS reads the apple-*
        # meta tags when installing to the home screen; without the
        # black-translucent status bar the safe-area insets above stay zero and
        # the page stops clearing the Dynamic Island.
        results.check(
            "the shell carries the iOS home-screen tags",
            'rel="apple-touch-icon"' in index
            and 'name="apple-mobile-web-app-capable"' in index
            and 'name="apple-mobile-web-app-title"' in index
            and 'black-translucent' in index
            and 'name="theme-color"' in index,
            "the built head is missing an apple-* tag or the theme colour")
        results.check(
            "there is no service worker, deliberately",
            "serviceWorker" not in index and "sw.js" not in index,
            "a service worker appeared -- iOS installs without one, so it would "
            "exist only to cache, which is the one thing no-store forbids")
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


# ---------------------------------------------------------------------------
# 19. The mobile contract lives in the stylesheet now
# ---------------------------------------------------------------------------


def test_the_shell_keeps_the_mobile_contract(results):
    """What the phone reported, asserted against the files that now own it.

    Measured on an iPhone 15 Pro with the app on the home screen, 2026-10-07:
    the title and the target list sat BEHIND the Dynamic Island, and a wide
    table pushed the whole document wider than the screen so the page scrolled
    sideways under the reader's thumb. Both were fixed in the server-rendered
    page's CSS; the CSS moved to the SPA in Task 5, so the guard moves with it.

    It reads the SOURCE, not the built bundle: the bundle is minified and its
    file name changes by design, while `frontend/src/styles.css` is the file a
    later edit actually touches.
    """
    try:
        with open(STYLES, encoding="utf-8") as fh:
            css = fh.read()
        with open(os.path.join(STATIC, "index.html"), encoding="utf-8") as fh:
            index = fh.read()
    except OSError as exc:
        results.check("the shell's stylesheet and shell html are present", False,
                      "could not read %s / the built index: %s" % (STYLES, exc))
        return

    wrap = css.split(".wrap {", 1)[1].split("}", 1)[0] if ".wrap {" in css else ""
    insets = [i for i in ("top", "right", "bottom", "left")
              if "env(safe-area-inset-%s" % i in wrap]
    results.check(
        "the page insets itself clear of the iPhone's status bar and edges",
        len(insets) == 4 and "calc(" in wrap,
        "the .wrap rule does not carry all four env(safe-area-inset-*) terms "
        "-- found %r. `viewport-fit=cover` and the black-translucent status bar "
        "put the document UNDER the island on purpose, so a page that does not "
        "inset itself hides its own title behind the camera housing" % (insets,))
    results.check(
        "the viewport meta still asks for the safe-area treatment",
        "viewport-fit=cover" in index,
        "without viewport-fit=cover, env() is always zero and the insets above "
        "are dead code")
    results.check(
        "tables can still scroll inside themselves",
        ".scroll { overflow-x:auto; }" in css.replace("\n", " ").replace(
            "  ", " ") or "overflow-x:auto" in css,
        "a wide table pushes the DOCUMENT sideways; the wrapper must scroll "
        "instead")
    results.check(
        "the four RAG tokens are defined",
        all(("--%s:" % c) in css for c in ("ok", "warn", "fail", "unknown")),
        "the stylesheet lost a RAG token -- a var() with no definition is an "
        "element that quietly has no colour")
    results.check(
        "reduced motion is respected",
        "prefers-reduced-motion" in css,
        "the page animates for a reader who asked it not to")
    results.check(
        "no webfont is fetched for the page that has to be trustworthy",
        "@font-face" not in css and "fonts.googleapis" not in index
        and "fonts.gstatic" not in index,
        "a typography dependency on the page whose whole job is to be "
        "believable when the network is the thing that is broken")
    results.check(
        "no heading uppercases itself",
        "uppercase" not in css,
        "a heading still text-transforms to caps -- the tracked-out ALL-CAPS "
        "eyebrow is the generated-page tell the design removed")


TESTS = (test_empty_store_is_loud,
         test_stale_says_so_and_cannot_also_be_ok,
         test_unknown_is_never_green,
         test_unrecognised_status_is_grey_not_green,
         test_no_result_renders_unknown_with_a_reason,
         test_nothing_is_cached,
         test_collector_rows_are_visible,
         test_informational_rows_carry_no_colour,
         test_remedy_attempts_and_command_history_are_in_the_model,
         test_a_sample_from_an_older_epoch_is_not_shown_as_current,
         test_status_api_is_three_valued,
         test_status_api_is_a_stable_contract,
         test_the_verdict_distinguishes_stale_from_never_collected,
         test_the_newest_epoch_read_uses_an_index,
         test_a_pending_incident_is_not_on_the_board,
         test_each_enabled_module_is_named_with_its_tiles,
         test_a_disabled_module_is_loud_and_has_no_tiles,
         test_insights_and_proposals_are_additive_and_empty_safe,
         test_the_empty_approvals_queue_names_the_engine_switch,
         test_the_app_shell_may_cache_and_nothing_else_may,
         test_the_shell_keeps_the_mobile_contract)


def main():
    results = Results()
    print("dashboard contract tests (loopback-only server, no fleet access)")
    for fn in TESTS:
        fn(results)
    return results.report("")


if __name__ == "__main__":
    sys.exit(main())
