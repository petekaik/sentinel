"""Offline tests for the collection loop. NO NETWORK -- asserted, not assumed.

Run directly (`python3 tests/test_collect_offline.py`) or via
`test.sh`, which is what the repo's convention expects.

WHAT THIS COVERS, AND WHY THESE TWO CASES IN PARTICULAR

The escalation in collect.py exists so that a fleet which has become
UNOBSERVABLE is loud rather than quiet. That is a claim about a state machine, and
the only way to test a state machine is to drive it through time. So both tests
run several epochs against a stubbed transport and assert on the INCIDENT TABLE --
a different layer than the code that produced the statuses, which is the item 45
rule (a check that reads the same variable it wrote is a restatement, not a test).

  1. A REAL OUTAGE MUST KEEP ITS HISTORY. Three failed collections must reach
     `open`, and the recovery must reach `resolved` -- with the row still there
     afterwards. An earlier version of the collector failed this, and the failure
     was invisible from the outside: it held the escalation at UNKNOWN for three
     attempts AND left the incident machine to confirm for three more, so the row
     was still `pending` when the host came back and got DELETED by the
     `pending -> delete` transition. A box unobservable for five minutes left no
     record at all.

  2. A ONE-POLL BLIP MUST LEAVE NO TRACE. The same `pending -> delete` transition
     is exactly right for a transient, and this proves the fix did not simply
     disable it. If test 1 passes and test 2 fails, the threshold has been
     removed rather than corrected -- which is why they are a pair and not two
     independent cases.

NO NETWORK, AND THE TEST PROVES IT. Every name that can reach a host --
`probes.run`, `probes.ssh`, `boxfacts.pull`, `backupfacts.pull`, `export.pull`,
`journal.pull` -- is replaced by a stub for the duration of a `with Fleet(...)`
block, and the two lowest-level stubs COUNT their calls. A count of zero on a
path that must have contacted a host is a failure: it would mean the code went
somewhere else, and the most likely place is the real network. (An earlier draft
of this file DID reach the real fleet, through `export.pull`, which nothing had
stubbed -- that is why the counter exists, and why the stub list now names every
transport rather than the two obvious ones.)

Fixtures are the live captures from 2026-09-26, read from disk rather than
restated, so the healthy-fleet half of these tests exercises the real probe
output.
"""

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import CHECKS_CONF, FIXTURES, Results, read_fixture  # noqa: E402

import backupfacts                   # noqa: E402
import boxfacts                      # noqa: E402
import export as export_mod          # noqa: E402
import collect                       # noqa: E402
import config as config_mod          # noqa: E402
import journal as journal_mod        # noqa: E402
import parsers                       # noqa: E402
import probes                        # noqa: E402
import store                         # noqa: E402

WHY = "simulated: no route to host (offline test)"

# ---------------------------------------------------------------------------
# The transport stubs.
# ---------------------------------------------------------------------------

CALLS = {"run": 0, "ssh": 0}


def _fake_result():
    r = probes.RemoteResult(transport=probes.Transport.UNREACHABLE, rc=None,
                            out="", err="ssh: connect to host: No route to host")
    r.duration_ms = 1
    return r


def _fake_run(argv, timeout=30, stdin=None, env=None):
    CALLS["run"] += 1
    return _fake_result()


def _fake_ssh(host, command, timeout=None):
    CALLS["ssh"] += 1
    return _fake_result()


# THE STUBS ARE INSTALLED BY `Fleet.__enter__` AND REMOVED BY `__exit__`, NOT AT
# IMPORT TIME. Patch-at-import leaks: another suite in the same process (this
# repo runs them all from `run_all.py`) then sees a stubbed transport and its own
# assertions fail for a reason that has nothing to do with the code under test --
# measured here as 7 failures that appeared ONLY when the suites ran together.
# A stub with a scope is the difference between a test and a global side effect.


class Fleet:
    """A stubbed fleet that can be switched between UP and DOWN mid-test."""

    def __init__(self, tmpdir):
        self.down = True
        self._saved = {}
        env = {
            "CUBOX_IDS": "cubox-1,cubox-2",
            "MONITOR_DB": os.path.join(tmpdir, "monitor.sqlite"),
            "MONITOR_CHECKS": CHECKS_CONF,
            # Deliberately absent: the docker socket and the two media paths, so
            # the storage checks stay deterministic and offline. Their verdicts
            # are not what these tests assert on, but they must not be able to
            # reach anything real.
            "DOCKER_SOCKET": os.path.join(tmpdir, "no-such-docker.sock"),
            "TVH_URL": "http://127.0.0.1:9/",
            "RECORDINGS_PATH": os.path.join(tmpdir, "no-such-recordings"),
            "TRANSCODED_PATH": os.path.join(tmpdir, "no-such-transcoded"),
            "MONITOR_SSH_TIMEOUT": "5",
            "MONITOR_INTERVAL": "60",
        }
        self.cfg = config_mod.Config(env=env)
        self.conn = store.connect(self.cfg.db_path)
        store.init(self.conn)

    # -- the stubbed transport, for the duration of one `with` block ---------

    def __enter__(self):
        self._patch()
        return self

    def __exit__(self, *exc):
        # Restore the EXACT object captured in `_patch`, by identity -- never a
        # re-import and never a name lookup, so a suite nested or run after this
        # one gets back the function it would have had.
        for obj, name, old, _new in self._patched:
            setattr(obj, name, old)
        return False

    def _patch(self):
        def boxfacts_pull(host, script, timeout=None, write_probe=False):
            if self.down:
                return parsers.parse_facts("", transport_ok=False, why=WHY)
            return parsers.parse_facts(
                read_fixture("boxfacts-%s-2026-09-26.txt" % host.name))

        def backupfacts_pull(host, script, cfg, timeout=None):
            if self.down:
                return parsers.parse_backup_facts("", transport_ok=False, why=WHY)
            return parsers.parse_backup_facts(
                read_fixture("facts-backup-nas-2026-09-26.txt"))

        def export_pull(ctx, cubox_id):
            if self.down:
                return export_mod.StateExport(cubox_id=cubox_id,
                                              transport="unreachable", why=WHY)
            se = export_mod.StateExport(cubox_id=cubox_id,
                                        transport=probes.Transport.RAN.value,
                                        dir_exists=True)
            se.config_text = read_fixture("config-%s.txt" % cubox_id)
            return se

        def journal_pull(host, conn, interval_s, timeout=None, lines=2000):
            jp = journal_mod.JournalPull(host.name)
            if self.down:
                jp.why = WHY
                return jp
            jp.transport = probes.Transport.RAN.value
            jp.new_cursor = "s=live-%s" % host.name
            jp.lines = [("s=live-%s" % host.name, 1758900000.0, "cubox-transcode",
                         6, "simulated journal line")]
            return jp

        # EVERY NAME THAT CAN REACH A HOST, in one list, so a new stub cannot be
        # added without a matching restore. `collect.boxfacts` IS the `boxfacts`
        # module and `export_mod` IS `export`, so these are the same objects the
        # checks import.
        self._patched = (
            (probes, "run", probes.run, _fake_run),
            (probes, "ssh", probes.ssh, _fake_ssh),
            (boxfacts, "pull", boxfacts.pull, boxfacts_pull),
            (backupfacts, "pull", backupfacts.pull, backupfacts_pull),
            (export_mod, "pull", export_mod.pull, export_pull),
            (journal_mod, "pull", journal_mod.pull, journal_pull),
        )
        for obj, name, _old, fn in self._patched:
            setattr(obj, name, fn)

    def epoch(self):
        return collect.collect_once(self.cfg, self.conn)

    def reach_incidents(self, host):
        """{state: n} for one host's reachability incidents, ALL states."""
        rows = self.conn.execute(
            "SELECT state, COUNT(*) AS n FROM incident WHERE key LIKE ? "
            "GROUP BY state", ("%s|host%%" % host,)).fetchall()
        return {r["state"]: r["n"] for r in rows}

    def live_reach(self):
        rows = self.conn.execute(
            "SELECT key FROM incident WHERE state IN "
            "('pending','open','unknown','latched') AND key LIKE '%|host%' "
            "ORDER BY key").fetchall()
        return [r["key"] for r in rows]


# ---------------------------------------------------------------------------
# The tests
# ---------------------------------------------------------------------------


def test_outage_keeps_its_history(results):
    """3 failed collections -> open; recovery -> resolved, row still present."""
    import shutil
    tmpdir = tempfile.mkdtemp()
    try:
        with Fleet(tmpdir) as f:
            c0 = dict(CALLS)

            for _ in range(3):
                f.epoch()
            # Asserted PER HOST and against the state, not merely "something is
            # live": `open` and `pending` are the whole distinction this test exists
            # to pin down, and a fleet-wide list would also match the backup host,
            # which is down here too.
            for host in ("cubox-1", "cubox-2"):
                results.check(
                    "the outage on %s reaches `open` after 3 failed collections"
                    % host,
                    f.reach_incidents(host) == {"open": 1},
                    "%s: %s (expected {'open': 1}; a `pending` row means the "
                    "confirmation threshold is being counted twice, and an empty dict "
                    "means the outage is silent, which is the whole bug)"
                    % (host, f.reach_incidents(host)))
            results.check(
                "every host that could not be collected has its own incident",
                len(f.live_reach()) == 3,
                "live reachability incidents: %s (expected one each for cubox-1, "
                "cubox-2 and backup)" % f.live_reach())

            # The stubs must have been used, or the epochs did not touch the hosts we
            # think they did -- and the likely reason is a real ssh somewhere.
            results.check(
                "the transport stubs were the ones actually used",
                CALLS["run"] > c0["run"] or CALLS["ssh"] > c0["ssh"],
                "probes.run/ssh call counts are unchanged (%s), so something bypassed "
                "the stubs -- most likely the real network" % CALLS)

            f.down = False
            f.epoch()
            results.check(
                "recovery RESOLVES the outage rather than deleting it",
                f.reach_incidents("cubox-1") == {"resolved": 1}
                and f.reach_incidents("cubox-2") == {"resolved": 1},
                "cubox-1 reachability rows: %s (expected {'resolved': 1} -- a row that "
                "is simply absent means the transition was `pending -> delete`, which "
                "is the branch meant for a one-poll transient)"
                % f.reach_incidents("cubox-1"))

            results.check(
                "the healthy fleet has no live reachability incident",
                f.live_reach() == [],
                "still live: %s" % f.live_reach())

            # A second healthy epoch must not open anything new: the OK branch is
            # emitted every epoch, and an OK observation against no incident is a
            # no-op rather than a row.
            f.epoch()
            results.check(
                "repeated healthy epochs create no incidents",
                f.reach_incidents("cubox-1") == {"resolved": 1},
                "cubox-1: %s" % f.reach_incidents("cubox-1"))
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def test_blip_leaves_no_trace(results):
    """ONE failed collection, then recovery: the row must be DELETED."""
    import shutil
    tmpdir = tempfile.mkdtemp()
    try:
        with Fleet(tmpdir) as f:
            f.down = False
            f.epoch()
            results.check("a healthy fleet opens no reachability incident",
                          f.reach_incidents("cubox-1") == {},
                          "cubox-1: %s" % f.reach_incidents("cubox-1"))

            f.down = True
            f.epoch()
            states = f.reach_incidents("cubox-1")
            results.check(
                "a single failed collection is `pending`, never `open`",
                states == {"pending": 1},
                "cubox-1: %s (a single poll must never create a confirmed incident)"
                % states)

            f.down = False
            f.epoch()
            results.check(
                "recovering from a blip DELETES the row rather than resolving it",
                f.reach_incidents("cubox-1") == {},
                "cubox-1: %s (expected {} -- a transient that never became an "
                "incident must not appear in history as one)"
                % f.reach_incidents("cubox-1"))
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def test_unknown_is_never_green(results):
    """An unreachable box must yield UNKNOWN everywhere, never OK.

    The item 26 / item 72 rule at the level that matters: with the transport
    down, EVERY per-box check must be grey or red. A single green row on an
    unobservable box is the monitor lying about the fleet.
    """
    import shutil
    tmpdir = tempfile.mkdtemp()
    try:
        with Fleet(tmpdir) as f:
            f.down = True
            s = f.epoch()
            green = [r for r in s["results"]
                     if r.status is store.Status.OK
                     and r.target in ("cubox-1", "cubox-2")]
            results.check(
                "no CuBox check is green while the box is unreachable",
                green == [],
                "green rows on an unreachable box: %s"
                % [(r.target, r.check_id) for r in green])

            grey = [r for r in s["results"] if r.status is store.Status.UNKNOWN]
            results.check(
                "the unreachable box's checks are UNKNOWN, not absent",
                len(grey) >= 20,
                "only %d UNKNOWN rows -- expected the box's whole check set to be "
                "present and grey" % len(grey))
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def test_transport_argv_is_the_measured_one(results):
    """The argv the transport builds, asserted where it cannot be a no-op.

    NOT a timing test. `ping` cannot be run from this Mac at all (macOS's ping
    has no `-w`), and running the real one would make the suite depend on the
    network it exists to be independent of. So this asserts the ARGV, which is
    the part that was actually wrong: `-W` is seconds in iputils while this code
    passed milliseconds, so a 3-second probe became a 3000-second one and the
    Backup-NAS reachability check could only ever be killed by its own caller --
    UNKNOWN on a dead NAS, green on a live one, and never RED.

    The ssh half is a safety property rather than a bug fix: `StrictHostKeyChecking=yes`
    with an explicit known_hosts is what makes a changed host key a FAILURE. The
    box's host keys are state-managed, so a rebuild regenerates them, and
    `accept-new` would take the new key silently -- turning "this box is not the
    box it was" into "everything is fine".
    """
    seen = []

    def spy(argv, timeout=30, stdin=None, env=None):
        seen.append((list(argv), timeout))
        return _fake_result()

    saved = probes.run
    probes.run = spy
    try:
        probes.ping("192.0.2.1", timeout=3)
        host = probes.Host(name="x", address="192.0.2.1", user="root",
                           key="/etc/monitor/id_ed25519",
                           known_hosts="/etc/monitor/known_hosts", timeout=25)
        argv = host.base_args()
    finally:
        probes.run = saved

    ping_argv, ping_timeout = seen[0] if seen else ([], 0)
    big_W = ping_argv[ping_argv.index("-W") + 1] if "-W" in ping_argv else None
    deadline = ping_argv[ping_argv.index("-w") + 1] if "-w" in ping_argv else None
    results.check(
        "ping uses a SECONDS deadline (-w), not iputils' seconds -W",
        deadline is not None and big_W is None,
        "argv=%s -- iputils reads -W as SECONDS, so the old '-W %s' meant 'wait "
        "up to %s seconds'; the caller's %ss subprocess timeout then killed it "
        "and the check reported a timeout instead of an unreachable NAS"
        % (ping_argv, big_W, big_W, ping_timeout))
    results.check(
        "the ping deadline is smaller than the caller's own timeout",
        deadline is not None and deadline.isdigit()
        and 0 < int(deadline) < ping_timeout,
        "deadline=%s caller timeout=%s -- a deadline at or above the caller's "
        "timeout means the caller always wins the race, which is the bug"
        % (deadline, ping_timeout))

    joined = " ".join(argv)
    results.check(
        "ssh never accepts an unknown host key",
        "StrictHostKeyChecking=yes" in argv and "accept-new" not in joined,
        "argv=%s -- `accept-new` would take a regenerated host key silently, and "
        "this box's host keys are state-managed, so a silent-no-persistence box "
        "can present the shared image's key" % argv)
    for want, why in (
        ("BatchMode=yes", "a password prompt is a hang with no timeout"),
        ("UserKnownHostsFile=/etc/monitor/known_hosts",
         "the container has no ~/.ssh; the file is mounted explicitly"),
        ("IdentitiesOnly=yes", "without it ssh offers every key it is given"),
        ("ConnectTimeout=10", "the state mount is HARD, so a client-side bound "
                              "is the only thing that stops a D-state hang"),
        ("ServerAliveInterval=5", "same, for a connection that goes silent"),
    ):
        results.check("ssh passes %s (%s)" % (want, why), want in joined,
                      "argv=%s" % argv)


TESTS = (test_outage_keeps_its_history, test_blip_leaves_no_trace,
         test_unknown_is_never_green, test_transport_argv_is_the_measured_one)


def main():
    results = Results()
    for fn in TESTS:
        fn(results)
    return results.report("collect.py offline tests (no network, asserted)")


if __name__ == "__main__":
    sys.exit(main())
