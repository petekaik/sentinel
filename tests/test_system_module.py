"""The system module: local /proc, /sys, disk and mdstat, as module #2.

Hermetic: every read points at a temporary tree, no check opens a socket, and
the only touch on the real filesystem is `shutil.disk_usage` against a mount the
test names.
"""

import os
import sqlite3
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import Results                                      # noqa: E402

import checks                                                    # noqa: E402
import collect                                                   # noqa: E402
import config as config_mod                                      # noqa: E402
import modules as loader                                         # noqa: E402
import store                                                     # noqa: E402
import thresholds                                                # noqa: E402
import web                                                       # noqa: E402
from modules.system import checks as system_checks               # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
SYSTEM_DIR = os.path.join(os.path.dirname(HERE), "app", "modules", "system")

# A missing file in this suite's tree. Distinct from None, which means a real
# empty value -- the same three-valued distinction the checks make.
ABSENT = object()

LOADAVG = "0.10 0.20 0.30 1/120 4567\n"
MEMINFO = ("MemTotal:       2048000 kB\n"
           "MemFree:         500000 kB\n"
           "MemAvailable:   1048576 kB\n"
           "Buffers:         100000 kB\n"
           "Cached:          400000 kB\n"
           "SwapTotal:            0 kB\n"
           "SwapFree:             0 kB\n")
UPTIME = "93784.20 123456.00\n"
MDSTAT_CLEAN = ("Personalities : [raid1]\n"
                "md0 : active raid1 sda1[0] sdb1[1]\n"
                "      1048576 blocks super 1.2 [2/2] [UU]\n"
                "\nunused devices: <none>\n")
# QTS's normal layout: more member SLOTS than installed devices. md9/md13
# expect 128 and carry two; per-disk mirrors carry a phantom partner. `_` is
# "no device in the slot", not a failure, and a healthy QNAP is full of them.
MDSTAT_UNPOPULATED = ("Personalities : [raid1]\n"
                      "md0 : active raid1 sda1[0]\n"
                      "      1048576 blocks super 1.2 [2/1] [U_]\n"
                      "\nunused devices: <none>\n")
MDSTAT_QTS_SLOTS = ("Personalities : [raid1]\n"
                    "md13 : active raid1 sdb4[0] sda4[128]\n"
                    "      458880 blocks super 1.0 [128/2] [UU" + "_" * 126
                    + "]\n\nunused devices: <none>\n")
MDSTAT_FAULTY = ("Personalities : [raid1]\n"
                 "md0 : active raid1 sda1[0] sdb1[1]\n"
                 "      1048576 blocks super 1.2 [2/2] [UF]\n"
                 "\nunused devices: <none>\n")
MDSTAT_RESYNC = ("Personalities : [raid1]\n"
                 "md0 : active raid1 sda1[0] sdb1[1]\n"
                 "      1048576 blocks super 1.2 [2/2] [UU]\n"
                 "      [==>.................]  resync = 10.0% "
                 "(104857/1048576) finish=1.0min speed=15728K/sec\n"
                 "\nunused devices: <none>\n")
MDSTAT_SCRUB = ("Personalities : [raid1]\n"
                "md0 : active raid1 sda1[0] sdb1[1]\n"
                "      1048576 blocks super 1.2 [2/2] [UU]\n"
                "      [==>.................]  check = 10.0% "
                "(104857/1048576) finish=1.0min speed=15728K/sec\n"
                "\nunused devices: <none>\n")
MDSTAT_MISSING_AND_RESYNC = (
    "Personalities : [raid1]\n"
    "md0 : inactive\n"
    "md1 : active raid1 sda1[0] sdb1[1]\n"
    "      1048576 blocks super 1.2 [2/2] [UU]\n"
    "      [==>.................]  resync = 10.0% "
    "(104857/1048576) finish=1.0min speed=15728K/sec\n"
    "\nunused devices: <none>\n")

_GOOD = {
    "proc/loadavg": LOADAVG,
    "proc/meminfo": MEMINFO,
    "proc/uptime": UPTIME,
    "proc/mdstat": MDSTAT_CLEAN,
    "sys/class/thermal/thermal_zone0/temp": "45000\n",
}


def _write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as fh:
        fh.write(text)


def _tree(root, over=None):
    """Write the proc/sys tree for one test; `ABSENT` deletes a default."""
    files = dict(_GOOD)
    files.update(over or {})
    for rel, text in files.items():
        if text is ABSENT:
            continue
        _write(os.path.join(root, rel), text)
    # An absent mdstat / thermal zone must be absent, not "a file we skipped".
    for rel in ("proc/mdstat", "sys/class/thermal/thermal_zone0/temp"):
        if files.get(rel) is ABSENT:
            path = os.path.join(root, rel)
            if os.path.exists(path):
                os.remove(path)
    return os.path.join(root, "proc"), os.path.join(root, "sys")


def _ctx(root, mounts="/", extra=None):
    """Preload the real module through the collector's own path."""
    env = {
        "SENTINEL_MODULES": "system",
        "SYSTEM_PROC": os.path.join(root, "proc"),
        "SYSTEM_SYS": os.path.join(root, "sys"),
        "SYSTEM_MOUNTS": mounts,
    }
    env.update(extra or {})
    cfg = config_mod.Config(env=env)
    mods = loader.discover_enabled(cfg)
    mod = [m for m in mods if m.id == "system"][0]
    specs = thresholds.load_effective(
        {"system": os.path.join(mod._path, mod.threshold_file)})
    ctx = checks.Context(cfg, specs, {}, modules=mods)
    collect.preload_modules(cfg, ctx, {})
    return ctx, mod


def _run(cls, ctx):
    return cls().timed(ctx)


def _disk(facts, pct_by_mount):
    """Deterministic disk figures -- a full filesystem cannot be made in a test."""
    facts.disks = {
        mount: {"total": 100, "free": pct, "pct_free": pct}
        for mount, pct in pct_by_mount.items()
    }


# ---------------------------------------------------------------------------
# Discovery and the contract
# ---------------------------------------------------------------------------


def test_discovery_finds_fleet_then_system(results):
    mods = loader.discover()
    ids = [m.id for m in mods]
    results.check(
        "discovery finds fleet (order 10) then system (order 20)",
        ids[:2] == ["fleet", "system"]
        and [m.order for m in mods[:2]] == [10, 20],
        "discovered %r with orders %r -- the module is one directory and must "
        "load with no platform edit, ordered by `order` then id"
        % (ids, [m.order for m in mods]))

    system = [m for m in mods if m.id == "system"][0]
    path = os.path.join(SYSTEM_DIR, system.threshold_file)
    results.check(
        "the system module declares its target and ships a threshold file",
        system.targets == ("local",) and os.path.isfile(path),
        "targets=%r threshold_file=%r -- a module whose threshold file cannot "
        "be found makes every spec-graded check UNKNOWN for a missing spec"
        % (system.targets, path))

    classes = checks.registry(*system.check_classes())
    results.check(
        "all six checks are registered, under the local target",
        sorted(c.id for c in classes) == sorted([
            "system_load1_per_cpu", "system_mem_available_mb",
            "system_disk_free_pct", "system_raid_degraded",
            "system_thermal_c", "system_uptime"])
        and all(c.target == "local" for c in classes),
        "registered %r" % sorted((c.target, c.id) for c in classes))


def test_every_threshold_is_claimed_by_a_check(results):
    mod = [m for m in loader.discover() if m.id == "system"][0]
    specs = thresholds.load_effective(
        {"system": os.path.join(SYSTEM_DIR, mod.threshold_file)})
    claimed, deferred, unclaimed = thresholds.audit(
        specs, checks.registry(*mod.check_classes()))
    results.check(
        "every declared spec is read by a check (an unclaimed band is a check "
        "that silently never fires)",
        set(specs) == claimed and not deferred and not unclaimed,
        "specs=%r claimed=%r deferred=%r unclaimed=%r"
        % (sorted(specs), sorted(claimed), sorted(deferred), sorted(unclaimed)))


# ---------------------------------------------------------------------------
# Healthy readings, and every breach
# ---------------------------------------------------------------------------


def test_healthy_readings_grade_ok(results):
    root = tempfile.mkdtemp()
    try:
        _tree(root)
        ctx, _ = _ctx(root)
        f = ctx.system_facts

        results.check(
            "preload reads loadavg, memory, uptime, mdstat and thermal",
            f.load1 == 0.10 and f.load5 == 0.20 and f.load15 == 0.30
            and f.procs_running == 1 and f.procs_total == 120
            and f.mem_available_kb == 1048576 and f.mem_source == "MemAvailable"
            and f.mem_total_kb == 2048000
            and f.uptime_s == 93784.20
            and f.mdstat_text is not None
            and f.thermal_max_c == 45.0 and f.thermal_zones == 1,
            "load=%r mem=%r/%r uptime=%r mdstat=%r thermal=%r errors=%r"
            % (f.load1, f.mem_available_kb, f.mem_source, f.uptime_s,
               f.mdstat_text is not None, f.thermal_max_c, f.errors))

        # The disks come from the real filesystem; grading is made
        # deterministic with figures, and the preload's own reading is checked
        # separately in test_disk_uses_the_worst_mount.
        _disk(f, {"/": 50.0})
        ctx.system.mounts = ("/",)
        for cls in (system_checks.SystemLoad, system_checks.SystemMemory,
                    system_checks.SystemRaid, system_checks.SystemThermal,
                    system_checks.SystemUptime, system_checks.SystemDisk):
            res = _run(cls, ctx)
            results.check(
                "%s grades OK on a healthy host" % cls.id,
                res.status is store.Status.OK,
                "status=%r subject=%r detail=%r"
                % (res.status, res.subject, res.detail))
    finally:
        import shutil
        shutil.rmtree(root, ignore_errors=True)


def test_threshold_breaches_grade_warn_and_fail(results):
    import shutil
    root = tempfile.mkdtemp()
    try:
        n = max(1, os.cpu_count() or 1)

        _tree(root, {"proc/loadavg": "%f 0 0 1/1 1\n" % (1.5 * n)})
        ctx, _ = _ctx(root)
        _disk(ctx.system_facts, {"/": 50.0})
        ctx.system.mounts = ("/",)
        res = _run(system_checks.SystemLoad, ctx)
        results.check(
            "a load between green and amber is WARN",
            res.status is store.Status.WARN,
            "load1=%r cpu_count=%r status=%r detail=%r"
            % (ctx.system_facts.load1, n, res.status, res.detail))

        _tree(root, {"proc/loadavg": "%f 0 0 1/1 1\n" % (3.0 * n)})
        ctx, _ = _ctx(root)
        _disk(ctx.system_facts, {"/": 50.0})
        ctx.system.mounts = ("/",)
        res = _run(system_checks.SystemLoad, ctx)
        results.check(
            "a load above amber is FAIL",
            res.status is store.Status.FAIL,
            "load1=%r cpu_count=%r status=%r detail=%r"
            % (ctx.system_facts.load1, n, res.status, res.detail))

        for kb, want, name in ((409600, store.Status.WARN, "400 MB is WARN"),
                               (102400, store.Status.FAIL, "100 MB is FAIL")):
            _tree(root, {"proc/meminfo": MEMINFO.replace(
                "MemAvailable:   1048576 kB",
                "MemAvailable:   %d kB" % kb)})
            ctx, _ = _ctx(root)
            res = _run(system_checks.SystemMemory, ctx)
            results.check(
                "available memory: %s" % name,
                res.status is want,
                "status=%r detail=%r" % (res.status, res.detail))

        for mdeg, want, name in ((85000, store.Status.WARN, "85 C is WARN"),
                                 (95000, store.Status.FAIL, "95 C is FAIL")):
            _tree(root, {"sys/class/thermal/thermal_zone0/temp": "%d\n" % mdeg})
            ctx, _ = _ctx(root)
            res = _run(system_checks.SystemThermal, ctx)
            results.check(
                "thermal: %s" % name,
                res.status is want,
                "status=%r detail=%r" % (res.status, res.detail))

        _tree(root)
        ctx, _ = _ctx(root)
        ctx.system.mounts = ("/",)
        for pct, want, name in ((7.0, store.Status.WARN, "7% free is WARN"),
                                (3.0, store.Status.FAIL, "3% free is FAIL")):
            _disk(ctx.system_facts, {"/": pct})
            res = _run(system_checks.SystemDisk, ctx)
            results.check(
                "free space: %s" % name,
                res.status is want,
                "status=%r detail=%r" % (res.status, res.detail))
    finally:
        shutil.rmtree(root, ignore_errors=True)


# ---------------------------------------------------------------------------
# Missing inputs are UNKNOWN, never green
# ---------------------------------------------------------------------------


def test_missing_figures_are_unknown_never_green(results):
    import shutil
    root = tempfile.mkdtemp()
    try:
        _tree(root, {"proc/loadavg": ABSENT,
                     "proc/meminfo": ABSENT,
                     "proc/uptime": ABSENT,
                     "sys/class/thermal/thermal_zone0/temp": ABSENT})
        ctx, _ = _ctx(root)
        for cls, must_say in (
                (system_checks.SystemLoad, "load average"),
                (system_checks.SystemMemory, "memory"),
                (system_checks.SystemUptime, "uptime"),
                (system_checks.SystemThermal, "no thermal zones")):
            res = _run(cls, ctx)
            results.check(
                "%s is UNKNOWN when its file is missing" % cls.id,
                res.status is store.Status.UNKNOWN
                and must_say in res.detail,
                "status=%r detail=%r -- an absent figure is not zero"
                % (res.status, res.detail))
        results.check(
            "the unreadable sections carry a reason for the checks to state",
            "loadavg" in ctx.system_facts.errors
            and "meminfo" in ctx.system_facts.errors
            and "uptime" in ctx.system_facts.errors,
            "errors=%r" % (ctx.system_facts.errors,))
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_partial_thermal_read_is_unknown(results):
    import shutil
    root = tempfile.mkdtemp()
    try:
        _tree(root)
        # A second zone exists but cannot be read. A directory named `temp`
        # fails the open deterministically, without depending on file modes
        # (which root would bypass).
        os.makedirs(os.path.join(root, "sys/class/thermal/thermal_zone1/temp"))
        ctx, _ = _ctx(root)
        f = ctx.system_facts
        res = _run(system_checks.SystemThermal, ctx)
        results.check(
            "a partial thermal read is UNKNOWN, never the readable maximum",
            f.thermal_zones == 2
            and f.thermal_values.get(
                os.path.join(root, "sys/class/thermal/thermal_zone0/temp")) == 45.0
            and res.status is store.Status.UNKNOWN
            and "thermal_zone1" in res.detail,
            "zones=%r values=%r unreadable=%r status=%r detail=%r -- the "
            "unreadable zone may be the hottest"
            % (f.thermal_zones, f.thermal_values, f.thermal_unreadable,
               res.status, res.detail))
        results.check(
            "the readable zones still travel in the evidence",
            res.evidence.get("values")
            == {os.path.join(root, "sys/class/thermal/thermal_zone0/temp"): 45.0}
            and bool(res.evidence.get("unreadable")),
            "evidence=%r" % (res.evidence,))
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_a_bad_meminfo_value_is_unknown_not_zero(results):
    import shutil
    root = tempfile.mkdtemp()
    try:
        # MemAvailable absent and the fallback fields absent: the pre-3.14
        # formula cannot be computed, so there is no number to grade.
        _tree(root, {"proc/meminfo": "MemTotal: 2048000 kB\n"})
        ctx, _ = _ctx(root)
        res = _run(system_checks.SystemMemory, ctx)
        results.check(
            "a meminfo without any availability field is UNKNOWN, not 0 MB",
            res.status is store.Status.UNKNOWN,
            "status=%r detail=%r" % (res.status, res.detail))
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_disk_uses_the_worst_mount_and_names_it(results):
    import shutil
    root = tempfile.mkdtemp()
    try:
        _tree(root)
        ctx, _ = _ctx(root)
        ctx.system.mounts = ("/", "/data")
        _disk(ctx.system_facts, {"/": 50.0, "/data": 7.0})
        res = _run(system_checks.SystemDisk, ctx)
        results.check(
            "the lowest free percentage is graded, with the constant subject",
            res.status is store.Status.WARN and res.subject == "disk",
            "status=%r subject=%r detail=%r"
            % (res.status, res.subject, res.detail))
        results.check(
            "the worst mount is named in the detail and evidence, and every "
            "mount is listed so an unlisted one cannot look fine",
            res.evidence.get("worst") == "/data"
            and "/data" in res.detail and "/" in res.detail
            and set(res.evidence["mounts"]) == {"/", "/data"},
            "detail=%r evidence=%r" % (res.detail, res.evidence))

        # ANY unreadable configured mount makes the whole check UNKNOWN: the
        # readable ones are carried as evidence, but a subset is not the answer
        # the operator asked for.
        ctx.system.mounts = ("/", "/no-such-mount")
        _disk(ctx.system_facts, {"/": 50.0})
        ctx.system_facts.errors["disk:/no-such-mount"] = \
            "cannot stat /no-such-mount: No such file or directory"
        res = _run(system_checks.SystemDisk, ctx)
        results.check(
            "one unreadable mount makes the check UNKNOWN and names it",
            res.status is store.Status.UNKNOWN
            and res.subject == "disk"
            and "/no-such-mount" in res.detail
            and res.evidence["readable"] == ctx.system_facts.disks,
            "status=%r subject=%r detail=%r evidence=%r"
            % (res.status, res.subject, res.detail, res.evidence))

        ctx.system.mounts = ("/no-such-mount",)
        ctx.system_facts.disks = {}
        res = _run(system_checks.SystemDisk, ctx)
        results.check(
            "no readable mount at all is UNKNOWN with the mount named",
            res.status is store.Status.UNKNOWN and "/no-such-mount" in res.detail,
            "status=%r detail=%r" % (res.status, res.detail))

        # FINDING 6: a configured path that exists but is NOT a mount point is
        # unreadable. `disk_usage` would grade its PARENT filesystem and report
        # a healthy answer about a different question.
        subdir = os.path.join(root, "not-a-mount")
        os.makedirs(subdir, exist_ok=True)
        ctx, _ = _ctx(root, mounts=subdir)
        ctx.system_facts.disks = {}
        res = _run(system_checks.SystemDisk, ctx)
        results.check(
            "a configured path that is not a mount point is UNKNOWN, not the "
            "parent filesystem's free space",
            res.status is store.Status.UNKNOWN
            and subdir in res.detail and "not a mount point" in res.detail,
            "status=%r detail=%r errors=%r"
            % (res.status, res.detail, ctx.system_facts.errors))
    finally:
        shutil.rmtree(root, ignore_errors=True)


# ---------------------------------------------------------------------------
# RAID parsing
# ---------------------------------------------------------------------------


def test_raid_states(results):
    import shutil
    root = tempfile.mkdtemp()
    try:
        for mdstat, want, name, must_say in (
                (MDSTAT_CLEAN, store.Status.OK, "all [UU] is OK", "md0"),
                (MDSTAT_UNPOPULATED, store.Status.OK,
                 "a phantom slot [U_] is OK, not degraded", "unpopulated"),
                (MDSTAT_QTS_SLOTS, store.Status.OK,
                 "QTS's 128-slot system array is OK with two disks",
                 "unpopulated"),
                (MDSTAT_FAULTY, store.Status.FAIL,
                 "a faulty member [UF] is FAIL", "FAULTY"),
                (MDSTAT_RESYNC, store.Status.WARN, "a resync is WARN", "md0"),
                (MDSTAT_SCRUB, store.Status.OK,
                 "a scrub (check=) is OK, not an array-loss risk", "md0"),
                (MDSTAT_MISSING_AND_RESYNC, store.Status.UNKNOWN,
                 "an ungradeable array is UNKNOWN even while another resyncs",
                 "md0"),
                (ABSENT, store.Status.UNKNOWN, "no mdstat is UNKNOWN",
                 "no /proc/mdstat")):
            _tree(root, {"proc/mdstat": mdstat})
            ctx, _ = _ctx(root)
            res = _run(system_checks.SystemRaid, ctx)
            results.check(
                "RAID: %s" % name,
                res.status is want and res.subject == "md" and must_say in res.detail,
                "status=%r subject=%r detail=%r"
                % (res.status, res.subject, res.detail))
    finally:
        shutil.rmtree(root, ignore_errors=True)


# ---------------------------------------------------------------------------
# Uptime is informational
# ---------------------------------------------------------------------------


def test_uptime_is_informational_and_uncounted(results):
    import shutil
    root = tempfile.mkdtemp()
    try:
        _tree(root)
        ctx, _ = _ctx(root)
        res = _run(system_checks.SystemUptime, ctx)
        tally = web._tally({"tiles": [], "extra": [], "others": [],
                            "informational": [{"status": res.status.value}]})
        results.check(
            "uptime reads OK and is declared informational",
            res.status is store.Status.OK
            and system_checks.SystemUptime.informational is True
            and res.subject == "uptime" and "up 1 d" in res.detail,
            "status=%r informational=%r subject=%r detail=%r"
            % (res.status, system_checks.SystemUptime.informational,
               res.subject, res.detail))
        results.check(
            "an informational OK row is not counted as a green verdict",
            tally == {"green": 0, "amber": 0, "red": 0, "grey": 0,
                      "informational": 1},
            "tally=%r -- a thermometer reading is not a health statement"
            % (tally,))
    finally:
        shutil.rmtree(root, ignore_errors=True)


# ---------------------------------------------------------------------------
# Selection and disablement: the platform paths, with no platform change
# ---------------------------------------------------------------------------


def test_uptime_lands_in_the_dashboard_informational_bucket(results):
    import shutil
    root = tempfile.mkdtemp()
    try:
        _tree(root)
        cfg = config_mod.Config(env={
            "SENTINEL_MODULES": "system",
            "MONITOR_CHECKS": os.path.join(os.path.dirname(HERE), "checks.conf"),
            "SYSTEM_PROC": os.path.join(root, "proc"),
            "SYSTEM_SYS": os.path.join(root, "sys"),
            "SYSTEM_MOUNTS": "/",
        })
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        store.init(conn)
        seq = store.next_epoch_seq(conn)
        store.record_collector_run(conn, seq, 1, 1, 0, None)
        store.record_check(conn, seq, "local", "system_uptime",
                           store.Status.OK, "up 1 d 2 h")
        state = web.build_state(cfg, conn)
        info = [i["check_id"] for i in state["informational"]]
        coloured = [i["check_id"] for i in state["tiles"] + state["others"]]
        verdict = [i["check_id"] for i in web._verdict_items(state)]
        results.check(
            "an OK system_uptime is in `informational`, not `others` or a tile",
            info == ["system_uptime"] and "system_uptime" not in coloured,
            "informational=%r tiles+others=%r -- a spec-less informational "
            "check is classified by `spec is None` first and would be counted"
            % (info, coloured))
        results.check(
            "and it is not a verdict-bearing row",
            "system_uptime" not in verdict,
            "verdict items=%r -- an uptime reading became a health statement"
            % (verdict,))
        conn.close()
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_a_check_without_preload_is_unknown(results):
    cfg = config_mod.Config(env={"SENTINEL_MODULES": "system"})
    mod = [m for m in loader.discover_enabled(cfg) if m.id == "system"][0]
    ctx = checks.Context(cfg, {}, {}, modules=[mod])
    res = system_checks.SystemLoad().run(ctx)
    results.check(
        "a check run with no preloaded facts is UNKNOWN, not healthy or a crash",
        res.status is store.Status.UNKNOWN
        and "preload did not run" in res.detail,
        "status=%r detail=%r" % (res.status, res.detail))


def test_selector_excludes_system(results):
    cfg = config_mod.Config(env={"SENTINEL_MODULES": "fleet"})
    results.check(
        "SENTINEL_MODULES=fleet leaves the system module out",
        [m.id for m in loader.discover_enabled(cfg)] == ["fleet"],
        "enabled=%r" % ([m.id for m in loader.discover_enabled(cfg)],))


def test_disabling_system_freezes_only_its_own_incidents(results):
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    store.init(conn)
    try:
        seq = store.next_epoch_seq(conn)
        for _ in range(store.CONFIRM_POLLS):
            store.sync_incident(conn, seq, "local", "system_load1_per_cpu",
                                "cpu", store.Status.FAIL, "high")
            store.sync_incident(conn, seq, "local", "system_mem_available_mb",
                                "mem", store.Status.FAIL, "low")
            # A fleet check shares nothing with the system module but the
            # store; disabling system must not touch it.
            store.sync_incident(conn, seq, "cubox-1", "mem_available_mb",
                                "mem", store.Status.FAIL, "low")

        mods = loader.discover()
        fleet = [m for m in mods if m.id == "fleet"][0]
        collect.freeze_disabled_modules(conn, seq, [fleet], all_modules=mods)
        rows = {(r["target"], r["check_id"]): r for r in conn.execute(
            "SELECT target, check_id, state, severity, resolved_at FROM incident")}

        results.check(
            "the disabled module's incidents are frozen, not resolved",
            rows[("local", "system_load1_per_cpu")]["state"] == "unknown"
            and rows[("local", "system_load1_per_cpu")]["resolved_at"] is None
            and rows[("local", "system_mem_available_mb")]["state"] == "unknown",
            "rows=%r" % ({k: dict(v) for k, v in rows.items()},))
        results.check(
            "a different module's incident is untouched",
            rows[("cubox-1", "mem_available_mb")]["state"] == "open"
            and rows[("cubox-1", "mem_available_mb")]["resolved_at"] is None,
            "cubox-1 row=%r -- ownership is by check id, never by target"
            % (dict(rows[("cubox-1", "mem_available_mb")]),))
    finally:
        conn.close()


TESTS = (test_discovery_finds_fleet_then_system,
         test_every_threshold_is_claimed_by_a_check,
         test_healthy_readings_grade_ok,
         test_threshold_breaches_grade_warn_and_fail,
         test_missing_figures_are_unknown_never_green,
         test_partial_thermal_read_is_unknown,
         test_a_bad_meminfo_value_is_unknown_not_zero,
         test_disk_uses_the_worst_mount_and_names_it,
         test_raid_states,
         test_uptime_is_informational_and_uncounted,
         test_uptime_lands_in_the_dashboard_informational_bucket,
         test_a_check_without_preload_is_unknown,
         test_selector_excludes_system,
         test_disabling_system_freezes_only_its_own_incidents)
