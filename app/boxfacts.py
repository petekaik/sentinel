"""Fetch one CuBox's fact block over ssh. The only thing that talks to a box.

WHY THIS IS A SEPARATE, TINY MODULE

Every ssh to a CuBox goes through here, so there is exactly ONE place where the
timeout, the credential and the transport-failure classification live. A check
that opened its own connection would be a second place for those to be wrong,
and the plan's rule is that a check must never be able to HANG -- which is why
the collector pre-fetches every host BEFORE it runs any check, and the checks
read the already-bounded result (`Context.facts`). A check that cannot open a
socket cannot wedge the collection.

THE BOUND IS CLIENT-SIDE, AND THAT IS NOT A STYLE CHOICE

The CuBoxes' /mnt/state mount is HARD -- `nolock,nfsvers=3`, no `soft`, no
`timeo`, no `retrans` (configs/initramfs/scripts/nfs-bottom/cubox-overlay:577).
If Backup-NAS stops answering, any process that touches that path blocks in
D state, and `timeout -s KILL` CANNOT kill D state. The remote `timeout` calls
inside boxfacts.sh are therefore a convenience, not the safety property. The
safety property is `Host.base_args()`'s ConnectTimeout/ServerAliveInterval plus
`subprocess.run(timeout=...)`, which kill the LOCAL ssh client and return
whatever partial stdout arrived. That is the only bound that always works, and
it is why the script's /mnt reads are ordered last.

The partial output is KEPT rather than discarded (`RemoteResult.out` is
populated even on timeout). Facts that arrived before the hang are real facts
and the check layer can use them; the ones that never arrived stay absent, and
absent is UNKNOWN -- which is the correct answer for a box whose state mount is
wedged, and is strictly better than throwing away the reachability evidence too.
"""

import os
import re

import parsers
import probes

_SCRIPT_CACHE = {}


def _script(path):
    """Read the probe script once. It is a constant of the image, not per-box."""
    if path not in _SCRIPT_CACHE:
        try:
            with open(path) as fh:
                _SCRIPT_CACHE[path] = fh.read()
        except OSError as exc:
            _SCRIPT_CACHE[path] = None
            _SCRIPT_CACHE[path + ":err"] = str(exc)
    return _SCRIPT_CACHE[path]


def script_error(path):
    return _SCRIPT_CACHE.get(path + ":err", "")


def pull(host, script_path, timeout=None, write_probe=False):
    """Run the probe on `host` and return a parsers.BoxFacts.

    A missing or unreadable script is a CONFIGURATION defect and comes back as a
    transport-failed BoxFacts, so it surfaces as UNKNOWN with the reason rather
    than as a box that reported nothing. That distinction is the whole point of
    this module's docstring, applied to its own failure mode.
    """
    text = _script(script_path)
    if text is None:
        return parsers.parse_facts(
            "", transport_ok=False,
            why="probe script %s unreadable: %s"
                % (script_path, script_error(script_path)),
        )

    argv_text = "sh -s -- BOXFACTS_WRITE_PROBE=1" if write_probe else "sh -s"
    res = probes.run(host.base_args() + [argv_text],
                     timeout=timeout or host.timeout,
                     stdin=text.encode())

    if not res.ran:
        # A TIMEOUT still carries whatever the box managed to send. Keep it: the
        # facts above the hang are true, and the check layer renders the missing
        # ones UNKNOWN on its own.
        return parsers.parse_facts(
            res.out, transport_ok=False, why=res.why or res.transport.value,
            duration_ms=res.duration_ms,
        )
    if res.rc != 0:
        return parsers.parse_facts(
            res.out, transport_ok=False,
            why="probe exited %s%s" % (res.rc, (": " + res.err.strip()) if res.err.strip() else ""),
            duration_ms=res.duration_ms,
        )
    return parsers.parse_facts(res.out, transport_ok=True,
                               duration_ms=res.duration_ms)


def normalize_worker(text):
    """Reduce worker.sh to the lines that can actually change behaviour.

    THE DRIFT CHECK CANNOT BE AN md5 COMPARISON, and this function is why.

    Measured 2026-09-26: the repo's configs/transcode/worker.sh and the copy
    running on both CuBoxes differ by 518 lines of raw `diff` -- and ZERO of them
    change behaviour. The differences are a `CAPTURE_BUFFERS` default that the
    per-device config overrides, and comment prose. An md5 equality check would
    therefore have reported a PERMANENT FALSE RED on a fleet that is transcoding
    correctly, which item 72 establishes is worse than having no check at all:
    it trains the operator to ignore red.

    So the comparison drops what cannot affect execution:
      * blank lines and whole-line comments
      * trailing comments on a code line (`foo=1  # why` -> `foo=1`)
      * leading/trailing whitespace, which shell ignores
      * the shebang, which is a constant
      * `set -...` option lines, which are identical on the fleet by convention

    and then compares the remaining LINE SEQUENCE, so a reordering or a real
    insertion still shows up. That is a strictly weaker test than md5 and a
    strictly stronger one than "no check", which is the right trade for a
    detector whose job is "has someone edited the worker on one box only".

    Deliberately NOT stripped: quoted `#` inside a string (`printf '%s # %s'`).
    The comment strip is a light heuristic -- it cuts at the first `#` that is
    preceded by whitespace and NOT inside single quotes -- because being wrong in
    that direction only risks a false DRIFT (loud, harmless) rather than a false
    match (silent, the failure mode here).
    """
    out = []
    for line in (text or "").splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if s.startswith("#!"):
            continue
        s = _strip_trailing_comment(s)
        if not s:
            continue
        out.append(s)
    return out


def _strip_trailing_comment(s):
    """Cut a trailing ` # comment`, respecting a simple single-quote state."""
    in_single = False
    for i, ch in enumerate(s):
        if ch == "'":
            in_single = not in_single
        elif ch == "#" and not in_single and i > 0 and s[i - 1] in " \t":
            return s[:i].rstrip()
    return s


def worker_drift(delivered_text, box_text, cfg_values=None):
    """Compare two worker.sh revisions. Returns (verdict, detail).

    verdict is one of:
      "identical"   byte-identical -- nothing to say
      "equivalent"  differs in bytes, but NO functional line differs. This is a
                    comment, or a dead default (see below). The fleet is running
                    correct code.
      "drifted"     a functional line differs -- the two disagree about what the
                    worker DOES.
      "unknown"     one side was unavailable

    NEITHER SIDE IS THE MONITOR'S OWN COPY (item 90). `delivered_text` is the
    worker.sh of the generation the box applied, and `box_text` is the box's live
    /etc copy; checks/cubox.py pulls both from the box. The names say which is
    which, not which one is right -- this function only reports that they differ,
    and the check decides what that means.

    THE CONFIG-OVERRIDE RULE, AND WHY IT IS NECESSARY

    A line of the form

        CAPTURE_BUFFERS="${CAPTURE_BUFFERS:-16}"

    is DEAD CODE whenever the per-device config sets CAPTURE_BUFFERS -- the
    config is sourced after this default, so the default can never be selected.
    Measured 2026-09-26 this is exactly one of the two differences between the
    repo's worker.sh and the copy on both CuBoxes (`:-64` in the repo, `:-16` on
    the boxes, and both boxes' config says `CAPTURE_BUFFERS 64`), so a drift
    check that counted it would flag a fleet that is transcoding correctly.

    The rule is evaluated against the BOX's effective config (`cfg_values`), not
    against the repo's, because the box is the thing being judged. And it is
    correct in the dangerous direction too: if the config ever DROPS
    CAPTURE_BUFFERS, the default becomes live, the two revisions become
    genuinely different, and the check goes to "drifted" -- which is the right
    alarm, because item 70 measured 16 capture buffers deadlocking the encoder.

    A caveat the caller must respect: `cfg_values` must be the values the worker
    actually sources. If it is empty or unavailable, NOTHING is dead and every
    difference counts, which errs toward reporting drift rather than hiding it.
    """
    if delivered_text is None or box_text is None:
        return "unknown", "one side of the comparison is unavailable"
    if delivered_text == box_text:
        return "identical", "byte-identical"

    a = normalize_worker(delivered_text)
    b = normalize_worker(box_text)
    if a == b:
        return "equivalent", ("byte-differs but no code line differs "
                              "(%d code lines compared)" % len(a))

    cfg = set(cfg_values or ())
    dead, func = _classify_diffs(a, b, cfg)
    if func:
        return "drifted", ("%d functional difference(s), %d dead default(s); "
                           "first: %s" % (len(func), len(dead), func[0]))
    return "equivalent", ("%d code line(s) differ, all dead defaults overridden "
                          "by the per-device config (%s)"
                          % (len(dead), ", ".join(sorted(set(dead))) or "-"))


_VAR_DEFAULT = re.compile(r'^(?:export\s+)?([A-Z][A-Z0-9_]*)="\$\{\1:-.*\}"$')


def _classify_diffs(a, b, cfg):
    """Split the difference between two normalized scripts into dead and real.

    Uses SequenceMatcher rather than a pairwise walk so an INSERTION or DELETION
    does not desynchronise every following line into a false difference -- a
    naive index-by-index comparison reports the rest of the file as changed the
    moment one line is added, which is the loudest possible false positive.
    """
    import difflib
    dead, func = [], []
    sm = difflib.SequenceMatcher(a=a, b=b, autojunk=False)
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal":
            continue
        if tag == "replace" and (i2 - i1) == (j2 - j1):
            for k in range(i2 - i1):
                la, lb = a[i1 + k], b[j1 + k]
                m1, m2 = _VAR_DEFAULT.match(la), _VAR_DEFAULT.match(lb)
                if m1 and m2 and m1.group(1) == m2.group(1) and m1.group(1) in cfg:
                    dead.append(m1.group(1))
                else:
                    func.append("repo %r vs box %r" % (la[:60], lb[:60]))
        else:
            # An insertion or deletion can never be a dead default: it changes
            # which lines exist, not which value wins.
            extra = a[i1:i2] or b[j1:j2]
            func.append("%s %r" % (tag, (extra[0] if extra else "")[:60]))
    return dead, func


