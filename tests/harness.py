"""The tiny test harness these offline suites share.

Deliberately not unittest: the repo's other suites (`test-worker.sh`,
`test-verify-transcode.sh`) print a PASS/FAIL line per check with a diagnostic
that explains what a failure MEANS, and the diagnostic is the point. A bare
`assertEqual` tells the reader what changed; it does not tell them which bug they
just reintroduced. Every `check()` here takes a `detail` written for the second
reader, and the two mutation experiments in test_collect_offline.py depend on
those details being specific enough to name the fault.
"""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
MONITOR = os.path.dirname(HERE)
APP = os.path.join(MONITOR, "app")
FIXTURES = os.path.join(HERE, "fixtures")
CHECKS_CONF = os.path.join(MONITOR, "checks.conf")

if APP not in sys.path:
    sys.path.insert(0, APP)

# ---------------------------------------------------------------------------
# NO SUITE MAY SSH ANYWHERE, AND UNTIL 2026-10-06 NOTHING ENFORCED THAT.
#
# run_all's own footer claims "no fleet access, asserted by the transport stubs",
# and `test_no_suite_leaked_a_transport_stub` checks only that a stub was not left
# INSTALLED -- not that one was in place when it mattered. Every suite's offline
# property therefore rested on the tests happening to take paths that preload their
# inputs, and a check whose branch moved could silently open a socket to a CuBox.
#
# Measured: deleting the `not ref_md5` guard in WorkerDrift made test_shared_layer
# call `probes.ssh` against 198.51.100.31 for real. On a Mac the call fails fast
# against the missing key, so the suite stayed green and 4 seconds long, and nothing
# said a packet had been sent (items 46/62: the answer is no, I could not ask, and I
# never asked must not share a branch).
#
# So the default is now a hard refusal, and a suite that wants the transport stubs
# it (which is what they already do -- they replace these attributes, so they compose
# with this rather than fight it). The message names the host, because the fix is
# almost always "preload the thing this check reads".
# ---------------------------------------------------------------------------
import probes as _probes                                          # noqa: E402


def _no_ssh(host, cmd, *a, **k):
    raise AssertionError(
        "an offline suite tried to ssh to %s (%r). Preload the input instead: "
        "this suite must not touch the fleet." % (getattr(host, "address", host),
                                                  (cmd or "")[:60]))


_probes.ssh = _no_ssh


class Results:
    def __init__(self):
        self.rows = []

    def check(self, name, ok, detail=""):
        self.rows.append((name, bool(ok), detail))
        return ok

    def report(self, title):
        bad = 0
        print(title)
        for name, ok, detail in self.rows:
            print("  [%s] %s" % ("PASS" if ok else "FAIL", name))
            if not ok:
                bad += 1
                for line in (detail or "").splitlines():
                    print("         %s" % line)
        print("\n%d checks, %d failed" % (len(self.rows), bad))
        return 1 if bad else 0


def read_fixture(name):
    with open(os.path.join(FIXTURES, name)) as fh:
        return fh.read()
