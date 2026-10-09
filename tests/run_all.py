"""One entry point for the monitor's offline tests. No fleet access.

`test.sh` calls this and nothing else, so there is exactly one
list of suites -- the same rule this repo applies to the provisioning definition
(item 7) and to the check registry (`checks.all_modules`): a second list is a
second thing to forget to update, and forgetting is not an error, so it fails
silently.

Subject override, matching `test-worker.sh`'s convention: a bare argument runs
only the suites whose title contains it.

    run_all.py            # everything
    run_all.py dashboard  # just the dashboard contract
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from harness import Results                     # noqa: E402

import test_checks_fixtures as fixture_tests    # noqa: E402
import test_collect_offline as collect_tests    # noqa: E402
import test_dashboard as dash_tests             # noqa: E402
import test_incident_lifecycle as incident_tests  # noqa: E402
import test_proxy_config as proxy_tests         # noqa: E402
import test_serial_identity as serial_tests     # noqa: E402
import test_shared_layer as shared_tests        # noqa: E402

SUITES = (
    ("serial -- the CuBox console identity: chip serial, not a /dev/ttyUSB number",
     serial_tests.TESTS),
    ("collect.py -- the collection loop, the escalation state machine, and "
     "the journal cursors",
     collect_tests.TESTS),
    ("store.py -- the incident lifecycle: what may close a row, and what must "
     "never be able to",
     incident_tests.TESTS),
    ("web.py -- the dashboard contract (never green on no data, never cached)",
     dash_tests.TESTS),
    ("checks/* -- the real check classes against verbatim fleet captures",
     fixture_tests.TESTS),
    ("checks/* -- the shared dynamic layer (T2): converging vs stuck, the "
     "subjects incidents resolve by, and worker_drift's box-side authority",
     shared_tests.TESTS),
    ("proxy/ -- the publishing stack's access rules (offline, text-level)",
     proxy_tests.TESTS),
)


def main(argv):
    wanted = argv[1].lower() if len(argv) > 1 else ""
    suites = [(t, fns) for t, fns in SUITES if wanted in t.lower()]
    if not suites:
        print("no suite matches %r; suites are:" % wanted)
        for title, _ in SUITES:
            print("  %s" % title.split(" --")[0])
        return 2

    results = Results()
    for title, fns in suites:
        print("\n== %s ==" % title)
        for fn in fns:
            fn(results)
    return results.report("fleet monitor: offline tests (no fleet access, "
                          "asserted by the transport stubs)")


if __name__ == "__main__":
    sys.exit(main(sys.argv))
