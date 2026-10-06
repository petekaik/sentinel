#!/usr/bin/env bash
#
# Offline tests for sentinel. NO NETWORK.
#
# The monitor's whole value is that it cannot report a clean fleet while
# measuring nothing, so its tests are contract tests: they assert that absent
# data is never green, that a corrupt status cannot become OK, that nothing in
# the response path is cacheable, and that an outage reaches `open` while a
# one-poll blip leaves no trace. Those are properties, and a property needs a
# test that can fail -- so every suite also asserts the healthy path still
# works, and each guard has been mutation-tested (revert it in a scratch copy and
# watch the suite go red).
#
# The dashboard suite starts a real HTTP server bound to 127.0.0.1 only. That is
# deliberate and asserted in the test: `web.serve()` binds 0.0.0.0, and a test
# must not be able to expose a monitoring page on the LAN by accident.
#
# Usage:
#   ./test.sh              # everything
#   ./test.sh dashboard    # one suite (subject substring)
#
set -euo pipefail

MONITOR_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

PY="${PYTHON:-}"
if [[ -z "$PY" ]]; then
    for cand in python3 /usr/bin/python3 /usr/local/bin/python3; do
        if command -v "$cand" >/dev/null 2>&1; then PY="$cand"; break; fi
    done
fi
if [[ -z "$PY" ]]; then
    echo "FAIL: no python3 found; set PYTHON=/path/to/python3" >&2
    exit 1
fi

# Every Python file in the tree must at least parse, before anything is run.
# The bash analogue is the repo's `bash -n` pre-commit check, and it catches the
# one class of error that a suite importing a module would report as a
# confusing ImportError from somewhere else.
echo "== syntax =="
fail=0
while IFS= read -r f; do
    if ! "$PY" -m py_compile "$f" 2>/tmp/test-monitor-syntax.err; then
        echo "  [FAIL] $f"
        sed 's/^/         /' /tmp/test-monitor-syntax.err
        fail=1
    fi
done < <(find "$MONITOR_ROOT" -name '*.py' -not -path '*/__pycache__/*' | sort)
if [[ "$fail" -eq 0 ]]; then
    echo "  all Python files parse"
else
    rm -f /tmp/test-monitor-syntax.err
    exit 1
fi
rm -f /tmp/test-monitor-syntax.err

exec "$PY" "$MONITOR_ROOT/tests/run_all.py" "$@"
