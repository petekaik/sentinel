"""The fleet module's check modules: the one place they are named.

`MODULE.checks` is this tuple, so the collector discovers the checks by
importing the module rather than by keeping a second list in the platform. A
check file added here and not listed still never runs -- but it is listed in
ONE place, next to the code, and `SpecCoverage` reports the consequence from
the other direction (a spec claimed by a check that never runs reads claimed).
"""

from modules.fleet.checks import backup, cubox, fleet, serial, storage
