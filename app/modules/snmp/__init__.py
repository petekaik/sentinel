"""Network devices over SNMP v2c.

The module package exists from Task 8 with a skeleton `MODULE` so the loader
discovers it: a package under `app/modules/` without one is a startup error,
which is a louder failure than the task that adds the checks arriving later.
Settings, preload and checks are Task 9; the codec and the client they use
(`ber.py`, `snmp.py`) are here and tested.
"""

from module import Module

MODULE = Module(
    id="snmp", title="Network devices", order=30, targets=("snmp",),
    settings=(), threshold_file="thresholds.conf")
