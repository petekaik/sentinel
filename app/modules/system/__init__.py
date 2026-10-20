"""HW/OS system resources of the host the monitor runs on.

The second module, and the module platform's acceptance test: it is one
directory under `app/modules/`, discovered by the loader with no edit to a
platform file. Everything it watches is local -- /proc, /sys, `shutil.disk_usage`
-- so it opens no socket and writes nothing.
"""

from module import Module, Setting

from modules.system import checks as system_checks
from modules.system.preload import context, preload

MODULE = Module(
    id="system",
    title="System resources",
    order=20,
    targets=("local",),
    settings=[
        Setting("SYSTEM_PROC", "/proc"),
        Setting("SYSTEM_SYS", "/sys"),
        Setting("SYSTEM_MOUNTS", "/"),
    ],
    threshold_file="thresholds.conf",
    context=context,
    preload=preload,
    checks=(system_checks,),
)
