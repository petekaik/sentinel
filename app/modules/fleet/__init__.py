"""The CuBox fleet: two transcoders and the two NASes they depend on."""

from module import Module, Setting

from modules.fleet import checks as fleet_checks
from modules.fleet.preload import after_epoch, context, preload

MODULE = Module(
    id="fleet",
    title="CuBox fleet",
    order=10,
    targets=("cubox-1", "cubox-2", "backup", "storage", "fleet"),
    settings=[
        Setting("CUBOX_IDS", "cubox-1,cubox-2"),
        Setting("MONITOR_HOST_CUBOX_1_ADDR", "198.51.100.31"),
        Setting("MONITOR_HOST_CUBOX_2_ADDR", "198.51.100.32"),
        Setting("MONITOR_HOST_BACKUP_ADDR", "198.51.100.20"),
        Setting("MONITOR_LOCAL_HOST", "storage"),
        Setting("RECORDINGS_PATH", ""),
        Setting("TRANSCODED_PATH", ""),
        Setting("MONITOR_REMEDIES", "0", "bool"),
    ],
    threshold_file="thresholds.conf",
    context=context,
    preload=preload,
    checks=(fleet_checks.cubox, fleet_checks.fleet, fleet_checks.storage,
            fleet_checks.backup, fleet_checks.serial),
    after_epoch=after_epoch,
)
