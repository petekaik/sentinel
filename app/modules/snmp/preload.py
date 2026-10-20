"""The SNMP module's preload: one bounded GET per configured OID, per epoch.

Every poll happens here, before any check runs, and the results are installed on
`ctx.snmp_facts`. A check then never opens a socket -- which is the same rule
the fleet module follows, and it is what bounds an epoch: a device that does not
answer costs `SNMP_TIMEOUT_S` (plus the client's single retry), not an unbounded
check.

`ok` MEANS "THE DEVICE ANSWERED", NOT "EVERY OID WAS GOOD". The distinction is
load-bearing twice over:

  * a `noSuchObject` reply is an ANSWER. The device is up; the OID is wrong. The
    reachability row stays OK and the OID row is UNKNOWN with the error.
  * only a timeout or a transport failure makes the device not-ok, which is the
    one case where `SnmpReachable` has something to FAIL about.

No `ctx.attempt`. The platform's attempt registry answers "can we see this ssh
host?" and feeds `host_unreachable` escalation; an SNMP device is not an ssh
host, and a row raised through it would be owned by the wrong module.
"""

from modules.snmp import snmp
from modules.snmp.checks import SYSTEM_UPTIME_OID
from modules.snmp.settings import SnmpConfig

# "I could not ask" -- as distinct from every SnmpError that carries an ANSWER
# (no such object, an error-status, a malformed reply from a host that is
# plainly alive). The client exposes the transport half as its own type so this
# distinction is not a message-prefix match.
_TRANSPORT = (snmp.SnmpTimeout, snmp.SnmpTransportError)


def configure(ctx):
    """Install the module's configuration. NO I/O."""
    cfg = SnmpConfig(ctx.cfg, ctx.cfg.env)
    ctx.snmp = cfg
    ctx.module_cfg["snmp"] = cfg
    return cfg


def preload(ctx):
    """Poll every enabled device once and install `ctx.snmp_facts`."""
    cfg = ctx.snmp
    facts = {}
    for dev in cfg.devices:
        if not dev["enabled"]:
            continue
        # A device with no checks still gets ONE poll: "is it up?" is the one
        # question every configured device can answer, and a device that never
        # appears on the board is one the operator believes is monitored.
        oids = list(dict.fromkeys(
            row["oid"] for row in cfg.checks if row["device"] == dev["name"]))
        if not oids:
            oids = [SYSTEM_UPTIME_OID]
        facts[dev["name"]] = _poll(dev, oids, cfg.timeout_s)
    ctx.snmp_facts = facts
    return facts


def _poll(dev, oids, timeout):
    entry = {"ok": False, "why": "", "oids": {}}
    answered = False
    why = ""
    for oid in oids:
        try:
            value, kind = snmp.get(dev["address"], dev["community"], oid,
                                   port=dev["port"], timeout=timeout)
        except _TRANSPORT as exc:
            why = why or str(exc)
            entry["oids"][oid] = {"value": None, "type": None,
                                  "error": str(exc)}
        except snmp.SnmpError as exc:
            answered = True
            entry["oids"][oid] = {"value": None, "type": None,
                                  "error": str(exc)}
        except Exception as exc:              # noqa: BLE001 - isolated per OID
            # The client promises SnmpError for every failure; anything else is
            # a defect on OUR side, so it must not be read as a healthy answer.
            why = why or "unexpected client error: %s" % exc
            entry["oids"][oid] = {"value": None, "type": None,
                                  "error": "unexpected client error: %s" % exc}
        else:
            answered = True
            entry["oids"][oid] = {"value": value, "type": kind, "error": ""}
    entry["ok"] = answered
    entry["why"] = "" if answered else (why or "no answer")
    return entry
