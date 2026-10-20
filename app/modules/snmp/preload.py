"""The SNMP module's preload: one bounded GET per configured OID, per epoch.

Every poll happens here, before any check runs, and the results are installed on
`ctx.snmp_facts`. A check then never opens a socket -- which is the same rule
the fleet module follows, and it is what bounds an epoch: a device that does not
answer costs `SNMP_TIMEOUT_S` (plus the client's single retry), so the epoch's
SNMP cost is bounded by devices x distinct OIDs x (timeout x 2). There is no
AGGREGATE deadline -- a very large device list lengthens the epoch rather than
truncating it; a follow-up if one ever does.

`ok` MEANS "THE DEVICE ANSWERED", NOT "EVERY OID WAS GOOD". The distinction is
load-bearing twice over:

  * a `noSuchObject` reply is an ANSWER. The device is up; the OID is wrong. The
    reachability row stays OK and the OID row is UNKNOWN with the error;
  * only a timeout, a transport failure or a missing community makes the device
    not-ok, which is the one case where `SnmpReachable` has something to FAIL
    about.

NO COMMUNITY, NO REQUEST. A device with no entry in the secret
`SNMP_COMMUNITIES` map is recorded unreachable with that reason: polling it
"anonymously" would either be refused by the agent or, worse, succeed against
an agent that accepts an empty community, and the operator would never learn
the credential is missing.

No `ctx.attempt`. The platform's attempt registry answers "can we see this ssh
host?" and feeds `host_unreachable` escalation; an SNMP device is not an ssh
host, and a row raised through it would be owned by the wrong module.
"""

from modules.snmp import snmp
from modules.snmp.checks import instances
from modules.snmp.settings import SYSTEM_UPTIME_OID, SnmpConfig

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


def owned_ids(ctx=None):
    """Every check id this module can own, for disablement.

    `check_instances` builds ids that exist in no class list, so the platform's
    static rule cannot see them: without this, disabling the module leaves its
    per-device incidents open forever. `ctx` is a settings-only Context; with
    no ctx only the static reachability id is knowable.
    """
    ids = {"snmp_reachable"}
    if ctx is None:
        return ids
    if getattr(ctx, "snmp", None) is None:
        configure(ctx)
    ids.update(inst.id for inst in instances(ctx))
    return ids


def preload(ctx):
    """Poll every enabled device once and install `ctx.snmp_facts`."""
    cfg = ctx.snmp
    facts = {}
    for dev in cfg.devices:
        if not dev["enabled"]:
            continue
        if not dev["community"]:
            facts[dev["name"]] = {
                "ok": False,
                "why": ("no community is configured for device %r in "
                        "SNMP_COMMUNITIES, so it was not polled"
                        % dev["name"]),
                "oids": {},
            }
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
