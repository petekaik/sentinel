# Module `snmp` — network devices over SNMP v2c

Generic, settings-driven monitoring for switches, PDUs, UPSes and anything else
with an SNMP agent. There is no per-device code: a device and each OID to poll
are rows in the settings, and saving a row makes it appear on the next
collection.

**Read-only, v2c only.** The module issues `GET` requests and nothing else; it
never writes to a device, never sends a `SET`, and never walks a subtree. SNMP
v3 (USM/encryption) is not implemented, and a device configured with any
version other than `v2c` is refused when the settings are parsed rather than
silently polled with the wrong protocol.

Every address in this file and in `.env.example` is documentation-range
placeholder; real device addresses belong in the gitignored `.env` or the
settings page.

## The model

```
SNMP_DEVICES   one row per device:  name, address, port, community, version, enabled
SNMP_CHECKS    one row per OID:     device, oid, label, unit, direction, green, amber, kind, expected
```

For each **enabled device** the module produces:

| Row | Check id | Subject | Grades |
|---|---|---|---|
| reachability | `snmp_reachable` | `<device>` | FAIL when the device did not answer; OK when it did |
| one per OID row | `snmp_<device>_<slug>` | `<device>:<label>` | the row's band, or its `state` equality |

All rows report under the single target `snmp`. The device identity lives in
the **subject**, because the incident key is `(target, check_id, subject)` —
two devices share the target and must not share a verdict.

A device with **no** OID rows still gets the reachability poll (a `GET` of
`sysUpTime.0`), so "configured and never polled" cannot happen.

Dynamic threshold bands are registered in `ctx.dynamic_specs` as the instances
are built: every OID row gets a spec and a metric named
`snmp.<device>.<slug>`, carrying that row's unit, direction, green and amber.
Spec ids are namespaced by module, so they cannot collide with a
`thresholds.conf` spec. Two rows with the same label get distinct slugs
(`cpu_load`, `cpu_load_2`) because the dashboard looks a reading up by metric
name.

## Grading

`kind` is one of:

| kind | Uses | Verdict |
|---|---|---|
| `gauge` | a numeric reading with a band | `result_from_spec`: OK / WARN / FAIL against `green`/`amber`, ordered by `direction` |
| `state` | a numeric equality, e.g. `ifOperStatus` | FAIL when `value != expected`, OK otherwise |

`direction` is `high_is_good` (OK when `value >= green`; WARN down to `amber`)
or `low_is_good` (the mirror). The amber boundary must sit on the WARN side of
green — `SNMP_CHECKS` refuses a band whose WARN range is unreachable.

Everything that is not a reading is **UNKNOWN**, never green:

| Situation | Reachability | OID row |
|---|---|---|
| timeout / no answer / transport error | **FAIL** naming device and error | UNKNOWN (the reachability row is the FAIL) |
| `noSuchObject`, `noSuchInstance`, an error-status | OK — the device answered | UNKNOWN naming the OID and the error |
| preload never ran | UNKNOWN | UNKNOWN |
| value that cannot be graded | — | UNKNOWN |

One dead device therefore produces one red row and a column of grey, not a page
of red that buries the cause.

## Save-time validation

`validate_settings` refuses a write (HTTP 422 with the reason) rather than
letting a typo become a grey row an epoch later:

* a check's `device` names no configured device;
* an `oid` is not dotted-numeric (the leading display dot is accepted and
  stripped — the wire form has none);
* a gauge row has no numeric `green`/`amber`, or the band is ordered the wrong
  way for its `direction`;
* a `state` row has no numeric `expected`;
* two devices share a name, or a device's `name`/`address`/`community` is empty;
* a device's `version` is not `v2c`.

The write hook sees only the keys in the request body, and the settings page
sends only the fields the operator touched. A checks-only save therefore
cannot resolve `device` against a device list it was not given; the reference
rule is enforced whenever both lists travel together, which is how the module
is configured initially.

## Settings

| Key | Kind | Default | Meaning |
|---|---|---|---|
| `SNMP_DEVICES` | list | `[]` | devices (fields above) |
| `SNMP_CHECKS` | list | `[]` | OID rows (fields above) |
| `SNMP_TIMEOUT_S` | int | `3` | per-request UDP timeout; one retry is fixed in the client |

`community` is declared `secret` in the row schema: it is never included in a
check detail, evidence or log line, and `snmp.py`'s errors carry the host and
the OID instead. The manifest publishes the field's *declaration*, never a
value.

```bash
# A state row: port 1 must report ifOperStatus up (1).
SNMP_DEVICES='[{"name":"switch-1","address":"192.0.2.200","port":161,
                "community":"change-me","version":"v2c","enabled":true}]'
SNMP_CHECKS='[{"device":"switch-1","oid":"1.3.6.1.2.1.2.2.1.8.1",
               "label":"Port 1 status","kind":"state","expected":1}]'
```

## Files

| File | Role |
|---|---|
| `ber.py` | minimal BER codec (integers, octet strings, OIDs, sequences) |
| `snmp.py` | the v2c `GET` client: bounded UDP timeout, one retry, one error type per failure |
| `settings.py` | parsing (`SnmpConfig`) and the save-time rules (`validate`) |
| `preload.py` | one poll per enabled device per epoch; installs `ctx.snmp_facts` |
| `checks.py` | `SnmpReachable` / `SnmpOid` and the dynamic `instances(ctx)` |
| `thresholds.conf` | deliberately comment-only: bands live on the settings rows |

The module opens no platform attempt row: an SNMP device is not an ssh host, so
a failed poll must not become a fleet `host_unreachable` incident owned by the
wrong module.
