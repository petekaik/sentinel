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
SNMP_DEVICES      one row per device:  name, address, port, version, enabled
SNMP_COMMUNITIES  the secret map:      {device name: community string}
SNMP_CHECKS       one row per OID:     device, oid, label, unit, direction, green, amber, kind, expected
```

The community lives in its own setting because it is a **secret**: the settings
API and the audit log redact a whole setting declared `secret=True`, and there
is no item-level secret machinery. A `community` field inside `SNMP_DEVICES`
would be published by `GET /api/v1/settings` and written in clear into the
change log. `SNMP_COMMUNITIES` is therefore write-only -- the read surface says
only that it is set, and a blank value on save means **unchanged** (use DELETE
to remove the override).

For each **enabled device** the module produces:

| Row | Check id | Subject | Grades |
|---|---|---|---|
| reachability | `snmp_reachable` | `<device>` | FAIL when the device did not answer; OK when it did |
| one per OID row | `snmp_<device>_<slug>` | `<device>:<label>` | the row's band, or its `state` equality |

All rows report under the single target `snmp`. The device identity lives in
the **subject**, because the incident key is `(target, check_id, subject)` —
two devices share the target and must not share a verdict.

A device with **no** OID rows still gets the reachability poll (a `GET` of
`sysUpTime.0`), so "configured and never polled" cannot happen. A device with
**no community entry** is not polled at all: its reachability row is FAIL
naming `SNMP_COMMUNITIES`, and its OID rows are UNKNOWN. Polling with a blank
credential would either be refused by the agent or silently succeed against an
agent that accepts one -- and the operator would never learn the credential is
missing.

A check row whose device is **absent** from `SNMP_DEVICES` (a typo in `.env`,
or a device removed while its rows stayed) is an UNKNOWN row naming the missing
device, never a dropped row: a row that vanishes reads exactly like a green
one. A device that is present but **disabled** is a decision, not a typo -- its
rows stop reporting entirely.

One epoch's SNMP cost is bounded by devices x distinct OIDs x (timeout x 2
attempts). There is no aggregate deadline: a very large device list lengthens
the epoch rather than truncating it (a documented follow-up if one ever does).

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
* two devices share a name, or a device's `name`/`address` is empty;
* a device's `version` is not `v2c`, or its `port` is outside 1..65535;
* a device has no non-empty entry in `SNMP_COMMUNITIES`, or the map names a
  device that is not configured, or a value is not a non-empty string;
* a `community` field appears inside a device row (it belongs in the map);
* `SNMP_TIMEOUT_S` is below 1.

The settings page sends only the fields the operator touched, and a checks-only
save must still be checked against the devices it names. `write_settings`
therefore resolves the effective values first -- the body over the stored
override over `.env` over the declaration's default -- and passes that MERGED
set to the hook. Passing a partial dict to `validate_settings` directly is
still legal (a rule whose other half is absent is skipped), but the API never
does it.

## Settings

| Key | Kind | Default | Meaning |
|---|---|---|---|
| `SNMP_DEVICES` | list | `[]` | devices (fields above) |
| `SNMP_COMMUNITIES` | json | `{}` | **secret** map of device name to community |
| `SNMP_CHECKS` | list | `[]` | OID rows (fields above) |
| `SNMP_TIMEOUT_S` | int | `3` | per-request UDP timeout (>= 1); one retry is fixed in the client |

`SNMP_COMMUNITIES` is `secret=True`, so the read API reports only `secret_set`
and the audit log stores `<redacted>` on both the old and the new side of every
write. It never reaches a check detail, evidence or log line, and `snmp.py`'s
errors carry the host and the OID instead.

```bash
# A state row: port 1 must report ifOperStatus up (1).
SNMP_DEVICES='[{"name":"switch-1","address":"192.0.2.200","port":161,
                "version":"v2c","enabled":true}]'
SNMP_COMMUNITIES='{"switch-1":"change-me"}'
SNMP_CHECKS='[{"device":"switch-1","oid":"1.3.6.1.2.1.2.2.1.8.1",
               "label":"Port 1 status","kind":"state","expected":1}]'
```

## Files

| File | Role |
|---|---|
| `ber.py` | minimal BER codec (integers, octet strings, OIDs, sequences) |
| `snmp.py` | the v2c `GET` client: bounded UDP timeout, one retry, one error type per failure |
| `settings.py` | parsing (`SnmpConfig`), the community map, and the save-time rules (`validate`) |
| `preload.py` | one poll per enabled device per epoch; installs `ctx.snmp_facts` |
| `checks.py` | `SnmpReachable` / `SnmpOid` and the dynamic `instances(ctx)` |
| `thresholds.conf` | deliberately comment-only: bands live on the settings rows |

The module opens no platform attempt row: an SNMP device is not an ssh host, so
a failed poll must not become a fleet `host_unreachable` incident owned by the
wrong module.

Disabling the module freezes the incidents its settings created. The ids exist
in no Check class, so the module supplies `owned_check_ids` in its contract and
the platform's disablement freeze, remedy engine and insight attribution all
read it through `module.owned_check_ids(mod, ctx)`; without it, switching the
module off would leave its per-device incidents open forever.
