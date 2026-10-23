# Module `snmp` — network devices over SNMP v2c

Generic, settings-driven monitoring for switches, PDUs, UPSes and anything else
with an SNMP agent. There is no per-device code: a device and each OID to poll
are rows in the settings, and saving a row makes it appear on the next
collection.

**Read-only, v2c only.** The module issues `GET` requests for its checks, plus
the `GETBULK` walk (with a `GETNEXT` fallback) that only the explicit `discover`
operator command uses; it
never writes to a device and never sends a `SET`. A walk only proposes
candidate rows and writes no setting by itself. SNMP v3
(USM/encryption) is not implemented, and a device configured with any version
other than `v2c` is refused when the settings are parsed rather than silently
polled with the wrong protocol.

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
would be an ordinary, unredacted value: the schema refuses it on a write and
the read surface drops it, but as part of a non-secret setting it would have no
secret flag, no audit redaction and no per-item handling. `SNMP_COMMUNITIES` is
what the machinery actually covers -- it is write-only, the read surface says
only that it is set, and a blank value on save means **unchanged** (use DELETE
to remove the override).

A device row must match its declared fields **exactly**. The schema
(`Setting.parse_item`) refuses an undeclared key with a 422, so the old
device-row shape `{"name", "address", "community"}` cannot be accepted with the
field silently dropped -- which would answer 200 while the stored map kept
authenticating with the old value. A row that reaches the module another way
(a hand-edited `.env`) is refused by `validate_settings`; both rules exist
because the API is not the only way a value can arrive.

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

## Adding a device by discovery

```text
add a device row (name, address, community)
  -> Discover
  -> review the candidates, edit labels and bands
  -> Add selected
  -> the next collection reports the rows
```

**Add a device.** The add-device form writes the device and its community in
one validated write. The community is merged server-side into
`SNMP_COMMUNITIES` (the browser cannot read that map), and it is never returned.

**Discover.** `discover` walks the MIB-II groups that carry semantics (system,
interfaces, bridge, host resources, ifXTable, sensors, PoE) -- not the whole
tree, whose RMON/IP tables can spend the object cap before ifXTable -- then the
**vendor root the device reports** in `sysObjectID` (for `1.3.6.1.4.1.41112.1.6.3` that
is `1.3.6.1.4.1.41112`). A Net-SNMP device (`8072`) also gets its UCD branch
(`1.3.6.1.4.1.2021`), where Linux keeps memory, disk and CPU metrics. Without
a usable `sysObjectID` it walks the whole enterprises tree (`1.3.6.1.4.1`), as
before. Each walk is capped by `max_oids`, with truncation reported, and an
optional `root` argument overrides the derivation.

The Discovery sheet is the command's surface: it sends `max_oids` (default
40000) and the optional `root`, and `snmp.discover` is hidden from the generic
Commands list. The command is bounded at 180 s, enough for a larger walk. It
writes no SETTINGS, so reviewing is always a separate, explicit step; the
walk's RESULT is stored per device (`store.record_snmp_discovery`) so the
intelligence layer's author lane can read the same candidates and propose rows
(`append_rows`, below).

The derivation matters because the enterprises tree is ordered: a 2000-object
cap spent on Broadcom's `4413` branch never reaches Ubiquiti's `41112`, so an
AP's own objects would be missing from its discovery.

**Review.** `discovery.SEMANTICS` is the checked-in translation table: standard
tables (system, IF-MIB, BRIDGE-MIB, HOST-RESOURCES, ENTITY-SENSOR, PoE) and the
vendor branches measured so far. A row is classified, not dumped:

| What the object is | What discovery does |
|---|---|
| a known status (`ifOperStatus`, sensor status, bridge port state) | proposes a `state` check with the expected value |
| a known gauge (`hrProcessorLoad`, link speed, PoE watts, radio utilization) | proposes a gauge with its unit and, where defensible, a starting band |
| a counter (`ifInOctets`, dot3 errors, vendor byte counters) | names it in `notes`; never proposes a gauge |
| a string/OID/inventory value (serial, model, description) | names it in `notes`; never proposes a check |
| an object with no bundled semantics | counts it under its vendor/MIB group in `notes`; proposes nothing |

The result is a review sheet of meaningful rows, not a dump of the walk.
`ENTERPRISE_NAMES` translates the IANA PEN (`4413` → Broadcom, `41112` →
Ubiquiti) so a note names the vendor; an unknown PEN keeps its number. The
device identity (`sysDescr`, `sysName`, `sysLocation`, `sysObjectID`, vendor) is
returned alongside the candidates.

Starting bands are reviewed values: `STARTING_BANDS` is the gauge/state subset
of `SEMANTICS`, and a band is never widened to fit the observation. Band inputs
in the sheet let the operator set one where the table has no defensible
suggestion; a gauge cannot be applied without it. An interface row whose index
has no name from `ifName`/`ifAlias`/`ifDescr` is reported, not proposed -- a
label a human cannot verify is not invented. Name columns are applied per table
family (`ifIndex`, `entPhysicalIndex`, `dskPath`, radio/VAP/unifiIf indices), so
one family's index cannot label another's row. When several rows share a name
(drivers often report one `ifDescr` for every port), the label gets its index --
`Interface MEDIATEK Corp. Device 7622 speed (index 8)` -- because the index is
the one stable, unique fact.

**Add selected.** One `apply_discovery` call validates the whole merged
`SNMP_CHECKS` list before writing, so a bad selected row refuses the entire
selection rather than leaving half of it in force.

**Author proposals.** The latest stored discovery per device is part of the
module's scoped view (`intelligence_facts`): the classified candidates,
identity, truncation and notes, bounded to 40 candidates per device. At an
`author` grant of `propose`, the model may return an `append_rows` proposal
naming rows from that pack; the platform merges them over the current
`SNMP_CHECKS`, validates the result, and stores a pending proposal. Approval is
the normal proposal path (a human decision), and a row whose OID is not in the
stored discovery is dropped before it reaches the queue.

**MIB files.** Each device row on the module page can carry one or more
operator-supplied MIB files (the MIB files card below the discovery sheet).
They are stored under the monitor's data volume at
`MONITOR_DATA/mibs/<device>/<name>` (mode 600), validated as a plain file name
with a `.mib`/`.txt`/`.my` extension, and never parsed or executed in this
delivery. They are the operator's reference for what an OID means; parsing them
into labels is a later step.

**Next collection.** The rows appear on the next epoch. An interface that is
currently down is proposed as a `state` row expecting `up`, so it reports
**observed-down** (FAIL) -- the truth about the device. Discovery never makes a
down interface green.

## Intelligence and remediation

`snmp` declares `observe` and `author` — **no `remediate`**: the module never
writes to a device and declares no actions. The grant is `SNMP_INTELLIGENCE`
(JSON, `.env` fallback) or the SPA grant, which wins; a `remediate` grant is
refused at startup. `SNMP_AUTHORITY` is accepted but inert.

Discovery stays the deterministic path: `discover` proposes candidates with
checked-in starting bands, and the operator reviews them. A model may author
additive rows as proposals (`auto` is reserved) — a new device or check row,
never a removal or a band widened past a failing value — and a proposal is
still reviewed before it is applied.

```bash
SNMP_INTELLIGENCE={"observe": true, "author": "propose"}
```

The optional per-module budget is `{"rows": 500, "bytes": 32768, "tokens": 2000}`.
A malformed grant refuses rather than granting anything. See
`docs/architecture.md` ("Module intelligence options") for the full matrix.

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
* a `community` field appears inside a device row (it belongs in the map) --
  for an API write the schema refuses the undeclared key first; this rule
  catches a row that arrived through `.env`;
* `SNMP_TIMEOUT_S` is below 1.

Every other undeclared key in a list row is refused by the same schema rule: a
row is normalized to `item_fields` only in the sense that an omitted optional
field becomes `None`; an extra field is never discarded.

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
| `snmp.py` | the v2c client: `GET`, `GETNEXT`, and the `GETBULK` walk (25 per request, `GETNEXT` fallback); bounded UDP timeout, one retry, one error type per failure |
| `settings.py` | parsing (`SnmpConfig`), the community map, and the save-time rules (`validate`) |
| `preload.py` | one poll per enabled device per epoch; installs `ctx.snmp_facts` |
| `checks.py` | `SnmpReachable` / `SnmpOid` and the dynamic `instances(ctx)` |
| `discovery.py` | the translation table and classifier: `SEMANTICS`, `ENTERPRISE_NAMES`, per-family `name_map`, `identity`, and candidates with counter/inventory/unclassified notes and no invented value |
| `commands.py` | the `discover` command: walks MIB-II plus the device-reported vendor root (or an explicit `root`), returns candidates and identity; writes no setting |
| `thresholds.conf` | deliberately comment-only: bands live on the settings rows |

The module opens no platform attempt row: an SNMP device is not an ssh host, so
a failed poll must not become a fleet `host_unreachable` incident owned by the
wrong module.

Disabling the module freezes the incidents its settings created. The ids exist
in no Check class, so the module supplies `owned_check_ids` in its contract and
the platform's disablement freeze, remedy engine and insight attribution all
read it through `module.owned_check_ids(mod, ctx)`; without it, switching the
module off would leave its per-device incidents open forever.
