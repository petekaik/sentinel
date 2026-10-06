"""Checks for Storage-NAS itself, the TVH container, and the DVB tuners.

NO SSH IN THIS FILE, AND THAT IS THE DESIGN. The monitor runs ON Storage-NAS,
so every fact here is read locally -- the share paths, the docker socket, the
container log. The plan states the rule as "do not ssh into Storage-NAS for
Storage-NAS checks", and the reason is not efficiency: an ssh hop introduces a
class of "could not ask" that has nothing to do with the NAS's health, and it
gives every check here a second way to be wrong. A local read either yields a
value or raises, and the collector turns a raise into UNKNOWN with the traceback
rather than into a silent pass.

THREE TRAPS THIS FILE IS WRITTEN AROUND

1. TVH ANSWERS 401. Authentication is on and the credentials are unknown, so
   `curl -f` would report a PERMANENT RED on a service that is working, and
   "any HTTP code came back" would report a permanent GREEN on a service that
   answered nothing. 401 proves exactly one thing -- something is listening on
   that port -- and that is what the check says. Credential VALIDITY needs its
   own probe, because a wrong password returns the same 401 as no password.

2. TUNER #2 IS NOT A FAULT. The operator reported the second Si2168 refusing
   recordings, and that is a known-accepted condition, not an outage. Modelling
   "both adapters must work" would make the dashboard red from day one, and a
   permanent false RED is worse than no check (item 72). So adapter PRESENCE is
   the check, "works" is UNKNOWN whenever no recording has happened, and the
   accepted condition is declared in checks.conf rather than hard-coded here.

3. ONE FILESYSTEM, TWO FAILURES. /mnt/recordings and /mnt/transcoded are the
   same volume, so "disk full" stops recording AND transcoding together. The
   check is written once, over the volume, and its note says so -- rather than
   two identical rows that an operator would read as two independent risks.
"""

import os
import time

from checks import Check, ok, warn, fail, unknown
from store import Status


class MediaVolume(Check):
    id = "media_volume_used_pct"
    target = "storage"
    spec = "media_volume_used_pct"
    title = "Media volume used"
    description = ("The filesystem behind BOTH /mnt/recordings and "
                   "/mnt/transcoded. Filling it stops recording and transcoding "
                   "at the same moment.")

    def run(self, ctx):
        path = ctx.cfg.recordings_root
        # statvfs is local, so the only failure is the path being gone -- and
        # that is itself a finding, not an "unknown", because the share is
        # supposed to exist on this host permanently.
        st, why = _statvfs(path)
        if st is None:
            parent, pwhy = _statvfs(os.path.dirname(path) or "/")
            if parent is None:
                return fail(self.id, self.target,
                            "cannot stat %s or its parent (%s) -- the "
                            "recordings share is not present on this host"
                            % (path, why or pwhy), subject=path,
                            evidence={"path": path, "why": why})
            return warn(self.id, self.target,
                        "%s is missing (%s), but its parent filesystem is "
                        "readable (%.1f%% used) -- the share may have been "
                        "moved or renamed" % (path, why, parent["used_pct"]),
                        subject=path, evidence={"path": path,
                                                "parent": parent})

        # The transcoded root is reported alongside so a reader can see that the
        # two paths really do share a filesystem, which is the whole point.
        same = _same_filesystem(path, ctx.cfg.transcoded_root)
        free_gb = (st.get("free") or 0) / 1073741824.0
        res = self.result_from_spec(
            ctx, st["used_pct"], subject="media-volume",
            evidence={**st, "transcoded_same_fs": same,
                      "transcoded_root": ctx.cfg.transcoded_root})
        res.detail = "%s (%.1f%% used, %.1f GB free)%s" % (
            res.detail, st["used_pct"], free_gb,
            "; transcoded/ is the SAME filesystem"
            if same else "; transcoded/ is a DIFFERENT filesystem")
        if same and st["used_pct"] >= 80:
            res.detail += " -- a full volume stops BOTH recording and transcoding"
        res.metric("media_free_gb", free_gb, "GB")
        return res


class DvbAdapters(Check):
    id = "dvb_adapter_count"
    target = "storage"
    spec = "dvb_adapter_count"
    title = "DVB adapters present"
    description = ("PRESENCE only. The only proof a tuner WORKS is a real "
                   "recording, which must never be run automatically.")

    def run(self, ctx):
        root = "/dev/dvb"
        try:
            names = sorted(d for d in os.listdir(root)
                           if os.path.isdir(os.path.join(root, d)))
        except OSError as exc:
            return unknown(self.id, self.target,
                           "%s not readable (%s) -- the DVB subsystem is not "
                           "exposed to this container, so adapter presence "
                           "cannot be assessed here" % (root, exc),
                           subject="dvb")
        # Each adapter must have the nodes a recording needs, not just exist.
        detailed, incomplete = {}, []
        for n in names:
            try:
                nodes = sorted(os.listdir(os.path.join(root, n)))
            except OSError:
                nodes = []
            detailed[n] = nodes
            for need in ("demux0", "dvr0", "frontend0"):
                if need not in nodes:
                    incomplete.append("%s/%s" % (n, need))

        n = len(names)
        res = self.result_from_spec(ctx, float(n), subject="dvb",
                                    evidence={"adapters": detailed})
        if incomplete:
            return warn(self.id, self.target,
                        "%d adapter(s) present but incomplete: missing %s"
                        % (n, ", ".join(incomplete[:5])), subject="dvb",
                        evidence={"adapters": detailed})
        expected = len(ctx.cfg.dvb_adapters)
        if n == expected:
            res.detail = ("%s; all have demux0/dvr0/frontend0 "
                          "(presence, not function)" % res.detail)
        return res


class TvhHttp(Check):
    id = "tvh_response_ms"
    target = "storage"
    spec = "tvh_response_ms"
    title = "TVH HTTP reachable"
    description = ("401 IS AN ANSWER. It proves something is listening; it does "
                   "not prove the service works.")

    def run(self, ctx):
        import probes
        url = ctx.cfg.tvh_url.rstrip("/") + "/"
        res, why = probes.http_probe(url, timeout=10)
        if res is None:
            return fail(self.id, self.target,
                        "TVH did not answer at %s: %s" % (url, why),
                        subject="tvh-http")
        code = res["code"]
        ms = float(res["duration_ms"])
        ev = {"code": code, "url": url, "auth_configured": bool(ctx.cfg.tvh_user)}

        if code == 401:
            # The whole reason this check does not use curl -f. An answer, but
            # not a verifiable one -- so it is UNKNOWN with the reason in words,
            # never green and never red.
            return unknown(
                self.id, self.target,
                "TVH answered 401 in %d ms -- it is LISTENING, which is all this "
                "proves. Authentication is on and no credentials are configured, "
                "so liveness is confirmed but health is not. A WRONG password "
                "returns the same 401, so supplying credentials without a "
                "separate validity probe would not change this reading." % ms,
                subject="tvh-http", evidence=ev)
        if code >= 500:
            return fail(self.id, self.target,
                        "TVH answered HTTP %d in %d ms" % (code, ms),
                        subject="tvh-http", evidence=ev)
        if code >= 400:
            return warn(self.id, self.target,
                        "TVH answered HTTP %d in %d ms (not 401, so this is not "
                        "the expected auth response)" % (code, ms),
                        subject="tvh-http", evidence=ev)
        return self.result_from_spec(ctx, ms, subject="tvh-http", evidence=ev)


class TvhContainer(Check):
    id = "tvh_container"
    target = "storage"
    spec = None
    title = "TVH container state"
    description = "The container's own health, from the docker API."

    def run(self, ctx):
        if ctx.docker is None:
            return unknown(self.id, self.target, "no docker client configured",
                           subject="docker")
        cs, why = ctx.docker.containers()
        if cs is None:
            return unknown(self.id, self.target,
                           "could not read the docker API: %s" % why,
                           subject="docker")
        name = ctx.cfg.tvh_container
        c = next((x for x in cs if x.get("name") == name), None)
        if c is None:
            return fail(self.id, self.target,
                        "container %r is not present (%d running)"
                        % (name, len(cs)), subject=name,
                        evidence={"containers": [x.get("name") for x in cs]})
        health = c.get("health") or "(no healthcheck)"
        state = c.get("state")
        # Read from INSPECT, because /containers/json has no RestartCount -- a
        # `c.get("restarts", 0)` here would always yield 0 and silently report
        # "no restarts" on a crash-looping container (item 26: a check that
        # cannot fire). An unavailable count is UNKNOWN, not zero.
        restarts, rwhy = ctx.docker.restart_count(name)
        if restarts is None:
            restarts = 0
            rnote = "restart count unavailable (%s)" % rwhy
        else:
            rnote = ""
        ev = {"state": state, "health": health, "restarts": restarts}
        if rnote:
            ev["restart_note"] = rnote
        if state != "running":
            return fail(self.id, self.target,
                        "%s is %s, not running" % (name, state),
                        subject=name, evidence=ev)
        if health == "unhealthy":
            return fail(self.id, self.target,
                        "%s is running but UNHEALTHY" % name, subject=name,
                        evidence=ev)
        # A rising restart count is the designed symptom of a crash loop rather
        # than a fault in itself, so it is reported, not alarmed -- the same
        # rule the plan applies to the worker's NRestarts.
        if restarts:
            return warn(self.id, self.target,
                        "%s running, health %s, but %d restart(s) recorded"
                        % (name, health, restarts), subject=name, evidence=ev)
        return ok(self.id, self.target,
                  "%s running, health %s, no restarts" % (name, health),
                  subject=name, evidence=ev)


class TvhLogSignals(Check):
    id = "tvh_log_signals"
    target = "storage"
    spec = "tvh_tuner_refusal_h"
    title = "TVH log: no free adapter, DVR pairing, EPG"
    description = ("The container log is the only place these appear. Read "
                   "through the docker API, so it needs no TVH credentials.")

    def run(self, ctx):
        import parsers
        text, why = ctx.tvh_log()
        if text is None:
            return unknown(self.id, self.target,
                           "could not read the %s log: %s"
                           % (ctx.cfg.tvh_container, why), subject="tvh-log")
        tl = parsers.parse_tvh_log(text)
        bal = tl.dvr_balance()
        ref = tl.refusal_summary()
        ev = {
            "lines": tl.lines,
            "unparsed": tl.unparsed,
            "errors": len(tl.errors),
            "no_free_adapter": len(tl.no_free_adapter),
            "refusals": ref,
            "epg_timeouts": len(tl.epg_timeouts),
            "perm_warnings": len(tl.perm_warnings),
            "adapters_tuned": tl.adapters_seen,
            "dvr": bal,
            "window": [tl.first_iso, tl.last_iso],
        }
        # THE TUNER REFUSALS, GRADED BY RECENCY AND CHECKED FIRST.
        #
        # This runs BEFORE the `no free adapter` / pairing tests because it is the
        # sharper signal: those describe a subscription going wrong, this one
        # names recordings that were actually LOST. Measured 2026-09-25, the
        # window contained three `Recording unable to start ... No input detected`
        # events while this check reported GREEN -- it tested only for the phrase
        # `no free adapter`, which this fleet has never emitted. A check keyed to
        # a signature the fleet does not produce cannot fire, and the dashboard
        # called a day on which three recordings were lost "balanced and healthy".
        #
        # The age is measured against the log's OWN newest line, so both stamps
        # come from one clock and skew cancels (the boxes have no RTC, item 23).
        # Only FAIL/WARN short-circuit: an OLD refusal must not mask a dangling
        # subscription, so a green age falls through to the checks below.
        if ref["total"]:
            newest = parsers.tvh_iso_to_epoch(ref["newest_iso"])
            log_end = parsers.tvh_iso_to_epoch(tl.last_iso)
            if newest is None or log_end is None:
                return unknown(
                    self.id, self.target,
                    "%d tuner-refusal event(s) are in this window but their age "
                    "cannot be computed (newest=%r, log newest=%r), so whether "
                    "this is happening NOW cannot be answered"
                    % (ref["total"], ref["newest_iso"], tl.last_iso),
                    subject="tvh-log", evidence=ev)
            age_h = (log_end - newest) / 3600.0
            if age_h < 0:
                return unknown(
                    self.id, self.target,
                    "the newest tuner refusal (%s) is LATER than the newest log "
                    "line (%s) -- the box clock is not monotonic and no "
                    "meaningful age exists" % (ref["newest_iso"], tl.last_iso),
                    subject="tvh-log", evidence=ev)
            res = self.result_from_spec(
                ctx, age_h, subject="tvh-log",
                evidence=dict(ev, refusal_age_h=round(age_h, 2)))
            if res.status in (Status.FAIL, Status.WARN):
                lost = ""
                if ref["unable_to_start"]:
                    lost = ("; %d recording(s) LOST: %s"
                            % (ref["unable_to_start"],
                               ", ".join(ref["titles_lost"][:3])))
                chans = ", ".join(
                    "%s x%d" % (k, v) for k, v in
                    sorted(ref["channels"].items(), key=lambda kv: -kv[1])[:3])
                # NAME THE TUNER AND THE SCOPE. An earlier version of this
                # string ended "...so it is a TUNER/AERIAL fault, not a
                # scheduling one" -- a DIAGNOSIS this check had no evidence for,
                # and the wrong one to assert: it collapses the two RCA branches
                # (wedged tuner vs changed mux) that need OPPOSITE remedies, a
                # driver rebind against a rescan. The verdict now comes from
                # tuner_faults(), which reads the adapter out of TVH's own
                # subscribing line and cross-checks the mux against the other
                # tuner. See the tuner_health and mux_unreachable checks below,
                # which carry the remedy-shaped verdict.
                tf = tl.tuner_faults()
                res.detail = (
                    "%s. Newest tuner refusal was %s, %.1f h before the log's "
                    "newest line: %d 'No input source available' + %d 'service "
                    "instance is bad'%s. Channels named: %s. %s"
                    % (res.detail, ref["newest_iso"], age_h,
                       ref["no_input_source"], ref["service_bad"], lost,
                       chans or "none", _scope_sentence(tf)))
                return res

        bad = []
        if tl.no_free_adapter:
            bad.append("%d 'no free adapter' event(s) -- a recording was "
                       "refused" % len(tl.no_free_adapter))
        if bal["dangling"]:
            bad.append("%d DVR subscription(s) never unsubscribed (a truncated "
                       "or wedged recording): %s"
                       % (len(bal["dangling"]), ", ".join(bal["dangling"][:3])))
        if bad:
            return fail(self.id, self.target, "; ".join(bad), subject="tvh-log",
                        evidence=ev)

        # Parse coverage is reported because an unparsed line is a blind spot,
        # exactly as it is for the worker log -- but the TVH format is not ours
        # and its volume is higher, so this warns rather than fails.
        if tl.lines and tl.unparsed:
            frac = tl.unparsed / float(tl.lines)
            if frac > 0.5:
                return warn(self.id, self.target,
                            "%.0f%% of %d TVH log lines did not match the "
                            "parser -- the checks below this are blind"
                            % (frac * 100, tl.lines), subject="tvh-log",
                            evidence=ev)

        # AN UNMEASURABLE PAIRING IS NOT A BALANCED ONE. Reaching here means
        # nothing was found wrong -- which is only worth a green if the window
        # could have shown it. `measurable` is false when no DVR subscribe line
        # is in the window, and that is the normal shape of a short tail: the
        # unsubscribes of recordings already in progress appear without their
        # subscribes. Reporting green there would be asserting a balance from a
        # window that had no way to be unbalanced (items 26, 72).
        if not bal["measurable"]:
            return unknown(
                self.id, self.target,
                "no RECENT tuner refusal and no parse problem, but the DVR "
                "subscribe/unsubscribe pairing CANNOT BE ASSESSED from this "
                "window: %d DVR unsubscription(s) appear with no matching "
                "subscribe line, so the window begins after those recordings "
                "started. A dangling subscription could not have been seen. "
                "Widen TVH_LOG_TAIL (currently %d lines) past one full "
                "recording to make this check measurable."
                % (len(bal["orphan_ends"]), ctx.cfg.tvh_log_tail),
                subject="tvh-log", evidence=ev)
        # "no refused recordings" was hardcoded here and became a LIE the moment
        # refusals were parsed at all: a window can hold old refusals that did
        # not reach the recency threshold. Report what is actually there.
        refusal_txt = "no tuner refusals"
        if ref["total"]:
            refusal_txt = ("%d tuner-refusal event(s), newest %s -- older than "
                           "the threshold, so not a live fault"
                           % (ref["total"], ref["newest_iso"]))
        return ok(self.id, self.target,
                  "%s, DVR pairing balanced (%d started / %d ended), %d EPG "
                  "timeout(s), %d error line(s) over %s..%s"
                  % (refusal_txt, bal["started"], bal["ended"],
                     len(tl.epg_timeouts), len(tl.errors),
                     tl.first_iso, tl.last_iso),
                  subject="tvh-log", evidence=ev)


class EpgFreshness(Check):
    id = "epg_freshness_h"
    target = "storage"
    spec = "epg_freshness_h"
    title = "EPG freshness"
    description = ("Stale EPG means the schedule is drifting, which is the "
                   "precursor to missed recordings.")

    def run(self, ctx):
        import parsers
        text, why = ctx.tvh_log()
        if text is None:
            return unknown(self.id, self.target,
                           "could not read the TVH log: %s" % why, subject="epg")
        tl = parsers.parse_tvh_log(text)
        if not tl.epgdb_saves:
            return unknown(
                self.id, self.target,
                "no EPG database save appears in the %d log line(s) read "
                "(window %s..%s), so EPG freshness cannot be measured from "
                "this source" % (tl.lines, tl.first_iso, tl.last_iso),
                subject="epg")
        last = tl.epgdb_saves[-1]["iso"]
        age_h = _hours_since(last, tl.last_iso)
        if age_h is None:
            return unknown(self.id, self.target,
                           "the newest EPG save stamp %r could not be placed "
                           "in time" % last, subject="epg")
        res = self.result_from_spec(
            ctx, age_h, subject="epg",
            evidence={"last_save": last, "saves": len(tl.epgdb_saves),
                      "timeouts": len(tl.epg_timeouts),
                      "log_last": tl.last_iso})
        if tl.epg_timeouts:
            res.detail += ("; NOTE %d EPG 'data completion timeout' warning(s) "
                           "in the same window" % len(tl.epg_timeouts))
        return res


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _scope_sentence(tf):
    """One sentence naming WHICH tuner failed and whether the MUX is exonerated.

    The two branches need opposite operator actions, so the sentence is written
    to be actionable rather than merely descriptive: a wedged tuner is a driver
    rebind, a changed mux is a rescan, and a message that says "tuner/aerial
    fault" sends the operator to do both or neither.
    """
    if not tf["faults"]:
        return ""
    adapters = sorted(tf["by_adapter"])
    if tf["scope"] == "adapter":
        return ("Scope: ADAPTER -- every mux that failed was carried by another "
                "tuner in this same window, so the mux table is demonstrably "
                "correct and the fault is the tuner (%s). Remedy is to reset "
                "that adapter, NOT to rescan." % ", ".join(adapters))
    if tf["scope"] == "mux":
        muxes = sorted({m["mux"] for m in tf["mux_scoped"]})
        return ("Scope: MUX -- no tuner carried %s in this window, so a signal "
                "or DVB-T mux-definition change cannot be ruled out. Remedy is a "
                "rescan of that mux, NOT a driver reset."
                % ", ".join(muxes))
    return "Scope: UNATTRIBUTED -- %s" % tf["scope_why"]


class TvhTunerSilent(Check):
    """Per-tuner: has it been ASSIGNED work and received nothing?

    WHY THIS IS NOT THE SAME CHECK AS tvh_log_signals. That one grades the
    RECORDING failures by recency, and recording failures are point events:
    three of them, on one evening, none since. A tuner that died on 2026-09-17
    and has silently accepted and dropped every assignment since is invisible to
    a recording-failure check, because TVH's EPG path does not error when a grab
    starves -- it waits out the window and logs one WARNING.

    THE ELIGIBILITY TEST IS THE WHOLE DESIGN, and it is what keeps this from
    being a permanent false FAIL. "No reception in the last N hours" is NOT a
    fault on a tuner that was simply not asked to do anything: this is a
    dual-tuner box where TVH may legitimately use one adapter for a whole day.
    So a tuner is graded ONLY if it was assigned at least one grab or recording
    AFTER its last successful reception. A tuner with no assignments is UNKNOWN
    -- never green, because "nothing was asked of it" is not evidence of health.

    Measured on the live log 2026-09-26, which is why this exists:
      * tuner #0 last RECEIVED at 2026-09-17 14:04 (a 562MHz EPG grab).
      * from 2026-09-18 02:04 it was assigned 18 consecutive EPG grabs on
        562MHz and received nothing from every one -- each held the mux for
        ~605 s until the timeout, where a healthy grab releases it in ~61 s.
      * it has written ZERO recording files in the entire ten-day window.
      * tuner #1 carried 562MHz AND 514MHz successfully throughout, including
        the same day.
    That is 9 days of a wedged tuner, dated to within ~12 hours, on a fleet
    whose DVB check said "2 adapters present" the whole time.
    """

    id = "tvh_tuner_silent_h"
    target = "storage"
    spec = "tvh_tuner_silent_h"
    title = "DVB tuner reception"
    description = ("A tuner that is assigned work and receives nothing is wedged "
                   "-- distinct from a mux that no tuner can reach.")

    def run(self, ctx):
        import parsers
        text, why = ctx.tvh_log()
        if text is None:
            return unknown(self.id, self.target,
                           "could not read the TVH log: %s" % why, subject="dvb")
        tl = parsers.parse_tvh_log(text)
        end = parsers.tvh_iso_to_epoch(tl.last_iso)
        if end is None:
            return unknown(self.id, self.target,
                           "the log's newest line %r has no usable timestamp"
                           % tl.last_iso, subject="dvb")

        # Reception = an EPG grab that completed without a data-completion
        # timeout, or a recording file line. Both mean bytes arrived.
        last_rx, rx_evidence = {}, {}
        for g in tl._successful_epg_grabs():
            a = g["adapter"]
            e = parsers.tvh_iso_to_epoch(g["end"])
            if a and e and (a not in last_rx or e > last_rx[a]):
                last_rx[a] = e
                rx_evidence[a] = "EPG grab %s on %s" % (g["mux"], g["end"])
        for r in tl.recordings:
            a = r.get("adapter")
            e = parsers.tvh_iso_to_epoch(r["iso"])
            if a and e and (a not in last_rx or e > last_rx[a]):
                last_rx[a] = e
                rx_evidence[a] = "recording %s on %s" % (r.get("mux"), r["iso"])

        # Assignment = anything TVH asked of that adapter, of any kind.
        assigned = {}
        for s in tl.subscribes:
            a = s.get("adapter")
            if a:
                assigned[a] = assigned.get(a, 0) + 1

        if not assigned:
            return unknown(
                self.id, self.target,
                "no subscription in this window names an adapter, so no tuner "
                "can be assessed (window %s..%s)" % (tl.first_iso, tl.last_iso),
                subject="dvb")

        graded, idle = {}, []
        for a, n in sorted(assigned.items()):
            rx = last_rx.get(a)
            if rx is None:
                # Never received in the whole window AND was assigned work:
                # silently failing for at least the window's length.
                graded[a] = {"silent_h": (end - parsers.tvh_iso_to_epoch(
                    tl.first_iso)) / 3600.0, "last_rx": None, "assigned": n,
                    "evidence": "no reception anywhere in this window"}
                continue
            # Was it asked to do anything AFTER it last received?
            after = [s for s in tl.subscribes
                     if s.get("adapter") == a
                     and parsers.tvh_iso_to_epoch(s["iso"]) > rx]
            if not after:
                idle.append(a)
                continue
            graded[a] = {"silent_h": (end - rx) / 3600.0,
                         "last_rx": rx_evidence.get(a), "assigned": len(after),
                         "evidence": "%d assignment(s) since it last received"
                                     % len(after)}

        ev = {"window": [tl.first_iso, tl.last_iso],
              "receivers": {a: rx_evidence.get(a) for a in assigned},
              "graded": graded, "idle": idle,
              "epg_faults": len(tl.epg_timeouts)}
        if not graded:
            return unknown(
                self.id, self.target,
                "every tuner that was asked to do something also received "
                "data, so nothing is wedged -- but this window has no tuner "
                "that was asked and starved, which is the only case this check "
                "can grade. Idle in this window: %s"
                % (", ".join(idle) or "none"), subject="dvb", evidence=ev)

        worst = max(graded, key=lambda a: graded[a]["silent_h"])
        w = graded[worst]
        res = self.result_from_spec(ctx, w["silent_h"], subject="dvb",
                                    evidence=dict(ev, worst_tuner=worst))
        if res.status in (Status.FAIL, Status.WARN):
            others = [a for a in graded if a != worst]
            res.detail = (
                "%s. %s has received NOTHING for %.0f h (last reception: %s) "
                "while being assigned %d item(s) since. %s%s"
                % (res.detail, worst, w["silent_h"], w["last_rx"] or "never",
                   w["assigned"],
                   ("Other tuners are receiving normally, so this is scoped to "
                    "the tuner and not to the aerial or the mux table."
                    if not others else ""),
                   (" Also silent: %s." % ", ".join(others)) if others else ""))
        return res


class TvhMuxUnreachable(Check):
    """A mux that NO tuner could carry -- the rescan branch of the RCA.

    This is the other half of _scope_sentence, and it exists so that the two
    faults never share a colour OR a remedy. When a tuner fails a mux that the
    other tuner carries, that is a tuner fault. When NO tuner can carry a mux,
    the aerial, the signal, or the DVB-T mux definition is the suspect, and the
    operator action is a rescan -- which is the opposite of rebinding a driver.
    Reporting both as one "DVB problem" is how an operator ends up doing the
    wrong one and concluding the monitor is noise.
    """

    id = "tvh_mux_unreachable"
    target = "storage"
    spec = "tvh_mux_unreachable"
    title = "DVB mux reachability"
    description = ("A mux no tuner could carry suggests a signal or "
                   "mux-definition change, which is fixed by a rescan.")

    def run(self, ctx):
        import parsers
        text, why = ctx.tvh_log()
        if text is None:
            return unknown(self.id, self.target,
                           "could not read the TVH log: %s" % why, subject="dvb")
        tl = parsers.parse_tvh_log(text)
        tf = tl.tuner_faults()
        ev = {"scope": tf["scope"], "scope_why": tf["scope_why"],
              "mux_scoped": tf["mux_scoped"], "carried": tf["carried"],
              "window": [tl.first_iso, tl.last_iso]}
        if not tf["faults"]:
            return unknown(
                self.id, self.target,
                "no tuner fault in this window, so no mux can be assessed -- "
                "this is not a green, it is an unasked question",
                subject="dvb", evidence=ev)
        if tf["scope"] == "unattributed":
            return unknown(
                self.id, self.target,
                "a tuner fault could not be joined to its subscribing line, so "
                "no mux can be named: %s" % tf["scope_why"],
                subject="dvb", evidence=ev)
        n = len({m["mux"] for m in tf["mux_scoped"]})
        res = self.result_from_spec(ctx, float(n), subject="dvb", evidence=ev)
        if n:
            muxes = sorted({m["mux"] for m in tf["mux_scoped"]})
            res.detail = (
                "%s. No tuner carried %s in this window, while %s were carried "
                "normally -- so this is not a wedged tuner. Check the aerial "
                "and rescan the mux."
                % (res.detail, ", ".join(muxes),
                   ", ".join(sorted(tf["carried"])) or "no mux"))
        return res


def _statvfs(path):
    """Local statvfs -> (fields, why). Mirrors probes.statvfs's own signature.

    probes.statvfs already returns a (value, why) PAIR, so this helper must
    unpack rather than pass it through -- an earlier version returned the tuple
    and every caller subscripted it, which would have raised a TypeError inside
    the check and surfaced as an UNKNOWN-with-traceback on a perfectly healthy
    volume.
    """
    import probes
    return probes.statvfs(path)


def _same_filesystem(a, b):
    """True when two paths live on one filesystem. None if either is missing."""
    try:
        return os.stat(a).st_dev == os.stat(b).st_dev
    except OSError:
        return None


def _hours_since(iso, ref_iso):
    """Hours between two TVH log stamps.

    Both stamps come from the SAME log, so this is a duration and not a clock
    comparison -- which matters because the TVH container's clock and the
    monitor's can differ.

    It must be `tvh_iso_to_epoch`, NOT `iso_to_epoch`. MEASURED 2026-09-26:
    this helper called `iso_to_epoch`, which accepts only the `T`/`Z` form, so
    it returned None for every TVH stamp and `epg_freshness_h` rendered UNKNOWN
    with "the newest EPG save stamp '2026-09-26 19:14:18.125' could not be
    placed in time" -- indefinitely, on every poll, since the check was written.
    Its threshold (green 6 / amber 24) was claimed and validated at load and
    could never be reached, which is item 26's shape: a check that cannot fire
    reads on the dashboard exactly like a healthy fleet.

    This is the SAME defect the refusal-age check was fixed for, in a second
    call site, found by reading the live status after that fix. Two call sites
    of one wrong helper is the reason the helper now names its source in its
    own name."""
    import parsers
    a = parsers.tvh_iso_to_epoch(iso)
    b = parsers.tvh_iso_to_epoch(ref_iso)
    if a is None or b is None:
        return None
    return max(0.0, (b - a) / 3600.0)
