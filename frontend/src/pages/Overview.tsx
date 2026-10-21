import { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import {
  api,
  getIntelligence,
  type IntelligenceState,
  type Status,
} from "../api";
import StaleBanner, { span } from "../components/StaleBanner";
import StatusPill, { tone } from "../components/StatusPill";

const DEFAULT_INTERVAL_S = 60;
const REQUEST_TIMEOUT_MS = 15_000;
const CLOCK_TICK_MS = 5_000;
const INCIDENT_PREVIEW = 5;

export default function Overview() {
  const [status, setStatus] = useState<Status | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(true);
  // When the server last answered. The API's own `staleness` is a fact about
  // the document at the instant it was built; between polls it cannot notice
  // that the connection died. This is the client-side half of that rule.
  const [lastOk, setLastOk] = useState<number | null>(null);
  const [clock, setClock] = useState(() => Date.now());
  // The last intelligence cycle, when one was reported. Its own read: a model
  // backend failing is not the fleet board failing, and a failed read here
  // must leave the banner off rather than claim the intelligence is healthy.
  const [cycle, setCycle] = useState<IntelligenceState["last_cycle"]>(null);
  // The collector's own interval, not a second literal: the page must refresh
  // at the rate the backend says it collects. Held in a ref because changing it
  // must not restart the effect (and re-fire the first request).
  const nextMs = useRef(DEFAULT_INTERVAL_S * 1000);

  // A clock so the "last known" test and the age line move without a poll.
  useEffect(() => {
    const id = setInterval(() => setClock(Date.now()), CLOCK_TICK_MS);
    return () => clearInterval(id);
  }, []);

  // ONE READ OF THE INTELLIGENCE SURFACE, for the failure banner only. A
  // rejected read means this page cannot say whether the last cycle ran, so it
  // says nothing; an empty green board is the failure this banner exists to
  // prevent. It is deliberately not part of the status poll: a model backend
  // outage must not turn the fleet board's own refresh into an error.
  useEffect(() => {
    let alive = true;
    getIntelligence()
      .then((s) => {
        if (alive) setCycle(s.last_cycle ?? null);
      })
      .catch(() => {
        if (alive) setCycle(null);
      });
    return () => {
      alive = false;
    };
  }, []);

  useEffect(() => {
    let alive = true;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let ctrl: AbortController | undefined;
    let requestTimeout: ReturnType<typeof setTimeout> | undefined;

    const load = async () => {
      const request = new AbortController();
      ctrl = request;
      // A half-open connection otherwise blocks the loop forever: the next
      // poll is scheduled in `finally`, so a request that never settles stops
      // every later one. The timeout aborts only this request.
      requestTimeout = setTimeout(() => request.abort(), REQUEST_TIMEOUT_MS);
      try {
        const s = await api.status(request.signal);
        if (!alive) return;
        setStatus(s);
        setError(null);
        setLastOk(Date.now());
        const secs = Number(s.collector?.interval_s);
        if (Number.isFinite(secs) && secs >= 5) nextMs.current = secs * 1000;
      } catch (e) {
        if (!alive) return;
        setError(
          (e as Error)?.name === "AbortError"
            ? `request timed out after ${REQUEST_TIMEOUT_MS / 1000}s`
            : e instanceof Error
              ? e.message
              : String(e),
        );
      } finally {
        clearTimeout(requestTimeout);
        if (alive) {
          setBusy(false);
          timer = setTimeout(load, nextMs.current);
        }
      }
    };

    void load();
    return () => {
      alive = false;
      ctrl?.abort();
      clearTimeout(timer);
      clearTimeout(requestTimeout);
    };
  }, []);

  if (busy && !status && !error) {
    return <p className="sub">Loading the fleet status…</p>;
  }

  // NO STATUS AT ALL IS UNREACHABLE, and it must not render as an empty board:
  // an empty board reads as "nothing is wrong". A failed refresh with an older
  // status still shows that status, labelled as last known.
  if (!status) {
    return (
      <section className="unreachable" role="alert">
        <h2>Monitor unreachable — this is not a healthy fleet</h2>
        <p>
          The dashboard could not read <code>/api/v1/status</code>. This is not
          an empty fleet and it is not a clean one; it is no observation at all.
        </p>
        {error && <p className="sub">{error}</p>}
        <p className="sub">
          The page keeps trying. If this persists, check that the container is
          running and that its store is reachable.
        </p>
      </section>
    );
  }

  const c = status.collector;
  const hosts = Object.entries(status.hosts);
  const incidents = status.incidents.slice(0, INCIDENT_PREVIEW);
  // The server said "fresh" when it built this document; that stops being true
  // if the next two polls never arrive. Two intervals is the same grace the
  // API itself gives before it calls a collector stale.
  const intervalMs = nextMs.current;
  const lastKnown =
    Boolean(error) ||
    (lastOk !== null && clock - lastOk > 2 * intervalMs);
  const asOf = lastOk ? new Date(lastOk).toLocaleTimeString() : "unknown";
  // The age ticks between polls by adding the client's elapsed time to the
  // server's `last_age_s`, so this line never freezes at the value it had when
  // the response was rendered.
  const ageSeconds =
    c.last_age_s == null
      ? null
      : c.last_age_s + (lastOk ? (clock - lastOk) / 1000 : 0);

  return (
    <>
      {lastKnown && (
        <div className="banner red" role="alert">
          <strong>Monitor unreachable — this is not a healthy fleet.</strong>{" "}
          {error
            ? `The last refresh failed (${error}).`
            : `No successful refresh in over ${span(
                (2 * intervalMs) / 1000,
              )}.`}{" "}
          Everything below is the last known state (as of {asOf}), not a live
          one.
        </div>
      )}

      <StaleBanner collector={c} />

      {/* THE ANALYSIS FAILING IS NOT THE FLEET FAILING. A selected model that
          could not be reached is an `error` cycle, and an overrun is `budget`;
          either leaves the deterministic evidence intact, so this sits above
          the cards rather than replacing them. The detail is the server's,
          already redacted -- never the model key. */}
      {cycle && (cycle.status === "error" || cycle.status === "budget") && (
        <div
          className={`banner ${cycle.status === "error" ? "red" : "amber"}`}
          role="alert"
        >
          <strong>
            {cycle.status === "error"
              ? "The last intelligence cycle failed."
              : "The last intelligence cycle exceeded its budget."}
          </strong>{" "}
          {cycle.detail || "No detail was recorded."} The fleet below is still
          the last measured state.
        </div>
      )}

      {/* A MODULE WHOSE SETTINGS DO NOT PARSE IS NOT AN EMPTY MODULE. Without
          this the only trace was a spec-less placeholder in `others`, which no
          page rendered -- malformed SNMP_DEVICES showed zero checks and a page
          that read like "nothing is configured". */}
      {(status.module_errors ?? []).length > 0 && (
        <div className="banner red" role="alert">
          <strong>
            Some modules could not build their settings-driven checks, so they
            are NOT being evaluated:
          </strong>
          <ul>
            {status.module_errors.map((e) => (
              <li key={e.module}>
                <code>{e.module}</code>: {e.reason}
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* The collector's own run note. It names module and platform failures
          that happened during the epoch (preload, advisors, instance builds)
          and was typed and returned but rendered nowhere. */}
      {c.note && (
        <div className="banner amber" role="alert">
          <strong>The collector reported problems during the last epoch.</strong>
          <pre>{c.note}</pre>
        </div>
      )}

      <section className="verdict" aria-label="Fleet verdict">
        <StatusPill status={status.verdict} />
        <p>{status.verdict_reason}</p>
      </section>

      <dl className="counts">
        <div>
          <dt>Green</dt>
          <dd>{status.counts.green}</dd>
        </div>
        <div>
          <dt>Amber</dt>
          <dd>{status.counts.amber}</dd>
        </div>
        <div>
          <dt>Red</dt>
          <dd>{status.counts.red}</dd>
        </div>
        <div>
          <dt>Grey</dt>
          <dd>{status.counts.grey}</dd>
        </div>
        <div>
          <dt>No result</dt>
          <dd>{status.counts.checks_without_result ?? 0}</dd>
        </div>
        <div>
          <dt>Checks</dt>
          <dd>{status.counts.checks_total ?? "—"}</dd>
        </div>
      </dl>

      <h2>Hosts</h2>
      {hosts.length === 0 ? (
        <p className="sub">
          No host is being observed. That is not “all clear” — it means nothing
          is reporting on the fleet.
        </p>
      ) : (
        <div className="grid">
          {hosts.map(([target, h]) => (
            <article key={target} className={`tile ${tone(h.verdict)}`}>
              <div className="tile-head">
                <strong>{target}</strong>
                <StatusPill status={h.verdict} />
              </div>
              <p className="sub">{h.verdict_reason}</p>
              <p className="sub">
                {h.checks} check{h.checks === 1 ? "" : "s"}
                {h.checks_without_result > 0 &&
                  ` — ${h.checks_without_result} with no result`}
              </p>
              <p className="rags">
                <span className="rag green">G {h.counts.green}</span>
                <span className="rag amber">A {h.counts.amber}</span>
                <span className="rag red">R {h.counts.red}</span>
                <span className="rag grey">X {h.counts.grey}</span>
              </p>
            </article>
          ))}
        </div>
      )}

      <h2>Live incidents</h2>
      {incidents.length === 0 ? (
        <p className="sub">
          No live incidents. That means no confirmed condition — it does not by
          itself mean the fleet is healthy.
        </p>
      ) : (
        <div className="scroll">
          <table>
            <thead>
              <tr>
                <th>Severity</th>
                <th>State</th>
                <th>Target</th>
                <th>Check</th>
                <th>Detail</th>
              </tr>
            </thead>
            <tbody>
              {incidents.map((i) => (
                <tr key={i.key}>
                  <td>
                    <StatusPill status={i.severity} />
                  </td>
                  <td>{i.state}</td>
                  <td>
                    {i.target}
                    {i.subject ? ` / ${i.subject}` : ""}
                  </td>
                  <td>{i.check_id}</td>
                  <td>{i.detail ?? "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <p>
        <Link to="/incidents">All incidents →</Link>
      </p>

      <p className="sub footer">
        Collected {ageSeconds == null ? "never" : `${span(ageSeconds)} ago`}
        {c.epoch_seq != null && ` · epoch ${c.epoch_seq}`}
        {c.duration_ms != null && ` · ${c.duration_ms} ms`}
        {c.errors != null && ` · ${c.errors} errors`} · refreshing every{" "}
        {span(c.interval_s)}
      </p>
    </>
  );
}
