import { useEffect, useRef, useState } from "react";
import { api, type IncidentsPayload } from "../api";
import StaleBanner, { span } from "../components/StaleBanner";
import StatusPill, { tone } from "../components/StatusPill";

const DEFAULT_INTERVAL_S = 60;
const REQUEST_TIMEOUT_MS = 15_000;
const CLOCK_TICK_MS = 5_000;

function when(ts: number | null | undefined): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleString();
}

function howLong(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds < 0) return "—";
  if (seconds < 90) return `${Math.round(seconds)}s`;
  if (seconds < 5400) return `${(seconds / 60).toFixed(0)} min`;
  return `${(seconds / 3600).toFixed(1)} h`;
}

/* The incident board.

   `/api/v1/incidents` serves BOTH halves -- `live` rows and terminal
   `history` -- plus the collector's freshness. The freshness is not
   decoration: "no live incident now" is only reassuring while the collector
   is running, so the page polls on the collector's own interval and stops
   trusting its last answer when two intervals pass without a successful
   refresh. */
export default function Incidents() {
  const [data, setData] = useState<IncidentsPayload | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [lastOk, setLastOk] = useState<number | null>(null);
  const [clock, setClock] = useState(() => Date.now());
  const nextMs = useRef(DEFAULT_INTERVAL_S * 1000);

  useEffect(() => {
    const id = setInterval(() => setClock(Date.now()), CLOCK_TICK_MS);
    return () => clearInterval(id);
  }, []);

  useEffect(() => {
    let alive = true;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let ctrl: AbortController | undefined;
    let requestTimeout: ReturnType<typeof setTimeout> | undefined;

    const load = async () => {
      const request = new AbortController();
      ctrl = request;
      requestTimeout = setTimeout(() => request.abort(), REQUEST_TIMEOUT_MS);
      try {
        const payload = await api.incidents(request.signal);
        if (!alive) return;
        setData(payload);
        setError(null);
        setLastOk(Date.now());
        const secs = Number(payload.collector?.interval_s);
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
        if (alive) timer = setTimeout(load, nextMs.current);
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

  if (!data && !error) {
    return <p className="sub">Loading incidents…</p>;
  }

  // NO DATA IS NOT AN EMPTY BOARD. An unreachable list rendered as "no live
  // incident" is exactly the false-clean the monitor exists to prevent.
  if (!data) {
    return (
      <section className="unreachable" role="alert">
        <h2>Monitor unreachable — this is not a healthy fleet</h2>
        <p>
          The incident list could not be read. An empty list would have meant
          “no confirmed condition”; this is no data at all.
        </p>
        {error && <p className="sub">{error}</p>}
      </section>
    );
  }

  const intervalMs = nextMs.current;
  const lastKnown =
    Boolean(error) ||
    (lastOk !== null && clock - lastOk > 2 * intervalMs);
  const asOf = lastOk ? new Date(lastOk).toLocaleTimeString() : "unknown";
  const now = clock / 1000;

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

      <StaleBanner collector={data.collector} />

      <h2>Live incidents</h2>
      {data.live.length === 0 ? (
        <p className="sub">
          No live incident now. That means no confirmed condition — it does not
          by itself mean the fleet is healthy.
        </p>
      ) : (
        <div className="grid">
          {data.live.map((i) => (
            <article key={i.key} className={`tile ${tone(i.severity)}`}>
              <div className="tile-head">
                <StatusPill status={i.severity} />
                <span className="state">{i.state}</span>
              </div>
              <p>
                <strong>
                  {i.target}
                  {i.subject ? ` / ${i.subject}` : ""}
                </strong>{" "}
                <span className="sub">{i.check_id}</span>
              </p>
              <p>{i.detail ?? "no detail recorded"}</p>
              <p className="sub">
                open for {howLong(now - i.first_seen)} · last seen{" "}
                {when(i.last_seen)} · {i.observed_count} observation
                {i.observed_count === 1 ? "" : "s"}
                {i.remedy_attempts > 0 &&
                  ` · ${i.remedy_attempts} remedy attempt${
                    i.remedy_attempts === 1 ? "" : "s"
                  }${i.remedy_latched ? " (latched)" : ""}`}
              </p>
            </article>
          ))}
        </div>
      )}

      <h2>Recent history</h2>
      {data.history.length === 0 ? (
        <p className="sub">
          No history recorded. No incident has been resolved or dismissed yet —
          that is a different statement from “no live incident now”.
        </p>
      ) : (
        <div className="scroll">
          <table>
            <thead>
              <tr>
                <th>Closed</th>
                <th>State</th>
                <th>Severity</th>
                <th>Target</th>
                <th>Check</th>
                <th>Detail</th>
                <th>First seen</th>
                <th>Last seen</th>
              </tr>
            </thead>
            <tbody>
              {data.history.map((i) => (
                <tr key={`${i.key}|${i.state}|${i.resolved_at ?? i.dismissed_at}`}>
                  <td>{when(i.resolved_at ?? i.dismissed_at)}</td>
                  <td>{i.state}</td>
                  <td>
                    <StatusPill status={i.severity} />
                  </td>
                  <td>
                    {i.target}
                    {i.subject ? ` / ${i.subject}` : ""}
                  </td>
                  <td>{i.check_id}</td>
                  <td>{i.detail ?? "—"}</td>
                  <td>{when(i.first_seen)}</td>
                  <td>{when(i.last_seen)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </>
  );
}
