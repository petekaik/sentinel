import { useEffect, useState } from "react";
import { api, type Incident } from "../api";
import StatusPill from "../components/StatusPill";

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

/* The incident board. `/api/v1/incidents` serves the CONFIRMED rows -- what is
   on the board now -- and each row carries its own history counters (first
   seen, last seen, observations). It does not serve resolved or dismissed rows;
   see the task report, which records that mismatch rather than inventing
   history the API never sent. */
export default function Incidents() {
  const [incidents, setIncidents] = useState<Incident[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const ctrl = new AbortController();
    let alive = true;
    api
      .incidents(ctrl.signal)
      .then((rows) => {
        if (!alive) return;
        setIncidents(rows);
        setError(null);
      })
      .catch((e: unknown) => {
        if (!alive || (e as Error)?.name === "AbortError") return;
        setError(e instanceof Error ? e.message : String(e));
      });
    return () => {
      alive = false;
      ctrl.abort();
    };
  }, []);

  if (error) {
    return (
      <section className="unreachable" role="alert">
        <h2>Monitor unreachable — this is not a healthy fleet</h2>
        <p>
          The incident list could not be read. An empty list would have meant
          “no confirmed condition”; this is no data at all.
        </p>
        <p className="sub">{error}</p>
      </section>
    );
  }

  if (incidents === null) {
    return <p className="sub">Loading incidents…</p>;
  }

  const now = Date.now() / 1000;

  return (
    <>
      <h2>Live incidents</h2>
      {incidents.length === 0 ? (
        <p className="sub">
          No live incident is on the board. That means no confirmed condition —
          it does not by itself mean the fleet is healthy.
        </p>
      ) : (
        <div className="grid">
          {incidents.map((i) => (
            <article key={i.key} className={`tile ${i.severity || "grey"}`}>
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
      <p className="sub">
        When each live incident was first and last seen, and how much evidence
        is behind it.
      </p>
      {incidents.length === 0 ? (
        <p className="sub">Nothing to show.</p>
      ) : (
        <div className="scroll">
          <table>
            <thead>
              <tr>
                <th>Severity</th>
                <th>State</th>
                <th>Target</th>
                <th>Check</th>
                <th>First seen</th>
                <th>Last seen</th>
                <th>Observations</th>
              </tr>
            </thead>
            <tbody>
              {[...incidents]
                .sort((a, b) => b.last_seen - a.last_seen)
                .map((i) => (
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
                    <td>{when(i.first_seen)}</td>
                    <td>{when(i.last_seen)}</td>
                    <td>{i.observed_count}</td>
                  </tr>
                ))}
            </tbody>
          </table>
        </div>
      )}
    </>
  );
}
