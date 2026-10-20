import { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { api, type Status } from "../api";
import StatusPill from "../components/StatusPill";

const DEFAULT_INTERVAL_S = 60;
const INCIDENT_PREVIEW = 5;

function span(seconds: number | null | undefined): string {
  if (seconds == null) return "never";
  if (seconds < 90) return `${Math.round(seconds)}s`;
  if (seconds < 5400) return `${(seconds / 60).toFixed(1)} min`;
  return `${(seconds / 3600).toFixed(1)} h`;
}

function tone(verdict: string): string {
  return (
    { ok: "green", warn: "amber", fail: "red", unknown: "grey" }[verdict] ??
    "grey"
  );
}

/* The stale banner is the whole reason this page cannot be a list of green
   numbers. `fresh` is the only value with nothing to say; every other value
   says that what follows is not a live description of the fleet. */
function StaleBanner({ collector }: { collector: Status["collector"] }) {
  if (collector.staleness === "fresh") return null;
  const last =
    collector.last_age_s == null ? "never" : `${span(collector.last_age_s)} ago`;

  if (collector.staleness === "none") {
    return (
      <div className="banner red" role="alert">
        <strong>No collection has ever been recorded.</strong> There is no
        observation of this fleet at all, so this page knows nothing about it.
        That is not the same as a healthy fleet.
      </div>
    );
  }
  if (collector.staleness === "stale") {
    return (
      <div className="banner red" role="alert">
        <strong>STALE — this is not a live verdict.</strong> The last collection
        was {last}, past the {span(collector.stale_after_s)} limit. Everything
        below describes the fleet as it was.
      </div>
    );
  }
  if (collector.staleness === "lagging") {
    return (
      <div className="banner amber" role="alert">
        <strong>Collector lagging.</strong> The last collection was {last}; the
        page is behind, though not yet past its {span(collector.stale_after_s)}{" "}
        staleness limit.
      </div>
    );
  }
  return (
    <div className="banner amber" role="alert">
      <strong>Unknown collector state “{collector.staleness}”.</strong> The page
      cannot say whether the data below is current.
    </div>
  );
}

export default function Overview() {
  const [status, setStatus] = useState<Status | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(true);
  // The collector's own interval, not a second literal: the page must refresh
  // at the rate the backend says it collects. Held in a ref because changing it
  // must not restart the effect (and re-fire the first request).
  const nextMs = useRef(DEFAULT_INTERVAL_S * 1000);

  useEffect(() => {
    let alive = true;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let ctrl: AbortController | undefined;

    const load = async () => {
      ctrl = new AbortController();
      try {
        const s = await api.status(ctrl.signal);
        if (!alive) return;
        setStatus(s);
        setError(null);
        const secs = Number(s.collector?.interval_s);
        if (Number.isFinite(secs) && secs >= 5) nextMs.current = secs * 1000;
      } catch (e) {
        if (!alive || (e as Error)?.name === "AbortError") return;
        setError(e instanceof Error ? e.message : String(e));
      } finally {
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

  return (
    <>
      {error && (
        <div className="banner red" role="alert">
          <strong>Monitor unreachable — this is not a healthy fleet.</strong>{" "}
          The last refresh failed ({error}), so everything below is the last
          known state, not a live one.
        </div>
      )}

      <StaleBanner collector={c} />

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
        Collected {c.last_age_s == null ? "never" : `${span(c.last_age_s)} ago`}
        {c.epoch_seq != null && ` · epoch ${c.epoch_seq}`}
        {c.duration_ms != null && ` · ${c.duration_ms} ms`}
        {c.errors != null && ` · ${c.errors} errors`} · refreshing every{" "}
        {span(c.interval_s)}
      </p>
    </>
  );
}
