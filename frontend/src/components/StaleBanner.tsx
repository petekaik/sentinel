import type { CollectorLiveness } from "../api";

/* The one freshness banner, shared by every page that can show "nothing is
   wrong" from data that is not current. `fresh` is the only value with nothing
   to say; every other value says that what follows is not a live description
   of the fleet. */

export function span(seconds: number | null | undefined): string {
  if (seconds == null) return "never";
  if (seconds < 90) return `${Math.round(seconds)}s`;
  if (seconds < 5400) return `${(seconds / 60).toFixed(1)} min`;
  return `${(seconds / 3600).toFixed(1)} h`;
}

export default function StaleBanner({
  collector,
}: {
  collector: CollectorLiveness;
}) {
  if (collector.staleness === "fresh") return null;
  const last =
    collector.last_age_s == null ? "never" : `${span(collector.last_age_s)} ago`;
  const limit =
    collector.stale_after_s == null
      ? "past the staleness limit"
      : `past the ${span(collector.stale_after_s)} limit`;

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
        was {last}, {limit}. Everything below describes the fleet as it was.
      </div>
    );
  }
  if (collector.staleness === "lagging") {
    return (
      <div className="banner amber" role="alert">
        <strong>Collector lagging.</strong> The last collection was {last}; the
        page is behind, though not yet {limit}.
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
