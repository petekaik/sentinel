"""Checks about the monitor itself, rather than about the fleet.

These exist because the monitor's own failure modes are the ones nobody notices:
a monitor that stopped collecting, or that has a threshold wired to nothing,
looks on the dashboard exactly like a healthy fleet. The web layer renders the
staleness banner; this module covers the "wired to nothing" half.

A note on why these are checks and not startup assertions: a startup assertion
either kills the container (so there is no dashboard to explain why) or logs to a
place nobody reads. As a check it gets a row, a colour, and a place in the
incident history -- which is what makes it possible to answer "since when?" later.
"""

from checks import Check, ok, unknown, fail


class SpecCoverage(Check):
    """Every declared threshold is either claimed by a check, or says why not.

    THE DEFECT THIS CATCHES. `thresholds.load()` validates the threshold file's
    own syntax strictly, so a misspelt key or an unparseable boundary is a loud
    startup failure. It cannot see a section that is perfectly well-formed and
    that no check ever reads -- and that is the ordinary way a data-driven
    threshold file rots. The author adds `[gap_sources]`, means to write the
    check, writes the threshold, and the check never comes. The file looks
    correct, the dashboard has no row for it, and a threshold that silently does
    nothing renders identically to a healthy fleet.

    It was not hypothetical: measured 2026-09-26, FOUR of the 22 declared
    sections (`temperature`, `heartbeat_age_min`, `orphan_parts`, `gap_sources`)
    were claimed by no check, and the only reason it was found is that the
    section list was diffed against the registry by hand. Nothing in the code
    said so. That diff is now this check.

    THE THREE OUTCOMES, and the middle one is the point:

      * every spec claimed                          -> OK
      * some spec carries `claim = <reason>`        -> UNKNOWN, reason in words
      * some spec has neither                       -> FAIL

    Why the deferred case is UNKNOWN and not OK or WARN. A spec that says
    "phase 3" is a real, deliberate gap in coverage, and the project's rule is
    that an unavailable answer is grey with the reason in words -- never green.
    Making it WARN would be an amber tile that is amber on a healthy fleet
    forever, and item 72 establishes that a permanent false alarm is worse than
    no check, because it trains the operator to ignore the colour. Making it OK
    would be a green tile for a metric nobody measures, which is the exact thing
    this check exists to prevent.

    Why an unclaimed spec is FAIL and not WARN: it is a defect someone introduced
    minutes ago by editing one file, it is fixed by editing that file, and its
    steady state on a correct file is zero. That is the profile of a genuine
    failure, not of noise.
    """

    id = "spec_coverage"
    target = "fleet"
    spec = None                      # deliberately: this check reads the FILE

    def run(self, ctx):
        classes = ctx.check_classes
        if classes is None:
            # Not a fleet problem -- a wiring problem in the caller. Said out
            # loud rather than reported as full coverage, because "I was never
            # told which checks run" must not render as "everything is claimed"
            # (items 28/46/62: the answer is no vs I could not ask).
            return unknown(
                self.id, self.target,
                "the collector did not supply its check registry, so spec "
                "coverage CANNOT BE AUDITED. This is not a coverage failure; it "
                "is the audit being unable to run. Set Context.check_classes "
                "from the collector's registry before evaluating checks.",
                subject="checks.conf",
            )

        claimed, deferred, unclaimed = _audit(ctx.specs, classes)
        n = len(ctx.specs)
        ev = {
            "declared": n,
            "claimed": len(claimed),
            "deferred": sorted(deferred),
            "unclaimed": sorted(unclaimed),
            "check_classes": len(classes),
        }

        if unclaimed:
            return fail(
                self.id, self.target,
                "%d of %d thresholds in checks.conf are claimed by NO CHECK and "
                "declare no reason: %s. A threshold no check reads does nothing "
                "at all -- it is not a loose bound, it is an absent check -- and "
                "an absent row reads on the dashboard exactly like a healthy "
                "fleet. Fix by writing the check that sets `spec = \"<id>\"`, or "
                "by adding `claim = <why it is not implemented yet>` to the "
                "section, which renders it as an explicit grey gap instead."
                % (len(unclaimed), n, ", ".join(sorted(unclaimed))),
                subject="checks.conf", evidence=ev,
            )

        if deferred:
            return unknown(
                self.id, self.target,
                "%d of %d thresholds are declared with no check behind them, "
                "each stating its own reason: %s. Nothing is wrong with the "
                "monitor -- these are known, deliberate gaps in coverage, and "
                "they are UNKNOWN rather than green so that an unmeasured metric "
                "is never mistaken for a healthy one."
                % (len(deferred), n,
                   "; ".join("%s (%s)" % (k, deferred[k].claim)
                             for k in sorted(deferred))),
                subject="checks.conf", evidence=ev,
            )

        res = ok(
            self.id, self.target,
            "all %d declared thresholds are claimed by a check (%d check "
            "classes in the registry), and none is deferred."
            % (n, len(classes)),
            subject="checks.conf", evidence=ev,
        )
        res.metric("specs_declared", n, "specs")
        res.metric("specs_unclaimed", 0, "specs")
        return res


def _audit(specs, classes):
    """Indirection so the offline suite can exercise this without thresholds."""
    import thresholds
    return thresholds.audit(specs, classes)
