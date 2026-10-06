"""The publishing stack's config: the two deliberate holes, and nothing else.

THIS SUITE DOES NOT RUN THE STACK. It cannot -- the suite is offline and the
stack is three containers on a NAS. What it guards is the pair of access-control
decisions that are EASY TO TIDY AWAY AND EXPENSIVE TO LOSE:

  * /healthz stays unauthenticated, so a broken login can be told apart from a
    dead monitor. Close that hole and the one question this design exists to
    keep answerable stops being answerable.
  * /api/* bypasses from the LAN only, so the curl integration the architecture
    doc documents keeps working. Break it and every script silently starts
    reading an HTML login page instead of JSON.

A text assertion is weaker than a behavioural one and this says so; what it can
do is fail loudly when the rule is deleted, which is the failure mode that
matters here.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import Results                      # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
MONITOR = os.path.dirname(HERE)


def _read(*parts):
    with open(os.path.join(MONITOR, *parts)) as fh:
        return fh.read()


def _rules(authelia):
    """The `access_control` rules, split on their own rule marker.

    TEXT-LEVEL, because the stdlib has no YAML parser and this file's shape is
    fixed. Splitting on `- domain:` is enough to tell one rule from another, and
    that is the whole point: it is what makes "two holes, and exactly these two"
    an assertion instead of a claim about a word that appears somewhere.
    """
    block = authelia.split("access_control:", 1)[1]
    return ["- domain:" + part for part in block.split("- domain:")[1:]]


def test_the_proxy_keeps_its_two_deliberate_holes(results):
    authelia = _read("proxy", "authelia", "configuration.yml")
    compose = _read("proxy", "compose.yml")

    # THE RULES ARE COMPARED AS RULES, NOT GREPPED FOR TOKENS. A check for the
    # word `bypass` anywhere in the file stays green when the `/healthz` policy
    # is deleted but the LAN rule keeps its own `bypass` -- and it stays green
    # when a THIRD hole is opened that no check names. Both are exactly the
    # failure this suite exists to catch, and both are invisible to a substring
    # search. The pairing matters too: the health probe's rule must carry NO
    # `networks:`, because a health check that only answers from the LAN cannot
    # be run from wherever the monitor is being watched from.
    rules = _rules(authelia)
    bypass = [r for r in rules if "policy: bypass" in r]
    healthz = [r for r in rules if "^/healthz$" in r]
    lan = [r for r in rules if "198.51.100.0/24" in r]

    results.check(
        "exactly two rules bypass authentication, and they are the two named",
        len(bypass) == 2 and len(healthz) == 1 and len(lan) == 1,
        "the two holes are deliberate and a third is not: %d rule(s) bypass, "
        "%d name /healthz, %d name the LAN"
        % (len(bypass), len(healthz), len(lan)))
    results.check(
        "the health probe bypasses authentication from anywhere",
        len(healthz) == 1 and healthz[0] in bypass
        and "networks:" not in healthz[0],
        "the /healthz rule is not an unscoped bypass -- if Authelia is down the "
        "operator is locked out, and this is the only way to tell a broken login "
        "from a dead monitor")
    results.check(
        "the API bypasses authentication only from the LAN",
        len(lan) == 1 and lan[0] in bypass and "198.51.100.0/24" in lan[0],
        "the /api bypass is gone or is not scoped to the LAN -- the "
        "architecture doc publishes `curl .../api/status.json` as the way an "
        "integrator reads the contract")
    # THE POLICY, NOT THE TOKEN. The file's own comment explains the catch-all in
    # prose -- "it is two_factor like everything else" -- so a check for the bare
    # word `two_factor` stays green on a rule relaxed to `one_factor`, and stays
    # green with the rule deleted entirely. Asserting `policy: two_factor`
    # present AND `one_factor` absent is what puts the gate itself on the hook.
    results.check(
        "everything else needs two factors, and nothing is down to one",
        "policy: two_factor" in authelia and "one_factor" not in authelia,
        "no rule requires two factors, or a rule was relaxed to one -- the "
        "passkey gate is not in force")
    results.check(
        "the proxy and the auth service are both declared",
        "nginx-proxy-manager" in compose and "authelia" in compose,
        "one of the two services is missing from the compose file")
    results.check(
        "the proxy manager's own admin interface is not published",
        "81:81" not in compose and "443:443" not in compose,
        "the admin interface or 443 is published on a host port -- the control "
        "plane for the edge does not belong on the edge")
    # THE ASSERTION IS THE TOKEN, NOT THE WORD. `"proxy" in deploy.sh` would be
    # satisfied by the COMMENT Step 6 asks you to write beside the exclusion, so
    # deleting the `--exclude` while leaving the comment would keep this green --
    # a guard that cannot fail on the exact deletion it names. Verified before
    # dispatching: deploy.sh contains no occurrence of "proxy" today, so the
    # check fails now and passes only once the real exclusion lands.
    results.check(
        "sentinel's own deploy does not ship this stack",
        "--exclude 'proxy/'" in _read("deploy.sh"),
        "deploy.sh does not exclude proxy/, so a sentinel deploy would rsync a "
        "second stack's config onto the NAS")


TESTS = (test_the_proxy_keeps_its_two_deliberate_holes,)
