"""The publishing stack's config: the two deliberate holes, and nothing else.

THIS SUITE DOES NOT RUN THE STACK. It cannot -- the suite is offline and the
stack runs on a NAS. What it guards is the pair of access-control
decisions that are EASY TO TIDY AWAY AND EXPENSIVE TO LOSE:

  * /healthz stays unauthenticated, so a broken login can be told apart from a
    dead monitor. Close that hole and the one question this design exists to
    keep answerable stops being answerable.
  * /api/* bypasses from the LAN only, so the curl integration the architecture
    doc documents keeps working. Break it and every script silently starts
    reading an HTML login page instead of JSON.

A text assertion is weaker than a behavioural one and this says so; what it can
do is fail loudly when the rule is deleted, which is the failure mode that
matters here. The LAN scoping of the API hole is where that limit bites hardest:
it is asserted here as configuration text and PROVEN only by the runbook's spoof
test in docs/publishing.md, because nothing in this repo can run the stack. A
forward-auth subrequest comes from nginx, so without `X-Forwarded-For` Authelia
matches the proxy's own address -- inside the LAN -- and "LAN only" silently
means everyone.
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


def _code(text):
    """The file with its comment lines removed -- the code, not the prose.

    THIS IS LOAD-BEARING, NOT TIDINESS. `proxy/compose.yml`'s header comment reads
    "NO `ports:` ON PURPOSE", so the raw-file form `"ports:" not in compose` is a
    FALSE FAIL on a correct file. Measured: `"ports:" in compose` is True;
    `"ports:" in _code(compose)` is False.
    """
    return "\n".join(ln for ln in text.split("\n")
                     if not ln.lstrip().startswith("#"))


def _val(text):
    """A scalar's value: YAML's quoting, then its escaping, removed.

    A double-quoted YAML scalar unescapes a doubled backslash to a single one, so
    the regex Authelia actually applies to a path is the UNESCAPED form. Comparing
    the source form instead would make the expected constants below carry a doubled
    backslash and read like a typo.
    """
    text = text.strip()
    if len(text) >= 2 and text[0] == text[-1] == '"':
        return text[1:-1].replace("\\\\", "\\")
    if len(text) >= 2 and text[0] == text[-1] == "'":
        return text[1:-1].replace("''", "'")
    return text.split(" #", 1)[0].rstrip()


_RULE_KEYS = ("domain", "resources", "networks", "policy")


def _rules(authelia):
    """The `access_control` rules as STRUCTURES, plus a count of what was not read.

    WHY THIS IS NOT A SUBSTRING SEARCH, and it is measured rather than argued: this
    file used to have the checks grep inside each rule's text, and FIVE OF THE SEVEN
    stayed green under ordinary YAML edits that break the exact thing their message
    names. Appending one line -- `- ".*"` -- to the health-probe rule's `resources:`
    opens the ENTIRE SITE with no authentication and left every check green. A guard
    whose green output is read as a design claim has to be able to fail on the bypass
    it names.

    So: split the block, read the rules into dicts, and RETURN THE NUMBER OF LINES THE
    PARSER COULD NOT READ. That third return value is what turns a rule this parser
    cannot see -- a third bypass written in flow style, a `resources:` given as an
    inline list -- into a LOUD failure instead of a silent green. It is the honest
    shape for a text parser: one that says when it has stopped understanding its
    input, rather than one that reports success for the part it happened to read.

    "I could not read this" must never share a branch with "this is fine", which is
    why the checks consuming it assert `unparsed == 0` rather than ignoring it.

    Cross-checked against PyYAML 6.0.2 on the real file and recorded rather than the
    parser being trusted: identical rules, identical `default_policy`, 0 unparsed. The
    repo cannot depend on PyYAML -- the NAS container has none, and a suite that skips
    its check when a tool is missing is the absent-data defect at test level.
    """
    body, seen = [], False
    for ln in authelia.split("\n"):
        if ln.startswith("access_control:"):
            seen = True
            continue
        if not seen:
            continue
        if ln.strip() and not ln.startswith(" "):
            break                      # the next top-level key ends the block
        if ln.strip() and not ln.lstrip().startswith("#"):
            body.append(ln)

    rules, cur, key = [], None, None
    default_policy, consumed = None, 0
    for ln in body:
        indent, text = len(ln) - len(ln.lstrip(" ")), ln.strip()
        if indent == 2 and text.startswith("default_policy:"):
            default_policy = _val(text.split(":", 1)[1])
            consumed += 1
        elif indent == 2 and text == "rules:":
            consumed += 1
        elif indent == 4 and text.startswith("- "):
            name, _, value = text[2:].partition(":")
            if name.strip() != "domain":
                continue               # NOT consumed: the guard must see it
            cur = {"domain": _val(value), "resources": set(),
                   "networks": set(), "policy": None}
            rules.append(cur)
            key, consumed = None, consumed + 1
        elif indent == 6 and cur is not None:
            name, _, value = text.partition(":")
            name = name.strip()
            if name not in _RULE_KEYS:
                continue               # not consumed
            if value.strip() and name in ("resources", "networks"):
                continue               # a flow list: not consumed, not guessed
            if value.strip():
                cur[name] = _val(value)
                key = None
            else:
                key = name
            consumed += 1
        elif indent == 8 and cur is not None and key:
            if not text.startswith("- ") or not isinstance(cur.get(key), set):
                continue
            cur[key].add(_val(text[2:]))
            consumed += 1
    return rules, default_policy, len(body) - consumed


def _services(compose):
    """The keys of the `services:` block -- the services actually declared.

    THE BARE WORDS ARE NOT EVIDENCE, and this file is the proof: `authelia`
    occurs in the `authelia-data:` volume key and `nginx-proxy-manager` in this
    file's own header comment. A substring check for either name therefore stays
    GREEN with that service deleted -- a guard that cannot fail on the exact
    deletion its message names. Measured: deleting the `authelia` service alone
    leaves the bare-word form at 7 checks, 0 failed.

    Structural, and the same shape as `_rules` above: split on the block header,
    take what follows, and keep the lines that are keys at the top level of that
    block. Indent depth is the discriminator, so a nested mapping key inside a
    service (`    environment:`) is not counted as a service and the assertion
    does not depend on any service's spelling.

    ITS CEILING IS THE `\\nvolumes:` ANCHOR, and it is named here because a
    docstring that hides it would hide the failure: the block ends where the
    top-level `volumes:` key begins, so a compose file with no such key is swept
    past -- `networks: eth1:` then reads as a third service. Measured, and it
    fails in the SAFE direction: the set gains a member rather than losing one,
    so the `<=` assertion cannot be satisfied by a service that is not declared.
    """
    block = compose.split("services:", 1)[1].split("\nvolumes:", 1)[0]
    return {ln.split(":", 1)[0].strip() for ln in block.split("\n")
            if len(ln) - len(ln.lstrip(" ")) == 2 and ln.strip().endswith(":")}


def test_the_proxy_keeps_its_two_deliberate_holes(results):
    authelia = _read("proxy", "authelia", "configuration.yml")
    compose = _read("proxy", "compose.yml")

    rules, default_policy, unparsed = _rules(authelia)
    healthz = [r for r in rules if r["resources"] == {"^/healthz$"}]
    lan = [r for r in rules if r["networks"] == {"198.51.100.0/24"}]
    bypass = [r for r in rules if r["policy"] == "bypass"]
    catch_all = [r for r in rules if not r["resources"]]

    # THE RULE SET IS THE ASSERTION, NOT THE WORDS IN IT. `unparsed` is a
    # first-class outcome here: a rule this parser could not read is a FAIL,
    # never a silent green.
    results.check(
        "every access rule is readable and scoped to the published domain",
        unparsed == 0 and len(rules) == 3
        and all(r["domain"] == "${DOMAIN}" for r in rules),
        "not the three rules this design decided on: %d rule(s), %d line(s) this "
        "parser could not read, domain(s) %r -- a rule pointed at another hostname "
        "is inert, so every scripted curl through the public name reads an HTML "
        "login page instead of JSON"
        % (len(rules), unparsed, sorted({r["domain"] for r in rules})))
    results.check(
        "exactly two rules bypass authentication, and they are the two named",
        len(bypass) == 2 and len(healthz) == 1 and len(lan) == 1
        and healthz[0] is not lan[0],
        "the two holes are deliberate and a third is not: %d rule(s) bypass, "
        "%d name /healthz and nothing else, %d name the LAN and nothing else"
        % (len(bypass), len(healthz), len(lan)))
    results.check(
        "the health probe bypasses authentication from anywhere",
        len(healthz) == 1 and healthz[0]["policy"] == "bypass"
        and healthz[0]["networks"] == set(),
        "the /healthz rule is not an unscoped bypass -- if Authelia is down the "
        "operator is locked out, and this is the only way to tell a broken login "
        "from a dead monitor")
    results.check(
        "the API bypasses authentication only from the LAN",
        len(lan) == 1 and lan[0]["policy"] == "bypass"
        and lan[0]["networks"] == {"198.51.100.0/24"}
        and lan[0]["resources"] == {"^/api/status\\.json$",
                                    "^/api/state\\.json$"},
        "the /api bypass is gone, or it reaches further than the two paths it "
        "names, or it is not scoped to the LAN -- the architecture doc publishes "
        "`curl .../api/status.json` as the way an integrator reads the contract, "
        "and this is the one hole that must not widen")
    # BOTH HALVES FAIL CLOSED OR THE DASHBOARD IS PUBLIC. `default_policy` is what
    # answers a request no rule matched, and the catch-all is what the whole site
    # falls through to; relaxing either opens everything.
    results.check(
        "the default is deny and the catch-all needs two factors",
        default_policy == "deny" and len(catch_all) == 1
        and catch_all[0]["policy"] == "two_factor",
        "the fail-closed backstop is gone or the catch-all was relaxed: "
        "default_policy is %r, %d rule(s) match every path, polic(y/ies) %r -- "
        "with the catch-all open the whole dashboard is public"
        % (default_policy, len(catch_all),
           sorted({r["policy"] for r in catch_all})))
    # ORDER IS PART OF THE MEANING. Authelia evaluates the rules top-down and the
    # FIRST MATCH WINS, so any rule that matches every path swallows every rule
    # below it. Moving the catch-all one line up kills BOTH deliberate holes at
    # once -- /healthz starts demanding two factors, so a broken login can no
    # longer be told from a dead monitor, and the LAN's curl reads an HTML login
    # page instead of JSON -- and every check above stayed green without this one.
    # Measured: the catch-all moved to the front of `rules:` gave 9 checks, 0
    # failed, on the real suite in a scratch tree.
    results.check(
        "the catch-all is the last rule, so the two holes above it are reachable",
        len(catch_all) == 1 and catch_all[0] is rules[-1],
        "the rule that matches every path is not last, and Authelia evaluates the "
        "rules top-down with the first match winning -- a catch-all that is not "
        "last swallows both deliberate holes, so /healthz and the LAN's curl both "
        "end up needing two factors")
    results.check(
        "the proxy and the auth service are both declared",
        {"nginx-proxy-manager", "authelia"} <= _services(compose),
        "one of the two services is missing from the compose file -- declared: "
        "%r" % sorted(_services(compose)))
    # NEITHER SERVICE PUBLISHES ANYTHING ON THE HOST, which is the assertion --
    # not a list of the three host ports one might imagine. Measured green under
    # the old form: `ports: ["8080:81"]` (the admin UI on the NAS's own
    # interface), `ports: ["4430:443"]`, and `network_mode: host`.
    results.check(
        "the proxy manager's own admin interface is not published",
        "ports:" not in _code(compose) and "network_mode" not in _code(compose),
        "a host port or host networking puts the edge's control plane on the NAS's "
        "own interface as well -- the LAN reaches NPM at its own macvlan address "
        "and the internet reaches it through the router's port-forward, so neither "
        "service needs to publish anything")
    results.check(
        "sentinel's own deploy does not ship this stack",
        "--exclude 'proxy/'" in _code(_read("deploy.sh")),
        "deploy.sh does not exclude proxy/, so a sentinel deploy would rsync a "
        "second stack's config onto the NAS")
    # THE RUNBOOK IS THE ARTIFACT HERE, so this is a check on prose and it is worth
    # saying why that is not the defect the checks above were fixed for: there is no
    # structure to read in a document, and losing the instruction silently is
    # exactly the failure -- the LAN scoping of the API hole depends on a header
    # NPM does not set by default, and NOTHING else in this repo can see it.
    runbook = _read("docs", "publishing.md")
    results.check(
        "the runbook says how the LAN bypass is made to actually hold",
        "X-Forwarded-For" in runbook and "169.254.1.2" in runbook,
        "the runbook does not carry the X-Forwarded-For instruction and the spoof "
        "test -- a forward-auth subrequest comes from nginx, so without that header "
        "Authelia matches NPM's own address, which is inside 198.51.100.0/24, and "
        "'LAN only' silently means everyone")


TESTS = (test_the_proxy_keeps_its_two_deliberate_holes,)
