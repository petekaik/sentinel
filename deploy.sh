#!/bin/bash
# sentinel/deploy.sh
# Deploy / upgrade the sentinel container on Storage-NAS.
#
# Usage:
#   ./deploy.sh                    # sync, build, start
#   ./deploy.sh --status           # what is running, what it sees
#   ./deploy.sh --once             # one collection, print it, exit
#   ./deploy.sh --once --dry-run   # ... and write NOTHING to the store
#   ./deploy.sh --showconf         # config + threshold coverage
#   ./deploy.sh --authorise-backup # let the monitor ssh to Backup-NAS
#   ./deploy.sh --logs             # follow the container log
#   ./deploy.sh --dismiss          # list the live incidents
#   ./deploy.sh --dismiss <key> --reason "why"
#                                                     # close one BY HAND. Read
#                                                     #   app/dismiss.py first:
#                                                     #   this is for an incident
#                                                     #   no check can ever
#                                                     #   close, and it is not
#                                                     #   a way to hide a fault.
#
# Environment overrides: STORAGE_IP, STORAGE_USER, MONITOR_DIR, MONITOR_DOCKER
#
# WHY A SCRIPT AT ALL, when `docker compose up -d` would nearly do. Three things
# travel with the image and are not in it: the ssh key, the known_hosts file and
# the operator's .env. Each has a way of being silently wrong that produces a
# permanently grey or permanently green fleet, and each is checked here rather
# than discovered later. (A fourth used to: a reference copy of worker.sh for the
# drift check. It went away with item 90 -- both sides of that comparison now
# come from the box's own applied generation, so nothing is pushed for it.)
#
# BUILD ON THE NAS. NEVER SHIP THE MAC'S IMAGE. This Mac is Apple Silicon; the
# NAS is x86_64. `docker build` here yields an aarch64 image that fails on the
# NAS with `exec format error`, and `docker save`/`load` moves the wrong
# architecture just as happily. The build context is rsynced and built remotely;
# there is no local build path, deliberately.
#
# set -euo pipefail; macOS /bin/bash 3.2 -- no associative arrays, no ${var,,}.

set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

STORAGE_IP="${STORAGE_IP:-198.51.100.10}"
STORAGE_USER="${STORAGE_USER:-admin}"
MONITOR_DIR="${MONITOR_DIR:-/share/CACHEDEV1_DATA/Programs/sentinel}"
# Not on PATH on QTS. Measured 2026-09-26: `command -v docker` finds nothing and
# this path is the one that answers, with compose v2.29.1-qnap2 as a plugin.
MONITOR_DOCKER="${MONITOR_DOCKER:-/share/CACHEDEV1_DATA/.qpkg/container-station/bin/docker}"
# Only used for the URLs this script prints and curls. The container gets the
# real values from .env; these must agree with it or the health check reads a
# healthy container as unreachable.
#
# The monitor holds its OWN LAN address on the `eth1` macvlan network and
# publishes no host port, so the dashboard is NOT on $STORAGE_IP -- curling the
# NAS's own address would report a perfectly healthy container as unreachable.
MONITOR_PORT="${MONITOR_PORT:-8787}"
MONITOR_IP="${MONITOR_IP:-198.51.100.11}"

BACKUP_IP="${BACKUP_IP:-198.51.100.20}"
BACKUP_USER="${BACKUP_USER:-admin}"

MODE=deploy
PASSTHRU=()
TRUST_NEW_HOST_KEYS=0

while [ $# -gt 0 ]; do
    case "$1" in
        --status)           MODE=status ;;
        --logs)             MODE=logs ;;
        --once)             MODE=once; PASSTHRU+=(--once) ;;
        --dry-run)          MODE=once; PASSTHRU+=(--dry-run) ;;
        --showconf)         MODE=showconf ;;
        --dismiss)          MODE=dismiss
                            # Everything after --dismiss belongs to dismiss.py,
                            # including a --reason whose text contains anything
                            # at all. Taken verbatim rather than rebuilt, so the
                            # shell never re-splits the operator's words -- and
                            # the reason IS the record, so mangling it would
                            # destroy the only thing this verb produces.
                            shift
                            PASSTHRU=("$@")
                            break ;;
        --authorise-backup) MODE=authorise ;;
        --trust-new-host-keys) TRUST_NEW_HOST_KEYS=1 ;;
        # Deliberately NOT a line range. Six of the eight --help blocks in this
        # repo used to print their own header by line count and five were wrong,
        # two of them silently withholding real content (docs/08 item 57). An
        # anchored range cannot drift when the header above it changes.
        # The terminator is a BARE `#`, not an empty line: every line of this
        # header starts with `#`, so /^$/ never matches until the comment block
        # ends -- and the first attempt at this printed the entire header.
        -h|--help)          sed -n '/^# Usage:/,/^#$/p' "$0" | sed 's/^# \{0,1\}//'
                            exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
    shift
done

SSH_OPTS=(-o ConnectTimeout=10 -o BatchMode=yes)
# IdentitiesOnly: without it, ssh offers every key in the agent in turn, and the
# NAS's MaxAuthTries can refuse the connection before reaching the right one --
# which reads as "the key does not work" (07-build-native.sh has the same note).
SSH_OPTS+=(-o IdentitiesOnly=yes)

remote() { ssh "${SSH_OPTS[@]}" "$STORAGE_USER@$STORAGE_IP" "$@"; }
rcopy()  { scp -q "${SSH_OPTS[@]}" -r "$@"; }
dc()     { remote "cd '$MONITOR_DIR' && '$MONITOR_DOCKER' compose $*"; }

# A ONE-OFF COMMAND INSIDE THE COLLECTOR'S OWN CONTAINER.
#
# This was `docker compose run --rm --no-deps monitor ...`, and THAT CANNOT WORK
# ON A MACVLAN ADDRESS. Measured 2026-09-26, minutes after the container was moved
# onto `eth1`: `compose run` builds a SECOND container from the same service
# definition, which means the same static `ipv4_address` -- and that address is
# already held by the running container:
#
#   Error response from daemon: Address already in use
#
# So every `--status` and every `--once` died with that line and told the operator
# NOTHING about the fleet, while the deploy itself reported success. This is the
# conversion's own blind spot: the address is the access control, and it is also
# an exclusive resource, so anything that clones the service collides with it.
#
# `docker exec` avoids this by construction -- a second PROCESS in the running
# container's existing network namespace, needing no second address and inheriting
# the mounts, the environment and the ssh material exactly. It is also why exec is
# the right shape here rather than a network override: `compose run` has no flag
# that replaces a service's own network config.
#
# THE FALLBACK IS NOT DECORATION, and the two branches together cover every case.
# `exec` requires a running container, and the moment `--status` matters most is
# when the container is NOT running -- which is exactly when the address IS free,
# so `compose run` is valid again. Neither branch can silently report nothing: if
# the container is down the `run` path starts a fresh one, if it is up `exec`
# reports. The inspect output is matched exactly (`^true$`) rather than grepped
# loosely, so a container that is `paused` or `restarting` takes the `run` path
# instead of producing an exec error that reads like a code fault.
# POSIX single-quoting for one argument, so a remote shell re-splits it back into
# exactly one word. This is item 81's trap in the direction that costs something:
# ssh joins argv with spaces and the remote shell re-splits, so an unquoted
# `--reason "TVH has auth on"` arrives as four arguments and dismiss.py refuses
# for a missing reason -- or worse, records a reason that is one word of what the
# operator typed. The reason IS the record this verb produces.
shq() { printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"; }

# A ONE-OFF COMMAND INSIDE THE COLLECTOR'S OWN CONTAINER, running `script`.
_oneoff() {
    _script="$1"; shift
    _args=""
    for a in "$@"; do _args="$_args $(shq "$a")"; done
    if remote "'$MONITOR_DOCKER' inspect -f '{{.State.Running}}' sentinel 2>/dev/null" | grep -q '^true$'; then
        remote "'$MONITOR_DOCKER' exec sentinel python3 $_script$_args"
    else
        dc "run --rm --no-deps monitor python3 $_script$_args"
    fi
}

dc_oneoff()  { _oneoff /app/collect.py "$@"; }
dc_dismiss() { _oneoff /app/dismiss.py "$@"; }

die() { echo "ERROR: $*" >&2; exit 1; }

# ---------------------------------------------------------------------------
echo "==> $STORAGE_USER@$STORAGE_IP:$MONITOR_DIR"
# ---------------------------------------------------------------------------

# The local half of the credential. Checked FIRST, because every remote step
# below is wasted without it and a missing key otherwise surfaces as an scp
# error naming a path the reader did not choose.
#
# THE KEY IS NOT IN THIS REPO, AND MUST NOT BE. It is the monitor's service
# credential: the private half grants login to every CuBox, and it lives here in
# the operator's own ~/.ssh rather than in a tree that is under version control.
# Override with MONITOR_KEY= when it lives elsewhere.
KEY="${MONITOR_KEY:-$HOME/.ssh/cubox-monitor_ed25519}"
PUB="$KEY.pub"
[ -s "$KEY" ] || die "$KEY is missing. It is the monitor's service key; the
       public half is baked into the CuBoxes as
       configs/rootfs/monitor_id.pub in the FLEET repo. Regenerate the pair with:
         ssh-keygen -t ed25519 -N '' -C cubox-monitor -f $KEY
       ...but note that a NEW pair no longer matches monitor_id.pub, so the
       CuBoxes must be rebuilt and redeployed before the monitor can ssh to them.
       Set MONITOR_KEY= if the key lives somewhere else."
[ -s "$PUB" ] || die "$PUB is missing. It is derivable from the private half:
       ssh-keygen -y -f $KEY > $PUB"

# THE PUBLIC HALF MUST MATCH WHAT THE FLEET AUTHORISES.
#
# This is the one check in this script that reads the FLEET repo, because the
# fact it needs -- which public key the CuBox image installs into
# authorized_keys -- is T1 content and belongs to the fleet, not here. The
# pointer is overridable and its failure is LOUD: a missing checkout must not
# skip the comparison, because skipping it reports a working credential for a
# key every CuBox would refuse. That is items 46/62 -- "I could not ask" and
# "the answer is no" get different remedies, so they get different messages.
FLEET_REPO="${FLEET_REPO:-$HOME/projects/pvr-cubox-fleet}"
FLEET_PUB="$FLEET_REPO/configs/rootfs/monitor_id.pub"
[ -s "$FLEET_PUB" ] || die "cannot read $FLEET_PUB
       That file is the fleet's record of the public key its image installs, and
       without it this script cannot tell whether the monitor's key would be
       accepted by a CuBox. It lives in the FLEET repo -- set
       FLEET_REPO=/path/to/pvr-cubox-fleet if it is not at the default location.
       This is NOT a licence to skip the check: a monitor whose key no longer
       matches the fleet reports every box as UNKNOWN and looks like an outage."
cmp -s "$PUB" "$FLEET_PUB" || die \
    "$PUB and $FLEET_PUB DIFFER.
       The fleet authorises the latter, so the container's key would be refused
       by every CuBox. One of the two has been regenerated without the other."
echo "    key:    $(ssh-keygen -l -f "$PUB" | awk '{print $2}') (matches the fleet's monitor_id.pub)"

if [ "$MODE" = deploy ]; then
    remote true 2>/dev/null || die "cannot ssh to $STORAGE_USER@$STORAGE_IP"
    remote "test -x '$MONITOR_DOCKER'" || die \
        "'$MONITOR_DOCKER' is not executable on $STORAGE_IP.
       Container Station's docker is not on PATH under a non-interactive ssh;
       the path above is the measured one. Override with MONITOR_DOCKER=..."
    ARCH="$(remote 'uname -m')"
    [ "$ARCH" = x86_64 ] || die "the NAS reports $ARCH; this script builds for its own architecture"
fi

# ---------------------------------------------------------------------------
# --authorise-backup: the one change this script makes OUTSIDE the NAS
# ---------------------------------------------------------------------------
if [ "$MODE" = authorise ]; then
    # Deliberately a separate mode, not part of `deploy`. This edits a THIRD
    # host's credential file, and a routine redeploy must never do that.
    #
    # WHY IT IS NEEDED: the transcode picture is read from the per-device state
    # export on Backup-NAS over ssh -- not an NFS mount in the container, which
    # would need SYS_ADMIN. Without this the worker/heartbeat/queue checks are
    # UNKNOWN, and UNKNOWN is not green, so the dashboard says so honestly rather
    # than pretending. This is what makes them answer.
    K="$(cat "$PUB")"
    FP="$(awk '{print $2}' "$PUB")"
    echo "==> Authorising the monitor on $BACKUP_USER@$BACKUP_IP"
    echo "    fingerprint: $FP"
    # Idempotent, and it backs the file up first. It also repairs a missing
    # trailing newline: appending to a file whose last line is unterminated
    # CONCATENATES the two keys into one unparseable line and silently kills
    # both, which is the kind of failure that shows up as "the key stopped
    # working" long after this command.
    ssh "${SSH_OPTS[@]}" "$BACKUP_USER@$BACKUP_IP" "
        set -e
        AK=\$HOME/.ssh/authorized_keys
        mkdir -p \$HOME/.ssh; chmod 700 \$HOME/.ssh
        if grep -qF '$FP' \"\$AK\" 2>/dev/null; then
            echo '    already present; no change'
        else
            [ -f \"\$AK\" ] && cp -p \"\$AK\" \"\$AK.bak-\$(date +%Y%m%d)\" || true
            if [ -f \"\$AK\" ] && [ -n \"\$(tail -c 1 \"\$AK\")\" ]; then
                printf '\n' >> \"\$AK\"
                echo '    (added a missing trailing newline first)'
            fi
            printf '%s\n' '$K' >> \"\$AK\"
            chmod 600 \"\$AK\"
            echo '    appended'
        fi
        echo \"    lines now: \$(wc -l < \$AK)\"
    "
    echo ""
    echo "Verify with:  ssh -i $KEY $BACKUP_USER@$BACKUP_IP hostname"
    exit 0
fi

# ---------------------------------------------------------------------------
# --status / --logs / --once / --showconf all run against what is deployed
# ---------------------------------------------------------------------------
case "$MODE" in
    logs)
        dc "logs --tail=80 -f monitor"
        exit 0 ;;
    status)
        echo ""
        echo "--- container ---"
        dc "ps" || true
        echo ""
        echo "--- the collector's own last epoch (from the store) ---"
        dc_oneoff "--status" || true
        echo ""
        echo "--- live endpoints ---"
        # The dashboard answering is the ONLY dead-man switch this design has, so
        # it is checked rather than assumed. -s -o /dev/null -w to get the code.
        #
        # CURLED FROM THIS MAC, NOT FROM THE NAS, and that is not a stylistic
        # choice. The container holds its own address on the `eth1` macvlan
        # network, and macvlan's defining restriction is that A CONTAINER CANNOT
        # BE REACHED FROM ITS OWN HOST -- the NAS cannot open a connection to
        # 198.51.100.11. Curling from the NAS would therefore report a perfectly
        # healthy container as unreachable on every run, which is a check that is
        # permanently wrong (item 72's family: a permanent false FAIL is worse
        # than no check). Any other machine on the LAN, including this Mac, can
        # reach it normally.
        for p in / /api/status.json /healthz; do
            code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 \
                    "http://${MONITOR_IP:-198.51.100.11}:${MONITOR_PORT:-8787}$p" 2>/dev/null || echo "---")"
            printf '    %-20s %s\n' "$p" "${code:-unreachable}"
        done
        exit 0 ;;
    dismiss)
        # This sits below the deploy, like every other mode, and that is
        # deliberate: `--dismiss` acts on what is DEPLOYED. Dismissing against a
        # stale container would run an older store.py -- and the failure mode if
        # that older copy lacked `dismiss()` is an ImportError rather than a
        # wrong answer, but the reverse (an older copy whose dismissal rule
        # differs) would silently write a row this revision cannot read back.
        # The sync above is idempotent and cheap, so agreement is guaranteed
        # rather than assumed.
        dc_dismiss ${PASSTHRU[@]+"${PASSTHRU[@]}"}
        exit $? ;;
    # PASS THE ARRAY, NEVER A JOINED STRING. This branch used to build
    # `ARGS="$ARGS $a"` from an empty ARGS and then call `dc_oneoff "$ARGS"`,
    # which hands `_oneoff` ONE argument -- the whole string, leading space and
    # all -- and `_oneoff` then single-quotes it as one word for the remote
    # shell. collect.py therefore received the literal argv element ` --once`,
    # which argparse does not recognise:
    #
    #     collect.py: error: unrecognized arguments:  --once
    #     collect.py: error: unrecognized arguments:  --once --dry-run
    #
    # (the double space is the tell: it is the concatenated string, not two
    # flags). `--showconf` and `--status` survived only because they assign a
    # CLEAN LITERAL with no leading space -- so the two documented invocations
    # in this file's own header, and the one at the bottom of the deploy, were
    # the two that could not run. Item 81's family: argv is joined and
    # re-split by the remote shell, so anything that re-joins argv locally is
    # already wrong before ssh sees it.
    #
    # `${PASSTHRU[@]+"${PASSTHRU[@]}"}` rather than "${PASSTHRU[*]}": under
    # `set -u`, macOS bash 3.2 treats the expansion of an EMPTY array as an
    # unset variable and aborts. The `dismiss` branch above uses this same
    # idiom -- this is not a new pattern, it is the one that already worked.
    showconf)
        dc_oneoff --showconf
        exit $? ;;
    once)
        dc_oneoff ${PASSTHRU[@]+"${PASSTHRU[@]}"}
        exit $? ;;
esac

# ---------------------------------------------------------------------------
# Deploy
# ---------------------------------------------------------------------------
echo ""
echo "==> Syncing the tree"
remote "mkdir -p '$MONITOR_DIR'"
# --delete is scoped by these excludes and that scoping is load-bearing.
# rsync protects excluded paths from --delete, so these are safe by mechanism
# rather than by hope:
#   data/  is the SQLite store, which OUTLIVES the container by design. Deleting
#          it would silently discard the fleet's only durable log and every
#          incident ever recorded.
#   .env   is the operator's file, created once from .env.example and never
#          overwritten (see its header). A deploy that reset it would revert a
#          corrected media path without saying so.
#   ssh/   is written by the explicit copy below and by the known_hosts build,
#          never by rsync. This became load-bearing at the split: while this
#          script lived inside the fleet repo the key was IN the source tree, so
#          the path existed on both sides and --delete had nothing to remove.
#          Now that the key lives in ~/.ssh, an unexcluded ssh/ is a path the
#          source does not have -- so rsync would delete the container's key and
#          known_hosts on every deploy and rebuild them a few lines later. The
#          window is small and the outcome usually identical, which is exactly
#          what makes it worth excluding rather than relying on the rebuild.
#   .git/  and docs/ are this repo's, not the container's.
#   tests/ is 200 KB of offline suites the image does not run.
#   proxy/ is the publishing stack, which is a separate concern with its own
#          compose file: a sentinel deploy must not ship a second stack's config
#          to the NAS.
rsync -az --delete \
    --exclude 'data/' --exclude '.env' --exclude 'ssh/' --exclude '.git/' \
    --exclude 'docs/' --exclude 'tests/' --exclude 'proxy/' \
    --exclude '__pycache__/' --exclude '*.pyc' \
    -e "ssh ${SSH_OPTS[*]}" \
    "$REPO_DIR/" "$STORAGE_USER@$STORAGE_IP:$MONITOR_DIR/"
echo "    app/, checks.conf, Dockerfile, compose.yml"

# ---------------------------------------------------------------------------
echo ""
echo "==> Operator file (.env)"
# ---------------------------------------------------------------------------
# Created ONCE. Never overwritten: several values in it are judgements made
# against the fleet as it is, and a deploy that reset them would silently revert
# a correction.
if remote "test -f '$MONITOR_DIR/.env'"; then
    echo "    exists; left alone"
    # ...but "left alone" cannot mean "never gains a knob it needs". LOCAL_IPV4
    # was introduced when the container moved onto the macvlan network, and an
    # .env written before that has no such line. compose.yml carries a default,
    # so the container would still start -- on an address the operator never
    # agreed to and cannot see in their own config, which is worse than a
    # failure. So the line is ADDED if absent (never rewritten if present), and
    # the superseded MONITOR_BIND is reported rather than deleted: it is inert
    # now, and a knob that silently does nothing is its own trap.
    if remote "grep -q '^LOCAL_IPV4=' '$MONITOR_DIR/.env'"; then
        echo "    LOCAL_IPV4 present: $(remote "grep '^LOCAL_IPV4=' '$MONITOR_DIR/.env'")"
    else
        remote "
            set -e
            f='$MONITOR_DIR/.env'
            [ -s \"\$f\" ] && [ -n \"\$(tail -c 1 \"\$f\")\" ] && printf '\n' >> \"\$f\"
            printf '\n# Added by deploy.sh: the container now holds its own\n' >> \"\$f\"
            printf '# address on the eth1 macvlan network (no host port is published).\n' >> \"\$f\"
            printf 'LOCAL_IPV4=%s\n' '$MONITOR_IP' >> \"\$f\"
            chmod 600 \"\$f\"
            echo \"    added LOCAL_IPV4=$MONITOR_IP\"
        "
    fi
    if remote "grep -q '^MONITOR_BIND=' '$MONITOR_DIR/.env'"; then
        echo "    NOTE: MONITOR_BIND is still in .env and is now INERT -- the port"
        echo "          publish it configured is gone. Harmless; delete when convenient."
    fi
else
    rcopy "$REPO_DIR/.env.example" "$STORAGE_USER@$STORAGE_IP:$MONITOR_DIR/.env"
    remote "chmod 600 '$MONITOR_DIR/.env'"
    echo "    created from .env.example -- REVIEW IT before trusting the dashboard"
fi

# ---------------------------------------------------------------------------
echo ""
echo "==> ssh material"
# ---------------------------------------------------------------------------
remote "mkdir -p '$MONITOR_DIR/ssh' && chmod 700 '$MONITOR_DIR/ssh'"
rcopy "$KEY" "$STORAGE_USER@$STORAGE_IP:$MONITOR_DIR/ssh/id_ed25519"
remote "chmod 600 '$MONITOR_DIR/ssh/id_ed25519'"

# known_hosts is BUILT here, not scanned blindly.
#
# StrictHostKeyChecking=yes is what the container uses, so this file is the whole
# of its trust. A bare `ssh-keyscan` would trust whatever answered at that
# address on the day it ran, which is trust-on-first-use with the "first use"
# chosen by whoever ran the script.
#
# So: scan the address the container will actually dial, and compare it against
# what this Mac already trusts for the same host. A mismatch is either a
# regenerated host key (legitimate -- the CuBoxes' keys are state-managed and a
# state rebuild replaces them) or something worse, and the two are not
# distinguishable from here. It refuses and names the override.
echo "    building known_hosts from the live hosts, checked against this Mac's records"

# Read a host key out of THIS Mac's known_hosts. Two things are load-bearing:
#
# 1. `|| true` ON EVERY PIPELINE. `ssh-keygen -F` exits 1 for a host it does not
#    know, and `ssh-keyscan | head` dies of SIGPIPE (141) when head closes early.
#    Under `set -euo pipefail` a FAILING COMMAND SUBSTITUTION IN AN ASSIGNMENT
#    ABORTS THE SHELL -- so `trusted="$(ssh-keygen -F ... | grep ...)"` killed
#    this script outright on the first host it did not know, printing NO error
#    at all: the log simply stopped mid-sentence. Measured 2026-09-26, and it is
#    the item-26 family (a producer that legitimately exits non-zero inside a
#    pipeline). The `live=` line carried the identical latent defect and would
#    have fired the moment a host was down -- which is exactly when this check
#    matters.
#
# 2. THE ADDRESS IS TRIED FIRST, because that is what known_hosts actually
#    stores. `cubox-1` is an ssh_config ALIAS; alias names are not written to
#    known_hosts, so `ssh-keygen -F cubox-1` finds nothing on this Mac while
#    `ssh-keygen -F 198.51.100.31` finds the real record. Looking up only by
#    alias did not merely abort -- had it survived it would have reported
#    "this Mac has no record" for both boxes on every run, which is a check that
#    is permanently wrong rather than permanently silent. The alias is still
#    tried as a fallback for a known_hosts that IS alias-keyed (e.g. via
#    HostKeyAlias).
# 3. IT RETURNS "type key", NOT JUST THE KEY, because the hosts do not all offer
#    the same key type. Backup-NAS is an armv5 BusyBox QTS whose sshd answers
#    RSA ONLY -- measured 2026-09-26: `ssh-keyscan -t ed25519 198.51.100.20`
#    returns nothing at all, while this Mac's known_hosts holds an RSA record for
#    it (AAAAB3NzaC1yc2EA...). The CuBoxes are ed25519. A hardcoded `-t ed25519`
#    therefore works for two hosts and declares the third missing, and the deploy
#    dies with "known_hosts is incomplete" on a host that is perfectly reachable.
#    So the type travels with the key and the comparison is always like-for-like:
#    comparing an ed25519 key against an RSA one would read as "DIFFERS" and
#    accuse a host of changing its key when it never did.
known_host_line() {   # $1=address $2=alias -> "type key", or nothing
    local out=""
    out="$(ssh-keygen -F "$1" 2>/dev/null | grep -v '^#' | head -1 | awk '{print $2, $3}' || true)"
    if [ -z "$out" ] && [ -n "${2:-}" ]; then
        out="$(ssh-keygen -F "$2" 2>/dev/null | grep -v '^#' | head -1 | awk '{print $2, $3}' || true)"
    fi
    printf '%s' "$out"
}

TMP_KH="$(mktemp)"
trap 'rm -f "$TMP_KH"' EXIT
KH_FAIL=0
for pair in "cubox-1:198.51.100.31" "cubox-2:198.51.100.32" "backup:$BACKUP_IP"; do
    hname="${pair%%:*}"
    ip="${pair##*:}"
    tline="$(known_host_line "$ip" "$hname")"
    ttype="${tline%% *}"
    tkey="${tline#* }"
    # `known_host_line` prints "type key"; with nothing found it prints nothing,
    # and the two expansions above then both yield the empty string. Guard the
    # no-space case explicitly rather than relying on that.
    if [ -z "$tline" ] || [ "$tline" = "$ttype" ]; then ttype=""; tkey=""; fi

    # `grep -v '^#'` IS REQUIRED, not tidiness. ssh-keyscan prints BANNER COMMENT
    # LINES before the key it was asked for:
    #     # 198.51.100.31 SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u2
    #     198.51.100.31 ssh-ed25519 AAAAC3Nza...
    # so `| head -1 | awk '{print $3}'` yields the OpenSSH VERSION STRING rather
    # than a key. Measured 2026-09-26. The consequence is not a missing answer but
    # a WRONG one: `trusted` is a real key, `live` is "SSH-2.0-OpenSSH_...", they
    # never match, and every host is reported as having a DIFFERENT host key from
    # this Mac's record -- which the message below correctly describes as "a
    # reason to stop". So the deploy refuses to proceed while accusing all three
    # hosts of a key change that never happened. A permanent false FAIL, and an
    # alarming one.
    #
    # No `-t`: scan every type the host offers and select from the result, so a
    # host that speaks only RSA is handled rather than declared missing.
    SCAN="$(ssh-keyscan "$ip" 2>/dev/null | grep -v '^#' || true)"

    ltype=""
    lkey=""
    if [ -n "$ttype" ]; then
        # We have a record, so we demand the SAME type back. Falling back to
        # another type here would compare unlike keys and manufacture a DIFFERS.
        lkey="$(printf '%s\n' "$SCAN" | awk -v t="$ttype" '$2 == t { print $3; exit }')"
        ltype="$ttype"
        if [ -z "$lkey" ]; then
            echo "    WARN  $hname ($ip): offers no $ttype key, but this Mac's record is $ttype" >&2
            echo "          The host key type changed, or the host is not what it was." >&2
            [ "$TRUST_NEW_HOST_KEYS" -eq 1 ] || { KH_FAIL=1; continue; }
        fi
    fi
    if [ -z "$lkey" ]; then
        # No local record, or the type changed and the operator accepted it:
        # take the strongest type the host actually offers.
        for want in ed25519 rsa ecdsa; do
            lkey="$(printf '%s\n' "$SCAN" | awk -v t="$want" '$2 == t { print $3; exit }')"
            if [ -n "$lkey" ]; then ltype="$want"; break; fi
        done
        if [ -z "$lkey" ]; then
            echo "    WARN  $hname ($ip): no host key of any type answered; not added" >&2
            KH_FAIL=1
            continue
        fi
    fi

    if [ -z "$tkey" ]; then
        echo "    WARN  $hname ($ip): this Mac has no record for '$ip'; got $ltype"
        echo "          Add it to ~/.ssh/known_hosts or re-run with --trust-new-host-keys" >&2
        [ "$TRUST_NEW_HOST_KEYS" -eq 1 ] || { KH_FAIL=1; continue; }
    elif [ "$tkey" != "$lkey" ]; then
        echo "    WARN  $hname ($ip): host key DIFFERS from this Mac's record" >&2
        echo "          trusted $ip ($ttype): $(printf '%s' "$tkey" | cut -c1-24)..." >&2
        echo "          live    $ip ($ltype): $(printf '%s' "$lkey" | cut -c1-24)..." >&2
        echo "          A state rebuild legitimately regenerates a CuBox host key;" >&2
        echo "          anything else here is a reason to stop." >&2
        [ "$TRUST_NEW_HOST_KEYS" -eq 1 ] || { KH_FAIL=1; continue; }
    fi
    # Keyed by the ADDRESS, because there is no ~/.ssh/config in the container
    # and an alias that resolves on this Mac and not in there is a failure that
    # only appears after deployment. The TYPE is the one verified above, never a
    # hardcoded ed25519.
    printf '%s %s %s\n' "$ip" "$ltype" "$lkey" >> "$TMP_KH"
done
if [ "$KH_FAIL" -ne 0 ] && [ "$TRUST_NEW_HOST_KEYS" -eq 0 ]; then
    die "known_hosts is incomplete; every check on the affected host would be
       UNKNOWN. Fix the record above, or accept it explicitly with
       --trust-new-host-keys."
fi
rcopy "$TMP_KH" "$STORAGE_USER@$STORAGE_IP:$MONITOR_DIR/ssh/known_hosts"
remote "chmod 644 '$MONITOR_DIR/ssh/known_hosts'"
echo "    installed: $(grep -c . "$TMP_KH" 2>/dev/null || echo 0) host key(s)"

# ---------------------------------------------------------------------------
echo ""
echo "==> Leftover reference worker.sh (item 90)"
# ---------------------------------------------------------------------------
# NOTHING IS PUSHED HERE ANY MORE (item 90, 2026-10-06). This step used to copy
# configs/transcode/worker.sh to $MONITOR_DIR/expected/worker.sh, and the drift
# check compared each box's /etc/cubox-transcode/worker.sh against it.
#
# That reference was the STALE SIDE. The fleet's worker.sh changes through the
# shared layer (`cubox-app activate`), a path this script is nowhere near, so the
# snapshot fell behind and the check reported BOTH CORRECT BOXES as the deviant
# for thirteen hours (measured 2026-10-04). The check now takes both of its
# digests from the box's own applied generation -- the MANIFEST that
# cubox-shared-apply verified before copying the file into /etc.
#
# A leftover copy on the NAS is inert, because nothing reads it. Say so rather
# than deleting it silently: "stop delivering" is not "is not present" (item 69),
# and this one belongs to the operator to remove.
if remote "test -e '$MONITOR_DIR/expected/worker.sh'"; then
    echo "    note: $MONITOR_DIR/expected/ is a leftover from before the item-90 fix."
    echo "          Nothing reads it. Safe to delete:  rm -rf $MONITOR_DIR/expected"
fi

# ---------------------------------------------------------------------------
echo ""
echo "==> Building on the NAS (x86_64), then starting"
# ---------------------------------------------------------------------------
dc "build"
dc "up -d"

echo ""
echo "==> Health"
# POLL, DO NOT SLEEP ONCE. The healthcheck's start_period is 30 s, and a single
# 5 s sleep measured a container that was already Up and 10 s from reporting
# healthy as `000 -- unreachable`. Every word of the caveat below was true and
# the reading was still misleading: on a GOOD deploy the operator's first
# impression was a failure. Retrying costs a few seconds and removes the false
# alarm entirely.
dc "ps" || true
CODE="---"
for _try in 1 2 3 4 5 6 7 8; do
    CODE="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 \
            "http://${MONITOR_IP:-198.51.100.11}:${MONITOR_PORT:-8787}/healthz" 2>/dev/null || echo "---")"
    [ "$CODE" = "200" ] && break
    sleep 5
done
if [ "$CODE" = "200" ]; then
    echo "    /healthz -> 200  (http://${MONITOR_IP:-198.51.100.11}:${MONITOR_PORT:-8787}/)"
else
    echo "    /healthz -> ${CODE:-unreachable} after ~40 s of retries" >&2
    echo "    That is past start_period, so this is what a failed start looks like." >&2
    echo "    Check with:" >&2
    echo "      ./deploy.sh --logs" >&2
    echo "    If the container IS up, the usual cause is the macvlan address:" >&2
    echo "      $MONITOR_IP may be taken on the LAN, or the image may have" >&2
    echo "      failed to attach to the external 'eth1' network." >&2
fi

cat <<EOF

Next:

  ./deploy.sh --status          # what it sees, and what it cannot
  ./deploy.sh --once --dry-run  # one epoch that writes nothing

The first real collection needs the monitor to be able to ssh to all three
remote hosts. If the two CuBoxes were rebuilt and redeployed after the key was
generated, they authorise it already; Backup-NAS does NOT until you run:

  ./deploy.sh --authorise-backup

Until then the state-export-derived checks report UNKNOWN -- which is the honest
answer, and not green.

Dashboard: http://${MONITOR_IP:-198.51.100.11}:${MONITOR_PORT:-8787}/

Note the address is the CONTAINER's own macvlan address, NOT the NAS's. The
container publishes no host port, so http://$STORAGE_IP:$MONITOR_PORT/ is not
the dashboard and will not answer -- and deliberately so, because that is how
every other service on Storage-NAS is addressed.
EOF
