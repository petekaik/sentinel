# cubox-monitor — the image the fleet monitor runs in.
#
# DELIBERATELY SMALL, AND DELIBERATELY PINNED. The application is Python 3
# standard library only (sqlite3, http.server, subprocess, urllib) so there is no
# requirements.txt to go stale; the base image is pinned by minor version so a
# `docker compose pull` cannot silently move the interpreter under it.
#
# ALPINE, NOT DEBIAN -- and the reason is size on a host that has 16 other
# containers. Measured 2026-09-26 with `docker image inspect --format {{.Size}}`,
# one store, one tree:
#
#   python:3.12-slim   (Debian trixie)   base 202.7 MB -> built image 192.8 MB
#   python:3.12-alpine (Alpine 3.24/musl) base  78.9 MB -> built image  80.2 MB
#
# The Debian build reads SMALLER than the base pulled beside it because it was
# built against an EARLIER DIGEST of that same tag -- the two are one base image
# at two points in time, not a contradiction. The comparison that matters is
# 80 MB against 193-203 MB, and note what it is NOT: the three apk packages below
# add ~1.3 MB over the bare Alpine base, so the saving is the base image's, not
# anything this file did.
#
# WHAT IS INSTALLED, AND WHY EACH THING IS HERE. Both of these are the reason the
# image cannot be FROM scratch, and neither is optional:
#
#   openssh-client   every CuBox and Backup-NAS check shells out to `ssh`. The
#                    client-side bounds (ConnectTimeout, ServerAliveInterval) are
#                    the ONLY reliable timeout on this fleet: the boxes' state
#                    mount is mounted HARD, so a `stat` against a dead Backup-NAS
#                    blocks in D state and no server-side or signal-based timeout
#                    can kill that. See docs/architecture.md.
#   iputils          the Backup-NAS reachability probe. The PACKAGE matters, not
#                    just the binary: iputils' `-W` is in SECONDS, and probes.py
#                    used to pass milliseconds there, turning a 3-second probe
#                    into a 3000-second one. probes.py now uses `-w` (deadline),
#                    which iputils and BusyBox both support -- so this would work
#                    on Alpine's busybox ping too, but iputils is installed
#                    anyway so that the binary the tests assume is the binary
#                    that runs.
#
# musl, NOT glibc, AND THAT IS WHY THE SMOKE TEST IS NOT OPTIONAL. The
# application is pure Python with one C module (the stdlib's sqlite3), and Alpine's
# python3 links it against Alpine's sqlite -- so `import sqlite3` and the WAL
# pragmas store.py depends on have to be verified ON THE IMAGE, not assumed from
# the Debian build working. `docker run ... python3 -c "import sqlite3; ..."` is
# part of the deploy script's own check for exactly this.
#
# RUNS AS ROOT, ON PURPOSE, AND IT IS NOT A LOWER-PRIVILEGE WIN EITHER WAY.
# The container needs /var/run/docker.sock to enumerate the 16 containers on
# Storage-NAS. Access to that socket is root-equivalent on the host by
# construction -- anything that can talk to the docker API can start a container
# that mounts the host's root -- so dropping to an unprivileged uid inside the
# container would buy no isolation while creating a real failure mode (a socket
# owned by root:docker that the process cannot open, reported as "could not read
# the docker API" forever). The honest note is therefore that the socket mount,
# not the uid, is the boundary -- and every docker check here only READS.
FROM python:3.12-alpine

RUN apk add --no-cache \
      openssh-client \
      tzdata
# NO iputils, AND THAT IS A MEASURED DECISION RATHER THAN A SIZE OPTIMISATION.
#
# `iputils` was here for ONE reason: probes.py:543 shells out to
# `ping -c 1 -w N <host>` for the ICMP hint that distinguishes "the box is down"
# from "the box is up and its ssh is broken". It cannot be installed on this
# host at all. QTS's Docker storage driver cannot set file capabilities, so apk
# fails while restoring iputils-ping's cap_net_raw+ep:
#
#   ( 4/10) Installing iputils-ping (20250605-r2)
#   WARNING: iputils-ping-20250605-r2: failed to preserve bin/ping: permission
#   1 error; 17.1 MiB in 48 packages
#   ERROR: process "/bin/sh -c apk add ..." did not complete successfully
#
# Measured 2026-09-26; it failed the entire image build. The fix is not a
# capability workaround, because THE BASE IMAGE ALREADY HAS A WORKING ping:
# /bin/ping is a symlink to /bin/busybox, and busybox's ping applet answers with
# the host's default capability set -- verified in python:3.12-alpine on this
# NAS, `ping -c 1 -w 2 127.0.0.1` returns 0 with no iputils and no added caps.
#
# The flags probes.py uses are supported by the busybox applet (-c count, -w
# deadline), which is what makes this a drop-in rather than a behaviour change.
# What we lose is iputils' extra diagnostics -- irrelevant, since the caller
# reads nothing but the exit status.

# The store lives here (bind-mounted to the NAS's own filesystem, never a
# network share -- SQLite is unsupported on one and can corrupt). /etc/monitor
# holds every bind-mounted INPUT (thresholds, ssh material); /app holds code
# only, so that /app can be mounted read-only as one unit. See compose.yml for
# why nothing may be nested under /app.
RUN mkdir -p /data /etc/monitor/ssh /app

WORKDIR /app

# The code is baked in so the image is runnable on its own, AND bind-mounted
# read-only by compose.yml so a change to a check or a threshold is an edit plus
# a restart rather than a rebuild. The bind mount wins at runtime; this COPY is
# what makes `docker run` without compose still work.
COPY app/ /app/

# Compose overrides every one of these; they are the defaults a bare
# `docker run` gets, and they are the CONTAINER paths, not the NAS paths.
#
# BuildKit warns about MONITOR_SSH_KEY here ("Do not use ARG or ENV for sensitive
# data"). It is a false positive and must not be "fixed" either way: the value is
# a PATH to a mounted file, not a key, and moving it to a build ARG would be
# strictly worse -- an ARG is baked into the image history. If that warning is
# ever silenced, silence it here, with this comment, and do not delete the
# variable: without it `probes.ssh` has no -i and the container silently offers
# no key at all.
ENV MONITOR_DB=/data/monitor.sqlite \
    MONITOR_CHECKS=/etc/monitor/checks.conf \
    MONITOR_SSH_KEY=/etc/monitor/ssh/id_ed25519 \
    MONITOR_KNOWN_HOSTS=/etc/monitor/ssh/known_hosts \
    MONITOR_PORT=8787 \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

EXPOSE 8787

CMD ["python3", "/app/main.py"]
