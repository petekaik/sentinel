"""Transport for the monitor: ssh, local, the Docker API, statvfs, HTTP.

THE SEPARATION THIS MODULE EXISTS TO MAKE

`ssh` returns 255 for ITS OWN failures and the remote command's status
otherwise. So `ssh box 'test -f /x'` returning non-zero is ambiguous between
"the file is absent" and "I never reached the box", and every check built on a
bare `ssh ... && ...` collapses the two. This project has shipped that bug at
least three times (items 28, 46, 62) and again in item 72, where a gate printed
"Coverage is complete" at exit 0 while reporting `done 0 / orphan 18`.

So a remote result NEVER carries a bare boolean. It carries a `transport` field
that says whether the command RAN, and the check layer is then forced to decide
what a non-zero rc means for that specific question. "The answer is no" and "I
could not ask" cannot be accidentally equal, because they are different enum
members.

TIMEOUTS ARE CLIENT-SIDE AND THAT IS LOAD-BEARING

The CuBox state mount is a HARD NFS mount with no `soft`/`timeo`/`retrans`
(configs/initramfs/scripts/nfs-bottom/cubox-overlay:577). A `stat` by any process
on the box blocks forever in D state if Backup-NAS dies, and `timeout -s KILL`
CANNOT kill D state. What we can bound is our own ssh CLIENT, which is in
userspace and killable -- so every remote call goes through `subprocess` with a
timeout, and a timeout is reported as such rather than as a failure.
"""

import http.client
import json
import os
import socket
import subprocess
import time
from dataclasses import dataclass, field
from enum import Enum

from store import Status


class Transport(str, Enum):
    RAN = "ran"                  # the command executed; rc is meaningful
    UNREACHABLE = "unreachable"  # could not ask (ssh 255, connect refused)
    TIMEOUT = "timeout"          # bounded out client-side
    ERROR = "error"              # a local defect: bad config, missing binary


# ssh's own failure code. Anything else is the remote command's status.
SSH_TRANSPORT_RC = 255

# Watchdog's own convention, remapped here for the same reason
# scripts/05-verify-boot.sh:108 remaps it: 143 must never be read as "the remote
# command said no".
WATCHDOG_RC = 143


@dataclass
class RemoteResult:
    """The result of asking a remote host something."""

    transport: Transport
    rc: int = None
    out: str = ""
    err: str = ""
    why: str = ""
    duration_ms: int = 0

    @property
    def ran(self):
        """True only if the command actually executed and we read its status."""
        return self.transport is Transport.RAN

    def status(self, false_is_fail=True):
        """Collapse to a Status -- explicitly, and only where that is correct.

        `false_is_fail=False` maps a non-zero rc to UNKNOWN, for the cases where
        a non-zero rc cannot distinguish "no" from "unknown" for that particular
        command. Callers must choose; there is no default that is right for
        every check, which is exactly why the transport is a separate field.
        """
        if self.transport is Transport.RAN:
            if self.rc == 0:
                return Status.OK
            if false_is_fail:
                return Status.FAIL
            return Status.UNKNOWN
        return Status.UNKNOWN

    def line(self):
        """First non-empty line of stdout, stripped -- the common 'one value' read."""
        for raw in self.out.splitlines():
            s = raw.strip()
            if s:
                return s
        return ""

    def reason(self):
        """A human-readable why, always ending in words rather than a code."""
        if self.transport is Transport.RAN:
            return "rc=%d" % self.rc
        if self.transport is Transport.TIMEOUT:
            return "timed out after %s" % (self.why or "the limit")
        if self.transport is Transport.UNREACHABLE:
            return self.why or "could not reach"
        return self.why or "error"


@dataclass
class Host:
    """One ssh target."""

    name: str
    address: str
    user: str = "root"
    port: int = 22
    key: str = None
    known_hosts: str = None
    timeout: int = 25

    def ssh_target(self):
        if self.user:
            return "%s@%s" % (self.user, self.address)
        return self.address

    def base_args(self):
        args = [
            "ssh",
            "-o", "BatchMode=yes",           # never prompt: a prompt is a hang
            "-o", "ConnectTimeout=10",
            "-o", "ServerAliveInterval=5",
            "-o", "ServerAliveCountMax=3",
            "-o", "StrictHostKeyChecking=yes",
            "-o", "LogLevel=ERROR",
        ]
        if self.known_hosts:
            args += ["-o", "UserKnownHostsFile=%s" % self.known_hosts]
        if self.key:
            args += ["-i", self.key, "-o", "IdentitiesOnly=yes"]
        if self.port != 22:
            args += ["-p", str(self.port)]
        args.append(self.ssh_target())
        return args


def run(argv, timeout=30, stdin=None):
    """Run a local argv with a hard timeout. Never raises for a non-zero rc."""
    t0 = time.time()
    try:
        proc = subprocess.run(
            argv,
            input=stdin,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        return RemoteResult(
            Transport.TIMEOUT,
            out=_dec(exc.stdout),
            err=_dec(exc.stderr),
            why="%ds" % timeout,
            duration_ms=int((time.time() - t0) * 1000),
        )
    except FileNotFoundError as exc:
        return RemoteResult(
            Transport.ERROR, why="cannot execute %s: %s" % (argv[0], exc),
            duration_ms=int((time.time() - t0) * 1000),
        )
    except OSError as exc:
        return RemoteResult(
            Transport.ERROR, why=str(exc),
            duration_ms=int((time.time() - t0) * 1000),
        )
    return _classify(proc, t0)


def ssh(host, command, timeout=None):
    """Run one command on a remote host. `command` is passed as a single argv word.

    Note this deliberately does NOT use a shell on this side: the remote shell is
    `sh`, and the command string is ours, built by the check layer.
    """
    timeout = timeout or host.timeout
    argv = host.base_args() + [command]
    return run(argv, timeout=timeout)


def ssh_script(host, script_text, timeout=None):
    """Run a scripted probe with the script on STDIN.

    The repo's existing idiom (`scripts/05-verify-boot.sh`) is
    `ssh host "bash -s -- $args" < localscript`: the script IS stdin, so any DATA
    must travel as argv. Used here for the combined state-export pull, which is
    one connection per interval rather than a dozen.
    """
    timeout = timeout or host.timeout
    argv = host.base_args() + ["sh -s"]
    return run(argv, timeout=timeout, stdin=script_text.encode())


def _dec(raw):
    if raw is None:
        return ""
    if isinstance(raw, bytes):
        return raw.decode("utf-8", "replace")
    return raw


def _classify(proc, t0):
    out = _dec(proc.stdout)
    err = _dec(proc.stderr)
    rc = proc.returncode
    dur = int((time.time() - t0) * 1000)
    if rc == 0:
        return RemoteResult(Transport.RAN, rc=0, out=out, err=err, duration_ms=dur)
    if rc == SSH_TRANSPORT_RC:
        # ssh's own failure: auth, no route, connection refused, host key.
        # The stderr text is kept verbatim because the DISTINCTION between
        # "auth failed" and "host down" matters -- the box's host keys are
        # per-device state, so a state rebuild changes them and that is a
        # different incident from a dead box.
        return RemoteResult(
            Transport.UNREACHABLE, rc=rc, out=out, err=err,
            why=_ssh_why(err), duration_ms=dur,
        )
    if rc == WATCHDOG_RC:
        return RemoteResult(
            Transport.TIMEOUT, rc=rc, out=out, err=err, why="watchdog",
            duration_ms=dur,
        )
    return RemoteResult(Transport.RAN, rc=rc, out=out, err=err, duration_ms=dur)


def _ssh_why(err):
    """Classify ssh's stderr into words an operator can act on."""
    low = err.lower()
    if "permission denied" in low or "publickey" in low:
        return "authentication failed (this is NOT the box being down)"
    if "host key verification failed" in low or "remote host identification" in low:
        return "host key changed (state-rebuild signature)"
    if "connection refused" in low:
        return "connection refused"
    if "no route to host" in low or "network is unreachable" in low:
        return "no route to host"
    if "connection timed out" in low or "operation timed out" in low:
        return "connection timed out"
    return "ssh failed: %s" % (err.strip().splitlines()[-1] if err.strip() else "no stderr")


# ---------------------------------------------------------------------------
# Docker, over the socket
# ---------------------------------------------------------------------------


class _UnixHTTP(http.client.HTTPConnection):
    def __init__(self, socket_path, timeout=20):
        super().__init__("localhost", timeout=timeout)
        self.socket_path = socket_path

    def connect(self):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        sock.connect(self.socket_path)
        self.sock = sock


class DockerAPI:
    """GET-only Docker API client over the unix socket.

    WHY THE SOCKET AND NOT THE CLI: the QTS Container Station docker binary is a
    host-arch wrapper at
    /share/CACHEDEV1_DATA/.qpkg/container-station/bin/docker and is not on PATH
    for a non-interactive ssh (measured 2026-09-26: `sh: docker: command not
    found`). Bind-mounting a host ELF into the container to shell out to it is
    worse than speaking the API directly, which needs no binary, no PATH and no
    BusyBox-vs-GNU parsing.

    HONESTY ABOUT PRIVILEGE: mounting /var/run/docker.sock is root-equivalent on
    the host -- the API can start a privileged container. This monitor only ever
    issues GETs, and `compose.yml` documents the trade. It is the
    single privileged thing in the design, and it exists only to read the TVH
    container's log, which is not on disk (measured: no tvheadend log file under
    /share/CACHEDEV1_DATA/Container/container-station-data).
    """

    def __init__(self, socket_path="/var/run/docker.sock", timeout=20):
        self.socket_path = socket_path
        self.timeout = timeout

    def _get(self, path):
        if not os.path.exists(self.socket_path):
            return None, "docker socket %s is absent" % self.socket_path
        conn = _UnixHTTP(self.socket_path, timeout=self.timeout)
        try:
            conn.request("GET", path)
            resp = conn.getresponse()
            body = resp.read()
        except (socket.timeout, TimeoutError):
            return None, "docker API timed out after %ds" % self.timeout
        except OSError as exc:
            return None, "docker API error: %s" % exc
        finally:
            try:
                conn.close()
            except Exception:
                pass
        if resp.status >= 400:
            return None, "docker API HTTP %d" % resp.status
        return body, None

    def containers(self):
        """[{name, state, status, health, image, id}] or (None, why)."""
        body, why = self._get("/containers/json?all=1")
        if body is None:
            return None, why
        try:
            raw = json.loads(body)
        except ValueError as exc:
            return None, "docker API returned non-JSON: %s" % exc
        out = []
        for c in raw:
            names = c.get("Names") or []
            name = (names[0].lstrip("/") if names else c.get("Id", "?")[:12])
            state = c.get("State", "")
            status_text = c.get("Status", "")
            health = _health_from_status(status_text)
            out.append({
                "id": c.get("Id", ""),
                "name": name,
                "state": state,
                "status": status_text,
                "health": health,
                "image": c.get("Image", ""),
            })
        return out, None

    def container(self, name):
        for c in (self.containers()[0] or []):
            if c["name"] == name:
                return c
        return None

    def inspect(self, name):
        """Full container state, or (None, why).

        NEEDED BECAUSE /containers/json DOES NOT CARRY RestartCount. A check that
        read `restarts` off `containers()` would have found the key absent,
        defaulted it to 0, and reported "no restarts" on a container in a crash
        loop -- a check that cannot fire, which is item 26's shape exactly. The
        count lives in /containers/<id>/inspect.
        """
        c = self.container(name)
        if c is None:
            return None, "container %r is not present" % name
        body, why = self._get("/containers/%s/json" % c["id"])
        if body is None:
            return None, why
        try:
            return json.loads(body), None
        except ValueError as exc:
            return None, "docker inspect returned non-JSON: %s" % exc

    def restart_count(self, name):
        """Container restart count, or (None, why)."""
        data, why = self.inspect(name)
        if data is None:
            return None, why
        n = data.get("RestartCount")
        if n is None:
            return None, "docker inspect returned no RestartCount"
        return int(n), None

    def logs(self, name, tail=500, since=None):
        """Container log text, demultiplexed. Returns (text, why)."""
        q = "stderr=1&stdout=1&timestamps=1&tail=%d" % tail
        if since:
            q += "&since=%d" % int(since)
        body, why = self._get("/containers/%s/logs?%s" % (name, q))
        if body is None:
            return None, why
        return _demux_docker_log(body), None


def _health_from_status(status_text):
    low = status_text.lower()
    if "(healthy)" in low:
        return "healthy"
    if "(unhealthy)" in low:
        return "unhealthy"
    if "(health: starting)" in low:
        return "starting"
    return None


def _demux_docker_log(body):
    """Decode Docker's multiplexed log stream.

    Format: repeated [stream(1) 000 size(4, big-endian)] + payload of `size`
    bytes. If the container runs with a TTY the stream is RAW instead, so the
    header test is explicit rather than assumed -- misreading a raw stream as
    multiplexed silently eats the first 8 bytes of every line.
    """
    if not body:
        return ""
    # A multiplexed stream always begins with a frame header whose type byte is
    # 0/1/2 and whose three following bytes are zero.
    if body[0] in (0, 1, 2) and body[1:4] == b"\x00\x00\x00":
        out = []
        i = 0
        n = len(body)
        while i + 8 <= n:
            size = int.from_bytes(body[i + 4:i + 8], "big")
            i += 8
            chunk = body[i:i + size]
            i += size
            out.append(chunk.decode("utf-8", "replace"))
        return "".join(out)
    return body.decode("utf-8", "replace")


# ---------------------------------------------------------------------------
# Local, HTTP, statvfs
# ---------------------------------------------------------------------------


def statvfs(path):
    """Free/total bytes for a path, via statvfs.

    Used instead of parsing `df` ON PURPOSE. `df` output differs between GNU and
    BusyBox and between QTS builds, so a column assumption is a permanent wrong
    number -- and this project already has a worked example of a numeric parse
    that silently disabled a guard for the whole life of a defect (item 53 /
    worker.sh:1128-1138). statvfs is one syscall with one meaning.
    """
    try:
        st = os.statvfs(path)
    except OSError as exc:
        return None, str(exc)
    if st.f_blocks == 0:
        return None, "statvfs reports zero blocks for %s" % path
    total = st.f_blocks * st.f_frsize
    free = st.f_bavail * st.f_frsize      # available to an unprivileged writer
    free_root = st.f_bfree * st.f_frsize
    used = total - free_root
    return {
        "total": total,
        "free": free,
        "used": used,
        "used_pct": (used / total * 100.0) if total else None,
    }, None


def http_probe(url, timeout=10):
    """A HEAD/GET probe that returns the status code rather than a bool.

    Deliberately does NOT use `curl -f`: `-f` exits non-zero on ANY 4xx, so a
    service that answers 401 reads identically to one that is down. That
    difference is the whole TVH check -- auth is on and the credentials are
    unknown, so 401 means "it answered", not "it failed".
    """
    from urllib import request as urlrequest
    from urllib.error import HTTPError, URLError

    req = urlrequest.Request(url, method="GET")
    t0 = time.time()
    try:
        with urlrequest.urlopen(req, timeout=timeout) as resp:
            return {
                "code": resp.status,
                "body": resp.read(4096).decode("utf-8", "replace"),
                "duration_ms": int((time.time() - t0) * 1000),
            }, None
    except HTTPError as exc:
        # An HTTP error IS an answer. 401 is the expected TVH response.
        try:
            body = exc.read(512).decode("utf-8", "replace")
        except Exception:
            body = ""
        return {
            "code": exc.code,
            "body": body,
            "duration_ms": int((time.time() - t0) * 1000),
        }, None
    except URLError as exc:
        return None, "no answer: %s" % (exc.reason,)
    except socket.timeout:
        return None, "timed out after %ds" % timeout
    except OSError as exc:
        return None, str(exc)


def ping(host, timeout=5):
    """ICMP reachability. A HINT, never a health verdict.

    Recorded because it is cheap and it distinguishes 'the network is gone' from
    'the box is up but ssh is broken', but it is not a check status: it reads RED
    if ICMP is filtered and GREEN while the box is silently persisting nothing.

    `-w`, IN SECONDS -- NOT `-W`, AND NOT MILLISECONDS. This was wrong, and it
    was wrong in the one direction that hides itself: the code passed
    `-W <timeout * 1000>`, which is the macOS/BusyBox convention, but iputils'
    `-W` is in SECONDS, so a 3-second probe became "wait up to 3000 seconds".
    Measured in a debian:12-slim container (iputils 20221126), against the
    blackhole 192.0.2.1:

        ping -c 1 -W 3000 192.0.2.1   ->  did not return within 25s
        ping -c 1 -W 3    192.0.2.1   ->  returned in 3.2s, rc=1
        ping -c 1 -w 3    192.0.2.1   ->  returned in 3.2s, rc=1
        ping -c 1 -W 3000 127.0.0.1   ->  returned in 0.1s, rc=0

    The last line is why nobody would have noticed: against a host that ANSWERS,
    the old form returns immediately. So the check worked perfectly against a
    live Backup-NAS and, against a dead one, was killed by the caller's own
    subprocess timeout and classified `timeout` -- i.e. UNKNOWN, never RED. The
    one check that has to say "the fleet's boot dependency is down" could not
    say it (item 26: a check that cannot fire is worse than no check).

    `-w` is the deadline and is supported by iputils and by BusyBox. macOS's
    ping has no `-w`, so this cannot be exercised from the Mac -- which is fine
    and is why the transport is stubbed in the tests: `ping` only ever runs in
    the container. The regression test asserts the ARGV rather than the timing,
    because the argv is the thing that was wrong.
    """
    argv = ["ping", "-c", "1", "-w", str(max(1, int(timeout))), host]
    res = run(argv, timeout=timeout + 5)
    if not res.ran:
        return None, res.reason()
    return res.rc == 0, res.reason()



def shq(text):
    """Single-quote `text` for the REMOTE shell, which is what ssh hands the
    string to. A literal single quote inside is closed, escaped and reopened --
    the only form that is safe for every byte a path may contain (item 51: this
    project has lost data to a path with a space in it), BusyBox sh included.
    """
    return "'" + str(text).replace("'", "'\\''") + "'"


_SCRIPT_CACHE = {}


def script_text(path):
    """Read a probe script once. It is a constant of the image, not per-host."""
    if path not in _SCRIPT_CACHE:
        try:
            with open(path) as fh:
                _SCRIPT_CACHE[path] = fh.read()
        except OSError as exc:
            _SCRIPT_CACHE[path] = None
            _SCRIPT_CACHE[path + ":err"] = str(exc)
    return _SCRIPT_CACHE[path]


def script_error(path):
    return _SCRIPT_CACHE.get(path + ":err", "")

@dataclass
class Evidence:
    """Free-form evidence attached to a check, for the incident's first_evidence_json."""

    data: dict = field(default_factory=dict)

    def add(self, **kwargs):
        self.data.update(kwargs)
        return self
