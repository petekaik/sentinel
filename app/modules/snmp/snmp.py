"""The SNMP v2c client: GET, GetNext, a bounded walk, one retry per request.

No logging on purpose -- the community string is a secret and there is nothing
this module could log that would not be either the packet or the credential.
Errors carry the host and the OID, never the community.
"""

import os
import socket

from . import ber


class SnmpError(Exception):
    pass


class SnmpTimeout(SnmpError):
    pass


class SnmpEndOfMib(SnmpError):
    """The v2c endOfMibView exception: a GetNext past the last object.

    It is an ANSWER, not a failure -- the agent looked and says there is
    nothing after this OID. walk() turns it into a clean end; nothing else
    should read it as a dead device.
    """


class SnmpTransportError(SnmpError):
    """The socket could not be used (DNS, unreachable, permission, ...).

    The two TRANSPORT failures -- this and SnmpTimeout -- are "I could not
    ask". Every other SnmpError carries an ANSWER: a noSuchObject, an error-
    status or a malformed reply all come from something that is alive. The
    module's preload grades device reachability on exactly that distinction,
    and telling the two apart by message prefix would rot with the wording.
    """


def _request(community, oid, request_id, tag=0xA0):
    return ber.sequence(
        ber.integer(1),                       # v2c
        ber.octet(community),
        ber.tlv(tag,                          # 0xA0 GetRequest, 0xA1 GetNext
                ber.integer(request_id) + ber.integer(0) +
                ber.integer(0) +
                # THE VARBIND ENDS WITH AN EXPLICIT NULL (RFC 3416 §4.2.1).
                # Leaving it out produced a request that every real agent
                # silently dropped -- a timeout per device, which the module
                # then graded as "not answering". The unit test agreed with the
                # encoder because it was hand-computed from the same bytes, so
                # the fake agent below now REFUSES a varbind without it.
                ber.sequence(ber.sequence(ber.oid(oid) + ber.tlv(0x05, b"")))))


def _decode(data, rid, host):
    """(oid, value, kind) from a reply, or None when it answers another request.

    The error-status and the v2c exception tags are answers, not values: 0x80
    and 0x81 raise, and 0x82 raises SnmpEndOfMib so a walk can stop cleanly.
    """
    try:
        _, msg, _ = ber.parse(data, 0)
        _, _version, i = ber.parse(msg, 0)
        _, _community, i = ber.parse(msg, i)
        ptag, pdu, _ = ber.parse(msg, i)
        _, req, j = ber.parse(pdu, 0)
        req_id = ber.parse_int(req)
        _, err_status, j = ber.parse(pdu, j)
        _, err_index, j = ber.parse(pdu, j)
        _, varbinds, j = ber.parse(pdu, j)
        _, vb, _ = ber.parse(varbinds, 0)
        _, name, k = ber.parse(vb, 0)
        name_text = ber.parse_oid(name)
        vtag, value, _ = ber.parse(vb, k)
        status = ber.parse_int(err_status)
        index = ber.parse_int(err_index)
        # A LATE DATAGRAM IS NOT THIS REQUEST'S ANSWER. The socket is fresh per
        # attempt, but an ephemeral port can be reused, so the request-id (and
        # the GetResponse tag) decide whether this reply is ours.
        if ptag != 0xA2 or req_id != rid:
            return None
        if status:
            raise SnmpError("error-status %d at %d" % (status, index))
        if vtag == 0x80:
            raise SnmpError("no such object: %s" % name_text)
        if vtag == 0x81:
            raise SnmpError("no such instance: %s" % name_text)
        if vtag == 0x82:
            raise SnmpEndOfMib("end of MIB view at %s" % name_text)
        # EVERY STANDARD SNMP v2c VALUE TYPE, because a WALK meets all of them:
        # a subtree contains OBJECT IDENTIFIERs (sysObjectID), IpAddresses
        # (ipAdEntAddr), Counter64s (ifHCInOctets) and the occasional Opaque.
        # Refusing a type does not skip that row -- it aborts the whole walk,
        # which on a switch hid every object after the first OID-valued one
        # ("unsupported value tag 0x06").
        if vtag == 0x02:                          # INTEGER, signed
            return name_text, ber.parse_int(value), "integer"
        if vtag in (0x41, 0x42, 0x43, 0x46, 0x47):
            # Counter32 / Gauge32 / TimeTicks / Counter64 / Uinteger32
            return name_text, ber.parse_uint(value), "integer"
        if vtag == 0x04:
            return name_text, ber.parse_string(value), "string"
        if vtag == 0x06:
            return name_text, ber.parse_oid(value), "oid"
        if vtag == 0x40:
            return name_text, ber.parse_ip(value), "string"
        if vtag == 0x44:
            # Opaque is agent-defined bytes, not text: hex is the honest form.
            return name_text, value.hex(), "opaque"
        raise SnmpError("unsupported value tag 0x%02x" % vtag)
    except (IndexError, ValueError):
        raise SnmpError("malformed response from %s" % host)


def _one(host, community, oid, tag, port=161, timeout=3.0, retries=1):
    """(oid, value, kind) for one request, or raise SnmpError/SnmpTimeout."""
    rid = int.from_bytes(os.urandom(4), "big") & 0x7fffffff
    packet = _request(community, oid, rid, tag)
    for _ in range(retries + 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            sock.sendto(packet, (host, port))
            data, _ = sock.recvfrom(65535)
        except socket.timeout:
            continue
        except OSError as exc:                   # gaierror, unreachable, ...
            raise SnmpTransportError("cannot query %s: %s" % (host, exc))
        finally:
            sock.close()
        got = _decode(data, rid, host)
        if got is not None:
            return got
    raise SnmpTimeout("no answer from %s for %s" % (host, oid))


def get(host, community, oid, port=161, timeout=3.0, retries=1):
    """(value, type) for one OID, or raise SnmpError/SnmpTimeout.

    EVERY failure is a SnmpError. A decode fault is wrapped because callers
    isolate per device -- a raw IndexError from a truncated datagram would
    escape that isolation and blank the module's rows for the epoch instead of
    failing the one device that sent it.
    """
    _, value, kind = _one(host, community, oid, 0xA0, port=port,
                          timeout=timeout, retries=retries)
    return value, kind


def getnext(host, community, oid, port=161, timeout=3.0, retries=1):
    """(next_oid, value, type) after `oid`, or raise SnmpEndOfMib.

    The returned name is the agent's, not ours: only the reply can say which
    object follows, which is why a walk trusts it and then checks the subtree.
    """
    return _one(host, community, oid, 0xA1, port=port, timeout=timeout,
                retries=retries)


def walk(host, community, root, port=161, timeout=3.0, max_oids=2000,
         retries=1):
    """(rows, truncated) for objects after `root`, within its subtree.

    `root` itself is never returned: a GetNext is strictly greater than the
    OID it names, so a walk starts at the first object after the root.

    `rows` is [(oid, value, type)], in the agent's order. `truncated` is True
    when objects remain past the cap: a caller that reports a capped walk as a
    complete tree reports missing objects as absent, which is the one thing a
    monitor must never do. A cap that lands exactly on the last object is not
    truncation, so one probe past the cap decides it.
    """
    rows, oid = [], root
    while len(rows) < max_oids:
        try:
            next_oid, value, kind = getnext(host, community, oid, port=port,
                                            timeout=timeout, retries=retries)
        except SnmpEndOfMib:
            return rows, False
        # A GetNext that leaves the subtree is the end of it: the next object
        # exists, but it is not this walk's. Without this the walk reads a
        # neighbouring MIB branch as part of the root.
        if not next_oid.startswith(root + "."):
            return rows, False
        rows.append((next_oid, value, kind))
        oid = next_oid
    if not rows:                                # max_oids <= 0: asked for none
        return rows, False
    # The cap stopped the walk. ONE probe says whether the subtree really
    # ended at it; silence or a transport failure leaves the answer unknown,
    # and unknown must be reported as truncated rather than as complete.
    try:
        nxt, _, _ = getnext(host, community, oid, port=port, timeout=timeout,
                            retries=retries)
    except SnmpEndOfMib:
        return rows, False
    except SnmpError:
        return rows, True
    return rows, nxt.startswith(root + ".")
