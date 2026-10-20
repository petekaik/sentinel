"""The SNMP v2c client: one GET, one retry, a bounded UDP timeout.

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


class SnmpTransportError(SnmpError):
    """The socket could not be used (DNS, unreachable, permission, ...).

    The two TRANSPORT failures -- this and SnmpTimeout -- are "I could not
    ask". Every other SnmpError carries an ANSWER: a noSuchObject, an error-
    status or a malformed reply all come from something that is alive. The
    module's preload grades device reachability on exactly that distinction,
    and telling the two apart by message prefix would rot with the wording.
    """


def _request(community, oid, request_id):
    return ber.sequence(
        ber.integer(1),                       # v2c
        ber.octet(community),
        ber.tlv(0xA0,                         # GetRequest
                ber.integer(request_id) + ber.integer(0) +
                ber.integer(0) +
                # THE VARBIND ENDS WITH AN EXPLICIT NULL (RFC 3416 §4.2.1).
                # Leaving it out produced a request that every real agent
                # silently dropped -- a timeout per device, which the module
                # then graded as "not answering". The unit test agreed with the
                # encoder because it was hand-computed from the same bytes, so
                # the fake agent below now REFUSES a varbind without it.
                ber.sequence(ber.sequence(ber.oid(oid) + ber.tlv(0x05, b"")))))


def get(host, community, oid, port=161, timeout=3.0, retries=1):
    """(value, type) for one OID, or raise SnmpError/SnmpTimeout.

    EVERY failure is a SnmpError. A decode fault is wrapped because callers
    isolate per device -- a raw IndexError from a truncated datagram would
    escape that isolation and blank the module's rows for the epoch instead of
    failing the one device that sent it.
    """
    rid = int.from_bytes(os.urandom(4), "big") & 0x7fffffff
    packet = _request(community, oid, rid)
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
        except (IndexError, ValueError):
            raise SnmpError("malformed response from %s" % host)
        # A LATE DATAGRAM IS NOT THIS REQUEST'S ANSWER. The socket is fresh per
        # attempt, but an ephemeral port can be reused, so the request-id (and
        # the GetResponse tag) decide whether this reply is ours; anything else
        # is treated like a lost packet and the retry still runs.
        if ptag != 0xA2 or req_id != rid:
            continue
        if status:
            raise SnmpError("error-status %d at %d" % (status, index))
        if vtag == 0x80:
            raise SnmpError("no such object: %s" % name_text)
        if vtag == 0x81:
            raise SnmpError("no such instance: %s" % name_text)
        if vtag in (0x02, 0x41, 0x42, 0x43):     # integer/counter/gauge/ticks
            return ber.parse_int(value), "integer"
        if vtag == 0x04:
            return ber.parse_string(value), "string"
        raise SnmpError("unsupported value tag 0x%02x" % vtag)
    raise SnmpTimeout("no answer from %s for %s" % (host, oid))
