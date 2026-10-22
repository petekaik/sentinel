"""BER: just enough ASN.1 to send an SNMP request and read the reply.

Tags are the single-byte identifier octet; SNMP v2c does not need anything
else. `parse(data, i)` returns `(tag, value, next)` where `next` is the offset
just past the TLV, which is what lets a sequence be walked without copying.
"""


def _len(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def tlv(tag, payload):
    return bytes([tag]) + _len(len(payload)) + payload


def integer(n):
    if n == 0:
        b = b"\x00"
    elif n > 0:
        b = n.to_bytes((n.bit_length() + 8) // 8, "big")
    else:
        b = n.to_bytes((n.bit_length() + 8) // 8, "big", signed=True)
    return tlv(0x02, b)


def octet(s):
    return tlv(0x04, s.encode() if isinstance(s, str) else s)


def oid(s):
    parts = [int(x) for x in s.split(".")]
    out = [40 * parts[0] + parts[1]]
    for p in parts[2:]:
        enc = [p & 0x7f]
        p >>= 7
        while p:
            enc.append(0x80 | (p & 0x7f))
            p >>= 7
        out.extend(reversed(enc))
    return tlv(0x06, bytes(out))


def sequence(*parts):
    return tlv(0x30, b"".join(parts))


def parse(data, i=0):
    # BOUNDS ARE CHECKED, NOT SLICED AROUND. An unchecked slice
    # (`data[i:i + n]`) silently returns fewer bytes than the length claims,
    # and a 2-byte integer read as `int.from_bytes(b"", ...)` returns 0 -- a
    # truncated reply would grade as a device reporting zero.
    if i + 2 > len(data):
        raise ValueError("truncated TLV")
    tag = data[i]; i += 1
    n = data[i]; i += 1
    if n & 0x80:
        k = n & 0x7f
        if i + k > len(data):
            raise ValueError("truncated TLV")
        n = int.from_bytes(data[i:i + k], "big"); i += k
    if i + n > len(data):
        raise ValueError("truncated TLV")
    return tag, data[i:i + n], i + n


def parse_int(v):
    if not v:
        raise ValueError("empty integer")
    return int.from_bytes(v, "big", signed=True)


def parse_uint(v):
    """Counter32, Gauge32, TimeTicks, Counter64 and Uinteger32 are UNSIGNED.

    Parsing them signed turns any value with the top bit set into a negative
    number -- a Counter64 at 2^63 reads as -2^63, which is a reading no check
    can grade and no operator can believe.
    """
    if not v:
        raise ValueError("empty unsigned integer")
    return int.from_bytes(v, "big")


def parse_ip(v):
    """IpAddress is four octets, dotted on the wire and on the screen."""
    if len(v) != 4:
        raise ValueError("IpAddress is not four octets")
    return ".".join(str(b) for b in v)


def parse_oid(v):
    first = v[0]
    parts = [first // 40, first % 40]
    val = 0
    for byte in v[1:]:
        val = (val << 7) | (byte & 0x7f)
        if not byte & 0x80:
            parts.append(val); val = 0
    return ".".join(str(p) for p in parts)


def parse_string(v):
    return v.decode("utf-8", "replace")
