"""LZ4 block format (the codec NVIDIA uses for compressed fatbin entries).

Pure-Python decompressor plus a small greedy compressor (used to build
synthetic fatbins for tests). Format: a sequence of
``token | [literal-length bytes] | literals | offset (u16 LE) | [match-length bytes]``
with the final sequence carrying literals only.
"""

from __future__ import annotations


class LZ4Error(ValueError):
    pass


def decompress(src: bytes, max_size: int = 1 << 30, expected_size: int = 0) -> bytes:
    """Decompress an LZ4 block. With ``expected_size`` the output is exactly that long (decoding stops there, so
    memory never exceeds it); without it, output beyond ``max_size`` raises :class:`LZ4Error`."""
    src = bytes(src)
    out = bytearray()
    i, n = 0, len(src)
    if expected_size:
        max_size = min(max_size, expected_size)
    while i < n:
        token = src[i]
        i += 1
        lit = token >> 4
        if lit == 15:
            while True:
                if i >= n:
                    raise LZ4Error("truncated literal length")
                b = src[i]
                i += 1
                lit += b
                if b != 255:
                    break
        if i + lit > n:
            raise LZ4Error("literal run past end of input")
        if len(out) + lit > max_size:
            if not expected_size:
                raise LZ4Error("output exceeds limit (%d bytes)" % max_size)
            lit = max_size - len(out)
        out += src[i:i + lit]
        i += lit
        if expected_size and len(out) >= expected_size:
            break
        if i >= n:
            break  # last sequence
        if i + 2 > n:
            raise LZ4Error("truncated match offset")
        offset = src[i] | (src[i + 1] << 8)
        i += 2
        if offset == 0 or offset > len(out):
            raise LZ4Error("invalid match offset %d at output %d" % (offset, len(out)))
        mlen = token & 0xF
        if mlen == 15:
            while True:
                if i >= n:
                    raise LZ4Error("truncated match length")
                b = src[i]
                i += 1
                mlen += b
                if b != 255:
                    break
        mlen += 4
        if len(out) + mlen > max_size:
            if not expected_size:
                raise LZ4Error("output exceeds limit (%d bytes)" % max_size)
            mlen = max_size - len(out)
        start = len(out) - offset
        if offset >= mlen:
            out += out[start:start + mlen]
        else:  # overlapping copy: byte-wise copying repeats the last `offset` bytes, i.e. a periodic pattern
            out += (out[start:] * (mlen // offset + 1))[:mlen]
        if expected_size and len(out) >= expected_size:
            break
    return bytes(out)


def _length_bytes(n: int) -> bytes:
    out = bytearray()
    while n >= 255:
        out.append(255)
        n -= 255
    out.append(n)
    return bytes(out)


def compress(data: bytes) -> bytes:
    """Greedy LZ4 block compressor (correct, not fast; for test data)."""
    data = bytes(data)
    n = len(data)
    out = bytearray()
    table = {}
    anchor = i = 0
    limit = n - 12  # LZ4 rule: last match must start >= 12 bytes before the end
    while i < limit:
        key = data[i:i + 4]
        cand = table.get(key)
        table[key] = i
        if cand is None or i - cand > 0xFFFF:
            i += 1
            continue
        mlen = 4
        while i + mlen < n - 5 and data[cand + mlen] == data[i + mlen]:
            mlen += 1
        lit = i - anchor
        token = (min(lit, 15) << 4) | min(mlen - 4, 15)
        out.append(token)
        if lit >= 15:
            out += _length_bytes(lit - 15)
        out += data[anchor:i]
        off = i - cand
        out += bytes((off & 0xFF, off >> 8))
        if mlen - 4 >= 15:
            out += _length_bytes(mlen - 4 - 15)
        i += mlen
        anchor = i
    lit = n - anchor
    out.append(min(lit, 15) << 4)
    if lit >= 15:
        out += _length_bytes(lit - 15)
    out += data[anchor:]
    return bytes(out)
