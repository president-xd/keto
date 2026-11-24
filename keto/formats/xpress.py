"""Pure-Python decoders for the Windows compression formats of [MS-XCA] (Xpress Compression Algorithm).

* ``lz77_decompress``    - Plain LZ77 ("Xpress", ``COMPRESSION_FORMAT_XPRESS`` = 3), MS-XCA section 2.4.
* ``huffman_decompress`` - LZ77+Huffman ("Xpress Huffman", ``COMPRESSION_FORMAT_XPRESS_HUFF`` = 4), section 2.2.
* ``lznt1_decompress``   - LZNT1 (``COMPRESSION_FORMAT_LZNT1`` = 2), section 2.5.

Windows 8+ hibernation files store compression sets in the first two formats; LZNT1 is NTFS/RtlCompressBuffer's
default format. The decoders follow the MS-XCA pseudocode and are checked byte for byte against ntdll's
``RtlCompressBuffer`` output and the spec's examples (tests/test_winformats.py).

Speed: runs of literal flags (plain LZ77, LZNT1) are copied as slices and matches as slice/repeat operations; only the
Huffman decoder has to walk one symbol at a time (its bit stream gives no byte-aligned literal runs).
"""

from __future__ import annotations

import struct
from typing import Optional

#: [MS-XCA] 2.2: each LZ77+Huffman block holds a 256-byte table and decodes to (at most) 64 KiB of output
HUFFMAN_TABLE_SIZE = 256
HUFFMAN_BLOCK = 65536
LZNT1_CHUNK = 4096


class XpressError(ValueError):
    """The compressed data is not valid for the format (truncated, bad table, match before the output start)."""


def _copy_match(out: bytearray, offset: int, length: int) -> None:
    """Append ``length`` bytes copied from ``offset`` bytes back (the regions may overlap: ``aaaa`` = 'a' + (1, 3))."""
    olen = len(out)
    if offset > olen or offset <= 0:
        raise XpressError("match offset %d points before the start of the output (%d bytes written)" % (offset, olen))
    start = olen - offset
    if offset >= length:
        out += out[start:start + length]
    else:
        out += (out[start:olen] * (length // offset + 1))[:length]


# -- plain LZ77 (MS-XCA 2.4.4) ----------------------------------------------------------------------------------------
def lz77_decompress(data, out_size: Optional[int] = None) -> bytes:
    """Decode Plain LZ77. ``out_size`` (when known, e.g. a hibernation set) stops decoding there and is required to
    be reached; without it the stream ends at the end-of-input marker (a match flag with no input left)."""
    src = bytes(data)
    n = len(src)
    out = bytearray()
    limit = out_size if out_size is not None else -1
    ip = 0
    flags = 0
    nflags = 0
    half = 0  # input position of the shared length nibble (0 = none; position 0 is always a flag byte)
    while True:
        if limit >= 0 and len(out) >= limit:
            break
        if nflags == 0:
            if ip + 4 > n:
                if ip == n:  # the stream ended on a flag-word boundary
                    break
                raise XpressError("plain LZ77: truncated flag word at input offset %d" % ip)
            flags = src[ip] | (src[ip + 1] << 8) | (src[ip + 2] << 16) | (src[ip + 3] << 24)
            ip += 4
            nflags = 32
        rem = flags & ((1 << nflags) - 1)
        lit = nflags - rem.bit_length()  # leading zero flags = literals (flags are consumed from bit 31 down)
        if lit:
            take = lit if ip + lit <= n else n - ip
            if limit >= 0 and len(out) + take > limit:
                take = limit - len(out)
            out += src[ip:ip + take]
            ip += take
            nflags -= take
            if take < lit:
                if limit >= 0 and len(out) >= limit:
                    break
                raise XpressError("plain LZ77: input ends inside a literal run at offset %d" % ip)
            continue
        nflags -= 1
        if ip == n:  # a match flag with no input left marks the end of the stream
            break
        if ip + 2 > n:
            raise XpressError("plain LZ77: truncated match at input offset %d" % ip)
        mb = src[ip] | (src[ip + 1] << 8)
        ip += 2
        length = mb & 7
        offset = (mb >> 3) + 1
        if length == 7:
            if half == 0:
                if ip >= n:
                    raise XpressError("plain LZ77: truncated length nibble at input offset %d" % ip)
                length = src[ip] & 15
                half = ip
                ip += 1
            else:
                length = src[half] >> 4
                half = 0
            if length == 15:
                if ip >= n:
                    raise XpressError("plain LZ77: truncated length byte at input offset %d" % ip)
                length = src[ip]
                ip += 1
                if length == 255:
                    if ip + 2 > n:
                        raise XpressError("plain LZ77: truncated 16-bit length at input offset %d" % ip)
                    length = src[ip] | (src[ip + 1] << 8)
                    ip += 2
                    if length == 0:
                        if ip + 4 > n:
                            raise XpressError("plain LZ77: truncated 32-bit length at input offset %d" % ip)
                        length = int.from_bytes(src[ip:ip + 4], "little")
                        ip += 4
                    if length < 15 + 7:
                        raise XpressError("plain LZ77: invalid long match length %d" % length)
                    length -= 15 + 7
                length += 15
            length += 7
        length += 3
        if limit >= 0 and len(out) + length > limit:
            length = limit - len(out)
        _copy_match(out, offset, length)
    if limit >= 0 and len(out) != limit:
        raise XpressError("plain LZ77: decoded %d bytes, expected %d" % (len(out), limit))
    return bytes(out)


# -- LZ77+Huffman (MS-XCA 2.2.4) --------------------------------------------------------------------------------------
def _huffman_table(src: bytes, pos: int):
    """Decoding table for the 256-byte code-length table at ``pos``: a list indexed by the next ``bits`` bits of the
    stream whose entries are ``symbol << 4 | code length`` (canonical code: by length, then by symbol value)."""
    by_len = [[] for _ in range(16)]
    sym = 0
    for b in src[pos:pos + HUFFMAN_TABLE_SIZE]:
        if b & 15:
            by_len[b & 15].append(sym)
        if b >> 4:
            by_len[b >> 4].append(sym + 1)
        sym += 2
    bits = 0
    for length in range(15, 0, -1):
        if by_len[length]:
            bits = length
            break
    if not bits:
        raise XpressError("LZ77+Huffman: the code-length table at input offset %d is empty" % pos)
    table = []
    for length in range(1, bits + 1):
        span = 1 << (bits - length)
        for s in by_len[length]:
            table += [(s << 4) | length] * span
    if len(table) != 1 << bits:
        raise XpressError("LZ77+Huffman: the code-length table at input offset %d is not a complete prefix code"
                          % pos)
    return table, bits


def huffman_decompress(data, out_size: int) -> bytes:
    """Decode LZ77+Huffman to exactly ``out_size`` bytes (the format does not record the output size: callers know it,
    e.g. ``RtlDecompressBufferEx``'s output buffer size or a hibernation set's page count)."""
    src = bytes(data)
    n = len(src)
    src += b"\x00" * 8  # the 32-bit bit register reads ahead; reads past the end see zeros and are checked below
    # words[i] = the little-endian 16-bit word at byte offset i (raw length bytes can leave the stream at an odd
    # offset, so both alignments are needed); one list lookup per refill instead of two byte reads
    even = struct.unpack_from("<%dH" % (len(src) // 2), src, 0)
    odd = struct.unpack_from("<%dH" % ((len(src) - 1) // 2), src, 1)
    words = [0] * (len(even) + len(odd))
    words[0::2] = even
    words[1::2] = odd
    out = bytearray()
    append = out.append
    ip = 0
    while len(out) < out_size:
        if ip + HUFFMAN_TABLE_SIZE > n:
            raise XpressError("LZ77+Huffman: input ends at offset %d with %d of %d bytes decoded"
                              % (ip, len(out), out_size))
        table, bits = _huffman_table(src, ip)
        shift = 32 - bits
        cur = ip + HUFFMAN_TABLE_SIZE
        nxt = (words[cur] << 16) | words[cur + 2]
        cur += 4
        extra = 16
        block_end = min(len(out) + HUFFMAN_BLOCK, out_size)
        olen = len(out)
        while olen < block_end:
            e = table[nxt >> shift]
            length = e & 15
            nxt = (nxt << length) & 0xFFFFFFFF
            extra -= length
            if extra < 0:
                nxt |= words[cur] << -extra
                extra += 16
                cur += 2
            if e < 0x1000:  # a literal (symbol < 256)
                append(e >> 4)
                olen += 1
                continue
            sym = e >> 4
            if sym == 256 and cur >= n and olen == out_size:
                break
            sym -= 256
            length = sym & 15
            obits = sym >> 4
            if length == 15:
                length = src[cur]
                cur += 1
                if length == 255:
                    length = src[cur] | (src[cur + 1] << 8)
                    cur += 2
                    if length == 0:  # ntdll extension (as in plain LZ77, 2.4.4): a 32-bit length follows
                        length = int.from_bytes(src[cur:cur + 4], "little")
                        cur += 4
                    if length < 15:
                        raise XpressError("LZ77+Huffman: invalid long match length %d" % length)
                    length -= 15
                length += 15
            length += 3
            if obits:
                offset = (nxt >> (32 - obits)) + (1 << obits)
                nxt = (nxt << obits) & 0xFFFFFFFF
                extra -= obits
                if extra < 0:
                    nxt |= words[cur] << -extra
                    extra += 16
                    cur += 2
            else:
                offset = 1
            if olen + length > out_size:
                raise XpressError("LZ77+Huffman: a match runs %d byte(s) past the expected output size %d"
                                  % (olen + length - out_size, out_size))
            _copy_match(out, offset, length)
            olen += length
        if cur > n + 4:
            raise XpressError("LZ77+Huffman: the bit stream runs past the end of the input (%d > %d)" % (cur, n))
        ip = cur
    return bytes(out)


# -- LZNT1 (MS-XCA 2.5) -----------------------------------------------------------------------------------------------
def lznt1_decompress(data, out_size: Optional[int] = None) -> bytes:
    """Decode LZNT1 chunks until the End_of_buffer header (two zero bytes), the end of the input or ``out_size``."""
    src = bytes(data)
    n = len(src)
    out = bytearray()
    ip = 0
    while ip + 2 <= n:
        hdr = src[ip] | (src[ip + 1] << 8)
        if hdr == 0:
            break
        if (hdr >> 12) & 7 != 3:
            raise XpressError("LZNT1: chunk header 0x%04x at input offset %d has signature %d (expected 3)"
                              % (hdr, ip, (hdr >> 12) & 7))
        end = ip + 2 + (hdr & 0xFFF) + 1
        if end > n:
            raise XpressError("LZNT1: chunk at input offset %d needs %d bytes, %d remain" % (ip, end - ip, n - ip))
        ip += 2
        chunk_start = len(out)
        if not hdr & 0x8000:
            out += src[ip:end]
            ip = end
        else:
            while ip < end:
                flags = src[ip]
                ip += 1
                bit = 0
                while bit < 8 and ip < end:
                    if not (flags >> bit) & 1:
                        rest = flags >> bit
                        run = 8 - bit if rest == 0 else ((rest & -rest).bit_length() - 1)
                        run = min(run, end - ip)
                        out += src[ip:ip + run]
                        ip += run
                        bit += run
                        continue
                    if ip + 2 > end:
                        raise XpressError("LZNT1: truncated compressed word at input offset %d" % ip)
                    word = src[ip] | (src[ip + 1] << 8)
                    ip += 2
                    bit += 1
                    u = len(out) - chunk_start
                    m = (u - 1).bit_length() if u > 1 else 0
                    m = 4 if m < 4 else (12 if m > 12 else m)
                    lbits = 16 - m
                    _copy_match(out, (word >> lbits) + 1, (word & ((1 << lbits) - 1)) + 3)
                    if len(out) - chunk_start > LZNT1_CHUNK:
                        raise XpressError("LZNT1: chunk at input offset %d decodes to more than 4096 bytes" % ip)
        produced = len(out) - chunk_start
        if produced < LZNT1_CHUNK and ip + 2 <= n and (src[ip] | (src[ip + 1] << 8)) != 0:
            out += b"\x00" * (LZNT1_CHUNK - produced)  # a short chunk followed by another stands for 4096 bytes
        if out_size is not None and len(out) >= out_size:
            break
    if out_size is not None:
        if len(out) < out_size:
            raise XpressError("LZNT1: decoded %d bytes, expected %d" % (len(out), out_size))
        del out[out_size:]
    return bytes(out)
