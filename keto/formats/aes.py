"""AES key-schedule detection (the technique popularised by ``aeskeyfind``).

A cipher key expanded in memory leaves a 176/208/240-byte schedule whose words
satisfy the AES key-expansion recurrence; checking that recurrence at every
aligned offset finds keys without knowing them. Both byte order conventions are
checked: the FIPS-197 byte array, and 32-bit big-endian words stored
little-endian (OpenSSL ``AES_KEY`` / T-table implementations on x86/ARM).
"""

from __future__ import annotations

from typing import Iterator, List, Tuple

SBOX = bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0"
    "b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275"
    "09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf"
    "d0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2"
    "cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb"
    "e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08"
    "ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e"
    "e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16")
RCON = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36)
SCHEDULE_LEN = {16: 176, 24: 208, 32: 240}


def expand_key(key: bytes) -> bytes:
    nk = len(key) // 4
    if len(key) not in SCHEDULE_LEN:
        raise ValueError("AES key must be 16, 24 or 32 bytes")
    total_words = SCHEDULE_LEN[len(key)] // 4
    w = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
    for i in range(nk, total_words):
        t = list(w[i - 1])
        if i % nk == 0:
            t = t[1:] + t[:1]
            t = [SBOX[b] for b in t]
            t[0] ^= RCON[i // nk - 1]
        elif nk > 6 and i % nk == 4:
            t = [SBOX[b] for b in t]
        w.append([a ^ b for a, b in zip(w[i - nk], t)])
    return bytes(b for word in w for b in word)


def _swap_words(data: bytes) -> bytes:
    out = bytearray(len(data))
    out[0::4], out[1::4], out[2::4], out[3::4] = data[3::4], data[2::4], data[1::4], data[0::4]
    return bytes(out)


def _quick(data: bytes, o: int, nk: int) -> bool:
    """Check the first expansion word only (cheap rejection)."""
    p = o + 4 * (nk - 1)
    q = o + 4 * nk
    return (data[q] == data[o] ^ SBOX[data[p + 1]] ^ 1 and data[q + 1] == data[o + 1] ^ SBOX[data[p + 2]]
            and data[q + 2] == data[o + 2] ^ SBOX[data[p + 3]] and data[q + 3] == data[o + 3] ^ SBOX[data[p]])


def find_key_schedules(data: bytes, base: int = 0, align: int = 4, key_sizes=(16, 24, 32),
                       skip_low_entropy: bool = True) -> Iterator[Tuple[int, int, str, bytes]]:
    """Yield ``(offset, key_bits, byte_order, key)`` for every exact schedule found."""
    views = [("bytes", data), ("u32-le", _swap_words(data[:len(data) - len(data) % 4]))]
    n = len(data)
    page = 4096
    for order, buf in views:
        for pstart in range(0, n, page):
            chunk = buf[pstart:pstart + page + 240]
            if skip_low_entropy and (chunk.count(0) > len(chunk) * 0.9 or len(set(chunk[:page])) < 32):
                continue
            for o in range(pstart - pstart % align, min(pstart + page, n - 16), align):
                for ks in key_sizes:
                    nk = ks // 4
                    end = o + SCHEDULE_LEN[ks]
                    if end > len(buf) or not _quick(buf, o, nk):
                        continue
                    key = bytes(buf[o:o + ks])
                    if len(set(key)) < 4:
                        continue
                    if expand_key(key) == bytes(buf[o:end]):
                        yield base + o, ks * 8, order, key


def entropy_ok(key: bytes) -> bool:
    return len(set(key)) >= len(key) // 2


def describe(results: List[Tuple[int, int, str, bytes]]):
    return [{"offset": o, "bits": b, "order": order, "key": k.hex()} for o, b, order, k in results]
