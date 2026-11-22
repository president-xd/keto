"""AES key-schedule detection (the technique popularised by ``aeskeyfind``).

A cipher key expanded in memory leaves a 176/208/240-byte schedule whose words
satisfy the AES key-expansion recurrence; checking that recurrence at every
aligned offset finds keys without knowing them. Both byte order conventions are
checked: the FIPS-197 byte array, and 32-bit big-endian words stored
little-endian (OpenSSL ``AES_KEY`` / T-table implementations on x86/ARM).
"""

from __future__ import annotations

import re
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


# Linear prefilter. For key words W[i] with i % Nk != 0 (and, for AES-256, i % Nk != 4) the expansion is linear:
# W[i] = W[i-Nk] ^ W[i-1]. So E[p] = d[p] ^ d[p - 4*Nk] ^ d[p - 4] is zero across those words of a schedule:
# 3 words (12 bytes) from byte 20 for AES-128, 5 words (20 bytes) from byte 28 for AES-192, 3 words from byte 36
# for AES-256. E for a whole chunk is three big-integer operations, and its zero runs are found by a C regex, so
# only real candidates reach the full check. Swapping bytes within words does not change XOR relations between
# whole words, so one pass serves both byte orders.
_LINEAR = {16: (4, 20, 12), 24: (6, 28, 20), 32: (8, 36, 12)}  # key bytes -> (Nk, zero window offset, length)
# (spelled with a literal prefix of zero bytes, which the regex engine searches for at C speed)
_RUNS = {ks: re.compile(re.escape(b"\x00" * ln) + rb"\x00{0,8}") for ks, (_nk, _o, ln) in _LINEAR.items()}
# Zero-filled memory satisfies the recurrence trivially (0 ^ 0 ^ 0). E is blanked over every run of >= 64 zero data
# bytes before the regex runs, so zero pages cost one C-level slice each instead of a Python check per offset. No
# real schedule is lost: 64 zero bytes hold 15 whole zero words, and among them is a word W[i] (i % Nk == 0, or
# i % 8 == 4 for AES-256) whose W[i-Nk] and W[i-1] are zero too, so W[i] = SubWord(0) (^ Rcon) != 0; a run reaching
# from before a schedule into its zero window zeroes W[0] and W[Nk-1] and therefore W[Nk], so it cannot exist either.
_ZERO_DATA = re.compile(re.escape(b"\x00" * 64) + rb"\x00*")


def find_key_schedules(data: bytes, base: int = 0, align: int = 4, key_sizes=(16, 24, 32),
                       skip_low_entropy: bool = True) -> Iterator[Tuple[int, int, str, bytes]]:
    """Yield ``(offset, key_bits, byte_order, key)`` for every exact schedule found (FIPS byte order, or
    32-bit words stored little-endian)."""
    data = bytes(data)
    n = len(data)
    if n < 176:
        return
    if align < 1:
        raise ValueError("align must be >= 1")
    a = int.from_bytes(data, "little")
    mask = (1 << (8 * n)) - 1
    a4 = a ^ (a << 32)
    zero_runs = [m.span() for m in _ZERO_DATA.finditer(data)]
    ones = memoryview(b"\xff" * max((e - s for s, e in zero_runs), default=0))
    for ks in key_sizes:
        nk, off, ln = _LINEAR[ks]
        eb = bytearray(((a4 ^ (a << (32 * nk))) & mask).to_bytes(n, "little"))
        for s, e in zero_runs:
            eb[s:e] = ones[:e - s]
        seen = set()
        for m in _RUNS[ks].finditer(eb):
            for o in range(max(0, m.start() - off), m.end() - off - ln + 1):
                if o % align or o in seen:
                    continue
                seen.add(o)
                end = o + SCHEDULE_LEN[ks]
                if end > n:
                    continue
                sched = data[o:end]
                if skip_low_entropy and len(set(sched[:ks])) < 4:
                    continue
                if expand_key(sched[:ks]) == sched:
                    yield base + o, ks * 8, "bytes", sched[:ks]
                    continue
                sw = _swap_words(sched)
                if (not skip_low_entropy or len(set(sw[:ks])) >= 4) and expand_key(sw[:ks]) == sw:
                    yield base + o, ks * 8, "u32-le", sw[:ks]


def entropy_ok(key: bytes) -> bool:
    return len(set(key)) >= len(key) // 2


def describe(results: List[Tuple[int, int, str, bytes]]):
    return [{"offset": o, "bits": b, "order": order, "key": k.hex()} for o, b, order, k in results]
