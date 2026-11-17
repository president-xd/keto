"""Heuristics for raw NVIDIA SASS machine code (Volta and later, sm_70+).

Volta+ instructions are 128 bits. The low 12 bits hold the opcode and bits
15:12 the guard predicate (7 = PT, always true). Compiled kernels end with an
``EXIT`` followed by a branch-to-self and ``NOP`` padding to a 128-byte
boundary; these encodings were confirmed against a cubin JIT-compiled by the
local driver for sm_89:

    EXIT      0x000000000000794d / 0x000fea0003800000
    BRA self  0xfffffff000007947 / 0x000fc0000383ffff
    NOP       0x0000000000007918 / 0x000fc00000000000

This module does not disassemble; it recognises code-shaped memory so that
code outside known cubins (injected / orphaned GPU code) can be flagged.
"""

from __future__ import annotations

import re
import struct
from typing import Dict, Iterator, List, Tuple

OPC_EXIT, OPC_BRA, OPC_NOP = 0x94D, 0x947, 0x918
#: opcodes (low 12 bits) frequently seen in compiled kernels; used only for density scoring
COMMON_OPCODES = {
    0x94D: "EXIT", 0x947: "BRA", 0x918: "NOP", 0xA02: "MOV", 0x919: "S2R", 0x986: "STG", 0x981: "LDG",
    0xAB9: "ULDC", 0x224: "IMAD", 0x210: "IADD3", 0x212: "LOP3", 0x819: "SHF", 0x20C: "ISETP",
    0x221: "FADD", 0x220: "FMUL", 0x223: "FFMA", 0x984: "LDS", 0x988: "STS", 0xB1D: "BAR", 0x992: "MEMBAR",
    0x3C4: "UMOV", 0x625: "IMAD.WIDE", 0x825: "IMAD.WIDE", 0xC02: "MOV", 0x802: "MOV", 0x424: "IMAD",
    0x810: "IADD3", 0x812: "LOP3", 0x80C: "ISETP", 0x20B: "FSETP", 0x308: "MUFU", 0x941: "BSYNC",
    0x945: "BSSY", 0x950: "RET", 0x943: "CALL", 0x9A3: "ATOMG", 0x98A: "ATOMS", 0x9A8: "ATOMG", 0x305: "F2I",
    0x306: "I2F", 0x310: "F2F", 0x31E: "?", 0x3A6: "?", 0x989: "SHFL", 0x806: "VOTE",
}

EXIT_PAIR = struct.pack("<QQ", 0x000000000000794D, 0x000FEA0003800000)
#: EXIT ; BRA self - the canonical kernel epilogue (control bits on EXIT may vary, so match the BRA)
BRA_SELF = struct.pack("<QQ", 0xFFFFFFF000007947, 0x000FC0000383FFFF)
NOP_INSN = struct.pack("<QQ", 0x0000000000007918, 0x000FC00000000000)

EPILOGUE_RE = re.compile(re.escape(b"\x4d\x79") + rb".{14}" + re.escape(BRA_SELF), re.DOTALL)


def opcode(lo: int) -> int:
    return lo & 0xFFF


def predicate(lo: int) -> int:
    return (lo >> 12) & 0xF


def instructions(data: bytes) -> Iterator[Tuple[int, int, int]]:
    for off in range(0, len(data) - 15, 16):
        lo, hi = struct.unpack_from("<QQ", data, off)
        yield off, lo, hi


def code_score(data: bytes) -> Dict[str, float]:
    """Return density statistics for 16-byte-aligned data."""
    n = known = pt = zero = 0
    exits = 0
    for _, lo, hi in instructions(data):
        n += 1
        if lo == 0 and hi == 0:
            zero += 1
            continue
        op = opcode(lo)
        if op in COMMON_OPCODES:
            known += 1
        if op == OPC_EXIT:
            exits += 1
        if predicate(lo) == 7:
            pt += 1
        # control field in the high word is usually 0x000xxxxx_xxxxxxxx (bits 63:52 small)
    nz = max(n - zero, 1)
    return {"instructions": n, "nonzero": n - zero, "known_ratio": known / nz, "pt_ratio": pt / nz,
            "exits": exits}


def looks_like_code(data: bytes, min_instructions: int = 4) -> bool:
    s = code_score(data)
    return s["nonzero"] >= min_instructions and s["known_ratio"] >= 0.6 and s["pt_ratio"] >= 0.5


def skeleton_hash(code: bytes) -> str:
    """Relocation-tolerant fingerprint: SHA-256 over each instruction's opcode and guard
    predicate (low 16 bits) only, so loaded copies whose immediates/addresses were
    patched by the driver still hash identically."""
    import hashlib
    h = hashlib.sha256()
    for _, lo, _hi in instructions(code):
        if lo or _hi:
            h.update(struct.pack("<H", lo & 0xFFFF))
    return "skel:" + h.hexdigest()


def find_epilogues(data: bytes, base: int = 0) -> List[int]:
    """Offsets of ``EXIT; BRA self`` pairs (16-byte aligned)."""
    return [base + m.start() for m in EPILOGUE_RE.finditer(data) if m.start() % 16 == 0]


def code_extent(data: bytes, epilogue_off: int, max_back: int = 64 * 1024) -> Tuple[int, int]:
    """Given an epilogue offset inside ``data``, estimate the start and end of the
    function by walking backwards over code-like instructions and forwards over NOP padding."""
    start = epilogue_off
    lo_limit = max(0, epilogue_off - max_back)
    while start - 16 >= lo_limit:
        insn = data[start - 16:start]
        lo, hi = struct.unpack_from("<QQ", insn)
        if (lo == 0 and hi == 0) or insn in (BRA_SELF, NOP_INSN):
            break  # gap, or the padding / epilogue of the previous function
        if opcode(lo) not in COMMON_OPCODES and predicate(lo) != 7:
            break  # neither a recognised opcode nor an always-true guard: probably not code
        start -= 16
    end = epilogue_off + 32
    while end + 16 <= len(data) and data[end:end + 16] == NOP_INSN:
        end += 16
    return start, end
