"""GPU code that is not CUDA: OpenCL C source, SPIR-V modules and Direct3D shader containers (DXBC/DXIL).

In-the-wild GPU loaders use OpenCL (CoffeeLoader/ArmouryLoader decrypt their payload with an OpenCL kernel
``c[i] = a[i] ^ b[i % d]``; GPUGate ships XOR-encoded OpenCL source), so the source text, its SPIR-V form
and the driver-compiled PTX all need to be recognised, and the XOR-with-modulo-key decryptor shape flagged.

SPIR-V (Khronos SPIR-V specification, "Physical Layout" / instruction enumerants)::

    header  u32 magic 0x07230203; u32 version (major 23:16, minor 15:8); u32 generator; u32 id bound; u32 0
    insn    u32 (word count << 16 | opcode), operands...
    OpSource 3 (language: 3 OpenCL_C, 4 OpenCL_CPP, 2 GLSL, 5 HLSL), OpName 5, OpMemoryModel 14,
    OpEntryPoint 15 (execution model, id, literal name), OpCapability 17, OpFunction 54, OpFunctionEnd 56,
    OpUMod 137, OpSRem 138, OpSMod 139, OpBitwiseXor 198
    execution models: 0 Vertex .. 4 Fragment, 5 GLCompute, 6 Kernel (OpenCL)

DXBC container (D3D10+ shader blob)::

    "DXBC", 16-byte hash, u32 version 1, u32 total size, u32 part count, u32 part offsets[]
    part: fourcc, u32 size, data   (SHDR/SHEX = SM4/5 bytecode, DXIL = SM6 program, RDEF, ISGN, OSGN, STAT, ...)
    SHEX/DXIL program version token: minor 3:0, major 7:4, program type 31:16 (5 = compute)
"""

from __future__ import annotations

import re
import struct
from typing import List, Optional, Tuple

SPIRV_MAGIC = 0x07230203
SPIRV_MAGIC_BYTES = struct.pack("<I", SPIRV_MAGIC)
EXEC_MODELS = {0: "vertex", 1: "tess-control", 2: "tess-eval", 3: "geometry", 4: "fragment", 5: "glcompute",
               6: "kernel", 5267: "task-nv", 5268: "mesh-nv", 5313: "raygen", 5314: "intersection",
               5315: "anyhit", 5316: "closesthit", 5317: "miss", 5318: "callable"}
SOURCE_LANGS = {0: "unknown", 1: "ESSL", 2: "GLSL", 3: "OpenCL_C", 4: "OpenCL_CPP", 5: "HLSL", 6: "CPP_for_OpenCL",
                7: "SYCL"}
OP_SOURCE, OP_NAME, OP_MEMORY_MODEL, OP_ENTRY_POINT, OP_CAPABILITY = 3, 5, 14, 15, 17
OP_MODS, OP_XOR = (137, 138, 139), 198
MAX_SPIRV = 16 << 20


def _literal_string(words: bytes) -> str:
    return words.split(b"\x00", 1)[0].decode("utf-8", "replace")


class SpirvModule:
    def __init__(self):
        self.version = (0, 0)
        self.generator = 0
        self.bound = 0
        self.size = 0
        self.entries: List[Tuple[str, str]] = []  # (execution model, name)
        self.capabilities: List[int] = []
        self.source_language: Optional[str] = None
        self.memory_model: Optional[int] = None
        self.has_xor = self.has_mod = False

    @property
    def is_opencl(self) -> bool:
        return any(m == "kernel" for m, _ in self.entries) or self.source_language in ("OpenCL_C", "OpenCL_CPP")

    @property
    def decryptor_pattern(self) -> bool:
        return self.has_xor and self.has_mod


def parse_spirv(data: bytes) -> Optional[SpirvModule]:
    """Parse a SPIR-V module at ``data[0]``; the module ends at the first malformed instruction."""
    if len(data) < 20 or struct.unpack_from("<I", data)[0] != SPIRV_MAGIC:
        return None
    _magic, version, gen, bound, schema = struct.unpack_from("<5I", data)
    major, minor = (version >> 16) & 0xFF, (version >> 8) & 0xFF
    if version & 0xFF0000FF or major != 1 or minor > 9 or schema != 0 or not 0 < bound < (1 << 22):
        return None
    mod = SpirvModule()
    mod.version, mod.generator, mod.bound = (major, minor), gen, bound
    pos, end = 20, min(len(data), MAX_SPIRV)
    n_insn = 0
    while pos + 4 <= end:
        word = struct.unpack_from("<I", data, pos)[0]
        wc, op = word >> 16, word & 0xFFFF
        if wc == 0 or pos + wc * 4 > end or op > 0x7FFF:
            break
        body = data[pos + 4:pos + wc * 4]
        if op == OP_ENTRY_POINT and len(body) >= 8:
            model = struct.unpack_from("<I", body)[0]
            mod.entries.append((EXEC_MODELS.get(model, "model%d" % model), _literal_string(body[8:])))
        elif op == OP_CAPABILITY and len(body) >= 4:
            mod.capabilities.append(struct.unpack_from("<I", body)[0])
        elif op == OP_SOURCE and len(body) >= 4:
            lang = struct.unpack_from("<I", body)[0]
            mod.source_language = SOURCE_LANGS.get(lang, "lang%d" % lang)
        elif op == OP_MEMORY_MODEL and len(body) >= 8:
            mod.memory_model = struct.unpack_from("<I", body, 4)[0]
        elif op == OP_XOR:
            mod.has_xor = True
        elif op in OP_MODS:
            mod.has_mod = True
        pos += wc * 4
        n_insn += 1
    if n_insn < 3 or not (mod.entries or mod.capabilities):
        return None
    mod.size = pos
    return mod


# -- OpenCL C source ------------------------------------------------------------------------------------------
KERNEL_RE = re.compile(rb"(?:__kernel|\bkernel)\s+(?:__attribute__\s*\(\(.{0,80}?\)\)\s*)?void\s+([A-Za-z_]\w{0,127})\s*\(",
                       re.DOTALL)
OPENCL_ANCHORS = (b"__kernel", b"kernel void", b"get_global_id")
_PRINTABLE = frozenset(range(0x20, 0x7F)) | {0x09, 0x0A, 0x0D}
_XOR_MOD_RE = re.compile(rb"\^\s*[\w\[\]\.\(\)]*\[[^\]]*%[^\]]*\]|\[[^\]]*%[^\]]*\]\s*\^", re.DOTALL)


def carve_text(data: bytes, hit: int, max_len: int = 1 << 20) -> Tuple[int, int]:
    """Extent of the printable-text run containing ``hit``."""
    s = hit
    while s > 0 and data[s - 1] in _PRINTABLE and hit - s < max_len:
        s -= 1
    e = hit
    while e < len(data) and data[e] in _PRINTABLE and e - s < max_len:
        e += 1
    return s, e


class OpenclSource:
    def __init__(self, text: bytes):
        self.text = text
        self.kernels = [m.group(1).decode() for m in KERNEL_RE.finditer(text)]
        self.uses_global_id = b"get_global_id" in text
        self.decryptor_pattern = bool(_XOR_MOD_RE.search(text))


def parse_opencl(text: bytes) -> Optional[OpenclSource]:
    src = OpenclSource(text)
    return src if src.kernels else None


# -- PTX compiled from a decryptor -----------------------------------------------------------------------------
_PTX_XOR = re.compile(rb"\bxor\.b(?:8|16|32|64)\b")
_PTX_REM = re.compile(rb"\brem\.[su](?:16|32|64)\b")


def ptx_decryptor_pattern(text: bytes) -> bool:
    """PTX with both XOR and integer remainder: the shape of ``out[i] = in[i] ^ key[i % n]``."""
    return bool(_PTX_XOR.search(text) and _PTX_REM.search(text))


# -- DXBC / DXIL ------------------------------------------------------------------------------------------------
DXBC_MAGIC = b"DXBC"
PROGRAM_TYPES = {0: "pixel", 1: "vertex", 2: "geometry", 3: "hull", 4: "domain", 5: "compute", 6: "library",
                 7: "raygen", 8: "intersection", 9: "anyhit", 10: "closesthit", 11: "miss", 12: "callable",
                 13: "mesh", 14: "amplification"}


class DxbcContainer:
    def __init__(self, size: int, parts: List[Tuple[str, int, int]]):
        self.size, self.parts = size, parts  # (fourcc, offset, size)
        self.program_type: Optional[str] = None
        self.shader_model: Optional[str] = None
        self.dxil = False


def parse_dxbc(data: bytes) -> Optional[DxbcContainer]:
    if len(data) < 32 or data[:4] != DXBC_MAGIC:
        return None
    version, total, count = struct.unpack_from("<III", data, 20)
    if version != 1 or not 32 <= total <= (64 << 20) or not 0 < count <= 64 or 32 + 4 * count > total \
            or 32 + 4 * count > len(data):  # the part table must be present, not only claimed
        return None
    parts = []
    for i in range(count):
        off = struct.unpack_from("<I", data, 32 + 4 * i)[0]
        if off + 8 > total or off + 8 > len(data):
            return None
        fourcc = data[off:off + 4]
        if not all(0x30 <= c <= 0x5A for c in fourcc):
            return None
        psize = struct.unpack_from("<I", data, off + 4)[0]
        if off + 8 + psize > total:
            return None
        parts.append((fourcc.decode("ascii"), off + 8, psize))
    c = DxbcContainer(total, parts)
    for fourcc, off, psize in parts:
        if fourcc in ("SHEX", "SHDR", "DXIL") and psize >= 4 and off + 4 <= len(data):
            tok = struct.unpack_from("<I", data, off)[0]
            c.program_type = PROGRAM_TYPES.get(tok >> 16, "type%d" % (tok >> 16))
            c.shader_model = "%d.%d" % ((tok >> 4) & 0xF, tok & 0xF)
            c.dxil = c.dxil or fourcc == "DXIL"
    return c


def build_spirv_kernel(name: str = "f", xor_mod: bool = True) -> bytes:
    """A minimal OpenCL-kernel SPIR-V module (test data): capability Kernel, memory model OpenCL,
    entry point Kernel ``name``, and optionally OpBitwiseXor + OpUMod in its body."""
    def insn(op, *words):
        return struct.pack("<I", ((len(words) + 1) << 16) | op) + b"".join(struct.pack("<I", w) for w in words)

    def lit(s):
        b = s.encode() + b"\x00"
        b += b"\x00" * (-len(b) % 4)
        return struct.unpack("<%dI" % (len(b) // 4), b)

    body = insn(OP_CAPABILITY, 6) + insn(OP_CAPABILITY, 4) + insn(OP_MEMORY_MODEL, 2, 2) + \
        insn(OP_ENTRY_POINT, 6, 1, *lit(name)) + insn(OP_SOURCE, 3, 102000) + insn(OP_NAME, 1, *lit(name))
    body += insn(21, 2, 32, 0)                     # OpTypeInt %2 32 0
    body += insn(19, 3) + insn(33, 4, 3)           # OpTypeVoid %3, OpTypeFunction %4 %3
    body += insn(54, 3, 1, 0, 4) + insn(248, 5)    # OpFunction, OpLabel
    if xor_mod:
        body += insn(43, 2, 6, 7) + insn(OP_MODS[0], 2, 8, 6, 6) + insn(OP_XOR, 2, 9, 8, 6)
    body += insn(253) + insn(56)                   # OpReturn, OpFunctionEnd
    return struct.pack("<5I", SPIRV_MAGIC, 0x00010000, 0, 16, 0) + body


def build_dxbc(program_type: int = 5, dxil: bool = False) -> bytes:
    """A minimal DXBC container with one shader part (test data)."""
    fourcc = b"DXIL" if dxil else b"SHEX"
    shader = struct.pack("<II", (program_type << 16) | (6 << 4 if dxil else 5 << 4), 4) + b"\x00" * 8
    part = fourcc + struct.pack("<I", len(shader)) + shader
    stat = b"STAT" + struct.pack("<I", 8) + b"\x00" * 8
    off0 = 32 + 8
    total = off0 + len(part) + len(stat)
    hdr = DXBC_MAGIC + b"\x11" * 16 + struct.pack("<IIIII", 1, total, 2, off0, off0 + len(part))
    return hdr + part + stat
