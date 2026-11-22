"""QMD (Queue Meta Data): the compute launch descriptor a kernel launch points at.

Every layout NVIDIA has published is supported, Kepler to Blackwell. Bit ranges are
the ``MW(hi:lo)`` defines of NVIDIA's ``cl<class>qmd.h`` headers (open-gpu-doc),
collected verbatim in docs/research/NVIDIA_COMMAND_FACTS.md section 1:

    version  size  where the version sits            program address
    V00_06   256   minor 579:576, major 583:580      32-bit PROGRAM_OFFSET (+ SET_PROGRAM_REGION_A/B)
    V01_06   256   "                                  "
    V01_07   256   "                                  "
    V02_00   256   "                                  "
    V02_01   256   "                                  "
    V02_02   256   "                                  64-bit PROGRAM_ADDRESS_LOWER/UPPER
    V02_03   256   "                                  "
    V02_04   256   "                                  "
    V03_00   256   "                                  "
    V04_00   384   "                                  64-bit PROGRAM_ADDRESS_LOWER/UPPER (moved)
    V04_01   384   "                                  "
    V05_00   384   minor 467:464, major 471:468      PROGRAM_ADDRESS_*_SHIFTED4 (address >> 4)
    V05_01   384   "                                  per sub-task (SUB_TASK_*(i), 416-bit stride, up to 5)

The version is read from the descriptor itself (the driver's choice per class is
not published), so decoding never depends on guessing the GPU generation.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple

QMD_SIZE = 256           # V00_06 .. V03_00 (and the alignment of every QMD: SEND_PCAS_A carries addr >> 8)
QMD_SIZE_LARGE = 384     # V04_xx, V05_xx
MAX_QMD_SIZE = QMD_SIZE_LARGE


def _v0x(prog_offset=True, regs=(1503, 1496), barriers=(1471, 1467), grid_d=(447, 432), cb="v0", rel="v0",
         local=((1463, 1440), (1495, 1472)), sass=(1535, 1528), prog_addr=None, regs_alt=None):
    f = {"minor": (579, 576), "major": (583, 580), "grid_w": (415, 384), "grid_h": (431, 416), "grid_d": grid_d,
         "block_x": (607, 592), "block_y": (623, 608), "block_z": (639, 624), "smem": (561, 544),
         "regs": regs, "barriers": barriers, "local_lo": local[0], "local_hi": local[1], "sass_version": sass}
    if prog_offset:
        f["prog_offset"] = (287, 256)
    if prog_addr:
        f["prog_lo"], f["prog_hi"] = prog_addr
    if regs_alt:
        f["regs_alt"] = regs_alt
    if rel == "v0":
        f.update(rel0_lo=(767, 736), rel0_hi=(775, 768), rel0_payload_lo=(831, 800), rel0_struct=(799, 799))
    if cb == "v0":
        cbs = {"valid": (640, 1), "lo": ((959, 928), 64), "hi": ((967, 960), 64), "size": ((991, 975), 64),
               "addr_shift": 0, "size_shift": 0}
    else:
        cbs = {"valid": (640, 1), "lo": ((1055, 1024), 64), "hi": ((1072, 1056), 64), "size": ((1087, 1075), 64),
               "addr_shift": 0, "size_shift": 4}
    return f, cbs


def _layouts():
    L = {}
    f, cb = _v0x()
    for name, (maj, minr) in (("v00_06", (0, 6)), ("v01_06", (1, 6)), ("v01_07", (1, 7))):
        L[name] = {"size": 256, "major": maj, "minor": minr, "fields": dict(f), "cb": cb, "prog": "offset"}
    f, cb = _v0x(regs=(991, 984), barriers=(959, 955), grid_d=(463, 448), cb="v2",
                 local=((951, 928), (983, 960)), sass=(1023, 1016))
    for name, minr in (("v02_00", 0), ("v02_01", 1)):
        L[name] = {"size": 256, "major": 2, "minor": minr, "fields": dict(f), "cb": cb, "prog": "offset"}
    # V02_02/V02_03 define both PROGRAM_OFFSET and PROGRAM_ADDRESS, and both REGISTER_COUNT(_V); drivers write the
    # 64-bit address and REGISTER_COUNT_V (NVK, gallium gv100_compute_setup_launch_desc)
    f, cb = _v0x(regs=(656, 648), regs_alt=(991, 984), barriers=(959, 955), grid_d=(463, 448), cb="v2",
                 local=((951, 928), (983, 960)), sass=(1023, 1016), prog_addr=((1567, 1536), (1584, 1568)))
    for name, minr in (("v02_02", 2), ("v02_03", 3)):
        L[name] = {"size": 256, "major": 2, "minor": minr, "fields": dict(f), "cb": cb, "prog": "address"}
    f2 = dict(f)
    f2.pop("regs_alt")
    L["v02_04"] = {"size": 256, "major": 2, "minor": 4, "fields": f2, "cb": cb, "prog": "address"}
    f3, cb3 = _v0x(prog_offset=False, regs=(656, 648), barriers=(767, 763), grid_d=(463, 448), cb="v2", rel=None,
                   local=((759, 736), (1623, 1600)), sass=(1663, 1656), prog_addr=((1567, 1536), (1584, 1568)))
    f3.update(rel0_lo=(799, 768), rel0_hi=(807, 800), rel0_payload_lo=(863, 832), rel0_payload_hi=(895, 864),
              rel0_struct=(831, 830))
    L["v03_00"] = {"size": 256, "major": 3, "minor": 0, "fields": f3, "cb": cb3, "prog": "address"}
    f4 = {"minor": (579, 576), "major": (583, 580), "prog_lo": (1247, 1216), "prog_hi": (1272, 1248),
          "grid_w": (1055, 1024), "grid_h": (1071, 1056), "grid_d": (1103, 1088), "block_x": (1167, 1152),
          "block_y": (1183, 1168), "block_z": (1199, 1184), "smem": (601, 584), "regs": (1208, 1200),
          "barriers": (1215, 1211), "rel0_lo": (671, 640), "rel0_hi": (696, 672), "rel0_payload_lo": (735, 704),
          "rel0_payload_hi": (767, 736), "rel0_struct": (322, 321), "rel0_enable": (320, 320),
          "local_lo": (535, 512), "local_hi": (567, 544), "sass_version": (543, 536)}
    cb4 = {"valid": (416, 4), "lo": ((1567, 1536), 64), "hi": ((1586, 1568), 64), "size": ((1599, 1587), 64),
           "addr_shift": 6, "size_shift": 4}
    L["v04_00"] = {"size": 384, "major": 4, "minor": 0, "fields": f4, "cb": cb4, "prog": "address"}
    f41 = dict(f4, block_z=(1191, 1184))
    L["v04_01"] = {"size": 384, "major": 4, "minor": 1, "fields": f41, "cb": cb4, "prog": "address"}
    f5 = {"minor": (467, 464), "major": (471, 468), "prog_lo": (1055, 1024), "prog_hi": (1076, 1056),
          "grid_w": (1279, 1248), "grid_h": (1295, 1280), "grid_d": (1327, 1312), "block_x": (1103, 1088),
          "block_y": (1119, 1104), "block_z": (1127, 1120), "smem": (1162, 1152), "regs": (1136, 1128),
          "barriers": (1141, 1137), "rel0_lo": (511, 480), "rel0_hi": (536, 512), "rel0_payload_lo": (575, 544),
          "rel0_payload_hi": (607, 576), "rel0_struct": (290, 289), "rel0_enable": (288, 288),
          "local_lo": (1199, 1184), "local_hi": (1215, 1200), "sass_version": (455, 448)}
    cb5 = {"valid": (1856, 4), "lo": ((1375, 1344), 64), "hi": ((1394, 1376), 64), "size": ((1407, 1395), 64),
           "addr_shift": 6, "size_shift": 4}
    L["v05_00"] = {"size": 384, "major": 5, "minor": 0, "fields": f5, "cb": cb5, "prog": "address_shift4",
                   "smem_shift": 7, "local_shift": 4}
    # V05_01 (clcdc0qmd.h / clcec0qmd.h): a task of NUM_SUB_TASKS_PER_TASK (157:154) sub-tasks; every launch field
    # is a SUB_TASK_*(i) array with a 416-bit stride (sub-task 0 below), each sub-task has two constant banks
    # (VALID stride 202 bits, address/size stride 64 bits); the release semaphore is shared by the task
    f51 = {"minor": (467, 464), "major": (471, 468), "qmd_type": (153, 151), "sub_tasks": (157, 154),
           "prog_lo": (799, 768), "prog_hi": (820, 800), "grid_w": (1151, 1120), "grid_h": (1167, 1152),
           "grid_d": (1183, 1168), "block_x": (847, 832), "block_y": (863, 848), "block_z": (871, 864),
           "smem": (906, 896), "regs": (880, 872), "barriers": (885, 881),
           "rel0_lo": (511, 480), "rel0_hi": (536, 512), "rel0_payload_lo": (575, 544),
           "rel0_payload_hi": (607, 576), "rel0_struct": (290, 289), "rel0_enable": (288, 288)}
    cb51 = {"valid": (886, 202), "lo": ((991, 960), 64), "hi": ((1010, 992), 64), "size": ((1023, 1011), 64),
            "addr_shift": 6, "size_shift": 4, "count": 2}
    L["v05_01"] = {"size": 384, "major": 5, "minor": 1, "fields": f51, "cb": cb51, "prog": "address_shift4",
                   "smem_shift": 7,
                   "sub_task": {"stride": 416, "max": 5,
                                "fields": ("prog_lo", "prog_hi", "grid_w", "grid_h", "grid_d", "block_x", "block_y",
                                           "block_z", "smem", "regs", "barriers")}}
    return L


LAYOUTS: Dict[str, dict] = _layouts()
#: versions recognised by their header but not decoded (none left: V05_01 sub-tasks are decoded)
RAW_ONLY: Dict[str, dict] = {}
QMD_TYPES = {0: "queue", 1: "grid null", 2: "grid CTA", 3: "grid GPC CGA", 4: "grid GPU CGA", 5: "grid GPU GPC CGA"}
EXPECT = {name: {"major": l["major"], "minor": l["minor"]} for name, l in LAYOUTS.items()}
CLASS_DEFAULT = {  # QMD version NVK writes per compute class family (for encoding test data only)
    "kepler_a": "v00_06", "kepler_b": "v01_07", "maxwell": "v01_07", "pascal": "v02_01", "volta": "v02_02",
    "turing": "v02_02", "ampere": "v03_00", "ada": "v03_00", "hopper": "v04_00", "blackwell": "v05_00"}

# version byte locations: byte 72 (bits 583:576) for V00..V04, byte 58 (bits 471:464) for V05
_V04_BYTE = {(l["major"] << 4) | l["minor"]: n for n, l in LAYOUTS.items() if l["major"] < 5}
_V05_BYTE = {(l["major"] << 4) | l["minor"]: n for n, l in list(LAYOUTS.items()) + list(RAW_ONLY.items())
             if l["major"] == 5}


def _get(blob_int: int, hi: int, lo: int) -> int:
    return (blob_int >> lo) & ((1 << (hi - lo + 1)) - 1)


# hardware launch limits shared by every generation (CUDA C programming guide, "Technical specifications per
# compute capability"): block 1024 x 1024 x 64 and 1024 threads, grid (2^31-1) x 65535 x 65535, 255 registers per
# thread, 16 named barriers, at most 228 KiB shared memory per block, 64 KiB constant banks, 57-bit virtual addresses
MAX_THREADS, MAX_BLOCK = 1024, (1024, 1024, 64)
MAX_GRID = ((1 << 31) - 1, 65535, 65535)
MAX_REGISTERS, MAX_BARRIERS, MAX_SHARED, MAX_CBUF, MAX_VA = 255, 16, 228 << 10, 64 << 10, 1 << 57


def _shape_ok(grid, block) -> bool:
    threads = 1
    for b, lim in zip(block, MAX_BLOCK):
        if not 1 <= b <= lim:
            return False
        threads *= b
    return threads <= MAX_THREADS and all(1 <= g <= lim for g, lim in zip(grid, MAX_GRID))


def detect(raw: bytes) -> Optional[str]:
    """Return the QMD version name encoded in ``raw`` (or None)."""
    if len(raw) > 58 and raw[58] in _V05_BYTE:
        return _V05_BYTE[raw[58]]
    if len(raw) > 72 and raw[72] in _V04_BYTE:
        return _V04_BYTE[raw[72]]
    return None


def scan_signatures() -> List[Tuple[int, int, set]]:
    """``(word_byte_offset, mask, {accepted values})`` pairs for 256-byte-stride scanning."""
    return [(72, 0xFF, set(_V04_BYTE)), (56, 0xFF0000, {v << 16 for v in _V05_BYTE})]


def signature(version: str):
    """``(byte_offset, mask, value)`` of the 32-bit word holding the version fields (single version)."""
    lay = LAYOUTS.get(version) or RAW_ONLY.get(version)
    if lay is None:
        return None
    v = (lay["major"] << 4) | lay["minor"]
    return (56, 0xFF0000, v << 16) if lay["major"] == 5 else (72, 0xFF, v)


class Qmd:
    def __init__(self, version: str, raw: bytes, fields: Dict[str, int], cbufs: List[Tuple[int, int, int]],
                 layout: dict, sub_task: int = 0):
        self.version, self.raw, self.fields, self._cbufs, self.layout = version, raw, fields, cbufs, layout
        #: index of the sub-task this view describes (V05_01; 0 for every other version)
        self.sub_task = sub_task

    @property
    def sub_tasks(self) -> List["Qmd"]:
        """One view per sub-task (V05_01): its own program, grid, block, registers, shared memory and constant
        banks; the release semaphore is the task's. Other versions: ``[self]``."""
        st = self.layout.get("sub_task")
        if not st:
            return [self]
        n = max(1, min(self.fields.get("sub_tasks", 0), st["max"]))
        blob = int.from_bytes(self.raw, "little")
        views = [self]
        for i in range(1, n):
            fields = dict(self.fields)
            for k in st["fields"]:
                hi, lo = self.layout["fields"][k]
                fields[k] = _get(blob, hi + i * st["stride"], lo + i * st["stride"])
            views.append(Qmd(self.version, self.raw, fields, _cbufs(blob, self.layout["cb"], i * st["stride"]),
                             self.layout, sub_task=i))
        return views

    @property
    def qmd_type(self) -> Optional[str]:
        t = self.fields.get("qmd_type")
        return None if t is None else QMD_TYPES.get(t, "type %d" % t)

    # -- normalised accessors (identical meaning on every generation) --------
    @property
    def program_mode(self) -> str:
        return self.layout["prog"]

    @property
    def program_offset(self) -> Optional[int]:
        return self.fields.get("prog_offset")

    @property
    def program_address(self) -> Optional[int]:
        """Absolute program VA; for offset-mode QMDs (Kepler..Pascal) the region base is unknown here,
        so this returns None - use :func:`resolve_program` with SET_PROGRAM_REGION."""
        f = self.fields
        if self.layout["prog"] == "offset":
            return None
        addr = f.get("prog_lo", 0) | (f.get("prog_hi", 0) << 32)
        return addr << 4 if self.layout["prog"] == "address_shift4" else addr

    @property
    def grid(self):
        return self.fields["grid_w"], self.fields["grid_h"], self.fields["grid_d"]

    @property
    def block(self):
        return self.fields["block_x"], self.fields["block_y"], self.fields["block_z"]

    @property
    def registers(self) -> int:
        return self.fields.get("regs") or self.fields.get("regs_alt", 0)

    @property
    def shared_memory(self) -> int:
        return self.fields.get("smem", 0) << self.layout.get("smem_shift", 0)

    @property
    def barriers(self) -> int:
        return self.fields.get("barriers", 0)

    def constant_buffers(self):
        return list(self._cbufs)

    @property
    def release_address(self) -> int:
        return self.fields.get("rel0_lo", 0) | (self.fields.get("rel0_hi", 0) << 32)

    @property
    def release_payload(self) -> int:
        return self.fields.get("rel0_payload_lo", 0) | (self.fields.get("rel0_payload_hi", 0) << 32)

    @property
    def release_four_words(self) -> bool:
        """True when the completion release writes the 16-byte payload + GPU timestamp structure."""
        return "rel0_struct" in self.fields and self.fields["rel0_struct"] == 0 and self.release_address != 0

    def resolve_program(self, region: Optional[int]) -> Optional[int]:
        if self.layout["prog"] != "offset":
            return self.program_address
        return None if region is None else region + (self.program_offset or 0)

    def plausible(self) -> bool:
        """Within the hardware limits of every generation (CUDA programming guide, compute capability table)."""
        if not _shape_ok(self.grid, self.block):
            return False
        if not 1 <= self.registers <= MAX_REGISTERS or self.barriers > MAX_BARRIERS:
            return False
        if self.shared_memory > MAX_SHARED or any(size > MAX_CBUF for _, _, size in self._cbufs):
            return False
        if self.layout["prog"] == "offset":
            return (self.program_offset or 0) % 16 == 0
        addr = self.program_address
        return bool(addr) and addr % 16 == 0 and addr < MAX_VA


def quick_plausible(raw: bytes, version: Optional[str] = None) -> bool:
    """Cheap pre-check before ``decode`` (used when scanning gigabytes): only the block, grid and program fields
    are extracted. Rejects what ``Qmd.plausible`` would reject; never rejects a descriptor it would accept."""
    if version in (None, "auto"):
        version = detect(raw)
    layout = LAYOUTS.get(version or "")
    if layout is None or len(raw) < layout["size"]:
        return False
    f = layout["fields"]
    blob = int.from_bytes(bytes(raw[:layout["size"]]), "little")
    return _shape_ok([_get(blob, *f[k]) for k in ("grid_w", "grid_h", "grid_d")],
                     [_get(blob, *f[k]) for k in ("block_x", "block_y", "block_z")])


def decode(raw: bytes, version: Optional[str] = None) -> Optional[Qmd]:
    """Decode a QMD; ``version=None`` (or "auto") reads the version from the descriptor."""
    if version in (None, "auto"):
        version = detect(raw)
    layout = LAYOUTS.get(version or "")
    if layout is None or len(raw) < layout["size"]:
        return None
    blob = int.from_bytes(bytes(raw[:layout["size"]]), "little")
    fields = {k: _get(blob, hi, lo) for k, (hi, lo) in layout["fields"].items()}
    return Qmd(version, bytes(raw[:layout["size"]]), fields, _cbufs(blob, layout["cb"]), layout)


def _cbufs(blob: int, cb: dict, shift: int = 0) -> List[Tuple[int, int, int]]:
    """Valid constant buffers ``(index, address, size)``; ``shift`` moves every field (V05_01 sub-tasks)."""
    out = []
    for i in range(cb.get("count", 8)):
        vbase, vstride = cb["valid"]
        v = vbase + i * vstride + shift
        if not _get(blob, v, v):
            continue
        (lhi, llo), st = cb["lo"]
        (hhi, hlo), _ = cb["hi"]
        (shi, slo), _ = cb["size"]
        o = i * st + shift
        addr = (_get(blob, lhi + o, llo + o) | (_get(blob, hhi + o, hlo + o) << 32)) << cb["addr_shift"]
        out.append((i, addr, _get(blob, shi + o, slo + o) << cb["size_shift"]))
    return out


def encode(version: str, fields: Dict[str, int], cbufs=(), sub_tasks=()) -> bytes:
    """Build a QMD from field values; ``sub_tasks`` (V05_01) gives the fields of sub-tasks 1, 2, ..."""
    layout = LAYOUTS[version]
    blob = 0

    def put(hi, lo, value):
        nonlocal blob
        blob |= (value & ((1 << (hi - lo + 1)) - 1)) << lo

    for name, value in dict(fields, major=layout["major"], minor=layout["minor"]).items():
        if name in layout["fields"]:
            put(*layout["fields"][name], value)
    st = layout.get("sub_task")
    for i, sub in enumerate(sub_tasks, 1):
        for name, value in sub.items():
            if st and name in st["fields"]:
                hi, lo = layout["fields"][name]
                put(hi + i * st["stride"], lo + i * st["stride"], value)
    cb = layout["cb"]
    for i, addr, size in cbufs:
        vbase, vstride = cb["valid"]
        put(vbase + i * vstride, vbase + i * vstride, 1)
        (lhi, llo), st = cb["lo"]
        (hhi, hlo), _ = cb["hi"]
        (shi, slo), _ = cb["size"]
        a = addr >> cb["addr_shift"]
        put(lhi + i * st, llo + i * st, a & 0xFFFFFFFF)
        put(hhi + i * st, hlo + i * st, a >> 32)
        put(shi + i * st, slo + i * st, size >> cb["size_shift"])
    return blob.to_bytes(layout["size"], "little")


def make_launch(program_address: int, grid=(1, 1, 1), block=(32, 1, 1), shared: int = 0, registers: int = 8,
                cbufs=(), release_address: int = 0, release_payload: int = 0, version: str = "v03_00",
                four_word_release: bool = False) -> bytes:
    """Build a launch descriptor of any version (``program_address`` is the offset for V00..V02_01)."""
    layout = LAYOUTS[version]
    f = {"grid_w": grid[0], "grid_h": grid[1], "grid_d": grid[2], "block_x": block[0], "block_y": block[1],
         "block_z": block[2], "smem": shared >> layout.get("smem_shift", 0), "regs": registers,
         "rel0_lo": release_address & 0xFFFFFFFF, "rel0_hi": release_address >> 32,
         "rel0_payload_lo": release_payload & 0xFFFFFFFF, "rel0_payload_hi": release_payload >> 32,
         "rel0_struct": 0 if four_word_release else 1}
    if layout["prog"] == "offset":
        f["prog_offset"] = program_address
    else:
        a = program_address >> 4 if layout["prog"] == "address_shift4" else program_address
        f["prog_lo"], f["prog_hi"] = a & 0xFFFFFFFF, a >> 32
    return encode(version, f, cbufs)
