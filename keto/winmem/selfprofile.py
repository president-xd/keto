"""Types for a Windows x64 kernel image without any PDB or ISF: the kernel describes itself.

Used when no symbol file for the imaged build is available (blocked symbol server, air-gapped lab), so every
analyst runs the same commands and gets the same core results. Three sources, each recorded in the notes:

1. **The kernel's own code.** ntoskrnl exports accessors whose first instruction reads an ``_EPROCESS`` member,
   so their machine code carries the exact offsets of the imaged build: ``PsGetProcessId`` (``mov rax,[rcx+X]``
   = 48 8B 81 X), ``PsGetProcessImageFileName`` (``lea rax,[rcx+X]``), ``PsGetProcessPeb``,
   ``PsGetProcessInheritedFromUniqueProcessId``, ``PsGetProcessCreateTimeQuadPart``, ``PsGetProcessExitTime``,
   ``PsGetProcessDxgProcess``, ``PsGetProcessWin32Process``, ``PsGetProcessWow64Process``,
   ``PsGetProcessProtection`` (a byte load), ``PsGetProcessSessionId`` (Session pointer, then SessionId) and
   ``PsGetThreadId`` (``_ETHREAD.Cid.UniqueThread``). ActiveProcessLinks follows UniqueProcessId (+8) on every
   x64 build; that is checked by walking the list from ``PsInitialSystemProcess``.
2. **The image's own data.** ``_EPROCESS.ObjectTable`` is the member whose ``_HANDLE_TABLE`` points back at the
   process (QuotaProcess, +0x10) and carries its PID (+0x28); ``VadRoot`` is the member pointing at a root VAD
   with a sane user range and no parent; ``SeAuditProcessCreationInfo`` points at a ``\\Device\\...`` path. The
   object-header cookie is decoded from the System process's own header and the Process type's index, then
   checked on the type objects; the root object directory is the parent of ``\\ObjectTypes``, reached from the
   Process type object's name; ``ObTypeIndexTable`` is the pointer array holding the exported type objects at
   their indexes. ``_MMVAD_FLAGS`` comes from a per-build table (below) and is confirmed on image-backed VADs.
3. **Layouts that did not change from Windows 10 1809 to Windows 11 25H2** (Vergilius Project pages of both
   builds, listed in docs/research/WINDOWS_LAYOUTS.md): handle tables and entries, object headers and name info,
   object types (Name, Index), file and driver objects, object directories, kernel and user loader entries, the
   PEB fields used, process parameters, ``_MMVAD_SHORT`` / ``_MMVAD.Subsection`` / ``_SUBSECTION.ControlArea`` /
   ``_CONTROL_AREA.FilePointer`` and ``_KPROCESS.DirectoryTableBase``.
"""

from __future__ import annotations

import struct
from typing import Dict, List, Optional, Tuple

from keto.framework.exceptions import InvalidAddressException, RequirementError
from keto.winmem import pe as pe_mod
from keto.winmem.isf import IsfSymbols
from keto.winmem.kernel import KUSER_SHARED_DATA, Located, WinKernel, is_kernel_va

# _MMVAD_FLAGS (VadType, Protection, PrivateMemory) as (bit, width) per Vergilius x64 pages
VAD_FLAG_LAYOUTS = {
    "1607": {"VadType": (0, 3), "Protection": (3, 5), "PrivateMemory": (15, 1)},
    "1809": {"VadType": (0, 3), "Protection": (3, 5), "PrivateMemory": (14, 1)},
    "2004": {"VadType": (4, 3), "Protection": (7, 5), "PrivateMemory": (20, 1)},
    "22H2": {"VadType": (4, 3), "Protection": (7, 5), "PrivateMemory": (21, 1)},  # also 24H2 and 25H2
}
BUILD_LAYOUT = [(14393, 14393, "1607"), (17763, 17763, "1809"), (19041, 19045, "2004"), (22621, 26200, "22H2")]

ACCESSORS = [  # export, member, load width
    ("PsGetProcessId", "UniqueProcessId", 8), ("PsGetProcessImageFileName", "ImageFileName", 0),
    ("PsGetProcessPeb", "Peb", 8), ("PsGetProcessInheritedFromUniqueProcessId", "InheritedFromUniqueProcessId", 8),
    ("PsGetProcessCreateTimeQuadPart", "CreateTime", 8), ("PsGetProcessExitTime", "ExitTime", 8),
    ("PsGetProcessDxgProcess", "DxgProcess", 8), ("PsGetProcessWin32Process", "Win32Process", 8),
    ("PsGetProcessWow64Process", "WoW64Process", 8), ("PsGetProcessProtection", "Protection", 1),
    ("PsGetProcessSectionBaseAddress", "SectionBaseAddress", 8),
]
EXPORTED_TYPES = ("PsProcessType", "PsThreadType", "IoFileObjectType", "IoDeviceObjectType", "IoDriverObjectType",
                  "ExEventObjectType", "PsJobType", "SeTokenObjectType", "CmKeyObjectType", "ExSemaphoreObjectType",
                  "ExMutantObjectType", "MmSectionObjectType", "IoCompletionObjectType", "TmTransactionObjectType")


def mem_operands(code: bytes) -> List[Tuple[int, int]]:
    """``(base register, displacement)`` of each load / lea through ``[reg+disp]`` in ``code``, in order. Forms:
    optional REX.W (48/4C), then ``8B /r``, ``8D /r``, ``8A /r`` or ``0F B6 /r``, ``0F B7 /r``; ModRM mod 01
    (disp8) or 10 (disp32); rm 4 (SIB) and 5 (RIP-relative) are skipped. Registers: 0 = rax, 1 = rcx."""
    out, i, n = [], 0, len(code)
    while i < n - 2:
        j = i + (1 if code[i] in (0x48, 0x4C) else 0)
        k = j + 1
        if code[j] == 0x0F and k < n and code[k] in (0xB6, 0xB7):
            k += 1
        elif code[j] not in (0x8B, 0x8D, 0x8A):
            i += 1
            continue
        if k >= n:
            break
        mod, rm = code[k] >> 6, code[k] & 7
        if rm not in (4, 5) and mod == 1 and k + 1 < n:
            out.append((rm, struct.unpack_from("<b", code, k + 1)[0]))
            i = k + 2
        elif rm not in (4, 5) and mod == 2 and k + 4 < n:
            out.append((rm, struct.unpack_from("<i", code, k + 1)[0]))
            i = k + 5
        else:
            i += 1
    return out


def _follow_thunk(read, va: int) -> bytes:
    code = read(va, 48)
    if code[0] == 0xE9:  # jmp rel32 (export thunks)
        target = va + 5 + struct.unpack_from("<i", code, 1)[0]
        code = read(target, 48)
    return code


class _Probe:
    """Reads through a located kernel before any types exist."""

    def __init__(self, phys, loc: Located):
        self.k = WinKernel(phys, loc.dtb, loc.base, IsfSymbols({"user_types": {}}, source="probe"), loc.levels)

    def u64(self, va):
        return self.k.u64(va)

    def read(self, va, n):
        return self.k.read(va, n)

    def ok(self, va, n=8):
        try:
            self.k.read(va, n)
            return True
        except InvalidAddressException:
            return False


def build(phys, loc: Located, sample: int = 24) -> Tuple[IsfSymbols, List[str]]:
    """An ISF-backed SymbolTable for the located kernel, derived from the image; raises RequirementError when
    the kernel's export table is not resident (nothing can be derived reliably then)."""
    notes: List[str] = []
    p = _Probe(phys, loc)
    try:
        exports = pe_mod.from_memory(p.read, loc.base).exports()
    except (InvalidAddressException, pe_mod.PeError, struct.error) as e:
        raise RequirementError("no symbols for this kernel and its export table is not in the image (%s): give "
                               "--pdb/--isf for %s %s" % (e, loc.codeview.pdb_name, loc.codeview.key))
    va = lambda name: loc.base + exports[name]  # noqa: E731
    code = accessor_offsets(p.read, exports, loc.base)
    notes.extend(code["notes"])
    ep: Dict[str, Tuple[int, dict]] = {m: (o, _member_type(m)) for m, o in code["eprocess"].items()}
    session_id_off = code["session_id"]
    if "UniqueProcessId" not in ep:
        raise RequirementError("self-profile: PsGetProcessId is not readable in the image; give --pdb/--isf for "
                               "%s %s" % (loc.codeview.pdb_name, loc.codeview.key))
    pid_off = ep["UniqueProcessId"][0]
    link_off = pid_off + 8
    ep["ActiveProcessLinks"] = (link_off, {"kind": "struct", "name": "_LIST_ENTRY"})
    ep["Pcb"] = (0, {"kind": "struct", "name": "_KPROCESS"})
    system = p.u64(va("PsInitialSystemProcess")) if "PsInitialSystemProcess" in exports else 0
    if not is_kernel_va(system) or p.u64(system + pid_off) != 4:
        raise RequirementError("self-profile: PsInitialSystemProcess does not lead to PID 4; give --pdb/--isf")
    head = p.u64(system + link_off + 8)  # System is first on the list: its Blink is PsActiveProcessHead
    if p.u64(head) != system + link_off:
        raise RequirementError("self-profile: ActiveProcessLinks is not UniqueProcessId + 8 in this build")
    procs = _walk(p, head, link_off, sample)
    notes.append("self-profile: PsActiveProcessHead 0x%x from the System process's ActiveProcessLinks.Blink" % head)
    _data_members(p, procs, pid_off, ep, notes)
    thread = {"Cid": (code["cid"], {"kind": "struct", "name": "_CLIENT_ID"})} if code["cid"] is not None else {}
    build_no = (p.u64(va("NtBuildNumber")) & 0xFFFF) if "NtBuildNumber" in exports else \
        struct.unpack("<I", p.read(KUSER_SHARED_DATA + 0x260, 4))[0] & 0xFFFF
    vadflags, why = _vad_layout(p, procs, ep, build_no)
    notes.append("self-profile: _MMVAD_FLAGS %s" % why)
    values: Dict[str, object] = {}
    symbols = {"PsActiveProcessHead": head - loc.base}
    for name in ("PsLoadedModuleList", "NtBuildNumber", "NtBuildLab", "KeNumberProcessors"):
        if name in exports:
            symbols[name] = exports[name]
    _object_manager(p, exports, va, system, symbols, values, notes, loc.base)
    doc = _document(ep, thread, session_id_off, vadflags, symbols, loc)
    table = IsfSymbols(doc, source="self-profile of %s %s (no PDB)" % (loc.codeview.pdb_name, loc.codeview.key))
    table.values = values
    return table, notes


KTHREAD_APC_PROCESS = 0xB8  # _KTHREAD.ApcState.Process on x64 Windows 8+ (ApcState 0x98 + Process 0x20)


def accessor_offsets(read, exports: Dict[str, int], base: int = 0) -> dict:
    """Member offsets decoded from ntoskrnl's accessor functions. ``read(va, n)`` reads the image (memory: VAs;
    a file: RVAs with ``base`` 0). Returns ``{"eprocess": {member: offset}, "session_id", "cid", "notes"}``.

    Two shapes besides the plain first-instruction load: ``PsGetProcessExitTime`` on recent builds reads the
    *current* process (``gs:[188h]`` -> ``[rax+0xB8]`` = KTHREAD.ApcState.Process -> ``[rax+ExitTime]``), and
    ``PsGetProcessSessionId`` loads the Session pointer into any register before reading ``[reg+SessionId]``."""
    out = {"eprocess": {}, "session_id": None, "cid": None, "notes": []}
    notes = out["notes"]

    def ops_of(fn):
        try:
            return mem_operands(_follow_thunk(read, base + exports[fn]))
        except InvalidAddressException:
            notes.append("self-profile: %s code not resident" % fn)
            return None

    for fn, member, _width in ACCESSORS:
        if fn not in exports:
            continue
        ops = ops_of(fn)
        if ops is None:
            continue
        disp = next((d for reg, d in ops if reg == 1), None)
        if disp is None and member == "ExitTime":  # current-process chain
            for i in range(len(ops) - 1):
                if ops[i][1] == KTHREAD_APC_PROCESS and ops[i + 1][0] == ops[i][0]:
                    disp = ops[i + 1][1]
                    break
        if disp is None or not 0 < disp < 0x2000:
            notes.append("self-profile: no member load found in %s" % fn)
            continue
        out["eprocess"][member] = disp
    if "PsGetProcessSessionId" in exports:
        ops = ops_of("PsGetProcessSessionId") or []
        first = next((i for i, (reg, d) in enumerate(ops) if reg == 1), None)
        if first is not None and 0 < ops[first][1] < 0x2000:
            out["eprocess"]["Session"] = ops[first][1]
            out["session_id"] = next((d for reg, d in ops[first + 1:] if reg != 1 and 0 <= d < 0x100), None)
    if "PsGetThreadId" in exports:
        ops = ops_of("PsGetThreadId") or []
        t = next((d for reg, d in ops if reg == 1), None)
        if t is not None and t > 8:
            out["cid"] = t - 8
    derived = ", ".join("%s 0x%x" % kv for kv in sorted(out["eprocess"].items(), key=lambda kv: kv[1]))
    notes.append("self-profile: _EPROCESS members from ntoskrnl accessor code: %s" % (derived or "none"))
    return out


def _member_type(member: str) -> dict:
    if member == "Session":
        return {"kind": "pointer", "subtype": {"kind": "struct", "name": "_MM_SESSION_SPACE"}}
    if member == "ImageFileName":
        return {"kind": "array", "count": 15, "subtype": {"kind": "base", "name": "unsigned char"}}
    if member in ("CreateTime", "ExitTime"):
        return {"kind": "union", "name": "_LARGE_INTEGER"}
    if member == "Protection":
        return {"kind": "struct", "name": "_PS_PROTECTION"}
    return {"kind": "pointer", "subtype": {"kind": "base", "name": "void"}}


def _walk(p: _Probe, head: int, link_off: int, limit: int) -> List[int]:
    out, node, seen = [], p.u64(head), set()
    while node != head and node not in seen and len(out) < limit and is_kernel_va(node):
        seen.add(node)
        out.append(node - link_off)
        try:
            node = p.u64(node)
        except InvalidAddressException:
            break
    return out


def _qwords(p: _Probe, ep_va: int, size: int = 0x1000) -> Dict[int, int]:
    out = {}
    for off in range(0, size, 8):
        try:
            out[off] = p.u64(ep_va + off)
        except InvalidAddressException:
            pass
    return out


def _data_members(p: _Probe, procs: List[int], pid_off: int, ep: Dict[str, Tuple[int, dict]], notes: List[str]):
    rows = [(e, _qwords(p, e), p.u64(e + pid_off)) for e in procs]
    # ObjectTable, VadRoot and SeAuditProcessCreationInfo are _EPROCESS's own members, after ActiveProcessLinks in
    # every build (the _KPROCESS part before it holds other pointers that can look alike)
    taken = {o for o, _t in ep.values()} | set(range(0, pid_off + 0x18, 8))

    def vote(test, min_hits=2):
        counts: Dict[int, int] = {}
        for e, qs, pid in rows:
            for off, v in qs.items():
                if off not in taken and test(e, off, v, pid):
                    counts[off] = counts.get(off, 0) + 1
        best = max(counts.items(), key=lambda kv: (kv[1], -kv[0]), default=(None, 0))
        return best[0] if best[1] >= min(min_hits, len(rows)) else None

    def handle_table(e, off, v, pid):
        return is_kernel_va(v) and p.ok(v + 0x28) and p.u64(v + 0x10) == e and p.u64(v + 0x28) == pid

    off = vote(handle_table)
    if off is not None:
        ep["ObjectTable"] = (off, {"kind": "pointer", "subtype": {"kind": "struct", "name": "_HANDLE_TABLE"}})
        notes.append("self-profile: ObjectTable 0x%x (its _HANDLE_TABLE points back at the process)" % off)

    def vad_node(v):
        raw = p.read(v, 0x22)
        left, right, parent = struct.unpack_from("<QQQ", raw, 0)
        s, e_ = struct.unpack_from("<II", raw, 0x18)
        return left, right, parent, (raw[0x20] << 32) | s, (raw[0x21] << 32) | e_

    def vad_root(e, off, v, pid):
        """A parentless node whose children point back at it (ParentValue, low 2 bits = balance) and lie on the
        correct side of its range: a binary tree, not just something with a plausible header."""
        if pid in (0, 4) or not is_kernel_va(v):
            return False
        try:
            left, right, parent, start, end = vad_node(v)
            if parent & ~3 or not start <= end < (1 << 36) or not (left or right):
                return False
            for child, is_left in ((left, True), (right, False)):
                if not child:
                    continue
                if not is_kernel_va(child):
                    return False
                _l, _r, cpar, cs, ce = vad_node(child)
                if cpar & ~3 != v or cs > ce or (is_left and ce >= start) or (not is_left and cs <= end):
                    return False
        except InvalidAddressException:
            return False
        return True

    off = vote(vad_root)
    if off is not None:
        ep["VadRoot"] = (off, {"kind": "struct", "name": "_RTL_AVL_TREE"})
        notes.append("self-profile: VadRoot 0x%x (points at a parentless VAD with a user range)" % off)

    def audit_name(e, off, v, pid):
        if not is_kernel_va(v) or not p.ok(v, 16):
            return False
        length, _mx, _pad, buf = struct.unpack("<HHIQ", p.read(v, 16))
        if not length or length & 1 or not is_kernel_va(buf):
            return False
        try:
            return p.read(buf, 16).decode("utf-16-le", "replace").startswith("\\Device\\")
        except InvalidAddressException:
            return False

    off = vote(audit_name)
    if off is not None:
        ep["SeAuditProcessCreationInfo"] = (off, {"kind": "struct", "name": "_SE_AUDIT_PROCESS_CREATION_INFO"})
        notes.append("self-profile: SeAuditProcessCreationInfo 0x%x (points at a \\Device\\ path)" % off)


def _vad_layout(p: _Probe, procs: List[int], ep, build_no: int) -> Tuple[dict, str]:
    """Per-build _MMVAD_FLAGS, confirmed (or chosen, for builds outside the table) on image-backed VADs: such a
    VAD has VadType 2 (VadImageMap), PrivateMemory 0 and protection EXECUTE_WRITECOPY (7)."""
    samples, others = [], []
    if "VadRoot" in ep:
        for e in procs:
            try:
                root = p.u64(e + ep["VadRoot"][0])
            except InvalidAddressException:
                continue
            stack, seen = [root], set()
            while stack and len(seen) < 64:
                n = stack.pop()
                if not n or n in seen or not is_kernel_va(n):
                    continue
                seen.add(n)
                try:
                    stack += [p.u64(n), p.u64(n + 8)]
                    flags = struct.unpack("<I", p.read(n + 0x30, 4))[0]
                    (samples if _image_file(p, n) else others).append(flags)
                except InvalidAddressException:
                    continue
    return choose_vad_layout(samples, build_no, others)


def _nearest_listed(build_no: int) -> Optional[str]:
    return min(BUILD_LAYOUT, key=lambda r: min(abs(build_no - r[0]), abs(build_no - r[1])))[2] if BUILD_LAYOUT else None


def choose_vad_layout(samples: List[int], build_no: int, others: List[int] = ()) -> Tuple[dict, str]:
    """The table layout for ``build_no`` unless the image's VADs fit another layout strictly better; for builds
    outside the table, the best-fitting layout, ties going to the nearest listed build. Image-backed VADs
    (``samples``) score one point per expectation met: VadType 2 (VadImageMap), PrivateMemory 0, Protection 7
    (EXECUTE_WRITECOPY). The other VADs (``others``: heaps, stacks, data sections) must set the layout's
    PrivateMemory bit on some but not all of them: a bit that is never set cannot be PrivateMemory."""
    listed = next((name for lo, hi, name in BUILD_LAYOUT if lo <= build_no <= hi), None)
    nearest = listed or _nearest_listed(build_no)

    def field(f, layout, name):
        pos, width = layout[name]
        return (f >> pos) & ((1 << width) - 1)

    def score(layout):
        good = sum((field(f, layout, "VadType") == 2) + (field(f, layout, "PrivateMemory") == 0) +
                   (field(f, layout, "Protection") == 7) for f in samples)
        private = sum(field(f, layout, "PrivateMemory") for f in others)
        plausible = 1 if not others or 0 < private < len(others) else 0
        return plausible, good

    if not samples:
        if listed:
            return VAD_FLAG_LAYOUTS[listed], "layout of %s from the build table (build %d; no image VAD to confirm " \
                                             "it)" % (listed, build_no)
        return {}, "unknown for build %d and no image VAD to choose a layout: VAD protection is not shown" % build_no
    best = max(VAD_FLAG_LAYOUTS, key=lambda n: (score(VAD_FLAG_LAYOUTS[n]), n == nearest))
    plausible, good = score(VAD_FLAG_LAYOUTS[best])
    return VAD_FLAG_LAYOUTS[best], "layout of %s (build %d%s), %d/%d checks on %d image-backed VADs%s" % (
        best, build_no, "" if best == listed else ", chosen from the data", good, 3 * len(samples), len(samples),
        ", PrivateMemory set on %d of %d other VADs" % (sum(field(f, VAD_FLAG_LAYOUTS[best], "PrivateMemory")
                                                           for f in others), len(others)) if others else "")


def _image_file(p: _Probe, vad: int) -> bool:
    """The VAD maps an executable image: _MMVAD.Subsection (+0x48) -> ControlArea (+0) -> FilePointer (+0x40,
    an _EX_FAST_REF) -> _FILE_OBJECT.FileName (+0x58) ending in a PE extension."""
    try:
        sub = p.u64(vad + 0x48)
        ca = p.u64(sub) if is_kernel_va(sub) else 0
        fo = (p.u64(ca + 0x40) & ~0xF) if is_kernel_va(ca) else 0
        if not is_kernel_va(fo):
            return False
        length, _m, _pad, buf = struct.unpack("<HHIQ", p.read(fo + 0x58, 16))
        name = p.read(buf, min(length, 520)).decode("utf-16-le", "replace").lower()
    except InvalidAddressException:
        return False
    return name.endswith((".dll", ".exe", ".sys", ".drv"))


def _object_manager(p: _Probe, exports, va, system: int, symbols: dict, values: dict, notes: List[str], base: int):
    types = {}
    for name in EXPORTED_TYPES:
        if name in exports:
            try:
                t = p.u64(va(name))
                if is_kernel_va(t):
                    types[name] = (t, p.read(t + 0x28, 1)[0])
            except InvalidAddressException:
                pass
    if "PsProcessType" not in types:
        notes.append("self-profile: PsProcessType unreadable: object types, handles and drivers unavailable")
        return
    ptype, pidx = types["PsProcessType"]
    hdr = system - 0x30
    raw = p.read(hdr + 0x18, 1)[0]
    cookie = raw ^ ((hdr >> 8) & 0xFF) ^ pidx
    checks = []
    for name, (t, _i) in types.items():  # every type object is itself an object of type "Type"
        th = t - 0x30
        checks.append(p.read(th + 0x18, 1)[0] ^ ((th >> 8) & 0xFF) ^ cookie)
    consistent = len(set(checks)) == 1
    values["ObHeaderCookie"] = cookie
    notes.append("self-profile: ObHeaderCookie 0x%02x from the System process header%s" % (
        cookie, " (type objects agree)" if consistent and len(checks) > 1 else ""))
    values["ObpInfoMaskToOffset"] = bytes(_info_mask_offsets())
    want = {idx: t for t, idx in types.values()}
    table = _find_type_table(p, base, want)
    if table:
        symbols["ObTypeIndexTable"] = table - base
        notes.append("self-profile: ObTypeIndexTable 0x%x (holds the exported type objects at their indexes)" % table)
    else:
        values["ObTypeNames"] = {idx: _type_name(p, t) for t, idx in types.values()}
        notes.append("self-profile: ObTypeIndexTable not found; only exported object types are named")
    try:  # \ObjectTypes\Process -> \ObjectTypes -> \  (name info sits below the header when InfoMask & 2)
        mask = p.read(ptype - 0x30 + 0x1A, 1)[0]
        ni = ptype - 0x30 - (0x20 if mask & 1 else 0) - 0x20
        objtypes = p.u64(ni)
        mask2 = p.read(objtypes - 0x30 + 0x1A, 1)[0]
        root = p.u64(objtypes - 0x30 - (0x20 if mask2 & 1 else 0) - 0x20)
        if is_kernel_va(root):
            values["ObpRootDirectoryObject"] = root
            notes.append("self-profile: root object directory 0x%x (parent of \\ObjectTypes)" % root)
    except InvalidAddressException:
        notes.append("self-profile: root object directory not reachable: driver objects unavailable")


def _info_mask_offsets() -> List[int]:
    """Stand-in for nt!ObpInfoMaskToOffset. Keto only reads entry ``InfoMask & 3`` (the name info, which lies below
    the creator info when bit 0 is set): _OBJECT_HEADER_CREATOR_INFO and _OBJECT_HEADER_NAME_INFO are 0x20 bytes
    each. Higher bits never affect those entries, so they are filled the same way."""
    return [(0x20 if m & 1 else 0) + (0x20 if m & 2 else 0) for m in range(256)]


def _find_type_table(p: _Probe, base: int, want: Dict[int, int]) -> Optional[int]:
    if not want:
        return None
    (idx0, t0), = list(want.items())[:1]
    needle = struct.pack("<Q", t0)
    size = 0x2000000
    try:
        size = pe_mod.from_memory(p.read, base).size_of_image
    except Exception:  # noqa: BLE001 - header already read once; keep the default
        pass
    for off in range(0, size, 0x1000):
        try:
            page = p.read(base + off, 0x1000)
        except InvalidAddressException:
            continue
        pos = page.find(needle)
        while pos >= 0:
            if pos % 8 == 0:
                cand = base + off + pos - 8 * idx0
                try:
                    if all(p.u64(cand + 8 * i) == t for i, t in want.items()):
                        return cand
                except InvalidAddressException:
                    pass
            pos = page.find(needle, pos + 1)
    return None


def _type_name(p: _Probe, t: int) -> str:
    try:
        length, _m, _pad, buf = struct.unpack("<HHIQ", p.read(t + 0x10, 16))
        return p.read(buf, length).decode("utf-16-le", "replace")
    except InvalidAddressException:
        return "?"


def _document(ep, thread, session_id_off, vadflags, symbols, loc: Located) -> dict:
    def b(n):
        return {"kind": "base", "name": n}

    def ptr(sub=None):
        return {"kind": "pointer", "subtype": sub or b("void")}

    def s(n):
        return {"kind": "struct", "name": n}

    def bf(pos, ln, base="unsigned long"):
        return {"kind": "bitfield", "bit_position": pos, "bit_length": ln, "type": b(base)}

    U8, U16, U32, U64 = b("unsigned char"), b("unsigned short"), b("unsigned long"), b("unsigned long long")
    types = {
        "_LIST_ENTRY": (16, {"Flink": (0, ptr()), "Blink": (8, ptr())}),
        "_UNICODE_STRING": (16, {"Length": (0, U16), "MaximumLength": (2, U16), "Buffer": (8, ptr(b("wchar")))}),
        "_LARGE_INTEGER": (8, {"QuadPart": (0, b("long long"))}),
        "_KPROCESS": (0x28 + 8, {"DirectoryTableBase": (0x28, U64)}),
        "_PS_PROTECTION": (1, {"Level": (0, U8)}),
        "_SE_AUDIT_PROCESS_CREATION_INFO": (8, {"ImageFileName": (0, ptr())}),
        "_RTL_AVL_TREE": (8, {"Root": (0, ptr())}),
        "_RTL_BALANCED_NODE": (0x18, {"Left": (0, ptr()), "Right": (8, ptr()), "ParentValue": (0x10, U64)}),
        "_HANDLE_TABLE": (0x80, {"NextHandleNeedingPool": (0, U32), "TableCode": (8, U64), "QuotaProcess": (0x10, ptr()),
                                 "UniqueProcessId": (0x28, ptr())}),
        "_HANDLE_TABLE_ENTRY": (16, {"ObjectPointerBits": (0, bf(20, 44, "unsigned long long")),
                                     "GrantedAccessBits": (8, bf(0, 25))}),
        "_OBJECT_HEADER": (0x38, {"TypeIndex": (0x18, U8), "InfoMask": (0x1A, U8), "Body": (0x30, U64)}),
        "_OBJECT_HEADER_NAME_INFO": (0x20, {"Directory": (0, ptr()), "Name": (8, s("_UNICODE_STRING"))}),
        "_OBJECT_TYPE": (0xD8, {"Name": (0x10, s("_UNICODE_STRING")), "Index": (0x28, U8)}),
        "_FILE_OBJECT": (0xD8, {"DeviceObject": (8, ptr()), "FileName": (0x58, s("_UNICODE_STRING"))}),
        "_DRIVER_OBJECT": (0x150, {"DriverStart": (0x18, ptr()), "DriverSize": (0x20, U32),
                                   "DriverName": (0x38, s("_UNICODE_STRING")),
                                   "MajorFunction": (0x70, {"kind": "array", "count": 28, "subtype": ptr()})}),
        "_OBJECT_DIRECTORY": (0x158, {"HashBuckets": (0, {"kind": "array", "count": 37, "subtype": ptr()})}),
        "_OBJECT_DIRECTORY_ENTRY": (0x18, {"ChainLink": (0, ptr()), "Object": (8, ptr())}),
        "_KLDR_DATA_TABLE_ENTRY": (0xA0, {"InLoadOrderLinks": (0, s("_LIST_ENTRY")), "DllBase": (0x30, ptr()),
                                          "SizeOfImage": (0x40, U32), "FullDllName": (0x48, s("_UNICODE_STRING")),
                                          "BaseDllName": (0x58, s("_UNICODE_STRING"))}),
        "_PEB": (0x7C8, {"Ldr": (0x18, ptr()), "ProcessParameters": (0x20, ptr())}),
        "_RTL_USER_PROCESS_PARAMETERS": (0x420, {"ImagePathName": (0x60, s("_UNICODE_STRING")),
                                                 "CommandLine": (0x70, s("_UNICODE_STRING")),
                                                 "Environment": (0x80, ptr()), "EnvironmentSize": (0x3F0, U64)}),
        "_CLIENT_ID": (16, {"UniqueProcess": (0, ptr()), "UniqueThread": (8, ptr())}),
        "_MMVAD_SHORT": (0x40, {"VadNode": (0, s("_RTL_BALANCED_NODE")), "StartingVpn": (0x18, U32),
                                "EndingVpn": (0x1C, U32), "StartingVpnHigh": (0x20, U8), "EndingVpnHigh": (0x21, U8),
                                "u": (0x30, {"kind": "union", "name": "__vadflags"})}),
        "_MMVAD": (0x88, {"Core": (0, s("_MMVAD_SHORT")), "Subsection": (0x48, ptr())}),
        "_SUBSECTION": (0x38, {"ControlArea": (0, ptr())}),
        "_CONTROL_AREA": (0x80, {"FilePointer": (0x40, {"kind": "union", "name": "_EX_FAST_REF"})}),
        "_EPROCESS": (0x1000, {m: v for m, v in ep.items()}),
    }
    unions = {"_EX_FAST_REF": (8, {"Object": (0, ptr()), "Value": (0, U64)}),
              "__vadflags": (4, {"LongFlags": (0, U32), "VadFlags": (0, s("_MMVAD_FLAGS"))})}
    types["_MMVAD_FLAGS"] = (4, {name: (0, bf(pos, ln)) for name, (pos, ln) in vadflags.items()})
    if session_id_off is not None:
        types["_MM_SESSION_SPACE"] = (session_id_off + 4, {"SessionId": (session_id_off, U32)})
    if thread:
        types["_ETHREAD"] = (max(o for o, _t in thread.values()) + 16, dict(thread))
    doc = {"metadata": {"windows": {"pdb": {"GUID": loc.codeview.guid, "age": loc.codeview.age,
                                            "database": loc.codeview.pdb_name, "machine_type": 0x8664}}},
           "base_types": {"unsigned char": {"size": 1, "signed": False, "kind": "int"},
                          "unsigned short": {"size": 2, "signed": False, "kind": "int"},
                          "unsigned long": {"size": 4, "signed": False, "kind": "int"},
                          "unsigned long long": {"size": 8, "signed": False, "kind": "int"},
                          "long long": {"size": 8, "signed": True, "kind": "int"},
                          "wchar": {"size": 2, "signed": False, "kind": "int"},
                          "void": {"size": 0, "signed": False, "kind": "void"},
                          "pointer": {"size": 8, "signed": False, "kind": "int"}},
           "user_types": {}, "enums": {}, "symbols": {n: {"address": a} for n, a in symbols.items()}}
    for kind, table in (("struct", types), ("union", unions)):
        for name, (size, fields) in table.items():
            doc["user_types"][name] = {"kind": kind, "size": size,
                                       "fields": {f: {"offset": o, "type": t} for f, (o, t) in fields.items()}}
    return doc
