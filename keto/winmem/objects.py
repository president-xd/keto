"""Walkers over Windows kernel objects. Member names come from the kernel's own symbols, so the same code
serves every build whose PDB names the members; members missing from a build give ``None`` values, not errors.

* Processes: ``nt!PsActiveProcessHead`` -> ``_EPROCESS.ActiveProcessLinks``.
* Modules: ``nt!PsLoadedModuleList`` -> ``_KLDR_DATA_TABLE_ENTRY.InLoadOrderLinks``.
* Handles: ``_EPROCESS.ObjectTable`` -> ``_HANDLE_TABLE.TableCode`` (low 2 bits = levels; 4 KiB pages of 16-byte
  ``_HANDLE_TABLE_ENTRY`` at level 0, pointer pages above; handle value = index * 4). Windows 8.1+ entries keep
  the object header in ``ObjectPointerBits`` (header VA = bits << 4 | 0xFFFF000000000000). The header's
  ``TypeIndex`` is encoded on Windows 10+: index = TypeIndex ^ nt!ObHeaderCookie ^ byte 1 of the header address,
  then ``nt!ObTypeIndexTable[index]`` -> ``_OBJECT_TYPE.Name``. Optional headers sit below the object header at
  ``nt!ObpInfoMaskToOffset[InfoMask & (bit*2-1)]``; bit 0x2 is ``_OBJECT_HEADER_NAME_INFO``.
* VADs: ``_EPROCESS.VadRoot`` (``_RTL_AVL_TREE``) of ``_MMVAD_SHORT`` nodes; start = (StartingVpnHigh << 32 |
  StartingVpn) << 12; a mapped file is ``_MMVAD.Subsection -> ControlArea -> FilePointer`` (``_EX_FAST_REF``,
  low 4 bits are a reference count).
* Drivers: ``nt!ObpRootDirectoryObject`` -> ``_OBJECT_DIRECTORY.HashBuckets[37]`` chains -> the ``\\Driver``
  directory -> ``_DRIVER_OBJECT`` (DriverStart, DriverSize, DriverName, MajorFunction[28]).
"""

from __future__ import annotations

import datetime
import struct
from typing import Dict, Iterator, List, Optional, Tuple

from keto.framework.exceptions import InvalidAddressException
from keto.winmem.kernel import WinKernel, WinObj, is_kernel_va
from keto.winmem.paging import ADDR
from keto.winmem.symtab import SymbolError

FILETIME_EPOCH = datetime.datetime(1601, 1, 1)
MAX_HANDLES = 1 << 20
IRP_MJ = ["CREATE", "CREATE_NAMED_PIPE", "CLOSE", "READ", "WRITE", "QUERY_INFORMATION", "SET_INFORMATION",
          "QUERY_EA", "SET_EA", "FLUSH_BUFFERS", "QUERY_VOLUME_INFORMATION", "SET_VOLUME_INFORMATION",
          "DIRECTORY_CONTROL", "FILE_SYSTEM_CONTROL", "DEVICE_CONTROL", "INTERNAL_DEVICE_CONTROL", "SHUTDOWN",
          "LOCK_CONTROL", "CLEANUP", "CREATE_MAILSLOT", "QUERY_SECURITY", "SET_SECURITY", "POWER", "SYSTEM_CONTROL",
          "DEVICE_CHANGE", "QUERY_QUOTA", "SET_QUOTA", "PNP"]
_PROT = ["NOACCESS", "READONLY", "EXECUTE", "EXECUTE_READ", "READWRITE", "WRITECOPY", "EXECUTE_READWRITE",
         "EXECUTE_WRITECOPY"]
_PROT_MOD = ["", "NOCACHE|", "GUARD|", "WRITECOMBINE|"]


def filetime(value: Optional[int]) -> Optional[datetime.datetime]:
    """UTC datetime of a FILETIME (100 ns since 1601), None for 0 or implausible values."""
    if not value or value < 0 or value > 0x0300000000000000:
        return None
    return FILETIME_EPOCH + datetime.timedelta(microseconds=value // 10)


def vad_protection(index: Optional[int]) -> str:
    if index is None:
        return "?"
    return "PAGE_" + _PROT_MOD[(index >> 3) & 3] + _PROT[index & 7]


# -- processes ------------------------------------------------------------------------------------------------
def processes(k: WinKernel, limit: int = 1 << 16) -> List[WinObj]:
    head = k.sym("PsActiveProcessHead")
    link = k.symtab.offsetof("_EPROCESS", "ActiveProcessLinks")
    return [k.obj("_EPROCESS", va) for va in k.list_entries(head, link, limit)]


def _first(obj: WinObj, *paths, default=None):
    for p in paths:
        if obj.has(p):
            return obj.get(p, default)
    return default


def proc_info(k: WinKernel, ep: WinObj) -> dict:
    """Identity and state of one ``_EPROCESS``; unreadable members become None."""
    info = {"va": ep.va, "pid": ep.get("UniqueProcessId"), "ppid": ep.get("InheritedFromUniqueProcessId"),
            "name": ep.string("ImageFileName") if ep.has("ImageFileName") else "",
            "create_time": filetime(ep.get("CreateTime.QuadPart")), "exit_time": filetime(ep.get("ExitTime.QuadPart")),
            "dtb": (ep.get("Pcb.DirectoryTableBase") or 0) & ADDR, "peb": ep.get("Peb"),
            "wow64": bool(_first(ep, "WoW64Process", "Wow64Process")),
            "threads": ep.get("ActiveThreads"), "dxg_process": ep.get("DxgProcess"),
            "win32_process": ep.get("Win32Process"), "object_table": ep.get("ObjectTable"),
            "protection": ep.get("Protection.Level"), "session": None, "path": None}
    try:
        sess = ep.deref("Session", "_MM_SESSION_SPACE") if ep.has("Session") else None
        info["session"] = sess.get("SessionId") if sess is not None else None
    except (SymbolError, InvalidAddressException):
        pass
    try:
        name_ptr = ep.get("SeAuditProcessCreationInfo.ImageFileName")
        if name_ptr:
            info["path"] = k.unicode(name_ptr)  # _OBJECT_NAME_INFORMATION starts with its UNICODE_STRING Name
    except InvalidAddressException:
        pass
    return info


# -- modules ----------------------------------------------------------------------------------------------------
def modules(k: WinKernel) -> List[dict]:
    head = k.sym("PsLoadedModuleList")
    link = k.symtab.offsetof("_KLDR_DATA_TABLE_ENTRY", "InLoadOrderLinks")
    out = []
    for va in k.list_entries(head, link):
        e = k.obj("_KLDR_DATA_TABLE_ENTRY", va)
        out.append({"va": va, "base": e.get("DllBase") or 0, "size": e.get("SizeOfImage") or 0,
                    "name": _safe_unicode(e, "BaseDllName"), "path": _safe_unicode(e, "FullDllName"),
                    "timestamp": e.get("TimeDateStamp")})
    return out


def _safe_unicode(obj: WinObj, path: str) -> str:
    try:
        return obj.unicode(path)
    except (InvalidAddressException, SymbolError):
        return ""


def module_at(mods: List[dict], addr: int) -> Optional[dict]:
    for m in mods:
        if m["base"] <= addr < m["base"] + m["size"]:
            return m
    return None


# -- object headers -------------------------------------------------------------------------------------------
class ObjectInfo:
    """Decoding of object headers with the per-boot cookie and type table, cached per kernel."""

    def __init__(self, k: WinKernel):
        self.k = k
        values = getattr(k.symtab, "values", None) or {}  # derived by keto.winmem.selfprofile (no PDB)
        self.body = k.symtab.offsetof("_OBJECT_HEADER", "Body")
        self.cookie = values.get("ObHeaderCookie")
        if self.cookie is None and k.has_sym("ObHeaderCookie"):
            self.cookie = k.u8(k.sym("ObHeaderCookie"))
        self.table = k.sym("ObTypeIndexTable") if k.has_sym("ObTypeIndexTable") else None
        self.mask_to_offset = values.get("ObpInfoMaskToOffset")
        if self.mask_to_offset is None and k.has_sym("ObpInfoMaskToOffset"):
            try:
                self.mask_to_offset = k.read(k.sym("ObpInfoMaskToOffset"), 256)
            except InvalidAddressException:
                pass
        self._types: Dict[int, str] = dict(values.get("ObTypeNames") or {})

    def header(self, body_va: int) -> int:
        return body_va - self.body

    def type_index(self, header_va: int) -> Optional[int]:
        h = self.k.obj("_OBJECT_HEADER", header_va)
        idx = h.get("TypeIndex")
        if idx is None:
            return None
        if self.cookie is not None:
            idx ^= self.cookie ^ ((header_va >> 8) & 0xFF)
        return idx

    def type_name(self, header_va: int) -> str:
        idx = self.type_index(header_va)
        if idx is None:
            return "?"
        if idx not in self._types and self.table is None:
            return "?"
        if idx not in self._types:
            name = "?"
            try:
                t = self.k.u64(self.table + 8 * idx)
                if is_kernel_va(t):
                    name = self.k.unicode(t + self.k.symtab.offsetof("_OBJECT_TYPE", "Name"))
            except (InvalidAddressException, SymbolError):
                pass
            self._types[idx] = name
        return self._types[idx]

    def name(self, header_va: int, depth: int = 0) -> str:
        """Object name with its directory path (``\\Device\\DxgKrnl``), or '' for unnamed objects."""
        try:
            h = self.k.obj("_OBJECT_HEADER", header_va)
            mask = h.get("InfoMask") or 0
            if not mask & 0x2 or self.mask_to_offset is None:
                return ""
            off = self.mask_to_offset[mask & 0x3]
            ni = self.k.obj("_OBJECT_HEADER_NAME_INFO", header_va - off)
            name = ni.unicode("Name")
            parent = ni.get("Directory")
            if parent and depth < 16:
                pname = self.name(self.header(parent), depth + 1)
                if pname and pname != "\\":
                    return pname + "\\" + name
                return "\\" + name
            return name
        except (InvalidAddressException, SymbolError):
            return ""

    def describe(self, body_va: int) -> Tuple[str, str]:
        """``(type name, name)`` of the object whose body is at ``body_va``; files get the device path plus file
        name, processes and threads their ids."""
        hva = self.header(body_va)
        tname = self.type_name(hva)
        name = self.name(hva)
        try:
            if tname == "File":
                fo = self.k.obj("_FILE_OBJECT", body_va)
                fname = fo.unicode("FileName")
                dev = fo.get("DeviceObject")
                dname = self.name(self.header(dev)) if dev else ""
                name = (dname + fname) if dname else fname
            elif tname == "Process":
                ep = self.k.obj("_EPROCESS", body_va)
                name = "%s (pid %s)" % (ep.string("ImageFileName"), ep.get("UniqueProcessId"))
            elif tname == "Thread":
                th = self.k.obj("_ETHREAD", body_va)
                name = "tid %s pid %s" % (th.get("Cid.UniqueThread"), th.get("Cid.UniqueProcess"))
        except (InvalidAddressException, SymbolError):
            pass
        return tname, name


def handles(k: WinKernel, ep: WinObj, oi: Optional[ObjectInfo] = None, errors: Optional[List[str]] = None
            ) -> Iterator[dict]:
    oi = oi or ObjectInfo(k)
    errors = errors if errors is not None else []
    table_va = ep.get("ObjectTable")
    if not table_va:
        return
    ht = k.obj("_HANDLE_TABLE", table_va)
    code = ht.get("TableCode") or 0
    levels, base = code & 3, code & ~3
    limit = min(ht.get("NextHandleNeedingPool") or MAX_HANDLES * 4, MAX_HANDLES * 4) // 4
    esize = k.symtab.sizeof("_HANDLE_TABLE_ENTRY") or 16
    per_page = 0x1000 // esize
    hte = k.symtab.struct("_HANDLE_TABLE_ENTRY")
    use_bits = k.symtab.has_member(hte, "ObjectPointerBits")

    def leaf_pages():
        if levels == 0:
            yield 0, base
        elif levels == 1:
            for i in range(512):
                p = k.u64(base + 8 * i)
                if p:
                    yield i * per_page, p
        else:
            for i in range(512):
                mid = k.u64(base + 8 * i)
                if not mid:
                    continue
                for j in range(512):
                    p = k.u64(mid + 8 * j)
                    if p:
                        yield (i * 512 + j) * per_page, p

    try:
        pages = list(leaf_pages())
    except InvalidAddressException as e:
        errors.append("handle table of pid %s unreadable: %s" % (ep.get("UniqueProcessId"), e))
        return
    for first, page_va in pages:
        try:
            raw = k.read(page_va, per_page * esize)
        except InvalidAddressException as e:
            errors.append("handle page 0x%x unreadable: %s" % (page_va, e))
            continue
        for i in range(per_page):
            index = first + i
            if index == 0 or index >= limit:
                continue
            low, high = struct.unpack_from("<QQ", raw, i * esize)
            if not low:
                continue
            if use_bits:
                obj_hdr = (((low >> 20) << 4) | 0xFFFF000000000000) & 0xFFFFFFFFFFFFFFFF
                access = high & 0x1FFFFFF
            else:
                obj_hdr = low & ~7
                access = high & 0xFFFFFFFF
            if not is_kernel_va(obj_hdr):
                continue
            body = obj_hdr + oi.body
            try:
                tname, name = oi.describe(body)
            except InvalidAddressException:
                tname, name = "?", ""
            yield {"handle": index * 4, "object": body, "type": tname, "name": name, "access": access}


# -- VADs -------------------------------------------------------------------------------------------------------
def vads(k: WinKernel, ep: WinObj, errors: Optional[List[str]] = None, limit: int = 1 << 17) -> List[dict]:
    errors = errors if errors is not None else []
    root = ep.get("VadRoot.Root") if ep.has("VadRoot.Root") else ep.get("VadRoot")
    if not root:
        return []
    st = k.symtab
    short = st.struct("_MMVAD_SHORT")
    left = st.offsetof(short, "VadNode.Left") if st.has_member(short, "VadNode.Left") else 0
    right = st.offsetof(short, "VadNode.Right") if st.has_member(short, "VadNode.Right") else 8
    out, stack, seen = [], [root], set()
    while stack and len(seen) < limit:
        node = stack.pop()
        if not node or node in seen or not is_kernel_va(node):
            continue
        seen.add(node)
        try:
            v = k.obj("_MMVAD_SHORT", node)
            stack.append(k.u64(node + right))
            stack.append(k.u64(node + left))
            start = ((v.get("StartingVpnHigh", 0) or 0) << 32 | v["StartingVpn"]) << 12
            end = (((v.get("EndingVpnHigh", 0) or 0) << 32 | v["EndingVpn"]) << 12) | 0xFFF
            private = _first(v, "u.VadFlags.PrivateMemory", "VadFlags.PrivateMemory")
            prot = _first(v, "u.VadFlags.Protection", "VadFlags.Protection")
            vtype = _first(v, "u.VadFlags.VadType", "VadFlags.VadType")
        except (InvalidAddressException, SymbolError) as e:
            errors.append("VAD node 0x%x unreadable: %s" % (node, e))
            continue
        out.append({"vad": node, "start": start, "end": end, "private": bool(private), "protection": prot,
                    "type": vtype, "file": _vad_file(k, node) if not private else ""})
    out.sort(key=lambda d: d["start"])
    return out


def _vad_file(k: WinKernel, node: int) -> str:
    try:
        vad = k.obj("_MMVAD", node)
        sub = vad.get("Subsection")
        if not sub:
            return ""
        ca = k.obj("_SUBSECTION", sub).get("ControlArea")
        if not ca:
            return ""
        ref = k.obj("_CONTROL_AREA", ca)
        fp = ref.get("FilePointer.Value") if ref.has("FilePointer.Value") else ref.get("FilePointer")
        if isinstance(fp, WinObj):
            fp = fp.get("Value")
        fp = (fp or 0) & ~0xF
        if not is_kernel_va(fp):
            return ""
        return k.obj("_FILE_OBJECT", fp).unicode("FileName")
    except (InvalidAddressException, SymbolError):
        return ""


# -- object directory / drivers ---------------------------------------------------------------------------------
def directory_entries(k: WinKernel, dir_va: int, oi: ObjectInfo, limit: int = 1 << 15) -> Iterator[Tuple[str, str, int]]:
    """``(type name, name, body address)`` of the objects in one ``_OBJECT_DIRECTORY``."""
    d = k.obj("_OBJECT_DIRECTORY", dir_va)
    buckets = k.read(d.addr("HashBuckets"), 37 * 8)
    seen = set()
    for i in range(37):
        entry = struct.unpack_from("<Q", buckets, 8 * i)[0]
        while entry and entry not in seen and len(seen) < limit and is_kernel_va(entry):
            seen.add(entry)
            e = k.obj("_OBJECT_DIRECTORY_ENTRY", entry)
            body = e.get("Object")
            if body and is_kernel_va(body):
                hva = oi.header(body)
                yield oi.type_name(hva), oi.name(hva).rsplit("\\", 1)[-1], body
            entry = e.get("ChainLink")


def driver_objects(k: WinKernel, oi: Optional[ObjectInfo] = None) -> List[dict]:
    oi = oi or ObjectInfo(k)
    root = (getattr(k.symtab, "values", None) or {}).get("ObpRootDirectoryObject")
    if root is None:
        root = k.u64(k.sym("ObpRootDirectoryObject"))
    drv_dir = None
    for tname, name, body in directory_entries(k, root, oi):
        if tname == "Directory" and name.lower() == "driver":
            drv_dir = body
            break
    if drv_dir is None:
        return []
    out = []
    for tname, name, body in directory_entries(k, drv_dir, oi):
        if tname != "Driver":
            continue
        d = k.obj("_DRIVER_OBJECT", body)
        try:
            mj = struct.unpack("<28Q", k.read(d.addr("MajorFunction"), 28 * 8))
        except InvalidAddressException:
            mj = ()
        out.append({"object": body, "name": _safe_unicode(d, "DriverName") or "\\Driver\\" + name,
                    "start": d.get("DriverStart") or 0, "size": d.get("DriverSize") or 0, "major": list(mj)})
    return out


def process_space_dtb(ep: WinObj) -> int:
    return (ep.get("Pcb.DirectoryTableBase") or 0) & ADDR


# -- pool scanning -------------------------------------------------------------------------------------------
POOL_TAGS_PROCESS = (b"Proc", b"Pro\xe3")  # 'Proc', with the protected-allocation bit on Windows 7 and earlier


def _kernel_half(k: WinKernel, dtb: int) -> Optional[Tuple[int, ...]]:
    try:
        return struct.unpack("<256Q", k.phys.read((dtb & ADDR) + 0x800, 0x800))
    except InvalidAddressException:
        return None


def pool_scan_processes(k: WinKernel, known: Optional[Dict[int, int]] = None, limit: int = 1 << 16) -> List[dict]:
    """``_EPROCESS`` objects found by pool tag in physical memory. A hit is a ``_POOL_HEADER`` (tag at +4,
    BlockSize = bits 16..23 of its first ULONG, in 16-byte units) followed within its first 0x200 bytes (the
    optional object headers) by an object body that starts with a ``_KPROCESS`` dispatcher header of Type 3
    (ProcessObject) and whose ``DirectoryTableBase`` is a page whose kernel half (entries 256..511) matches the
    system address space in most present entries (every process shares the kernel mappings). The body must lie in
    the pool header's physical page. ``known`` maps physical body addresses of listed processes to their kernel
    addresses; otherwise the address is recovered through ActiveProcessLinks (a neighbour's Blink, or a
    self-linked entry) and confirmed by translating it back; without it, members are read from the body's
    physical page only (``partial``)."""
    from keto.framework.scanners import BytesScanner, scan
    st = k.symtab
    body_off = st.offsetof("_OBJECT_HEADER", "Body")
    dtb_off = st.offsetof("_EPROCESS", "Pcb.DirectoryTableBase")
    link_off = st.offsetof("_EPROCESS", "ActiveProcessLinks")
    system = _kernel_half(k, k.dtb) or ()
    present = [i for i, e in enumerate(system) if e & 1]
    phys = k.phys
    known = known or {}
    out, seen = [], set()
    for tag in POOL_TAGS_PROCESS:
        for hit, _ in scan(phys, BytesScanner(tag)):
            if len(out) >= limit:
                return out
            hdr = hit - 4
            if hdr & 0xF:
                continue
            try:
                page = phys.read(hdr & ~0xFFF, 0x1000)
            except InvalidAddressException:
                continue
            base = hdr & 0xFFF
            alloc = page[base + 2] * 16
            if alloc < 0x100:
                continue
            for o in range(base + 16, min(base + 0x200, 0x1000 - body_off - 8), 8):
                b = o + body_off
                if page[b] != 3 or b + dtb_off + 8 > 0x1000 or (hdr & ~0xFFF) + b in seen:
                    continue
                dtb = struct.unpack_from("<Q", page, b + dtb_off)[0]
                half = _kernel_half(k, dtb) if dtb & ADDR else None
                if not half or not present:
                    continue
                same = sum(1 for i in present if half[i] == system[i])
                if same * 2 < len(present):
                    continue
                body_pa = (hdr & ~0xFFF) + b
                seen.add(body_pa)
                out.append(_scanned_process(k, body_pa, link_off, known.get(body_pa)))
                break
    return out


def _scanned_process(k: WinKernel, body_pa: int, link_off: int, va: Optional[int] = None) -> dict:
    try:
        if va is None and (body_pa & 0xFFF) + link_off + 16 <= 0x1000:
            flink, blink = struct.unpack("<QQ", k.phys.read(body_pa + link_off, 16))
            cands = [(flink - link_off) if flink and flink == blink else None]
            if is_kernel_va(flink) and k.readable(flink + 8):
                cands.append(k.u64(flink + 8) - link_off)
            for cand in cands:
                if cand and is_kernel_va(cand) and k.readable(cand) and k.v2p(cand) == body_pa:
                    va = cand
                    break
    except InvalidAddressException:
        pass
    if va is not None:
        info = proc_info(k, k.obj("_EPROCESS", va))
        info["phys"] = body_pa
        return info
    st = k.symtab
    ep = st.struct("_EPROCESS")

    def phys_member(path, size=None):
        try:
            off, t = st.member(ep, path)
        except SymbolError:
            return None
        n = size or t.size
        if (body_pa & 0xFFF) + off + n > 0x1000:
            return None  # crosses into a page whose physical address is unknown without the virtual address
        try:
            data = k.phys.read(body_pa + off, n)
        except InvalidAddressException:
            return None
        return data if size else int.from_bytes(data, "little")

    name = phys_member("ImageFileName", 15)
    return {"va": None, "phys": body_pa, "pid": phys_member("UniqueProcessId"),
            "ppid": phys_member("InheritedFromUniqueProcessId"),
            "name": name.split(b"\x00", 1)[0].decode("latin-1") if name else None,
            "create_time": filetime(phys_member("CreateTime")), "exit_time": filetime(phys_member("ExitTime")),
            "dtb": (phys_member("Pcb.DirectoryTableBase") or 0) & ADDR, "partial": True}
