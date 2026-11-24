"""Synthetic Windows x64 kernel memory image with ground truth, for tests of keto.winmem and windows.kernel.*.

Builds physical RAM with real 4-level page tables, a low stub, KUSER_SHARED_DATA, an ntoskrnl PE header with an
RSDS record, kernel objects (processes with pool and object headers, modules, handle tables, VADs, the object
directory, drivers) and user pages, plus a Volatility-ISF symbol file describing exactly the layouts used.
Layouts are synthetic (offsets differ from real builds) on purpose: the engine must take every offset from the
symbols. Structures are placed so that some straddle pages backed by non-contiguous physical frames.
"""

from __future__ import annotations

import json
import os
import struct
from typing import Dict, List, Optional, Tuple

PAGE = 0x1000
P, RW, US, A, D, PS = 0x1, 0x2, 0x4, 0x20, 0x40, 0x80
KFLAGS = P | RW | A | D
UFLAGS = P | RW | US | A | D
KUSER = 0xFFFFF78000000000
KBASE = 0xFFFFF80612000000
POOL = 0xFFFF9A8000000000
GUID = "1D2C3B4A5F6E7D8C9BA0B1C2D3E4F506"
AGE = 1
KEY = GUID + "%X" % AGE
SELF_REF_INDEX = 0x1ED
OPT_SIZES = [(0x1, 0x20), (0x2, 0x20), (0x4, 0x10), (0x8, 0x20), (0x10, 0x10), (0x20, 0x10), (0x40, 0x10), (0x80, 0x10)]
COOKIE = 0x5A
TYPE_INDEX = {"Type": 2, "Directory": 3, "Device": 4, "Driver": 5, "File": 6, "Process": 7, "Thread": 8, "Event": 9}
IRP_COUNT = 28

# -- symbol layout (ISF) ------------------------------------------------------------------------------------------
def _b(name):
    return {"kind": "base", "name": name}


def _p(sub=None):
    return {"kind": "pointer", "subtype": sub or _b("void")}


def _s(name):
    return {"kind": "struct", "name": name}


def _u(name):
    return {"kind": "union", "name": name}


def _arr(n, sub):
    return {"kind": "array", "count": n, "subtype": sub}


def _bf(pos, length, base="unsigned long"):
    return {"kind": "bitfield", "bit_position": pos, "bit_length": length, "type": _b(base)}


U8, U16, U32, U64, I64 = _b("unsigned char"), _b("unsigned short"), _b("unsigned long"), _b("unsigned long long"), \
    _b("long long")

STRUCTS = {
    "_LIST_ENTRY": (16, {"Flink": (0, _p(_s("_LIST_ENTRY"))), "Blink": (8, _p(_s("_LIST_ENTRY")))}),
    "_UNICODE_STRING": (16, {"Length": (0, U16), "MaximumLength": (2, U16), "Buffer": (8, _p(_b("wchar")))}),
    "_DISPATCHER_HEADER": (0x18, {"Type": (0, U8), "Signalling": (1, U8), "Size": (2, U8)}),
    "_KPROCESS": (0x440, {"Header": (0, _s("_DISPATCHER_HEADER")), "DirectoryTableBase": (0x28, U64)}),
    "_SE_AUDIT_PROCESS_CREATION_INFO": (8, {"ImageFileName": (0, _p(_s("_OBJECT_NAME_INFORMATION")))}),
    "_OBJECT_NAME_INFORMATION": (16, {"Name": (0, _s("_UNICODE_STRING"))}),
    "_RTL_AVL_TREE": (8, {"Root": (0, _p(_s("_RTL_BALANCED_NODE")))}),
    "_RTL_BALANCED_NODE": (0x18, {"Left": (0, _p(_s("_RTL_BALANCED_NODE"))),
                                  "Right": (8, _p(_s("_RTL_BALANCED_NODE"))), "ParentValue": (0x10, U64)}),
    "_PS_PROTECTION": (1, {"Level": (0, U8)}),
    "_MM_SESSION_SPACE": (0x40, {"SessionId": (8, U32)}),
    "_EPROCESS": (0xB80, {
        "Pcb": (0, _s("_KPROCESS")), "UniqueProcessId": (0x440, _p()), "ActiveProcessLinks": (0x448, _s("_LIST_ENTRY")),
        "CreateTime": (0x468, _u("_LARGE_INTEGER")), "Session": (0x470, _p()), "InheritedFromUniqueProcessId": (0x540, _p()),
        "Peb": (0x550, _p(_s("_PEB"))), "ObjectTable": (0x570, _p(_s("_HANDLE_TABLE"))), "Win32Process": (0x578, _p()),
        "WoW64Process": (0x580, _p()), "ImageFileName": (0x5A8, _arr(15, U8)),
        "SeAuditProcessCreationInfo": (0x5C0, _s("_SE_AUDIT_PROCESS_CREATION_INFO")), "ActiveThreads": (0x5F0, U32),
        "ExitTime": (0x600, _u("_LARGE_INTEGER")), "VadRoot": (0x7D8, _s("_RTL_AVL_TREE")), "DxgProcess": (0x7E0, _p()),
        "Protection": (0x87A, _s("_PS_PROTECTION"))}),
    "_KLDR_DATA_TABLE_ENTRY": (0xA0, {"InLoadOrderLinks": (0, _s("_LIST_ENTRY")), "DllBase": (0x30, _p()),
                                      "SizeOfImage": (0x40, U32), "FullDllName": (0x48, _s("_UNICODE_STRING")),
                                      "BaseDllName": (0x58, _s("_UNICODE_STRING"))}),
    "_HANDLE_TABLE": (0x80, {"NextHandleNeedingPool": (0, U32), "TableCode": (8, U64)}),
    "_OBJECT_HEADER": (0x38, {"PointerCount": (0, I64), "HandleCount": (8, I64), "TypeIndex": (0x18, U8),
                              "InfoMask": (0x1A, U8), "Body": (0x30, U64)}),
    "_OBJECT_HEADER_NAME_INFO": (0x20, {"Directory": (0, _p(_s("_OBJECT_DIRECTORY"))),
                                        "Name": (8, _s("_UNICODE_STRING"))}),
    "_OBJECT_TYPE": (0xD8, {"TypeList": (0, _s("_LIST_ENTRY")), "Name": (0x10, _s("_UNICODE_STRING")), "Index": (0x28, U8)}),
    "_FILE_OBJECT": (0xD8, {"Type": (0, U16), "DeviceObject": (8, _p()), "FileName": (0x58, _s("_UNICODE_STRING"))}),
    "_DEVICE_OBJECT": (0x150, {"Type": (0, U16)}),
    "_DRIVER_OBJECT": (0x150, {"Type": (0, U16), "DriverStart": (0x18, _p()), "DriverSize": (0x20, U32),
                               "DriverName": (0x38, _s("_UNICODE_STRING")), "MajorFunction": (0x70, _arr(IRP_COUNT, _p()))}),
    "_OBJECT_DIRECTORY": (0x158, {"HashBuckets": (0, _arr(37, _p(_s("_OBJECT_DIRECTORY_ENTRY"))))}),
    "_OBJECT_DIRECTORY_ENTRY": (0x18, {"ChainLink": (0, _p(_s("_OBJECT_DIRECTORY_ENTRY"))), "Object": (8, _p()),
                                       "HashValue": (0x10, U32)}),
    "_MMVAD_FLAGS": (4, {"VadType": (0, _bf(4, 3)), "Protection": (0, _bf(7, 5)), "PrivateMemory": (0, _bf(21, 1))}),
    "_MMVAD_SHORT": (0x40, {"VadNode": (0, _s("_RTL_BALANCED_NODE")), "StartingVpn": (0x18, U32), "EndingVpn": (0x1C, U32),
                            "StartingVpnHigh": (0x20, U8), "EndingVpnHigh": (0x21, U8), "u": (0x30, _u("__unnamed_vadflags"))}),
    "_MMVAD": (0x88, {"Core": (0, _s("_MMVAD_SHORT")), "Subsection": (0x48, _p(_s("_SUBSECTION")))}),
    "_SUBSECTION": (0x38, {"ControlArea": (0, _p(_s("_CONTROL_AREA")))}),
    "_CONTROL_AREA": (0x80, {"FilePointer": (0x40, _u("_EX_FAST_REF"))}),
    "_PEB": (0x7D8, {"Ldr": (0x18, _p()), "ProcessParameters": (0x20, _p(_s("_RTL_USER_PROCESS_PARAMETERS")))}),
    "_RTL_USER_PROCESS_PARAMETERS": (0x440, {"ImagePathName": (0x60, _s("_UNICODE_STRING")),
                                             "CommandLine": (0x70, _s("_UNICODE_STRING")), "Environment": (0x80, _p()),
                                             "EnvironmentSize": (0x3F0, U64)}),
    "_CLIENT_ID": (16, {"UniqueProcess": (0, _p()), "UniqueThread": (8, _p())}),
    "_ETHREAD": (0x500, {"Cid": (0x478, _s("_CLIENT_ID"))}),
}
UNIONS = {
    "_LARGE_INTEGER": (8, {"QuadPart": (0, I64), "LowPart": (0, U32)}),
    "_HANDLE_TABLE_ENTRY": (16, {"LowValue": (0, I64), "ObjectPointerBits": (0, _bf(20, 44, "unsigned long long")),
                                 "GrantedAccessBits": (8, _bf(0, 25))}),
    "_EX_FAST_REF": (8, {"Object": (0, _p()), "RefCnt": (0, _bf(0, 4, "unsigned long long")), "Value": (0, U64)}),
    "__unnamed_vadflags": (4, {"LongFlags": (0, U32), "VadFlags": (0, _s("_MMVAD_FLAGS"))}),
}
SYMBOL_RVAS = {"PsActiveProcessHead": 0x150000, "PsLoadedModuleList": 0x150010, "ObHeaderCookie": 0x150020,
               "ObTypeIndexTable": 0x150100, "ObpInfoMaskToOffset": 0x150200, "ObpRootDirectoryObject": 0x150300,
               "NtBuildNumber": 0x150308, "KeNumberProcessors": 0x15030C, "NtBuildLab": 0x150400,
               "PsInitialSystemProcess": 0x150500, "PsProcessType": 0x150508, "IoFileObjectType": 0x150510,
               "IoDeviceObjectType": 0x150518, "IoDriverObjectType": 0x150520, "PsThreadType": 0x150528}
EXPORT_DATA = ("PsLoadedModuleList", "NtBuildNumber", "NtBuildLab", "KeNumberProcessors", "PsInitialSystemProcess",
               "PsProcessType", "IoFileObjectType", "IoDeviceObjectType", "IoDriverObjectType", "PsThreadType")
TYPE_EXPORTS = {"PsProcessType": "Process", "IoFileObjectType": "File", "IoDeviceObjectType": "Device",
                "IoDriverObjectType": "Driver", "PsThreadType": "Thread"}


def _code(prefix_hex: str, disp: int, tail_hex: str = "c3") -> bytes:
    return bytes.fromhex(prefix_hex) + struct.pack("<i", disp) + bytes.fromhex(tail_hex)


MOV_RAX = "488b81"  # mov rax, [rcx+disp32]
#: accessor stubs as the real ntoskrnl compiles them: the first instruction reads the member through rcx
ACCESSOR_CODE = {
    "PsGetProcessId": _code(MOV_RAX, 0x440),
    "PsGetProcessImageFileName": _code("488d81", 0x5A8),  # lea rax, [rcx+disp32]
    "PsGetProcessPeb": _code(MOV_RAX, 0x550),
    "PsGetProcessInheritedFromUniqueProcessId": _code(MOV_RAX, 0x540),
    "PsGetProcessCreateTimeQuadPart": _code(MOV_RAX, 0x468),
    "PsGetProcessExitTime": _code(MOV_RAX, 0x600),
    "PsGetProcessDxgProcess": _code(MOV_RAX, 0x7E0),
    "PsGetProcessWin32Process": _code(MOV_RAX, 0x578),
    "PsGetProcessWow64Process": _code(MOV_RAX, 0x580, "4885c07403488b00c3"),  # test; je; mov rax,[rax]; ret
    "PsGetProcessProtection": _code("0fb681", 0x87A),  # movzx eax, byte ptr [rcx+disp32]
    "PsGetProcessSessionId": _code(MOV_RAX, 0x470, "4885c074048b4008c333c0c3"),  # ...; mov eax,[rax+8]; ret
    "PsGetThreadId": _code(MOV_RAX, 0x480),
}
THUNKED = "PsGetProcessDxgProcess"  # exported as a jmp thunk, as some builds do


def isf_document() -> dict:
    base = {"unsigned char": (1, False), "unsigned short": (2, False), "unsigned long": (4, False),
            "unsigned long long": (8, False), "long long": (8, True), "wchar": (2, False), "void": (0, False),
            "pointer": (8, False)}
    doc = {"metadata": {"format": "6.2.0", "windows": {"pdb": {"GUID": GUID, "age": AGE, "database": "ntkrnlmp.pdb",
                                                              "machine_type": 0x8664}}},
           "base_types": {n: {"size": s, "signed": sg, "kind": "void" if n == "void" else "int", "endian": "little"}
                          for n, (s, sg) in base.items()},
           "user_types": {}, "enums": {},
           "symbols": {n: {"address": rva} for n, rva in SYMBOL_RVAS.items()}}
    for kind, table in (("struct", STRUCTS), ("union", UNIONS)):
        for name, (size, fields) in table.items():
            doc["user_types"][name] = {"kind": kind, "size": size,
                                       "fields": {f: {"offset": o, "type": t} for f, (o, t) in fields.items()}}
    return doc


def off(struct_name: str, field: str) -> int:
    table = STRUCTS if struct_name in STRUCTS else UNIONS
    return table[struct_name][1][field][0]


def _filetime(year: int, month: int, day: int) -> int:
    import datetime
    return int((datetime.datetime(year, month, day) - datetime.datetime(1601, 1, 1)).total_seconds() * 10 ** 7)


# -- the image ---------------------------------------------------------------------------------------------------
class Builder:
    def __init__(self, size: int = 48 << 20):
        self.mem = bytearray(size)
        self.next_frame = 0x200000  # frames handed out from 2 MiB up; the first MiB holds the low stub
        self.kdtb = self.frame()
        self.kva = POOL
        self.truth: Dict[str, object] = {}

    # physical frames and page tables
    def frame(self) -> int:
        pa = self.next_frame
        self.next_frame += PAGE
        if self.next_frame > len(self.mem):
            raise MemoryError("synthetic image too small")
        return pa

    def q(self, pa: int, value: Optional[int] = None) -> int:
        if value is None:
            return struct.unpack_from("<Q", self.mem, pa)[0]
        struct.pack_into("<Q", self.mem, pa, value)
        return value

    def pte_slot(self, dtb: int, va: int, flags: int) -> int:
        table = dtb
        for sh in (39, 30, 21):
            slot = table + ((va >> sh) & 0x1FF) * 8
            e = self.q(slot)
            if not e & P:
                e = self.q(slot, self.frame() | (flags & (P | RW | US)) | A)
            table = e & 0x000FFFFFFFFFF000
        return table + ((va >> 12) & 0x1FF) * 8

    def map(self, dtb: int, va: int, pa: Optional[int] = None, flags: int = KFLAGS) -> int:
        if pa is None:
            pa = self.frame()
            self.frame()  # leave a gap: consecutive virtual pages are never physically contiguous
        self.q(self.pte_slot(dtb, va, flags), pa | flags)
        return pa

    def pa_of(self, dtb: int, va: int) -> Optional[int]:
        table = dtb
        for sh in (39, 30, 21, 12):
            e = self.q(table + ((va >> sh) & 0x1FF) * 8)
            if not e & P:
                return None
            table = e & 0x000FFFFFFFFFF000
        return table | (va & 0xFFF)

    def write(self, dtb: int, va: int, data: bytes, flags: int = KFLAGS):
        pos = 0
        while pos < len(data):
            cur = va + pos
            pa = self.pa_of(dtb, cur)
            if pa is None:
                self.map(dtb, cur & ~0xFFF, flags=flags)
                pa = self.pa_of(dtb, cur)
            take = min(len(data) - pos, PAGE - (cur & 0xFFF))
            self.mem[pa:pa + take] = data[pos:pos + take]
            pos += take

    def kwrite(self, va, data):
        self.write(self.kdtb, va, data)

    def kq(self, va, value):
        self.kwrite(va, struct.pack("<Q", value))

    def kalloc(self, size: int, align: int = 16) -> int:
        self.kva = (self.kva + align - 1) & ~(align - 1)
        va = self.kva
        self.kva += size
        self.kwrite(va, bytes(size))  # maps fresh, non-contiguous frames as it goes
        return va

    def kstring(self, text: str) -> Tuple[int, int]:
        raw = text.encode("utf-16-le")
        va = self.kalloc(len(raw) + 2)
        self.kwrite(va, raw)
        return va, len(raw)

    def unicode_at(self, va: int, text: str, dtb: Optional[int] = None, buf: Optional[int] = None):
        raw = text.encode("utf-16-le")
        if buf is None:
            buf, _ = self.kstring(text)
        self.write(dtb or self.kdtb, va, struct.pack("<HHIQ", len(raw), len(raw) + 2, 0, buf))

    # kernel objects
    def object(self, type_name: str, body_size: int, name: Optional[str] = None, directory: int = 0,
               pool_tag: Optional[bytes] = None, pad: int = 0) -> int:
        """Pool header + optional name info + object header + body; returns the body address."""
        mask = 0x2 if name is not None else 0
        opt = 0x20 if name is not None else 0
        total = 16 + pad + opt + 0x30 + body_size
        alloc = self.kalloc((total + 15) & ~15, align=16)
        if pool_tag:
            self.kwrite(alloc, struct.pack("<I4sQ", (((total + 15) // 16) & 0xFF) << 16, pool_tag, 0))
        hdr = alloc + 16 + pad + opt
        if name is not None:
            ni = hdr - 0x20
            self.kq(ni, directory)
            self.unicode_at(ni + 8, name)
        encoded = TYPE_INDEX[type_name] ^ COOKIE ^ ((hdr >> 8) & 0xFF)
        self.kwrite(hdr + 0x18, bytes([encoded, 0, mask]))
        return hdr + 0x30


def build(out_dir: str, size: int = 48 << 20) -> dict:
    """Write ``win.raw`` and ``symbols/windows/ntkrnlmp.pdb/<KEY>.json`` into ``out_dir``; returns ground truth."""
    b = Builder(size)
    kd = b.kdtb
    # pre-create the kernel-half PML4 entries so process address spaces can share them by copy
    for va in (POOL, KBASE, KUSER, 0xFFFFF80700000000):
        b.pte_slot(kd, va, KFLAGS)
    b.q(kd + SELF_REF_INDEX * 8, kd | KFLAGS | (1 << 63))
    # KUSER_SHARED_DATA
    ks = bytearray(PAGE)
    root = "C:\\Windows".encode("utf-16-le")
    ks[0x30:0x30 + len(root)] = root
    struct.pack_into("<III", ks, 0x260, 26100, 1, 0)
    struct.pack_into("<II", ks, 0x26C, 10, 0)
    b.kwrite(KUSER, bytes(ks))
    # ntoskrnl image: PE header with RSDS, symbols in a data area
    hdr = bytearray(PAGE)
    hdr[0:2] = b"MZ"
    struct.pack_into("<I", hdr, 0x3C, 0x80)
    hdr[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into("<HHIIIHH", hdr, 0x84, 0x8664, 1, 0x5F5E1000, 0, 0, 0xF0, 0x22)
    opt = 0x98
    struct.pack_into("<H", hdr, opt, 0x20B)
    struct.pack_into("<Q", hdr, opt + 24, KBASE)
    struct.pack_into("<I", hdr, opt + 56, 0x200000)
    struct.pack_into("<I", hdr, opt + 108, 16)
    struct.pack_into("<II", hdr, opt + 112 + 6 * 8, 0x400, 28)
    struct.pack_into("<II", hdr, opt + 112, 0x2000, 0x1000)  # export directory
    struct.pack_into("<8sIIII", hdr, opt + 0xF0, b".text", 0x1FF000, 0x1000, 0x1FF000, 0x1000)
    struct.pack_into("<IIHHIIII", hdr, 0x400, 0, 0, 0, 0, 2, 24 + 13, 0x500, 0)
    guid = bytes.fromhex(GUID)
    raw_guid = struct.pack("<IHH", int(GUID[0:8], 16), int(GUID[8:12], 16), int(GUID[12:16], 16)) + guid[8:16]
    hdr[0x500:0x500 + 24 + 13] = b"RSDS" + raw_guid + struct.pack("<I", AGE) + b"ntkrnlmp.pdb\x00"
    b.kwrite(KBASE, bytes(hdr))
    sym = {n: KBASE + rva for n, rva in SYMBOL_RVAS.items()}
    _exports(b)
    b.kwrite(sym["ObHeaderCookie"], bytes([COOKIE]))
    b.kwrite(sym["NtBuildNumber"], struct.pack("<I", 0xF0000000 | 26100))
    b.kwrite(sym["KeNumberProcessors"], struct.pack("<I", 8))
    b.kwrite(sym["NtBuildLab"], b"26100.1.amd64fre.synthetic\x00")
    table = bytearray(256)
    for m in range(256):
        table[m] = sum(size for bit, size in OPT_SIZES if m & bit)
    b.kwrite(sym["ObpInfoMaskToOffset"], bytes(table))
    # low stub (first MiB): jmp + mode words, LmTarget inside ntoskrnl, CR3
    stub = 0x13000
    struct.pack_into("<Q", b.mem, stub, 0x00000001000600E9 | 0x1200)
    struct.pack_into("<Q", b.mem, stub + 0x70, KBASE + 0x5A20)
    struct.pack_into("<Q", b.mem, stub + 0xA0, kd)
    b.kwrite(KBASE + 0x5000, b"\xCC" * 0x40)  # the page LmTarget points into

    # object directory: \ , \Device, \Driver
    def directory(name, parent):
        body = b.object("Directory", 0x158, name=name, directory=parent)
        return body

    root_dir = directory("\\", 0)
    b.kq(sym["ObpRootDirectoryObject"], root_dir)
    dev_dir = directory("Device", root_dir)
    drv_dir = directory("Driver", root_dir)
    types_dir = directory("ObjectTypes", root_dir)
    buckets: Dict[int, List[int]] = {}

    def link(dir_body, obj_body, slot):
        e = b.kalloc(0x18)
        head = dir_body + 8 * slot
        b.kq(e, b.q(b.pa_of(kd, head)))  # push on the chain
        b.kq(e + 8, obj_body)
        b.kq(head, e)
        buckets.setdefault(dir_body, []).append(obj_body)

    link(root_dir, dev_dir, 3)
    link(root_dir, drv_dir, 11)
    link(root_dir, types_dir, 17)
    type_objects = {}
    for tname, idx in TYPE_INDEX.items():
        t = b.object("Type", 0xD8, name=tname, directory=types_dir)
        b.unicode_at(t + 0x10, tname)
        b.kwrite(t + 0x28, bytes([idx]))
        b.kq(sym["ObTypeIndexTable"] + 8 * idx, t)
        link(types_dir, t, idx)
        type_objects[tname] = t
    for export, tname in TYPE_EXPORTS.items():
        b.kq(sym[export], type_objects[tname])
    dxg_dev = b.object("Device", 0x150, name="DxgKrnl", directory=dev_dir)
    vol_dev = b.object("Device", 0x150, name="HarddiskVolume3", directory=dev_dir)
    link(dev_dir, dxg_dev, 5)
    link(dev_dir, vol_dev, 5)  # same bucket: exercises the chain

    # modules: ntoskrnl, dxgkrnl, nvlddmkm, a rogue driver, the KMDF framework and a KMDF client
    mods = [("ntoskrnl.exe", KBASE, 0x200000), ("dxgkrnl.sys", 0xFFFFF80700000000, 0x400000),
            ("nvlddmkm.sys", 0xFFFFF80700400000, 0x1000000), ("evil.sys", 0xFFFFF80701400000, 0x10000),
            ("Wdf01000.sys", 0xFFFFF80701500000, 0x100000), ("HidUsb.sys", 0xFFFFF80701600000, 0x10000)]
    head = sym["PsLoadedModuleList"]
    entries = []
    for name, base, size in mods:
        e = b.kalloc(0xA0)
        b.kq(e + 0x30, base)
        b.kwrite(e + 0x40, struct.pack("<I", size))
        b.unicode_at(e + 0x48, "\\SystemRoot\\system32\\drivers\\" + name if name != "ntoskrnl.exe"
                     else "\\SystemRoot\\system32\\ntoskrnl.exe")
        b.unicode_at(e + 0x58, name)
        entries.append(e)
    _chain(b, head, entries, 0)
    for _name, base, _size in mods[1:]:
        b.kwrite(base, b"MZ")  # resident header page without a CodeView record

    # drivers: nvlddmkm with one hooked dispatch entry, Null wholly in ntoskrnl
    def driver(name, start, size, targets):
        body = b.object("Driver", 0x150, name=name, directory=drv_dir)
        b.kq(body + 0x18, start)
        b.kwrite(body + 0x20, struct.pack("<I", size))
        b.unicode_at(body + 0x38, "\\Driver\\" + name)
        for i, t in enumerate(targets):
            b.kq(body + 0x70 + 8 * i, t)
        link(drv_dir, body, (len(name) * 7) % 37)
        return body

    nv_targets = [0xFFFFF80700400000 + 0x1000 + i * 0x40 for i in range(IRP_COUNT)]
    nv_targets[14] = 0xFFFFF80701400000 + 0x2340  # IRP_MJ_DEVICE_CONTROL -> evil.sys
    driver("nvlddmkm", 0xFFFFF80700400000, 0x1000000, nv_targets)
    null_targets = [KBASE + 0x9000] * IRP_COUNT
    null_targets[0] = POOL + 0x7F000  # IRP_MJ_CREATE -> pool memory: no module (unbacked code)
    driver("Null", 0xFFFFF80700A00000, 0x8000, null_targets)
    driver("HidUsb", 0xFFFFF80701600000, 0x10000, [0xFFFFF80701500000 + 0x4000 + 8 * i for i in range(IRP_COUNT)])

    # processes
    created = _filetime(2026, 11, 20)
    procs = []

    def process(pid, ppid, name, path=None, dxg=0, linked=True, exited=None, env=None, files=(), handles=(),
                private_blob=None, page_offset=None):
        if page_offset is not None:  # place the pool header at this offset of a fresh page
            b.kva = ((b.kva + 0xFFF) & ~0xFFF) + page_offset
        body = b.object("Process", 0xB80, pool_tag=b"Proc")
        dtb = b.frame()
        for i in range(256, 512):  # kernel half shared with the system address space
            b.q(dtb + 8 * i, b.q(kd + 8 * i))
        b.kwrite(body, bytes([3, 0, (0x440 // 4) & 0xFF, 0]))  # ProcessObject; Size truncated to a UCHAR
        b.kq(body + 0x28, dtb | 0x2)  # PCID-style low bits are ignored by the engine
        b.kq(body + 0x440, pid)
        b.kq(body + 0x540, ppid)
        b.kwrite(body + 0x5A8, name.encode("ascii")[:14] + b"\x00")
        b.kq(body + 0x468, created + pid)
        if exited:
            b.kq(body + 0x600, exited)
        b.kwrite(body + 0x5F0, struct.pack("<I", 3))
        b.kq(body + 0x7E0, dxg)
        if path:
            raw = path.encode("utf-16-le")
            oni = b.kalloc(16 + len(raw) + 2)
            b.unicode_at(oni, path, buf=oni + 16)
            b.kwrite(oni + 16, raw)
            b.kq(body + 0x5C0, oni)
        sess = b.kalloc(0x40)
        b.kwrite(sess + 8, struct.pack("<I", 1 if pid > 4 else 0))
        b.kq(body + 0x470, sess)
        if env is not None:
            _user_env(b, body, dtb, env)
        _vads(b, body, dtb, files, private_blob)
        if handles:
            _handles(b, body, handles, pid)
        procs.append({"pid": pid, "ppid": ppid, "name": name, "body": body, "dtb": dtb, "linked": linked,
                      "exited": exited, "dxg": dxg})
        return body

    dll = "\\Windows\\System32\\nvcuda64.dll"
    process(4, 0, "System")
    process(1200, 1100, "explorer.exe", "\\Device\\HarddiskVolume3\\Windows\\explorer.exe", dxg=0xFFFF9A80DEAD0000,
            env={"PATH": "C:\\Windows"}, files=["\\Windows\\System32\\d3d12.dll"],
            handles=[("file", dxg_dev, "")])
    process(5000, 1200, "python.exe", "\\Device\\HarddiskVolume3\\Python\\python.exe", dxg=0xFFFF9A80BEEF0000,
            env={"CUDA_INJECTION64_PATH": "C:\\Users\\u\\AppData\\Local\\Temp\\hook.dll", "PATH": "C:\\Python"},
            files=[dll], handles=[("file", dxg_dev, ""),
                                  ("file", vol_dev, "\\Windows\\System32\\DriverStore\\FileRepository\\"
                                                    "nvlt.inf_amd64_1234\\nvcubins.bin")],
            private_blob=b".version 8.0\n.target sm_89\n.address_size 64\n.visible .entry steal_kernel(\n)\n{\nret;\n}\n",
            page_offset=0xE00)  # body at +0xE40: most members live on the next, non-contiguous frame
    process(3300, 1200, "miner.exe", "\\Device\\HarddiskVolume3\\Users\\u\\AppData\\Roaming\\miner.exe",
            dxg=0xFFFF9A80CAFE0000, linked=False, files=["\\Users\\u\\AppData\\Roaming\\x\\nvcuda64.dll"],
            page_offset=0x100)
    process(6100, 1200, "gone.exe", linked=False, exited=_filetime(2026, 11, 21), page_offset=0)
    b.kq(sym["PsInitialSystemProcess"], procs[0]["body"])
    linked = [p for p in procs if p["linked"]]
    _chain(b, sym["PsActiveProcessHead"], [p["body"] + 0x448 for p in linked], 0)
    for p in procs:
        if p["name"] == "miner.exe":  # DKOM: unlinked, links point at itself
            b.kq(p["body"] + 0x448, p["body"] + 0x448)
            b.kq(p["body"] + 0x450, p["body"] + 0x448)
    os.makedirs(out_dir, exist_ok=True)
    img = os.path.join(out_dir, "win.raw")
    with open(img, "wb") as fh:
        fh.write(b.mem[:b.next_frame + PAGE])
    sym_dir = os.path.join(out_dir, "symbols")
    folder = os.path.join(sym_dir, "windows", "ntkrnlmp.pdb")
    os.makedirs(folder, exist_ok=True)
    with open(os.path.join(folder, KEY + ".json"), "w", encoding="utf-8") as fh:
        json.dump(isf_document(), fh)
    return {"image": img, "symbols_dir": sym_dir, "dtb": kd, "kernel_base": KBASE, "low_stub_pa": stub,
            "processes": procs, "modules": mods, "symbols": sym, "dxg_device": dxg_dev}


def _chain(b: Builder, head: int, nodes: List[int], link_off: int):
    """Circular doubly linked _LIST_ENTRY list: ``nodes`` are the addresses of the embedded list entries."""
    seq = [head] + [n + link_off for n in nodes]
    for i, cur in enumerate(seq):
        b.kq(cur, seq[(i + 1) % len(seq)])
        b.kq(cur + 8, seq[i - 1])


def _user_env(b: Builder, body: int, dtb: int, env: Dict[str, str]):
    peb, params, block = 0x7FF6A0000000, 0x7FF6A0010000, 0x7FF6A0020000
    data = "".join("%s=%s\x00" % kv for kv in env.items()).encode("utf-16-le") + b"\x00\x00"
    b.write(dtb, block, data, UFLAGS)
    pp = bytearray(0x440)
    struct.pack_into("<Q", pp, 0x80, block)
    struct.pack_into("<Q", pp, 0x3F0, len(data))
    b.write(dtb, params, bytes(pp), UFLAGS)
    pb = bytearray(0x40)
    struct.pack_into("<Q", pb, 0x20, params)
    b.write(dtb, peb, bytes(pb), UFLAGS)
    b.kq(body + 0x550, peb)


def _vads(b: Builder, body: int, dtb: int, files, private_blob):
    nodes = []
    base = 0x7FFB00000000
    for i, f in enumerate(files):
        start = base + i * 0x100000
        fo = b.object("File", 0xD8)
        b.unicode_at(fo + 0x58, f)
        ca = b.kalloc(0x80)
        b.kq(ca + 0x40, fo | 0x7)  # _EX_FAST_REF with a reference count in the low bits
        sub = b.kalloc(0x38)
        b.kq(sub, ca)
        vad = b.kalloc(0x88)
        b.kwrite(vad + 0x18, struct.pack("<II", (start >> 12) & 0xFFFFFFFF, ((start + 0x3FFFF) >> 12) & 0xFFFFFFFF))
        b.kwrite(vad + 0x20, bytes([start >> 44, (start + 0x3FFFF) >> 44]))
        b.kwrite(vad + 0x30, struct.pack("<I", (2 << 4) | (7 << 7)))  # image map, EXECUTE_WRITECOPY, not private
        b.kq(vad + 0x48, sub)
        b.write(dtb, start, b"MZ" + bytes(PAGE - 2), UFLAGS)
        nodes.append((start, vad))
    if private_blob is not None:
        start = 0x1F0000000
        vad = b.kalloc(0x88)
        b.kwrite(vad + 0x18, struct.pack("<II", start >> 12, (start + 0x3FFF) >> 12))
        b.kwrite(vad + 0x30, struct.pack("<I", (4 << 7) | (1 << 21)))  # READWRITE, private (22H2+ layout)
        b.write(dtb, start, private_blob.ljust(PAGE, b"\x00"), UFLAGS)
        trans = b.frame()  # second page: on the standby list (transition PTE)
        b.mem[trans:trans + 16] = b"TRANSITION-PAGE!"
        b.q(b.pte_slot(dtb, start + PAGE, UFLAGS), trans | 0x800)
        b.q(b.pte_slot(dtb, start + 2 * PAGE, UFLAGS), (0x1234 << 32) | 0x80)  # page file
        b.q(b.pte_slot(dtb, start + 3 * PAGE, UFLAGS), 0xFFFFA00000001000 | 0x400)  # prototype
        nodes.append((start, vad))
    elif files:  # a thread stack: private, never touched
        start = 0x0A0000000
        vad = b.kalloc(0x88)
        b.kwrite(vad + 0x18, struct.pack("<II", start >> 12, (start + 0xFFFFF) >> 12))
        b.kwrite(vad + 0x30, struct.pack("<I", (4 << 7) | (1 << 21)))
        nodes.append((start, vad))
    if not nodes:
        return
    # a balanced binary search tree ordered by start, children pointing back through ParentValue (balance bits 0)
    order = [v for _s, v in sorted(nodes)]

    def subtree(lo, hi, parent):
        if lo >= hi:
            return 0
        mid = (lo + hi) // 2
        node = order[mid]
        b.kq(node + 0x10, parent)
        b.kq(node, subtree(lo, mid, node))
        b.kq(node + 8, subtree(mid + 1, hi, node))
        return node

    b.kq(body + 0x7D8, subtree(0, len(order), 0))


def _handles(b: Builder, body: int, handles, pid: int):
    table = b.kalloc(0x80)
    page = b.kalloc(PAGE, align=PAGE)
    for i, (kind, dev, fname) in enumerate(handles, start=1):
        fo = b.object("File", 0xD8)
        b.kq(fo + 8, dev)
        if fname:
            b.unicode_at(fo + 0x58, fname)
        hdr = fo - 0x30
        low = ((hdr & 0x0000FFFFFFFFFFF0) >> 4) << 20 | 1
        b.kwrite(page + 16 * i, struct.pack("<QQ", low, 0x0012019F))
    b.kwrite(table, struct.pack("<I", (len(handles) + 1) * 4))
    b.kq(table + 8, page)
    b.kq(table + 0x10, body)  # QuotaProcess
    b.kq(table + 0x28, pid)  # UniqueProcessId
    b.kq(body + 0x570, table)


def _exports(b: Builder):
    """Export directory at RVA 0x2000 (names, ordinals, function RVAs) and accessor code at RVA 0x3000."""
    names = sorted(list(ACCESSOR_CODE) + list(EXPORT_DATA))
    code_rva, code = 0x3000, bytearray()
    rvas = {}
    for name in sorted(ACCESSOR_CODE):
        rvas[name] = code_rva + len(code)
        code += ACCESSOR_CODE[name].ljust(32, bytes.fromhex("cc"))  # int3 padding
    real = rvas[THUNKED]
    rvas[THUNKED] = code_rva + len(code)
    code += (bytes.fromhex("e9") + struct.pack("<i", real - (rvas[THUNKED] + 5))).ljust(16, bytes.fromhex("cc"))
    for name in EXPORT_DATA:
        rvas[name] = SYMBOL_RVAS[name]
    n = len(names)
    d = 0x2000
    funcs, name_ptrs, ords, strings = d + 40, d + 40 + 4 * n, d + 40 + 8 * n, d + 40 + 10 * n
    blob = bytearray(0x1000)
    struct.pack_into("<IIHHIIIIIII", blob, 0, 0, 0, 0, 0, 0, 1, n, n, funcs, name_ptrs, ords)
    pos = strings
    for i, name in enumerate(names):
        struct.pack_into("<I", blob, funcs - d + 4 * i, rvas[name])
        struct.pack_into("<I", blob, name_ptrs - d + 4 * i, pos)
        struct.pack_into("<H", blob, ords - d + 2 * i, i)
        raw = name.encode() + bytes(1)
        blob[pos - d:pos - d + len(raw)] = raw
        pos += len(raw)
    b.kwrite(KBASE + d, bytes(blob))
    b.kwrite(KBASE + code_rva, bytes(code))
