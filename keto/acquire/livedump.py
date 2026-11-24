"""``acquire --method livedump``: a Windows live kernel memory dump, converted into a .keto sysmem container.

``NtSystemDebugControl(SysDbgGetLiveKernelDump = 37, SYSDBG_LIVEDUMP_CONTROL_V1, 64 bytes)`` is the call
behind Task Manager's "Create live kernel memory dump" (layouts from System Informer's ``phnt/ntexapi.h``;
call pattern from its ``kdump.c``). Windows writes a consistent snapshot through memory mirroring, without a
third-party driver; it needs an elevated process with SeDebugPrivilege. Flags: bit 0 UseDumpStorageStack, bit 1
CompressMemoryPagesData, bit 2 IncludeUserSpaceMemoryPages, bit 3 AbortIfMemoryPressure; AddPagesControl bit 0
HypervisorPages. Keto never sets CompressMemoryPagesData (the pages stay plain) and sets AbortIfMemoryPressure so
a loaded system is not pushed into paging.

The dump is written next to the output, parsed with keto.formats.memimage, and every page it holds is copied into
the container's ``sysmem`` space keyed by physical address. The dump header facts go into
``metadata.memory_image``, the original file's SHA-256 into ``metadata.acquisition.source_digest`` and the
kernel's PDB identity (found in the dump) into ``metadata.windows.kernel``; the temporary .dmp is removed unless
``--keep-dump``. ``acquire --method import --space sysmem`` uses the same conversion for any memory image format
keto.formats.memimage recognises.
"""

from __future__ import annotations

import ctypes
import hashlib
import os
import sys
import time

from keto.framework.exceptions import RequirementError, UnsupportedError

SYSDBG_GET_LIVE_KERNEL_DUMP = 37
CONTROL_VERSION_1 = 1
FLAG_USE_DUMP_STORAGE_STACK, FLAG_COMPRESS, FLAG_INCLUDE_USER, FLAG_ABORT_IF_PRESSURE = 0x1, 0x2, 0x4, 0x8
ADD_HYPERVISOR_PAGES = 0x1
NTSTATUS_TEXT = {0xC0000022: "STATUS_ACCESS_DENIED (run from an elevated prompt)",
                 0xC0000061: "STATUS_PRIVILEGE_NOT_HELD (SeDebugPrivilege could not be enabled: run elevated)",
                 0xC0000002: "STATUS_NOT_IMPLEMENTED (live dumps need Windows 8.1 or later)",
                 0xC00000BB: "STATUS_NOT_SUPPORTED (live dumps disabled on this system)",
                 0xC000009A: "STATUS_INSUFFICIENT_RESOURCES (memory pressure: retry later)",
                 0xC0000120: "STATUS_CANCELLED"}
BLOCK = 16 << 20


class SYSDBG_LIVEDUMP_CONTROL_V1(ctypes.Structure):
    _fields_ = [("Version", ctypes.c_uint32), ("BugCheckCode", ctypes.c_uint32),
                ("BugCheckParam1", ctypes.c_size_t), ("BugCheckParam2", ctypes.c_size_t),
                ("BugCheckParam3", ctypes.c_size_t), ("BugCheckParam4", ctypes.c_size_t),
                ("DumpFileHandle", ctypes.c_void_p), ("CancelEventHandle", ctypes.c_void_p),
                ("Flags", ctypes.c_uint32), ("AddPagesControl", ctypes.c_uint32)]


def control_block(handle: int, include_user: bool = False, hypervisor: bool = False) -> SYSDBG_LIVEDUMP_CONTROL_V1:
    c = SYSDBG_LIVEDUMP_CONTROL_V1()
    c.Version = CONTROL_VERSION_1
    c.DumpFileHandle = handle
    c.Flags = FLAG_ABORT_IF_PRESSURE | (FLAG_INCLUDE_USER if include_user else 0)
    c.AddPagesControl = ADD_HYPERVISOR_PAGES if hypervisor else 0
    return c


def _enable_debug_privilege():
    from ctypes import wintypes
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)

    class LUID(ctypes.Structure):
        _fields_ = [("LowPart", wintypes.DWORD), ("HighPart", wintypes.LONG)]

    class TOKEN_PRIVILEGES(ctypes.Structure):
        _fields_ = [("PrivilegeCount", wintypes.DWORD), ("Luid", LUID), ("Attributes", wintypes.DWORD)]

    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    advapi.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    advapi.LookupPrivilegeValueW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.POINTER(LUID)]
    advapi.AdjustTokenPrivileges.argtypes = [wintypes.HANDLE, wintypes.BOOL, ctypes.POINTER(TOKEN_PRIVILEGES),
                                             wintypes.DWORD, ctypes.c_void_p, ctypes.c_void_p]
    token = wintypes.HANDLE()
    if not advapi.OpenProcessToken(kernel.GetCurrentProcess(), 0x0020 | 0x0008, ctypes.byref(token)):
        raise RequirementError("cannot open the process token (error %d)" % ctypes.get_last_error())
    try:
        tp = TOKEN_PRIVILEGES()
        tp.PrivilegeCount = 1
        tp.Attributes = 0x2  # SE_PRIVILEGE_ENABLED
        if not advapi.LookupPrivilegeValueW(None, "SeDebugPrivilege", ctypes.byref(tp.Luid)):
            raise RequirementError("SeDebugPrivilege lookup failed (error %d)" % ctypes.get_last_error())
        advapi.AdjustTokenPrivileges(token, False, ctypes.byref(tp), 0, None, None)
        if ctypes.get_last_error() == 1300:  # ERROR_NOT_ALL_ASSIGNED
            raise RequirementError("SeDebugPrivilege is not held: run 'keto acquire --method livedump' from an "
                                   "elevated (Administrator) prompt")
    finally:
        kernel.CloseHandle(token)


def take_live_dump(path: str, include_user: bool = False, hypervisor: bool = False) -> None:
    """Write a live kernel dump to ``path`` (which must not exist)."""
    if os.name != "nt":
        raise UnsupportedError("--method livedump uses the Windows live kernel dump facility (Windows 8.1+); on "
                               "Linux use --method kcore")
    from ctypes import wintypes
    _enable_debug_privilege()
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    ntdll = ctypes.WinDLL("ntdll")
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD,
                                   wintypes.DWORD, wintypes.HANDLE]
    ntdll.NtSystemDebugControl.restype = ctypes.c_uint32
    ntdll.NtSystemDebugControl.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p,
                                           ctypes.c_uint32, ctypes.c_void_p]
    handle = kernel.CreateFileW(path, 0xC0000000, 0x7, None, 1, 0x80, None)  # GENERIC_RW, share all, CREATE_NEW
    if handle in (None, ctypes.c_void_p(-1).value):
        raise RequirementError("cannot create %s (error %d)" % (path, ctypes.get_last_error()))
    try:
        ctrl = control_block(handle, include_user, hypervisor)
        status = ntdll.NtSystemDebugControl(SYSDBG_GET_LIVE_KERNEL_DUMP, ctypes.byref(ctrl), ctypes.sizeof(ctrl),
                                            None, 0, None)
    finally:
        kernel.CloseHandle(handle)
    if status != 0:
        try:
            os.unlink(path)
        except OSError:
            pass
        raise RequirementError("live kernel dump failed: NTSTATUS 0x%08X %s" % (status, NTSTATUS_TEXT.get(status, "")))


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(BLOCK), b""):
            h.update(chunk)
    return h.hexdigest()


def dump_to_container(dump_path: str, out: str, metadata: dict, force: bool = False, progress=None):
    """Copy every page of a Windows memory image (crash/live dump, or any format memimage opens) into a .keto
    container's ``sysmem`` space. Returns the closed ContainerWriter."""
    from keto.formats.container import ContainerWriter
    from keto.formats.memimage import open_memory_image
    from keto.winmem.kernel import locate
    from keto.winmem.session import windows_evidence
    layer, fmt = open_memory_image("sysmem", dump_path)
    metadata["memory_image"] = {k: v for k, v in fmt.items()
                                if isinstance(v, (int, str, float, bool, list, dict, type(None)))}
    metadata["acquisition"]["source_digest"] = {"name": os.path.basename(dump_path),
                                                "size": os.path.getsize(dump_path), "sha256": _sha256(dump_path)}
    if windows_evidence(layer, fmt):
        win = metadata.setdefault("windows", {})
        try:
            loc = locate(layer, fmt)
            win["kernel"] = {"pdb": loc.codeview.pdb_name, "key": loc.codeview.key, "base": "0x%x" % loc.base,
                             "dtb": "0x%x" % loc.dtb, "notes": loc.notes}
        except Exception as e:  # recorded, not fatal: the container is still the evidence
            win["kernel"] = {"error": "%s: %s" % (type(e).__name__, e)}
    writer = ContainerWriter(out, metadata, exclusive=not force)
    status = "complete"
    copied = 0
    try:
        for start, length in layer.ranges():
            pos, end = start, start + length
            while pos < end:
                n = min(BLOCK, end - pos)
                writer.append("sysmem", pos, layer.read(pos, n))
                pos += n
                copied += n
                if progress:
                    progress(copied)
    except BaseException as exc:
        status = "incomplete: %s: %s" % (type(exc).__name__, exc)
        raise
    finally:
        metadata["acquisition"]["status"] = status
        metadata["acquisition"]["notes"] = "%d bytes of physical memory copied from %s" % (
            copied, metadata["memory_image"].get("format", "the memory image"))
        writer.metadata = metadata
        writer.close()
        close = getattr(layer, "close", None)
        if close:
            close()
    return writer


def acquire_livedump(args, out, base_metadata: dict) -> int:
    from keto.acquire.cli import report_written
    dump = args.out + ".dmp"
    if os.path.exists(dump):
        raise RequirementError("%s already exists (a previous dump?): move it away first" % dump)
    t0 = time.time()
    out.write("taking a live kernel dump (%s user pages) ...\n" % ("with" if args.include_user_pages else "without"))
    take_live_dump(dump, include_user=args.include_user_pages, hypervisor=args.hypervisor_pages)
    out.write("  %s: %d bytes in %.1fs; converting to %s\n" % (dump, os.path.getsize(dump), time.time() - t0, args.out))
    meta = dict(base_metadata)
    meta["acquisition"]["livedump"] = {"include_user_pages": bool(args.include_user_pages),
                                       "hypervisor_pages": bool(args.hypervisor_pages),
                                       "control_version": CONTROL_VERSION_1}

    step = [256 << 20]

    def progress(n):
        if n >= step[0]:  # one line per 256 MiB, also when stderr is a log file
            sys.stderr.write("  %d MiB copied\n" % (n >> 20))
            sys.stderr.flush()
            step[0] = (n // (256 << 20) + 1) * (256 << 20)

    try:
        writer = dump_to_container(dump, args.out, meta, force=args.force, progress=progress)
    finally:
        if not args.keep_dump and os.path.exists(dump):
            os.unlink(dump)
    kernel = (meta.get("windows") or {}).get("kernel", {"error": "no Windows kernel evidence in the dump"})
    if kernel.get("key"):
        out.write("kernel: %s %s (symbols: keto pdb find --name %s --key %s)\n" % (
            kernel["pdb"], kernel["key"], kernel["pdb"], kernel["key"]))
    else:
        out.write("kernel not located in the dump: %s\n" % kernel.get("error"))
    report_written(out, writer)
    return 0
