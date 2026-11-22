"""Windows live data through ctypes (stdlib only): processes, loaded modules, visible windows and per-process
GPU use from the performance counters the Windows graphics kernel publishes.

* Processes / modules: ``CreateToolhelp32Snapshot`` (TH32CS_SNAPPROCESS, TH32CS_SNAPMODULE|SNAPMODULE32),
  ``QueryFullProcessImageNameW``.
* Windows: ``EnumWindows`` + ``GetWindowThreadProcessId`` + ``IsWindowVisible``.
* GPU use: PDH counters ``\\GPU Engine(*)\\Utilization Percentage`` (instances
  ``pid_<pid>_luid_<hi>_<lo>_phys_<n>_eng_<n>_engtype_<type>``) and
  ``\\GPU Process Memory(*)\\Dedicated Usage`` / ``Shared Usage`` (instances ``pid_<pid>_luid_..._phys_<n>``).
* PEB: command line, environment block, ImagePathName (``NtQueryInformationProcess`` + ``ReadProcessMemory``);
  ProcessDebugPort; process memory (``VirtualQueryEx`` / ``ReadProcessMemory``).
* Registry keys (``winreg``), loaded kernel drivers (``SystemModuleInformation``), file version resources,
  Authenticode (``WinVerifyTrust``).

Everything is read-only. Functions return plain JSON-serialisable data so a RecordingSource can snapshot it.
"""

from __future__ import annotations

import ctypes
import os
import re
import time
from ctypes import wintypes
from typing import Dict, List, Optional, Tuple

from keto.live import gpuhandles

TH32CS_SNAPPROCESS, TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32 = 0x2, 0x8, 0x10
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
PDH_FMT_DOUBLE, PDH_FMT_LARGE = 0x200, 0x400
PDH_MORE_DATA = 0x800007D2
ENGINE_RE = re.compile(r"pid_(\d+)_luid_(0x[0-9A-Fa-f]+)_(0x[0-9A-Fa-f]+)_phys_(\d+)_eng_(\d+)_engtype_(.*)$")
PROCMEM_RE = re.compile(r"pid_(\d+)_luid_(0x[0-9A-Fa-f]+)_(0x[0-9A-Fa-f]+)_phys_(\d+)$")
ADAPTERMEM_RE = re.compile(r"luid_(0x[0-9A-Fa-f]+)_(0x[0-9A-Fa-f]+)_phys_(\d+)$")
PROCESS_VM_READ = 0x10
PROCESS_QUERY_INFORMATION = 0x400


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD), ("th32ProcessID", wintypes.DWORD),
                ("th32DefaultHeapID", ctypes.c_size_t), ("th32ModuleID", wintypes.DWORD),
                ("cntThreads", wintypes.DWORD), ("th32ParentProcessID", wintypes.DWORD),
                ("pcPriClassBase", ctypes.c_long), ("dwFlags", wintypes.DWORD), ("szExeFile", ctypes.c_wchar * 260)]


class MODULEENTRY32W(ctypes.Structure):
    _fields_ = [("dwSize", wintypes.DWORD), ("th32ModuleID", wintypes.DWORD), ("th32ProcessID", wintypes.DWORD),
                ("GlblcntUsage", wintypes.DWORD), ("ProccntUsage", wintypes.DWORD),
                ("modBaseAddr", ctypes.c_void_p), ("modBaseSize", wintypes.DWORD), ("hModule", wintypes.HMODULE),
                ("szModule", ctypes.c_wchar * 256), ("szExePath", ctypes.c_wchar * 260)]


class PDH_FMT_COUNTERVALUE(ctypes.Structure):
    class _U(ctypes.Union):
        _fields_ = [("longValue", ctypes.c_long), ("doubleValue", ctypes.c_double), ("largeValue", ctypes.c_longlong)]
    _fields_ = [("CStatus", wintypes.DWORD), ("u", _U)]


class PDH_FMT_COUNTERVALUE_ITEM_W(ctypes.Structure):
    _fields_ = [("szName", ctypes.c_wchar_p), ("FmtValue", PDH_FMT_COUNTERVALUE)]


def _k32():
    k = ctypes.WinDLL("kernel32", use_last_error=True)
    k.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    k.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    k.Process32FirstW.argtypes = k.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
    k.Module32FirstW.argtypes = k.Module32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(MODULEENTRY32W)]
    k.OpenProcess.restype = wintypes.HANDLE
    k.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    k.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR,
                                             ctypes.POINTER(wintypes.DWORD)]
    k.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
    k.CloseHandle.argtypes = [wintypes.HANDLE]
    return k


def processes() -> List[dict]:
    """``[{pid, ppid, name, path, threads, start_time}]`` for every process (start time in epoch seconds)."""
    k = _k32()
    snap = k.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap in (None, INVALID_HANDLE_VALUE):
        return []
    out = []
    try:
        e = PROCESSENTRY32W()
        e.dwSize = ctypes.sizeof(e)
        ok = k.Process32FirstW(snap, ctypes.byref(e))
        while ok:
            path, start = _image_and_start(k, e.th32ProcessID)
            out.append({"pid": e.th32ProcessID, "ppid": e.th32ParentProcessID, "name": e.szExeFile,
                        "threads": e.cntThreads, "path": path, "start_time": start})
            ok = k.Process32NextW(snap, ctypes.byref(e))
    finally:
        k.CloseHandle(snap)
    return out


def _image_and_start(k, pid: int):
    """Full image path (QueryFullProcessImageNameW) and creation time (GetProcessTimes) of ``pid``."""
    h = k.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not h:
        return None, None
    try:
        buf = ctypes.create_unicode_buffer(32768)
        n = wintypes.DWORD(len(buf))
        path = buf.value if k.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(n)) else None
        times = [wintypes.FILETIME() for _ in range(4)]
        start = None
        if k.GetProcessTimes(h, *[ctypes.byref(t) for t in times]):
            ft = (times[0].dwHighDateTime << 32) | times[0].dwLowDateTime
            start = (ft - 116444736000000000) / 1e7 if ft else None  # FILETIME (1601, 100 ns) -> epoch
        return path, start
    finally:
        k.CloseHandle(h)


def image_path(k, pid: int) -> Optional[str]:
    return _image_and_start(k, pid)[0]


def modules(pid: int) -> Optional[List[dict]]:
    """Loaded modules of ``pid`` (None when access is denied, e.g. protected processes). PID 0 (the System Idle
    Process) has none; Toolhelp would read PID 0 as "the calling process" and return this tool's own modules."""
    if pid == 0:
        return []
    k = _k32()
    snap = k.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
    if snap in (None, INVALID_HANDLE_VALUE):
        return None
    out = []
    try:
        e = MODULEENTRY32W()
        e.dwSize = ctypes.sizeof(e)
        ok = k.Module32FirstW(snap, ctypes.byref(e))
        while ok:
            out.append({"name": e.szModule, "path": e.szExePath, "base": e.modBaseAddr or 0, "size": e.modBaseSize})
            ok = k.Module32NextW(snap, ctypes.byref(e))
    finally:
        k.CloseHandle(snap)
    return out


def windowed_pids() -> List[int]:
    """PIDs owning at least one visible top-level window."""
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    pids = set()
    proto = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    user32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
    user32.IsWindowVisible.argtypes = [wintypes.HWND]

    def cb(hwnd, _lp):
        if user32.IsWindowVisible(hwnd):
            pid = wintypes.DWORD()
            user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
            pids.add(pid.value)
        return True

    user32.EnumWindows(proto(cb), 0)
    return sorted(pids)


def _pdh():
    pdh = ctypes.WinDLL("pdh")
    pdh.PdhOpenQueryW.argtypes = [wintypes.LPCWSTR, ctypes.c_size_t, ctypes.POINTER(wintypes.HANDLE)]
    pdh.PdhAddEnglishCounterW.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR, ctypes.c_size_t,
                                          ctypes.POINTER(wintypes.HANDLE)]
    pdh.PdhCollectQueryData.argtypes = [wintypes.HANDLE]
    pdh.PdhGetFormattedCounterArrayW.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
                                                 ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
    pdh.PdhCloseQuery.argtypes = [wintypes.HANDLE]
    for fn in ("PdhOpenQueryW", "PdhAddEnglishCounterW", "PdhCollectQueryData", "PdhGetFormattedCounterArrayW",
               "PdhCloseQuery"):
        getattr(pdh, fn).restype = wintypes.DWORD
    return pdh


def _array(pdh, counter, fmt) -> Dict[str, float]:
    size, count = wintypes.DWORD(0), wintypes.DWORD(0)
    st = pdh.PdhGetFormattedCounterArrayW(counter, fmt, ctypes.byref(size), ctypes.byref(count), None)
    if st != PDH_MORE_DATA or not size.value:
        return {}
    buf = (ctypes.c_byte * size.value)()
    if pdh.PdhGetFormattedCounterArrayW(counter, fmt, ctypes.byref(size), ctypes.byref(count), buf):
        return {}
    items = ctypes.cast(buf, ctypes.POINTER(PDH_FMT_COUNTERVALUE_ITEM_W))
    out = {}
    for i in range(count.value):
        it = items[i]
        if it.FmtValue.CStatus in (0, 1):  # PDH_CSTATUS_VALID_DATA / NEW_DATA
            out[it.szName] = it.FmtValue.u.doubleValue if fmt == PDH_FMT_DOUBLE else it.FmtValue.u.largeValue
    return out


def gpu_counters(sample_seconds: float = 0.5) -> dict:
    """Per-process GPU engine utilisation and GPU memory from the Windows GPU performance counters."""
    pdh = _pdh()
    q = wintypes.HANDLE()
    if pdh.PdhOpenQueryW(None, 0, ctypes.byref(q)):
        return {"available": False, "error": "PdhOpenQuery failed", "processes": {}}
    try:
        counters = {}
        for key, path in (("util", r"\GPU Engine(*)\Utilization Percentage"),
                          ("dedicated", r"\GPU Process Memory(*)\Dedicated Usage"),
                          ("shared", r"\GPU Process Memory(*)\Shared Usage"),
                          ("adapter_dedicated", r"\GPU Adapter Memory(*)\Dedicated Usage"),
                          ("adapter_shared", r"\GPU Adapter Memory(*)\Shared Usage")):
            c = wintypes.HANDLE()
            if pdh.PdhAddEnglishCounterW(q, path, 0, ctypes.byref(c)) == 0:
                counters[key] = c
        if "util" not in counters:
            return {"available": False, "error": "GPU Engine counters not available", "processes": {}}
        pdh.PdhCollectQueryData(q)
        time.sleep(sample_seconds)  # utilisation is a rate counter: needs two samples
        pdh.PdhCollectQueryData(q)
        procs: Dict[str, dict] = {}
        for inst, val in _array(pdh, counters["util"], PDH_FMT_DOUBLE).items():
            m = ENGINE_RE.match(inst)
            if not m:
                continue
            p = procs.setdefault(m.group(1), {"engines": {}, "luids": [], "dedicated": 0, "shared": 0})
            luid = "%s_%s" % (m.group(2), m.group(3))
            if luid not in p["luids"]:
                p["luids"].append(luid)
            et = m.group(6) or "engine%s" % m.group(5)
            p["engines"][et] = round(max(p["engines"].get(et, 0.0), val), 2)
        for key in ("dedicated", "shared"):
            if key not in counters:
                continue
            for inst, val in _array(pdh, counters[key], PDH_FMT_LARGE).items():
                m = PROCMEM_RE.match(inst)
                if m:
                    p = procs.setdefault(m.group(1), {"engines": {}, "luids": [], "dedicated": 0, "shared": 0})
                    p[key] += int(val)
                    luid = "%s_%s" % (m.group(2), m.group(3))
                    per = p.setdefault("by_luid", {}).setdefault(luid, {"dedicated": 0, "shared": 0})
                    per[key] += int(val)
                    if luid not in p["luids"]:
                        p["luids"].append(luid)
        adapters: Dict[str, dict] = {}
        for key in ("adapter_dedicated", "adapter_shared"):
            if key not in counters:
                continue
            for inst, val in _array(pdh, counters[key], PDH_FMT_LARGE).items():
                m = ADAPTERMEM_RE.match(inst)
                if m:
                    a = adapters.setdefault("%s_%s" % (m.group(1), m.group(2)), {"dedicated": 0, "shared": 0})
                    a[key.split("_", 1)[1]] += int(val)
        return {"available": True, "sample_seconds": sample_seconds, "processes": procs, "adapters": adapters}
    finally:
        pdh.PdhCloseQuery(q)


# -- adapters (DXGI) ---------------------------------------------------------------------------------------------
class _GUID(ctypes.Structure):
    _fields_ = [("Data1", wintypes.DWORD), ("Data2", wintypes.WORD), ("Data3", wintypes.WORD),
                ("Data4", ctypes.c_ubyte * 8)]

    @classmethod
    def parse(cls, text):
        import uuid
        u = uuid.UUID(text)
        g = cls()
        g.Data1, g.Data2, g.Data3 = u.fields[0], u.fields[1], u.fields[2]
        g.Data4[:] = list(u.bytes[8:])
        return g


class DXGI_ADAPTER_DESC1(ctypes.Structure):
    _fields_ = [("Description", ctypes.c_wchar * 128), ("VendorId", wintypes.UINT), ("DeviceId", wintypes.UINT),
                ("SubSysId", wintypes.UINT), ("Revision", wintypes.UINT),
                ("DedicatedVideoMemory", ctypes.c_size_t), ("DedicatedSystemMemory", ctypes.c_size_t),
                ("SharedSystemMemory", ctypes.c_size_t), ("LuidLow", wintypes.DWORD), ("LuidHigh", ctypes.c_long),
                ("Flags", wintypes.UINT)]


def luid_key(high: int, low: int) -> str:
    """The form the GPU performance counters use in instance names (``0xHHHHHHHH_0xLLLLLLLL``)."""
    return "0x%08X_0x%08X" % (high & 0xFFFFFFFF, low & 0xFFFFFFFF)


def normalise_luid(text: str) -> str:
    hi, lo = text.split("_")
    return luid_key(int(hi, 16), int(lo, 16))


def _vcall(obj, index, restype, *argtypes):
    vtbl = ctypes.cast(obj, ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p)))[0]
    return ctypes.WINFUNCTYPE(restype, ctypes.c_void_p, *argtypes)(vtbl[index])


def adapters() -> List[dict]:
    """Every DXGI adapter: name, PCI vendor/device id, LUID and memory sizes."""
    try:
        dxgi = ctypes.WinDLL("dxgi")
    except OSError:
        return []
    factory = ctypes.c_void_p()
    iid = _GUID.parse("770aae78-f26f-4dba-a829-253c83d1b387")  # IID_IDXGIFactory1
    dxgi.CreateDXGIFactory1.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
    dxgi.CreateDXGIFactory1.restype = ctypes.c_long
    if dxgi.CreateDXGIFactory1(ctypes.byref(iid), ctypes.byref(factory)) != 0 or not factory:
        return []
    out = []
    try:
        enum1 = _vcall(factory, 12, ctypes.c_long, wintypes.UINT, ctypes.POINTER(ctypes.c_void_p))  # EnumAdapters1
        for i in range(64):
            ad = ctypes.c_void_p()
            if enum1(factory, i, ctypes.byref(ad)) != 0 or not ad:
                break
            try:
                desc = DXGI_ADAPTER_DESC1()
                if _vcall(ad, 10, ctypes.c_long, ctypes.POINTER(DXGI_ADAPTER_DESC1))(ad, ctypes.byref(desc)) == 0:
                    out.append({"luid": luid_key(desc.LuidHigh, desc.LuidLow), "name": desc.Description,
                                "vendor_id": desc.VendorId, "device_id": desc.DeviceId,
                                "dedicated_video_memory": desc.DedicatedVideoMemory,
                                "dedicated_system_memory": desc.DedicatedSystemMemory,
                                "shared_system_memory": desc.SharedSystemMemory,
                                "software": bool(desc.Flags & 2)})
            finally:
                _vcall(ad, 2, wintypes.ULONG)(ad)  # IUnknown::Release
    finally:
        _vcall(factory, 2, wintypes.ULONG)(factory)
    return out


# -- command lines (PEB) -----------------------------------------------------------------------------------------
class PROCESS_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [("ExitStatus", ctypes.c_void_p), ("PebBaseAddress", ctypes.c_void_p),
                ("AffinityMask", ctypes.c_void_p), ("BasePriority", ctypes.c_void_p),
                ("UniqueProcessId", ctypes.c_void_p), ("InheritedFromUniqueProcessId", ctypes.c_void_p)]


def _k32_mem():
    k = _k32()
    k.ReadProcessMemory.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
                                    ctypes.POINTER(ctypes.c_size_t)]
    k.ReadProcessMemory.restype = wintypes.BOOL
    return k


def _rpm(k, h, addr, n) -> Optional[bytes]:
    buf = ctypes.create_string_buffer(n)
    got = ctypes.c_size_t(0)
    if not k.ReadProcessMemory(h, ctypes.c_void_p(addr), buf, n, ctypes.byref(got)) or got.value != n:
        return None
    return buf.raw


def command_line(pid: int) -> Optional[str]:
    """The command line from the process's PEB (``ProcessParameters->CommandLine``, 64-bit layout, which a 64-bit
    reader also gets for WOW64 processes). None when access is denied."""
    if ctypes.sizeof(ctypes.c_void_p) != 8:
        return None
    k = _k32_mem()
    h = k.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, False, pid)
    if not h:
        return None
    try:
        ntdll = ctypes.WinDLL("ntdll")
        ntdll.NtQueryInformationProcess.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.ULONG,
                                                    ctypes.POINTER(wintypes.ULONG)]
        ntdll.NtQueryInformationProcess.restype = ctypes.c_long
        pbi = PROCESS_BASIC_INFORMATION()
        ret = wintypes.ULONG(0)
        if ntdll.NtQueryInformationProcess(h, 0, ctypes.byref(pbi), ctypes.sizeof(pbi), ctypes.byref(ret)) != 0 \
                or not pbi.PebBaseAddress:
            return None
        raw = _rpm(k, h, pbi.PebBaseAddress + 0x20, 8)          # PEB.ProcessParameters
        if raw is None:
            return None
        params = int.from_bytes(raw, "little")
        us = _rpm(k, h, params + 0x70, 16) if params else None   # RTL_USER_PROCESS_PARAMETERS.CommandLine
        if us is None:
            return None
        length = int.from_bytes(us[0:2], "little")
        buf = int.from_bytes(us[8:16], "little")
        if not buf or not length:
            return ""
        text = _rpm(k, h, buf, min(length, 65534))
        return text.decode("utf-16-le", "replace") if text is not None else None
    finally:
        k.CloseHandle(h)


def _ntq(h, info_class: int, buf, size: int) -> bool:
    ntdll = ctypes.WinDLL("ntdll")
    ntdll.NtQueryInformationProcess.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.ULONG,
                                                ctypes.POINTER(wintypes.ULONG)]
    ntdll.NtQueryInformationProcess.restype = ctypes.c_long
    ret = wintypes.ULONG(0)
    return ntdll.NtQueryInformationProcess(h, info_class, buf, size, ctypes.byref(ret)) == 0


def _unicode_string(k, h, addr) -> Optional[str]:
    us = _rpm(k, h, addr, 16)
    if us is None:
        return None
    length, buf = int.from_bytes(us[0:2], "little"), int.from_bytes(us[8:16], "little")
    if not buf or not length:
        return ""
    text = _rpm(k, h, buf, min(length, 65534))
    return text.decode("utf-16-le", "replace") if text is not None else None


def process_info(pid: int, keep) -> Optional[dict]:
    """PEB facts of ``pid`` (64-bit layout): the environment block (``ProcessParameters->Environment``, only the
    variables ``keep(name)`` accepts are returned, matched case-insensitively as Windows does), the PEB
    ``ImagePathName`` and whether a debugger is attached (``NtQueryInformationProcess(ProcessDebugPort)``).
    None when the process cannot be opened; a field is None when that part is unreadable."""
    if ctypes.sizeof(ctypes.c_void_p) != 8:
        return None
    k = _k32_mem()
    h = k.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid) or \
        k.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, False, pid)
    if not h:
        return None
    out = {"environ": None, "environ_total": None, "image_path_name": None, "debugged": None}
    try:
        port = ctypes.c_void_p()
        if _ntq(h, 7, ctypes.byref(port), ctypes.sizeof(port)):  # ProcessDebugPort (needs QUERY_INFORMATION)
            out["debugged"] = bool(port.value)
        pbi = PROCESS_BASIC_INFORMATION()
        if not _ntq(h, 0, ctypes.byref(pbi), ctypes.sizeof(pbi)) or not pbi.PebBaseAddress:
            return out
        raw = _rpm(k, h, pbi.PebBaseAddress + 0x20, 8)               # PEB.ProcessParameters
        params = int.from_bytes(raw, "little") if raw else 0
        if not params:
            return out
        out["image_path_name"] = _unicode_string(k, h, params + 0x60)  # RTL_USER_PROCESS_PARAMETERS.ImagePathName
        envp = _rpm(k, h, params + 0x80, 8)                           # .Environment
        envsize = _rpm(k, h, params + 0x3F0, 8)                       # .EnvironmentSize (Vista+)
        if not envp or not envsize:
            return out
        addr, size = int.from_bytes(envp, "little"), min(int.from_bytes(envsize, "little"), 4 << 20)
        block = _rpm(k, h, addr, size) if addr and size else None
        if block is None:
            return out
        env, total = {}, 0
        for item in block.decode("utf-16-le", "replace").split("\x00"):
            if not item:
                break  # the block ends with an empty string
            if item.startswith("="):
                continue  # per-drive current directories (=C:=C:\...), not variables
            name, sep, value = item.partition("=")
            if sep:
                total += 1
                if keep(name) or keep(name.upper()):
                    env[name] = value
        out["environ"], out["environ_total"] = env, total
        return out
    finally:
        k.CloseHandle(h)


# -- registry ----------------------------------------------------------------------------------------------------
def _reg_value(data, typ):
    import winreg
    if typ == winreg.REG_EXPAND_SZ and isinstance(data, str):
        return winreg.ExpandEnvironmentStrings(data)
    if isinstance(data, (bytes, bytearray)):
        return {"binary": bytes(data[:256]).hex(), "size": len(data)}
    if data is None or isinstance(data, (int, str)):
        return data
    if isinstance(data, list):
        return [str(x) for x in data]
    return repr(data)


def registry_key(path: str) -> Optional[dict]:
    """``{"values": {name: value}, "subkeys": [names]}`` of ``HKLM\\...``, ``HKCU\\...`` or ``HKU\\...`` (64-bit
    view). REG_EXPAND_SZ values are expanded, binary values are ``{"binary": hex of the first 256 bytes, "size"}``.
    None when the key does not exist; ``{"error": "access denied", ...}`` when it cannot be opened."""
    import winreg
    hives = {"HKLM": winreg.HKEY_LOCAL_MACHINE, "HKCU": winreg.HKEY_CURRENT_USER, "HKU": winreg.HKEY_USERS}
    hive, _, sub = path.partition("\\")
    if hive.upper() not in hives:
        return None
    try:
        with winreg.OpenKey(hives[hive.upper()], sub, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
            nsub, nval, _ = winreg.QueryInfoKey(key)
            subkeys = [winreg.EnumKey(key, i) for i in range(nsub)]
            values = {}
            for i in range(nval):
                name, data, typ = winreg.EnumValue(key, i)
                values[name] = _reg_value(data, typ)
    except FileNotFoundError:
        return None
    except PermissionError:
        return {"error": "access denied", "values": {}, "subkeys": []}
    except OSError as exc:
        return {"error": str(exc), "values": {}, "subkeys": []}
    return {"values": values, "subkeys": subkeys}


# -- kernel drivers and file versions ------------------------------------------------------------------------------
def nt_to_win32(path: str) -> str:
    """``\\SystemRoot\\...``, ``\\??\\C:\\...`` and bare ``System32\\...`` driver paths as Win32 paths."""
    root = os.environ.get("SystemRoot", r"C:\Windows")
    low = path.lower()
    if low.startswith("\\systemroot\\"):
        return root + path[len("\\SystemRoot"):]
    if low.startswith("\\??\\") or low.startswith("\\\\?\\"):
        return path[4:]
    if low.startswith("system32\\"):
        return os.path.join(root, path)
    return path


def drivers() -> List[dict]:
    """Loaded kernel modules from ``NtQuerySystemInformation(SystemModuleInformation)`` in load order:
    ``[{name, path, nt_path, base, size}]``. Current Windows returns base addresses as 0 to non-administrators;
    names and paths are still complete."""
    ntdll = ctypes.WinDLL("ntdll")
    ntdll.NtQuerySystemInformation.argtypes = [ctypes.c_int, ctypes.c_void_p, wintypes.ULONG,
                                               ctypes.POINTER(wintypes.ULONG)]
    ntdll.NtQuerySystemInformation.restype = ctypes.c_long
    size = 1 << 17
    for _ in range(6):
        buf = ctypes.create_string_buffer(size)
        ret = wintypes.ULONG(0)
        st = ntdll.NtQuerySystemInformation(11, buf, size, ctypes.byref(ret)) & 0xFFFFFFFF
        if st == 0xC0000004:  # STATUS_INFO_LENGTH_MISMATCH
            size = max(size * 2, ret.value + 4096)
            continue
        if st != 0:
            return []
        raw = buf.raw
        count = int.from_bytes(raw[0:4], "little")
        out = []
        for i in range(count):
            e = raw[8 + i * 296:8 + (i + 1) * 296]  # RTL_PROCESS_MODULE_INFORMATION (x64)
            if len(e) < 296:
                break
            full = e[40:296].split(b"\x00", 1)[0].decode("mbcs", "replace")
            name_off = int.from_bytes(e[38:40], "little")
            out.append({"name": full[name_off:] or full.rsplit("\\", 1)[-1], "path": nt_to_win32(full),
                        "nt_path": full, "base": int.from_bytes(e[16:24], "little"),
                        "size": int.from_bytes(e[24:28], "little")})
        return out
    return []


def file_version(path: str) -> Optional[dict]:
    """Version resource of a PE file: fixed file/product version and the CompanyName, FileDescription,
    ProductName, OriginalFilename strings of its first language."""
    ver = ctypes.WinDLL("version")
    ver.GetFileVersionInfoSizeW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(wintypes.DWORD)]
    ver.GetFileVersionInfoW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p]
    ver.VerQueryValueW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_void_p),
                                   ctypes.POINTER(wintypes.UINT)]
    size = ver.GetFileVersionInfoSizeW(path, None)
    if not size:
        return None
    data = ctypes.create_string_buffer(size)
    if not ver.GetFileVersionInfoW(path, 0, size, data):
        return None
    ptr, n = ctypes.c_void_p(), wintypes.UINT()
    out = {}
    if ver.VerQueryValueW(data, "\\", ctypes.byref(ptr), ctypes.byref(n)) and n.value >= 52:
        fixed = ctypes.string_at(ptr, 52)
        ms, ls = int.from_bytes(fixed[8:12], "little"), int.from_bytes(fixed[12:16], "little")
        pms, pls = int.from_bytes(fixed[16:20], "little"), int.from_bytes(fixed[20:24], "little")
        out["file_version"] = "%d.%d.%d.%d" % (ms >> 16, ms & 0xFFFF, ls >> 16, ls & 0xFFFF)
        out["product_version"] = "%d.%d.%d.%d" % (pms >> 16, pms & 0xFFFF, pls >> 16, pls & 0xFFFF)
    if ver.VerQueryValueW(data, "\\VarFileInfo\\Translation", ctypes.byref(ptr), ctypes.byref(n)) and n.value >= 4:
        tr = ctypes.string_at(ptr, 4)
        lang = "%04x%04x" % (int.from_bytes(tr[0:2], "little"), int.from_bytes(tr[2:4], "little"))
        for key, field in (("CompanyName", "company"), ("FileDescription", "description"),
                           ("ProductName", "product"), ("OriginalFilename", "original_filename")):
            if ver.VerQueryValueW(data, "\\StringFileInfo\\%s\\%s" % (lang, key), ctypes.byref(ptr),
                                  ctypes.byref(n)) and n.value:
                out[field] = ctypes.wstring_at(ptr, n.value).rstrip("\x00")
    return out or None


# -- Authenticode signatures --------------------------------------------------------------------------------------
class WINTRUST_FILE_INFO(ctypes.Structure):
    _fields_ = [("cbStruct", wintypes.DWORD), ("pcwszFilePath", wintypes.LPCWSTR), ("hFile", wintypes.HANDLE),
                ("pgKnownSubject", ctypes.c_void_p)]


class WINTRUST_CATALOG_INFO(ctypes.Structure):
    _fields_ = [("cbStruct", wintypes.DWORD), ("dwCatalogVersion", wintypes.DWORD),
                ("pcwszCatalogFilePath", wintypes.LPCWSTR), ("pcwszMemberTag", wintypes.LPCWSTR),
                ("pcwszMemberFilePath", wintypes.LPCWSTR), ("hMemberFile", wintypes.HANDLE),
                ("pbCalculatedFileHash", ctypes.c_void_p), ("cbCalculatedFileHash", wintypes.DWORD),
                ("pcCatalogContext", ctypes.c_void_p), ("hCatAdmin", ctypes.c_void_p)]


class WINTRUST_DATA(ctypes.Structure):
    _fields_ = [("cbStruct", wintypes.DWORD), ("pPolicyCallbackData", ctypes.c_void_p),
                ("pSIPClientData", ctypes.c_void_p), ("dwUIChoice", wintypes.DWORD),
                ("fdwRevocationChecks", wintypes.DWORD), ("dwUnionChoice", wintypes.DWORD),
                ("pInfo", ctypes.c_void_p), ("dwStateAction", wintypes.DWORD), ("hWVTStateData", wintypes.HANDLE),
                ("pwszURLReference", wintypes.LPWSTR), ("dwProvFlags", wintypes.DWORD), ("dwUIContext", wintypes.DWORD),
                ("pSignatureSettings", ctypes.c_void_p)]


class _FILETIME(ctypes.Structure):
    _fields_ = [("lo", wintypes.DWORD), ("hi", wintypes.DWORD)]


class CRYPT_PROVIDER_SGNR(ctypes.Structure):
    _fields_ = [("cbStruct", wintypes.DWORD), ("sftVerifyAsOf", _FILETIME), ("csCertChain", wintypes.DWORD),
                ("pasCertChain", ctypes.c_void_p)]


class CRYPT_PROVIDER_CERT(ctypes.Structure):
    _fields_ = [("cbStruct", wintypes.DWORD), ("pCert", ctypes.c_void_p)]


class CATALOG_INFO(ctypes.Structure):
    _fields_ = [("cbStruct", wintypes.DWORD), ("wszCatalogFile", ctypes.c_wchar * 260)]


WTD_UI_NONE, WTD_REVOKE_NONE, WTD_CHOICE_FILE, WTD_CHOICE_CATALOG = 2, 0, 1, 2
WTD_STATEACTION_VERIFY, WTD_STATEACTION_CLOSE = 1, 2
WTD_CACHE_ONLY_URL_RETRIEVAL = 0x1000  # never touch the network
TRUST_E_NOSIGNATURE = 0x800B0100
TRUST_RESULTS = {0x800B0100: "unsigned", 0x80096010: "BAD DIGEST (modified after signing)",
                 0x800B0101: "certificate expired", 0x800B010C: "certificate revoked",
                 0x800B0109: "untrusted root", 0x800B0111: "explicitly distrusted", 0x80092026: "no signer",
                 0x800B0004: "subject form not supported", 0x800B0003: "subject form not supported"}
_GENERIC_VERIFY_V2 = "00AAC56B-CD44-11d0-8CC2-00C04FC295EE"


def _signer_name(wt, crypt32, state) -> Optional[str]:
    wt.WTHelperProvDataFromStateData.restype = ctypes.c_void_p
    wt.WTHelperProvDataFromStateData.argtypes = [wintypes.HANDLE]
    wt.WTHelperGetProvSignerFromChain.restype = ctypes.POINTER(CRYPT_PROVIDER_SGNR)
    wt.WTHelperGetProvSignerFromChain.argtypes = [ctypes.c_void_p, wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    prov = wt.WTHelperProvDataFromStateData(state)
    if not prov:
        return None
    sg = wt.WTHelperGetProvSignerFromChain(prov, 0, False, 0)
    if not sg or not sg.contents.csCertChain or not sg.contents.pasCertChain:
        return None
    cert = ctypes.cast(sg.contents.pasCertChain, ctypes.POINTER(CRYPT_PROVIDER_CERT)).contents.pCert
    if not cert:
        return None
    crypt32.CertGetNameStringW.argtypes = [ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                                           wintypes.LPWSTR, wintypes.DWORD]
    buf = ctypes.create_unicode_buffer(512)
    crypt32.CertGetNameStringW(cert, 4, 0, None, buf, 512)  # CERT_NAME_SIMPLE_DISPLAY_TYPE
    return buf.value or None


def _verify(wt, crypt32, choice, info) -> Tuple[int, Optional[str]]:
    action = _GUID.parse(_GENERIC_VERIFY_V2)
    data = WINTRUST_DATA()
    data.cbStruct = ctypes.sizeof(data)
    data.dwUIChoice, data.fdwRevocationChecks, data.dwUnionChoice = WTD_UI_NONE, WTD_REVOKE_NONE, choice
    data.pInfo = ctypes.cast(ctypes.pointer(info), ctypes.c_void_p)
    data.dwStateAction = WTD_STATEACTION_VERIFY
    data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL
    wt.WinVerifyTrust.argtypes = [wintypes.HWND, ctypes.c_void_p, ctypes.c_void_p]
    wt.WinVerifyTrust.restype = ctypes.c_long
    status = wt.WinVerifyTrust(None, ctypes.byref(action), ctypes.byref(data)) & 0xFFFFFFFF
    signer = _signer_name(wt, crypt32, data.hWVTStateData) if status == 0 else None
    data.dwStateAction = WTD_STATEACTION_CLOSE
    wt.WinVerifyTrust(None, ctypes.byref(action), ctypes.byref(data))
    return status, signer


def _verify_catalog(wt, crypt32, path):
    """Verify ``path`` through the installed system catalogs. Returns ``(status, signer)`` or None when no catalog
    lists the file. The catalog-admin context stays open during verification and is passed in, so WinVerifyTrust
    uses the same hash algorithm (SHA-256 catalogs, then SHA-1) that found the member."""
    k = _k32()
    k.CreateFileW.restype = wintypes.HANDLE
    k.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD,
                              wintypes.DWORD, wintypes.HANDLE]
    h = k.CreateFileW(path, 0x80000000, 1 | 2 | 4, None, 3, 0, None)  # GENERIC_READ, share all, OPEN_EXISTING
    if h in (None, INVALID_HANDLE_VALUE):
        return None
    wt.CryptCATAdminAcquireContext2.argtypes = [ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p, wintypes.LPCWSTR,
                                                ctypes.c_void_p, wintypes.DWORD]
    wt.CryptCATAdminCalcHashFromFileHandle2.argtypes = [ctypes.c_void_p, wintypes.HANDLE,
                                                        ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p,
                                                        wintypes.DWORD]
    wt.CryptCATAdminEnumCatalogFromHash.restype = ctypes.c_void_p
    wt.CryptCATAdminEnumCatalogFromHash.argtypes = [ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
                                                    ctypes.c_void_p]
    wt.CryptCATCatalogInfoFromContext.argtypes = [ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD]
    wt.CryptCATAdminReleaseCatalogContext.argtypes = [ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD]
    wt.CryptCATAdminReleaseContext.argtypes = [ctypes.c_void_p, wintypes.DWORD]
    result = None
    try:
        for algo in ("SHA256", "SHA1"):
            admin = ctypes.c_void_p()
            if not wt.CryptCATAdminAcquireContext2(ctypes.byref(admin), None, algo, None, 0):
                continue
            try:
                size = wintypes.DWORD(64)
                hbuf = (ctypes.c_ubyte * 64)()
                if not wt.CryptCATAdminCalcHashFromFileHandle2(admin, h, ctypes.byref(size), hbuf, 0):
                    continue
                cat = wt.CryptCATAdminEnumCatalogFromHash(admin, hbuf, size, 0, None)
                if not cat:
                    continue
                try:
                    info = CATALOG_INFO()
                    info.cbStruct = ctypes.sizeof(info)
                    if not wt.CryptCATCatalogInfoFromContext(cat, ctypes.byref(info), 0):
                        continue
                    ci = WINTRUST_CATALOG_INFO()
                    ci.cbStruct = ctypes.sizeof(ci)
                    ci.pcwszCatalogFilePath = info.wszCatalogFile
                    ci.pcwszMemberTag = bytes(hbuf[:size.value]).hex().upper()
                    ci.pcwszMemberFilePath = path
                    ci.hMemberFile = h
                    ci.pbCalculatedFileHash = ctypes.cast(hbuf, ctypes.c_void_p)
                    ci.cbCalculatedFileHash = size.value
                    ci.hCatAdmin = admin
                    result = _verify(wt, crypt32, WTD_CHOICE_CATALOG, ci)
                    if result[0] == 0:
                        return result
                finally:
                    wt.CryptCATAdminReleaseCatalogContext(admin, cat, 0)
            finally:
                wt.CryptCATAdminReleaseContext(admin, 0)
    finally:
        k.CloseHandle(h)
    return result


def signature(path: str) -> dict:
    """Authenticode status of ``path``: embedded signature first, then the installed system catalogs (most
    Windows binaries are catalog-signed). Revocation is not checked and no network access is made."""
    if not path or not os.path.isfile(path):
        return {"status": "not found", "signer": None, "kind": None}
    wt = ctypes.WinDLL("wintrust")
    crypt32 = ctypes.WinDLL("crypt32")
    fi = WINTRUST_FILE_INFO()
    fi.cbStruct = ctypes.sizeof(fi)
    fi.pcwszFilePath = path
    status, signer = _verify(wt, crypt32, WTD_CHOICE_FILE, fi)
    if status == 0:
        return {"status": "valid", "signer": signer, "kind": "embedded"}
    if status in (TRUST_E_NOSIGNATURE, 0x800B0003):
        cat = _verify_catalog(wt, crypt32, path)
        if cat is not None:
            cstatus, csigner = cat
            if cstatus == 0:
                return {"status": "valid", "signer": csigner, "kind": "catalog"}
            return {"status": TRUST_RESULTS.get(cstatus, "error 0x%08X" % cstatus), "signer": None, "kind": "catalog"}
    return {"status": TRUST_RESULTS.get(status, "error 0x%08X" % status), "signer": None, "kind": "embedded"}


# -- process memory (acquisition) ---------------------------------------------------------------------------------
class MEMORY_BASIC_INFORMATION64(ctypes.Structure):
    _fields_ = [("BaseAddress", ctypes.c_ulonglong), ("AllocationBase", ctypes.c_ulonglong),
                ("AllocationProtect", wintypes.DWORD), ("_a1", wintypes.DWORD), ("RegionSize", ctypes.c_ulonglong),
                ("State", wintypes.DWORD), ("Protect", wintypes.DWORD), ("Type", wintypes.DWORD),
                ("_a2", wintypes.DWORD)]


MEM_COMMIT, MEM_PRIVATE, MEM_MAPPED, MEM_IMAGE = 0x1000, 0x20000, 0x40000, 0x1000000
PAGE_NOACCESS, PAGE_GUARD = 0x01, 0x100
_PROT = {0x02: "r--", 0x04: "rw-", 0x08: "rw-", 0x10: "--x", 0x20: "r-x", 0x40: "rwx", 0x80: "rwx"}


def _dos_devices() -> Dict[str, str]:
    k = _k32()
    k.QueryDosDeviceW.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD]
    out = {}
    buf = ctypes.create_unicode_buffer(1024)
    for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        if k.QueryDosDeviceW(letter + ":", buf, 1024):
            out[buf.value] = letter + ":"
    return out


def regions(pid: int):
    """``(process handle, [region])`` for every committed, accessible region (the caller closes the handle).
    Region: start, end, perms (``rwx`` + ``p`` private/image or ``s`` mapped), backing path, type."""
    k = _k32_mem()
    h = k.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not h:
        raise PermissionError("OpenProcess(%d) failed (error %d)" % (pid, ctypes.get_last_error()))
    k.VirtualQueryEx.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.POINTER(MEMORY_BASIC_INFORMATION64),
                                 ctypes.c_size_t]
    k.VirtualQueryEx.restype = ctypes.c_size_t
    k.K32GetMappedFileNameW.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.LPWSTR, wintypes.DWORD]
    devs = _dos_devices()
    name = ctypes.create_unicode_buffer(1024)
    out, addr = [], 0
    mbi = MEMORY_BASIC_INFORMATION64()
    while addr < (1 << 47) and k.VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)):
        base, size = mbi.BaseAddress, mbi.RegionSize
        if size == 0:
            break
        if mbi.State == MEM_COMMIT and not mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD) and mbi.Protect & 0xFF:
            path = ""
            if mbi.Type in (MEM_IMAGE, MEM_MAPPED) and k.K32GetMappedFileNameW(h, ctypes.c_void_p(base), name, 1024):
                path = name.value
                for dev, letter in devs.items():
                    if path.startswith(dev + "\\"):
                        path = letter + path[len(dev):]
                        break
            perms = _PROT.get(mbi.Protect & 0xFF, "---") + ("s" if mbi.Type == MEM_MAPPED else "p")
            out.append({"start": base, "end": base + size, "perms": perms, "path": path,
                        "type": {MEM_PRIVATE: "private", MEM_MAPPED: "mapped", MEM_IMAGE: "image"}.get(mbi.Type, "?")})
        addr = base + size
    return h, out


def read_region(h, start: int, size: int, chunk: int = 1 << 20) -> Tuple[bytes, int]:
    """Read ``size`` bytes at ``start``; unreadable pages become zeros. Returns ``(data, unreadable bytes)``."""
    k = _k32_mem()
    out = bytearray()
    bad = 0
    pos = start
    while pos < start + size:
        n = min(chunk, start + size - pos)
        data = _rpm(k, h, pos, n)
        if data is None:  # partial copy: retry page by page
            for p in range(pos, pos + n, 0x1000):
                m = min(0x1000, pos + n - p)
                d = _rpm(k, h, p, m)
                if d is None:
                    d = bytes(m)
                    bad += m
                out += d
        else:
            out += data
        pos += n
    return bytes(out), bad


def close_handle(h):
    _k32().CloseHandle(h)


def memory_regions(pid: int) -> Optional[List[dict]]:
    """The committed, accessible regions of ``pid`` (see ``regions``); None when the process cannot be opened."""
    try:
        h, regs = regions(pid)
    except PermissionError:
        return None
    close_handle(h)
    return regs


def read_memory(pid: int, address: int, length: int, chunk: int = 1 << 20) -> Optional[bytes]:
    """``length`` bytes of ``pid``'s memory at ``address`` through ReadProcessMemory, or None when the process
    cannot be opened or any part is unreadable (the same all-or-nothing answer as a failed /proc/<pid>/mem read)."""
    k = _k32_mem()
    h = k.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, False, pid)
    if not h:
        return None
    try:
        out = bytearray()
        pos = address
        while pos < address + length:
            data = _rpm(k, h, pos, min(chunk, address + length - pos))
            if data is None:
                return None
            out += data
            pos += len(data)
        return bytes(out)
    finally:
        k.CloseHandle(h)


class _LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("LowPart", wintypes.DWORD), ("HighPart", ctypes.c_long), ("Attributes", wintypes.DWORD)]


class _TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [("PrivilegeCount", wintypes.DWORD), ("Privileges", _LUID_AND_ATTRIBUTES * 1)]


def enable_debug_privilege() -> bool:
    """Enable SeDebugPrivilege in this process's token (only possible when running elevated). With it, modules,
    command lines and memory of other users' and service processes become readable; protected (PPL) processes
    stay closed. Returns True when the privilege is now enabled."""
    adv = ctypes.WinDLL("advapi32", use_last_error=True)
    k = _k32()
    k.GetCurrentProcess.restype = wintypes.HANDLE
    adv.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    adv.LookupPrivilegeValueW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.c_void_p]
    adv.AdjustTokenPrivileges.argtypes = [wintypes.HANDLE, wintypes.BOOL, ctypes.c_void_p, wintypes.DWORD,
                                          ctypes.c_void_p, ctypes.c_void_p]
    tok = wintypes.HANDLE()
    if not adv.OpenProcessToken(k.GetCurrentProcess(), 0x20 | 0x8, ctypes.byref(tok)):  # ADJUST_PRIVILEGES|QUERY
        return False
    try:
        tp = _TOKEN_PRIVILEGES()
        tp.PrivilegeCount = 1
        luid = wintypes.LARGE_INTEGER()
        if not adv.LookupPrivilegeValueW(None, "SeDebugPrivilege", ctypes.byref(luid)):
            return False
        tp.Privileges[0].LowPart = luid.value & 0xFFFFFFFF
        tp.Privileges[0].HighPart = luid.value >> 32
        tp.Privileges[0].Attributes = 2  # SE_PRIVILEGE_ENABLED
        ctypes.set_last_error(0)
        if not adv.AdjustTokenPrivileges(tok, False, ctypes.byref(tp), 0, None, None):
            return False
        return ctypes.get_last_error() != 1300  # ERROR_NOT_ALL_ASSIGNED: not elevated
    finally:
        k.CloseHandle(tok)


# -- open handles to GPU objects (classification: keto.live.gpuhandles) ---------------------------------------------
SYSTEM_EXTENDED_HANDLE_INFORMATION = 64
STATUS_INFO_LENGTH_MISMATCH = 0xC0000004
PROCESS_DUP_HANDLE = 0x40
DUPLICATE_SAME_ACCESS = 0x2


class _HANDLE_ENTRY(ctypes.Structure):  # SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX
    _fields_ = [("Object", ctypes.c_void_p), ("UniqueProcessId", ctypes.c_size_t), ("HandleValue", ctypes.c_size_t),
                ("GrantedAccess", wintypes.ULONG), ("CreatorBackTraceIndex", wintypes.USHORT),
                ("ObjectTypeIndex", wintypes.USHORT), ("HandleAttributes", wintypes.ULONG),
                ("Reserved", wintypes.ULONG)]


def _ntdll():
    nt = ctypes.WinDLL("ntdll")
    nt.NtQuerySystemInformation.restype = ctypes.c_ulong
    nt.NtQuerySystemInformation.argtypes = [ctypes.c_int, ctypes.c_void_p, wintypes.ULONG,
                                            ctypes.POINTER(wintypes.ULONG)]
    nt.NtQueryObject.restype = ctypes.c_ulong
    nt.NtQueryObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.ULONG,
                                 ctypes.POINTER(wintypes.ULONG)]
    return nt


def _object_name(nt, h) -> Optional[str]:
    """``NtQueryObject(ObjectNameInformation)``: the object's NT name (None on failure)."""
    buf = ctypes.create_string_buffer(4096)
    ret = wintypes.ULONG()
    if nt.NtQueryObject(h, 1, buf, len(buf), ctypes.byref(ret)) != 0:
        return None
    length = ctypes.c_ushort.from_buffer(buf, 0).value
    ptr = ctypes.c_void_p.from_buffer(buf, 8).value
    return ctypes.wstring_at(ptr, length // 2) if ptr and length else ""


class _NameResolver:
    """Runs each name query in a worker thread with a timeout. A name query on a synchronous file object (typically
    a pipe) blocks while another thread of the owning process has I/O pending on it, and cannot be cancelled: on a
    timeout the worker is abandoned (left blocked as a daemon thread, its duplicated handle not closed) and a new one
    is started; after ``max_stuck`` abandoned workers no more names are resolved."""

    def __init__(self, nt, timeout: float = 0.25, max_stuck: int = 8):
        import queue
        import threading
        self._queue_mod, self._threading = queue, threading
        self.nt, self.timeout, self.max_stuck = nt, timeout, max_stuck
        self.stuck = 0
        self._start()

    def _start(self):
        self.req, self.res = self._queue_mod.Queue(), self._queue_mod.Queue()
        req, res, nt = self.req, self.res, self.nt

        def loop():
            while True:
                h = req.get()
                if h is None:
                    return
                res.put(_object_name(nt, h))
        self._threading.Thread(target=loop, daemon=True, name="keto-handle-names").start()

    def name(self, h) -> Tuple[Optional[str], bool]:
        """``(name, completed)``: completed is False when the query timed out (the handle must not be closed)."""
        if self.stuck >= self.max_stuck:
            return None, True
        self.req.put(h)
        try:
            return self.res.get(timeout=self.timeout), True
        except self._queue_mod.Empty:
            self.stuck += 1
            self._start()
            return None, False


class HandleTable:
    """One snapshot of the system handle table (``NtQuerySystemInformation(SystemExtendedHandleInformation)``).
    ``gpu_handles(pid)`` duplicates that process's File handles into this process (``PROCESS_DUP_HANDLE``: same user,
    or Administrator), resolves their names through :class:`_NameResolver` and returns only the GPU-related ones
    (:func:`keto.live.gpuhandles.handle_kind`), so nothing else about the process leaves this function."""

    def __init__(self):
        self.k = _k32()
        self.k.GetCurrentProcess.restype = wintypes.HANDLE
        self.k.DuplicateHandle.argtypes = [wintypes.HANDLE, wintypes.HANDLE, wintypes.HANDLE,
                                           ctypes.POINTER(wintypes.HANDLE), wintypes.DWORD, wintypes.BOOL,
                                           wintypes.DWORD]
        self.k.CreateFileW.restype = wintypes.HANDLE
        self.k.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                                       wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
        self.nt = _ntdll()
        # the File object type index is learned from a handle this process opens itself (indices differ per build)
        nul = self.k.CreateFileW("NUL", 0x80000000, 3, None, 3, 0, None)  # GENERIC_READ, share r/w, OPEN_EXISTING
        opened = bool(nul) and nul != INVALID_HANDLE_VALUE
        try:
            entries = self._snapshot()
            me = os.getpid()
            self.file_type = next((e[3] for e in entries if e[0] == me and e[1] == nul), None) if opened else None
        finally:
            if opened:
                self.k.CloseHandle(nul)
        self.by_pid: Dict[int, List[tuple]] = {}
        for e in entries:
            if self.file_type is not None and e[3] == self.file_type:
                self.by_pid.setdefault(e[0], []).append(e)
        self.resolver = _NameResolver(self.nt)

    def _snapshot(self) -> List[tuple]:
        size = 4 << 20
        while size <= (1 << 30):
            buf = ctypes.create_string_buffer(size)
            ret = wintypes.ULONG()
            st = self.nt.NtQuerySystemInformation(SYSTEM_EXTENDED_HANDLE_INFORMATION, buf, size, ctypes.byref(ret))
            if st == STATUS_INFO_LENGTH_MISMATCH:
                size = max(size * 2, ret.value + (1 << 20))
                continue
            if st != 0:
                return []
            n = min(ctypes.c_size_t.from_buffer(buf, 0).value, (size - 16) // ctypes.sizeof(_HANDLE_ENTRY))
            return [(e.UniqueProcessId, e.HandleValue, e.GrantedAccess, e.ObjectTypeIndex)
                    for e in (_HANDLE_ENTRY * n).from_buffer(buf, 16)]
        return []

    def gpu_handles(self, pid: int) -> Optional[dict]:
        """``{"handles": [{handle, access, name, kind}], "file_handles": n, "unresolved": n}`` for ``pid``; None when
        the process cannot be opened for handle duplication (or the handle table is unavailable)."""
        if self.file_type is None:
            return None
        mine = self.k.GetCurrentProcess()
        hp = self.k.OpenProcess(PROCESS_DUP_HANDLE, False, pid)
        if not hp:
            return None
        out, unresolved = [], 0
        try:
            entries = self.by_pid.get(pid, [])
            for _pid, value, access, _type in entries:
                dup = wintypes.HANDLE()
                if not self.k.DuplicateHandle(hp, value, mine, ctypes.byref(dup), 0, False, DUPLICATE_SAME_ACCESS):
                    unresolved += 1
                    continue
                name, done = self.resolver.name(dup)
                if done:
                    self.k.CloseHandle(dup)
                if name is None:
                    unresolved += 1
                    continue
                kind = gpuhandles.handle_kind(name)
                if kind:
                    out.append({"handle": int(value), "access": int(access), "name": name, "kind": kind})
        finally:
            self.k.CloseHandle(hp)
        return {"handles": out, "file_handles": len(self.by_pid.get(pid, [])), "unresolved": unresolved}
