"""NVIDIA Xid error catalogue and kernel-log parsing.

Xid messages are printed by the NVIDIA kernel driver (``NVRM: Xid (PCI:...): <code>, ...``)
when the GPU reports an error. Names follow NVIDIA's published Xid table; the
``forensic`` note says why an investigator may care. Entries with
``certain=False`` are included because they are commonly seen, but their exact
wording should be checked against the Xid table for the driver branch in use.
"""

from __future__ import annotations

import datetime as _dt
import re
from typing import Dict, List, Optional

XID: Dict[int, dict] = {
    8: {"name": "GPU stopped processing", "cause": "driver/application error, hang", "certain": True},
    13: {"name": "Graphics Engine Exception", "cause": "illegal instruction/address in a shader or kernel, "
         "out-of-range access", "certain": True,
         "forensic": "a kernel faulted on purpose or by accident (fuzzing, exploitation attempts, buggy code)"},
    31: {"name": "GPU memory page fault", "cause": "MMU fault: access to an unmapped or protected GPU VA",
         "certain": True, "forensic": "the faulting VA, engine and access type identify the offending context; "
         "repeated faults can indicate probing of GPU memory"},
    32: {"name": "Invalid or corrupted push buffer stream", "cause": "bad pushbuffer / DMA", "certain": True,
         "forensic": "command streams submitted outside the user-mode driver can trigger this"},
    38: {"name": "Driver firmware error", "cause": "firmware/microcontroller error", "certain": True},
    43: {"name": "GPU stopped processing", "cause": "user application fault (the channel was torn down)",
         "certain": True},
    45: {"name": "Preemptive cleanup, due to previous errors", "cause": "channel cleaned up after an earlier "
         "error or process termination", "certain": True},
    48: {"name": "Double Bit ECC Error", "cause": "uncorrectable DRAM error", "certain": True},
    61: {"name": "Internal micro-controller breakpoint/warning", "cause": "PMU/firmware", "certain": True},
    62: {"name": "Internal micro-controller halt", "cause": "PMU/firmware", "certain": True},
    63: {"name": "ECC page retirement or row remapping recording event", "cause": "memory error handling",
         "certain": True, "forensic": "retired/remapped VRAM regions are recorded in the InfoROM"},
    64: {"name": "ECC page retirement or row remapper recording failure", "cause": "memory error handling",
         "certain": True},
    68: {"name": "NVDEC0 Exception", "cause": "video decoder error", "certain": True},
    69: {"name": "Graphics Engine class error", "cause": "illegal method/class usage in a command stream",
         "certain": True, "forensic": "malformed or hand-crafted command streams"},
    74: {"name": "NVLINK Error", "cause": "NVLink link/protocol error", "certain": True},
    79: {"name": "GPU has fallen off the bus", "cause": "PCIe link loss: power, thermal, hardware, or the "
         "device was removed/reset", "certain": True,
         "forensic": "device disappearance; correlate with physical access / power events"},
    92: {"name": "High single-bit ECC error rate", "cause": "degrading memory", "certain": True},
    94: {"name": "Contained ECC error", "cause": "ECC error contained to the affected application",
         "certain": True},
    95: {"name": "Uncontained ECC error", "cause": "ECC error affecting multiple applications", "certain": True},
    109: {"name": "Context Switch Timeout Error", "cause": "a context could not be switched out (hang, "
          "monopolising workload)", "certain": True},
    119: {"name": "GSP RPC Timeout", "cause": "GPU System Processor firmware did not answer", "certain": True},
    120: {"name": "GSP Error", "cause": "GPU System Processor firmware error", "certain": True},
    110: {"name": "Security Fault Error", "cause": "hardware security fault", "certain": False},
    140: {"name": "Unrecovered ECC Error", "cause": "uncorrectable memory error", "certain": False},
}

XID_RE = re.compile(r"NVRM: Xid \((?P<pci>[^)]*)\):\s*(?P<code>\d+),\s*(?P<rest>.*)")
PID_RE = re.compile(r"pid='?(?P<pid>[^,']*)'?")
NAME_RE = re.compile(r"name=(?P<name>[^,]*)")
FAULT_ADDR_RE = re.compile(r"faulted @ (0x[0-9a-fA-F_]+)")
FAULT_TYPE_RE = re.compile(r"Fault is of type (\S+)(?: (\S+))?")
ENGINE_RE = re.compile(r"ENGINE (\S+)")
DMESG_TS_RE = re.compile(r"^\[\s*(\d+\.\d+)\]")
ISO_TS_RE = re.compile(r"^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})(?:[.,]\d+)?(Z|[+-]\d{2}:?\d{2})?")
SYSLOG_TS_RE = re.compile(r"^([A-Z][a-z]{2})\s+(\d{1,2}) (\d{2}:\d{2}:\d{2}) ")
MONTHS = {m: i + 1 for i, m in enumerate("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split())}


def describe(code: int) -> dict:
    return XID.get(code, {"name": "Xid %d (not in the built-in catalogue)" % code, "cause": "see NVIDIA Xid table",
                          "certain": False})


def _timestamp(line: str, boot_epoch: Optional[float], year: Optional[int]):
    """The event time: an aware UTC datetime when the line says its zone (dmesg offset + boot time, ISO with an
    offset or Z); a *naive* datetime (zone unknown: the logging host's local time, shown as logged) for ISO
    times without an offset and for syslog times, rather than pretending they are UTC."""
    m = DMESG_TS_RE.match(line)
    if m:
        if boot_epoch is None:
            return None
        return _dt.datetime.fromtimestamp(boot_epoch + float(m.group(1)), tz=_dt.timezone.utc)
    m = ISO_TS_RE.match(line)
    if m:
        try:
            dt = _dt.datetime.strptime(m.group(1) + " " + m.group(2), "%Y-%m-%d %H:%M:%S")
        except ValueError:
            return None
        tz = m.group(3)
        if not tz:
            return dt
        if tz == "Z":
            offset = _dt.timezone.utc
        else:
            sign = 1 if tz[0] == "+" else -1
            hh, mm = int(tz[1:3]), int(tz[-2:])
            offset = _dt.timezone(sign * _dt.timedelta(hours=hh, minutes=mm))
        return dt.replace(tzinfo=offset).astimezone(_dt.timezone.utc)
    m = SYSLOG_TS_RE.match(line)
    if m and year:
        try:
            return _dt.datetime(year, MONTHS[m.group(1)], int(m.group(2)), *[int(x) for x in m.group(3).split(":")])
        except (KeyError, ValueError):
            return None
    return None


def parse_log(lines: List[str], boot_epoch: Optional[float] = None, year: Optional[int] = None) -> List[dict]:
    """Parse Xid events from kernel-log lines (dmesg raw/ISO, journalctl short-iso, syslog)."""
    out = []
    for line in lines:
        m = XID_RE.search(line)
        if not m:
            continue
        code = int(m.group("code"))
        rest = m.group("rest")
        pid_m, name_m = PID_RE.search(rest), NAME_RE.search(rest)
        pid = pid_m.group("pid").strip() if pid_m else ""
        details = []
        fa, ft, en = FAULT_ADDR_RE.search(rest), FAULT_TYPE_RE.search(rest), ENGINE_RE.search(rest)
        if fa:
            details.append("fault VA %s" % fa.group(1).replace("_", ""))
        if ft:
            details.append("type %s" % " ".join(g for g in ft.groups() if g))
        if en:
            details.append("engine %s" % en.group(1))
        info = describe(code)
        out.append({"time": _timestamp(line.strip(), boot_epoch, year), "pci": m.group("pci"), "code": code,
                    "name": info["name"], "certain": info.get("certain", False),
                    "pid": int(pid) if pid.isdigit() else None,
                    "process": name_m.group("name").strip() if name_m else "",
                    "details": "; ".join(details) if details else rest.strip()[:200],
                    "forensic": info.get("forensic", ""), "raw": line.strip()})
    return out
