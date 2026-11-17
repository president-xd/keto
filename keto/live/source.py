"""Live sources: the real system, a recorder, and a replayer.

Every live plugin talks to the machine only through the small ``LiveSource``
interface below. ``RecordingSource`` wraps the real system and memoises each
call's result; ``keto acquire --method snapshot`` runs every live plugin under
it and stores the records in the evidence container. ``ReplaySource`` answers
the same calls from those records, so a snapshot taken during incident response
can be analysed later, elsewhere, with byte-identical plugin output.

Privacy: process environments are reduced to GPU/loader-relevant variables
(see ``ENV_KEEP``) before they reach any plugin or snapshot.
"""

from __future__ import annotations

import base64
import json
import os
import platform
import re
import socket
import stat as _stat
import subprocess
import time
from typing import Any, Dict, List, Optional

from keto.framework.exceptions import LiveSourceError

ENV_KEEP_PREFIXES = ("CUDA_", "NV", "NVIDIA_", "__GL_", "__NV", "LD_", "OPENCL", "OCL_", "VK_", "OMP_", "PYTORCH_",
                     "TF_", "XLA_", "TORCH_", "CUPY_", "NCCL_", "CUPTI", "DXG", "DISPLAY", "WAYLAND_DISPLAY",
                     "XDG_SESSION_TYPE", "KUBERNETES_", "DOCKER_", "container", "SINGULARITY", "APPTAINER")
ENV_KEEP_EXACT = {"PATH", "HOME", "USER", "LOGNAME", "SHELL", "PWD", "SUDO_USER", "SUDO_COMMAND", "SSH_CONNECTION"}
ALLOWED_COMMANDS = {"dpkg", "dpkg-query", "rpm", "modinfo", "dmesg", "journalctl", "nvidia-smi", "systemctl", "lspci",
                    "uname", "debsums", "sha256sum", "lsmod"}
MAX_TEXT = 4 << 20


def keep_env(key: str) -> bool:
    return key in ENV_KEEP_EXACT or key.startswith(ENV_KEEP_PREFIXES)


class LiveSource:
    kind = "abstract"

    def platform(self) -> Dict[str, Any]: ...
    def nvml(self) -> Dict[str, Any]: ...
    def cuda(self) -> Dict[str, Any]: ...
    def read_text(self, path: str, limit: int = MAX_TEXT) -> Optional[str]: ...
    def read_bytes(self, path: str, limit: int = MAX_TEXT) -> Optional[bytes]: ...
    def listdir(self, path: str) -> Optional[List[str]]: ...
    def readlink(self, path: str) -> Optional[str]: ...
    def stat(self, path: str) -> Optional[Dict[str, Any]]: ...
    def pids(self) -> List[int]: ...
    def proc(self, pid: int) -> Optional[Dict[str, Any]]: ...
    def command(self, argv: List[str], timeout: int = 30) -> Optional[Dict[str, Any]]: ...
    def proc_mem(self, pid: int, address: int, length: int) -> Optional[bytes]: ...
    def file_sha256(self, path: str) -> Optional[str]: ...
    def registry(self, key: str, name: str) -> Optional[Any]: ...  # HKLM value on Windows, else None
    # Windows process view (empty/None elsewhere)
    def win_processes(self) -> List[Dict[str, Any]]: return []
    def win_modules(self, pid: int) -> Optional[List[Dict[str, Any]]]: return None
    def win_windowed(self) -> List[int]: return []
    def win_gpu(self) -> Dict[str, Any]: return {"available": False, "processes": {}}
    def now(self) -> float: ...

    # convenience built on the primitives (identical for every implementation)
    def glob_dir(self, path: str, pattern: str) -> List[str]:
        names = self.listdir(path) or []
        rx = re.compile(pattern)
        return [os.path.join(path, n).replace("\\", "/") for n in sorted(names) if rx.search(n)]

    @property
    def is_linux(self) -> bool:
        return (self.platform() or {}).get("system") == "Linux"

    @property
    def is_wsl(self) -> bool:
        return bool((self.platform() or {}).get("wsl"))


class SystemSource(LiveSource):
    kind = "system"

    def __init__(self):
        self._nvml = None
        self._boot_time = None
        self._clk = None

    def platform(self):
        info = {"system": platform.system(), "release": platform.release(), "version": platform.version(),
                "machine": platform.machine(), "python": platform.python_version(), "hostname": socket.gethostname(),
                "self_pid": os.getpid()}
        try:
            with open("/proc/version") as fh:
                pv = fh.read()
            info["proc_version"] = pv.strip()
            info["wsl"] = "microsoft" in pv.lower()
        except OSError:
            info["wsl"] = False
        return info

    def nvml(self):
        if self._nvml is None:
            from keto.live import nvml
            try:
                self._nvml = nvml.collect()
            except Exception as exc:
                self._nvml = {"available": False, "error": repr(exc), "devices": []}
        return self._nvml

    def cuda(self):
        from keto.live.cuda import CudaDriver
        try:
            drv = CudaDriver()
            return {"available": True, "driver_version": drv.driver_version(), "devices": drv.devices()}
        except (LiveSourceError, OSError, AttributeError) as exc:
            return {"available": False, "error": str(exc)}

    def read_text(self, path, limit=MAX_TEXT):
        try:
            with open(path, "rb") as fh:
                return fh.read(limit).decode("utf-8", "replace")
        except (OSError, ValueError):
            return None

    def read_bytes(self, path, limit=MAX_TEXT):
        try:
            with open(path, "rb") as fh:
                return fh.read(limit)
        except (OSError, ValueError):
            return None

    def listdir(self, path):
        try:
            return sorted(os.listdir(path))
        except OSError:
            return None

    def readlink(self, path):
        try:
            return os.readlink(path)
        except OSError:
            return None

    def stat(self, path):
        try:
            st = os.lstat(path)
        except OSError:
            return None
        d = {"mode": st.st_mode, "perm": oct(st.st_mode & 0o7777), "uid": st.st_uid, "gid": st.st_gid,
             "size": st.st_size, "mtime": st.st_mtime, "ctime": st.st_ctime, "atime": st.st_atime,
             "is_dir": _stat.S_ISDIR(st.st_mode), "is_link": _stat.S_ISLNK(st.st_mode),
             "is_char": _stat.S_ISCHR(st.st_mode), "is_reg": _stat.S_ISREG(st.st_mode)}
        if d["is_char"] and hasattr(os, "major"):
            d["rdev_major"], d["rdev_minor"] = os.major(st.st_rdev), os.minor(st.st_rdev)
        return d

    def pids(self):
        names = self.listdir("/proc") or []
        return sorted(int(n) for n in names if n.isdigit())

    def _boot(self):
        if self._boot_time is None:
            txt = self.read_text("/proc/stat") or ""
            m = re.search(r"^btime (\d+)", txt, re.M)
            self._boot_time = int(m.group(1)) if m else None
            try:
                self._clk = os.sysconf("SC_CLK_TCK")
            except (ValueError, OSError, AttributeError):
                self._clk = 100
        return self._boot_time, self._clk

    def proc(self, pid):
        base = "/proc/%d" % pid
        status_txt = self.read_text(base + "/status")
        if status_txt is None:
            return None
        status = {}
        for line in status_txt.splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                status[k.strip()] = v.strip()
        raw_cmd = self.read_bytes(base + "/cmdline") or b""
        cmdline = [a.decode("utf-8", "replace") for a in raw_cmd.split(b"\x00") if a]
        env = None
        env_total = None
        raw_env = self.read_bytes(base + "/environ")
        if raw_env is not None:
            env, env_total = {}, 0
            for item in raw_env.split(b"\x00"):
                if b"=" in item:
                    env_total += 1
                    k, v = item.split(b"=", 1)
                    k = k.decode("utf-8", "replace")
                    if keep_env(k):
                        env[k] = v.decode("utf-8", "replace")
        start = None
        stat_txt = self.read_text(base + "/stat")
        if stat_txt:
            try:
                fields = stat_txt[stat_txt.rindex(")") + 2:].split()
                btime, clk = self._boot()
                if btime:
                    start = btime + int(fields[19]) / clk
            except (ValueError, IndexError):
                pass
        maps = []
        for line in (self.read_text(base + "/maps") or "").splitlines():
            parts = line.split(None, 5)
            if len(parts) < 5:
                continue
            lo, hi = parts[0].split("-")
            maps.append({"start": int(lo, 16), "end": int(hi, 16), "perms": parts[1], "offset": int(parts[2], 16),
                         "dev": parts[3], "inode": int(parts[4]), "path": parts[5] if len(parts) > 5 else ""})
        fds = []
        for fd in self.listdir(base + "/fd") or []:
            target = self.readlink("%s/fd/%s" % (base, fd))
            if target is not None:
                fds.append([int(fd), target])
        return {"pid": pid, "comm": (self.read_text(base + "/comm") or "").strip(), "cmdline": cmdline,
                "exe": self.readlink(base + "/exe"), "cwd": self.readlink(base + "/cwd"),
                "status": {k: status[k] for k in ("Name", "State", "PPid", "Uid", "Gid", "NSpid", "NSpgid",
                                                  "CapEff", "CapPrm", "TracerPid", "Seccomp", "Threads")
                           if k in status},
                "ppid": int(status.get("PPid", "0") or 0), "uid": int((status.get("Uid", "0").split() or ["0"])[0]),
                "tracer_pid": int(status.get("TracerPid", "0") or 0),
                "start_time": start, "environ": env, "environ_total": env_total, "maps": maps, "fds": fds,
                "cgroup": (self.read_text(base + "/cgroup") or "").strip()}

    def command(self, argv, timeout=30):
        if not argv or os.path.basename(argv[0]) not in ALLOWED_COMMANDS:
            raise LiveSourceError("command %r is not on the read-only allow list" % (argv[:1],))
        try:
            p = subprocess.run(argv, capture_output=True, timeout=timeout)
        except (OSError, subprocess.TimeoutExpired) as exc:
            return {"rc": None, "stdout": "", "stderr": str(exc)}
        return {"rc": p.returncode, "stdout": p.stdout[:MAX_TEXT].decode("utf-8", "replace"),
                "stderr": p.stderr[:65536].decode("utf-8", "replace")}

    def proc_mem(self, pid, address, length):
        try:
            with open("/proc/%d/mem" % pid, "rb") as fh:
                fh.seek(address)
                return fh.read(length)
        except (OSError, ValueError, OverflowError):
            return None

    def file_sha256(self, path):
        import hashlib
        h = hashlib.sha256()
        try:
            with open(path, "rb") as fh:
                for chunk in iter(lambda: fh.read(1 << 20), b""):
                    h.update(chunk)
        except OSError:
            return None
        return h.hexdigest()

    def registry(self, key, name):
        """Read ``HKEY_LOCAL_MACHINE\\<key>`` value ``name`` (Windows); None when absent or not Windows."""
        try:
            import winreg
        except ImportError:
            return None
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key) as k:
                value, _type = winreg.QueryValueEx(k, name)
        except OSError:
            return None
        return value if isinstance(value, (int, str)) else repr(value)

    def _win(self):
        if os.name != "nt":
            return None
        from keto.live import windows
        return windows

    def win_processes(self):
        w = self._win()
        return w.processes() if w else []

    def win_modules(self, pid):
        w = self._win()
        return w.modules(pid) if w else None

    def win_windowed(self):
        w = self._win()
        return w.windowed_pids() if w else []

    def win_gpu(self):
        w = self._win()
        if not w:
            return {"available": False, "processes": {}}
        if getattr(self, "_win_gpu", None) is None:
            self._win_gpu = w.gpu_counters()
        return self._win_gpu

    def now(self):
        return time.time()


def _key(method: str, args) -> str:
    return method + "|" + json.dumps(args, sort_keys=True, default=str)


def _encode(value):
    if isinstance(value, bytes):
        return {"_b64": base64.b64encode(value).decode()}
    return value


def _decode(value):
    if isinstance(value, dict) and "_b64" in value and len(value) == 1:
        return base64.b64decode(value["_b64"])
    return value


class RecordingSource(LiveSource):
    """Pass-through to a real source that remembers every answer."""

    kind = "recording"

    def __init__(self, inner: LiveSource):
        self.inner = inner
        self.records: Dict[str, Any] = {}
        self.created = time.time()

    def _rec(self, method, *args):
        k = _key(method, list(args))
        if k not in self.records:
            self.records[k] = _encode(getattr(self.inner, method)(*args))
        return _decode(self.records[k])

    def platform(self): return self._rec("platform")
    def nvml(self): return self._rec("nvml")
    def cuda(self): return self._rec("cuda")
    def read_text(self, path, limit=MAX_TEXT): return self._rec("read_text", path, limit)
    def read_bytes(self, path, limit=MAX_TEXT): return self._rec("read_bytes", path, limit)
    def listdir(self, path): return self._rec("listdir", path)
    def readlink(self, path): return self._rec("readlink", path)
    def stat(self, path): return self._rec("stat", path)
    def pids(self): return self._rec("pids")
    def proc(self, pid): return self._rec("proc", pid)
    def command(self, argv, timeout=30): return self._rec("command", list(argv), timeout)
    def proc_mem(self, pid, address, length): return self._rec("proc_mem", pid, address, length)
    def file_sha256(self, path): return self._rec("file_sha256", path)
    def registry(self, key, name): return self._rec("registry", key, name)
    def win_processes(self): return self._rec("win_processes")
    def win_modules(self, pid): return self._rec("win_modules", pid)
    def win_windowed(self): return self._rec("win_windowed")
    def win_gpu(self): return self._rec("win_gpu")

    def now(self):
        return self._rec("now")

    def snapshot(self) -> Dict[str, Any]:
        return {"format": "keto-live-snapshot/1", "created": self.created, "records": self.records}


class ReplaySource(LiveSource):
    """Answer live queries from a recorded snapshot."""

    kind = "snapshot"

    def __init__(self, snapshot: Dict[str, Any]):
        if snapshot.get("format") != "keto-live-snapshot/1":
            raise LiveSourceError("unsupported snapshot format %r" % snapshot.get("format"))
        self.records = snapshot.get("records", {})
        self.created = snapshot.get("created")
        self.misses: List[str] = []

    def _get(self, method, *args, default=None):
        k = _key(method, list(args))
        if k in self.records:
            return _decode(self.records[k])
        self.misses.append(k)
        return default

    def platform(self): return self._get("platform", default={})
    def nvml(self): return self._get("nvml", default={"available": False, "error": "not in snapshot", "devices": []})
    def cuda(self): return self._get("cuda", default={"available": False, "error": "not in snapshot"})
    def read_text(self, path, limit=MAX_TEXT): return self._get("read_text", path, limit)
    def read_bytes(self, path, limit=MAX_TEXT): return self._get("read_bytes", path, limit)
    def listdir(self, path): return self._get("listdir", path)
    def readlink(self, path): return self._get("readlink", path)
    def stat(self, path): return self._get("stat", path)
    def pids(self): return self._get("pids", default=[])
    def proc(self, pid): return self._get("proc", pid)
    def command(self, argv, timeout=30): return self._get("command", list(argv), timeout)
    def proc_mem(self, pid, address, length): return self._get("proc_mem", pid, address, length)
    def file_sha256(self, path): return self._get("file_sha256", path)

    def registry(self, key, name): return self._get("registry", key, name)
    def win_processes(self): return self._get("win_processes", default=[])
    def win_modules(self, pid): return self._get("win_modules", pid)
    def win_windowed(self): return self._get("win_windowed", default=[])
    def win_gpu(self): return self._get("win_gpu", default={"available": False, "processes": {}})

    def now(self):
        return self._get("now", default=self.created or 0.0)
