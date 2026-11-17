"""``keto acquire``: produce a hashed evidence container.

Methods
  snapshot  Record the live GPU/driver/process state by running every live
            plugin under a recording source (no device memory is touched).
  cuda      Allocate device memory through the CUDA driver API and copy it back
            *without initialising it*, capturing residual data left by earlier
            allocations (GPU memory remanence). Drivers that scrub memory between
            allocations (observed under WDDM/WSL2) yield zero pages, which is
            itself recorded as a finding. A snapshot is included unless
            ``--no-snapshot``.
  import    Wrap an existing dump (from a hypervisor, a PCIe DMA tool, a GPU
            debugger...) into a container with device metadata and hashes.
  process   Capture GPU processes' address spaces through /proc/<pid>/mem.
  kcore     Physical RAM of the running Linux/WSL2 kernel through /proc/kcore
            (root), with the kernel's BTF and symbols for offline analysis.
"""

from __future__ import annotations

import datetime as _dt
import json
import os
import platform
import time

from keto import __version__
from keto.formats.container import SPACE_IDS, ContainerWriter
from keto.framework.exceptions import RequirementError
from keto.framework.util import parse_size


def add_acquire_parser(sub):
    ap = sub.add_parser("acquire", help="acquire evidence into a .keto container")
    ap.add_argument("--method", choices=("snapshot", "cuda", "import", "process", "kcore"), default="snapshot")
    ap.add_argument("--pid", type=int, action="append", default=[],
                    help="process method: PID to capture (repeatable; one container per PID)")
    ap.add_argument("--gpu-processes", action="store_true",
                    help="process method: capture every process with evidence of GPU use")
    ap.add_argument("--max-mapping", type=parse_size, default=2 << 30,
                    help="process method: skip mappings larger than this (default 2G)")
    ap.add_argument("--out", required=True, help="output .keto path")
    ap.add_argument("--device", type=int, default=0, help="CUDA device ordinal (cuda method)")
    ap.add_argument("--size", type=parse_size, default=256 << 20,
                    help="bytes of device memory to capture (cuda method, default 256M)")
    ap.add_argument("--all-free", action="store_true",
                    help="capture all free device memory minus --reserve (cuda method)")
    ap.add_argument("--reserve", type=parse_size, default=512 << 20,
                    help="memory left free for the display/desktop with --all-free (default 512M)")
    ap.add_argument("--chunk", type=parse_size, default=64 << 20, help="allocation granularity (default 64M)")
    ap.add_argument("--no-snapshot", action="store_true", help="do not record live state")
    ap.add_argument("--input", help="dump to import (import method)")
    ap.add_argument("--space", default="vram", choices=sorted(SPACE_IDS), help="address space of --input")
    ap.add_argument("--address", type=lambda s: int(s, 0), default=0, help="start address of --input")
    ap.add_argument("--json-snapshot", help="also write the live snapshot as plain JSON to this path")
    ap.add_argument("--examiner", default="", help="examiner name / case reference stored in the metadata")


def _base_metadata(args) -> dict:
    return {"tool": "Keto", "tool_version": __version__,
            "created_utc": _dt.datetime.now(tz=_dt.timezone.utc).isoformat(),
            "acquisition": {"method": args.method, "examiner": args.examiner,
                            "host": {"system": platform.system(), "release": platform.release(),
                                     "machine": platform.machine(), "python": platform.python_version()}}}


def _device_metadata(nvml: dict, cuda: dict, ordinal: int) -> dict:
    dev = {}
    if cuda.get("available") and ordinal < len(cuda.get("devices", [])):
        c = cuda["devices"][ordinal]
        dev.update(name=c["name"], uuid=c["uuid"], compute_capability=c["compute_capability"],
                   vram_size=c["total_memory"], pci_bus_id=c["pci_bus_id"])
        dev["cuda_driver_version"] = cuda.get("driver_version")
    for d in nvml.get("devices", []):
        if dev.get("uuid") and d.get("uuid") != dev["uuid"]:
            continue
        arch = d.get("architecture")
        if isinstance(arch, dict):
            dev["nvml_arch"] = arch.get("id")
            dev["architecture"] = arch.get("name")
        dev.setdefault("name", d.get("name"))
        dev["vbios_version"] = d.get("vbios_version")
        dev["driver_version"] = nvml.get("driver_version")
        break
    return dev


def record_snapshot(ctx_factory) -> dict:
    """Run every live plugin under a RecordingSource; return the snapshot dict."""
    from keto.framework.plugin import PLUGINS, load_plugins
    from keto.live.source import RecordingSource, SystemSource
    load_plugins()
    rec = RecordingSource(SystemSource())
    rec.platform()
    rec.nvml()
    rec.cuda()
    rec.now()
    errors = {}
    for name in sorted(PLUGINS):
        cls = PLUGINS[name]
        if "live" not in cls.SOURCES or not getattr(cls, "SNAPSHOT", True):
            continue
        ctx = ctx_factory()
        ctx.set_live_source(rec)
        try:
            _ = cls(ctx, {}).run().rows
        except Exception as exc:  # record but keep going: a snapshot must be best-effort
            errors[name] = "%s: %s" % (type(exc).__name__, exc)
    snap = rec.snapshot()
    snap["plugin_errors"] = errors
    return snap


def _acquire_process(args, out) -> int:
    """Capture the readable address space of GPU process(es) through /proc/<pid>/mem.

    Needs root (or CAP_SYS_PTRACE) for processes that are not descendants of the
    caller when kernel.yama.ptrace_scope >= 1. Each PID gets its own container whose
    'process' segments are keyed by virtual address."""
    from keto.live import procfs
    from keto.live.source import SystemSource
    src = SystemSource()
    pids = list(args.pid)
    if args.gpu_processes:
        own = os.getpid()
        pids += [p for p in procfs.gpu_processes(src) if p != own and src.proc(p) is not None]
    if not pids:
        raise RequirementError("process method needs --pid or --gpu-processes")
    device = _device_metadata(src.nvml(), src.cuda(), args.device)
    stem, ext = os.path.splitext(args.out)
    for pid in sorted(set(pids)):
        proc = src.proc(pid)
        if proc is None:
            out.write("pid %d: not found / not readable\n" % pid)
            continue
        path = args.out if len(set(pids)) == 1 else "%s-%d%s" % (stem, pid, ext or ".keto")
        meta = _base_metadata(args)
        meta["device"] = device
        meta["process"] = {k: proc.get(k) for k in ("pid", "comm", "cmdline", "exe", "uid", "ppid", "start_time")}
        meta["process"]["gpu_evidence"] = sorted(procfs.gpu_processes(src).get(pid, {}).get("evidence", []))
        captured, skipped = [], []
        writer = ContainerWriter(path, meta)
        t0 = time.time()
        try:
            with open("/proc/%d/mem" % pid, "rb", buffering=0) as mem:
                for m in proc["maps"]:
                    size = m["end"] - m["start"]
                    if "r" not in m["perms"] or m["path"] in ("[vvar]", "[vsyscall]", "[vvar_vclock]") or \
                            size > args.max_mapping:
                        skipped.append({"start": m["start"], "end": m["end"], "path": m["path"],
                                        "reason": "not readable" if "r" not in m["perms"] else
                                        ("too large" if size > args.max_mapping else "kernel page")})
                        continue

                    def chunks(m=m):
                        pos = m["start"]
                        while pos < m["end"]:
                            n = min(4 << 20, m["end"] - pos)
                            mem.seek(pos)
                            yield mem.read(n)
                            pos += n
                    try:
                        data = b"".join(chunks())
                    except OSError as exc:
                        skipped.append({"start": m["start"], "end": m["end"], "path": m["path"], "reason": str(exc)})
                        continue
                    writer.add_segment("process", m["start"], data)
                    captured.append({"start": m["start"], "end": m["end"], "perms": m["perms"], "path": m["path"]})
        except PermissionError as exc:
            raise RequirementError("cannot read /proc/%d/mem (%s): run as root or use a descendant process"
                                   % (pid, exc))
        finally:
            meta["process"]["mappings"] = captured
            meta["process"]["skipped"] = skipped
            meta["acquisition"]["notes"] = ("process memory via /proc/%d/mem: %d mapping(s) captured, %d skipped"
                                            % (pid, len(captured), len(skipped)))
            writer.metadata = meta
            writer.close()
        out.write("pid %d (%s): %d mappings, %d bytes -> %s in %.1fs (%d skipped)\n" % (
            pid, proc["comm"], len(captured), sum(s.length for s in writer.segments), path, time.time() - t0,
            len(skipped)))
    return 0


def run_acquire(args, out) -> int:
    from keto.framework.context import Context
    if args.method == "process":
        return _acquire_process(args, out)
    if args.method == "kcore":
        from keto.acquire.kcore import acquire_kcore
        return acquire_kcore(args, out, _base_metadata(args))
    meta = _base_metadata(args)
    t0 = time.time()
    snapshot = None
    if args.method in ("snapshot", "cuda") and not args.no_snapshot:
        out.write("recording live snapshot (running live plugins)...\n")
        snapshot = record_snapshot(lambda: Context())
        meta["live_snapshot"] = snapshot
        rec = snapshot["records"]
        nv = rec.get('nvml|[]', {})
        cu = rec.get('cuda|[]', {})
        meta["device"] = _device_metadata(nv, cu, args.device)
        if args.json_snapshot:
            with open(args.json_snapshot, "w", encoding="utf-8") as fh:
                json.dump(snapshot, fh)
    elif args.method in ("snapshot", "cuda", "import"):
        from keto.live.source import SystemSource
        src = SystemSource()
        meta["device"] = _device_metadata(src.nvml(), src.cuda(), args.device)
    writer = ContainerWriter(args.out, meta)
    try:
        if args.method == "cuda":
            _acquire_cuda(args, writer, meta, out)
        elif args.method == "import":
            if not args.input or not os.path.exists(args.input):
                raise RequirementError("--input must name an existing dump for the import method")

            def chunks(path):
                with open(path, "rb") as fh:
                    for c in iter(lambda: fh.read(1 << 22), b""):
                        yield c

            writer.add_segment(args.space, args.address, chunks(args.input))
            meta["acquisition"]["source_file"] = os.path.abspath(args.input)
    finally:
        writer.metadata = meta
        writer.close()
    out.write("wrote %s (%d segment(s)) in %.1fs\n" % (args.out, len(writer.segments), time.time() - t0))
    for s, h in zip(writer.segments, writer.hashes):
        out.write("  %-8s 0x%012x %10d bytes sha256=%s\n" % (s.space_name, s.address, s.length, h))
    return 0


def _acquire_cuda(args, writer: ContainerWriter, meta: dict, out):
    from keto.live.cuda import CudaDriver
    drv = CudaDriver()
    drv.create_context(args.device)
    free, total = drv.mem_info()
    target = max(0, free - args.reserve) if args.all_free else min(args.size, free)
    chunk = max(1 << 20, args.chunk)
    ptrs, stats = [], []
    done = 0
    try:
        while done < target:
            size = min(chunk, target - done)
            ptr = drv.try_alloc(size)
            if ptr is None:
                if chunk > (2 << 20):
                    chunk //= 2
                    continue
                break
            ptrs.append(ptr)
            data = drv.read(ptr, size)
            zero = data.count(0)
            stats.append({"va": ptr, "size": size, "zero_bytes": zero, "nonzero_bytes": size - zero})
            writer.add_segment("residual", ptr, data)
            done += size
            out.write("  captured 0x%x +%d (%.1f%% zero)\n" % (ptr, size, 100.0 * zero / size))
    finally:
        for p in ptrs:
            drv.free(p)
        drv.destroy_context()
    nonzero = sum(s["nonzero_bytes"] for s in stats)
    meta["acquisition"].update(device_free_before=free, device_total=total, captured=done, chunks=stats,
                               nonzero_bytes=nonzero,
                               notes=("Residual capture via uninitialised cuMemAlloc+cuMemcpyDtoH. "
                                      + ("All captured pages were zero: the driver scrubs device memory "
                                         "between allocations on this platform." if nonzero == 0 else
                                         "Non-zero residual data present: memory was NOT scrubbed.")))
