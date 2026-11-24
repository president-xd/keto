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
  pramin    Physical VRAM through the BAR0 PRAMIN window (Linux, root; see
            keto/acquire/pramin.py and docs/ACQUISITION.md).
  livedump  Windows live kernel memory dump (NtSystemDebugControl, elevated),
            converted to physical-memory segments (keto/acquire/livedump.py).
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import platform
import time

from keto import __version__
from keto.formats.container import SPACE_IDS, ContainerWriter
from keto.framework.exceptions import RequirementError, UnsupportedError
from keto.framework.util import parse_size


def add_acquire_parser(sub):
    ap = sub.add_parser("acquire", help="acquire evidence into a .keto container")
    ap.add_argument("--method", choices=("snapshot", "cuda", "import", "process", "kcore", "pramin", "livedump"),
                    default="snapshot")
    ap.add_argument("--include-user-pages", action="store_true",
                    help="livedump method: also capture user-mode memory (needed for process memory, PEB and "
                         "environment analysis)")
    ap.add_argument("--hypervisor-pages", action="store_true", help="livedump method: also capture hypervisor pages")
    ap.add_argument("--keep-dump", action="store_true",
                    help="livedump method: keep Windows' original .dmp next to the container")
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
    ap.add_argument("--force", action="store_true",
                    help="replace an existing --out file (by default existing evidence is never overwritten)")
    ap.add_argument("--phys-range", action="append", default=[], metavar="START-END",
                    help="kcore method: acquire only this physical range, end exclusive (hex, decimal or a size "
                         "such as 4G; repeatable)")
    ap.add_argument("--max-bytes", type=parse_size, default=None,
                    help="kcore method: stop once this much non-zero data is stored (e.g. 2G)")
    ap.add_argument("--live-device", action="store_true",
                    help="import method: record THIS machine's GPU (NVML/CUDA) as the dump's device; only correct "
                         "when the dump was taken from this machine's GPU")
    ap.add_argument("--pci", metavar="BDF", help="pramin method: PCI address of the GPU (e.g. 0000:01:00.0); "
                                                 "required when there are several NVIDIA GPUs")
    ap.add_argument("--allow-bound-driver", action="store_true",
                    help="pramin method: proceed although a GPU driver is bound. RISK: the driver's own PRAMIN "
                         "accesses during the acquisition can corrupt VRAM or hang the GPU; recorded as "
                         "driver_active=true")
    ap.add_argument("--start", type=parse_size, default=None,
                    help="pramin method: first VRAM address to read (default 0; rounded down to 4 KiB)")
    ap.add_argument("--length", type=parse_size, default=None,
                    help="pramin method: bytes of VRAM to read (default: up to the VRAM size; rounded up to 4 KiB)")
    ap.add_argument("--passes", type=int, default=1,
                    help="pramin method: read the range N times; pages that change between passes are recorded "
                         "(only the first pass is stored)")
    ap.add_argument("--bulk-mmio", action="store_true",
                    help="pramin method: read the aperture with memcpy instead of 32-bit loads (faster; the CPU may "
                         "issue wider loads to BAR0)")
    ap.add_argument("--vram-size", type=parse_size, default=argparse.SUPPRESS,
                    help="pramin method: VRAM size when no cited register or NVML gives it (e.g. 8G)")


def check_output(path: str, force: bool, inputs=()) -> None:
    """Refuse to destroy evidence: an existing ``path`` needs ``force``, and ``path`` may never be one of the
    ``inputs`` (an in-place import would truncate the dump before reading it)."""
    for src in inputs:
        if src and os.path.exists(src) and os.path.exists(path) and os.path.samefile(src, path):
            raise RequirementError("--out %s is the input file itself: refusing to overwrite the evidence" % path)
    if os.path.exists(path) and not force:
        raise RequirementError("%s already exists: refusing to overwrite it (choose another --out, or --force)"
                               % path)
    parent = os.path.dirname(os.path.abspath(path))
    if not os.path.isdir(parent):
        raise RequirementError("output directory does not exist: %s" % parent)


def report_written(out, writer: ContainerWriter) -> None:
    out.write("evidence fingerprint (record it in the case notes; check with "
              "'verify --expected-fingerprint'): %s\n" % writer.fingerprint)


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
    errors, not_applicable = {}, {}
    for name in sorted(PLUGINS):
        cls = PLUGINS[name]
        if "live" not in cls.SOURCES or not getattr(cls, "SNAPSHOT", True):
            continue
        ctx = ctx_factory()
        ctx.set_live_source(rec)
        try:
            _ = cls(ctx, {}).run().rows
        except (UnsupportedError, RequirementError) as exc:  # e.g. a Windows-only plugin on Linux
            not_applicable[name] = str(exc)
        except Exception as exc:  # record but keep going: a snapshot must be best-effort
            errors[name] = "%s: %s" % (type(exc).__name__, exc)
    snap = rec.snapshot()
    snap["plugin_errors"] = errors
    snap["plugins_not_applicable"] = not_applicable
    return snap


def windows_gpu_pids(src) -> dict:
    """``pid -> [evidence]`` for Windows processes using a GPU engine or GPU memory, or loading a GPU compute
    runtime."""
    from keto.plugins.windows.gpu import runtimes
    out = {}
    for pid_s, g in (src.win_gpu().get("processes") or {}).items():
        if any(u > 0 for u in (g.get("engines") or {}).values()) or g.get("dedicated"):
            out.setdefault(int(pid_s), []).append("gpu-counters")
    for p in src.win_processes():
        rts = [r for r in runtimes(src.win_modules(p["pid"])) if r[1]]
        if rts:
            out.setdefault(p["pid"], []).append("runtime:" + ",".join(sorted({r[0] for r in rts})))
    return out


def _acquire_process_windows(args, out) -> int:
    """Windows: committed, accessible regions through VirtualQueryEx + ReadProcessMemory, keyed by virtual address,
    with each region's protection, type and backing file (needs PROCESS_VM_READ: same user, or Administrator)."""
    from keto.live import windows as w
    from keto.live.source import SystemSource
    src = SystemSource()
    pids = list(args.pid)
    evidence = windows_gpu_pids(src) if args.gpu_processes else {}
    if args.gpu_processes:
        pids += [p for p in evidence if p not in (os.getpid(), 0, 4)]
    if not pids:
        raise RequirementError("process method needs --pid or --gpu-processes")
    device = _device_metadata(src.nvml(), src.cuda(), args.device)
    procs = {p["pid"]: p for p in src.win_processes()}
    stem, ext = os.path.splitext(args.out)
    pids = sorted(set(pids))
    paths = {pid: args.out if len(pids) == 1 else "%s-%d%s" % (stem, pid, ext or ".keto") for pid in pids}
    for p in paths.values():
        check_output(p, args.force)
    written = 0
    for pid in pids:
        info = procs.get(pid)
        if info is None:
            out.write("pid %d: not found\n" % pid)
            continue
        try:
            h, regs = w.regions(pid)
        except PermissionError as exc:
            out.write("pid %d (%s): %s - run as Administrator for other users' processes\n" % (pid, info["name"], exc))
            continue
        path = paths[pid]
        meta = _base_metadata(args)
        meta["device"] = device
        meta["process"] = {"pid": pid, "comm": info["name"], "exe": info.get("path"), "ppid": info.get("ppid"),
                           "cmdline": src.win_cmdline(pid), "gpu_evidence": evidence.get(pid, []),
                           "platform": "Windows"}
        captured, skipped = [], []
        writer = ContainerWriter(path, meta, exclusive=not args.force)
        t0 = time.time()
        status = "complete"
        try:
            for r in regs:
                size = r["end"] - r["start"]
                if size > args.max_mapping:
                    skipped.append(dict(r, reason="too large"))
                    continue
                bad = 0
                for pos in range(r["start"], r["end"], 4 << 20):  # bounded memory: one 4 MiB block at a time
                    data, nbad = w.read_region(h, pos, min(4 << 20, r["end"] - pos))
                    writer.append("process", pos, data)
                    bad += nbad
                captured.append({"start": r["start"], "end": r["end"], "perms": r["perms"], "path": r["path"],
                                 "type": r["type"], "unreadable": bad})
        except BaseException as exc:
            status = "incomplete: %s: %s" % (type(exc).__name__, exc)
            raise
        finally:
            w.close_handle(h)
            meta["process"]["mappings"] = captured
            meta["process"]["skipped"] = skipped
            meta["acquisition"]["status"] = status
            meta["acquisition"]["notes"] = ("process memory via ReadProcessMemory: %d region(s) captured, %d skipped"
                                            % (len(captured), len(skipped)))
            writer.metadata = meta
            writer.close()
        written += 1
        out.write("pid %d (%s): %d regions, %d bytes -> %s in %.1fs (%d skipped)\n" % (
            pid, info["name"], len(captured), sum(s.length for s in writer.segments), path, time.time() - t0,
            len(skipped)))
        report_written(out, writer)
    if not written:
        raise RequirementError("no process was captured")
    return 0


def _acquire_process(args, out) -> int:
    """Capture the readable address space of GPU process(es) through /proc/<pid>/mem.

    Needs root (or CAP_SYS_PTRACE) for processes that are not descendants of the
    caller when kernel.yama.ptrace_scope >= 1. Each PID gets its own container whose
    'process' segments are keyed by virtual address."""
    if os.name == "nt":
        return _acquire_process_windows(args, out)
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
    pids = sorted(set(pids))
    paths = {pid: args.out if len(pids) == 1 else "%s-%d%s" % (stem, pid, ext or ".keto") for pid in pids}
    for p in paths.values():
        check_output(p, args.force)
    written = 0
    for pid in pids:
        proc = src.proc(pid)
        if proc is None:
            out.write("pid %d: not found / not readable\n" % pid)
            continue
        path = paths[pid]
        meta = _base_metadata(args)
        meta["device"] = device
        meta["process"] = {k: proc.get(k) for k in ("pid", "comm", "cmdline", "exe", "uid", "ppid", "start_time")}
        meta["process"]["gpu_evidence"] = sorted(procfs.gpu_processes(src).get(pid, {}).get("evidence", []))
        captured, skipped = [], []
        try:
            mem = open("/proc/%d/mem" % pid, "rb", buffering=0)
        except PermissionError as exc:
            out.write("pid %d (%s): cannot read /proc/%d/mem (%s): run as root or use a descendant process\n"
                      % (pid, proc["comm"], pid, exc))
            continue
        writer = ContainerWriter(path, meta, exclusive=not args.force)
        t0 = time.time()
        status = "complete"
        try:
            with mem:
                for m in proc["maps"]:
                    size = m["end"] - m["start"]
                    if "r" not in m["perms"] or m["path"] in ("[vvar]", "[vsyscall]", "[vvar_vclock]") or \
                            size > args.max_mapping:
                        skipped.append({"start": m["start"], "end": m["end"], "path": m["path"],
                                        "reason": "not readable" if "r" not in m["perms"] else
                                        ("too large" if size > args.max_mapping else "kernel page")})
                        continue
                    bad = _copy_mapping(mem, writer, m["start"], m["end"])
                    captured.append({"start": m["start"], "end": m["end"], "perms": m["perms"], "path": m["path"],
                                     "unreadable": bad})
        except BaseException as exc:
            status = "incomplete: %s: %s" % (type(exc).__name__, exc)
            raise
        finally:
            meta["process"]["mappings"] = captured
            meta["process"]["skipped"] = skipped
            meta["acquisition"]["status"] = status
            meta["acquisition"]["notes"] = ("process memory via /proc/%d/mem: %d mapping(s) captured, %d skipped"
                                            % (pid, len(captured), len(skipped)))
            writer.metadata = meta
            writer.close()
        written += 1
        out.write("pid %d (%s): %d mappings, %d bytes -> %s in %.1fs (%d skipped)\n" % (
            pid, proc["comm"], len(captured), sum(s.length for s in writer.segments), path, time.time() - t0,
            len(skipped)))
        report_written(out, writer)
    if not written:
        raise RequirementError("no process was captured")
    return 0


def _copy_mapping(mem, writer: ContainerWriter, start: int, end: int, block: int = 4 << 20) -> int:
    """Stream ``[start, end)`` of a /proc/<pid>/mem handle into the container, one block at a time. A block that
    fails or reads short is retried page by page; unreadable pages are left out (a gap in the segment list, never
    zeros) and counted. Returns the number of unreadable bytes."""
    bad = 0
    pos = start
    while pos < end:
        n = min(block, end - pos)
        try:
            mem.seek(pos)
            data = mem.read(n)
        except (OSError, ValueError, OverflowError):
            data = b""
        if len(data) == n:
            writer.append("process", pos, data)
        else:
            for p in range(pos, pos + n, 0x1000):
                m = min(0x1000, pos + n - p)
                try:
                    mem.seek(p)
                    page = mem.read(m)
                except (OSError, ValueError, OverflowError):
                    page = b""
                if page:
                    writer.append("process", p, page)
                bad += m - len(page)
        pos += n
    return bad


def run_acquire(args, out) -> int:
    from keto.framework.context import Context
    if args.method == "process":
        return _acquire_process(args, out)
    if args.method == "import":
        if not args.input or not os.path.isfile(args.input):
            raise RequirementError("--input must name an existing dump file for the import method")
        if os.path.getsize(args.input) == 0:
            raise RequirementError("--input %s is empty" % args.input)
        check_output(args.out, args.force, inputs=[args.input])
    else:
        check_output(args.out, args.force)
    if args.json_snapshot:
        check_output(args.json_snapshot, args.force, inputs=[args.out])
    if args.method == "kcore":
        from keto.acquire.kcore import acquire_kcore
        return acquire_kcore(args, out, _base_metadata(args))
    if args.method == "pramin":
        from keto.acquire.pramin import acquire_pramin
        return acquire_pramin(args, out, _base_metadata(args))
    if args.method == "livedump":
        from keto.acquire.livedump import acquire_livedump
        return acquire_livedump(args, out, _base_metadata(args))
    if args.method == "import" and args.space == "sysmem":
        from keto.formats.memimage import detect
        fmt = detect(args.input)
        if fmt not in (None, "container"):  # a crash dump, hiberfil, ELF core, VMware or LiME image: map pages
            from keto.acquire.livedump import dump_to_container
            meta = _base_metadata(args)
            meta["acquisition"]["source_file"] = os.path.abspath(args.input)
            meta["acquisition"]["source_format"] = fmt
            writer = dump_to_container(args.input, args.out, meta, force=args.force)
            out.write("imported %s image %s as physical memory (%d segment(s))\n" % (fmt, args.input,
                                                                                   len(writer.segments)))
            report_written(out, writer)
            return 0
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
    elif args.method in ("snapshot", "cuda") or (args.method == "import" and args.live_device):
        # an imported dump comes from wherever it was taken: this machine's GPU is recorded only on request
        from keto.live.source import SystemSource
        src = SystemSource()
        meta["device"] = _device_metadata(src.nvml(), src.cuda(), args.device)
        if args.method == "import":
            meta["device"]["source"] = "recorded from the acquiring machine (--live-device)"
    writer = ContainerWriter(args.out, meta, exclusive=not args.force)
    status = "complete"
    try:
        if args.method == "cuda":
            _acquire_cuda(args, writer, meta, out)
        elif args.method == "import":
            meta["acquisition"]["source_file"] = os.path.abspath(args.input)
            meta["acquisition"]["source_size"] = os.path.getsize(args.input)
            with open(args.input, "rb") as fh:
                pos = args.address
                for c in iter(lambda: fh.read(1 << 22), b""):
                    writer.append(args.space, pos, c)
                    pos += len(c)
    except BaseException as exc:
        status = "incomplete: %s: %s" % (type(exc).__name__, exc)
        raise
    finally:
        meta["acquisition"]["status"] = status
        writer.metadata = meta
        writer.close()
    out.write("wrote %s (%d segment(s)) in %.1fs\n" % (args.out, len(writer.segments), time.time() - t0))
    for s, h in zip(writer.segments, writer.hashes):
        out.write("  %-8s 0x%012x %10d bytes sha256=%s\n" % (s.space_name, s.address, s.length, h))
    report_written(out, writer)
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
