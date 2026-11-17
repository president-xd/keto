"""WSL2 GPU paravirtualisation (``drivers/hv/dxgkrnl``) and Linux task objects in kernel memory.

Object tree (``dxgkrnl.h``, WSL2-Linux-Kernel)::

    dxgdrv.dxgglobal -> plisthead -> dxgprocess {pid, tgid, vpid, nspid, host_handle, handle_table}
      -> process_adapter_list_head -> dxgprocess_adapter {adapter, device_list_head}
           -> dxgdevice {context_list_head, alloc_list_head, resource_list_head, pqueue_list_head,
                         syncobj_list_head}
                -> dxgcontext -> hwqueue_list_head -> dxghwqueue
                -> dxgallocation {num_pages, cpu_address, pages}
                -> dxgresource -> alloc_list_head -> dxgallocation

``/dev/dxg`` file handles carry ``private_data`` = the opener's ``dxgprocess`` and ``f_op`` = ``dxgk_fops``.
Every walk is bounded and every unreadable pointer is recorded instead of aborting the walk.
"""

from __future__ import annotations

from collections import Counter
from typing import Dict, Iterator, List, Optional

from keto.framework.exceptions import InvalidAddressException, KetoError
from keto.hostmem.btf import BtfError
from keto.hostmem.linux import KernelMemory, KObj

HMGR_TYPES = {1: "adapter", 2: "sharedresource", 3: "device", 4: "resource", 5: "allocation", 6: "overlay",
              7: "context", 8: "syncobject", 9: "keyedmutex", 10: "pagingqueue", 11: "devicesyncobject",
              12: "process", 13: "sharedvmobject", 14: "protectedsession", 15: "hwqueue", 16: "remotebundle",
              17: "compsurface", 18: "compsurfaceproxy", 19: "trackedworkload",
              32: "monitoredfence"}  # hmgr.h: HMGRENTRY_TYPE_MONITOREDFENCE = HMGRENTRY_TYPE_LIMIT (31) + 1
MAX_HANDLES = 1 << 20


def _u(value) -> int:
    """Integer value of a field that may be a small struct (``struct d3dkmthandle {union {...; u32 v}}``,
    ``struct winluid {a, b}``)."""
    if isinstance(value, KObj):
        return int.from_bytes(value.raw, "little")
    if isinstance(value, (bytes, bytearray)):
        return int.from_bytes(value[:8], "little")
    return value


def pidns_inum(km: KernelMemory, ns_va: int) -> Optional[int]:
    """``pid_namespace.ns.inum`` (the number shown in /proc/<pid>/ns/pid) or None."""
    if not ns_va:
        return None
    try:
        return km.obj("pid_namespace", ns_va)["ns.inum"]
    except (InvalidAddressException, BtfError):
        return None


def _safe_list(obj: KObj, head, etype, link, errors: List[str]) -> List[KObj]:
    out = []
    try:
        for e in obj.list(head, etype, link):
            out.append(e)
    except (InvalidAddressException, BtfError) as exc:
        errors.append("%s.%s: %s" % (obj.t.name, head, exc))
    return out


def adapter_info(km: KernelMemory, va: int, errors: List[str]) -> dict:
    try:
        a = km.obj("dxgadapter", va)
        return {"va": va, "description": a.string("device_description", utf16=True),
                "luid": _u(a["luid"]), "compute_only": bool(a["compute_only"]), "host_handle": _u(a["host_handle"]),
                "state": a["adapter_state"]}
    except (InvalidAddressException, BtfError) as exc:
        errors.append("dxgadapter@0x%x: %s" % (va, exc))
        return {"va": va, "description": "?", "luid": None, "compute_only": None, "host_handle": None,
                "state": None}


def _allocation(a: KObj) -> dict:
    return {"va": a.va, "handle": _u(a["alloc_handle"]), "num_pages": a["num_pages"], "cpu_address": a["cpu_address"],
            "pages": a["pages"], "cpu_mapped": bool(a["cpu_address_mapped"]), "cached": bool(a["cached"]),
            "resource_owner": bool(a["resource_owner"])}


def walk_handles(km: KernelMemory, table: KObj, errors: List[str]) -> Counter:
    counts: Counter = Counter()
    try:
        size, base = table["table_size"], table["entry_table"]
        if not base or not 0 < size <= MAX_HANDLES:
            return counts
        ent_t = km.btf.struct("hmgrentry")
        esz = ent_t.size
        data = km.read(base, size * esz)
        toff, _, tbits = km.btf.member(ent_t, "type")
        doff, _, dbits = km.btf.member(ent_t, "destroyed")
        for i in range(size):
            word = int.from_bytes(data[i * esz:(i + 1) * esz], "little")
            typ = (word >> toff) & ((1 << tbits) - 1)
            if typ:
                name = HMGR_TYPES.get(typ, "type%d" % typ)
                counts[name + (" (destroyed)" if (word >> doff) & 1 else "")] += 1
    except (InvalidAddressException, BtfError) as exc:
        errors.append("hmgrtable@0x%x: %s" % (table.va, exc))
    return counts


def walk_processes(km: KernelMemory) -> dict:
    """Everything reachable from ``dxgdrv.dxgglobal``."""
    errors: List[str] = []
    drv = km.obj("dxgdriver", km.sym("dxgdrv"))
    g_va = drv["dxgglobal"]
    out = {"dxgglobal": g_va, "adapters": [], "processes": [], "errors": errors}
    if not g_va:
        return out
    g = km.obj("dxgglobal", g_va)
    out["num_adapters"] = g["num_adapters"]
    out["vmbus_ver"] = g["vmbus_ver"]
    for a in _safe_list(g, "adapter_list_head", "dxgadapter", "adapter_list_entry", errors):
        out["adapters"].append(adapter_info(km, a.va, errors))
    for p in _safe_list(g, "plisthead", "dxgprocess", "plistentry", errors):
        try:
            rec = {"va": p.va, "pid": p["pid"], "tgid": p["tgid"], "vpid": p["vpid"], "nspid": p["nspid"],
                   "pidns": pidns_inum(km, p["nspid"]), "host_handle": _u(p["host_handle"]), "adapters": [], "devices": 0, "contexts": 0, "hwqueues": 0,
                   "allocations": [], "resources": 0, "pagingqueues": 0, "syncobjects": 0}
        except (InvalidAddressException, BtfError) as exc:
            errors.append("dxgprocess@0x%x: %s" % (p.va, exc))
            continue
        for pa in _safe_list(p, "process_adapter_list_head", "dxgprocess_adapter", "process_adapter_list_entry",
                             errors):
            try:
                rec["adapters"].append(adapter_info(km, pa["adapter"], errors))
            except (InvalidAddressException, BtfError) as exc:
                errors.append("dxgprocess_adapter@0x%x: %s" % (pa.va, exc))
                continue
            for dev in _safe_list(pa, "device_list_head", "dxgdevice", "device_list_entry", errors):
                rec["devices"] += 1
                for ctx in _safe_list(dev, "context_list_head", "dxgcontext", "context_list_entry", errors):
                    rec["contexts"] += 1
                    rec["hwqueues"] += len(_safe_list(ctx, "hwqueue_list_head", "dxghwqueue", "hwqueue_list_entry",
                                                      errors))
                for a in _safe_list(dev, "alloc_list_head", "dxgallocation", "alloc_list_entry", errors):
                    rec["allocations"].append(_allocation(a))
                for r in _safe_list(dev, "resource_list_head", "dxgresource", "resource_list_entry", errors):
                    rec["resources"] += 1
                    for a in _safe_list(r, "alloc_list_head", "dxgallocation", "alloc_list_entry", errors):
                        rec["allocations"].append(_allocation(a))
                rec["pagingqueues"] += len(_safe_list(dev, "pqueue_list_head", "dxgpagingqueue", "pqueue_list_entry",
                                                      errors))
                rec["syncobjects"] += len(_safe_list(dev, "syncobj_list_head", "dxgsyncobject", "syncobj_list_entry",
                                                     errors))
        rec["handles"] = dict(walk_handles(km, p["handle_table"], errors))
        out["processes"].append(rec)
    return out


# -- Linux tasks and their open files ------------------------------------------------------------------------
def walk_tasks(km: KernelMemory, limit: int = 1 << 16) -> Iterator[dict]:
    """Thread-group leaders on ``init_task.tasks``."""
    init = km.obj("task_struct", km.sym("init_task"))
    for t in [init] + list(init.list("tasks", "task_struct", "tasks", limit)):
        try:
            yield {"va": t.va, "pid": t["pid"], "tgid": t["tgid"], "comm": t.string("comm"), "files": t["files"],
                   "mm": t["mm"]}
        except (InvalidAddressException, BtfError):
            continue


def task_files(km: KernelMemory, files_va: int, max_fds: int = 1 << 16) -> Iterator[tuple]:
    """``(fd, file va, f_op, private_data)`` for every open file of a ``files_struct``."""
    if not files_va:
        return
    fs = km.obj("files_struct", files_va)
    fdt = km.obj("fdtable", fs["fdt"])
    n = min(fdt["max_fds"], max_fds)
    arr = fdt["fd"]
    if not arr or not n:
        return
    ptrs = km.read(arr, n * 8)
    f_op_off = km.btf.offsetof("file", "f_op")
    pd_off = km.btf.offsetof("file", "private_data")
    for fd in range(n):
        fva = int.from_bytes(ptrs[fd * 8:fd * 8 + 8], "little")
        if not fva:
            continue
        try:
            raw = km.read(fva, max(f_op_off, pd_off) + 8)
        except InvalidAddressException:
            continue
        yield fd, fva, int.from_bytes(raw[f_op_off:f_op_off + 8], "little"), \
            int.from_bytes(raw[pd_off:pd_off + 8], "little")


def dxg_cross_view(km: KernelMemory) -> dict:
    """Join dxgprocess objects with tasks and the ``/dev/dxg`` files they hold."""
    walk = walk_processes(km)
    fops = km.symbols.get("dxgk_fops")
    tasks = list(walk_tasks(km))
    by_tgid = {t["tgid"]: t for t in tasks}
    holders: Dict[int, List[tuple]] = {}  # dxgprocess va -> [(pid, comm, fd)]
    task_errors = 0
    if fops:
        for t in tasks:
            try:
                for fd, _fva, f_op, priv in task_files(km, t["files"]):
                    if f_op == fops:
                        holders.setdefault(priv, []).append((t["pid"], t["comm"], fd))
            except (InvalidAddressException, BtfError, KetoError):
                task_errors += 1
    listed = {p["va"] for p in walk["processes"]}
    for p in walk["processes"]:
        t = by_tgid.get(p["tgid"])
        p["task_comm"] = t["comm"] if t else None
        p["task_present"] = t is not None
        p["dxg_fds"] = holders.get(p["va"], [])
    walk["unlinked_handles"] = [{"dxgprocess": va, "holders": h} for va, h in holders.items() if va not in listed]
    walk["tasks"] = len(tasks)
    walk["task_errors"] = task_errors
    walk["dxgk_fops"] = fops
    return walk
