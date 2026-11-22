"""Synthetic Linux x86-64 kernel memory (WSL2 dxgkrnl objects) with a ground-truth manifest.

The image is a physical RAM dump with a KASLR-style layout: the kernel image is loaded at a non-zero
``phys_base``, objects live in the direct map, and the handle table sits in vmalloc space reachable only
through ``init_top_pgt`` (4-level walk, with one 2 MiB large page), as does one page in module space above
``_end``. Decoy ``"Linux version "`` strings check that ``phys_base`` is only accepted when the image's own
``phys_base`` variable agrees. ``write_kcore`` turns the image into a ``/proc/kcore``-style ELF core.

Scenario:
  * task 100 "cudaapp" holds /dev/dxg (fd 3) -> dxgprocess A (vpid 7 in a child PID namespace) with one
    adapter, one device, one context with two hardware queues, allocations (one backed by guest pages
    holding a cubin with kernel ``ethash_search``), a resource, a paging queue and a sync object
  * dxgprocess X (tgid 400) has no task: exited or hidden from the task list
  * task 300 "hider" holds /dev/dxg (fd 4) whose private_data is a dxgprocess not on dxgglobal.plisthead
  * task 200 "bash" uses no GPU
  * task 100 is PID 7 in that child namespace (``thread_pid->numbers[1]``); tasks 200 and 300 are in the initial one
"""

from __future__ import annotations

import struct
from typing import Dict, Tuple

from keto.formats.cubin import build_cubin
from keto.hostmem.btf import BtfBuilder
from keto.hostmem.linux import START_KERNEL_MAP

PHYS_SIZE = 32 << 20
TEXT_VA = 0xFFFFFFFF81000000
PHYS_BASE = 0x200000
POB = 0xFFFF888000000000                  # page_offset_base
VMALLOC_VA = 0xFFFFC90000010000           # handle table (4 KiB pages)
VMALLOC_LARGE_VA = 0xFFFFC90000400000     # 2 MiB large page
MODULE_VA = 0xFFFFFFFFC0001000            # module space: above _end, reachable only through the page tables
MODULE_PA = 0x1F80000
VMEMMAP = 0xFFFFEA0000000000
NS_INUM = 4026532252
PT_POOL = 0x1D00000                      # user page-table pages


def build_btf() -> Tuple[bytes, Dict[str, int]]:
    b = BtfBuilder()
    u8, u16, u32, u64 = b.int("u8", 1), b.int("u16", 2), b.int("unsigned int", 4), b.int("long unsigned int", 8)
    i32 = b.int("int", 4, signed=True)
    char = b.int("char", 1, signed=True)
    vp = b.ptr(0)
    comm = b.array(char, 16, u32)
    desc = b.array(u16, 80, u32)
    lh = b.struct("list_head", 16, [("next", vp, 0), ("prev", vp, 8)])
    b.struct("dxgdriver", 16, [("dxgglobal", vp, 0), ("dxgdev", vp, 8)])
    b.struct("dxgglobal", 48, [("num_adapters", u32, 0), ("vmbus_ver", u32, 4), ("plisthead", lh, 8),
                               ("adapter_list_head", lh, 24)])
    hmt = b.struct("hmgrtable", 24, [("process", vp, 0), ("entry_table", vp, 8), ("table_size", u32, 16),
                                     ("free_count", u32, 20)])
    b.struct("hmgrentry", 16, [("object", vp, 0), ("type", u32, 64, 6), ("unique", u32, 70, 2),
                               ("instance", u32, 72, 6), ("destroyed", u32, 78, 1)])
    handle = b.struct("d3dkmthandle", 4, [("v", u32, 0)])
    b.struct("dxgprocess", 96, [("plistentry", lh, 0), ("pid", i32, 16), ("tgid", i32, 20), ("vpid", i32, 24),
                                ("nspid", vp, 32), ("handle_table", hmt, 40), ("host_handle", handle, 64),
                                ("process_adapter_list_head", lh, 72)])
    b.struct("dxgprocess_adapter", 48, [("process_adapter_list_entry", lh, 0), ("device_list_head", lh, 16),
                                        ("adapter", vp, 32), ("process", vp, 40)])
    luid = b.struct("winluid", 8, [("a", u32, 0), ("b", i32, 4)])
    b.struct("dxgadapter", 216, [("adapter_list_entry", lh, 0), ("host_handle", handle, 16),
                                 ("adapter_state", u32, 20), ("luid", luid, 24), ("device_description", desc, 32),
                                 ("compute_only", u8, 192)])
    b.struct("dxgdevice", 96, [("device_list_entry", lh, 0), ("context_list_head", lh, 16), ("alloc_list_head", lh, 32),
                               ("resource_list_head", lh, 48), ("pqueue_list_head", lh, 64),
                               ("syncobj_list_head", lh, 80)])
    b.struct("dxgcontext", 32, [("context_list_entry", lh, 0), ("hwqueue_list_head", lh, 16)])
    b.struct("dxghwqueue", 24, [("hwqueue_list_entry", lh, 0), ("handle", handle, 16)])
    b.struct("dxgallocation", 48, [("alloc_list_entry", lh, 0), ("alloc_handle", handle, 16), ("num_pages", u32, 20),
                                   ("cpu_address", vp, 24), ("pages", vp, 32), ("resource_owner", u32, 320, 1),
                                   ("cpu_address_mapped", u32, 321, 1), ("cached", u32, 322, 1)])
    b.struct("dxgresource", 32, [("resource_list_entry", lh, 0), ("alloc_list_head", lh, 16)])
    b.struct("dxgpagingqueue", 16, [("pqueue_list_entry", lh, 0)])
    b.struct("dxgsyncobject", 16, [("syncobj_list_entry", lh, 0)])
    nsc = b.struct("ns_common", 8, [("inum", u32, 0)])
    b.struct("pid_namespace", 16, [("level", u32, 0), ("ns", nsc, 8)])
    b.struct("task_struct", 64, [("tasks", lh, 0), ("pid", i32, 16), ("tgid", i32, 20), ("comm", comm, 24),
                                 ("files", vp, 40), ("mm", vp, 48), ("thread_pid", vp, 56)])
    upid = b.struct("upid", 16, [("nr", i32, 0), ("ns", vp, 8)])
    b.struct("pid", 8, [("count", u32, 0), ("level", u32, 4), ("numbers", b.array(upid, 0, u32), 8)])  # numbers[]
    b.struct("files_struct", 16, [("fdt", vp, 0)])
    b.struct("fdtable", 16, [("max_fds", u32, 0), ("fd", vp, 8)])
    b.struct("file", 32, [("f_op", vp, 0), ("private_data", vp, 8)])
    b.struct("page", 64, [("flags", u64, 0)])
    b.struct("mm_struct", 16, [("pgd", vp, 0), ("map_count", u32, 8)])
    return b.build(), {}


class _Mem:
    def __init__(self):
        self.buf = bytearray(PHYS_SIZE)
        self.next = 0x100000  # direct-map heap

    def alloc(self, size: int, align: int = 64) -> int:
        self.next = (self.next + align - 1) // align * align
        pa = self.next
        self.next += size
        assert self.next < 0x1000000
        return pa

    def put(self, pa: int, data: bytes):
        self.buf[pa:pa + len(data)] = data

    def q(self, pa: int, v: int):
        struct.pack_into("<Q", self.buf, pa, v)

    def d(self, pa: int, v: int):
        struct.pack_into("<I", self.buf, pa, v & 0xFFFFFFFF)


def build_image() -> Tuple[bytes, bytes, str, dict]:
    """Return ``(physical image, BTF blob, kallsyms text, ground truth)``."""
    btf_blob, _ = build_btf()
    m = _Mem()
    va = lambda pa: POB + pa  # noqa: E731  direct map

    def text_pa(sym_va):
        return sym_va - START_KERNEL_MAP + PHYS_BASE

    syms = {"_text": TEXT_VA, "linux_banner": TEXT_VA + 0x1000, "phys_base": TEXT_VA + 0x2000,
            "page_offset_base": TEXT_VA + 0x2008, "vmemmap_base": TEXT_VA + 0x2010,
            "__pgtable_l5_enabled": TEXT_VA + 0x2018, "init_task": TEXT_VA + 0x3000, "init_top_pgt": TEXT_VA + 0x10000,
            "dxgdrv": TEXT_VA + 0x4000, "dxgk_fops": TEXT_VA + 0x5000, "_end": TEXT_VA + 0x20000}
    banner = b"Linux version 6.18.0-synthetic (keto@test) #1 SMP"
    m.put(text_pa(syms["linux_banner"]), banner + b"\x00")
    m.put(0x1100000, b"Linux version decoy-before-kernel\x00")        # decoys: phys_base check must reject them
    m.put(0x1F00000, b"Linux version decoy-after-kernel\x00")
    m.q(text_pa(syms["phys_base"]), PHYS_BASE)
    m.q(text_pa(syms["page_offset_base"]), POB)
    m.q(text_pa(syms["vmemmap_base"]), VMEMMAP)
    m.d(text_pa(syms["__pgtable_l5_enabled"]), 0)

    def list_init(pa):
        m.q(pa, va(pa))
        m.q(pa + 8, va(pa))

    def list_add(head_pa, node_pa):  # append at tail
        prev = struct.unpack_from("<Q", m.buf, head_pa + 8)[0]
        prev_pa = prev - POB if prev >= POB and prev < 0xFFFFFFFF80000000 else text_pa(prev)
        m.q(node_pa, va(head_pa) if head_pa < 0x1000000 else head_va_map[head_pa])
        m.q(node_pa + 8, prev)
        m.q(prev_pa, va(node_pa))
        m.q(head_pa + 8, va(node_pa))

    head_va_map = {}

    # -- page tables for vmalloc space (built inside the kernel image) ------------------------------------
    pgd = text_pa(syms["init_top_pgt"])
    pdpt, pd, pt = pgd + 0x1000, pgd + 0x2000, pgd + 0x3000
    m.q(pgd + ((VMALLOC_VA >> 39) & 0x1FF) * 8, pdpt | 0x63)
    m.q(pdpt + ((VMALLOC_VA >> 30) & 0x1FF) * 8, pd | 0x63)
    m.q(pd + ((VMALLOC_VA >> 21) & 0x1FF) * 8, pt | 0x63)
    table_pa = 0x1800000
    m.q(pt + ((VMALLOC_VA >> 12) & 0x1FF) * 8, table_pa | 0x8000000000000063)  # NX bit set
    large_pa = 0x1A00000
    m.q(pd + ((VMALLOC_LARGE_VA >> 21) & 0x1FF) * 8, large_pa | 0xE3)         # PS: 2 MiB page
    m.put(large_pa + 0x1234, b"LARGE-PAGE-MARKER")
    mpdpt, mpd, mpt = pgd + 0x4000, pgd + 0x5000, pgd + 0x6000                # module page (still below _end)
    m.q(pgd + ((MODULE_VA >> 39) & 0x1FF) * 8, mpdpt | 0x63)
    m.q(mpdpt + ((MODULE_VA >> 30) & 0x1FF) * 8, mpd | 0x63)
    m.q(mpd + ((MODULE_VA >> 21) & 0x1FF) * 8, mpt | 0x63)
    m.q(mpt + ((MODULE_VA >> 12) & 0x1FF) * 8, MODULE_PA | 0x8000000000000063)
    m.put(MODULE_PA, b"MODULE-PAGE-MARKER")

    # -- dxgglobal ---------------------------------------------------------------------------------------
    g = m.alloc(48)
    m.q(text_pa(syms["dxgdrv"]), va(g))
    m.d(g, 1)
    m.d(g + 4, 40)
    list_init(g + 8)
    list_init(g + 24)
    adapter = m.alloc(216)
    m.d(adapter + 16, 0x40000000)
    m.q(adapter + 24, 0xB0A4C5)
    m.put(adapter + 32, "NVIDIA GeForce RTX 4050 Laptop GPU".encode("utf-16-le"))
    list_add(g + 24, adapter)
    ns = m.alloc(16)
    m.d(ns + 8, NS_INUM)

    def new_process(pid, tgid, vpid, on_list=True):
        p = m.alloc(96)
        if on_list:
            list_add(g + 8, p)
        m.d(p + 16, pid)
        m.d(p + 20, tgid)
        m.d(p + 24, vpid)
        m.q(p + 32, va(ns))
        m.d(p + 64, 0x80000001)
        list_init(p + 72)
        return p

    proc_a = new_process(1000, 100, 7)
    proc_x = new_process(4000, 400, 400)
    proc_u = new_process(3000, 300, 300, on_list=False)
    # process A: adapter -> device -> context(2 hwqueues), allocations, resource, paging queue, sync object
    pad = m.alloc(48)
    list_add(proc_a + 72, pad)
    list_init(pad + 16)
    m.q(pad + 32, va(adapter))
    dev = m.alloc(96)
    list_add(pad + 16, dev)
    for off in (16, 32, 48, 64, 80):
        list_init(dev + off)
    ctx = m.alloc(32)
    list_add(dev + 16, ctx)
    list_init(ctx + 16)
    for _ in range(2):
        hq = m.alloc(24)
        list_add(ctx + 16, hq)
    cub = build_cubin({"ethash_search": bytes(range(256)) * 2})
    gpages = []
    for i in range(2):
        pa = 0x1C00000 + i * 0x1000
        gpages.append(pa)
    m.put(gpages[0], cub[:0x1000])
    m.put(gpages[1], cub[0x1000:0x2000])
    page_array = m.alloc(16, 8)
    for i, pa in enumerate(gpages):
        m.q(page_array + i * 8, VMEMMAP + (pa >> 12) * 64)
    allocs = []
    for handle, npages, pages_ptr, flags in ((0x40000100, 2, va(page_array), 0b010), (0x40000140, 16, 0, 0b000)):
        a = m.alloc(48)
        list_add(dev + 32, a)
        m.d(a + 16, handle)
        m.d(a + 20, npages)
        m.q(a + 24, 0x7F0000000000 + (handle & 0xFFF) * 0x100000)  # page-aligned CPU VA
        m.q(a + 32, pages_ptr)
        m.buf[a + 40] = flags
        allocs.append(a)
    res = m.alloc(32)
    list_add(dev + 48, res)
    list_init(res + 16)
    ra = m.alloc(48)
    list_add(res + 16, ra)
    m.d(ra + 16, 0x40000180)
    m.d(ra + 20, 512)
    m.buf[ra + 40] = 0b001
    list_add(dev + 64, m.alloc(16))
    list_add(dev + 80, m.alloc(16))
    # handle table of A in vmalloc space: device, context, 2 hwqueues, 3 allocations, a destroyed context
    entries = [3, 7, 15, 15, 5, 5, 5, 7 | (1 << 14)]  # bit 78 - 64 = 14: destroyed
    for i, e in enumerate(entries):
        struct.pack_into("<QQ", m.buf, table_pa + i * 16, 0xFFFF888000123000, e)
    m.q(proc_a + 40, 0)
    m.q(proc_a + 48, VMALLOC_VA)
    m.d(proc_a + 56, len(entries) + 4)  # 4 free slots

    # -- tasks -------------------------------------------------------------------------------------------
    init_pa = text_pa(syms["init_task"])
    head_va_map[init_pa] = syms["init_task"]
    m.q(init_pa, syms["init_task"])
    m.q(init_pa + 8, syms["init_task"])
    m.put(init_pa + 24, b"swapper/0")

    def files_with(fds):
        fs, fdt = m.alloc(16), m.alloc(16)
        arr = m.alloc(8 * 8, 8)
        m.q(fs, va(fdt))
        m.d(fdt, 8)
        m.q(fdt + 8, va(arr))
        for fd, private in fds.items():
            f = m.alloc(32)
            m.q(f, syms["dxgk_fops"])
            m.q(f + 8, va(private))
            m.q(arr + fd * 8, va(f))
        return va(fs)

    # -- user page tables (4-level) for G4 page ownership: page pool at PT_POOL ----------------------------
    pool = [PT_POOL]

    def new_page():
        pa = pool[0]
        pool[0] += 0x1000
        return pa

    def map_user(pgd, uva, pa, rw=True):
        table = pgd
        for sh in (39, 30, 21):
            slot = table + ((uva >> sh) & 0x1FF) * 8
            e = struct.unpack_from("<Q", m.buf, slot)[0]
            if not e & 1:
                e = new_page() | 0x67
                m.q(slot, e)
            table = e & 0x000FFFFFFFFFF000
        m.q(table + ((uva >> 12) & 0x1FF) * 8, pa | 0x65 | (0x2 if rw else 0) | (1 << 63))

    victim_pa = 0x1E00000
    m.put(victim_pa, b"keyboard ring buffer: user typed secrets here")
    cpu_va = 0x7F0000000000 + 0x100 * 0x100000
    user_maps = {100: [(cpu_va, gpages[0]), (cpu_va + 0x1000, gpages[1]), (0x400000, 0x1E40000)],
                 200: [(0x7FFE00000000, victim_pa)],
                 300: [(0x7FAA00000000, gpages[1])]}  # hider maps a page of A's GPU allocation
    tasks, mms = {}, {}
    nspids = {100: 7, 200: 200, 300: 300}  # cudaapp runs in the child PID namespace of dxgprocess A
    for pid, comm, fds in ((100, b"cudaapp", {3: proc_a}), (200, b"bash", {}), (300, b"hider", {4: proc_u})):
        t = m.alloc(64)
        list_add(init_pa, t)
        m.d(t + 16, pid)
        m.d(t + 20, pid)
        m.put(t + 24, comm)
        m.q(t + 40, files_with(fds))
        numbers = [(pid, 0)] + ([(nspids[pid], va(ns))] if nspids[pid] != pid else [])
        sp = m.alloc(8 + 16 * len(numbers), 8)  # struct pid with numbers[level + 1]
        m.d(sp + 4, len(numbers) - 1)
        for i, (nr, ns_va) in enumerate(numbers):
            m.d(sp + 8 + 16 * i, nr)
            m.q(sp + 16 + 16 * i, ns_va)
        m.q(t + 56, va(sp))
        mm = m.alloc(16)
        pgd = new_page()
        m.q(mm, va(pgd))
        for uva, upa in user_maps[pid]:
            map_user(pgd, uva, upa)
        m.q(t + 48, va(mm))
        tasks[pid] = va(t)
        mms[pid] = pgd

    kallsyms = "".join("%016x T %s\n" % (v, k) for k, v in sorted(syms.items(), key=lambda kv: kv[1]))
    truth = {"phys_base": PHYS_BASE, "page_offset_base": POB, "banner": banner.decode(),
             "processes": {"A": {"va": va(proc_a), "pid": 1000, "tgid": 100, "vpid": 7, "comm": "cudaapp", "fd": 3,
                                 "devices": 1, "contexts": 1, "hwqueues": 2, "allocations": 3, "resources": 1,
                                 "pagingqueues": 1, "syncobjects": 1,
                                 "handles": {"device": 1, "context": 1, "hwqueue": 2, "allocation": 3,
                                             "context (destroyed)": 1}},
                           "X": {"va": va(proc_x), "tgid": 400}},
             "unlinked": {"va": va(proc_u), "holder_pid": 300, "fd": 4},
             "pidns": NS_INUM, "adapter": "NVIDIA GeForce RTX 4050 Laptop GPU",
             "guest_page_alloc": {"handle": 0x40000100, "kernel": "ethash_search", "cubin": cub[:0x2000]},
             "vmalloc": {"va": VMALLOC_VA, "pa": table_pa}, "large_page": {"va": VMALLOC_LARGE_VA, "pa": large_pa},
             "module_page": {"va": MODULE_VA, "pa": MODULE_PA},
             "kernel_image": (text_pa(syms["_text"]), text_pa(syms["_end"])),
             "tasks": tasks, "nspids": nspids,
             "page_owners": {"victim_pa": victim_pa, "victim_owner": 200, "kernel_text_pa": text_pa(TEXT_VA + 0x1000),
                             "guest_pages": gpages, "foreign": {gpages[1]: 300}, "cpu_va": cpu_va}}
    return bytes(m.buf), btf_blob, kallsyms, truth


def write_kcore(path: str, image: bytes, truth: dict,
                ram: Tuple[Tuple[int, int], ...] = ((0x1000, 0x9F000), (0x100000, PHYS_SIZE - 0x100000))) -> None:
    """Write ``image`` as a ``/proc/kcore``-style ELF core, laid out as ``fs/proc/kcore.c`` does: one PT_LOAD per
    RAM range in the direct map (``p_vaddr = page_offset_base + p_paddr``), the kernel text ``_text`` .. ``_end``
    (``p_paddr = __pa_symbol(_text)``) and the vmalloc and module pages (``p_paddr = -1``)."""
    ki = truth["kernel_image"]
    segs = [(POB + start, start, image[start:start + size]) for start, size in ram]
    segs.append((TEXT_VA, ki[0], image[ki[0]:ki[1]]))
    for va, pa in ((truth["vmalloc"]["va"], truth["vmalloc"]["pa"]), (MODULE_VA, MODULE_PA)):
        segs.append((va, 0xFFFFFFFFFFFFFFFF, image[pa:pa + 0x1000]))
    off = 64 + 56 * len(segs)
    with open(path, "wb") as fh:
        fh.write(struct.pack("<16sHHIQQQIHHHHHH", b"\x7fELF\x02\x01\x01", 4, 62, 1, 0, 64, 0, 0, 64, 56,
                             len(segs), 0, 0, 0))
        for va, pa, data in segs:
            fh.write(struct.pack("<IIQQQQQQ", 1, 7, off, va, pa, len(data), len(data), 0x1000))
            off += len(data)
        for _va, _pa, data in segs:
            fh.write(data)
