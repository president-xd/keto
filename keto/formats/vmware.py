"""VMware saved state / snapshot files (.vmss / .vmsn) and their guest memory (.vmem) as a physical-address layer.

State file layout (Volatility 2/3 ``vmware`` address spaces; crash-utility ``vmware_vmss.[ch]`` by VMware):

    header      u32 magic, u32 version, u32 group count                                   (12 bytes)
    groups      char name[64], u64 tags offset, u64 size                                  (80 bytes each)
    tags        u16 tag: bits 15..8 name length, 7..6 index count, 5..0 value size;
                name; index count x u32 indices; then the value: ``value size`` bytes, or for value size 63 (block) /
                62 (compressed block): u64 size on disk, u64 size in memory (u32 each for magics with low nibble 0),
                u16 pad length, pad, data. A zero tag ends a group.

Memory ("memory" group): ``regionsCount`` and per region ``regionPPN[i]`` (guest physical page number),
``regionPageNum[i]`` (page number inside the memory data) and ``regionSize[i]`` (pages); the memory data is the
``Memory`` block when the state file embeds it, otherwise the companion .vmem file. Without regions the memory is one
flat run from physical address 0. Guests with more RAM than fits below the PCI hole have a region above 4 GiB whose
regionPPN differs from its regionPageNum. CPU state ("cpu" group): ``CR64`` per vCPU, either a 72-byte block (cr0..cr8)
indexed [cpu] or 8-byte values indexed [cpu][n].
"""

from __future__ import annotations

import os
import struct
from typing import Dict, Optional, Tuple

from keto.formats.memimage import PAGE, file_runs
from keto.framework.exceptions import FormatError, InvalidAddressException, UnsupportedError
from keto.framework.layers import FileLayer

MAGICS = {0xBED0BED0: "old", 0xBED2BED0: "old", 0xBED2BED2: "checkpoint", 0xBED3BED3: "partial",
          0xBAD1BAD1: "restored", 0xBAD2BAD2: "norestore"}
GROUP = struct.Struct("<64sQQ")
BLOCK, BLOCK_COMPRESSED = 63, 62


def _magic(head: bytes) -> Optional[int]:
    if len(head) < 12:
        return None
    m = struct.unpack_from("<I", head, 0)[0]
    return m if m in MAGICS else None


def looks_like_state(head: bytes, path: str) -> bool:
    """A known magic, a plausible group count whose table fits the file, and printable group names."""
    m = _magic(head)
    if m is None:
        return False
    ngroups = struct.unpack_from("<I", head, 8)[0]
    try:
        size = os.path.getsize(path)
    except OSError:
        return False
    if not 0 < ngroups <= 1024 or 12 + GROUP.size * ngroups > size:
        return False
    if len(head) >= 12 + GROUP.size:
        name = GROUP.unpack_from(head, 12)[0].split(b"\x00", 1)[0]
        return bool(name) and all(32 <= c < 127 for c in name)
    return True


def looks_like_vmem(path: str) -> bool:
    """A .vmem file (raw guest memory; its layout lives in the companion state file): page-multiple size."""
    if not path.lower().endswith(".vmem") or not os.path.isfile(path):
        return False
    try:
        size = os.path.getsize(path)
    except OSError:
        return False
    return size > 0 and size % PAGE == 0


def companion(path: str, exts) -> Optional[str]:
    """The file next to ``path`` with the same stem and one of ``exts`` (case-insensitive extension)."""
    d, base = os.path.split(os.path.abspath(path))
    stem = os.path.splitext(base)[0]
    try:
        names = sorted(os.listdir(d))
    except OSError:
        return None
    for ext in exts:
        for n in names:
            s, e = os.path.splitext(n)
            if s == stem and e.lower() == ext and os.path.isfile(os.path.join(d, n)):
                return os.path.join(d, n)
    return None


def parse_state(path: str, groups_wanted=("memory", "cpu")) -> dict:
    """Header, group table and the tags of the wanted groups:
    ``{"magic", "version", "groups": {name: (offset, size)}, "tags": {group: {(name, indices): tag}}}`` where a tag
    is ``("value", int, raw_bytes)`` or ``("block", data_offset, size_on_disk, size_in_memory, compressed)``."""
    f = FileLayer("vmware-state", path)
    try:
        size = f.length
        head = f.read(0, min(size, 12))
        magic = _magic(head)
        if magic is None:
            raise FormatError("%s is not a VMware state file (magic %r)" % (path, head[:4]))
        _m, version, ngroups = struct.unpack_from("<III", head, 0)
        if 12 + GROUP.size * ngroups > size:
            raise FormatError("%s: %d groups do not fit the file" % (path, ngroups))
        wide = magic & 0xF != 0  # block sizes are u64, or u32 for the old magics (low nibble 0)
        groups: Dict[str, Tuple[int, int]] = {}
        for i in range(ngroups):
            raw, off, gsize = GROUP.unpack(f.read(12 + GROUP.size * i, GROUP.size))
            groups[raw.split(b"\x00", 1)[0].decode("latin-1")] = (off, gsize)
        tags: Dict[str, dict] = {}
        for gname in groups_wanted:
            if gname in groups:
                tags[gname] = _parse_tags(f, path, gname, groups[gname][0], size, wide)
        return {"magic": magic, "version": version, "groups": groups, "tags": tags}
    except InvalidAddressException as exc:
        raise FormatError("%s: the state file is truncated (%s)" % (path, exc))
    finally:
        f.close()


def _parse_tags(f: FileLayer, path: str, gname: str, pos: int, size: int, wide: bool) -> dict:
    out = {}
    width = 8 if wide else 4
    while True:
        if pos + 2 > size:
            raise FormatError("%s: group '%s' runs past the end of the file at 0x%x" % (path, gname, pos))
        tag = struct.unpack("<H", f.read(pos, 2))[0]
        pos += 2
        if tag == 0:
            return out
        namelen, nindx, valsize = tag >> 8, (tag >> 6) & 3, tag & 0x3F
        name = f.read(pos, namelen).decode("latin-1")
        pos += namelen
        idx = struct.unpack("<%dI" % nindx, f.read(pos, 4 * nindx)) if nindx else ()
        pos += 4 * nindx
        if valsize in (BLOCK, BLOCK_COMPRESSED):
            raw = f.read(pos, 2 * width + 2)
            disk, mem = struct.unpack("<QQ" if wide else "<II", raw[:2 * width])
            pad = struct.unpack_from("<H", raw, 2 * width)[0]
            data = pos + 2 * width + 2 + pad
            if data + disk > size:
                raise FormatError("%s: block '%s' in group '%s' (0x%x bytes at 0x%x) runs past the end of the file"
                                  % (path, name, gname, disk, data))
            out[(name, idx)] = ("block", data, disk, mem, valsize == BLOCK_COMPRESSED)
            pos = data + disk
        else:
            raw = f.read(pos, valsize)
            out[(name, idx)] = ("value", int.from_bytes(raw, "little"), raw)
            pos += valsize


def _value(tags: dict, name: str, idx=()) -> Optional[int]:
    t = tags.get((name, tuple(idx)))
    return t[1] if t is not None and t[0] == "value" else None


def _cpus(tags: dict) -> list:
    """Per-vCPU control registers from ``CR64`` (block [cpu] or values [cpu][n])."""
    regs: Dict[int, Dict[int, int]] = {}
    for (name, idx), t in tags.items():
        if name != "CR64" or not idx:
            continue
        if t[0] == "value" and len(idx) == 2:
            regs.setdefault(idx[0], {})[idx[1]] = t[1]
    return [dict(cpu=c, **{"cr%d" % n: v for n, v in sorted(r.items())}) for c, r in sorted(regs.items())]


def _cpus_from_blocks(path: str, tags: dict, cpus: list) -> list:
    blocks = [(idx[0], t) for (name, idx), t in tags.items() if name == "CR64" and idx and t[0] == "block"
              and t[2] == 72 and not t[4]]
    if not blocks:
        return cpus
    known = {c["cpu"] for c in cpus}
    with open(path, "rb") as fh:
        for cpu, t in sorted(blocks):
            if cpu in known:
                continue
            fh.seek(t[1])
            cr = struct.unpack("<9Q", fh.read(72))
            cpus.append(dict(cpu=cpu, **{"cr%d" % n: v for n, v in enumerate(cr)}))
    return sorted(cpus, key=lambda c: c["cpu"])


def open_vmware(name: str, path: str):
    """Open a .vmss/.vmsn (finding its .vmem) or a .vmem (finding its .vmss/.vmsn)."""
    with open(path, "rb") as fh:
        head = fh.read(12 + GROUP.size)
    if looks_like_state(head, path):
        state, vmem = path, companion(path, (".vmem",))
    else:
        state, vmem = companion(path, (".vmss", ".vmsn")), path
    meta = {"format": "vmware", "state_file": state, "vmem_file": vmem, "warnings": []}
    if state is None:
        meta.update(mapping="flat", regions=[], cpus=[])
        meta["warnings"].append("no .vmss/.vmsn companion next to %s: the .vmem is mapped flat from physical address 0, "
                                "so memory a VM keeps above the PCI hole (guests with more than ~3 GiB) is at the wrong "
                                "address" % path)
        layer, w = file_runs(name, path, [(0, os.path.getsize(path), 0)], "vmware")
        meta["warnings"] += w
        meta["physical_runs"] = list(layer.ranges())
        return layer, meta
    st = parse_state(state)
    mem = st["tags"].get("memory", {})
    cpu_tags = st["tags"].get("cpu", {})
    meta.update(magic=st["magic"], magic_name=MAGICS[st["magic"]], header_version=st["version"],
                groups=sorted(st["groups"]))
    if MAGICS[st["magic"]] == "restored":
        meta["warnings"].append("state file magic 0xbad1bad1 (restored): the VM was resumed from this state, so a "
                                "companion .vmem may have changed since it was written")
    if "memory" not in st["groups"]:
        raise FormatError("%s: no 'memory' group (groups: %s)" % (state, ", ".join(sorted(st["groups"]))))
    block = next((t for (n, _i), t in mem.items() if n == "Memory" and t[0] == "block" and t[2]), None)
    if block is not None:
        if block[4] or block[2] != block[3]:
            raise UnsupportedError("%s: the embedded Memory block is compressed (%d bytes on disk, %d in memory): "
                                   "not supported" % (state, block[2], block[3]))
        base_path, base_off, base_len = state, block[1], block[2]
        meta["memory_embedded"] = True
    else:
        if vmem is None:
            raise FormatError("%s: the guest memory is not embedded (no Memory block) and no companion .vmem was "
                              "found next to it" % state)
        base_path, base_off, base_len = vmem, 0, os.path.getsize(vmem)
        meta["memory_embedded"] = False
    count = _value(mem, "regionsCount") or 0
    regions, runs = [], []
    for i in range(count):
        ppn, pnum, pages = (_value(mem, "regionPPN", (i,)), _value(mem, "regionPageNum", (i,)),
                            _value(mem, "regionSize", (i,)))
        if None in (ppn, pnum, pages):
            raise FormatError("%s: memory region %d of %d lacks regionPPN/regionPageNum/regionSize" % (state, i, count))
        regions.append({"ppn": ppn, "page_num": pnum, "pages": pages})
        runs.append((ppn * PAGE, pages * PAGE, base_off + pnum * PAGE))
    if not count:
        runs.append((0, base_len, base_off))
    end = max((r["page_num"] + r["pages"]) * PAGE for r in regions) if regions else base_len
    if end > base_len:
        meta["warnings"].append("the regions describe %d bytes of memory data but %s holds %d" % (end, base_path,
                                                                                                    base_len))
    meta.update(mapping="regions" if count else "flat", regions=regions, align_mask=_value(mem, "align_mask"),
                num_vcpus=_value(cpu_tags, "cpu:numVCPUs"), memory_file=base_path, memory_offset=base_off)
    meta["cpus"] = _cpus_from_blocks(state, cpu_tags, _cpus(cpu_tags))
    if meta["cpus"] and "cr3" in meta["cpus"][0]:
        meta["cr3"] = meta["cpus"][0]["cr3"]
    # clip regions to the memory data (embedded block or .vmem), then to the file
    clipped = []
    for addr, length, off in runs:
        avail = min(length, base_off + base_len - off)
        if avail > 0:
            clipped.append((addr, avail, off))
    layer, w = file_runs(name, base_path, clipped, "vmware")
    meta["warnings"] += w
    meta["physical_runs"] = list(layer.ranges())
    return layer, meta
