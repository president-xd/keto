"""Building the Windows kernel view for a plugin run: which physical layer, which symbols, cached per context."""

from __future__ import annotations

from typing import Tuple

from keto.framework.exceptions import InvalidAddressException, RequirementError
from keto.framework.layers import DataLayer
from keto.framework.plugin import Requirement
from keto.winmem import symbols
from keto.winmem.kernel import KUSER_SHARED_DATA, WinKernel, locate
from keto.winmem.symtab import SymbolError

WIN_REQS = [
    Requirement("pdb", str, None, "kernel PDB (ntkrnlmp.pdb) of the imaged build; default: found by GUID in the "
                                  "local symbol stores (keto pdb find)"),
    Requirement("isf", str, None, "Volatility ISF symbol file (.json / .json.xz) of the imaged kernel instead of a "
                                  "PDB"),
    Requirement("symbols_dir", str, None, "extra directory searched for symbols (symbol-store or Volatility layout)"),
    Requirement("dtb", "address", None, "kernel directory table base (CR3) when it cannot be found automatically"),
    Requirement("kernel_base", "address", None, "ntoskrnl load address when it cannot be found automatically"),
    Requirement("self_profile", bool, False, "derive types from the kernel image even when a PDB/ISF is available "
                                             "(used automatically when none is)"),
]


def _container_meta(ctx, name: str) -> dict:
    """Format facts an acquisition recorded (metadata.memory_image: dump header, CPU CR3)."""
    meta = ctx.host_metadata if name == "sysmem" and ctx.host_metadata else ctx.metadata
    return dict((meta or {}).get("memory_image") or {})


def physical_layer(ctx) -> Tuple[DataLayer, str, dict]:
    """The layer holding Windows physical RAM and what its format recorded (dump header, CPU CR3)."""
    formats = getattr(ctx, "image_formats", None) or {}
    for name in ("sysmem", "physical"):
        layer = ctx.layers.get(name)
        if layer is not None:
            meta = dict(formats.get(name) or {})
            for k, v in _container_meta(ctx, name).items():
                meta.setdefault(k, v)
            if "format" not in meta:
                meta["format"] = "keto container" if (ctx.host_metadata if name == "sysmem" else ctx.metadata) \
                    else "raw"
            return layer, name, meta
    if "vram" in ctx.layers and ctx.container is None:  # a raw file given with -f
        return ctx.layers["vram"], "vram", {"format": "raw"}
    raise RequirementError("no physical memory image: give a Windows RAM image (raw, crash/live dump, hiberfil, "
                           "ELF core, VMware .vmem or a .keto sysmem container) with -f or --host-image")


WINDOWS_FORMATS = ("windump", "hiber")


def looks_windows(ctx) -> bool:
    """Cheap test used by report and timeliner before running windows.kernel.* plugins: a Windows dump or
    hibernation header, a recorded CR3 that maps KUSER_SHARED_DATA, or an x64 low stub in the first MiB.
    (Explicitly run plugins also try the slower self-referencing-PML4 scan.)"""
    try:
        layer, _name, meta = physical_layer(ctx)
    except RequirementError:
        return False
    return windows_evidence(layer, meta)


def windows_evidence(layer: DataLayer, meta: dict) -> bool:
    """See :func:`looks_windows`; for a layer and its format facts."""
    from keto.winmem.kernel import find_low_stub, kuser_ok
    from keto.winmem.paging import X64Paging
    if meta.get("format") in WINDOWS_FORMATS or meta.get("directory_table_base"):
        return True
    cr3 = meta.get("cr3")
    for value in (cr3 if isinstance(cr3, list) else [cr3] if cr3 else []):
        if kuser_ok(X64Paging(layer.read), layer, int(value)):
            return True
    try:
        return find_low_stub(layer) is not None
    except InvalidAddressException:
        return False


def _symbols(layer, loc, opts, notes):
    cv = loc.codeview
    explicit = opts.get("isf") or opts.get("pdb")
    if explicit and not opts.get("self_profile"):
        table = symbols.load(explicit)
        problems = symbols.check_match(table, cv.pdb_name, cv.key)
        if problems:
            raise RequirementError("%s: %s - the symbols must come from the imaged kernel build (%s %s)" % (
                explicit, "; ".join(problems), cv.pdb_name, cv.key))
        return table
    dirs = symbols.search_dirs([opts.get("symbols_dir")] if opts.get("symbols_dir") else [])
    found = None if opts.get("self_profile") else symbols.find_local(cv.pdb_name, cv.key, dirs)
    if found:
        return symbols.load(found)
    from keto.winmem import selfprofile
    if not opts.get("self_profile"):
        notes.append("no PDB/ISF for %s %s in the local symbol stores: types derived from the kernel image "
                     "(self-profile). 'keto pdb fetch --name %s --key %s' adds full symbols"
                     % (cv.pdb_name, cv.key, cv.pdb_name, cv.key))
    table, more = selfprofile.build(layer, loc)
    notes.extend(more)
    return table


def win_kernel(ctx, opts: dict) -> WinKernel:
    key = ("win_kernel", opts.get("pdb"), opts.get("isf"), opts.get("symbols_dir"), opts.get("dtb"),
           opts.get("kernel_base"), bool(opts.get("self_profile")))
    if key in ctx.cache:
        return ctx.cache[key]
    layer, name, meta = physical_layer(ctx)
    loc = locate(layer, meta, opts.get("dtb"), opts.get("kernel_base"))
    notes = list(loc.notes)
    table = _symbols(layer, loc, opts, notes)
    k = WinKernel(layer, loc.dtb, loc.base, table, loc.levels, notes=notes, image_meta=meta)
    k.codeview, k.layer_name = loc.codeview, name
    _sanity(k)
    ctx.cache[key] = k
    return k


def _sanity(k: WinKernel):
    try:
        build = k.u32(k.sym("NtBuildNumber")) if k.has_sym("NtBuildNumber") else None
        shared = k.u32(KUSER_SHARED_DATA + 0x260)
        k.build = (build or shared) & 0xFFFF
        if build is not None and build & 0xFFFF != shared & 0xFFFF:
            k.notes.append("WARNING: NtBuildNumber %d disagrees with KUSER_SHARED_DATA (%d)" % (
                build & 0xFFFF, shared & 0xFFFF))
        head = k.sym("PsActiveProcessHead")
        flink = k.u64(head)
        if not (flink >> 47) or not k.readable(flink):
            k.notes.append("WARNING: PsActiveProcessHead.Flink 0x%x is not a readable kernel address - wrong "
                           "symbols or a damaged image" % flink)
    except (InvalidAddressException, RequirementError, SymbolError) as e:
        k.notes.append("WARNING: kernel sanity check failed: %s" % e)
        k.build = None
