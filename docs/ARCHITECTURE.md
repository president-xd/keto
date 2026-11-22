# Keto architecture

Keto deliberately mirrors Volatility 3's architecture so Volatility users find their way around immediately.

```
                 +------------------------------ cli.py (keto) ------------------------------+
                 |  global options: -f image, --live/--snapshot, --host-image, -p profile,  |
                 |  -r renderer, -o outdir, --pdb, --reference          plugin + options     |
                 +---------------------------------------+-----------------------------------+
                                                         |
                            +----------------------------v----------------------------+
                            |                Context (framework/context.py)            |
                            |  layers{}  profile (automagic)  live source  cache{}      |
                            +----+-------------------+-------------------+------------+
                                 |                   |                   |
         +-----------------------v--+   +------------v---------+   +-----v-----------------------+
         | Layers (framework/layers)|   | Profiles (symbols/)  |   | Live sources (live/source)  |
         | FileLayer  BytesLayer    |   | <arch>.json          |   | SystemSource (NVML, CUDA,   |
         | SegmentedLayer (.keto,    |   | _layouts.json        |   |   /proc, /sys, allow-listed |
         |   LiME)                  |   | _classes.json        |   |   commands)                 |
         | GmmuLayer (gpu/gmmu)     |   |  + provenance        |   | RecordingSource -> snapshot |
         +-----------+--------------+   +----------+-----------+   | ReplaySource   <- snapshot  |
                     |                             |               +-------------+---------------+
         +-----------v-----------------------------v-----------+                 |
         |  Discovery (gpu/discovery.py), cached per context    |                 |
         |  instance_blocks  runlists  address_spaces           |                 |
         |  cubins fatbins ptx  kernel_code  channel_commands   |                 |
         |  launches  sass_regions                              |                 |
         +---------------------------+--------------------------+                 |
                                     |                                            |
                    +----------------v--------------------------------------------v--+
                    |   Plugins (plugins/core.py, plugins/nvidia/*.py)               |
                    |   NAME / DESCRIPTION / METHOD / ANALOG / SOURCES / REQUIREMENTS |
                    |   run() -> TreeGrid  -> renderers (quick/pretty/csv/json/jsonl) |
                    +----------------------------------------------------------------+
```

## Layers

A layer is an address space with `ranges()` (readable runs) and `read(offset, length, pad)`. Physical images
are `FileLayer`s (memory-mapped) or `SegmentedLayer`s (sparse: `.keto` segments, LiME ranges). A GPU virtual
address space is a `GmmuLayer`. It walks the page tables once, indexes leaf PTEs by page size, and translates
each read. It prefers the smallest page covering an address, as the hardware does for dual PDEs. PTEs with a
system-memory aperture read through the `sysmem` layer (`--host-image`), so a GPU VA can resolve into host RAM.

## Profiles (the "symbol tables")

`keto/symbols/nvidia/<arch>.json` describes one architecture. Each profile gives:

- MMU format and VA width
- the structure layout name (`_layouts.json`: RAMIN/RAMFC/USERD/runlist offsets)
- the QMD version
- chipset ids, NVML architecture id and compute capabilities, used by the automagic
- engine class ids and per-family method tables (`_classes.json`)
- provenance notes

`profileinfo --provenance` prints which facts were checked against NVIDIA's published headers and which are
assumed. Extra profiles can be supplied with `--profile-dir`.

**Automagic** picks a profile from, in order:

1. `--profile`
2. the container's chipset id, NVML architecture id, compute capability or device name
3. live NVML data
4. GPU-name banners in the image
5. a fallback with a warning

## Discovery

Most plugins build on the same few expensive analyses, so they live in `gpu/discovery.py` and are cached in
the context. Cross-view plugins (`chanxview`, `cubinxview`) and `timeliner` combine them without rescanning.

## Scanning performance

All scanning runs in C:

- `bytes.find`, `re`, and `memoryview.cast` striding for aligned signature checks (one 32-bit word per 4 KiB page
  for instance blocks, one byte per 256 B block for QMDs)
- the `AnchoredScanner`, which finds cheap literal anchors first and applies expensive regexes only in a small
  window around them

Python's `re` does not optimise large alternations, so a single combined regex would be 30x slower.

Large images:

- **No copies.** File-backed layers (raw dumps, `.keto` containers) expose their memory mappings
  (`regions()` / `iter_views()`); `bytes.find`-style searches and regexes run on the mapping itself, and the aligned
  scanners read zero-copy `memoryview`s. Signature scans take a one-byte prefilter (`byte_prefilter`) so only
  candidates reach Python.
- **All cores.** `scan()` splits images of 512 MiB or more into 256 MiB parts and runs them in a persistent process
  pool (`framework/parallel.py`); each worker maps the file itself, and regex matches come back as picklable
  `PMatch` objects. `--workers N` / `KETO_WORKERS` (0 or 1 = single process).
- **Exact boundaries.** Every part (and every chunk on the single-process chunked path) is scanned with the
  scanner's overlap as look-*ahead* and as look-*behind*, and keeps only hits that start inside it. The look-behind
  is what lets a match that began in the previous part be recognised as such, instead of its tail being reported as
  a new match at the boundary; every hit is reported exactly once, whatever the part size. Multi-anchor scanners
  return their hits sorted by offset, so output order does not depend on `--workers`.
- **Algorithms.** AES schedules are found with a linear prefilter (XOR of the image with itself shifted by 4 and
  4*Nk bytes leaves zero runs where schedules start); QMD candidates get a field-level plausibility check before
  full decoding.

## Live sources and snapshots

Live plugins never touch the OS directly; they call the `LiveSource` API (`nvml()`, `proc(pid)`, `read_text()`,
`listdir()`, `stat()`, `command()` ...). `RecordingSource` memoises every answer. `keto acquire --method snapshot`
runs all live plugins under it and stores the records in the container. `ReplaySource` answers from the records,
so the same plugins produce identical output offline. Process environments are reduced to GPU/loader-relevant
variables before they reach plugins or snapshots.

## Host kernel memory (hostmem/)

The `host.*` and `wsl.*` plugins read the host side of GPU activity from Linux kernel memory without Volatility or
an ISF:

- `hostmem/btf.py` parses the kernel's own BTF (`/sys/kernel/btf/vmlinux`) for struct layouts, bitfields included.
- `hostmem/linux.py` translates x86-64 kernel addresses over a physical image (kernel image via `phys_base`, the
  direct map via `page_offset_base`, everything else by walking `init_top_pgt`, 4- or 5-level, large pages) or
  reads `/proc/kcore` directly; `KObj` gives typed field access and `list_head` iteration.
- `hostmem/dxg.py` walks the WSL2 GPU paravirtualisation driver (`dxgdrv.dxgglobal` -> `dxgprocess` -> adapters,
  devices, contexts, hardware queues, allocations, handle tables) and joins it with `init_task.tasks` and the
  `/dev/dxg` files tasks hold (cross-view: exited/hidden and unlinked GPU processes).
- `hostmem/session.py` picks the evidence: a `kcore` container, a RAM image plus `--btf`/`--kallsyms`, or `--kcore`.

## Windows live view (live/windows.py)

Toolhelp32 process/module snapshots, `EnumWindows`, the PDH `GPU Engine` / `GPU Process Memory` / `GPU Adapter
Memory` counters, DXGI `EnumAdapters1` (adapter names and LUIDs), command lines from each process's PEB, and
Authenticode verification (`WinVerifyTrust`: embedded signature, then the system catalogs with the catalog admin
context kept open; no revocation or network), exposed through the LiveSource methods `win_processes`,
`win_modules`, `win_windowed`, `win_gpu`, `win_adapters`, `win_cmdline`, `win_signature` and `registry`, so the
Windows plugins are recorded into snapshots and replayed like every other live plugin. When run elevated,
`SeDebugPrivilege` is enabled so system and other users' processes become readable (protected processes stay
closed). `VirtualQueryEx`/`ReadProcessMemory` back the Windows process acquisition.

## Adding a plugin

```python
from keto.framework.plugin import Plugin, Requirement
from keto.framework.treegrid import Address, TreeGrid
from keto.gpu import discovery

class MyPlugin(Plugin):
    NAME = "nvidia.example"
    CATEGORY = "nvidia.channels"
    DESCRIPTION = "What it does."
    METHOD = "How it does it (structures, signatures, APIs)."
    ANALOG = "windows.something"
    SOURCES = ("image",)            # or ("live",) / ("image", "live") / ("file",)
    REQUIREMENTS = [Requirement("limit", int, 10, "max rows")]

    def run(self):
        rows = ((0, (Address(ib.pa), ib.gp_entries)) for ib in discovery.instance_blocks(self.ctx))
        return TreeGrid([("InstanceBlock", Address), ("Entries", int)], rows)
```

Drop the module in `keto/plugins/` (or `plugins/nvidia/`) and it registers itself.
