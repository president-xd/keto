# Formats and decoded structures

## Evidence container (`.keto`)

| Offset | Size | Field |
|---|---|---|
| 0 | 8 | magic `KETOEVD\x01` (containers written before the rename carry `VRMNCR\0\1` and are still read) |
| 8 | 4 | version (2; version 1 containers have no header digest) |
| 12 | 4 | header size (64) |
| 16 | 8 | segment table offset |
| 24 | 4 | segment count |
| 28 | 4 | flags |
| 32 | 8 | metadata offset |
| 40 | 8 | metadata length |
| 48 | 16 | header digest: the first 16 bytes of the evidence fingerprint (version 2; zero in version 1) |

Segment table entry (32 bytes): `u32 space, u32 flags, u64 address, u64 length, u64 file_offset`.
Spaces: 0 vram, 1 sysmem, 2 bar0, 3 bar1, 4 rom, 5 residual (keyed by CUDA VA), 6 gpuva, 7 process (keyed by
process VA), 8 kbtf (the imaged kernel's BTF blob, kcore containers).

The metadata JSON holds:

- `tool`, `tool_version`, `created_utc`
- `acquisition` (method, examiner, notes, statistics, `status`: `complete` or `incomplete: <error>`)
- `device` (name, uuid, chipset/NVML arch/compute capability, VRAM size, VBIOS, driver). An imported dump has no
  `device` unless `--live-device` recorded the acquiring machine's GPU.
- `segments` (each with space, address, length and SHA-256), `data_sha256` (SHA-256 over all segment data in order)
- optional `live_snapshot` (recorded live-source answers)
- `kernel` (kcore containers): banner, symbols, `phys_base`, `page_offset_base`, paging mode, `btf_sha256`,
  `ram_ranges`, `zero_pages_omitted`, `own_pages_omitted` (RAM pages identical to already-written output pages),
  and `acquired_ranges` when the acquisition was limited (`--phys-range`, `--max-bytes`) or interrupted

**Integrity.** The *evidence fingerprint* is `SHA-256("keto-fingerprint/1" || header bytes 8..48 || metadata JSON
|| segment table)`. It covers the header fields, every recorded hash and the segment table, so with the segment
hashes it pins the whole container. Its first 16 bytes are stored in the header and checked whenever a container
is opened: a modified metadata block or segment table produces a warning before any analysis. The full fingerprint
is printed by `keto acquire`; record it in the case notes. Because anyone who rewrites the data can also rewrite the
hashes stored inside the file, only that external record exposes a complete forgery
(`verify --expected-fingerprint <hex>`).

`keto -f x.keto verify` re-hashes every segment, compares each segment-table entry with the metadata, recomputes
`data_sha256`, checks the header digest and, with `--expected-fingerprint`, the recorded fingerprint. It works on
every container, including live-snapshot containers (which hold no segments, only metadata).

## Profile JSON (`keto-profile/1`)

Required keys: `format, name, vendor, architecture, mmu {format v2|v3, va_bits, big_page_sizes}, layout, classes,
provenance`. Optional: `chipsets {"0x197": "AD107"}`, `nvml_arch`, `compute_capabilities`, `name_patterns`, `qmd`.
Layouts (`_layouts.json`) give byte offsets for `ramin`, `ramfc`, `userd`, `runlist`.

## NVIDIA structures and their sources

| Structure | Fields used | Source |
|---|---|---|
| GMMU VER2 PDE / dual PDE / PTE | aperture, address (sys/vid), VOL, PRIVILEGE, READ_ONLY, ENCRYPTED, ATOMIC_DISABLE, KIND, COMPTAGLINE, PEER | `open-gpu-kernel-modules/.../pascal/gp100/dev_mmu.h` (verified) |
| GMMU VER3 PDE / dual PDE / PTE | aperture, PCF (privilege/RO/uncached/atomic/ACD), KIND 11:8, ADDRESS 51:12, PEER_ID | `.../hopper/gh100/dev_mmu.h` (verified) |
| VA split | VER2 2/9/9/8/9 (+12); VER3 1/9/9/9/8/9 (+12) | derived from entry sizes; consistent with nouveau |
| Instance block (RAMIN) | PAGE_DIR_BASE @0x200 (target, VOL, VER2, BIG_PAGE_SIZE, LO/HI), ENGINE_WFI @0x210, VEID @0x218, PASID @0x21C, SC_PDB_VALID @0x298, SC_PAGE_DIR_BASE[i] @0x2A0+16i | `open-gpu-doc/manuals/volta/gv100/dev_ram.ref.txt` (verified) |
| RAMFC | GP_PUT 0x00, USERD 0x08/0x0C, SIGNATURE 0x10, GP_GET 0x14, PB_GET 0x18, SEM_* 0x38..0x44, GP_BASE 0x48/0x4C (LIMIT2 20:16), PB_PUT 0x5C, HCE_CTRL 0xE4, CONFIG 0xF4, SET_CHANNEL_INFO 0xFC | same (verified); signature value 0xFACE and HCE privilege bit from nouveau |
| USERD | PUT 0x40, GET 0x44, REF 0x48, GP_GET 0x88, GP_PUT 0x8C | same + GA100 header (verified identical) |
| Runlist entry (16 B) | TYPE, RUNQUEUE, INST/USERD target, USERD_PTR, CHID, INST_PTR; TSG: TIMESLICE_SCALE/TIMEOUT, LENGTH, TSGID | gv100 manual + nouveau gv100 runlist code |
| GPFIFO entry | GET 31:2, GET_HI 7:0, LEVEL 9, LENGTH 30:10, SYNC 31 | `open-gpu-doc/classes/host/clc56f.h` (verified) |
| Method header | SEC_OP 31:29, COUNT/IMMD 28:16, SUBCHANNEL 15:13, ADDRESS 11:0 | `clc56f.h` (verified) |
| Host methods | SET_OBJECT, SEMAPHOREA..D, NON_STALL_INTERRUPT, MEM_OP_*, SEM_ADDR/PAYLOAD/EXECUTE, WFI, YIELD | `clc56f.h` (verified) |
| Copy engine | LAUNCH_DMA fields, OFFSET_IN/OUT, PITCH, LINE_LENGTH/COUNT, SET_SEMAPHORE_*, SET_SRC/DST_PHYS_MODE | `open-gpu-doc/classes/dma-copy/clc6b5.h` (verified) |
| Compute | SEND_PCAS_A (QMD >> 8), SEND_SIGNALING_PCAS_B, inline-to-memory, SET_REPORT_SEMAPHORE_A..D | `open-gpu-doc/classes/compute/clc6c0.h` (verified) |
| QMD V03_00 | version, raster, thread dims, shared mem, registers, barriers, constant buffers, PROGRAM_ADDRESS, RELEASE0 | `clc6c0qmd.h` (verified) |
| cubin | EM_CUDA 190; SM from e_flags (ABI v7 bits 7:0, ABI v8 bits 15:8); `.nv.info` EIATTR records; `.note.nv.cuinfo`/`tkinfo` | verified against a cubin JIT-compiled by the local driver (sm_89, CUDA 13.1) |
| SASS (sm_70+) | 128-bit insns, opcode 11:0, predicate 15:12; EXIT `…794d`, BRA-self `…7947`, NOP `…7918` | verified against the same cubin |
| Fatbin | header 0xBA55ED50, 64-byte entry headers, flag 0x2000 = LZ4 | cricket project documentation; consistent with nvcc output |
| Block-linear surfaces | 64 B × 8-row GOBs, block height in GOBs, in-GOB swizzle formula | public Tegra/Maxwell documentation used by open-source emulators |
| PCI option ROM / BIT | 0x55AA, PCIR, image length, code type, last image; BIT token `i` = version | PCI firmware spec; nouveau BIT parsing |

## Physical memory images (`keto/formats/memimage.py`)

`memimage.detect(path)` names the format (`windump`, `elfcore`, `vmware`, `hiber`, `lime`, `container`, or None for
a raw image); every positive answer needs a signature plus structural checks. `memimage.open_memory_image(name,
path)` returns `(layer, metadata)`: the layer is addressed by physical address, absent pages raise
`InvalidAddressException`, `ranges()` lists what is present; `metadata["format"]` names the format and
`metadata["warnings"]` lists what the analyst must know (truncation, inferred layouts, aliases). `-f` opens these
formats as layer `physical` (primary) and `--host-image` as `sysmem`; `Context.image_formats[layer]` keeps the
metadata. Raw files, LiME and `.keto` containers open as before. Recognised but unsupported variants are refused
with the reason; they never fall back to a raw image.

### Windows crash and live kernel dumps (`windump.py`)

| Offset | Field |
|---|---|
| 0x0000 | `"PAGE"` `"DU64"` (`"PAGEDUMP"` = 32-bit: refused) |
| 0x0008 / 0x000C | MajorVersion / MinorVersion (as stored; minor = build) |
| 0x0010 / 0x0018 | DirectoryTableBase / PfnDatabase |
| 0x0020 / 0x0028 | PsLoadedModuleList / PsActiveProcessHead |
| 0x0030 / 0x0034 / 0x0038 | MachineImageType / NumberProcessors / BugCheckCode |
| 0x0040 | BugCheckCodeParameters[4] |
| 0x0080 | KdDebuggerDataBlock |
| 0x0088 | PhysicalMemoryBlock: NumberOfRuns u32, pad, NumberOfPages u64, runs {BasePage, PageCount} u64 pairs from 0x98 (700 bytes: at most 42 runs) |
| 0x0F98 | DumpType |
| 0x0FA0 / 0x0FA8 | RequiredDumpSpace / SystemTime (FILETIME) |
| 0x0FB0 | Comment[128] (`PAGE` fill when unused) |
| 0x1030 .. 0x1054 | SystemUpTime, MiniDumpFields, SecondaryDataState, ProductType, SuiteMask, WriterStatus, KdSecondaryVersion (0x104D), Attributes (0x1050), BootId (0x1054) |
| 0x2000 | DumpType 1: page data of the runs, in run order |
| 0x2000 | DumpType 5 (bitmap) / 6 (live kernel bitmap, Task Manager 22H2+): `"SDMP"` (kernel) or `"FDMP"` (full), `"DUMP"`, FirstPage u64 @+0x20 (file offset of the first page), TotalPresentPages @+0x28, Pages @+0x30 (bitmap bits), bitmap @+0x38; bit i (LSB first) = PFN i; pages stored in PFN order |
| 0x2000 | DumpType 8 / 9 / 0xA (dbgeng `.dump /k`, `/ka`, `/f`): u32 0x40, `"RDMP"`, `"DUMP"`, MetadataSize @+0x10, FirstPageOffset @+0x18 (= 0x2020 + MetadataSize); 0x2020 PhysmemDesc (complete: TotalNumberOfPages @0x2028); PFN ranges {PFN u64, count u64} from 0x2030 until FirstPageOffset or a zero PFN |

Refused: 32-bit dumps, DumpType 4 (triage/mini), 2 (legacy summary), unknown types, a DumpType 1 whose run list is
the `PAGE` fill, inconsistent RDMP headers. A bitmap signature other than SDMP/FDMP is accepted only when
`ValidDump` is `DUMP`, the bitmap population equals TotalPresentPages and the data fits the file (with a warning);
otherwise refused naming the bytes found. A truncated file keeps the pages that are present (`truncated`, warning).
Opening a dump reads the header and bitmap only: whole 0x00/0xFF bitmap bytes are handled by regular expressions,
runs are accumulated in arrays and consecutive pages coalesce into one run. Measured for a 16 GiB bitmap (4M bits):
0.04 s when dense, 0.13 s with a hole every 64 pages, 1.7 s for the pathological every-other-page case.
Metadata: `dump_type`, `dump_type_value`, `bitmap_signature`, `directory_table_base`, `pfn_database`,
`ps_loaded_module_list`, `ps_active_process_head`, `kd_debugger_data_block`, `machine`, `number_processors`,
`bugcheck_code`, `bugcheck_parameters`, `system_time` (ISO 8601 UTC), `major_version`, `minor_version`, `comment`,
`attributes`, `physical_runs`, `present_pages`, `first_page_offset`, `header_physical_runs` (type 1).

Sources: kdmp-parser `src/lib/kdmp-parser-structs.h` and `kdmp-parser.h`
(https://github.com/0vercl0k/kdmp-parser, MIT) and its Rust port's RDMP layout notes
(https://docs.rs/kdmp-parser); Volatility 3 `layers/crash.py` and `symbols/windows/crash_common.json`
(`_SUMMARY_DUMP64`); Rekall `plugins/overlays/windows/crashdump.py` (`_BMP_DUMP_HEADER`). No source consulted
documents a `DMP_` bitmap signature.

### ELF cores (`elfcore.py`)

| Producer | Physical address | CPU state (DTB hint) |
|---|---|---|
| QEMU `dump-guest-memory` | `p_paddr`; `p_vaddr` = guest virtual with `-p`, else a copy of `p_paddr`; `p_filesz` may be < `p_memsz` (rest absent); PN_XNUM -> section 0 `sh_info` | per CPU a "CORE" NT_PRSTATUS and a "QEMU" note (type 0, `QEMUCPUState`: version, size, 16 GPRs, rip, rflags, 10 x 24-byte segments, `cr[5]` at 392, kernel_gs_base) |
| VirtualBox `dumpvmcore` | `p_paddr` = GCPhysStart, `p_vaddr` = 0, MMIO ranges `p_filesz` 0 | "VBCORE" 0xB00 (`DBGFCOREDESCRIPTOR`, magic 0xC01AC0DE, version, revision, CPU count), "VBCPU" 0xB01 per CPU (`DBGFCORECPU`: cr0/cr2/cr3/cr4 at 288/296/304/312); n_namesz excludes the NUL, names and data padded to 8 |

Other little-endian ELF cores with physical `p_paddr` open the same way (`producer: generic`); `p_paddr` = -1 segments
are skipped, aliases of already-mapped physical bytes are mapped once (`aliased_bytes`). Refused: process cores (all
`p_paddr` 0), big-endian cores. Metadata: `producer`, `elf_class`, `machine`, `cpus` [{cpu, cr0, cr2, cr3, cr4, rip}],
`cr3` (first CPU), `qemu_paging`, `vbox_version`, `vbox_revision`, `absent_tail_bytes`, `physical_runs`.

Sources: QEMU `dump/dump.c` (`write_elf64_load`, `write_elf32_load`, PN_XNUM) and `target/i386/arch_dump.c`
(https://github.com/qemu/qemu); VirtualBox `src/VBox/VMM/VMMR3/DBGFR3CoreWrite.cpp`,
`include/VBox/vmm/dbgfcorefmt.h`, `include/iprt/formats/elf-common.h` (https://github.com/VirtualBox/virtualbox).

### VMware saved state / snapshot (`vmware.py`)

| Part | Layout |
|---|---|
| header | u32 magic (0xBED2BED2, 0xBED3BED3 partial, 0xBAD1BAD1 restored, 0xBAD2BAD2, old 0xBED0BED0 / 0xBED2BED0), u32 version, u32 group count |
| group | name[64], u64 tags offset, u64 size (80 bytes, from offset 12) |
| tag | u16: bits 15..8 name length, 7..6 index count, 5..0 value size; name; u32 indices; value, or for value size 63 (block) / 62 (compressed block) u64 size on disk, u64 size in memory (u32 each when the magic's low nibble is 0), u16 pad length, pad, data; a zero tag ends the group |
| memory | `regionsCount`; per region `regionPPN[i]` (guest physical page), `regionPageNum[i]` (page in the memory data), `regionSize[i]` (pages); memory data = the `Memory` block when embedded, else the companion `.vmem`; no regions = one flat run |
| CPU | `CR64` per vCPU: a 72-byte block [cpu] (cr0..cr8) or 8-byte values [cpu][n] |

Each region maps independently (`regionPPN * 4096` <- `regionPageNum * 4096`), so memory above the PCI hole lands at
its guest physical address. Opening the state file finds `<stem>.vmem`; opening the `.vmem` finds `<stem>.vmss` /
`.vmsn`. A lone `.vmem` is mapped flat from 0 with a warning; a compressed embedded `Memory` block is refused.
Metadata: `state_file`, `vmem_file`, `magic`, `magic_name`, `mapping` (`regions`/`flat`), `regions`
[{ppn, page_num, pages}], `memory_embedded`, `cpus`, `cr3`, `physical_runs`.

Sources: crash-utility `vmware_vmss.h` / `vmware_vmss.c` (https://github.com/crash-utility/crash; written by VMware);
Volatility 2 `plugins/addrspaces/vmware.py` (pad length, 32-bit block sizes for old magics) and Volatility 3
`layers/vmware.py`.

### Windows 8+ hibernation files (`hiber.py`, codecs in `xpress.py`)

| Field | Win 8/8.1 | 10 1507/1511 | 10 1607 | 10 1703 .. 11 23H2 | 11 24H2/25H2 | 11 26H2 |
|---|---|---|---|---|---|---|
| LengthSelf (0x0C) = sizeof(PO_MEMORY_IMAGE) | 0x360 | 0x3B0 | 0x3C8 | 0x3D8 / 0x3E0 / 0x448 | 0x4D8 | 0x4F0 |
| NumPagesForLoader | 0x58 | 0x58 | 0x58 | 0x58 | 0x58 | 0x58 |
| FirstSecureRestorePage | - | 0x60 | 0x60 | 0x60 | 0x60 | 0x60 |
| FirstBootRestorePage | 0x60 | 0x68 | 0x68 | 0x68 | 0x68 | 0x68 |
| FirstKernelRestorePage | 0x68 | 0x70 | 0x70 | 0x70 | 0x70 | 0x70 |
| PerfInfo (`_PO_HIBER_PERF`) | 0x70 | 0x88 | 0x88 | 0x88 | 0x88 | 0x88 |
| PerfInfo.BootPagesProcessed | 0x1C0 | 0x210 | 0x218 | 0x228 | 0x230 | 0x248 |
| PerfInfo.KernelPagesProcessed | 0x1C8 | 0x218 | 0x220 | 0x230 | 0x238 | 0x250 |
| compression set header | 22-bit size, bit 31 Huffman | same | same | same | 21-bit size, bit 30 Huffman | same as 24H2 |

PageSize is at 0x18 (x64; at 0x14 in x86 files, which are refused). `_KPROCESSOR_STATE` is at 0x1000, so CR3 is at
0x1010 (`_KSPECIAL_REGISTERS` Cr0/Cr2/Cr3/Cr4). Signatures: `HIBR` hibernated, `HORM` hibernate once / resume many,
`RSTR` captured while resuming (opened with a warning), `WAKE` resumed: Windows zeroes everything after the first
4 KiB, so the file is refused unless restoration sets are still present. Lowercase `hibr`/`wake`/`rstr` and
`\x81\x81xpress` blocks are the Windows XP-7 format (refused).

Restoration sets: boot = NumPagesForLoader pages from page FirstBootRestorePage; kernel = KernelPagesProcessed pages
from page FirstKernelRestorePage (0 = none); FirstSecureRestorePage (Secure Kernel, encrypted) is reported, not
decoded. Each is a chain of compression sets: u32 header (bits 0-7 descriptor count 1..16, then size and codec as
above), that many u64 descriptors (bits 0-3 pages - 1, bits 4-63 first PFN), then the data: stored if its size equals
pages x 4096, else Xpress or Xpress Huffman; at most 16 pages (64 KiB) per set; the next set follows immediately.
The layout named by LengthSelf is tried first and must be confirmed by walking both chains to their exact page counts;
otherwise every other layout is tried and the one that checks out is used with a warning (an unknown LengthSelf, or
a servicing build that moved a PerfInfo counter). A set whose data fails its declared codec but decodes with the other
one is used and listed in `decode_problems`. A PFN present in both sets takes the kernel set's copy. Pages are
decompressed on demand, one LRU cache entry (1024 sets) per compression set.
Metadata: `signature`, `state`, `layout`, `layout_inferred`, `length_self`, `system_time`, `num_pages_for_loader`,
`first_boot_restore_page`, `first_kernel_restore_page`, `boot_pages_processed`, `kernel_pages_processed`,
`first_secure_restore_page`, `highest_physical_page`, `cr0`, `cr2`, `cr3`, `cr4`, `compression_sets`, `codecs`,
`pages`, `duplicate_pages`, `physical_runs`, `decode_problems`.

Sources: J. T. Sylve, V. Marziale, G. G. Richard III, "Modern Windows hibernation file analysis", Digital
Investigation 20 (2017), doi:10.1016/j.diin.2016.12.003 (https://cct.lsu.edu/~golden/Papers/modern-windows-hibernation-2017.pdf):
signatures, restoration sets, compression set and descriptor bits, `_KPROCESSOR_STATE` at 0x1000; Vergilius Project
`PO_MEMORY_IMAGE`, `_PO_HIBER_PERF`, `_KPROCESSOR_STATE`, `_KSPECIAL_REGISTERS` per build
(https://www.vergiliusproject.com/kernels/x64/); Volatility 3 PR #1036 `layers/hib.py`
(https://github.com/volatilityfoundation/volatility3/pull/1036): 24H2 size/Huffman bits and the moving
KernelPagesProcessed; M. Suiche, "Windows 11 Hibernation on ARM64" (https://msuiche.com/posts/windows-11-arm64-hibernation/):
signature values, 21-bit length with a 3-bit format field (25H2).

### Xpress, Xpress Huffman, LZNT1 (`xpress.py`)

Pure-Python decoders for [MS-XCA] (https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xca/):
Plain LZ77 (2.4, `COMPRESSION_FORMAT_XPRESS` = 3), LZ77+Huffman (2.2, `XPRESS_HUFF` = 4: 256-byte table of 4-bit
code lengths per 64 KiB output block, canonical codes up to 15 bits, the next block's table starts where the bit
reader stands) and LZNT1 (2.5, = 2: 4 KiB chunks, displacement/length split by position in the chunk). Two behaviours
not in the MS-XCA pseudocode were established against ntdll: LZ77+Huffman accepts a 32-bit match length after a
16-bit 0 (as Plain LZ77 does), and an LZNT1 chunk that decodes to less than 4 KiB but is followed by another chunk
stands for 4 KiB (zero-filled). Tests compare the decoders with ntdll `RtlCompressBuffer` output (Windows),
embedded ntdll output (all platforms) and the MS-XCA section 3 examples.
