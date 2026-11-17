# Formats and decoded structures

## Evidence container (`.keto`)

| Offset | Size | Field |
|---|---|---|
| 0 | 8 | magic `VRMNCR\0\1` |
| 8 | 4 | version (1) |
| 12 | 4 | header size (64) |
| 16 | 8 | segment table offset |
| 24 | 4 | segment count |
| 28 | 4 | flags |
| 32 | 8 | metadata offset |
| 40 | 8 | metadata length |
| 48 | 16 | reserved |

Segment table entry (32 bytes): `u32 space, u32 flags, u64 address, u64 length, u64 file_offset`.
Spaces: 0 vram, 1 sysmem, 2 bar0, 3 bar1, 4 rom, 5 residual (keyed by CUDA VA), 6 gpuva.

The metadata JSON holds:

- `tool`, `tool_version`, `created_utc`
- `acquisition` (method, examiner, notes, statistics)
- `device` (name, uuid, chipset/NVML arch/compute capability, VRAM size, VBIOS, driver)
- `segments` (each with SHA-256), `data_sha256`
- optional `live_snapshot` (recorded live-source answers)

`keto -f x.keto verify` re-hashes every segment.

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
