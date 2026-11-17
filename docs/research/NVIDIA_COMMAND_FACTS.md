# NVIDIA command-stream facts (Kepler to Blackwell)

Research notes for Keto's pushbuffer, QMD, engine-class and CUDA-binary decoders.
Collected 2026-11-17 from pinned source snapshots (table below). Every fact names its source
URL and carries a provenance tag. Defines in code blocks are copied verbatim from the cited
file (only trailing whitespace removed). Where something could not be found, it says so.

## Tags

| tag | meaning |
|---|---|
| `[NVIDIA-published]` | Header, manual or doc authored and published by NVIDIA: open-gpu-doc, open-gpu-kernel-modules, docs.nvidia.com, NVIDIA's nvgpu Tegra driver (public mirror). |
| `[nouveau/Mesa]` | Mesa (NVK, NAK, nouveau gallium, Mesa's copies of NVIDIA class headers) or the Linux nouveau kernel driver. |
| `[envytools]` | envytools documentation or rnndb. |
| `[cricket]` | RWTH-ACS/cricket. |
| `[LLVM]` | llvm-project (LLVM/clang). Added tag. |
| `[ZLUDA]` | vosen/ZLUDA. Added tag. |
| `[community-RE]` | Other reverse-engineering projects (redplait/denvdis, cloudcores/CuAssembler, n-eiling/cuda-fatbin-decompression). Added tag. |
| `[derived]` | Computed or inferred in this note from the cited sources; no source states it directly. |

Attribution and licences: NVIDIA class headers and manuals are "Copyright (c) NVIDIA CORPORATION"
under the MIT licence (https://github.com/NVIDIA/open-gpu-doc/blob/9fdf5c406200/LICENSE.md and the
header preambles). Mesa NAK/NVK: MIT. Linux nouveau: MIT. envytools: MIT. cricket: MIT.
LLVM: Apache-2.0 WITH LLVM-exception. ZLUDA: Apache-2.0. cuda-fatbin-decompression: Apache-2.0.
CuAssembler: MIT. denvdis: LGPL-2.1 (only attribute ids and names are reproduced).

## Source snapshots

| source | commit | base URL |
|---|---|---|
| NVIDIA open-gpu-doc | 9fdf5c4062007929d9f4e6cbad9c9771fe61b880 (2026-06-09) | https://github.com/NVIDIA/open-gpu-doc/tree/9fdf5c406200 |
| NVIDIA open-gpu-kernel-modules | e6a2e01579fbbd1ca2ed43fef2ee2589e9bd8bd9 (620.70.06) | https://github.com/NVIDIA/open-gpu-kernel-modules/tree/e6a2e01579fb/src/common/sdk/nvidia/inc/class |
| Mesa | 60d7516520ab31c5e42c5eaf2bf878c5f2538a3c (2026-11-17) | https://gitlab.freedesktop.org/mesa/mesa/-/tree/60d7516520ab/src/nouveau |
| Linux (nouveau) | 141b164bbe186423e295b139e40e8e2d11cf1341 (master, 2026-11-16) | https://github.com/torvalds/linux/tree/141b164bbe18/drivers/gpu/drm/nouveau |
| nvgpu (NVIDIA Tegra GPU driver, OE4T mirror) | 21d928824dc7ca3dc17603a53b11edc6641ace2d (branch patches-rel-36) | https://github.com/OE4T/linux-nvgpu/tree/21d928824dc7/drivers/gpu/nvgpu |
| envytools | f102b82381f3f11cee113d16374c87091db039d9 | https://github.com/envytools/envytools/tree/f102b82381f3 |
| LLVM | af6967c85227696ec08ff692007a23a603bb18d1 | https://github.com/llvm/llvm-project/tree/af6967c85227 |
| cricket | 5d55bd582fc7acbb2a12c45f104020566a67218a | https://github.com/RWTH-ACS/cricket/tree/5d55bd582fc7 |
| ZLUDA | eb89ae3b23b2abaf8480e496fdd5d51f0651d330 | https://github.com/vosen/ZLUDA/tree/eb89ae3b23b2 |
| cuda-fatbin-decompression | 9b194a9aa526b71131990ddd97ff5c41a273ace5 | https://github.com/n-eiling/cuda-fatbin-decompression/tree/9b194a9aa526 |
| CuAssembler | 96a9f72baf00f40b9b299653fcef8d3e2b4a3d49 | https://github.com/cloudcores/CuAssembler/tree/96a9f72baf00 |
| denvdis | 0a39f82bc3709cec5144de7435bec97f2e3c9052 | https://github.com/redplait/denvdis/tree/0a39f82bc370 |

Cross-checks done while collecting `[derived]`: every `cl*qmd.h` in open-gpu-doc is byte-for-byte
identical (ignoring whitespace) to Mesa's copy in `src/nouveau/headers/nvidia/classes/`. The
host headers `cla06f/cla16f/clb06f/clc06f/clc36f/clc46f/clc56f.h` define the same `#define`s in
open-gpu-doc and open-gpu-kernel-modules (they differ only in comments and formatting).

---

## 0. Generation map: chip to classes to QMD

Which class ids a channel binds with `SET_OBJECT` on each chip family, and which QMD version NVK
writes. The QMD column "defined" lists the versions in the compute class's own `cl<id>qmd.h`.

| generation / chip | host | copy | compute | 3D | i2m | QMD versions defined | QMD NVK writes |
|---|---|---|---|---|---|---|---|
| Kepler GK104/106/107 | A06F | A0B5 | A0C0 | A097 | A040 | 00_06, 01_06, 01_07 | 00_06 |
| Kepler GK20A (Tegra K1) | A06F | A0B5 | A0C0 | A297 | A040 | 00_06, 01_06, 01_07 | 00_06 |
| Kepler GK110/GK110B | A16F | A0B5 | A1C0 | A197 | A140 | 00_06, 01_07 | 01_07 |
| Kepler GK208 | A06F | A0B5 | A1C0 | A197 | A140 | 00_06, 01_07 | 01_07 |
| Maxwell GM107/GM108 | A16F | A0B5, B0B5 | B0C0 | B097 | A140 | 00_06, 01_07 | 01_07 |
| Maxwell GM20x | B06F | B0B5 | B1C0 | B197 | A140 | 00_06, 01_07 | 01_07 |
| Maxwell GM20B (Tegra X1) | B06F | B0B5 (nvgpu also accepts A0B5) | B1C0 | B197 | A140 | 00_06, 01_07 | 01_07 |
| Pascal GP100 | C06F | C0B5 | C0C0 | C097 | A140 | 01_07, 02_00, 02_01 | 02_01 |
| Pascal GP102..GP108 | C06F | C0B5, C1B5 | C1C0 | C197 | A140 | 01_07, 02_00, 02_01 | 02_01 |
| Pascal GP10B (Tegra X2) | C06F | C0B5 | C0C0 | C097 | A140 | 01_07, 02_00, 02_01 | 02_01 |
| Volta GV100 | C36F | C3B5 | C3C0 | C397 | A140 | 02_02 | 02_02 |
| Volta GV11B (Xavier) | C36F | C3B5 | C3C0 | C397 | not listed by nvgpu | 02_02 | (NVK has no GV11B support) |
| Turing TU10x/TU11x | C46F | C5B5 | C5C0 | C597 | A140 | 02_03 | 02_02 |
| Ampere GA100 | C56F | C6B5 | C6C0 | C697 | A140 | 02_03, 02_04, 03_00 | 03_00 |
| Ampere GA10x | C56F | C7B5 (nouveau non-GSP path also exposes C6B5) | C7C0 | C797 | A140 | 02_03, 02_04, 03_00 | 03_00 |
| Ampere GA10B (Orin) | C76F | C7B5 | C7C0 | C797 | not listed by nvgpu | 02_03, 02_04, 03_00 | 03_00 |
| Ada AD10x | C56F | C7B5 | C9C0 | C997 | A140 | 02_04, 03_00 | 03_00 |
| Hopper GH100 | C86F | C8B5 | CBC0 | CB97 | A140 | 03_00, 04_00 | 04_00 |
| Blackwell GB10x | C96F | C9B5 | CDC0 | CD97 | CD40 | 04_01, 05_00, 05_01 | 05_00 |
| Blackwell GB20x | CA6F | CAB5 | CEC0 | CE97 | CD40 | 04_01, 05_00, 05_01 | 05_00 |
| Blackwell Tegra (Thor) | not found | not found | not found | not found | not found | | |

2D is FERMI_TWOD_A (902D) on every row above (nouveau gr tables and GSP-RM tables). Usermode
doorbell classes: C361 Volta, C461 Turing, C561 Ampere and Ada, C661 Hopper and GB10x, C761 GB20x.

Sources for the rows:
- Kepler to Turing (pre-GSP nouveau): `{ -1, -1, CLASS }` tables in
  https://github.com/torvalds/linux/blob/141b164bbe18/drivers/gpu/drm/nouveau/nvkm/engine/gr/ (files gk104.c, gk110.c, gk110b.c, gk208.c, gk20a.c, gm107.c, gm200.c, gm20b.c, gp100.c, gp102.c, gp104.c, gp107.c, gp10b.c, gv100.c, tu102.c, ga102.c),
  https://github.com/torvalds/linux/blob/141b164bbe18/drivers/gpu/drm/nouveau/nvkm/engine/fifo/ (gk104.c, gk110.c, gk208.c, gk20a.c, gm107.c, gm200.c, gp100.c, gv100.c, tu102.c, ga100.c, ga102.c),
  https://github.com/torvalds/linux/blob/141b164bbe18/drivers/gpu/drm/nouveau/nvkm/engine/ce/ (gk104.c, gm107.c, gm200.c, gp100.c, gp102.c, gv100.c, tu102.c, ga100.c, ga102.c),
  chip to constructor bindings in https://github.com/torvalds/linux/blob/141b164bbe18/drivers/gpu/drm/nouveau/nvkm/engine/device/base.c
  (GK20A uses gk104_ce/gk20a_fifo/gk20a_gr; GM20B uses gm200_ce/gm200_fifo/gm20b_gr; GP10B uses gp100_ce/gp100_fifo/gp10b_gr; GP102/GP107 use gp100_fifo). `[nouveau/Mesa]`
- Turing to Blackwell (GSP-RM nouveau): `.fifo.chan.class`, `.ce.class`, `.gr.class.{i2m,twod,threed,compute}`, `.usermode.class` in
  https://github.com/torvalds/linux/blob/141b164bbe18/drivers/gpu/drm/nouveau/nvkm/subdev/gsp/rm/ (tu1xx.c, ga100.c, ga1xx.c, ad10x.c, gh100.c, gb10x.c, gb20x.c). `[nouveau/Mesa]`
- Tegra GM20B/GP10B/GV11B/GA10B: class validators
  https://github.com/OE4T/linux-nvgpu/blob/21d928824dc7/drivers/gpu/nvgpu/hal/class/class_gm20b.c, class_gp10b.c, class_gv11b_fusa.c, class_ga10b.c,
  ids in https://github.com/OE4T/linux-nvgpu/blob/21d928824dc7/drivers/gpu/nvgpu/include/nvgpu/class.h. `[NVIDIA-published]`
  (class_gp10b.c also accepts MAXWELL_B/MAXWELL_COMPUTE_B.)
- QMD "NVK writes": `nak_fill_qmd()` / `nak_qmd_size_B()` in
  https://gitlab.freedesktop.org/mesa/mesa/-/blob/60d7516520ab/src/nouveau/compiler/nak/qmd.rs
  selects V05_00 for `cls_compute >= BLACKWELL_COMPUTE_A`, V04_00 for `>= HOPPER_COMPUTE_A`, V03_00 for `>= AMPERE_COMPUTE_A`,
  V02_02 for `>= VOLTA_COMPUTE_A`, V02_01 for `>= PASCAL_COMPUTE_A`, V01_07 for `>= KEPLER_COMPUTE_B`, V00_06 for `>= KEPLER_COMPUTE_A`. `[nouveau/Mesa]`
- QMD "defined": `Queue Meta Data, Version XX_YY` banners in https://github.com/NVIDIA/open-gpu-doc/tree/9fdf5c406200/classes/compute. `[NVIDIA-published]`

What the proprietary CUDA driver writes per class is not published. Only Ampere V03_00 is already
confirmed by Keto. Turing is the visible mismatch: `clc5c0qmd.h` defines only V02_03, but NVK
writes V02_02. Decoders should therefore read the version fields (section 1.3) rather than
assume a version from the class. `[derived]`

VOLTA_COMPUTE_B (C4C0) has a class header (`clc4c0.h` in open-gpu-kernel-modules) and a QMD header
(`clc4c0qmd.h`, V02_02). No chip that binds it was found in nouveau, nvgpu or Mesa.

---

## 1. QMD (compute launch descriptor) layouts

### 1.1 The MW() notation

Every QMD header from Kepler to Blackwell uses the same `MW(hi:lo)` multi-word bit-range notation,
including Hopper (`clcbc0qmd.h`) and Blackwell (`clcdc0qmd.h`, `clcec0qmd.h`). The headers carry
this explanatory comment, verbatim from
https://github.com/NVIDIA/open-gpu-doc/blob/9fdf5c406200/classes/compute/clc6c0qmd.h `[NVIDIA-published]`:

```c
// The below C preprocessor definitions describe "multi-word" structures, where
// fields may have bit numbers beyond 32.  For example, MW(127:96) means
// the field is in bits 0-31 of word number 3 of the structure.  The "MW(X:Y)"
// syntax is to distinguish from similar "X:Y" single-word definitions: the
// macros historically used for single-word definitions would fail with
// multi-word definitions.
//
// See nvmisc.h:DRF_VAL_MW() in the source code of the kernel
```

Bit `n` is bit `n % 32` of little-endian 32-bit word `n / 32`. Array fields take the form
`MW((hi_base+(i)*stride):(lo_base+(i)*stride))`. The Blackwell headers add sections titled
"(inferred arrays)" that use the same macro, with a second index in V05_01, for example
`NVCDC0_QMDV05_01_SUB_TASK_CONSTANT_BANK_VALID(i,j) MW((886+(i)*416+(j)*202):(886+(i)*416+(j)*202))`
(https://github.com/NVIDIA/open-gpu-doc/blob/9fdf5c406200/classes/compute/clcdc0qmd.h). No
Hopper or Blackwell header uses a macro other than `MW()`. `[NVIDIA-published]`

### 1.2 Size, alignment, version per class

| QMD version | size | defined in (open-gpu-doc `classes/compute/`) | written by NVK for |
|---|---|---|---|
| V00_06 | 256 B | cla0c0qmd.h, cla1c0qmd.h, clb0c0qmd.h, clb1c0qmd.h | KEPLER_COMPUTE_A |
| V01_06 | 256 B | cla0c0qmd.h | (none) |
| V01_07 | 256 B | cla0c0qmd.h, cla1c0qmd.h, clb0c0qmd.h, clb1c0qmd.h, clc0c0qmd.h, clc1c0qmd.h | KEPLER_COMPUTE_B, MAXWELL_COMPUTE_A/B |
| V02_00 | 256 B | clc0c0qmd.h, clc1c0qmd.h | (none) |
| V02_01 | 256 B | clc0c0qmd.h, clc1c0qmd.h | PASCAL_COMPUTE_A/B |
| V02_02 | 256 B | clc3c0qmd.h, clc4c0qmd.h | VOLTA_COMPUTE_A, TURING_COMPUTE_A |
| V02_03 | 256 B | clc5c0qmd.h, clc6c0qmd.h, clc7c0qmd.h | (none) |
| V02_04 | 256 B | clc6c0qmd.h, clc7c0qmd.h, clc9c0qmd.h | (none) |
| V03_00 | 256 B | clc6c0qmd.h, clc7c0qmd.h, clc9c0qmd.h, clcbc0qmd.h | AMPERE_COMPUTE_A/B, ADA_COMPUTE_A |
| V04_00 | 384 B | clcbc0qmd.h | HOPPER_COMPUTE_A |
| V04_01 | 384 B | clcdc0qmd.h, clcec0qmd.h | (none) |
| V05_00 | 384 B | clcdc0qmd.h, clcec0qmd.h | BLACKWELL_COMPUTE_A/B |
| V05_01 | 384 B | clcdc0qmd.h, clcec0qmd.h | (none) |

No layout older than V00_06 exists in any compute header. There is no
QMD header for FERMI_COMPUTE_A/B (`cl90c0.h`, `cl91c0.h` have no `*qmd.h`). No version newer
than V05_01 exists in any of the snapshots. `[NVIDIA-published]`

Size facts:
- No header defines the QMD size as a constant. The highest non-array `MW` bit is 2047 in every
  version up to V03_00, and 3071 in V04_00, V04_01 and V05_00. That gives 256 and 384 bytes. `[derived]`
- NAK stores the QMD as `[u32; 64]` for V00_06 to V03_00 and as `[u32; 96]` for V04_00 and V05_00
  (https://gitlab.freedesktop.org/mesa/mesa/-/blob/60d7516520ab/src/nouveau/compiler/nak/qmd.rs). `[nouveau/Mesa]`
- Hopper and Blackwell inline-QMD launches select between 256 and 384 bytes: `SET_INLINE_QMD_ADDRESS_A_INLINE_SIZE 30:30`,
  `INLINE_256 0x0` / `INLINE_384 0x1` in clcbc0.h, clcdc0.h and clcec0.h (section 2.1). `[NVIDIA-published]`
- V05_01 is a multi-sub-task variant. Its `SUB_TASK_*(i)` fields start at bit 768 with a stride of
  416 bits, and `NUM_SUB_TASKS_PER_TASK` is `MW(157:154)`. Inside 3072 bits, indices i = 0..4 fit:
  the last field of i = 4 ends at bit 2847, and i = 5 would end at bit 3263. `[derived]`

Alignment: `SEND_PCAS_A_QMD_ADDRESS_SHIFTED8 31:0` (all compute classes A0C0..CEC0) carries
`address >> 8`, so a QMD that a launch names is 256-byte aligned. `[NVIDIA-published]` NVK allocates
QMDs with alignment 0x100 (`nvk_cmd_buffer_alloc_qmd(cmd, qmd_size_B, 0x100, ...)`) and pushes
`qmd_addr >> 8` (https://gitlab.freedesktop.org/mesa/mesa/-/blob/60d7516520ab/src/nouveau/vulkan/nvk_cmd_dispatch.c). `[nouveau/Mesa]`
`DEPENDENT_QMD*_POINTER` fields also hold `qmd_addr >> 8` (NAK `qmd_impl_set_dependent_qmd_addr`). `[nouveau/Mesa]`

### 1.3 Detecting the version from raw bytes

| versions | QMD_VERSION / QMD_MINOR_VERSION | QMD_MAJOR_VERSION |
|---|---|---|
| V00_06 ... V04_01 | `MW(579:576)` (named `QMD_MINOR_VERSION` from V04_00) | `MW(583:580)` |
| V05_00, V05_01 | `MW(467:464)` (`QMD_MINOR_VERSION`) | `MW(471:468)` |

So for V00_06 to V04_01, byte 72 (word 18, bits 7:0) holds `major << 4 | minor`. For V05_xx,
byte 58 (word 14, bits 23:16) holds it. `[derived]` from the defines in section 1.5.
What the other window holds in each version, which matters for false positives `[derived]`:
- Bits 464..471: `CTA_RASTER_WIDTH_RESUME` in V00_06 and V01_07, `QMD_RESERVED14A` in V02_01..V02_04,
  unassigned in V03_00, `DEPENDENT_QMD0_POINTER` in V04_00/V04_01.
- Bits 576..583: `RELEASE_SEMAPHORE0_PAYLOAD_UPPER` in V05_00/V05_01.

A practical order: check the V05 window for major = 5 first, then the 576 window for major 0..4.
V05_00 and V05_01 differ by `QMD_MINOR_VERSION`. NAK also writes `QMD_TYPE = 2` (`GRID_CTA`)
and `QMD_GROUP_ID = 0x1f` into every V05_00 QMD (qmd.rs). `[nouveau/Mesa]`

### 1.4 Key-field matrix

Bit ranges are `MW(hi:lo)`, with `i` the constant-buffer or release index. All values are from
the defines reproduced in section 1.5. `[NVIDIA-published]`

| field | V00_06 / V01_06 / V01_07 | V02_00 / V02_01 | V02_02 | V02_03 | V02_04 | V03_00 | V04_00 / V04_01 | V05_00 |
|---|---|---|---|---|---|---|---|---|
| version (minor) | 579:576 | 579:576 | 579:576 | 579:576 | 579:576 | 579:576 | 579:576 `QMD_MINOR_VERSION` | 467:464 `QMD_MINOR_VERSION` |
| major | 583:580 | 583:580 | 583:580 | 583:580 | 583:580 | 583:580 | 583:580 | 471:468 |
| program, low | `PROGRAM_OFFSET` 287:256 | `PROGRAM_OFFSET` 287:256 | `PROGRAM_OFFSET` 287:256 and `PROGRAM_ADDRESS_LOWER` 1567:1536 | `PROGRAM_ADDRESS_LOWER` 1567:1536 | same | same | `PROGRAM_ADDRESS_LOWER` 1247:1216 | `PROGRAM_ADDRESS_LOWER_SHIFTED4` 1055:1024 |
| program, high | (none) | (none) | `PROGRAM_ADDRESS_UPPER` 1584:1568 | 1584:1568 | 1584:1568 | 1584:1568 | 1272:1248 | `_UPPER_SHIFTED4` 1076:1056 |
| grid W / H / D | `CTA_RASTER_*` 415:384 / 431:416 / 447:432 | 415:384 / 431:416 / 463:448 | same as V02_00 | same | same | same | `GRID_*` 1055:1024 / 1071:1056 / 1103:1088 | `GRID_*` 1279:1248 / 1295:1280 / 1327:1312 |
| block x / y / z | 607:592 / 623:608 / 639:624 | same | same | same | same | same | 1167:1152 / 1183:1168 / 1199:1184 (V04_01: z 1191:1184) | 1103:1088 / 1119:1104 / 1127:1120 |
| shared memory | `SHARED_MEMORY_SIZE` 561:544 | 561:544 | 561:544 | 561:544 | 561:544 | 561:544 | 601:584 | `SHARED_MEMORY_SIZE_SHIFTED7` 1162:1152 |
| registers | `REGISTER_COUNT` 1503:1496 | `REGISTER_COUNT` 991:984 | `REGISTER_COUNT` 991:984 and `REGISTER_COUNT_V` 656:648 | both, as V02_02 | `REGISTER_COUNT_V` 656:648 | `REGISTER_COUNT_V` 656:648 | `REGISTER_COUNT` 1208:1200 | `REGISTER_COUNT` 1136:1128 |
| barriers | 1471:1467 | 959:955 | 959:955 | 959:955 | 959:955 | 767:763 | 1215:1211 | 1141:1137 |
| CB valid(i) | 640+i | 640+i | 640+i | 640+i | 640+i | 640+i | 416+4i | 1856+4i |
| CB addr low(i) | 959+64i:928+64i | 1055+64i:1024+64i | same | same | same | same | `_SHIFTED6` 1567+64i:1536+64i | `_SHIFTED6` 1375+64i:1344+64i |
| CB addr high(i) | 967+64i:960+64i | 1072+64i:1056+64i | same | same | same | same | `_SHIFTED6` 1586+64i:1568+64i | `_SHIFTED6` 1394+64i:1376+64i |
| CB size(i) | `CONSTANT_BUFFER_SIZE` 991+64i:975+64i | `SIZE_SHIFTED4` 1087+64i:1075+64i | same | same | same | same | `SIZE_SHIFTED4` 1599+64i:1587+64i | `SIZE_SHIFTED4` 1407+64i:1395+64i |
| release0 addr low | 767:736 | 767:736 | 767:736 | 767:736 | 767:736 | 799:768 | `RELEASE_SEMAPHORE0_ADDR_LOWER` 671:640 | 511:480 |
| release0 addr high | 775:768 | 775:768 | 775:768 | 775:768 | 775:768 | 807:800 | 696:672 | 536:512 |
| release0 payload low | `RELEASE0_PAYLOAD` 831:800 | 831:800 | 831:800 | 831:800 | 831:800 | `RELEASE0_PAYLOAD_LOWER` 863:832 | 735:704 | 575:544 |
| release0 payload high | (none) | (none) | (none) | (none) | (none) | 895:864 | 767:736 | 607:576 |
| release0 enable | (none) | (none) | (none) | (none) | (none) | 823:823 | `RELEASE_ENABLE(i)` 320+16i | `RELEASE_ENABLE(i)` 288+16i |
| release0 structure size | 799:799 | 799:799 | 799:799 | 799:799 | 799:799 | 831:830 | `RELEASE_STRUCTURE_SIZE(i)` 322+16i:321+16i | 290+16i:289+16i |
| release0 64-bit payload | (none) | (none) | (none) | (none) | (none) | 829:829 | `RELEASE_PAYLOAD64B(i)` 332+16i | 300+16i |
| local mem low | 1463:1440 | 951:928 | 951:928 | 951:928 | 951:928 | 759:736 | 535:512 | `_SHIFTED4` 1199:1184 |
| local mem high | 1495:1472 | 983:960 | 983:960 | 983:960 | 983:960 | 1623:1600 | 567:544 | `_SHIFTED4` 1215:1200 |
| CRS size | 1527:1504 | 1015:992 | 1015:992 | (none) | (none) | (none) | (none) | (none) |
| SASS_VERSION | 1535:1528 | 1023:1016 | 1023:1016 | 1023:1016 | 1023:1016 | 1663:1656 | 543:536 | 455:448 |
| dependent QMD pointer | V01_07 only: 191:160 | V02_00: 191:160; V02_01: 511:480 | 511:480 | 511:480 | `DEPENDENT_QMD0_POINTER` 511:480 | 511:480 | 479:448 | 415:384 |
| queue / type | V01_07 only: `IS_QUEUE` 200:200 | V02_00: 200:200; V02_01: 136:136 | 136:136 | 136:136 | 136:136 | 136:136 | `QMD_TYPE` 25:23 | `QMD_TYPE` 153:151 |

V01_06 has the same key fields as V00_06 and no `DEPENDENT_QMD_POINTER` or `IS_QUEUE`.
V04_01 equals V04_00 for every key field except `CTA_THREAD_DIMENSION2` (8 bits instead of 16).
Release 1 and release 2 (V04+/V05: `RELEASE_SEMAPHORE1_*`, `RELEASE_SEMAPHORE2_*`) exist but are
not tabulated. `[NVIDIA-published]`

Encodings, as NAK fills them (https://gitlab.freedesktop.org/mesa/mesa/-/blob/60d7516520ab/src/nouveau/compiler/nak/qmd.rs) `[nouveau/Mesa]`:
- `_SHIFTED4` / `_SHIFTED6` / `_SHIFTED7` mean the stored value is the byte quantity shifted right
  by 4 / 6 / 7. NAK asserts the low bits are zero. It rounds shared memory up to 256 bytes for V05 and
  local memory up to 16 bytes.
- Constant-buffer (address shift, size shift) per version: V00_06 and V01_07 (none, none), so the
  size is in bytes; V02_01, V02_02 and V03_00 (none, 4); V04_00 and V05_00 (6, 4).
- Program address: V00_06, V01_07 and V02_01 write the 32-bit `PROGRAM_OFFSET`
  (`qmd_impl_set_prog_addr_32`). V02_02, V03_00 and V04_00 write `PROGRAM_ADDRESS_LOWER/UPPER`
  unshifted. V05_00 writes `PROGRAM_ADDRESS_*_SHIFTED4`, so `address = ((UPPER << 32) | LOWER) << 4`.
- Register field: `REGISTER_COUNT` for V00_06, V01_07, V02_01, V04_00 and V05_00, and
  `REGISTER_COUNT_V` for V02_02 and V03_00. Gallium's Volta path also uses `REGISTER_COUNT_V` and
  64-bit `PROGRAM_ADDRESS_LOWER/UPPER` for V02_02
  (https://gitlab.freedesktop.org/mesa/mesa/-/blob/60d7516520ab/src/gallium/drivers/nouveau/nvc0/nve4_compute.c, `gv100_compute_setup_launch_desc`).
- `L1_CONFIGURATION` (V00_06, V01_07) is set to 16/32/48 KB enum values. `MIN/MAX/TARGET_SM_CONFIG_SHARED_MEM_SIZE`
  (V02_02+) are set from `gv100_get_hw_smem_sizes()`.

Release-structure enums (verbatim, same headers) `[NVIDIA-published]`: V00_06..V02_04 have
`RELEASE0_STRUCTURE_SIZE_FOUR_WORDS 0x0` and `ONE_WORD 0x1`. V03_00, V04_xx and V05_xx have
`SEMAPHORE_FOUR_WORDS 0x0`, `SEMAPHORE_ONE_WORD 0x1` and `SEMAPHORE_TWO_WORDS 0x2`.
`QMD_TYPE` (V04_00, V05_00): `QUEUE 0`, `GRID_NULL 1`, `GRID_CTA 2`, `GRID_GPC_CGA 3`, `GRID_GPU_CGA 4`,
`GRID_GPU_GPC_CGA 5`.

### 1.5 Verbatim key defines per QMD version

Selection: the version, program, grid, block, shared-memory, register, barrier, constant-buffer,
release0, local-memory, SASS, dependency, queue/type and SM-config fields of each version, taken
from one representative header. The "Scope" line names the other headers and any differences.
Copied by script, unedited.

#### QMD V00_06 -- `cla0c0qmd.h`

Source: https://github.com/NVIDIA/open-gpu-doc/blob/9fdf5c406200/classes/compute/cla0c0qmd.h  [NVIDIA-published]  
Scope: Kepler (KEPLER_COMPUTE_A); also defined in cla1c0qmd.h, clb0c0qmd.h, clb1c0qmd.h (identical defines)

```c
#define NVA0C0_QMDV00_06_PROGRAM_OFFSET                            MW(287:256)
#define NVA0C0_QMDV00_06_CTA_RASTER_WIDTH                          MW(415:384)
#define NVA0C0_QMDV00_06_CTA_RASTER_HEIGHT                         MW(431:416)
#define NVA0C0_QMDV00_06_CTA_RASTER_DEPTH                          MW(447:432)
#define NVA0C0_QMDV00_06_SHARED_MEMORY_SIZE                        MW(561:544)
#define NVA0C0_QMDV00_06_QMD_VERSION                               MW(579:576)
#define NVA0C0_QMDV00_06_QMD_MAJOR_VERSION                         MW(583:580)
#define NVA0C0_QMDV00_06_CTA_THREAD_DIMENSION0                     MW(607:592)
#define NVA0C0_QMDV00_06_CTA_THREAD_DIMENSION1                     MW(623:608)
#define NVA0C0_QMDV00_06_CTA_THREAD_DIMENSION2                     MW(639:624)
#define NVA0C0_QMDV00_06_CONSTANT_BUFFER_VALID(i)                  MW((640+(i)*1):(640+(i)*1))
#define NVA0C0_QMDV00_06_L1_CONFIGURATION                          MW(671:669)
#define NVA0C0_QMDV00_06_RELEASE0_ADDRESS_LOWER                    MW(767:736)
#define NVA0C0_QMDV00_06_RELEASE0_ADDRESS_UPPER                    MW(775:768)
#define NVA0C0_QMDV00_06_RELEASE0_STRUCTURE_SIZE                   MW(799:799)
#define NVA0C0_QMDV00_06_RELEASE0_STRUCTURE_SIZE_FOUR_WORDS        0x00000000
#define NVA0C0_QMDV00_06_RELEASE0_STRUCTURE_SIZE_ONE_WORD          0x00000001
#define NVA0C0_QMDV00_06_RELEASE0_PAYLOAD                          MW(831:800)
#define NVA0C0_QMDV00_06_CONSTANT_BUFFER_ADDR_LOWER(i)             MW((959+(i)*64):(928+(i)*64))
#define NVA0C0_QMDV00_06_CONSTANT_BUFFER_ADDR_UPPER(i)             MW((967+(i)*64):(960+(i)*64))
#define NVA0C0_QMDV00_06_CONSTANT_BUFFER_SIZE(i)                   MW((991+(i)*64):(975+(i)*64))
#define NVA0C0_QMDV00_06_SHADER_LOCAL_MEMORY_LOW_SIZE              MW(1463:1440)
#define NVA0C0_QMDV00_06_BARRIER_COUNT                             MW(1471:1467)
#define NVA0C0_QMDV00_06_SHADER_LOCAL_MEMORY_HIGH_SIZE             MW(1495:1472)
#define NVA0C0_QMDV00_06_REGISTER_COUNT                            MW(1503:1496)
#define NVA0C0_QMDV00_06_SHADER_LOCAL_MEMORY_CRS_SIZE              MW(1527:1504)
#define NVA0C0_QMDV00_06_SASS_VERSION                              MW(1535:1528)
```

#### QMD V01_06 -- `cla0c0qmd.h`

Source: https://github.com/NVIDIA/open-gpu-doc/blob/9fdf5c406200/classes/compute/cla0c0qmd.h  [NVIDIA-published]  
Scope: Kepler (only in cla0c0qmd.h)

```c
#define NVA0C0_QMDV01_06_PROGRAM_OFFSET                            MW(287:256)
#define NVA0C0_QMDV01_06_CTA_RASTER_WIDTH                          MW(415:384)
#define NVA0C0_QMDV01_06_CTA_RASTER_HEIGHT                         MW(431:416)
#define NVA0C0_QMDV01_06_CTA_RASTER_DEPTH                          MW(447:432)
#define NVA0C0_QMDV01_06_SHARED_MEMORY_SIZE                        MW(561:544)
#define NVA0C0_QMDV01_06_QMD_VERSION                               MW(579:576)
#define NVA0C0_QMDV01_06_QMD_MAJOR_VERSION                         MW(583:580)
#define NVA0C0_QMDV01_06_CTA_THREAD_DIMENSION0                     MW(607:592)
#define NVA0C0_QMDV01_06_CTA_THREAD_DIMENSION1                     MW(623:608)
#define NVA0C0_QMDV01_06_CTA_THREAD_DIMENSION2                     MW(639:624)
#define NVA0C0_QMDV01_06_CONSTANT_BUFFER_VALID(i)                  MW((640+(i)*1):(640+(i)*1))
#define NVA0C0_QMDV01_06_L1_CONFIGURATION                          MW(671:669)
#define NVA0C0_QMDV01_06_RELEASE0_ADDRESS_LOWER                    MW(767:736)
#define NVA0C0_QMDV01_06_RELEASE0_ADDRESS_UPPER                    MW(775:768)
#define NVA0C0_QMDV01_06_RELEASE0_STRUCTURE_SIZE                   MW(799:799)
#define NVA0C0_QMDV01_06_RELEASE0_STRUCTURE_SIZE_FOUR_WORDS        0x00000000
#define NVA0C0_QMDV01_06_RELEASE0_STRUCTURE_SIZE_ONE_WORD          0x00000001
#define NVA0C0_QMDV01_06_RELEASE0_PAYLOAD                          MW(831:800)
#define NVA0C0_QMDV01_06_CONSTANT_BUFFER_ADDR_LOWER(i)             MW((959+(i)*64):(928+(i)*64))
#define NVA0C0_QMDV01_06_CONSTANT_BUFFER_ADDR_UPPER(i)             MW((967+(i)*64):(960+(i)*64))
#define NVA0C0_QMDV01_06_CONSTANT_BUFFER_SIZE(i)                   MW((991+(i)*64):(975+(i)*64))
#define NVA0C0_QMDV01_06_SHADER_LOCAL_MEMORY_LOW_SIZE              MW(1463:1440)
#define NVA0C0_QMDV01_06_BARRIER_COUNT                             MW(1471:1467)
#define NVA0C0_QMDV01_06_SHADER_LOCAL_MEMORY_HIGH_SIZE             MW(1495:1472)
#define NVA0C0_QMDV01_06_REGISTER_COUNT                            MW(1503:1496)
#define NVA0C0_QMDV01_06_SHADER_LOCAL_MEMORY_CRS_SIZE              MW(1527:1504)
#define NVA0C0_QMDV01_06_SASS_VERSION                              MW(1535:1528)
```

#### QMD V01_07 -- `cla1c0qmd.h`

Source: https://github.com/NVIDIA/open-gpu-doc/blob/9fdf5c406200/classes/compute/cla1c0qmd.h  [NVIDIA-published]  
Scope: Kepler GK110+/Maxwell/Pascal headers (cla0c0, cla1c0, clb0c0, clb1c0, clc0c0, clc1c0); key fields identical, only IS_QUEUE / reserved / RUN_CTA_IN_ONE_SM_PARTITION / SM_GLOBAL_CACHING_ENABLE / HW_ONLY_SCG_TYPE differ

```c
#define NVA1C0_QMDV01_07_DEPENDENT_QMD_POINTER                     MW(191:160)
#define NVA1C0_QMDV01_07_IS_QUEUE                                  MW(200:200)
#define NVA1C0_QMDV01_07_DEPENDENT_QMD_TYPE                        MW(206:206)
#define NVA1C0_QMDV01_07_DEPENDENT_QMD_TYPE_QUEUE                  0x00000000
#define NVA1C0_QMDV01_07_DEPENDENT_QMD_TYPE_GRID                   0x00000001
#define NVA1C0_QMDV01_07_PROGRAM_OFFSET                            MW(287:256)
#define NVA1C0_QMDV01_07_CTA_RASTER_WIDTH                          MW(415:384)
#define NVA1C0_QMDV01_07_CTA_RASTER_HEIGHT                         MW(431:416)
#define NVA1C0_QMDV01_07_CTA_RASTER_DEPTH                          MW(447:432)
#define NVA1C0_QMDV01_07_SHARED_MEMORY_SIZE                        MW(561:544)
#define NVA1C0_QMDV01_07_QMD_VERSION                               MW(579:576)
#define NVA1C0_QMDV01_07_QMD_MAJOR_VERSION                         MW(583:580)
#define NVA1C0_QMDV01_07_CTA_THREAD_DIMENSION0                     MW(607:592)
#define NVA1C0_QMDV01_07_CTA_THREAD_DIMENSION1                     MW(623:608)
#define NVA1C0_QMDV01_07_CTA_THREAD_DIMENSION2                     MW(639:624)
#define NVA1C0_QMDV01_07_CONSTANT_BUFFER_VALID(i)                  MW((640+(i)*1):(640+(i)*1))
#define NVA1C0_QMDV01_07_L1_CONFIGURATION                          MW(671:669)
#define NVA1C0_QMDV01_07_RELEASE0_ADDRESS_LOWER                    MW(767:736)
#define NVA1C0_QMDV01_07_RELEASE0_ADDRESS_UPPER                    MW(775:768)
#define NVA1C0_QMDV01_07_RELEASE0_STRUCTURE_SIZE                   MW(799:799)
#define NVA1C0_QMDV01_07_RELEASE0_STRUCTURE_SIZE_FOUR_WORDS        0x00000000
#define NVA1C0_QMDV01_07_RELEASE0_STRUCTURE_SIZE_ONE_WORD          0x00000001
#define NVA1C0_QMDV01_07_RELEASE0_PAYLOAD                          MW(831:800)
#define NVA1C0_QMDV01_07_CONSTANT_BUFFER_ADDR_LOWER(i)             MW((959+(i)*64):(928+(i)*64))
#define NVA1C0_QMDV01_07_CONSTANT_BUFFER_ADDR_UPPER(i)             MW((967+(i)*64):(960+(i)*64))
#define NVA1C0_QMDV01_07_CONSTANT_BUFFER_SIZE(i)                   MW((991+(i)*64):(975+(i)*64))
#define NVA1C0_QMDV01_07_SHADER_LOCAL_MEMORY_LOW_SIZE              MW(1463:1440)
#define NVA1C0_QMDV01_07_BARRIER_COUNT                             MW(1471:1467)
#define NVA1C0_QMDV01_07_SHADER_LOCAL_MEMORY_HIGH_SIZE             MW(1495:1472)
#define NVA1C0_QMDV01_07_REGISTER_COUNT                            MW(1503:1496)
#define NVA1C0_QMDV01_07_SHADER_LOCAL_MEMORY_CRS_SIZE              MW(1527:1504)
#define NVA1C0_QMDV01_07_SASS_VERSION                              MW(1535:1528)
```

#### QMD V02_00 -- `clc0c0qmd.h`

Source: https://github.com/NVIDIA/open-gpu-doc/blob/9fdf5c406200/classes/compute/clc0c0qmd.h  [NVIDIA-published]  
Scope: Pascal (clc0c0qmd.h, clc1c0qmd.h; identical)

```c
#define NVC0C0_QMDV02_00_DEPENDENT_QMD_POINTER                     MW(191:160)
#define NVC0C0_QMDV02_00_IS_QUEUE                                  MW(200:200)
#define NVC0C0_QMDV02_00_DEPENDENT_QMD_TYPE                        MW(206:206)
#define NVC0C0_QMDV02_00_DEPENDENT_QMD_TYPE_QUEUE                  0x00000000
#define NVC0C0_QMDV02_00_DEPENDENT_QMD_TYPE_GRID                   0x00000001
#define NVC0C0_QMDV02_00_PROGRAM_OFFSET                            MW(287:256)
#define NVC0C0_QMDV02_00_CTA_RASTER_WIDTH                          MW(415:384)
#define NVC0C0_QMDV02_00_CTA_RASTER_HEIGHT                         MW(431:416)
#define NVC0C0_QMDV02_00_CTA_RASTER_DEPTH                          MW(463:448)
#define NVC0C0_QMDV02_00_SHARED_MEMORY_SIZE                        MW(561:544)
#define NVC0C0_QMDV02_00_QMD_VERSION                               MW(579:576)
#define NVC0C0_QMDV02_00_QMD_MAJOR_VERSION                         MW(583:580)
#define NVC0C0_QMDV02_00_CTA_THREAD_DIMENSION0                     MW(607:592)
#define NVC0C0_QMDV02_00_CTA_THREAD_DIMENSION1                     MW(623:608)
#define NVC0C0_QMDV02_00_CTA_THREAD_DIMENSION2                     MW(639:624)
#define NVC0C0_QMDV02_00_CONSTANT_BUFFER_VALID(i)                  MW((640+(i)*1):(640+(i)*1))
#define NVC0C0_QMDV02_00_RELEASE0_ADDRESS_LOWER                    MW(767:736)
#define NVC0C0_QMDV02_00_RELEASE0_ADDRESS_UPPER                    MW(775:768)
#define NVC0C0_QMDV02_00_RELEASE0_STRUCTURE_SIZE                   MW(799:799)
#define NVC0C0_QMDV02_00_RELEASE0_STRUCTURE_SIZE_FOUR_WORDS        0x00000000
#define NVC0C0_QMDV02_00_RELEASE0_STRUCTURE_SIZE_ONE_WORD          0x00000001
#define NVC0C0_QMDV02_00_RELEASE0_PAYLOAD                          MW(831:800)
#define NVC0C0_QMDV02_00_SHADER_LOCAL_MEMORY_LOW_SIZE              MW(951:928)
#define NVC0C0_QMDV02_00_BARRIER_COUNT                             MW(959:955)
#define NVC0C0_QMDV02_00_SHADER_LOCAL_MEMORY_HIGH_SIZE             MW(983:960)
#define NVC0C0_QMDV02_00_REGISTER_COUNT                            MW(991:984)
#define NVC0C0_QMDV02_00_SHADER_LOCAL_MEMORY_CRS_SIZE              MW(1015:992)
#define NVC0C0_QMDV02_00_SASS_VERSION                              MW(1023:1016)
#define NVC0C0_QMDV02_00_CONSTANT_BUFFER_ADDR_LOWER(i)             MW((1055+(i)*64):(1024+(i)*64))
#define NVC0C0_QMDV02_00_CONSTANT_BUFFER_ADDR_UPPER(i)             MW((1072+(i)*64):(1056+(i)*64))
#define NVC0C0_QMDV02_00_CONSTANT_BUFFER_SIZE_SHIFTED4(i)          MW((1087+(i)*64):(1075+(i)*64))
```

#### QMD V02_01 -- `clc0c0qmd.h`

Source: https://github.com/NVIDIA/open-gpu-doc/blob/9fdf5c406200/classes/compute/clc0c0qmd.h  [NVIDIA-published]  
Scope: Pascal (clc0c0qmd.h, clc1c0qmd.h; identical)

```c
#define NVC0C0_QMDV02_01_IS_QUEUE                                  MW(136:136)
#define NVC0C0_QMDV02_01_DEPENDENT_QMD_TYPE                        MW(142:142)
#define NVC0C0_QMDV02_01_DEPENDENT_QMD_TYPE_QUEUE                  0x00000000
#define NVC0C0_QMDV02_01_DEPENDENT_QMD_TYPE_GRID                   0x00000001
#define NVC0C0_QMDV02_01_PROGRAM_OFFSET                            MW(287:256)
#define NVC0C0_QMDV02_01_CTA_RASTER_WIDTH                          MW(415:384)
#define NVC0C0_QMDV02_01_CTA_RASTER_HEIGHT                         MW(431:416)
#define NVC0C0_QMDV02_01_CTA_RASTER_DEPTH                          MW(463:448)
#define NVC0C0_QMDV02_01_DEPENDENT_QMD_POINTER                     MW(511:480)
#define NVC0C0_QMDV02_01_SHARED_MEMORY_SIZE                        MW(561:544)
#define NVC0C0_QMDV02_01_QMD_VERSION                               MW(579:576)
#define NVC0C0_QMDV02_01_QMD_MAJOR_VERSION                         MW(583:580)
#define NVC0C0_QMDV02_01_CTA_THREAD_DIMENSION0                     MW(607:592)
#define NVC0C0_QMDV02_01_CTA_THREAD_DIMENSION1                     MW(623:608)
#define NVC0C0_QMDV02_01_CTA_THREAD_DIMENSION2                     MW(639:624)
#define NVC0C0_QMDV02_01_CONSTANT_BUFFER_VALID(i)                  MW((640+(i)*1):(640+(i)*1))
#define NVC0C0_QMDV02_01_RELEASE0_ADDRESS_LOWER                    MW(767:736)
#define NVC0C0_QMDV02_01_RELEASE0_ADDRESS_UPPER                    MW(775:768)
#define NVC0C0_QMDV02_01_RELEASE0_STRUCTURE_SIZE                   MW(799:799)
#define NVC0C0_QMDV02_01_RELEASE0_STRUCTURE_SIZE_FOUR_WORDS        0x00000000
#define NVC0C0_QMDV02_01_RELEASE0_STRUCTURE_SIZE_ONE_WORD          0x00000001
#define NVC0C0_QMDV02_01_RELEASE0_PAYLOAD                          MW(831:800)
#define NVC0C0_QMDV02_01_SHADER_LOCAL_MEMORY_LOW_SIZE              MW(951:928)
#define NVC0C0_QMDV02_01_BARRIER_COUNT                             MW(959:955)
#define NVC0C0_QMDV02_01_SHADER_LOCAL_MEMORY_HIGH_SIZE             MW(983:960)
#define NVC0C0_QMDV02_01_REGISTER_COUNT                            MW(991:984)
#define NVC0C0_QMDV02_01_SHADER_LOCAL_MEMORY_CRS_SIZE              MW(1015:992)
#define NVC0C0_QMDV02_01_SASS_VERSION                              MW(1023:1016)
#define NVC0C0_QMDV02_01_CONSTANT_BUFFER_ADDR_LOWER(i)             MW((1055+(i)*64):(1024+(i)*64))
#define NVC0C0_QMDV02_01_CONSTANT_BUFFER_ADDR_UPPER(i)             MW((1072+(i)*64):(1056+(i)*64))
#define NVC0C0_QMDV02_01_CONSTANT_BUFFER_SIZE_SHIFTED4(i)          MW((1087+(i)*64):(1075+(i)*64))
```

#### QMD V02_02 -- `clc3c0qmd.h`

Source: https://github.com/NVIDIA/open-gpu-doc/blob/9fdf5c406200/classes/compute/clc3c0qmd.h  [NVIDIA-published]  
Scope: Volta (clc3c0qmd.h, clc4c0qmd.h; identical)

```c
#define NVC3C0_QMDV02_02_IS_QUEUE                                  MW(136:136)
#define NVC3C0_QMDV02_02_DEPENDENT_QMD_TYPE                        MW(142:142)
#define NVC3C0_QMDV02_02_DEPENDENT_QMD_TYPE_QUEUE                  0x00000000
#define NVC3C0_QMDV02_02_DEPENDENT_QMD_TYPE_GRID                   0x00000001
#define NVC3C0_QMDV02_02_PROGRAM_OFFSET                            MW(287:256)
#define NVC3C0_QMDV02_02_CTA_RASTER_WIDTH                          MW(415:384)
#define NVC3C0_QMDV02_02_CTA_RASTER_HEIGHT                         MW(431:416)
#define NVC3C0_QMDV02_02_CTA_RASTER_DEPTH                          MW(463:448)
#define NVC3C0_QMDV02_02_DEPENDENT_QMD_POINTER                     MW(511:480)
#define NVC3C0_QMDV02_02_SHARED_MEMORY_SIZE                        MW(561:544)
#define NVC3C0_QMDV02_02_MIN_SM_CONFIG_SHARED_MEM_SIZE             MW(568:562)
#define NVC3C0_QMDV02_02_MAX_SM_CONFIG_SHARED_MEM_SIZE             MW(575:569)
#define NVC3C0_QMDV02_02_QMD_VERSION                               MW(579:576)
#define NVC3C0_QMDV02_02_QMD_MAJOR_VERSION                         MW(583:580)
#define NVC3C0_QMDV02_02_CTA_THREAD_DIMENSION0                     MW(607:592)
#define NVC3C0_QMDV02_02_CTA_THREAD_DIMENSION1                     MW(623:608)
#define NVC3C0_QMDV02_02_CTA_THREAD_DIMENSION2                     MW(639:624)
#define NVC3C0_QMDV02_02_CONSTANT_BUFFER_VALID(i)                  MW((640+(i)*1):(640+(i)*1))
#define NVC3C0_QMDV02_02_REGISTER_COUNT_V                          MW(656:648)
#define NVC3C0_QMDV02_02_TARGET_SM_CONFIG_SHARED_MEM_SIZE          MW(663:657)
#define NVC3C0_QMDV02_02_RELEASE0_ADDRESS_LOWER                    MW(767:736)
#define NVC3C0_QMDV02_02_RELEASE0_ADDRESS_UPPER                    MW(775:768)
#define NVC3C0_QMDV02_02_RELEASE0_STRUCTURE_SIZE                   MW(799:799)
#define NVC3C0_QMDV02_02_RELEASE0_STRUCTURE_SIZE_FOUR_WORDS        0x00000000
#define NVC3C0_QMDV02_02_RELEASE0_STRUCTURE_SIZE_ONE_WORD          0x00000001
#define NVC3C0_QMDV02_02_RELEASE0_PAYLOAD                          MW(831:800)
#define NVC3C0_QMDV02_02_SHADER_LOCAL_MEMORY_LOW_SIZE              MW(951:928)
#define NVC3C0_QMDV02_02_BARRIER_COUNT                             MW(959:955)
#define NVC3C0_QMDV02_02_SHADER_LOCAL_MEMORY_HIGH_SIZE             MW(983:960)
#define NVC3C0_QMDV02_02_REGISTER_COUNT                            MW(991:984)
#define NVC3C0_QMDV02_02_SHADER_LOCAL_MEMORY_CRS_SIZE              MW(1015:992)
#define NVC3C0_QMDV02_02_SASS_VERSION                              MW(1023:1016)
#define NVC3C0_QMDV02_02_CONSTANT_BUFFER_ADDR_LOWER(i)             MW((1055+(i)*64):(1024+(i)*64))
#define NVC3C0_QMDV02_02_CONSTANT_BUFFER_ADDR_UPPER(i)             MW((1072+(i)*64):(1056+(i)*64))
#define NVC3C0_QMDV02_02_CONSTANT_BUFFER_SIZE_SHIFTED4(i)          MW((1087+(i)*64):(1075+(i)*64))
#define NVC3C0_QMDV02_02_PROGRAM_ADDRESS_LOWER                     MW(1567:1536)
#define NVC3C0_QMDV02_02_PROGRAM_ADDRESS_UPPER                     MW(1584:1568)
```

#### QMD V02_03 -- `clc5c0qmd.h`

Source: https://github.com/NVIDIA/open-gpu-doc/blob/9fdf5c406200/classes/compute/clc5c0qmd.h  [NVIDIA-published]  
Scope: Turing (clc5c0qmd.h); also in clc6c0qmd.h/clc7c0qmd.h where bit 1073+64i is CONSTANT_BUFFER_PREFETCH_POST(i) instead of CONSTANT_BUFFER_RESERVED_ADDR(i)

```c
#define NVC5C0_QMDV02_03_IS_QUEUE                                  MW(136:136)
#define NVC5C0_QMDV02_03_DEPENDENT_QMD_TYPE                        MW(142:142)
#define NVC5C0_QMDV02_03_DEPENDENT_QMD_TYPE_QUEUE                  0x00000000
#define NVC5C0_QMDV02_03_DEPENDENT_QMD_TYPE_GRID                   0x00000001
#define NVC5C0_QMDV02_03_CTA_RASTER_WIDTH                          MW(415:384)
#define NVC5C0_QMDV02_03_CTA_RASTER_HEIGHT                         MW(431:416)
#define NVC5C0_QMDV02_03_CTA_RASTER_DEPTH                          MW(463:448)
#define NVC5C0_QMDV02_03_DEPENDENT_QMD_POINTER                     MW(511:480)
#define NVC5C0_QMDV02_03_SHARED_MEMORY_SIZE                        MW(561:544)
#define NVC5C0_QMDV02_03_MIN_SM_CONFIG_SHARED_MEM_SIZE             MW(568:562)
#define NVC5C0_QMDV02_03_MAX_SM_CONFIG_SHARED_MEM_SIZE             MW(575:569)
#define NVC5C0_QMDV02_03_QMD_VERSION                               MW(579:576)
#define NVC5C0_QMDV02_03_QMD_MAJOR_VERSION                         MW(583:580)
#define NVC5C0_QMDV02_03_CTA_THREAD_DIMENSION0                     MW(607:592)
#define NVC5C0_QMDV02_03_CTA_THREAD_DIMENSION1                     MW(623:608)
#define NVC5C0_QMDV02_03_CTA_THREAD_DIMENSION2                     MW(639:624)
#define NVC5C0_QMDV02_03_CONSTANT_BUFFER_VALID(i)                  MW((640+(i)*1):(640+(i)*1))
#define NVC5C0_QMDV02_03_REGISTER_COUNT_V                          MW(656:648)
#define NVC5C0_QMDV02_03_TARGET_SM_CONFIG_SHARED_MEM_SIZE          MW(663:657)
#define NVC5C0_QMDV02_03_RELEASE0_ADDRESS_LOWER                    MW(767:736)
#define NVC5C0_QMDV02_03_RELEASE0_ADDRESS_UPPER                    MW(775:768)
#define NVC5C0_QMDV02_03_RELEASE0_STRUCTURE_SIZE                   MW(799:799)
#define NVC5C0_QMDV02_03_RELEASE0_STRUCTURE_SIZE_FOUR_WORDS        0x00000000
#define NVC5C0_QMDV02_03_RELEASE0_STRUCTURE_SIZE_ONE_WORD          0x00000001
#define NVC5C0_QMDV02_03_RELEASE0_PAYLOAD                          MW(831:800)
#define NVC5C0_QMDV02_03_SHADER_LOCAL_MEMORY_LOW_SIZE              MW(951:928)
#define NVC5C0_QMDV02_03_BARRIER_COUNT                             MW(959:955)
#define NVC5C0_QMDV02_03_SHADER_LOCAL_MEMORY_HIGH_SIZE             MW(983:960)
#define NVC5C0_QMDV02_03_REGISTER_COUNT                            MW(991:984)
#define NVC5C0_QMDV02_03_SASS_VERSION                              MW(1023:1016)
#define NVC5C0_QMDV02_03_CONSTANT_BUFFER_ADDR_LOWER(i)             MW((1055+(i)*64):(1024+(i)*64))
#define NVC5C0_QMDV02_03_CONSTANT_BUFFER_ADDR_UPPER(i)             MW((1072+(i)*64):(1056+(i)*64))
#define NVC5C0_QMDV02_03_CONSTANT_BUFFER_SIZE_SHIFTED4(i)          MW((1087+(i)*64):(1075+(i)*64))
#define NVC5C0_QMDV02_03_PROGRAM_ADDRESS_LOWER                     MW(1567:1536)
#define NVC5C0_QMDV02_03_PROGRAM_ADDRESS_UPPER                     MW(1584:1568)
```

#### QMD V02_04 -- `clc6c0qmd.h`

Source: https://github.com/NVIDIA/open-gpu-doc/blob/9fdf5c406200/classes/compute/clc6c0qmd.h  [NVIDIA-published]  
Scope: Ampere headers (clc6c0, clc7c0 identical); clc9c0qmd.h differs only in reserved fields

```c
#define NVC6C0_QMDV02_04_IS_QUEUE                                  MW(136:136)
#define NVC6C0_QMDV02_04_CTA_RASTER_WIDTH                          MW(415:384)
#define NVC6C0_QMDV02_04_CTA_RASTER_HEIGHT                         MW(431:416)
#define NVC6C0_QMDV02_04_CTA_RASTER_DEPTH                          MW(463:448)
#define NVC6C0_QMDV02_04_DEPENDENT_QMD0_POINTER                    MW(511:480)
#define NVC6C0_QMDV02_04_SHARED_MEMORY_SIZE                        MW(561:544)
#define NVC6C0_QMDV02_04_MIN_SM_CONFIG_SHARED_MEM_SIZE             MW(568:562)
#define NVC6C0_QMDV02_04_MAX_SM_CONFIG_SHARED_MEM_SIZE             MW(575:569)
#define NVC6C0_QMDV02_04_QMD_VERSION                               MW(579:576)
#define NVC6C0_QMDV02_04_QMD_MAJOR_VERSION                         MW(583:580)
#define NVC6C0_QMDV02_04_CTA_THREAD_DIMENSION0                     MW(607:592)
#define NVC6C0_QMDV02_04_CTA_THREAD_DIMENSION1                     MW(623:608)
#define NVC6C0_QMDV02_04_CTA_THREAD_DIMENSION2                     MW(639:624)
#define NVC6C0_QMDV02_04_CONSTANT_BUFFER_VALID(i)                  MW((640+(i)*1):(640+(i)*1))
#define NVC6C0_QMDV02_04_REGISTER_COUNT_V                          MW(656:648)
#define NVC6C0_QMDV02_04_TARGET_SM_CONFIG_SHARED_MEM_SIZE          MW(663:657)
#define NVC6C0_QMDV02_04_RELEASE0_ADDRESS_LOWER                    MW(767:736)
#define NVC6C0_QMDV02_04_RELEASE0_ADDRESS_UPPER                    MW(775:768)
#define NVC6C0_QMDV02_04_RELEASE0_STRUCTURE_SIZE                   MW(799:799)
#define NVC6C0_QMDV02_04_RELEASE0_STRUCTURE_SIZE_FOUR_WORDS        0x00000000
#define NVC6C0_QMDV02_04_RELEASE0_STRUCTURE_SIZE_ONE_WORD          0x00000001
#define NVC6C0_QMDV02_04_RELEASE0_PAYLOAD                          MW(831:800)
#define NVC6C0_QMDV02_04_SHADER_LOCAL_MEMORY_LOW_SIZE              MW(951:928)
#define NVC6C0_QMDV02_04_BARRIER_COUNT                             MW(959:955)
#define NVC6C0_QMDV02_04_SHADER_LOCAL_MEMORY_HIGH_SIZE             MW(983:960)
#define NVC6C0_QMDV02_04_SASS_VERSION                              MW(1023:1016)
#define NVC6C0_QMDV02_04_CONSTANT_BUFFER_ADDR_LOWER(i)             MW((1055+(i)*64):(1024+(i)*64))
#define NVC6C0_QMDV02_04_CONSTANT_BUFFER_ADDR_UPPER(i)             MW((1072+(i)*64):(1056+(i)*64))
#define NVC6C0_QMDV02_04_CONSTANT_BUFFER_SIZE_SHIFTED4(i)          MW((1087+(i)*64):(1075+(i)*64))
#define NVC6C0_QMDV02_04_PROGRAM_ADDRESS_LOWER                     MW(1567:1536)
#define NVC6C0_QMDV02_04_PROGRAM_ADDRESS_UPPER                     MW(1584:1568)
```

#### QMD V03_00 -- `clc6c0qmd.h`

Source: https://github.com/NVIDIA/open-gpu-doc/blob/9fdf5c406200/classes/compute/clc6c0qmd.h  [NVIDIA-published]  
Scope: Ampere/Ada/Hopper headers (clc6c0, clc7c0, clc9c0, clcbc0); key fields identical except RELEASE0_NON_BLOCKING_INTR_TYPE (clc6c0) is named RELEASE0_TRAP_TYPE MW(828:827) in clc7c0/clc9c0/clcbc0

```c
#define NVC6C0_QMDV03_00_IS_QUEUE                                  MW(136:136)
#define NVC6C0_QMDV03_00_CTA_RASTER_WIDTH                          MW(415:384)
#define NVC6C0_QMDV03_00_CTA_RASTER_HEIGHT                         MW(431:416)
#define NVC6C0_QMDV03_00_CTA_RASTER_DEPTH                          MW(463:448)
#define NVC6C0_QMDV03_00_DEPENDENT_QMD0_POINTER                    MW(511:480)
#define NVC6C0_QMDV03_00_SHARED_MEMORY_SIZE                        MW(561:544)
#define NVC6C0_QMDV03_00_MIN_SM_CONFIG_SHARED_MEM_SIZE             MW(567:562)
#define NVC6C0_QMDV03_00_MAX_SM_CONFIG_SHARED_MEM_SIZE             MW(574:569)
#define NVC6C0_QMDV03_00_QMD_VERSION                               MW(579:576)
#define NVC6C0_QMDV03_00_QMD_MAJOR_VERSION                         MW(583:580)
#define NVC6C0_QMDV03_00_CTA_THREAD_DIMENSION0                     MW(607:592)
#define NVC6C0_QMDV03_00_CTA_THREAD_DIMENSION1                     MW(623:608)
#define NVC6C0_QMDV03_00_CTA_THREAD_DIMENSION2                     MW(639:624)
#define NVC6C0_QMDV03_00_CONSTANT_BUFFER_VALID(i)                  MW((640+(i)*1):(640+(i)*1))
#define NVC6C0_QMDV03_00_REGISTER_COUNT_V                          MW(656:648)
#define NVC6C0_QMDV03_00_TARGET_SM_CONFIG_SHARED_MEM_SIZE          MW(662:657)
#define NVC6C0_QMDV03_00_SHADER_LOCAL_MEMORY_LOW_SIZE              MW(759:736)
#define NVC6C0_QMDV03_00_BARRIER_COUNT                             MW(767:763)
#define NVC6C0_QMDV03_00_RELEASE0_ADDRESS_LOWER                    MW(799:768)
#define NVC6C0_QMDV03_00_RELEASE0_ADDRESS_UPPER                    MW(807:800)
#define NVC6C0_QMDV03_00_RELEASE0_ENABLE                           MW(823:823)
#define NVC6C0_QMDV03_00_RELEASE0_PAYLOAD64B                       MW(829:829)
#define NVC6C0_QMDV03_00_RELEASE0_STRUCTURE_SIZE                   MW(831:830)
#define NVC6C0_QMDV03_00_RELEASE0_STRUCTURE_SIZE_SEMAPHORE_FOUR_WORDS 0x00000000
#define NVC6C0_QMDV03_00_RELEASE0_STRUCTURE_SIZE_SEMAPHORE_ONE_WORD 0x00000001
#define NVC6C0_QMDV03_00_RELEASE0_STRUCTURE_SIZE_SEMAPHORE_TWO_WORDS 0x00000002
#define NVC6C0_QMDV03_00_RELEASE0_PAYLOAD_LOWER                    MW(863:832)
#define NVC6C0_QMDV03_00_RELEASE0_PAYLOAD_UPPER                    MW(895:864)
#define NVC6C0_QMDV03_00_CONSTANT_BUFFER_ADDR_LOWER(i)             MW((1055+(i)*64):(1024+(i)*64))
#define NVC6C0_QMDV03_00_CONSTANT_BUFFER_ADDR_UPPER(i)             MW((1072+(i)*64):(1056+(i)*64))
#define NVC6C0_QMDV03_00_CONSTANT_BUFFER_SIZE_SHIFTED4(i)          MW((1087+(i)*64):(1075+(i)*64))
#define NVC6C0_QMDV03_00_PROGRAM_ADDRESS_LOWER                     MW(1567:1536)
#define NVC6C0_QMDV03_00_PROGRAM_ADDRESS_UPPER                     MW(1584:1568)
#define NVC6C0_QMDV03_00_SHADER_LOCAL_MEMORY_HIGH_SIZE             MW(1623:1600)
#define NVC6C0_QMDV03_00_SASS_VERSION                              MW(1663:1656)
```

#### QMD V04_00 -- `clcbc0qmd.h`

Source: https://github.com/NVIDIA/open-gpu-doc/blob/9fdf5c406200/classes/compute/clcbc0qmd.h  [NVIDIA-published]  
Scope: Hopper (only in clcbc0qmd.h)

```c
#define NVCBC0_QMDV04_00_QMD_TYPE                                  MW(25:23)
#define NVCBC0_QMDV04_00_QMD_TYPE_QUEUE                            0x00000000
#define NVCBC0_QMDV04_00_QMD_TYPE_GRID_NULL                        0x00000001
#define NVCBC0_QMDV04_00_QMD_TYPE_GRID_CTA                         0x00000002
#define NVCBC0_QMDV04_00_QMD_TYPE_GRID_GPC_CGA                     0x00000003
#define NVCBC0_QMDV04_00_QMD_TYPE_GRID_GPU_CGA                     0x00000004
#define NVCBC0_QMDV04_00_QMD_TYPE_GRID_GPU_GPC_CGA                 0x00000005
#define NVCBC0_QMDV04_00_RELEASE_ENABLE(i)                         MW((320+(i)*16):(320+(i)*16))
#define NVCBC0_QMDV04_00_RELEASE_STRUCTURE_SIZE(i)                 MW((322+(i)*16):(321+(i)*16))
#define NVCBC0_QMDV04_00_RELEASE_STRUCTURE_SIZE_SEMAPHORE_FOUR_WORDS 0x00000000
#define NVCBC0_QMDV04_00_RELEASE_STRUCTURE_SIZE_SEMAPHORE_ONE_WORD 0x00000001
#define NVCBC0_QMDV04_00_RELEASE_STRUCTURE_SIZE_SEMAPHORE_TWO_WORDS 0x00000002
#define NVCBC0_QMDV04_00_RELEASE_PAYLOAD64B(i)                     MW((332+(i)*16):(332+(i)*16))
#define NVCBC0_QMDV04_00_CONSTANT_BUFFER_VALID(i)                  MW((416+(i)*4):(416+(i)*4))
#define NVCBC0_QMDV04_00_DEPENDENT_QMD0_POINTER                    MW(479:448)
#define NVCBC0_QMDV04_00_SHADER_LOCAL_MEMORY_LOW_SIZE              MW(535:512)
#define NVCBC0_QMDV04_00_SASS_VERSION                              MW(543:536)
#define NVCBC0_QMDV04_00_SHADER_LOCAL_MEMORY_HIGH_SIZE             MW(567:544)
#define NVCBC0_QMDV04_00_QMD_MINOR_VERSION                         MW(579:576)
#define NVCBC0_QMDV04_00_QMD_MAJOR_VERSION                         MW(583:580)
#define NVCBC0_QMDV04_00_SHARED_MEMORY_SIZE                        MW(601:584)
#define NVCBC0_QMDV04_00_MIN_SM_CONFIG_SHARED_MEM_SIZE             MW(613:608)
#define NVCBC0_QMDV04_00_MAX_SM_CONFIG_SHARED_MEM_SIZE             MW(619:614)
#define NVCBC0_QMDV04_00_TARGET_SM_CONFIG_SHARED_MEM_SIZE          MW(625:620)
#define NVCBC0_QMDV04_00_RELEASE_SEMAPHORE0_ADDR_LOWER             MW(671:640)
#define NVCBC0_QMDV04_00_RELEASE_SEMAPHORE0_ADDR_UPPER             MW(696:672)
#define NVCBC0_QMDV04_00_RELEASE_SEMAPHORE0_PAYLOAD_LOWER          MW(735:704)
#define NVCBC0_QMDV04_00_RELEASE_SEMAPHORE0_PAYLOAD_UPPER          MW(767:736)
#define NVCBC0_QMDV04_00_GRID_WIDTH                                MW(1055:1024)
#define NVCBC0_QMDV04_00_GRID_HEIGHT                               MW(1071:1056)
#define NVCBC0_QMDV04_00_GRID_DEPTH                                MW(1103:1088)
#define NVCBC0_QMDV04_00_CTA_THREAD_DIMENSION0                     MW(1167:1152)
#define NVCBC0_QMDV04_00_CTA_THREAD_DIMENSION1                     MW(1183:1168)
#define NVCBC0_QMDV04_00_CTA_THREAD_DIMENSION2                     MW(1199:1184)
#define NVCBC0_QMDV04_00_REGISTER_COUNT                            MW(1208:1200)
#define NVCBC0_QMDV04_00_BARRIER_COUNT                             MW(1215:1211)
#define NVCBC0_QMDV04_00_PROGRAM_ADDRESS_LOWER                     MW(1247:1216)
#define NVCBC0_QMDV04_00_PROGRAM_ADDRESS_UPPER                     MW(1272:1248)
#define NVCBC0_QMDV04_00_CONSTANT_BUFFER_ADDR_LOWER_SHIFTED6(i)    MW((1567+(i)*64):(1536+(i)*64))
#define NVCBC0_QMDV04_00_CONSTANT_BUFFER_ADDR_UPPER_SHIFTED6(i)    MW((1586+(i)*64):(1568+(i)*64))
#define NVCBC0_QMDV04_00_CONSTANT_BUFFER_SIZE_SHIFTED4(i)          MW((1599+(i)*64):(1587+(i)*64))
```

#### QMD V04_01 -- `clcdc0qmd.h`

Source: https://github.com/NVIDIA/open-gpu-doc/blob/9fdf5c406200/classes/compute/clcdc0qmd.h  [NVIDIA-published]  
Scope: Blackwell headers (clcdc0qmd.h, clcec0qmd.h; identical)

```c
#define NVCDC0_QMDV04_01_QMD_TYPE                                  MW(25:23)
#define NVCDC0_QMDV04_01_QMD_TYPE_QUEUE                            0x00000000
#define NVCDC0_QMDV04_01_QMD_TYPE_GRID_NULL                        0x00000001
#define NVCDC0_QMDV04_01_QMD_TYPE_GRID_CTA                         0x00000002
#define NVCDC0_QMDV04_01_QMD_TYPE_GRID_GPC_CGA                     0x00000003
#define NVCDC0_QMDV04_01_QMD_TYPE_GRID_GPU_CGA                     0x00000004
#define NVCDC0_QMDV04_01_QMD_TYPE_GRID_GPU_GPC_CGA                 0x00000005
#define NVCDC0_QMDV04_01_RELEASE_ENABLE(i)                         MW((320+(i)*16):(320+(i)*16))
#define NVCDC0_QMDV04_01_RELEASE_STRUCTURE_SIZE(i)                 MW((322+(i)*16):(321+(i)*16))
#define NVCDC0_QMDV04_01_RELEASE_STRUCTURE_SIZE_SEMAPHORE_FOUR_WORDS 0x00000000
#define NVCDC0_QMDV04_01_RELEASE_STRUCTURE_SIZE_SEMAPHORE_ONE_WORD 0x00000001
#define NVCDC0_QMDV04_01_RELEASE_STRUCTURE_SIZE_SEMAPHORE_TWO_WORDS 0x00000002
#define NVCDC0_QMDV04_01_RELEASE_PAYLOAD64B(i)                     MW((332+(i)*16):(332+(i)*16))
#define NVCDC0_QMDV04_01_CONSTANT_BUFFER_VALID(i)                  MW((416+(i)*4):(416+(i)*4))
#define NVCDC0_QMDV04_01_DEPENDENT_QMD0_POINTER                    MW(479:448)
#define NVCDC0_QMDV04_01_SHADER_LOCAL_MEMORY_LOW_SIZE              MW(535:512)
#define NVCDC0_QMDV04_01_SASS_VERSION                              MW(543:536)
#define NVCDC0_QMDV04_01_SHADER_LOCAL_MEMORY_HIGH_SIZE             MW(567:544)
#define NVCDC0_QMDV04_01_QMD_MINOR_VERSION                         MW(579:576)
#define NVCDC0_QMDV04_01_QMD_MAJOR_VERSION                         MW(583:580)
#define NVCDC0_QMDV04_01_SHARED_MEMORY_SIZE                        MW(601:584)
#define NVCDC0_QMDV04_01_MIN_SM_CONFIG_SHARED_MEM_SIZE             MW(613:608)
#define NVCDC0_QMDV04_01_MAX_SM_CONFIG_SHARED_MEM_SIZE             MW(619:614)
#define NVCDC0_QMDV04_01_TARGET_SM_CONFIG_SHARED_MEM_SIZE          MW(625:620)
#define NVCDC0_QMDV04_01_RELEASE_SEMAPHORE0_ADDR_LOWER             MW(671:640)
#define NVCDC0_QMDV04_01_RELEASE_SEMAPHORE0_ADDR_UPPER             MW(696:672)
#define NVCDC0_QMDV04_01_RELEASE_SEMAPHORE0_PAYLOAD_LOWER          MW(735:704)
#define NVCDC0_QMDV04_01_RELEASE_SEMAPHORE0_PAYLOAD_UPPER          MW(767:736)
#define NVCDC0_QMDV04_01_GRID_WIDTH                                MW(1055:1024)
#define NVCDC0_QMDV04_01_GRID_HEIGHT                               MW(1071:1056)
#define NVCDC0_QMDV04_01_GRID_DEPTH                                MW(1103:1088)
#define NVCDC0_QMDV04_01_CTA_THREAD_DIMENSION0                     MW(1167:1152)
#define NVCDC0_QMDV04_01_CTA_THREAD_DIMENSION1                     MW(1183:1168)
#define NVCDC0_QMDV04_01_CTA_THREAD_DIMENSION2                     MW(1191:1184)
#define NVCDC0_QMDV04_01_REGISTER_COUNT                            MW(1208:1200)
#define NVCDC0_QMDV04_01_BARRIER_COUNT                             MW(1215:1211)
#define NVCDC0_QMDV04_01_PROGRAM_ADDRESS_LOWER                     MW(1247:1216)
#define NVCDC0_QMDV04_01_PROGRAM_ADDRESS_UPPER                     MW(1272:1248)
#define NVCDC0_QMDV04_01_CONSTANT_BUFFER_ADDR_LOWER_SHIFTED6(i)    MW((1567+(i)*64):(1536+(i)*64))
#define NVCDC0_QMDV04_01_CONSTANT_BUFFER_ADDR_UPPER_SHIFTED6(i)    MW((1586+(i)*64):(1568+(i)*64))
#define NVCDC0_QMDV04_01_CONSTANT_BUFFER_SIZE_SHIFTED4(i)          MW((1599+(i)*64):(1587+(i)*64))
```

#### QMD V05_00 -- `clcdc0qmd.h`

Source: https://github.com/NVIDIA/open-gpu-doc/blob/9fdf5c406200/classes/compute/clcdc0qmd.h  [NVIDIA-published]  
Scope: Blackwell headers (clcdc0qmd.h, clcec0qmd.h; identical)

```c
#define NVCDC0_QMDV05_00_QMD_TYPE                                  MW(153:151)
#define NVCDC0_QMDV05_00_QMD_TYPE_QUEUE                            0x00000000
#define NVCDC0_QMDV05_00_QMD_TYPE_GRID_NULL                        0x00000001
#define NVCDC0_QMDV05_00_QMD_TYPE_GRID_CTA                         0x00000002
#define NVCDC0_QMDV05_00_QMD_TYPE_GRID_GPC_CGA                     0x00000003
#define NVCDC0_QMDV05_00_QMD_TYPE_GRID_GPU_CGA                     0x00000004
#define NVCDC0_QMDV05_00_QMD_TYPE_GRID_GPU_GPC_CGA                 0x00000005
#define NVCDC0_QMDV05_00_NUM_SUB_TASKS_PER_TASK                    MW(157:154)
#define NVCDC0_QMDV05_00_RELEASE_ENABLE(i)                         MW((288+(i)*16):(288+(i)*16))
#define NVCDC0_QMDV05_00_RELEASE_STRUCTURE_SIZE(i)                 MW((290+(i)*16):(289+(i)*16))
#define NVCDC0_QMDV05_00_RELEASE_STRUCTURE_SIZE_SEMAPHORE_FOUR_WORDS 0x00000000
#define NVCDC0_QMDV05_00_RELEASE_STRUCTURE_SIZE_SEMAPHORE_ONE_WORD 0x00000001
#define NVCDC0_QMDV05_00_RELEASE_STRUCTURE_SIZE_SEMAPHORE_TWO_WORDS 0x00000002
#define NVCDC0_QMDV05_00_RELEASE_PAYLOAD64B(i)                     MW((300+(i)*16):(300+(i)*16))
#define NVCDC0_QMDV05_00_DEPENDENT_QMD0_POINTER                    MW(415:384)
#define NVCDC0_QMDV05_00_SASS_VERSION                              MW(455:448)
#define NVCDC0_QMDV05_00_QMD_MINOR_VERSION                         MW(467:464)
#define NVCDC0_QMDV05_00_QMD_MAJOR_VERSION                         MW(471:468)
#define NVCDC0_QMDV05_00_RELEASE_SEMAPHORE0_ADDR_LOWER             MW(511:480)
#define NVCDC0_QMDV05_00_RELEASE_SEMAPHORE0_ADDR_UPPER             MW(536:512)
#define NVCDC0_QMDV05_00_RELEASE_SEMAPHORE0_PAYLOAD_LOWER          MW(575:544)
#define NVCDC0_QMDV05_00_RELEASE_SEMAPHORE0_PAYLOAD_UPPER          MW(607:576)
#define NVCDC0_QMDV05_00_PROGRAM_ADDRESS_LOWER_SHIFTED4            MW(1055:1024)
#define NVCDC0_QMDV05_00_PROGRAM_ADDRESS_UPPER_SHIFTED4            MW(1076:1056)
#define NVCDC0_QMDV05_00_CTA_THREAD_DIMENSION0                     MW(1103:1088)
#define NVCDC0_QMDV05_00_CTA_THREAD_DIMENSION1                     MW(1119:1104)
#define NVCDC0_QMDV05_00_CTA_THREAD_DIMENSION2                     MW(1127:1120)
#define NVCDC0_QMDV05_00_REGISTER_COUNT                            MW(1136:1128)
#define NVCDC0_QMDV05_00_BARRIER_COUNT                             MW(1141:1137)
#define NVCDC0_QMDV05_00_SHARED_MEMORY_SIZE_SHIFTED7               MW(1162:1152)
#define NVCDC0_QMDV05_00_MIN_SM_CONFIG_SHARED_MEM_SIZE             MW(1168:1163)
#define NVCDC0_QMDV05_00_MAX_SM_CONFIG_SHARED_MEM_SIZE             MW(1174:1169)
#define NVCDC0_QMDV05_00_TARGET_SM_CONFIG_SHARED_MEM_SIZE          MW(1180:1175)
#define NVCDC0_QMDV05_00_SHADER_LOCAL_MEMORY_LOW_SIZE_SHIFTED4     MW(1199:1184)
#define NVCDC0_QMDV05_00_SHADER_LOCAL_MEMORY_HIGH_SIZE_SHIFTED4    MW(1215:1200)
#define NVCDC0_QMDV05_00_GRID_WIDTH                                MW(1279:1248)
#define NVCDC0_QMDV05_00_GRID_HEIGHT                               MW(1295:1280)
#define NVCDC0_QMDV05_00_GRID_DEPTH                                MW(1327:1312)
#define NVCDC0_QMDV05_00_CONSTANT_BUFFER_ADDR_LOWER_SHIFTED6(i)    MW((1375+(i)*64):(1344+(i)*64))
#define NVCDC0_QMDV05_00_CONSTANT_BUFFER_ADDR_UPPER_SHIFTED6(i)    MW((1394+(i)*64):(1376+(i)*64))
#define NVCDC0_QMDV05_00_CONSTANT_BUFFER_SIZE_SHIFTED4(i)          MW((1407+(i)*64):(1395+(i)*64))
#define NVCDC0_QMDV05_00_CONSTANT_BUFFER_VALID(i)                  MW((1856+(i)*4):(1856+(i)*4))
```

#### QMD V05_01 -- `clcdc0qmd.h`

Source: https://github.com/NVIDIA/open-gpu-doc/blob/9fdf5c406200/classes/compute/clcdc0qmd.h  [NVIDIA-published]  
Scope: Blackwell headers (clcdc0qmd.h, clcec0qmd.h; identical); multi-sub-task layout

```c
#define NVCDC0_QMDV05_01_QMD_TYPE                                  MW(153:151)
#define NVCDC0_QMDV05_01_QMD_TYPE_QUEUE                            0x00000000
#define NVCDC0_QMDV05_01_QMD_TYPE_GRID_NULL                        0x00000001
#define NVCDC0_QMDV05_01_QMD_TYPE_GRID_CTA                         0x00000002
#define NVCDC0_QMDV05_01_QMD_TYPE_GRID_GPC_CGA                     0x00000003
#define NVCDC0_QMDV05_01_QMD_TYPE_GRID_GPU_CGA                     0x00000004
#define NVCDC0_QMDV05_01_QMD_TYPE_GRID_GPU_GPC_CGA                 0x00000005
#define NVCDC0_QMDV05_01_NUM_SUB_TASKS_PER_TASK                    MW(157:154)
#define NVCDC0_QMDV05_01_RELEASE_ENABLE(i)                         MW((288+(i)*16):(288+(i)*16))
#define NVCDC0_QMDV05_01_RELEASE_STRUCTURE_SIZE(i)                 MW((290+(i)*16):(289+(i)*16))
#define NVCDC0_QMDV05_01_RELEASE_STRUCTURE_SIZE_SEMAPHORE_FOUR_WORDS 0x00000000
#define NVCDC0_QMDV05_01_RELEASE_STRUCTURE_SIZE_SEMAPHORE_ONE_WORD 0x00000001
#define NVCDC0_QMDV05_01_RELEASE_STRUCTURE_SIZE_SEMAPHORE_TWO_WORDS 0x00000002
#define NVCDC0_QMDV05_01_RELEASE_PAYLOAD64B(i)                     MW((300+(i)*16):(300+(i)*16))
#define NVCDC0_QMDV05_01_DEPENDENT_QMD0_POINTER                    MW(415:384)
#define NVCDC0_QMDV05_01_SASS_VERSION                              MW(455:448)
#define NVCDC0_QMDV05_01_QMD_MINOR_VERSION                         MW(467:464)
#define NVCDC0_QMDV05_01_QMD_MAJOR_VERSION                         MW(471:468)
#define NVCDC0_QMDV05_01_RELEASE_SEMAPHORE0_ADDR_LOWER             MW(511:480)
#define NVCDC0_QMDV05_01_RELEASE_SEMAPHORE0_ADDR_UPPER             MW(536:512)
#define NVCDC0_QMDV05_01_RELEASE_SEMAPHORE0_PAYLOAD_LOWER          MW(575:544)
#define NVCDC0_QMDV05_01_RELEASE_SEMAPHORE0_PAYLOAD_UPPER          MW(607:576)
#define NVCDC0_QMDV05_01_SUB_TASK_PROGRAM_ADDRESS_LOWER_SHIFTED4(i) MW((799+(i)*416):(768+(i)*416))
#define NVCDC0_QMDV05_01_SUB_TASK_PROGRAM_ADDRESS_UPPER_SHIFTED4(i) MW((820+(i)*416):(800+(i)*416))
#define NVCDC0_QMDV05_01_SUB_TASK_CTA_THREAD_DIMENSION0(i)         MW((847+(i)*416):(832+(i)*416))
#define NVCDC0_QMDV05_01_SUB_TASK_CTA_THREAD_DIMENSION1(i)         MW((863+(i)*416):(848+(i)*416))
#define NVCDC0_QMDV05_01_SUB_TASK_CTA_THREAD_DIMENSION2(i)         MW((871+(i)*416):(864+(i)*416))
#define NVCDC0_QMDV05_01_SUB_TASK_REGISTER_COUNT(i)                MW((880+(i)*416):(872+(i)*416))
#define NVCDC0_QMDV05_01_SUB_TASK_BARRIER_COUNT(i)                 MW((885+(i)*416):(881+(i)*416))
#define NVCDC0_QMDV05_01_SUB_TASK_CONSTANT_BANK0_VALID(i)          MW((886+(i)*416):(886+(i)*416))
#define NVCDC0_QMDV05_01_SUB_TASK_SHARED_MEMORY_SIZE_SHIFTED7(i)   MW((906+(i)*416):(896+(i)*416))
#define NVCDC0_QMDV05_01_SUB_TASK_CONSTANT_BANK0_ADDR_LOWER_SHIFTED6(i) MW((991+(i)*416):(960+(i)*416))
#define NVCDC0_QMDV05_01_SUB_TASK_CONSTANT_BANK0_ADDR_UPPER_SHIFTED6(i) MW((1010+(i)*416):(992+(i)*416))
#define NVCDC0_QMDV05_01_SUB_TASK_CONSTANT_BANK0_SIZE_SHIFTED4(i)  MW((1023+(i)*416):(1011+(i)*416))
#define NVCDC0_QMDV05_01_SUB_TASK_GRID_WIDTH(i)                    MW((1151+(i)*416):(1120+(i)*416))
#define NVCDC0_QMDV05_01_SUB_TASK_GRID_HEIGHT(i)                   MW((1167+(i)*416):(1152+(i)*416))
#define NVCDC0_QMDV05_01_SUB_TASK_GRID_DEPTH(i)                    MW((1183+(i)*416):(1168+(i)*416))
```

---

## 2. How a launch names its QMD, and how the program address is formed

### 2.1 Launch methods (all compute classes Kepler to Blackwell)

Verbatim from https://github.com/NVIDIA/open-gpu-doc/blob/9fdf5c406200/classes/compute/cla0c0.h (Kepler)
and https://github.com/NVIDIA/open-gpu-doc/blob/9fdf5c406200/classes/compute/clcdc0.h (Blackwell) `[NVIDIA-published]`:

```c
#define NVA0C0_SEND_PCAS_A                                                                                 0x02b4
#define NVA0C0_SEND_PCAS_A_QMD_ADDRESS_SHIFTED8                                                              31:0
#define NVA0C0_SEND_PCAS_B                                                                                 0x02b8
#define NVA0C0_SEND_PCAS_B_FROM                                                                              23:0
#define NVA0C0_SEND_PCAS_B_DELTA                                                                            31:24
#define NVA0C0_SEND_SIGNALING_PCAS_B                                                                       0x02bc
#define NVA0C0_SEND_SIGNALING_PCAS_B_INVALIDATE                                                               0:0
#define NVA0C0_SEND_SIGNALING_PCAS_B_SCHEDULE                                                                 1:1
#define NVA0C0_SET_PROGRAM_REGION_A                                                                        0x1608
#define NVA0C0_SET_PROGRAM_REGION_A_ADDRESS_UPPER                                                             7:0
#define NVA0C0_SET_PROGRAM_REGION_B                                                                        0x160c
#define NVA0C0_SET_PROGRAM_REGION_B_ADDRESS_LOWER                                                            31:0

#define NVCDC0_SEND_PCAS_A                                                                                 0x02b4
#define NVCDC0_SEND_PCAS_A_QMD_ADDRESS_SHIFTED8                                                              31:0
#define NVCDC0_SEND_PCAS_B                                                                                 0x02b8
#define NVCDC0_SEND_PCAS_B_FROM                                                                              23:0
#define NVCDC0_SEND_PCAS_B_DELTA                                                                            31:24
#define NVCDC0_SEND_SIGNALING_PCAS_B                                                                       0x02bc
#define NVCDC0_SEND_SIGNALING_PCAS_B_INVALIDATE                                                               0:0
#define NVCDC0_SEND_SIGNALING_PCAS_B_SCHEDULE                                                                 1:1
#define NVCDC0_SEND_SIGNALING_PCAS2_B                                                                      0x02c0
#define NVCDC0_SEND_SIGNALING_PCAS2_B_PCAS_ACTION                                                             3:0
#define NVCDC0_SEND_SIGNALING_PCAS2_B_PCAS_ACTION_NOP                                                  0x00000000
#define NVCDC0_SEND_SIGNALING_PCAS2_B_PCAS_ACTION_INVALIDATE                                           0x00000001
#define NVCDC0_SEND_SIGNALING_PCAS2_B_PCAS_ACTION_SCHEDULE                                             0x00000002
#define NVCDC0_SEND_SIGNALING_PCAS2_B_PCAS_ACTION_INVALIDATE_COPY_SCHEDULE                             0x00000003
#define NVCDC0_SEND_SIGNALING_PCAS2_B_PCAS_ACTION_INCREMENT_PUT                                        0x00000006
#define NVCDC0_SEND_SIGNALING_PCAS2_B_PCAS_ACTION_DECREMENT_DEPENDENCE                                 0x00000007
#define NVCDC0_SEND_SIGNALING_PCAS2_B_PCAS_ACTION_PREFETCH                                             0x00000008
#define NVCDC0_SEND_SIGNALING_PCAS2_B_PCAS_ACTION_PREFETCH_SCHEDULE                                    0x00000009
#define NVCDC0_SEND_SIGNALING_PCAS2_B_PCAS_ACTION_INVALIDATE_PREFETCH_COPY_SCHEDULE                    0x0000000A
#define NVCDC0_SEND_SIGNALING_PCAS2_B_PCAS_ACTION_INVALIDATE_PREFETCH_COPY_FORCE_REQUIRE_SCHEDULING             0x0000000B
#define NVCDC0_SEND_SIGNALING_PCAS2_B_PCAS_ACTION_INCREMENT_DEPENDENCE                                 0x0000000C
#define NVCDC0_SEND_SIGNALING_PCAS2_B_PCAS_ACTION_INCREMENT_CWD_REF_COUNTER                            0x0000000D
#define NVCDC0_SEND_SIGNALING_PCAS2_B_SELECT                                                                 13:8
#define NVCDC0_SEND_SIGNALING_PCAS2_B_OFFSET_MINUS_ONE                                                      23:14
#define NVCDC0_SET_INLINE_QMD_ADDRESS_A                                                                    0x0318
#define NVCDC0_SET_INLINE_QMD_ADDRESS_A_QMD_ADDRESS_SHIFTED8_UPPER                                            8:0
#define NVCDC0_SET_INLINE_QMD_ADDRESS_A_INLINE_SIZE                                                         30:30
#define NVCDC0_SET_INLINE_QMD_ADDRESS_A_INLINE_SIZE_INLINE_256                                         0x00000000
#define NVCDC0_SET_INLINE_QMD_ADDRESS_A_INLINE_SIZE_INLINE_384                                         0x00000001
#define NVCDC0_SET_INLINE_QMD_ADDRESS_B                                                                    0x031c
#define NVCDC0_SET_INLINE_QMD_ADDRESS_B_QMD_ADDRESS_SHIFTED8_LOWER                                           31:0
#define NVCDC0_LOAD_INLINE_QMD_DATA(i)                                                             (0x0320+(i)*4)
#define NVCDC0_LOAD_INLINE_QMD_DATA_V                                                                        31:0

```

Method presence by class (open-gpu-doc `classes/compute/cl{a0c0,a1c0,b0c0,b1c0,c0c0,c1c0,c3c0,c5c0,c6c0,c7c0,c9c0,cbc0,cdc0,cec0}.h`) `[NVIDIA-published]`:
- `SEND_PCAS_A 0x02b4`, `SEND_PCAS_B 0x02b8` and `SEND_SIGNALING_PCAS_B 0x02bc` exist with identical
  fields in all 14 compute classes, from A0C0 (Kepler) to CEC0.
- `SEND_SIGNALING_PCAS2_B 0x02c0` exists from C6C0 (Ampere) on.
- `SET_INLINE_QMD_ADDRESS_A 0x0318`, `SET_INLINE_QMD_ADDRESS_B 0x031c` and `LOAD_INLINE_QMD_DATA(i) (0x0320+(i)*4)`
  exist from C0C0 (Pascal) on. `QMD_ADDRESS_SHIFTED8_UPPER` is `31:0` in C0C0..C9C0 and `8:0` plus
  `INLINE_SIZE 30:30` in CBC0, CDC0 and CEC0.
- `SET_PROGRAM_REGION_A 0x1608` and `SET_PROGRAM_REGION_B 0x160c` exist in A0C0..C1C0 only.
- `CHECK_QMD_VERSION 0x0290` exists in A0C0..C9C0 and is gone from CBC0, CDC0 and CEC0.

Launch sequences used by open drivers `[nouveau/Mesa]`:
- NVK (all generations): `SEND_PCAS_A = qmd_addr >> 8`. Then, for `cls <= TURING_COMPUTE_A`,
  `SEND_SIGNALING_PCAS_B {INVALIDATE_TRUE, SCHEDULE_TRUE}`. Otherwise it sends
  `SEND_SIGNALING_PCAS2_B = PCAS_ACTION_INVALIDATE_COPY_SCHEDULE` (3)
  (https://gitlab.freedesktop.org/mesa/mesa/-/blob/60d7516520ab/src/nouveau/vulkan/nvk_cmd_dispatch.c).
- Gallium nouveau calls 0x2b4 `LAUNCH_DESC_ADDRESS` (`__SHR 8`) and 0x2bc `LAUNCH`
  (https://gitlab.freedesktop.org/mesa/mesa/-/blob/60d7516520ab/src/gallium/drivers/nouveau/nvc0/nve4_compute.xml.h).
  It writes `LAUNCH = 0x3` for classes below GA102 (AMPERE_COMPUTE_B). For AMPERE_COMPUTE_B and
  later it writes two non-incrementing words `1, 2` to 0x02c0, which is PCAS_ACTION INVALIDATE then
  SCHEDULE (https://gitlab.freedesktop.org/mesa/mesa/-/blob/60d7516520ab/src/gallium/drivers/nouveau/nvc0/nve4_compute.c).

So for every generation, a launch in a pushbuffer looks like `SEND_PCAS_A(qmd>>8)` followed by a
signalling write to 0x2bc or 0x2c0, on the compute subchannel. A QMD can also travel inline:
`SET_INLINE_QMD_ADDRESS_A/B` followed by `LOAD_INLINE_QMD_DATA(i)` words, which puts the QMD body
inside the pushbuffer itself (Pascal and later). `[derived]`

### 2.2 Program address formation

| generation | QMD field | absolute SASS address | source |
|---|---|---|---|
| Kepler, Maxwell, Pascal (A0C0..C1C0) | `PROGRAM_OFFSET` 32-bit | `((SET_PROGRAM_REGION_A.ADDRESS_UPPER(7:0) << 32) \| SET_PROGRAM_REGION_B.ADDRESS_LOWER) + PROGRAM_OFFSET` | see below |
| Volta to Hopper (C3C0..CBC0; QMD V02_02..V04_00) | `PROGRAM_ADDRESS_LOWER/UPPER` | `(UPPER << 32) \| LOWER` | NAK `qmd_impl_set_prog_addr_64(..., NONE)` |
| Blackwell (CDC0, CEC0; QMD V05_00) | `PROGRAM_ADDRESS_LOWER/UPPER_SHIFTED4` | `((UPPER << 32) \| LOWER) << 4` | NAK `qmd_impl_set_prog_addr_64(..., SHIFTED4)` |

Evidence for the pre-Volta formula:
- NVK pushes `SET_PROGRAM_REGION_A = shader_heap_base >> 32` and `SET_PROGRAM_REGION_B = shader_heap_base`
  when `cls_compute < VOLTA_COMPUTE_A` (nvk_cmd_dispatch.c). For `cls_eng3d < VOLTA_A` it subtracts
  the heap base from the shader address before storing it in the QMD
  (`shader->hdr_addr -= heap_base_addr`, https://gitlab.freedesktop.org/mesa/mesa/-/blob/60d7516520ab/src/nouveau/vulkan/nvk_shader.c). `[nouveau/Mesa]`
- Gallium writes `CODE_ADDRESS_HIGH/LOW` (0x1608/0x160c, the same methods as SET_PROGRAM_REGION_A/B)
  `= screen->text->offset` and the QMD `PROGRAM_OFFSET = cp->code_base` for Kepler (V00_06) and Pascal
  (V02_01). For Volta it writes `PROGRAM_ADDRESS = screen->text->offset + cp->code_base` (nve4_compute.c). `[nouveau/Mesa]`
- The 3D classes FERMI_A..PASCAL_B also define `SET_PROGRAM_REGION_A 0x1608` / `SET_PROGRAM_REGION_B 0x160c`
  (open-gpu-doc `classes/3d/cl9097.h` etc.). `[NVIDIA-published]` The arithmetic is not written
  out in any NVIDIA document; it follows from the two drivers. `[derived]`
- `SET_PROGRAM_REGION_A/B` must therefore be tracked per channel from the pushbuffer stream
  (method 0x1608/0x160c on the compute subchannel) to resolve pre-Volta kernels. `[derived]`

### 2.3 Compute-class method differences across generations

Offsets of methods that are not identical in all 14 compute class headers. "-" means the method
is not defined in that header. Not shown, to save space:
- `SET_FALCON16..31` (0x540..0x57c) exist in A0C0..C5C0 only. C6C0 and later reuse 0x550..0x568 for the MME DMA methods listed in the table.
- `SET_RESERVED_SW_METHOD00..15` (0x220..0x23c, 0x24c..0x268) exist from B0C0.
- `SET_SPARE_NOOP00..15` exist in A0C0..C1C0 only.

Generated from open-gpu-doc
`classes/compute/cl{a0c0,...,cec0}.h`. `[NVIDIA-published]`

| method | cla0c0 | cla1c0 | clb0c0 | clb1c0 | clc0c0 | clc1c0 | clc3c0 | clc5c0 | clc6c0 | clc7c0 | clc9c0 | clcbc0 | clcdc0 | clcec0 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `LOAD_MME_INSTRUCTION_RAM_POINTER` | - | - | - | - | - | - | - | - | - | 0x0114 | 0x0114 | 0x0114 | 0x0114 | 0x0114 |
| `LOAD_MME_INSTRUCTION_RAM` | - | - | - | - | - | - | - | - | - | 0x0118 | 0x0118 | 0x0118 | 0x0118 | 0x0118 |
| `LOAD_MME_START_ADDRESS_RAM_POINTER` | - | - | - | - | - | - | - | - | - | 0x011c | 0x011c | 0x011c | 0x011c | 0x011c |
| `LOAD_MME_START_ADDRESS_RAM` | - | - | - | - | - | - | - | - | - | 0x0120 | 0x0120 | 0x0120 | 0x0120 | 0x0120 |
| `SET_MME_SHADOW_RAM_CONTROL` | - | - | - | - | - | - | - | - | - | 0x0124 | 0x0124 | 0x0124 | 0x0124 | 0x0124 |
| `FE_ATOMIC_SEQUENCE_BEGIN` | - | - | - | - | - | 0x0148 | 0x0148 | 0x0148 | 0x0148 | 0x0148 | 0x0148 | 0x0148 | 0x0148 | 0x0148 |
| `FE_ATOMIC_SEQUENCE_END` | - | - | - | - | - | 0x014c | 0x014c | 0x014c | 0x014c | 0x014c | 0x014c | 0x014c | 0x014c | 0x014c |
| `SET_REPORT_SEMAPHORE_PAYLOAD_LOWER` | - | - | - | - | - | - | - | - | - | 0x0158 | 0x0158 | 0x0158 | 0x0158 | 0x0158 |
| `SET_REPORT_SEMAPHORE_PAYLOAD_UPPER` | - | - | - | - | - | - | - | - | - | 0x015c | 0x015c | 0x015c | 0x015c | 0x015c |
| `SET_REPORT_SEMAPHORE_ADDRESS_LOWER` | - | - | - | - | - | - | - | - | - | 0x0160 | 0x0160 | 0x0160 | 0x0160 | 0x0160 |
| `SET_REPORT_SEMAPHORE_ADDRESS_UPPER` | - | - | - | - | - | - | - | - | - | 0x0164 | 0x0164 | 0x0164 | 0x0164 | 0x0164 |
| `REPORT_SEMAPHORE_EXECUTE` | - | - | - | - | - | - | - | - | - | 0x0168 | 0x0168 | 0x0168 | 0x0168 | 0x0168 |
| `SET_DST_BLOCK_SIZE` | 0x0194 | 0x0194 | 0x0194 | 0x0194 | 0x0194 | 0x0194 | 0x0194 | 0x0194 | 0x0194 | 0x0194 | 0x0194 | 0x0194 | - | - |
| `SET_DST_WIDTH` | 0x0198 | 0x0198 | 0x0198 | 0x0198 | 0x0198 | 0x0198 | 0x0198 | 0x0198 | 0x0198 | 0x0198 | 0x0198 | 0x0198 | - | - |
| `SET_DST_HEIGHT` | 0x019c | 0x019c | 0x019c | 0x019c | 0x019c | 0x019c | 0x019c | 0x019c | 0x019c | 0x019c | 0x019c | 0x019c | - | - |
| `SET_DST_DEPTH` | 0x01a0 | 0x01a0 | 0x01a0 | 0x01a0 | 0x01a0 | 0x01a0 | 0x01a0 | 0x01a0 | 0x01a0 | 0x01a0 | 0x01a0 | 0x01a0 | - | - |
| `SET_DST_LAYER` | 0x01a4 | 0x01a4 | 0x01a4 | 0x01a4 | 0x01a4 | 0x01a4 | 0x01a4 | 0x01a4 | 0x01a4 | 0x01a4 | 0x01a4 | 0x01a4 | - | - |
| `SET_DST_ORIGIN_BYTES_X` | 0x01a8 | 0x01a8 | 0x01a8 | 0x01a8 | 0x01a8 | 0x01a8 | 0x01a8 | 0x01a8 | 0x01a8 | 0x01a8 | 0x01a8 | 0x01a8 | - | - |
| `SET_DST_ORIGIN_SAMPLES_Y` | 0x01ac | 0x01ac | 0x01ac | 0x01ac | 0x01ac | 0x01ac | 0x01ac | 0x01ac | 0x01ac | 0x01ac | 0x01ac | 0x01ac | - | - |
| `SET_SM_SCG_CONTROL` | - | - | - | - | - | - | - | 0x01e8 | 0x01e8 | 0x01e8 | 0x01e8 | 0x01e8 | 0x01e8 | 0x01e8 |
| `SET_MME_SWITCH_STATE` | - | - | - | - | - | - | - | - | - | 0x01ec | 0x01ec | 0x01ec | 0x01ec | 0x01ec |
| `SET_VALID_SPAN_OVERFLOW_AREA_A` | - | 0x0200 | 0x0200 | 0x0200 | 0x0200 | 0x0200 | 0x0200 | 0x0200 | 0x0200 | 0x0200 | 0x0200 | 0x0200 | 0x0200 | 0x0200 |
| `SET_VALID_SPAN_OVERFLOW_AREA_B` | - | 0x0204 | 0x0204 | 0x0204 | 0x0204 | 0x0204 | 0x0204 | 0x0204 | 0x0204 | 0x0204 | 0x0204 | 0x0204 | 0x0204 | 0x0204 |
| `SET_VALID_SPAN_OVERFLOW_AREA_C` | - | 0x0208 | 0x0208 | 0x0208 | 0x0208 | 0x0208 | 0x0208 | 0x0208 | 0x0208 | 0x0208 | 0x0208 | 0x0208 | 0x0208 | 0x0208 |
| `SET_COALESCE_WAITING_PERIOD_UNIT` | - | 0x020c | 0x020c | 0x020c | 0x020c | 0x020c | - | - | - | - | - | - | - | - |
| `UPDATE_ALL_COMPUTE_CONTROL` | - | - | - | - | - | - | - | - | - | - | - | - | - | 0x020c |
| `SET_SHADER_SHARED_MEMORY_WINDOW` | 0x0214 | 0x0214 | 0x0214 | 0x0214 | 0x0214 | 0x0214 | - | - | - | - | - | - | - | - |
| `SET_QMD_VIRTUALIZATION_BASE_A` | - | - | - | - | - | - | - | 0x0214 | 0x0214 | 0x0214 | 0x0214 | 0x0214 | - | - |
| `SET_SELECT_MAXWELL_TEXTURE_HEADERS` | - | - | 0x0218 | 0x0218 | 0x0218 | 0x0218 | - | - | - | - | - | - | - | - |
| `SET_QMD_VIRTUALIZATION_BASE_B` | - | - | - | - | - | - | - | 0x0218 | 0x0218 | 0x0218 | 0x0218 | 0x0218 | - | - |
| `SET_CWD_CONTROL` | 0x0240 | 0x0240 | 0x0240 | 0x0240 | 0x0240 | 0x0240 | - | - | - | - | - | - | - | - |
| `SET_GWC_SCG_TYPE` | - | - | - | 0x026c | 0x026c | 0x026c | - | - | - | - | - | - | - | - |
| `SET_SCG_CONTROL` | - | - | - | 0x0270 | 0x0270 | 0x0270 | 0x0270 | 0x0270 | 0x0270 | 0x0270 | 0x0270 | - | - | - |
| `INVALIDATE_CONSTANT_BUFFER_CACHE_A` | 0x0274 | 0x0274 | 0x0274 | 0x0274 | 0x0274 | 0x0274 | - | - | - | - | - | - | - | - |
| `INVALIDATE_CONSTANT_BUFFER_CACHE_B` | 0x0278 | 0x0278 | 0x0278 | 0x0278 | 0x0278 | 0x0278 | - | - | - | - | - | - | - | - |
| `INVALIDATE_CONSTANT_BUFFER_CACHE_C` | 0x027c | 0x027c | 0x027c | 0x027c | 0x027c | 0x027c | - | - | - | - | - | - | - | - |
| `SET_WFI_CONFIG` | - | - | - | 0x028c | 0x028c | 0x028c | - | - | - | - | - | - | - | - |
| `CHECK_QMD_VERSION` | 0x0290 | 0x0290 | 0x0290 | 0x0290 | 0x0290 | 0x0290 | 0x0290 | 0x0290 | 0x0290 | 0x0290 | 0x0290 | - | - | - |
| `WAIT_FOR_IDLE_SCG_TYPE` | - | - | - | 0x0294 | 0x0294 | 0x0294 | - | - | - | - | - | - | - | - |
| `INVALIDATE_SKED_CACHES` | - | - | - | 0x0298 | 0x0298 | 0x0298 | 0x0298 | 0x0298 | 0x0298 | 0x0298 | 0x0298 | 0x0298 | 0x0298 | 0x0298 |
| `SET_SCG_RENDER_ENABLE_CONTROL` | - | - | - | 0x029c | 0x029c | 0x029c | - | - | - | - | - | - | - | - |
| `SET_QMD_VIRTUALIZATION_CONTROL` | - | - | - | - | - | - | - | 0x029c | 0x029c | 0x029c | 0x029c | 0x029c | - | - |
| `SET_SHADER_SHARED_MEMORY_WINDOW_A` | - | - | - | - | 0x02a0 | 0x02a0 | 0x02a0 | 0x02a0 | 0x02a0 | 0x02a0 | 0x02a0 | 0x02a0 | 0x02a0 | 0x02a0 |
| `SET_SHADER_SHARED_MEMORY_WINDOW_B` | - | - | - | - | 0x02a4 | 0x02a4 | 0x02a4 | 0x02a4 | 0x02a4 | 0x02a4 | 0x02a4 | 0x02a4 | 0x02a4 | 0x02a4 |
| `SCG_HYSTERESIS_CONTROL` | - | - | - | - | - | 0x02a8 | 0x02a8 | 0x02a8 | 0x02a8 | 0x02a8 | 0x02a8 | - | - | - |
| `SEND_SIGNALING_PCAS2_B` | - | - | - | - | - | - | - | - | 0x02c0 | 0x02c0 | 0x02c0 | 0x02c0 | 0x02c0 | 0x02c0 |
| `SET_GLOBAL_LOAD_VIA_TEXTURE` | - | 0x02c4 | - | - | - | - | - | - | - | - | - | - | - | - |
| `SET_SKED_CACHE_CONTROL` | - | - | - | - | - | - | 0x02cc | 0x02cc | 0x02cc | 0x02cc | 0x02cc | 0x02cc | 0x02cc | 0x02cc |
| `SET_SHADER_LOCAL_MEMORY_THROTTLED_A` | 0x02f0 | 0x02f0 | 0x02f0 | 0x02f0 | 0x02f0 | 0x02f0 | - | - | - | - | - | - | - | - |
| `SET_SHADER_LOCAL_MEMORY_THROTTLED_B` | 0x02f4 | 0x02f4 | 0x02f4 | 0x02f4 | 0x02f4 | 0x02f4 | - | - | - | - | - | - | - | - |
| `SET_SHADER_LOCAL_MEMORY_THROTTLED_C` | 0x02f8 | 0x02f8 | 0x02f8 | 0x02f8 | 0x02f8 | 0x02f8 | - | - | - | - | - | - | - | - |
| `SET_INLINE_QMD_ADDRESS_A` | - | - | - | - | 0x0318 | 0x0318 | 0x0318 | 0x0318 | 0x0318 | 0x0318 | 0x0318 | 0x0318 | 0x0318 | 0x0318 |
| `SET_INLINE_QMD_ADDRESS_B` | - | - | - | - | 0x031c | 0x031c | 0x031c | 0x031c | 0x031c | 0x031c | 0x031c | 0x031c | 0x031c | 0x031c |
| `LOAD_INLINE_QMD_DATA(i)` | - | - | - | - | 0x0320+i*4 | 0x0320+i*4 | 0x0320+i*4 | 0x0320+i*4 | 0x0320+i*4 | 0x0320+i*4 | 0x0320+i*4 | 0x0320+i*4 | 0x0320+i*4 | 0x0320+i*4 |
| `SET_MME_MEM_ADDRESS_A` | - | - | - | - | - | - | - | - | - | 0x0550 | 0x0550 | 0x0550 | 0x0550 | 0x0550 |
| `SET_MME_MEM_ADDRESS_B` | - | - | - | - | - | - | - | - | - | 0x0554 | 0x0554 | 0x0554 | 0x0554 | 0x0554 |
| `SET_MME_DATA_RAM_ADDRESS` | - | - | - | - | - | - | - | - | - | 0x0558 | 0x0558 | 0x0558 | 0x0558 | 0x0558 |
| `MME_DMA_READ` | - | - | - | - | - | - | - | - | - | 0x055c | 0x055c | 0x055c | 0x055c | 0x055c |
| `MME_DMA_READ_FIFOED` | - | - | - | - | - | - | - | - | - | 0x0560 | 0x0560 | 0x0560 | 0x0560 | 0x0560 |
| `MME_DMA_WRITE` | - | - | - | - | - | - | - | - | - | 0x0564 | 0x0564 | 0x0564 | 0x0564 | 0x0564 |
| `MME_DMA_REDUCTION` | - | - | - | - | - | - | - | - | - | 0x0568 | 0x0568 | 0x0568 | 0x0568 | 0x0568 |
| `MME_DMA_SYSMEMBAR` | - | - | - | - | - | - | - | - | - | 0x056c | 0x056c | 0x056c | 0x056c | 0x056c |
| `MME_DMA_SYNC` | - | - | - | - | - | - | - | - | - | 0x0570 | 0x0570 | 0x0570 | 0x0570 | 0x0570 |
| `SET_MME_DATA_FIFO_CONFIG` | - | - | - | - | - | - | - | - | - | 0x0574 | 0x0574 | 0x0574 | - | - |
| `EVENT_START_TRIGGER` | - | - | - | - | - | - | - | - | - | - | - | - | 0x074c | 0x074c |
| `EVENT_STOP_TRIGGER` | - | - | - | - | - | - | - | - | - | - | - | - | 0x075c | 0x075c |
| `SET_SHADER_LOCAL_MEMORY_WINDOW` | 0x077c | 0x077c | 0x077c | 0x077c | 0x077c | 0x077c | - | - | - | - | - | - | - | - |
| `SET_TEXTURE_HEADER_VERSION` | - | - | - | - | - | - | - | - | - | - | - | 0x07ac | 0x07ac | 0x07ac |
| `SET_SHADER_LOCAL_MEMORY_WINDOW_A` | - | - | - | - | 0x07b0 | 0x07b0 | 0x07b0 | 0x07b0 | 0x07b0 | 0x07b0 | 0x07b0 | 0x07b0 | 0x07b0 | 0x07b0 |
| `SET_SHADER_LOCAL_MEMORY_WINDOW_B` | - | - | - | - | 0x07b4 | 0x07b4 | 0x07b4 | 0x07b4 | 0x07b4 | 0x07b4 | 0x07b4 | 0x07b4 | 0x07b4 | 0x07b4 |
| `SET_MONITORED_FENCE_SIGNAL_ADDRESS_BASE_A` | - | - | - | - | - | - | - | - | - | - | - | 0x07b8 | 0x07b8 | 0x07b8 |
| `SET_MONITORED_FENCE_SIGNAL_ADDRESS_BASE_B` | - | - | - | - | - | - | - | - | - | - | - | 0x07bc | 0x07bc | 0x07bc |
| `THROTTLE_SM` | - | - | - | - | - | - | - | - | - | 0x07fc | 0x07fc | 0x07fc | 0x07fc | 0x07fc |
| `SET_SCG_COMPUTE_SCHEDULING_PARAMETERS(i)` | - | - | - | - | - | - | - | 0x0da0+i*4 | 0x0da0+i*4 | 0x0da0+i*4 | 0x0da0+i*4 | 0x0da0+i*4 | 0x0da0+i*4 | 0x0da0+i*4 |
| `MME_DMA_WRITE_METHOD_BARRIER` | - | - | - | - | - | - | - | - | - | 0x0dec | 0x0dec | 0x0dec | 0x0dec | 0x0dec |
| `SET_WFI_FILTER_STATE` | - | - | - | - | - | - | - | - | - | - | - | - | - | 0x0f10 |
| `EVENT_STOP_TRIGGER_WFI` | - | - | - | - | - | - | - | - | - | - | - | - | 0x0ffc | 0x0ffc |
| `INVALIDATE_SAMPLER_CACHE_ALL` | - | - | - | 0x120c | 0x120c | 0x120c | 0x120c | - | - | - | - | - | - | - |
| `INVALIDATE_TEXTURE_HEADER_CACHE_ALL` | - | - | - | 0x1210 | 0x1210 | 0x1210 | 0x1210 | - | - | - | - | - | - | - |
| `ACTIVATE_PERF_SETTINGS_FOR_COMPUTE_CONTEXT` | - | 0x12a8 | 0x12a8 | 0x12a8 | 0x12a8 | 0x12a8 | 0x12a8 | 0x12a8 | 0x12a8 | 0x12a8 | 0x12a8 | 0x12a8 | 0x12a8 | 0x12a8 |
| `INVALIDATE_SAMPLER_CACHE_BY_TAG` | - | - | - | - | - | - | - | - | - | - | - | - | - | 0x1458 |
| `INVALIDATE_TEXTURE_HEADER_CACHE_BY_TAG` | - | - | - | - | - | - | - | - | - | - | - | - | - | 0x145c |
| `INVALIDATE_TEXTURE_DATA_CACHE_BY_TAG` | - | - | - | - | - | - | - | - | - | - | - | - | - | 0x1460 |
| `SET_MME_TASK_EVENT_STATE` | - | - | - | - | - | - | - | - | - | - | - | - | - | 0x1464 |
| `SET_PROGRAM_REGION_A` | 0x1608 | 0x1608 | 0x1608 | 0x1608 | 0x1608 | 0x1608 | - | - | - | - | - | - | - | - |
| `SET_PROGRAM_REGION_B` | 0x160c | 0x160c | 0x160c | 0x160c | 0x160c | 0x160c | - | - | - | - | - | - | - | - |
| `SET_SHADER_CONTROL` | 0x1690 | 0x1690 | - | - | - | - | - | - | - | - | - | - | - | - |
| `INVALIDATE_SAMPLER_CACHE_BY_TAG_NO_WFI` | - | - | - | - | - | - | - | - | - | - | - | - | - | 0x1930 |
| `INVALIDATE_TEXTURE_HEADER_CACHE_BY_TAG_NO_WFI` | - | - | - | - | - | - | - | - | - | - | - | - | - | 0x1934 |
| `INVALIDATE_TEXTURE_DATA_CACHE_BY_TAG_NO_WFI` | - | - | - | - | - | - | - | - | - | - | - | - | - | 0x1938 |
| `SET_TRAP_HANDLER_A` | - | - | - | - | - | - | 0x25f8 | 0x25f8 | 0x25f8 | 0x25f8 | 0x25f8 | 0x25f8 | 0x25f8 | 0x25f8 |
| `SET_TRAP_HANDLER_B` | - | - | - | - | - | - | 0x25fc | 0x25fc | 0x25fc | 0x25fc | 0x25fc | 0x25fc | 0x25fc | 0x25fc |
| `SET_TRAP_HANDLER` | 0x260c | 0x260c | 0x260c | 0x260c | 0x260c | 0x260c | - | - | - | - | - | - | - | - |
| `SET_SHADER_PERFORMANCE_SNAPSHOT_COUNTER_VALUE(i)` | - | - | - | - | - | - | 0x32f4+i*4 | 0x32f4+i*4 | 0x32f4+i*4 | 0x32f4+i*4 | 0x32f4+i*4 | 0x32f4+i*4 | 0x32f4+i*4 | 0x32f4+i*4 |
| `SET_SHADER_PERFORMANCE_SNAPSHOT_COUNTER_VALUE_UPPER(i)` | - | - | - | - | - | - | 0x3314+i*4 | 0x3314+i*4 | 0x3314+i*4 | 0x3314+i*4 | 0x3314+i*4 | 0x3314+i*4 | 0x3314+i*4 | 0x3314+i*4 |
| `ENABLE_SHADER_PERFORMANCE_SNAPSHOT_COUNTER` | - | - | - | - | - | - | 0x3334 | 0x3334 | 0x3334 | 0x3334 | 0x3334 | 0x3334 | 0x3334 | 0x3334 |
| `DISABLE_SHADER_PERFORMANCE_SNAPSHOT_COUNTER` | - | - | - | - | - | - | 0x3338 | 0x3338 | 0x3338 | 0x3338 | 0x3338 | 0x3338 | 0x3338 | 0x3338 |
| `SET_SHADER_PERFORMANCE_COUNTER_VALUE_UPPER(i)` | - | - | 0x333c+i*4 | 0x333c+i*4 | 0x333c+i*4 | 0x333c+i*4 | 0x333c+i*4 | 0x333c+i*4 | 0x333c+i*4 | 0x333c+i*4 | 0x333c+i*4 | 0x333c+i*4 | 0x333c+i*4 | 0x333c+i*4 |
| `START_SHADER_PERFORMANCE_COUNTER` | - | - | 0x33e0 | 0x33e0 | 0x33e0 | 0x33e0 | 0x33e0 | 0x33e0 | 0x33e0 | 0x33e0 | 0x33e0 | 0x33e0 | 0x33e0 | 0x33e0 |
| `STOP_SHADER_PERFORMANCE_COUNTER` | - | - | 0x33e4 | 0x33e4 | 0x33e4 | 0x33e4 | 0x33e4 | 0x33e4 | 0x33e4 | 0x33e4 | 0x33e4 | 0x33e4 | 0x33e4 | 0x33e4 |
| `SET_SHADER_PERFORMANCE_COUNTER_SCTL_FILTER` | - | - | - | - | 0x33e8 | 0x33e8 | 0x33e8 | 0x33e8 | 0x33e8 | 0x33e8 | 0x33e8 | 0x33e8 | 0x33e8 | 0x33e8 |
| `SET_SHADER_PERFORMANCE_COUNTER_CORE_MIO_FILTER` | - | - | - | - | 0x33ec | 0x33ec | 0x33ec | 0x33ec | 0x33ec | 0x33ec | 0x33ec | 0x33ec | 0x33ec | 0x33ec |
| `CALL_MME_MACRO(j)` | - | - | - | - | - | - | - | - | - | 0x3800+i*8 | 0x3800+i*8 | 0x3800+i*8 | 0x3800+i*8 | 0x3800+i*8 |
| `CALL_MME_DATA(j)` | - | - | - | - | - | - | - | - | - | 0x3804+i*8 | 0x3804+i*8 | 0x3804+i*8 | 0x3804+i*8 | 0x3804+i*8 |

Methods with the same offset in all 14 headers: `SET_OBJECT`, `NO_OPERATION`, `SET_NOTIFY_A`, `SET_NOTIFY_B`, `NOTIFY`, `WAIT_FOR_IDLE`, `SET_GLOBAL_RENDER_ENABLE_A`, `SET_GLOBAL_RENDER_ENABLE_B`, `SET_GLOBAL_RENDER_ENABLE_C`, `SEND_GO_IDLE`, `PM_TRIGGER`, `PM_TRIGGER_WFI`, `SET_INSTRUMENTATION_METHOD_HEADER`, `SET_INSTRUMENTATION_METHOD_DATA`, `LINE_LENGTH_IN`, `LINE_COUNT`, `OFFSET_OUT_UPPER`, `OFFSET_OUT`, `PITCH_OUT`, `LAUNCH_DMA`, `LOAD_INLINE_DATA`, `SET_I2M_SEMAPHORE_A`, `SET_I2M_SEMAPHORE_B`, `SET_I2M_SEMAPHORE_C`, `SET_I2M_SPARE_NOOP00`, `SET_I2M_SPARE_NOOP01`, `SET_I2M_SPARE_NOOP02`, `SET_I2M_SPARE_NOOP03`, `PERFMON_TRANSFER`, `INVALIDATE_SHADER_CACHES`, `INVALIDATE_TEXTURE_HEADER_CACHE_NO_WFI`, `SET_CWD_REF_COUNTER`, `SET_COMPUTE_CLASS_VERSION`, `CHECK_COMPUTE_CLASS_VERSION`, `SET_QMD_VERSION`, `SET_CWD_SLOT_COUNT`, `SEND_PCAS_A`, `SEND_PCAS_B`, `SEND_SIGNALING_PCAS_B`, `SET_SHADER_LOCAL_MEMORY_NON_THROTTLED_A`, `SET_SHADER_LOCAL_MEMORY_NON_THROTTLED_B`, `SET_SHADER_LOCAL_MEMORY_NON_THROTTLED_C`, `SET_SPA_VERSION`, `SET_FALCON00`, `SET_FALCON01`, `SET_FALCON02`, `SET_FALCON03`, `SET_FALCON04`, `SET_FALCON05`, `SET_FALCON06`, `SET_FALCON07`, `SET_FALCON08`, `SET_FALCON09`, `SET_FALCON10`, `SET_FALCON11`, `SET_FALCON12`, `SET_FALCON13`, `SET_FALCON14`, `SET_FALCON15`, `SET_SHADER_LOCAL_MEMORY_A`, `SET_SHADER_LOCAL_MEMORY_B`, `SET_SHADER_CACHE_CONTROL`, `SET_SM_TIMEOUT_INTERVAL`, `INVALIDATE_TEXTURE_DATA_CACHE_NO_WFI`, `INVALIDATE_SAMPLER_CACHE`, `INVALIDATE_TEXTURE_HEADER_CACHE`, `INVALIDATE_TEXTURE_DATA_CACHE`, `INVALIDATE_SAMPLER_CACHE_NO_WFI`, `SET_SHADER_EXCEPTIONS`, `SET_RENDER_ENABLE_A`, `SET_RENDER_ENABLE_B`, `SET_RENDER_ENABLE_C`, `SET_TEX_SAMPLER_POOL_A`, `SET_TEX_SAMPLER_POOL_B`, `SET_TEX_SAMPLER_POOL_C`, `SET_TEX_HEADER_POOL_A`, `SET_TEX_HEADER_POOL_B`, `SET_TEX_HEADER_POOL_C`, `INVALIDATE_SHADER_CACHES_NO_WFI`, `SET_RENDER_ENABLE_OVERRIDE`, `PIPE_NOP`, `SET_SPARE00`, `SET_SPARE01`, `SET_SPARE02`, `SET_SPARE03`, `SET_REPORT_SEMAPHORE_A`, `SET_REPORT_SEMAPHORE_B`, `SET_REPORT_SEMAPHORE_C`, `SET_REPORT_SEMAPHORE_D`, `SET_BINDLESS_TEXTURE`, `SET_SHADER_PERFORMANCE_COUNTER_VALUE(i)`, `SET_SHADER_PERFORMANCE_COUNTER_EVENT(i)`, `SET_SHADER_PERFORMANCE_COUNTER_CONTROL_A(i)`, `SET_SHADER_PERFORMANCE_COUNTER_CONTROL_B(i)`, `SET_SHADER_PERFORMANCE_COUNTER_TRAP_CONTROL`, `SET_MME_SHADOW_SCRATCH(i)`

---

## 3. Class ids

### 3.1 Every engine class id found in a header

Each row is a `#define NAME (0x0000XXXX)` whose value equals the header's file id. "Verified from"
lists every header that contains the define. `[NVIDIA-published]` Display (`xx7x`), RM-control and
pre-Fermi classes are omitted.


**host (GPFIFO channel)**

| id | name | verbatim define | verified from |
|---|---|---|---|
| 0x906F | `GF100_CHANNEL_GPFIFO` | `#define GF100_CHANNEL_GPFIFO (0x0000906F)` | https://github.com/NVIDIA/open-gpu-doc/blob/9fdf5c406200/classes/host/cl906f.h <br> https://github.com/NVIDIA/open-gpu-kernel-modules/blob/e6a2e01579fb/src/common/sdk/nvidia/inc/class/cl906f.h |
| 0xA06F | `KEPLER_CHANNEL_GPFIFO_A` | `#define KEPLER_CHANNEL_GPFIFO_A (0x0000A06F)` | https://github.com/NVIDIA/open-gpu-doc/blob/9fdf5c406200/classes/host/cla06f.h <br> https://github.com/NVIDIA/open-gpu-kernel-modules/blob/e6a2e01579fb/src/common/sdk/nvidia/inc/class/cla06f.h |
| 0xA16F | `KEPLER_CHANNEL_GPFIFO_B` | `#define KEPLER_CHANNEL_GPFIFO_B (0x0000A16F)` | https://github.com/NVIDIA/open-gpu-doc/blob/9fdf5c406200/classes/host/cla16f.h <br> https://github.com/NVIDIA/open-gpu-kernel-modules/blob/e6a2e01579fb/src/common/sdk/nvidia/inc/class/cla16f.h |
| 0xA26F | `KEPLER_CHANNEL_GPFIFO_C` | `#define KEPLER_CHANNEL_GPFIFO_C (0x0000A26F)` | https://github.com/NVIDIA/open-gpu-doc/blob/9fdf5c406200/classes/host/cla26f.h |
| 0xB06F | `MAXWELL_CHANNEL_GPFIFO_A` | `#define MAXWELL_CHANNEL_GPFIFO_A (0x0000B06F)` | https://github.com/NVIDIA/open-gpu-doc/blob/9fdf5c406200/classes/host/clb06f.h <br> https://github.com/NVIDIA/open-gpu-kernel-modules/blob/e6a2e01579fb/src/common/sdk/nvidia/inc/class/clb06f.h |
| 0xC06F | `PASCAL_CHANNEL_GPFIFO_A` | `#define PASCAL_CHANNEL_GPFIFO_A (0x0000C06F)` | https://github.com/NVIDIA/open-gpu-doc/blob/9fdf5c406200/classes/host/clc06f.h <br> https://github.com/NVIDIA/open-gpu-kernel-modules/blob/e6a2e01579fb/src/common/sdk/nvidia/inc/class/clc06f.h |
| 0xC36F | `VOLTA_CHANNEL_GPFIFO_A` | `#define VOLTA_CHANNEL_GPFIFO_A (0x0000C36F)` | https://github.com/NVIDIA/open-gpu-doc/blob/9fdf5c406200/classes/host/clc36f.h <br> https://github.com/NVIDIA/open-gpu-kernel-modules/blob/e6a2e01579fb/src/common/sdk/nvidia/inc/class/clc36f.h |
| 0xC46F | `TURING_CHANNEL_GPFIFO_A` | `#define TURING_CHANNEL_GPFIFO_A (0x0000C46F)` | https://github.com/NVIDIA/open-gpu-doc/blob/9fdf5c406200/classes/host/clc46f.h <br> https://github.com/NVIDIA/open-gpu-kernel-modules/blob/e6a2e01579fb/src/common/sdk/nvidia/inc/class/clc46f.h |
| 0xC56F | `AMPERE_CHANNEL_GPFIFO_A` | `#define AMPERE_CHANNEL_GPFIFO_A (0x0000C56F)` | https://github.com/NVIDIA/open-gpu-doc/blob/9fdf5c406200/classes/host/clc56f.h <br> https://github.com/NVIDIA/open-gpu-kernel-modules/blob/e6a2e01579fb/src/common/sdk/nvidia/inc/class/clc56f.h |
| 0xC572 | `PHYSICAL_CHANNEL_GPFIFO` | `#define PHYSICAL_CHANNEL_GPFIFO (0x0000C572)` | https://github.com/NVIDIA/open-gpu-kernel-modules/blob/e6a2e01579fb/src/common/sdk/nvidia/inc/class/clc572.h |
| 0xC76F | `AMPERE_CHANNEL_GPFIFO_B` | `#define AMPERE_CHANNEL_GPFIFO_B (0x0000C76F)` | https://github.com/NVIDIA/open-gpu-doc/blob/9fdf5c406200/classes/host/clc76f.h |
| 0xC86F | `HOPPER_CHANNEL_GPFIFO_A` | `#define HOPPER_CHANNEL_GPFIFO_A (0x0000C86F)` | https://github.com/NVIDIA/open-gpu-kernel-modules/blob/e6a2e01579fb/src/common/sdk/nvidia/inc/class/clc86f.h |
| 0xC96F | `BLACKWELL_CHANNEL_GPFIFO_A` | `#define BLACKWELL_CHANNEL_GPFIFO_A (0x0000C96F)` | https://github.com/NVIDIA/open-gpu-kernel-modules/blob/e6a2e01579fb/src/common/sdk/nvidia/inc/class/clc96f.h |
| 0xCA6F | `BLACKWELL_CHANNEL_GPFIFO_B` | `#define BLACKWELL_CHANNEL_GPFIFO_B (0x0000CA6F)` | https://github.com/NVIDIA/open-gpu-kernel-modules/blob/e6a2e01579fb/src/common/sdk/nvidia/inc/class/clca6f.h |

**copy engine**

| id | name | verbatim define | verified from |
|---|---|---|---|
| 0x90B5 | `GF100_DMA_COPY` | `#define GF100_DMA_COPY (0x000090B5)` | https://github.com/NVIDIA/open-gpu-doc/blob/9fdf5c406200/classes/dma-copy/cl90b5.h |
| 0xA0B5 | `KEPLER_DMA_COPY_A` | `#define KEPLER_DMA_COPY_A (0x0000A0B5)` | https://github.com/NVIDIA/open-gpu-doc/blob/9fdf5c406200/classes/dma-copy/cla0b5.h <br> https://github.com/NVIDIA/open-gpu-kernel-modules/blob/e6a2e01579fb/src/common/sdk/nvidia/inc/class/cla0b5.h |
| 0xB0B5 | `MAXWELL_DMA_COPY_A` | `#define MAXWELL_DMA_COPY_A (0x0000B0B5)` | https://github.com/NVIDIA/open-gpu-doc/blob/9fdf5c406200/classes/dma-copy/clb0b5.h <br> https://github.com/NVIDIA/open-gpu-kernel-modules/blob/e6a2e01579fb/src/common/sdk/nvidia/inc/class/clb0b5.h |
| 0xC0B5 | `PASCAL_DMA_COPY_A` | `#define PASCAL_DMA_COPY_A (0x0000C0B5)` | https://github.com/NVIDIA/open-gpu-doc/blob/9fdf5c406200/classes/dma-copy/clc0b5.h <br> https://github.com/NVIDIA/open-gpu-kernel-modules/blob/e6a2e01579fb/src/common/sdk/nvidia/inc/class/clc0b5.h |
| 0xC1B5 | `PASCAL_DMA_COPY_B` | `#define PASCAL_DMA_COPY_B (0x0000C1B5)` | https://github.com/NVIDIA/open-gpu-doc/blob/9fdf5c406200/classes/dma-copy/clc1b5.h <br> https://github.com/NVIDIA/open-gpu-kernel-modules/blob/e6a2e01579fb/src/common/sdk/nvidia/inc/class/clc1b5.h |
| 0xC3B5 | `VOLTA_DMA_COPY_A` | `#define VOLTA_DMA_COPY_A (0x0000C3B5)` | https://github.com/NVIDIA/open-gpu-doc/blob/9fdf5c406200/classes/dma-copy/clc3b5.h <br> https://github.com/NVIDIA/open-gpu-kernel-modules/blob/e6a2e01579fb/src/common/sdk/nvidia/inc/class/clc3b5.h |
| 0xC5B5 | `TURING_DMA_COPY_A` | `#define TURING_DMA_COPY_A (0x0000C5B5)` | https://github.com/NVIDIA/open-gpu-doc/blob/9fdf5c406200/classes/dma-copy/clc5b5.h <br> https://github.com/NVIDIA/open-gpu-kernel-modules/blob/e6a2e01579fb/src/common/sdk/nvidia/inc/class/clc5b5.h |
| 0xC6B5 | `AMPERE_DMA_COPY_A` | `#define AMPERE_DMA_COPY_A (0x0000C6B5)` | https://github.com/NVIDIA/open-gpu-doc/blob/9fdf5c406200/classes/dma-copy/clc6b5.h <br> https://github.com/NVIDIA/open-gpu-kernel-modules/blob/e6a2e01579fb/src/common/sdk/nvidia/inc/class/clc6b5.h |
| 0xC7B5 | `AMPERE_DMA_COPY_B` | `#define AMPERE_DMA_COPY_B (0x0000C7B5)` | https://github.com/NVIDIA/open-gpu-doc/blob/9fdf5c406200/classes/dma-copy/clc7b5.h <br> https://github.com/NVIDIA/open-gpu-kernel-modules/blob/e6a2e01579fb/src/common/sdk/nvidia/inc/class/clc7b5.h |
| 0xC8B5 | `HOPPER_DMA_COPY_A` | `#define HOPPER_DMA_COPY_A (0x0000C8B5)` | https://github.com/NVIDIA/open-gpu-doc/blob/9fdf5c406200/classes/dma-copy/clc8b5.h <br> https://github.com/NVIDIA/open-gpu-kernel-modules/blob/e6a2e01579fb/src/common/sdk/nvidia/inc/class/clc8b5.h |
| 0xC9B5 | `BLACKWELL_DMA_COPY_A` | `#define BLACKWELL_DMA_COPY_A (0x0000C9B5)` | https://github.com/NVIDIA/open-gpu-doc/blob/9fdf5c406200/classes/dma-copy/clc9b5.h <br> https://github.com/NVIDIA/open-gpu-kernel-modules/blob/e6a2e01579fb/src/common/sdk/nvidia/inc/class/clc9b5.h |
| 0xCAB5 | `BLACKWELL_DMA_COPY_B` | `#define BLACKWELL_DMA_COPY_B (0x0000CAB5)` | https://github.com/NVIDIA/open-gpu-doc/blob/9fdf5c406200/classes/dma-copy/clcab5.h <br> https://github.com/NVIDIA/open-gpu-kernel-modules/blob/e6a2e01579fb/src/common/sdk/nvidia/inc/class/clcab5.h |

**compute**

| id | name | verbatim define | verified from |
|---|---|---|---|
| 0x900E | `MPS_COMPUTE` | `#define MPS_COMPUTE (0x0000900E)` | https://github.com/NVIDIA/open-gpu-kernel-modules/blob/e6a2e01579fb/src/common/sdk/nvidia/inc/class/cl900e.h |
| 0x90C0 | `FERMI_COMPUTE_A` | `#define FERMI_COMPUTE_A 0x90C0` | https://github.com/NVIDIA/open-gpu-doc/blob/9fdf5c406200/classes/compute/cl90c0.h |
| 0x91C0 | `FERMI_COMPUTE_B` | `#define FERMI_COMPUTE_B 0x91C0` | https://github.com/NVIDIA/open-gpu-doc/blob/9fdf5c406200/classes/compute/cl91c0.h |
| 0xA0C0 | `KEPLER_COMPUTE_A` | `#define KEPLER_COMPUTE_A 0xA0C0` | https://github.com/NVIDIA/open-gpu-doc/blob/9fdf5c406200/classes/compute/cla0c0.h |
| 0xA1C0 | `KEPLER_COMPUTE_B` | `#define KEPLER_COMPUTE_B 0xA1C0` | https://github.com/NVIDIA/open-gpu-doc/blob/9fdf5c406200/classes/compute/cla1c0.h |
| 0xB0C0 | `MAXWELL_COMPUTE_A` | `#define MAXWELL_COMPUTE_A 0xB0C0` | https://github.com/NVIDIA/open-gpu-doc/blob/9fdf5c406200/classes/compute/clb0c0.h <br> https://github.com/NVIDIA/open-gpu-kernel-modules/blob/e6a2e01579fb/src/common/sdk/nvidia/inc/class/clb0c0.h |
| 0xB1C0 | `MAXWELL_COMPUTE_B` | `#define MAXWELL_COMPUTE_B 0xB1C0` | https://github.com/NVIDIA/open-gpu-doc/blob/9fdf5c406200/classes/compute/clb1c0.h <br> https://github.com/NVIDIA/open-gpu-kernel-modules/blob/e6a2e01579fb/src/common/sdk/nvidia/inc/class/clb1c0.h |
| 0xC0C0 | `PASCAL_COMPUTE_A` | `#define PASCAL_COMPUTE_A 0xC0C0` | https://github.com/NVIDIA/open-gpu-doc/blob/9fdf5c406200/classes/compute/clc0c0.h <br> https://github.com/NVIDIA/open-gpu-kernel-modules/blob/e6a2e01579fb/src/common/sdk/nvidia/inc/class/clc0c0.h |
| 0xC1C0 | `PASCAL_COMPUTE_B` | `#define PASCAL_COMPUTE_B 0xC1C0` | https://github.com/NVIDIA/open-gpu-doc/blob/9fdf5c406200/classes/compute/clc1c0.h <br> https://github.com/NVIDIA/open-gpu-kernel-modules/blob/e6a2e01579fb/src/common/sdk/nvidia/inc/class/clc1c0.h |
| 0xC3C0 | `VOLTA_COMPUTE_A` | `#define VOLTA_COMPUTE_A 0xC3C0` | https://github.com/NVIDIA/open-gpu-doc/blob/9fdf5c406200/classes/compute/clc3c0.h <br> https://github.com/NVIDIA/open-gpu-kernel-modules/blob/e6a2e01579fb/src/common/sdk/nvidia/inc/class/clc3c0.h |
| 0xC4C0 | `VOLTA_COMPUTE_B` | `#define VOLTA_COMPUTE_B 0xC4C0` | https://github.com/NVIDIA/open-gpu-kernel-modules/blob/e6a2e01579fb/src/common/sdk/nvidia/inc/class/clc4c0.h |
| 0xC5C0 | `TURING_COMPUTE_A` | `#define TURING_COMPUTE_A 0xC5C0` | https://github.com/NVIDIA/open-gpu-doc/blob/9fdf5c406200/classes/compute/clc5c0.h <br> https://github.com/NVIDIA/open-gpu-kernel-modules/blob/e6a2e01579fb/src/common/sdk/nvidia/inc/class/clc5c0.h |
| 0xC6C0 | `AMPERE_COMPUTE_A` | `#define AMPERE_COMPUTE_A 0xC6C0` | https://github.com/NVIDIA/open-gpu-doc/blob/9fdf5c406200/classes/compute/clc6c0.h <br> https://github.com/NVIDIA/open-gpu-kernel-modules/blob/e6a2e01579fb/src/common/sdk/nvidia/inc/class/clc6c0.h |
| 0xC7C0 | `AMPERE_COMPUTE_B` | `#define AMPERE_COMPUTE_B 0xC7C0` | https://github.com/NVIDIA/open-gpu-doc/blob/9fdf5c406200/classes/compute/clc7c0.h <br> https://github.com/NVIDIA/open-gpu-kernel-modules/blob/e6a2e01579fb/src/common/sdk/nvidia/inc/class/clc7c0.h |
| 0xC9C0 | `ADA_COMPUTE_A` | `#define ADA_COMPUTE_A 0xC9C0` | https://github.com/NVIDIA/open-gpu-doc/blob/9fdf5c406200/classes/compute/clc9c0.h <br> https://github.com/NVIDIA/open-gpu-kernel-modules/blob/e6a2e01579fb/src/common/sdk/nvidia/inc/class/clc9c0.h |
| 0xCBC0 | `HOPPER_COMPUTE_A` | `#define HOPPER_COMPUTE_A 0xCBC0` | https://github.com/NVIDIA/open-gpu-doc/blob/9fdf5c406200/classes/compute/clcbc0.h <br> https://github.com/NVIDIA/open-gpu-kernel-modules/blob/e6a2e01579fb/src/common/sdk/nvidia/inc/class/clcbc0.h |
| 0xCDC0 | `BLACKWELL_COMPUTE_A` | `#define BLACKWELL_COMPUTE_A 0xCDC0` | https://github.com/NVIDIA/open-gpu-doc/blob/9fdf5c406200/classes/compute/clcdc0.h <br> https://github.com/NVIDIA/open-gpu-kernel-modules/blob/e6a2e01579fb/src/common/sdk/nvidia/inc/class/clcdc0.h |
| 0xCEC0 | `BLACKWELL_COMPUTE_B` | `#define BLACKWELL_COMPUTE_B 0xCEC0` | https://github.com/NVIDIA/open-gpu-doc/blob/9fdf5c406200/classes/compute/clcec0.h <br> https://github.com/NVIDIA/open-gpu-kernel-modules/blob/e6a2e01579fb/src/common/sdk/nvidia/inc/class/clcec0.h |

**3D**

| id | name | verbatim define | verified from |
|---|---|---|---|
| 0x9097 | `FERMI_A` | `#define FERMI_A 0x9097` | https://github.com/NVIDIA/open-gpu-doc/blob/9fdf5c406200/classes/3d/cl9097.h <br> https://github.com/NVIDIA/open-gpu-kernel-modules/blob/e6a2e01579fb/src/common/sdk/nvidia/inc/class/cl9097.h |
| 0x9197 | `FERMI_B` | `#define FERMI_B 0x9197` | https://github.com/NVIDIA/open-gpu-doc/blob/9fdf5c406200/classes/3d/cl9197.h |
| 0x9297 | `FERMI_C` | `#define FERMI_C 0x9297` | https://github.com/NVIDIA/open-gpu-doc/blob/9fdf5c406200/classes/3d/cl9297.h |
| 0xA097 | `KEPLER_A` | `#define KEPLER_A 0xA097` | https://github.com/NVIDIA/open-gpu-doc/blob/9fdf5c406200/classes/3d/cla097.h <br> https://github.com/NVIDIA/open-gpu-kernel-modules/blob/e6a2e01579fb/src/common/sdk/nvidia/inc/class/cla097.h |
| 0xA197 | `KEPLER_B` | `#define KEPLER_B 0xA197` | https://github.com/NVIDIA/open-gpu-doc/blob/9fdf5c406200/classes/3d/cla197.h |
| 0xA297 | `KEPLER_C` | `#define KEPLER_C 0xA297` | https://github.com/NVIDIA/open-gpu-doc/blob/9fdf5c406200/classes/3d/cla297.h |
| 0xB097 | `MAXWELL_A` | `#define MAXWELL_A 0xB097` | https://github.com/NVIDIA/open-gpu-doc/blob/9fdf5c406200/classes/3d/clb097.h <br> https://github.com/NVIDIA/open-gpu-kernel-modules/blob/e6a2e01579fb/src/common/sdk/nvidia/inc/class/clb097.h |
| 0xB197 | `MAXWELL_B` | `#define MAXWELL_B 0xB197` | https://github.com/NVIDIA/open-gpu-doc/blob/9fdf5c406200/classes/3d/clb197.h <br> https://github.com/NVIDIA/open-gpu-kernel-modules/blob/e6a2e01579fb/src/common/sdk/nvidia/inc/class/clb197.h |
| 0xC097 | `PASCAL_A` | `#define PASCAL_A 0xC097` | https://github.com/NVIDIA/open-gpu-doc/blob/9fdf5c406200/classes/3d/clc097.h <br> https://github.com/NVIDIA/open-gpu-kernel-modules/blob/e6a2e01579fb/src/common/sdk/nvidia/inc/class/clc097.h |
| 0xC197 | `PASCAL_B` | `#define PASCAL_B 0xC197` | https://github.com/NVIDIA/open-gpu-doc/blob/9fdf5c406200/classes/3d/clc197.h <br> https://github.com/NVIDIA/open-gpu-kernel-modules/blob/e6a2e01579fb/src/common/sdk/nvidia/inc/class/clc197.h |
| 0xC397 | `VOLTA_A` | `#define VOLTA_A 0xC397` | https://github.com/NVIDIA/open-gpu-doc/blob/9fdf5c406200/classes/3d/clc397.h <br> https://github.com/NVIDIA/open-gpu-kernel-modules/blob/e6a2e01579fb/src/common/sdk/nvidia/inc/class/clc397.h |
| 0xC597 | `TURING_A` | `#define TURING_A 0xC597` | https://github.com/NVIDIA/open-gpu-doc/blob/9fdf5c406200/classes/3d/clc597.h <br> https://github.com/NVIDIA/open-gpu-kernel-modules/blob/e6a2e01579fb/src/common/sdk/nvidia/inc/class/clc597.h |
| 0xC697 | `AMPERE_A` | `#define AMPERE_A 0xC697` | https://github.com/NVIDIA/open-gpu-doc/blob/9fdf5c406200/classes/3d/clc697.h <br> https://github.com/NVIDIA/open-gpu-kernel-modules/blob/e6a2e01579fb/src/common/sdk/nvidia/inc/class/clc697.h |
| 0xC797 | `AMPERE_B` | `#define AMPERE_B 0xC797` | https://github.com/NVIDIA/open-gpu-doc/blob/9fdf5c406200/classes/3d/clc797.h <br> https://github.com/NVIDIA/open-gpu-kernel-modules/blob/e6a2e01579fb/src/common/sdk/nvidia/inc/class/clc797.h |
| 0xC997 | `ADA_A` | `#define ADA_A 0xC997` | https://github.com/NVIDIA/open-gpu-doc/blob/9fdf5c406200/classes/3d/clc997.h <br> https://github.com/NVIDIA/open-gpu-kernel-modules/blob/e6a2e01579fb/src/common/sdk/nvidia/inc/class/clc997.h |
| 0xCB97 | `HOPPER_A` | `#define HOPPER_A 0xCB97` | https://github.com/NVIDIA/open-gpu-doc/blob/9fdf5c406200/classes/3d/clcb97.h <br> https://github.com/NVIDIA/open-gpu-kernel-modules/blob/e6a2e01579fb/src/common/sdk/nvidia/inc/class/clcb97.h |
| 0xCD97 | `BLACKWELL_A` | `#define BLACKWELL_A 0xCD97` | https://github.com/NVIDIA/open-gpu-doc/blob/9fdf5c406200/classes/3d/clcd97.h <br> https://github.com/NVIDIA/open-gpu-kernel-modules/blob/e6a2e01579fb/src/common/sdk/nvidia/inc/class/clcd97.h |
| 0xCE97 | `BLACKWELL_B` | `#define BLACKWELL_B 0xCE97` | https://github.com/NVIDIA/open-gpu-doc/blob/9fdf5c406200/classes/3d/clce97.h <br> https://github.com/NVIDIA/open-gpu-kernel-modules/blob/e6a2e01579fb/src/common/sdk/nvidia/inc/class/clce97.h |

**2D**

| id | name | verbatim define | verified from |
|---|---|---|---|
| 0x902D | `FERMI_TWOD_A` | `#define FERMI_TWOD_A 0x902D` | https://github.com/NVIDIA/open-gpu-doc/blob/9fdf5c406200/classes/twod/cl902d.h <br> https://github.com/NVIDIA/open-gpu-kernel-modules/blob/e6a2e01579fb/src/common/sdk/nvidia/inc/class/cl902d.h |

**inline-to-memory**

| id | name | verbatim define | verified from |
|---|---|---|---|
| 0xA040 | `KEPLER_INLINE_TO_MEMORY_A` | `#define KEPLER_INLINE_TO_MEMORY_A 0xA040` | https://github.com/NVIDIA/open-gpu-doc/blob/9fdf5c406200/classes/inline-to-memory/cla040.h |
| 0xA140 | `KEPLER_INLINE_TO_MEMORY_B` | `#define KEPLER_INLINE_TO_MEMORY_B 0xA140` | https://github.com/NVIDIA/open-gpu-doc/blob/9fdf5c406200/classes/inline-to-memory/cla140.h <br> https://github.com/NVIDIA/open-gpu-kernel-modules/blob/e6a2e01579fb/src/common/sdk/nvidia/inc/class/cla140.h |
| 0xCD40 | `BLACKWELL_INLINE_TO_MEMORY_A` | `#define BLACKWELL_INLINE_TO_MEMORY_A 0xCD40` | https://github.com/NVIDIA/open-gpu-kernel-modules/blob/e6a2e01579fb/src/common/sdk/nvidia/inc/class/clcd40.h |

**memory-to-memory-format**

| id | name | verbatim define | verified from |
|---|---|---|---|
| 0x9039 | `FERMI_MEMORY_TO_MEMORY_FORMAT_A` | `#define FERMI_MEMORY_TO_MEMORY_FORMAT_A 0x9039` | https://github.com/NVIDIA/open-gpu-doc/blob/9fdf5c406200/classes/memory-to-memory-format/cl9039.h |

**video decode (NVDEC)**

| id | name | verbatim define | verified from |
|---|---|---|---|
| 0xA0B0 | `NVA0B0_VIDEO_DECODER` | `#define NVA0B0_VIDEO_DECODER (0x0000A0B0)` | https://github.com/NVIDIA/open-gpu-kernel-modules/blob/e6a2e01579fb/src/common/sdk/nvidia/inc/class/cla0b0.h |
| 0xB0B0 | `NVB0B0_VIDEO_DECODER` | `#define NVB0B0_VIDEO_DECODER (0x0000B0B0)` | https://github.com/NVIDIA/open-gpu-kernel-modules/blob/e6a2e01579fb/src/common/sdk/nvidia/inc/class/clb0b0.h |
| 0xB6B0 | `NVB6B0_VIDEO_DECODER` | `#define NVB6B0_VIDEO_DECODER (0x0000B6B0)` | https://github.com/NVIDIA/open-gpu-kernel-modules/blob/e6a2e01579fb/src/common/sdk/nvidia/inc/class/clb6b0.h |
| 0xB8B0 | `NVB8B0_VIDEO_DECODER` | `#define NVB8B0_VIDEO_DECODER (0x0000B8B0)` | https://github.com/NVIDIA/open-gpu-kernel-modules/blob/e6a2e01579fb/src/common/sdk/nvidia/inc/class/clb8b0.h |
| 0xC1B0 | `NVC1B0_VIDEO_DECODER` | `#define NVC1B0_VIDEO_DECODER (0x0000C1B0)` | https://github.com/NVIDIA/open-gpu-kernel-modules/blob/e6a2e01579fb/src/common/sdk/nvidia/inc/class/clc1b0.h |
| 0xC2B0 | `NVC2B0_VIDEO_DECODER` | `#define NVC2B0_VIDEO_DECODER (0x0000C2B0)` | https://github.com/NVIDIA/open-gpu-kernel-modules/blob/e6a2e01579fb/src/common/sdk/nvidia/inc/class/clc2b0.h |
| 0xC3B0 | `NVC3B0_VIDEO_DECODER` | `#define NVC3B0_VIDEO_DECODER (0x0000C3B0)` | https://github.com/NVIDIA/open-gpu-kernel-modules/blob/e6a2e01579fb/src/common/sdk/nvidia/inc/class/clc3b0.h |
| 0xC4B0 | `NVC4B0_VIDEO_DECODER` | `#define NVC4B0_VIDEO_DECODER (0x0000C4B0)` | https://github.com/NVIDIA/open-gpu-kernel-modules/blob/e6a2e01579fb/src/common/sdk/nvidia/inc/class/clc4b0.h |
| 0xC5B0 | `NVC5B0_VIDEO_DECODER` | `#define NVC5B0_VIDEO_DECODER (0x0000C5B0)` | https://github.com/NVIDIA/open-gpu-doc/blob/9fdf5c406200/classes/video/clc5b0.h |
| 0xC6B0 | `NVC6B0_VIDEO_DECODER` | `#define NVC6B0_VIDEO_DECODER (0x0000C6B0)` | https://github.com/NVIDIA/open-gpu-doc/blob/9fdf5c406200/classes/video/clc6b0.h <br> https://github.com/NVIDIA/open-gpu-kernel-modules/blob/e6a2e01579fb/src/common/sdk/nvidia/inc/class/clc6b0.h |
| 0xC7B0 | `NVC7B0_VIDEO_DECODER` | `#define NVC7B0_VIDEO_DECODER (0x0000C7B0)` | https://github.com/NVIDIA/open-gpu-doc/blob/9fdf5c406200/classes/video/clc7b0.h <br> https://github.com/NVIDIA/open-gpu-kernel-modules/blob/e6a2e01579fb/src/common/sdk/nvidia/inc/class/clc7b0.h |
| 0xC9B0 | `NVC9B0_VIDEO_DECODER` | `#define NVC9B0_VIDEO_DECODER (0x0000C9B0)` | https://github.com/NVIDIA/open-gpu-doc/blob/9fdf5c406200/classes/video/clc9b0.h <br> https://github.com/NVIDIA/open-gpu-kernel-modules/blob/e6a2e01579fb/src/common/sdk/nvidia/inc/class/clc9b0.h |
| 0xCDB0 | `NVCDB0_VIDEO_DECODER` | `#define NVCDB0_VIDEO_DECODER (0x0000CDB0)` | https://github.com/NVIDIA/open-gpu-kernel-modules/blob/e6a2e01579fb/src/common/sdk/nvidia/inc/class/clcdb0.h |
| 0xCEB0 | `NVCEB0_VIDEO_DECODER` | `#define NVCEB0_VIDEO_DECODER (0x0000CEB0)` | https://github.com/NVIDIA/open-gpu-kernel-modules/blob/e6a2e01579fb/src/common/sdk/nvidia/inc/class/clceb0.h |
| 0xCFB0 | `NVCFB0_VIDEO_DECODER` | `#define NVCFB0_VIDEO_DECODER (0x0000CFB0)` | https://github.com/NVIDIA/open-gpu-kernel-modules/blob/e6a2e01579fb/src/common/sdk/nvidia/inc/class/clcfb0.h |
| 0xD1B0 | `NVD1B0_VIDEO_DECODER` | `#define NVD1B0_VIDEO_DECODER (0x0000D1B0)` | https://github.com/NVIDIA/open-gpu-kernel-modules/blob/e6a2e01579fb/src/common/sdk/nvidia/inc/class/cld1b0.h |
| 0xD2B0 | `NVD2B0_VIDEO_DECODER` | `#define NVD2B0_VIDEO_DECODER (0x0000D2B0)` | https://github.com/NVIDIA/open-gpu-kernel-modules/blob/e6a2e01579fb/src/common/sdk/nvidia/inc/class/cld2b0.h |

**video encode (NVENC)**

| id | name | verbatim define | verified from |
|---|---|---|---|
| 0xB4B7 | `NVB4B7_VIDEO_ENCODER` | `#define NVB4B7_VIDEO_ENCODER (0x0000B4B7)` | https://github.com/NVIDIA/open-gpu-kernel-modules/blob/e6a2e01579fb/src/common/sdk/nvidia/inc/class/clb4b7.h |
| 0xC0B7 | `NVC0B7_VIDEO_ENCODER` | `#define NVC0B7_VIDEO_ENCODER (0x0000C0B7)` | https://github.com/NVIDIA/open-gpu-kernel-modules/blob/e6a2e01579fb/src/common/sdk/nvidia/inc/class/clc0b7.h |
| 0xC1B7 | `NVC1B7_VIDEO_ENCODER` | `#define NVC1B7_VIDEO_ENCODER (0x0000C1B7)` | https://github.com/NVIDIA/open-gpu-kernel-modules/blob/e6a2e01579fb/src/common/sdk/nvidia/inc/class/clc1b7.h |
| 0xC2B7 | `NVC2B7_VIDEO_ENCODER` | `#define NVC2B7_VIDEO_ENCODER (0x0000C2B7)` | https://github.com/NVIDIA/open-gpu-kernel-modules/blob/e6a2e01579fb/src/common/sdk/nvidia/inc/class/clc2b7.h |
| 0xC3B7 | `NVC3B7_VIDEO_ENCODER` | `#define NVC3B7_VIDEO_ENCODER (0x0000C3B7)` | https://github.com/NVIDIA/open-gpu-kernel-modules/blob/e6a2e01579fb/src/common/sdk/nvidia/inc/class/clc3b7.h |
| 0xC4B7 | `NVC4B7_VIDEO_ENCODER` | `#define NVC4B7_VIDEO_ENCODER (0x0000C4B7)` | https://github.com/NVIDIA/open-gpu-kernel-modules/blob/e6a2e01579fb/src/common/sdk/nvidia/inc/class/clc4b7.h |
| 0xC5B7 | `NVC5B7_VIDEO_ENCODER` | `#define NVC5B7_VIDEO_ENCODER (0x0000C5B7U)` | https://github.com/NVIDIA/open-gpu-doc/blob/9fdf5c406200/classes/video/clc5b7.h |
| 0xC7B7 | `NVC7B7_VIDEO_ENCODER` | `#define NVC7B7_VIDEO_ENCODER (0x0000C7B7)` | https://github.com/NVIDIA/open-gpu-doc/blob/9fdf5c406200/classes/video/clc7b7.h <br> https://github.com/NVIDIA/open-gpu-kernel-modules/blob/e6a2e01579fb/src/common/sdk/nvidia/inc/class/clc7b7.h |
| 0xC9B7 | `NVC9B7_VIDEO_ENCODER` | `#define NVC9B7_VIDEO_ENCODER (0x0000C9B7)` | https://github.com/NVIDIA/open-gpu-doc/blob/9fdf5c406200/classes/video/clc9b7.h <br> https://github.com/NVIDIA/open-gpu-kernel-modules/blob/e6a2e01579fb/src/common/sdk/nvidia/inc/class/clc9b7.h |
| 0xCEB7 | `NVCEB7_VIDEO_ENCODER` | `#define NVCEB7_VIDEO_ENCODER (0x0000CEB7)` | https://github.com/NVIDIA/open-gpu-kernel-modules/blob/e6a2e01579fb/src/common/sdk/nvidia/inc/class/clceb7.h |
| 0xCFB7 | `NVCFB7_VIDEO_ENCODER` | `#define NVCFB7_VIDEO_ENCODER (0x0000CFB7)` | https://github.com/NVIDIA/open-gpu-kernel-modules/blob/e6a2e01579fb/src/common/sdk/nvidia/inc/class/clcfb7.h |
| 0xD0B7 | `NVD0B7_VIDEO_ENCODER` | `#define NVD0B7_VIDEO_ENCODER (0x0000D0B7)` | https://github.com/NVIDIA/open-gpu-kernel-modules/blob/e6a2e01579fb/src/common/sdk/nvidia/inc/class/cld0b7.h |
| 0xD1B7 | `NVD1B7_VIDEO_ENCODER` | `#define NVD1B7_VIDEO_ENCODER (0x0000D1B7)` | https://github.com/NVIDIA/open-gpu-kernel-modules/blob/e6a2e01579fb/src/common/sdk/nvidia/inc/class/cld1b7.h |

**JPEG (NVJPG)**

| id | name | verbatim define | verified from |
|---|---|---|---|
| 0xB8D1 | `NVB8D1_VIDEO_NVJPG` | `#define NVB8D1_VIDEO_NVJPG (0x0000B8D1)` | https://github.com/NVIDIA/open-gpu-kernel-modules/blob/e6a2e01579fb/src/common/sdk/nvidia/inc/class/clb8d1.h |
| 0xC4D1 | `NVC4D1_VIDEO_NVJPG` | `#define NVC4D1_VIDEO_NVJPG (0x0000C4D1)` | https://github.com/NVIDIA/open-gpu-kernel-modules/blob/e6a2e01579fb/src/common/sdk/nvidia/inc/class/clc4d1.h |
| 0xC9D1 | `NVC9D1_VIDEO_NVJPG` | `#define NVC9D1_VIDEO_NVJPG (0x0000C9D1)` | https://github.com/NVIDIA/open-gpu-doc/blob/9fdf5c406200/classes/video/clc9d1.h <br> https://github.com/NVIDIA/open-gpu-kernel-modules/blob/e6a2e01579fb/src/common/sdk/nvidia/inc/class/clc9d1.h |
| 0xCDD1 | `NVCDD1_VIDEO_NVJPG` | `#define NVCDD1_VIDEO_NVJPG (0x0000CDD1)` | https://github.com/NVIDIA/open-gpu-kernel-modules/blob/e6a2e01579fb/src/common/sdk/nvidia/inc/class/clcdd1.h |
| 0xCED0 | `NVCED0_VIDEO_NVJPG` | `#define NVCED0_VIDEO_NVJPG (0x0000CED0)` | https://github.com/NVIDIA/open-gpu-kernel-modules/blob/e6a2e01579fb/src/common/sdk/nvidia/inc/class/clced0.h |
| 0xCFD1 | `NVCFD1_VIDEO_NVJPG` | `#define NVCFD1_VIDEO_NVJPG (0x0000CFD1)` | https://github.com/NVIDIA/open-gpu-kernel-modules/blob/e6a2e01579fb/src/common/sdk/nvidia/inc/class/clcfd1.h |
| 0xD2D1 | `NVD2D1_VIDEO_NVJPG` | `#define NVD2D1_VIDEO_NVJPG (0x0000D2D1)` | https://github.com/NVIDIA/open-gpu-kernel-modules/blob/e6a2e01579fb/src/common/sdk/nvidia/inc/class/cld2d1.h |
| 0xE7D0 | `NVE7D0_VIDEO_NVJPG` | `#define NVE7D0_VIDEO_NVJPG (0x0000E7D0)` | https://github.com/NVIDIA/open-gpu-doc/blob/9fdf5c406200/classes/video/cle7d0.h |

**optical flow (OFA)**

| id | name | verbatim define | verified from |
|---|---|---|---|
| 0xB8FA | `NVB8FA_VIDEO_OFA` | `#define NVB8FA_VIDEO_OFA (0x0000B8FA)` | https://github.com/NVIDIA/open-gpu-kernel-modules/blob/e6a2e01579fb/src/common/sdk/nvidia/inc/class/clb8fa.h |
| 0xC6FA | `NVC6FA_VIDEO_OFA` | `#define NVC6FA_VIDEO_OFA (0x0000C6FA)` | https://github.com/NVIDIA/open-gpu-kernel-modules/blob/e6a2e01579fb/src/common/sdk/nvidia/inc/class/clc6fa.h |
| 0xC7FA | `NVC7FA_VIDEO_OFA` | `#define NVC7FA_VIDEO_OFA (0x0000C7FA)` | https://github.com/NVIDIA/open-gpu-kernel-modules/blob/e6a2e01579fb/src/common/sdk/nvidia/inc/class/clc7fa.h |
| 0xC9FA | `NVC9FA_VIDEO_OFA` | `#define NVC9FA_VIDEO_OFA (0x0000C9FA)` | https://github.com/NVIDIA/open-gpu-kernel-modules/blob/e6a2e01579fb/src/common/sdk/nvidia/inc/class/clc9fa.h |
| 0xCDFA | `NVCDFA_VIDEO_OFA` | `#define NVCDFA_VIDEO_OFA (0x0000CDFA)` | https://github.com/NVIDIA/open-gpu-kernel-modules/blob/e6a2e01579fb/src/common/sdk/nvidia/inc/class/clcdfa.h |
| 0xCEFA | `NVCEFA_VIDEO_OFA` | `#define NVCEFA_VIDEO_OFA (0x0000CEFA)` | https://github.com/NVIDIA/open-gpu-kernel-modules/blob/e6a2e01579fb/src/common/sdk/nvidia/inc/class/clcefa.h |
| 0xCFFA | `NVCFFA_VIDEO_OFA` | `#define NVCFFA_VIDEO_OFA (0x0000CFFAU)` | https://github.com/NVIDIA/open-gpu-kernel-modules/blob/e6a2e01579fb/src/common/sdk/nvidia/inc/class/clcffa.h |
| 0xD1FA | `NVD1FA_VIDEO_OFA` | `#define NVD1FA_VIDEO_OFA (0x0000D1FA)` | https://github.com/NVIDIA/open-gpu-kernel-modules/blob/e6a2e01579fb/src/common/sdk/nvidia/inc/class/cld1fa.h |
| 0xD2FA | `NVD2FA_VIDEO_OFA` | `#define NVD2FA_VIDEO_OFA (0x0000D2FA)` | https://github.com/NVIDIA/open-gpu-kernel-modules/blob/e6a2e01579fb/src/common/sdk/nvidia/inc/class/cld2fa.h |

**video compositor (VIC)**

| id | name | verbatim define | verified from |
|---|---|---|---|
| 0xCEB6 | `NVCEB6_VIDEO_COMPOSITOR` | `#define NVCEB6_VIDEO_COMPOSITOR (0x0000CEB6U)` | https://github.com/NVIDIA/open-gpu-doc/blob/9fdf5c406200/classes/video/clceb6.h |

**usermode doorbell region**

| id | name | verbatim define | verified from |
|---|---|---|---|
| 0xC361 | `VOLTA_USERMODE_A` | `#define VOLTA_USERMODE_A (0xc361)` | https://github.com/NVIDIA/open-gpu-kernel-modules/blob/e6a2e01579fb/src/common/sdk/nvidia/inc/class/clc361.h |
| 0xC461 | `TURING_USERMODE_A` | `#define TURING_USERMODE_A (0xc461)` | https://github.com/NVIDIA/open-gpu-kernel-modules/blob/e6a2e01579fb/src/common/sdk/nvidia/inc/class/clc461.h |
| 0xC561 | `AMPERE_USERMODE_A` | `#define AMPERE_USERMODE_A (0xc561)` | https://github.com/NVIDIA/open-gpu-kernel-modules/blob/e6a2e01579fb/src/common/sdk/nvidia/inc/class/clc561.h |
| 0xC661 | `HOPPER_USERMODE_A` | `#define HOPPER_USERMODE_A (0xc661)` | https://github.com/NVIDIA/open-gpu-kernel-modules/blob/e6a2e01579fb/src/common/sdk/nvidia/inc/class/clc661.h |
| 0xC761 | `BLACKWELL_USERMODE_A` | `#define BLACKWELL_USERMODE_A (0xc761)` | https://github.com/NVIDIA/open-gpu-kernel-modules/blob/e6a2e01579fb/src/common/sdk/nvidia/inc/class/clc761.h |

**MMU fault/access buffers**

| id | name | verbatim define | verified from |
|---|---|---|---|
| 0xB069 | `MAXWELL_FAULT_BUFFER_A` | `#define MAXWELL_FAULT_BUFFER_A (0xb069)` | https://github.com/NVIDIA/open-gpu-kernel-modules/blob/e6a2e01579fb/src/common/sdk/nvidia/inc/class/clb069.h |
| 0xC365 | `ACCESS_COUNTER_NOTIFY_BUFFER` | `#define ACCESS_COUNTER_NOTIFY_BUFFER (0xc365)` | https://github.com/NVIDIA/open-gpu-kernel-modules/blob/e6a2e01579fb/src/common/sdk/nvidia/inc/class/clc365.h |
| 0xC369 | `MMU_FAULT_BUFFER` | `#define MMU_FAULT_BUFFER (0xc369)` | https://github.com/NVIDIA/open-gpu-kernel-modules/blob/e6a2e01579fb/src/common/sdk/nvidia/inc/class/clc369.h |
| 0xC763 | `MMU_VIDMEM_ACCESS_BIT_BUFFER` | `#define MMU_VIDMEM_ACCESS_BIT_BUFFER (0xc763)` | https://github.com/NVIDIA/open-gpu-kernel-modules/blob/e6a2e01579fb/src/common/sdk/nvidia/inc/class/clc763.h |
| 0xC863 | `HOPPER_MMU_VIDMEM_ACCESS_BIT_BUFFER` | `#define HOPPER_MMU_VIDMEM_ACCESS_BIT_BUFFER (0xc863)` | https://github.com/NVIDIA/open-gpu-kernel-modules/blob/e6a2e01579fb/src/common/sdk/nvidia/inc/class/clc863.h |

**SEC2 work launch**

| id | name | verbatim define | verified from |
|---|---|---|---|
| 0xCBA2 | `HOPPER_SEC2_WORK_LAUNCH_A` | `#define HOPPER_SEC2_WORK_LAUNCH_A (0x0000CBA2)` | https://github.com/NVIDIA/open-gpu-kernel-modules/blob/e6a2e01579fb/src/common/sdk/nvidia/inc/class/clcba2.h |

**TSG / channel group**

| id | name | verbatim define | verified from |
|---|---|---|---|
| 0xA06C | `KEPLER_CHANNEL_GROUP_A` | `#define KEPLER_CHANNEL_GROUP_A (0x0000A06C)` | https://github.com/NVIDIA/open-gpu-kernel-modules/blob/e6a2e01579fb/src/common/sdk/nvidia/inc/class/cla06c.h |

Ids that nouveau's class list also carries
(https://github.com/torvalds/linux/blob/141b164bbe18/drivers/gpu/drm/nouveau/include/nvif/class.h)
match the table above. nvgpu's
https://github.com/OE4T/linux-nvgpu/blob/21d928824dc7/drivers/gpu/nvgpu/include/nvgpu/class.h
additionally names `TURING_NVENC_A 0xC4B7U`.

### 3.2 Video, JPEG and OFA engines per chip family

From the GSP-RM chip tables in nouveau
(https://github.com/torvalds/linux/blob/141b164bbe18/drivers/gpu/drm/nouveau/nvkm/subdev/gsp/rm/tu1xx.c, ga100.c, ga1xx.c, ad10x.c, gh100.c, gb10x.c, gb20x.c) `[nouveau/Mesa]`:

| family | NVDEC | NVENC | NVJPG | OFA |
|---|---|---|---|---|
| TU1xx | C4B0 | C4B7 | not listed | not listed |
| GA100 | C6B0 | not listed | not listed | not listed |
| GA10x | C7B0 | C7B7 | not listed | C7FA |
| AD10x | C9B0 | C9B7 | not listed | C9FA |
| GH100 | B8B0 | not listed | B8D1 | B8FA |
| GB10x | CDB0 | not listed | CDD1 | CDFA |
| GB20x | CFB0 | CFB7 | CFD1 | CFFA |

No chip mapping was found for these classes, although each has an NVIDIA header (section 3.1):
A0B0, B0B0, B4B7, B6B0, C0B7, C1B0, C1B7, C2B0, C2B7, C3B0, C3B7, C4D1, C5B0, C5B7, C6FA, C9D1,
CEB0, CEB6 (VIC), CEB7, CED0, CEFA, D0B7, D1B0, D1B7, D1FA, D2B0, D2D1, D2FA and E7D0. Assigning
them a generation from the id prefix alone would be guesswork.

---

## 4. Copy engine (DMA_COPY) across generations

### 4.1 Method offsets

Generated from open-gpu-doc `classes/dma-copy/cl{a0b5,b0b5,c0b5,c1b5,c3b5,c5b5,c6b5,c7b5,c8b5,c9b5,cab5}.h`
(https://github.com/NVIDIA/open-gpu-doc/tree/9fdf5c406200/classes/dma-copy). `[NVIDIA-published]`

| method | cla0b5 | clb0b5 | clc0b5 | clc1b5 | clc3b5 | clc5b5 | clc6b5 | clc7b5 | clc8b5 | clc9b5 | clcab5 |
|---|---|---|---|---|---|---|---|---|---|---|---|
| `NOP` | 0x0100 | 0x0100 | 0x0100 | 0x0100 | 0x0100 | 0x0100 | 0x0100 | 0x0100 | 0x0100 | 0x0100 | 0x0100 |
| `PM_TRIGGER` | 0x0140 | 0x0140 | 0x0140 | 0x0140 | 0x0140 | 0x0140 | 0x0140 | 0x0140 | 0x0140 | 0x0140 | 0x0140 |
| `SET_MONITORED_FENCE_TYPE` | - | - | - | - | - | - | - | 0x021c | 0x021c | 0x021c | 0x021c |
| `SET_MONITORED_FENCE_SIGNAL_ADDR_BASE_UPPER` | - | - | - | - | - | - | - | 0x0220 | 0x0220 | 0x0220 | 0x0220 |
| `SET_MONITORED_FENCE_SIGNAL_ADDR_BASE_LOWER` | - | - | - | - | - | - | - | 0x0224 | 0x0224 | 0x0224 | 0x0224 |
| `SET_SEMAPHORE_A` | 0x0240 | 0x0240 | 0x0240 | 0x0240 | 0x0240 | 0x0240 | 0x0240 | 0x0240 | 0x0240 | 0x0240 | 0x0240 |
| `SET_SEMAPHORE_B` | 0x0244 | 0x0244 | 0x0244 | 0x0244 | 0x0244 | 0x0244 | 0x0244 | 0x0244 | 0x0244 | 0x0244 | 0x0244 |
| `SET_SEMAPHORE_PAYLOAD` | 0x0248 | 0x0248 | 0x0248 | 0x0248 | 0x0248 | 0x0248 | 0x0248 | 0x0248 | 0x0248 | 0x0248 | 0x0248 |
| `SET_SEMAPHORE_PAYLOAD_UPPER` | - | - | - | - | - | - | - | 0x024c | 0x024c | 0x024c | 0x024c |
| `SET_RENDER_ENABLE_A` | 0x0254 | 0x0254 | 0x0254 | 0x0254 | 0x0254 | 0x0254 | 0x0254 | 0x0254 | 0x0254 | 0x0254 | 0x0254 |
| `SET_RENDER_ENABLE_B` | 0x0258 | 0x0258 | 0x0258 | 0x0258 | 0x0258 | 0x0258 | 0x0258 | 0x0258 | 0x0258 | 0x0258 | 0x0258 |
| `SET_RENDER_ENABLE_C` | 0x025c | 0x025c | 0x025c | 0x025c | 0x025c | 0x025c | 0x025c | 0x025c | 0x025c | 0x025c | 0x025c |
| `SET_SRC_PHYS_MODE` | 0x0260 | 0x0260 | 0x0260 | 0x0260 | 0x0260 | 0x0260 | 0x0260 | 0x0260 | 0x0260 | 0x0260 | 0x0260 |
| `SET_DST_PHYS_MODE` | 0x0264 | 0x0264 | 0x0264 | 0x0264 | 0x0264 | 0x0264 | 0x0264 | 0x0264 | 0x0264 | 0x0264 | 0x0264 |
| `LAUNCH_DMA` | 0x0300 | 0x0300 | 0x0300 | 0x0300 | 0x0300 | 0x0300 | 0x0300 | 0x0300 | 0x0300 | 0x0300 | 0x0300 |
| `OFFSET_IN_UPPER` | 0x0400 | 0x0400 | 0x0400 | 0x0400 | 0x0400 | 0x0400 | 0x0400 | 0x0400 | 0x0400 | 0x0400 | 0x0400 |
| `OFFSET_IN_LOWER` | 0x0404 | 0x0404 | 0x0404 | 0x0404 | 0x0404 | 0x0404 | 0x0404 | 0x0404 | 0x0404 | 0x0404 | 0x0404 |
| `OFFSET_OUT_UPPER` | 0x0408 | 0x0408 | 0x0408 | 0x0408 | 0x0408 | 0x0408 | 0x0408 | 0x0408 | 0x0408 | 0x0408 | 0x0408 |
| `OFFSET_OUT_LOWER` | 0x040c | 0x040c | 0x040c | 0x040c | 0x040c | 0x040c | 0x040c | 0x040c | 0x040c | 0x040c | 0x040c |
| `PITCH_IN` | 0x0410 | 0x0410 | 0x0410 | 0x0410 | 0x0410 | 0x0410 | 0x0410 | 0x0410 | 0x0410 | 0x0410 | 0x0410 |
| `PITCH_OUT` | 0x0414 | 0x0414 | 0x0414 | 0x0414 | 0x0414 | 0x0414 | 0x0414 | 0x0414 | 0x0414 | 0x0414 | 0x0414 |
| `LINE_LENGTH_IN` | 0x0418 | 0x0418 | 0x0418 | 0x0418 | 0x0418 | 0x0418 | 0x0418 | 0x0418 | 0x0418 | 0x0418 | 0x0418 |
| `LINE_COUNT` | 0x041c | 0x041c | 0x041c | 0x041c | 0x041c | 0x041c | 0x041c | 0x041c | 0x041c | 0x041c | 0x041c |
| `SET_SECURE_COPY_MODE` | - | - | - | - | - | - | - | - | 0x0500 | 0x0500 | 0x0500 |
| `SET_DECRYPT_AUTH_TAG_COMPARE_ADDR_UPPER` | - | - | - | - | - | - | - | - | 0x0514 | 0x0514 | 0x0514 |
| `SET_DECRYPT_AUTH_TAG_COMPARE_ADDR_LOWER` | - | - | - | - | - | - | - | - | 0x0518 | 0x0518 | 0x0518 |
| `SET_ENCRYPT_AUTH_TAG_ADDR_UPPER` | - | - | - | - | - | - | - | - | 0x0530 | 0x0530 | 0x0530 |
| `SET_ENCRYPT_AUTH_TAG_ADDR_LOWER` | - | - | - | - | - | - | - | - | 0x0534 | 0x0534 | 0x0534 |
| `SET_ENCRYPT_IV_ADDR_UPPER` | - | - | - | - | - | - | - | - | 0x0538 | 0x0538 | 0x0538 |
| `SET_ENCRYPT_IV_ADDR_LOWER` | - | - | - | - | - | - | - | - | 0x053c | 0x053c | 0x053c |
| `SET_MEMORY_SCRUB_PARAMETERS` | - | - | - | - | - | - | - | - | 0x06fc | 0x06fc | 0x06fc |
| `SET_REMAP_CONST_A` | 0x0700 | 0x0700 | 0x0700 | 0x0700 | 0x0700 | 0x0700 | 0x0700 | 0x0700 | 0x0700 | 0x0700 | 0x0700 |
| `SET_REMAP_CONST_B` | 0x0704 | 0x0704 | 0x0704 | 0x0704 | 0x0704 | 0x0704 | 0x0704 | 0x0704 | 0x0704 | 0x0704 | 0x0704 |
| `SET_REMAP_COMPONENTS` | 0x0708 | 0x0708 | 0x0708 | 0x0708 | 0x0708 | 0x0708 | 0x0708 | 0x0708 | 0x0708 | 0x0708 | 0x0708 |
| `SET_DST_BLOCK_SIZE` | 0x070c | 0x070c | 0x070c | 0x070c | 0x070c | 0x070c | 0x070c | 0x070c | 0x070c | 0x070c | 0x070c |
| `SET_DST_WIDTH` | 0x0710 | 0x0710 | 0x0710 | 0x0710 | 0x0710 | 0x0710 | 0x0710 | 0x0710 | 0x0710 | 0x0710 | 0x0710 |
| `SET_DST_HEIGHT` | 0x0714 | 0x0714 | 0x0714 | 0x0714 | 0x0714 | 0x0714 | 0x0714 | 0x0714 | 0x0714 | 0x0714 | 0x0714 |
| `SET_DST_DEPTH` | 0x0718 | 0x0718 | 0x0718 | 0x0718 | 0x0718 | 0x0718 | 0x0718 | 0x0718 | 0x0718 | 0x0718 | 0x0718 |
| `SET_DST_LAYER` | 0x071c | 0x071c | 0x071c | 0x071c | 0x071c | 0x071c | 0x071c | 0x071c | 0x071c | 0x071c | 0x071c |
| `SET_DST_ORIGIN` | 0x0720 | 0x0720 | 0x0720 | 0x0720 | 0x0720 | 0x0720 | 0x0720 | 0x0720 | 0x0720 | 0x0720 | 0x0720 |
| `SET_SRC_BLOCK_SIZE` | 0x0728 | 0x0728 | 0x0728 | 0x0728 | 0x0728 | 0x0728 | 0x0728 | 0x0728 | 0x0728 | 0x0728 | 0x0728 |
| `SET_SRC_WIDTH` | 0x072c | 0x072c | 0x072c | 0x072c | 0x072c | 0x072c | 0x072c | 0x072c | 0x072c | 0x072c | 0x072c |
| `SET_SRC_HEIGHT` | 0x0730 | 0x0730 | 0x0730 | 0x0730 | 0x0730 | 0x0730 | 0x0730 | 0x0730 | 0x0730 | 0x0730 | 0x0730 |
| `SET_SRC_DEPTH` | 0x0734 | 0x0734 | 0x0734 | 0x0734 | 0x0734 | 0x0734 | 0x0734 | 0x0734 | 0x0734 | 0x0734 | 0x0734 |
| `SET_SRC_LAYER` | 0x0738 | 0x0738 | 0x0738 | 0x0738 | 0x0738 | 0x0738 | 0x0738 | 0x0738 | 0x0738 | 0x0738 | 0x0738 |
| `SET_SRC_ORIGIN` | 0x073c | 0x073c | 0x073c | 0x073c | 0x073c | 0x073c | 0x073c | 0x073c | 0x073c | 0x073c | 0x073c |
| `SRC_ORIGIN_X` | - | - | - | 0x0744 | 0x0744 | 0x0744 | 0x0744 | 0x0744 | 0x0744 | 0x0744 | 0x0744 |
| `SRC_ORIGIN_Y` | - | - | - | 0x0748 | 0x0748 | 0x0748 | 0x0748 | 0x0748 | 0x0748 | 0x0748 | 0x0748 |
| `DST_ORIGIN_X` | - | - | - | 0x074c | 0x074c | 0x074c | 0x074c | 0x074c | 0x074c | 0x074c | 0x074c |
| `DST_ORIGIN_Y` | - | - | - | 0x0750 | 0x0750 | 0x0750 | 0x0750 | 0x0750 | 0x0750 | 0x0750 | 0x0750 |
| `PM_TRIGGER_END` | 0x1114 | 0x1114 | 0x1114 | 0x1114 | 0x1114 | 0x1114 | 0x1114 | 0x1114 | 0x1114 | 0x1114 | 0x1114 |

Confirmed for all 11 classes, Kepler A0B5 to Blackwell CAB5, with identical offsets:
`LAUNCH_DMA 0x300`, `OFFSET_IN_UPPER/LOWER 0x400/0x404`, `OFFSET_OUT_UPPER/LOWER 0x408/0x40c`,
`PITCH_IN/OUT 0x410/0x414`, `LINE_LENGTH_IN 0x418`, `LINE_COUNT 0x41c`, `SET_SEMAPHORE_A/B/PAYLOAD 0x240/0x244/0x248`,
`SET_SRC_PHYS_MODE 0x260`, `SET_DST_PHYS_MODE 0x264`. `[NVIDIA-published]`

### 4.2 Field differences by generation

All `[NVIDIA-published]`, from the same headers:
- **Kepler A0B5, Maxwell B0B5**: `SET_SEMAPHORE_A_UPPER 7:0`, a 40-bit semaphore VA. `LAUNCH_DMA` bit 11 is `BYPASS_L2`.
  `SET_*_PHYS_MODE_TARGET 1:0` is `LOCAL_FB 0`, `COHERENT_SYSMEM 1` or `NONCOHERENT_SYSMEM 2`. `SEMAPHORE_TYPE 4:3` is `NONE 0`,
  `RELEASE_ONE_WORD_SEMAPHORE 1` or `RELEASE_FOUR_WORD_SEMAPHORE 2`.
- **Pascal C0B5/C1B5**: `SET_SEMAPHORE_A_UPPER 16:0`, a 49-bit VA. Bit 11 becomes `FORCE_RMWDISABLE`.
  New `SRC_BYPASS_L2 20:20` and `DST_BYPASS_L2 21:21`, and `RESERVED 31:28`. C1B5 adds
  `SRC_ORIGIN_X/Y 0x744/0x748` and `DST_ORIGIN_X/Y 0x74c/0x750`.
- **Volta C3B5**: adds `LAUNCH_DMA_VPRMODE 23:22`, `RESERVED_START_OF_COPY 24:24`, `FLUSH_TYPE 25:25` and
  `RESERVED_ERR_CODE 31:28`. `SET_*_PHYS_MODE_BASIC_KIND 5:2`.
- **Turing C5B5**: adds `DISABLE_PLC 26:26`.
- **Ampere C6B5**: `SRC/DST_BYPASS_L2` removed. `PHYS_MODE_TARGET_PEERMEM 3`, `PEER_ID 8:6` and `FLA 9:9` added.
  `SEMAPHORE_TYPE` gains `RELEASE_CONDITIONAL_INTR_SEMAPHORE 3`.
- **Ampere-B C7B5**: `SET_SEMAPHORE_PAYLOAD_UPPER 0x024c` and `LAUNCH_DMA_SEMAPHORE_PAYLOAD_SIZE 27:27`
  (`ONE_WORD 0`, `TWO_WORD 1`), so the 64-bit semaphore payload starts here, not at Hopper.
  `SEMAPHORE_TYPE` adds the aliases `RELEASE_SEMAPHORE_NO_TIMESTAMP 1` and `RELEASE_SEMAPHORE_WITH_TIMESTAMP 2`.
  `SET_MONITORED_FENCE_TYPE 0x21c` and `SET_MONITORED_FENCE_SIGNAL_ADDR_BASE_UPPER/LOWER 0x220/0x224` are new.
- **Hopper C8B5**: `SET_SEMAPHORE_A_UPPER 24:0`, a 57-bit VA. `LAUNCH_DMA_COPY_TYPE 21:20` (`PROT2PROT`/`DEFAULT 0`, `SECURE 1`, `NONPROT2NONPROT 2`).
  `VPRMODE` shrinks to `22:22`, and `MEMORY_SCRUB_ENABLE 23:23` is added. Confidential-computing methods
  `SET_SECURE_COPY_MODE 0x500`, `SET_DECRYPT_AUTH_TAG_COMPARE_ADDR_* 0x514/0x518`, `SET_ENCRYPT_AUTH_TAG_ADDR_* 0x530/0x534`,
  `SET_ENCRYPT_IV_ADDR_* 0x538/0x53c` and `SET_MEMORY_SCRUB_PARAMETERS 0x6fc` are new.
- **Blackwell C9B5**: the same as C8B5 for every field compared here.
- **Blackwell-B CAB5**: `FORCE_RMWDISABLE` (bit 11) removed. `DATA_TRANSFER_TYPE` gains `PREFETCH 3`.

Verbatim, Kepler `cla0b5.h` (https://github.com/NVIDIA/open-gpu-doc/blob/9fdf5c406200/classes/dma-copy/cla0b5.h):

```c
#define NVA0B5_SET_SEMAPHORE_A                                                  (0x00000240)
#define NVA0B5_SET_SEMAPHORE_A_UPPER                                            7:0
#define NVA0B5_SET_SEMAPHORE_B                                                  (0x00000244)
#define NVA0B5_SET_SEMAPHORE_B_LOWER                                            31:0
#define NVA0B5_SET_SEMAPHORE_PAYLOAD                                            (0x00000248)
#define NVA0B5_SET_SEMAPHORE_PAYLOAD_PAYLOAD                                    31:0
#define NVA0B5_SET_SRC_PHYS_MODE                                                (0x00000260)
#define NVA0B5_SET_SRC_PHYS_MODE_TARGET                                         1:0
#define NVA0B5_SET_SRC_PHYS_MODE_TARGET_LOCAL_FB                                (0x00000000)
#define NVA0B5_SET_SRC_PHYS_MODE_TARGET_COHERENT_SYSMEM                         (0x00000001)
#define NVA0B5_SET_SRC_PHYS_MODE_TARGET_NONCOHERENT_SYSMEM                      (0x00000002)
#define NVA0B5_SET_DST_PHYS_MODE                                                (0x00000264)
#define NVA0B5_SET_DST_PHYS_MODE_TARGET                                         1:0
#define NVA0B5_SET_DST_PHYS_MODE_TARGET_LOCAL_FB                                (0x00000000)
#define NVA0B5_SET_DST_PHYS_MODE_TARGET_COHERENT_SYSMEM                         (0x00000001)
#define NVA0B5_SET_DST_PHYS_MODE_TARGET_NONCOHERENT_SYSMEM                      (0x00000002)
#define NVA0B5_LAUNCH_DMA                                                       (0x00000300)
#define NVA0B5_LAUNCH_DMA_DATA_TRANSFER_TYPE                                    1:0
#define NVA0B5_LAUNCH_DMA_DATA_TRANSFER_TYPE_NONE                               (0x00000000)
#define NVA0B5_LAUNCH_DMA_DATA_TRANSFER_TYPE_PIPELINED                          (0x00000001)
#define NVA0B5_LAUNCH_DMA_DATA_TRANSFER_TYPE_NON_PIPELINED                      (0x00000002)
#define NVA0B5_LAUNCH_DMA_FLUSH_ENABLE                                          2:2
#define NVA0B5_LAUNCH_DMA_SEMAPHORE_TYPE                                        4:3
#define NVA0B5_LAUNCH_DMA_SEMAPHORE_TYPE_NONE                                   (0x00000000)
#define NVA0B5_LAUNCH_DMA_SEMAPHORE_TYPE_RELEASE_ONE_WORD_SEMAPHORE             (0x00000001)
#define NVA0B5_LAUNCH_DMA_SEMAPHORE_TYPE_RELEASE_FOUR_WORD_SEMAPHORE            (0x00000002)
#define NVA0B5_LAUNCH_DMA_INTERRUPT_TYPE                                        6:5
#define NVA0B5_LAUNCH_DMA_INTERRUPT_TYPE_NONE                                   (0x00000000)
#define NVA0B5_LAUNCH_DMA_INTERRUPT_TYPE_BLOCKING                               (0x00000001)
#define NVA0B5_LAUNCH_DMA_INTERRUPT_TYPE_NON_BLOCKING                           (0x00000002)
#define NVA0B5_LAUNCH_DMA_SRC_MEMORY_LAYOUT                                     7:7
#define NVA0B5_LAUNCH_DMA_SRC_MEMORY_LAYOUT_BLOCKLINEAR                         (0x00000000)
#define NVA0B5_LAUNCH_DMA_SRC_MEMORY_LAYOUT_PITCH                               (0x00000001)
#define NVA0B5_LAUNCH_DMA_DST_MEMORY_LAYOUT                                     8:8
#define NVA0B5_LAUNCH_DMA_DST_MEMORY_LAYOUT_BLOCKLINEAR                         (0x00000000)
#define NVA0B5_LAUNCH_DMA_DST_MEMORY_LAYOUT_PITCH                               (0x00000001)
#define NVA0B5_LAUNCH_DMA_MULTI_LINE_ENABLE                                     9:9
#define NVA0B5_LAUNCH_DMA_REMAP_ENABLE                                          10:10
#define NVA0B5_LAUNCH_DMA_BYPASS_L2                                             11:11
#define NVA0B5_LAUNCH_DMA_BYPASS_L2_USE_PTE_SETTING                             (0x00000000)
#define NVA0B5_LAUNCH_DMA_BYPASS_L2_FORCE_VOLATILE                              (0x00000001)
#define NVA0B5_LAUNCH_DMA_SRC_TYPE                                              12:12
#define NVA0B5_LAUNCH_DMA_SRC_TYPE_VIRTUAL                                      (0x00000000)
#define NVA0B5_LAUNCH_DMA_SRC_TYPE_PHYSICAL                                     (0x00000001)
#define NVA0B5_LAUNCH_DMA_DST_TYPE                                              13:13
#define NVA0B5_LAUNCH_DMA_DST_TYPE_VIRTUAL                                      (0x00000000)
#define NVA0B5_LAUNCH_DMA_DST_TYPE_PHYSICAL                                     (0x00000001)
#define NVA0B5_LAUNCH_DMA_SEMAPHORE_REDUCTION                                   17:14
#define NVA0B5_LAUNCH_DMA_SEMAPHORE_REDUCTION_SIGN_SIGNED                       (0x00000000)
#define NVA0B5_LAUNCH_DMA_SEMAPHORE_REDUCTION_SIGN_UNSIGNED                     (0x00000001)
#define NVA0B5_OFFSET_IN_UPPER                                                  (0x00000400)
#define NVA0B5_OFFSET_IN_UPPER_UPPER                                            7:0
#define NVA0B5_OFFSET_IN_LOWER                                                  (0x00000404)
#define NVA0B5_OFFSET_IN_LOWER_VALUE                                            31:0
#define NVA0B5_OFFSET_OUT_UPPER                                                 (0x00000408)
#define NVA0B5_OFFSET_OUT_UPPER_UPPER                                           7:0
#define NVA0B5_OFFSET_OUT_LOWER                                                 (0x0000040C)
#define NVA0B5_OFFSET_OUT_LOWER_VALUE                                           31:0
#define NVA0B5_PITCH_IN                                                         (0x00000410)
#define NVA0B5_PITCH_IN_VALUE                                                   31:0
#define NVA0B5_PITCH_OUT                                                        (0x00000414)
#define NVA0B5_PITCH_OUT_VALUE                                                  31:0
#define NVA0B5_LINE_LENGTH_IN                                                   (0x00000418)
#define NVA0B5_LINE_LENGTH_IN_VALUE                                             31:0
#define NVA0B5_LINE_COUNT                                                       (0x0000041C)
#define NVA0B5_LINE_COUNT_VALUE                                                 31:0
```

Verbatim, Hopper `clc8b5.h` (https://github.com/NVIDIA/open-gpu-doc/blob/9fdf5c406200/classes/dma-copy/clc8b5.h):

```c
#define NVC8B5_SET_SEMAPHORE_A                                                  (0x00000240)
#define NVC8B5_SET_SEMAPHORE_A_UPPER                                            24:0
#define NVC8B5_SET_SEMAPHORE_B                                                  (0x00000244)
#define NVC8B5_SET_SEMAPHORE_B_LOWER                                            31:0
#define NVC8B5_SET_SEMAPHORE_PAYLOAD                                            (0x00000248)
#define NVC8B5_SET_SEMAPHORE_PAYLOAD_PAYLOAD                                    31:0
#define NVC8B5_SET_SEMAPHORE_PAYLOAD_UPPER                                      (0x0000024C)
#define NVC8B5_SET_SEMAPHORE_PAYLOAD_UPPER_PAYLOAD                              31:0
#define NVC8B5_SET_SRC_PHYS_MODE                                                (0x00000260)
#define NVC8B5_SET_SRC_PHYS_MODE_TARGET                                         1:0
#define NVC8B5_SET_SRC_PHYS_MODE_TARGET_LOCAL_FB                                (0x00000000)
#define NVC8B5_SET_SRC_PHYS_MODE_TARGET_COHERENT_SYSMEM                         (0x00000001)
#define NVC8B5_SET_SRC_PHYS_MODE_TARGET_NONCOHERENT_SYSMEM                      (0x00000002)
#define NVC8B5_SET_SRC_PHYS_MODE_TARGET_PEERMEM                                 (0x00000003)
#define NVC8B5_SET_SRC_PHYS_MODE_BASIC_KIND                                     5:2
#define NVC8B5_SET_SRC_PHYS_MODE_PEER_ID                                        8:6
#define NVC8B5_SET_SRC_PHYS_MODE_FLA                                            9:9
#define NVC8B5_SET_DST_PHYS_MODE                                                (0x00000264)
#define NVC8B5_SET_DST_PHYS_MODE_TARGET                                         1:0
#define NVC8B5_SET_DST_PHYS_MODE_TARGET_LOCAL_FB                                (0x00000000)
#define NVC8B5_SET_DST_PHYS_MODE_TARGET_COHERENT_SYSMEM                         (0x00000001)
#define NVC8B5_SET_DST_PHYS_MODE_TARGET_NONCOHERENT_SYSMEM                      (0x00000002)
#define NVC8B5_SET_DST_PHYS_MODE_TARGET_PEERMEM                                 (0x00000003)
#define NVC8B5_SET_DST_PHYS_MODE_BASIC_KIND                                     5:2
#define NVC8B5_SET_DST_PHYS_MODE_PEER_ID                                        8:6
#define NVC8B5_SET_DST_PHYS_MODE_FLA                                            9:9
#define NVC8B5_LAUNCH_DMA_DATA_TRANSFER_TYPE                                    1:0
#define NVC8B5_LAUNCH_DMA_DATA_TRANSFER_TYPE_NONE                               (0x00000000)
#define NVC8B5_LAUNCH_DMA_DATA_TRANSFER_TYPE_PIPELINED                          (0x00000001)
#define NVC8B5_LAUNCH_DMA_DATA_TRANSFER_TYPE_NON_PIPELINED                      (0x00000002)
#define NVC8B5_LAUNCH_DMA_SEMAPHORE_TYPE                                        4:3
#define NVC8B5_LAUNCH_DMA_SEMAPHORE_TYPE_NONE                                   (0x00000000)
#define NVC8B5_LAUNCH_DMA_SEMAPHORE_TYPE_RELEASE_SEMAPHORE_NO_TIMESTAMP         (0x00000001)
#define NVC8B5_LAUNCH_DMA_SEMAPHORE_TYPE_RELEASE_SEMAPHORE_WITH_TIMESTAMP       (0x00000002)
#define NVC8B5_LAUNCH_DMA_SEMAPHORE_TYPE_RELEASE_ONE_WORD_SEMAPHORE             (0x00000001)
#define NVC8B5_LAUNCH_DMA_SEMAPHORE_TYPE_RELEASE_FOUR_WORD_SEMAPHORE            (0x00000002)
#define NVC8B5_LAUNCH_DMA_SEMAPHORE_TYPE_RELEASE_CONDITIONAL_INTR_SEMAPHORE     (0x00000003)
#define NVC8B5_LAUNCH_DMA_COPY_TYPE                                             21:20
#define NVC8B5_LAUNCH_DMA_COPY_TYPE_PROT2PROT                                   (0x00000000)
#define NVC8B5_LAUNCH_DMA_COPY_TYPE_DEFAULT                                     (0x00000000)
#define NVC8B5_LAUNCH_DMA_COPY_TYPE_SECURE                                      (0x00000001)
#define NVC8B5_LAUNCH_DMA_COPY_TYPE_NONPROT2NONPROT                             (0x00000002)
#define NVC8B5_LAUNCH_DMA_COPY_TYPE_RESERVED                                    (0x00000003)
#define NVC8B5_LAUNCH_DMA_VPRMODE                                               22:22
#define NVC8B5_LAUNCH_DMA_VPRMODE_VPR_NONE                                      (0x00000000)
#define NVC8B5_LAUNCH_DMA_VPRMODE_VPR_VID2VID                                   (0x00000001)
#define NVC8B5_LAUNCH_DMA_MEMORY_SCRUB_ENABLE                                   23:23
#define NVC8B5_LAUNCH_DMA_SEMAPHORE_PAYLOAD_SIZE                                27:27
#define NVC8B5_LAUNCH_DMA_SEMAPHORE_PAYLOAD_SIZE_ONE_WORD                       (0x00000000)
#define NVC8B5_LAUNCH_DMA_SEMAPHORE_PAYLOAD_SIZE_TWO_WORD                       (0x00000001)
#define NVC8B5_SET_SECURE_COPY_MODE                                             (0x00000500)
#define NVC8B5_SET_SECURE_COPY_MODE_MODE                                        0:0
#define NVC8B5_SET_SECURE_COPY_MODE_MODE_ENCRYPT                                (0x00000000)
#define NVC8B5_SET_SECURE_COPY_MODE_MODE_DECRYPT                                (0x00000001)
#define NVC8B5_SET_MEMORY_SCRUB_PARAMETERS                                      (0x000006FC)
#define NVC8B5_SET_MEMORY_SCRUB_PARAMETERS_DISCARDABLE                          0:0
```

Verbatim, Blackwell-B `clcab5.h` `DATA_TRANSFER_TYPE` (https://github.com/NVIDIA/open-gpu-doc/blob/9fdf5c406200/classes/dma-copy/clcab5.h):

```c
#define NVCAB5_LAUNCH_DMA_DATA_TRANSFER_TYPE                                    1:0
#define NVCAB5_LAUNCH_DMA_DATA_TRANSFER_TYPE_NONE                               (0x00000000)
#define NVCAB5_LAUNCH_DMA_DATA_TRANSFER_TYPE_PIPELINED                          (0x00000001)
#define NVCAB5_LAUNCH_DMA_DATA_TRANSFER_TYPE_NON_PIPELINED                      (0x00000002)
#define NVCAB5_LAUNCH_DMA_DATA_TRANSFER_TYPE_PREFETCH                           (0x00000003)
```

---

## 5. Host / GPFIFO classes

### 5.1 Method offsets

Headers: open-gpu-doc `classes/host/cl{a06f,a16f,a26f,b06f,c06f,c36f,c46f,c56f,c76f}.h`
(https://github.com/NVIDIA/open-gpu-doc/tree/9fdf5c406200/classes/host), Mesa's `clc86f.h`
(https://gitlab.freedesktop.org/mesa/mesa/-/blob/60d7516520ab/src/nouveau/headers/nvidia/classes/clc86f.h, an NVIDIA-copyright header),
and open-gpu-kernel-modules `clc96f.h`, `clca6f.h`
(https://github.com/NVIDIA/open-gpu-kernel-modules/blob/e6a2e01579fb/src/common/sdk/nvidia/inc/class/clc96f.h, .../clca6f.h).

Caveat: the published Blackwell host headers C96F and CA6F are partial. In both the
open-gpu-kernel-modules and Mesa copies, which are identical, they define only `SET_OBJECT`, `MEM_OP_A..D`
(C96F only), `SEM_*` and `GP_ENTRY*`. A "-" in those two columns means "not published", not
"absent". The open-gpu-kernel-modules `clc86f.h` is also partial (136 defines, against 281 in
Mesa's copy), so the Mesa copy is used for Hopper. Mesa's C86F differs from C76F only in
`SEM_ADDR_HI_OFFSET 24:0` (was `7:0`) and the new GP_ENTRY extended-base opcode (section 5.3).
`[NVIDIA-published]` / `[nouveau/Mesa]`

| method | cla06f | cla16f | cla26f | clb06f | clc06f | clc36f | clc46f | clc56f | clc76f | clc86f (Mesa copy) | clc96f | clca6f |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `SET_OBJECT` | 0x0000 | 0x0000 | 0x0000 | 0x0000 | 0x0000 | 0x0000 | 0x0000 | 0x0000 | 0x0000 | 0x0000 | 0x0000 | 0x0000 |
| `ILLEGAL` | 0x0004 | 0x0004 | 0x0004 | 0x0004 | 0x0004 | 0x0004 | 0x0004 | 0x0004 | 0x0004 | 0x0004 | - | - |
| `NOP` | 0x0008 | 0x0008 | 0x0008 | 0x0008 | 0x0008 | 0x0008 | 0x0008 | 0x0008 | 0x0008 | 0x0008 | - | - |
| `SEMAPHOREA` | 0x0010 | 0x0010 | 0x0010 | 0x0010 | 0x0010 | 0x0010 | 0x0010 | 0x0010 | 0x0010 | 0x0010 | - | - |
| `SEMAPHOREB` | 0x0014 | 0x0014 | 0x0014 | 0x0014 | 0x0014 | 0x0014 | 0x0014 | 0x0014 | 0x0014 | 0x0014 | - | - |
| `SEMAPHOREC` | 0x0018 | 0x0018 | 0x0018 | 0x0018 | 0x0018 | 0x0018 | 0x0018 | 0x0018 | 0x0018 | 0x0018 | - | - |
| `SEMAPHORED` | 0x001c | 0x001c | 0x001c | 0x001c | 0x001c | 0x001c | 0x001c | 0x001c | 0x001c | 0x001c | - | - |
| `NON_STALL_INTERRUPT` | 0x0020 | 0x0020 | 0x0020 | 0x0020 | 0x0020 | 0x0020 | 0x0020 | 0x0020 | 0x0020 | 0x0020 | - | - |
| `FB_FLUSH` | 0x0024 | 0x0024 | 0x0024 | 0x0024 | - | - | - | - | - | - | - | - |
| `MEM_OP_A` | 0x0028 | 0x0028 | 0x0028 | - | 0x0028 | 0x0028 | 0x0028 | 0x0028 | 0x0028 | 0x0028 | 0x0028 | - |
| `MEM_OP_B` | 0x002c | 0x002c | 0x002c | - | 0x002c | 0x002c | 0x002c | 0x002c | 0x002c | 0x002c | 0x002c | - |
| `MEM_OP_C` | - | - | - | 0x0030 | 0x0030 | 0x0030 | 0x0030 | 0x0030 | 0x0030 | 0x0030 | 0x0030 | - |
| `MEM_OP_D` | - | - | - | 0x0034 | 0x0034 | 0x0034 | 0x0034 | 0x0034 | 0x0034 | 0x0034 | 0x0034 | - |
| `SET_REFERENCE` | 0x0050 | 0x0050 | 0x0050 | 0x0050 | 0x0050 | 0x0050 | 0x0050 | 0x0050 | 0x0050 | 0x0050 | - | - |
| `SEM_ADDR_LO` | - | - | - | - | - | 0x005c | 0x005c | 0x005c | 0x005c | 0x005c | 0x005c | 0x005c |
| `SEM_ADDR_HI` | - | - | - | - | - | 0x0060 | 0x0060 | 0x0060 | 0x0060 | 0x0060 | 0x0060 | 0x0060 |
| `SEM_PAYLOAD_LO` | - | - | - | - | - | 0x0064 | 0x0064 | 0x0064 | 0x0064 | 0x0064 | 0x0064 | 0x0064 |
| `SEM_PAYLOAD_HI` | - | - | - | - | - | 0x0068 | 0x0068 | 0x0068 | 0x0068 | 0x0068 | 0x0068 | 0x0068 |
| `SEM_EXECUTE` | - | - | - | - | - | 0x006c | 0x006c | 0x006c | 0x006c | 0x006c | 0x006c | 0x006c |
| `SYNCPOINTA` | - | - | 0x0070 | - | 0x0070 | - | - | - | - | - | - | - |
| `SYNCPOINTB` | - | - | 0x0074 | - | 0x0074 | - | - | - | - | - | - | - |
| `WFI` | - | 0x0078 | 0x0078 | 0x0078 | 0x0078 | 0x0078 | 0x0078 | 0x0078 | 0x0078 | 0x0078 | - | - |
| `CRC_CHECK` | 0x007c | 0x007c | 0x007c | 0x007c | 0x007c | 0x007c | 0x007c | - | - | - | - | - |
| `YIELD` | 0x0080 | 0x0080 | 0x0080 | 0x0080 | 0x0080 | 0x0080 | 0x0080 | 0x0080 | 0x0080 | 0x0080 | - | - |
| `CLEAR_FAULTED` | - | - | - | - | - | 0x0084 | 0x0084 | 0x0084 | 0x0084 | 0x0084 | - | - |

Other notes `[NVIDIA-published]`:
- `clb06f.h` (Maxwell) comments that MEM_OP_A and MEM_OP_B "have been removed for gm20x".
- `SYNCPOINTA/B 0x70/0x74` (Tegra host1x syncpoints, an inference) appear only in A26F (KEPLER_CHANNEL_GPFIFO_C) and C06F.
  The Tegra association is `[derived]`.

### 5.2 Pushbuffer method header (DMA header)

Verbatim from https://github.com/NVIDIA/open-gpu-doc/blob/9fdf5c406200/classes/host/cla06f.h (Kepler),
together with the semaphore and GP_ENTRY defines, in a single block `[NVIDIA-published]`:

```c
#define NVA06F_SEMAPHOREA                                          (0x00000010)
#define NVA06F_SEMAPHOREA_OFFSET_UPPER                                     7:0
#define NVA06F_SEMAPHOREB                                          (0x00000014)
#define NVA06F_SEMAPHOREB_OFFSET_LOWER                                    31:2
#define NVA06F_SEMAPHOREC                                          (0x00000018)
#define NVA06F_SEMAPHOREC_PAYLOAD                                         31:0
#define NVA06F_SEMAPHORED                                          (0x0000001C)
#define NVA06F_SEMAPHORED_OPERATION                                        3:0
#define NVA06F_SEMAPHORED_OPERATION_ACQUIRE                         0x00000001
#define NVA06F_SEMAPHORED_OPERATION_RELEASE                         0x00000002
#define NVA06F_SEMAPHORED_OPERATION_ACQ_GEQ                         0x00000004
#define NVA06F_SEMAPHORED_OPERATION_ACQ_AND                         0x00000008
#define NVA06F_SEMAPHORED_ACQUIRE_SWITCH                                 12:12
#define NVA06F_SEMAPHORED_ACQUIRE_SWITCH_DISABLED                   0x00000000
#define NVA06F_SEMAPHORED_ACQUIRE_SWITCH_ENABLED                    0x00000001
#define NVA06F_SEMAPHORED_RELEASE_WFI                                    20:20
#define NVA06F_SEMAPHORED_RELEASE_WFI_EN                            0x00000000
#define NVA06F_SEMAPHORED_RELEASE_WFI_DIS                           0x00000001
#define NVA06F_SEMAPHORED_RELEASE_SIZE                                   24:24
#define NVA06F_SEMAPHORED_RELEASE_SIZE_16BYTE                       0x00000000
#define NVA06F_SEMAPHORED_RELEASE_SIZE_4BYTE                        0x00000001
#define NVA06F_GP_ENTRY__SIZE                                   8
#define NVA06F_GP_ENTRY0_FETCH                                0:0
#define NVA06F_GP_ENTRY0_FETCH_UNCONDITIONAL           0x00000000
#define NVA06F_GP_ENTRY0_FETCH_CONDITIONAL             0x00000001
#define NVA06F_GP_ENTRY0_GET                                 31:2
#define NVA06F_GP_ENTRY0_OPERAND                             31:0
#define NVA06F_GP_ENTRY1_GET_HI                               7:0
#define NVA06F_GP_ENTRY1_PRIV                                 8:8
#define NVA06F_GP_ENTRY1_PRIV_USER                     0x00000000
#define NVA06F_GP_ENTRY1_PRIV_KERNEL                   0x00000001
#define NVA06F_GP_ENTRY1_LEVEL                                9:9
#define NVA06F_GP_ENTRY1_LEVEL_MAIN                    0x00000000
#define NVA06F_GP_ENTRY1_LEVEL_SUBROUTINE              0x00000001
#define NVA06F_GP_ENTRY1_LENGTH                             30:10
#define NVA06F_GP_ENTRY1_SYNC                               31:31
#define NVA06F_GP_ENTRY1_SYNC_PROCEED                  0x00000000
#define NVA06F_GP_ENTRY1_SYNC_WAIT                     0x00000001
#define NVA06F_GP_ENTRY1_OPCODE                               7:0
#define NVA06F_GP_ENTRY1_OPCODE_NOP                    0x00000000
#define NVA06F_GP_ENTRY1_OPCODE_ILLEGAL                0x00000001
#define NVA06F_GP_ENTRY1_OPCODE_GP_CRC                 0x00000002
#define NVA06F_GP_ENTRY1_OPCODE_PB_CRC                 0x00000003
#define NVA06F_DMA_METHOD_ADDRESS_OLD                              12:2
#define NVA06F_DMA_METHOD_ADDRESS                                  11:0
#define NVA06F_DMA_SUBDEVICE_MASK                                  15:4
#define NVA06F_DMA_METHOD_SUBCHANNEL                               15:13
#define NVA06F_DMA_TERT_OP                                         17:16
#define NVA06F_DMA_TERT_OP_GRP0_INC_METHOD                         (0x00000000)
#define NVA06F_DMA_TERT_OP_GRP0_SET_SUB_DEV_MASK                   (0x00000001)
#define NVA06F_DMA_TERT_OP_GRP0_STORE_SUB_DEV_MASK                 (0x00000002)
#define NVA06F_DMA_TERT_OP_GRP0_USE_SUB_DEV_MASK                   (0x00000003)
#define NVA06F_DMA_TERT_OP_GRP2_NON_INC_METHOD                     (0x00000000)
#define NVA06F_DMA_METHOD_COUNT_OLD                                28:18
#define NVA06F_DMA_METHOD_COUNT                                    28:16
#define NVA06F_DMA_SEC_OP                                          31:29
#define NVA06F_DMA_SEC_OP_GRP0_USE_TERT                            (0x00000000)
#define NVA06F_DMA_SEC_OP_INC_METHOD                               (0x00000001)
#define NVA06F_DMA_SEC_OP_GRP2_USE_TERT                            (0x00000002)
#define NVA06F_DMA_SEC_OP_NON_INC_METHOD                           (0x00000003)
#define NVA06F_DMA_SEC_OP_IMMD_DATA_METHOD                         (0x00000004)
#define NVA06F_DMA_SEC_OP_ONE_INC                                  (0x00000005)
#define NVA06F_DMA_SEC_OP_RESERVED6                                (0x00000006)
#define NVA06F_DMA_SEC_OP_END_PB_SEGMENT                           (0x00000007)
```

- The `DMA_*` field defines are identical in A06F, A16F, A26F, B06F, C06F, C36F, C46F, C56F, C76F and
  Mesa's C86F. The script diff between consecutive headers shows no `DMA_*` change. `[NVIDIA-published]` / `[derived]`
- The Volta manual repeats the same layout: `NV_FIFO_DMA_METHOD_ADDRESS 11:0` (a dword address),
  `METHOD_SUBCHANNEL 15:13`, `TERT_OP 17:16`, `METHOD_COUNT 28:16`, `IMMD_DATA 28:16`, `SEC_OP 31:29`
  with `INC_METHOD 1`, `NON_INC_METHOD 3`, `IMMD_DATA_METHOD 4`, `ONE_INC 5` and `END_PB_SEGMENT 7`
  (https://github.com/NVIDIA/open-gpu-doc/blob/9fdf5c406200/manuals/volta/gv100/dev_ram.ref.txt). `[NVIDIA-published]`
- The published C96F and CA6F headers contain no `DMA_*` defines. Mesa's NVK builds every pushbuffer,
  Blackwell included, with the Fermi `NV906F_DMA_*` defines (`NVC0_FIFO_PKHDR_SQ`, `_IL`, `_1I`, `_0I`
  in https://gitlab.freedesktop.org/mesa/mesa/-/blob/60d7516520ab/src/nouveau/headers/nv_push.h). So the
  header format is unchanged from Fermi through Blackwell in practice. `[nouveau/Mesa]`

### 5.3 GP_ENTRY (GPFIFO entry, 8 bytes)

`[NVIDIA-published]`, from the headers in section 5.1:
- Kepler to Volta (A06F..C36F): `GP_ENTRY0_FETCH 0:0`, `GP_ENTRY0_GET 31:2`, `GP_ENTRY0_OPERAND 31:0`,
  `GP_ENTRY1_GET_HI 7:0`, `GP_ENTRY1_PRIV 8:8` (`USER 0`, `KERNEL 1`), `GP_ENTRY1_LEVEL 9:9`,
  `GP_ENTRY1_LENGTH 30:10`, `GP_ENTRY1_SYNC 31:31`, `GP_ENTRY1_OPCODE 7:0` (`NOP 0`, `ILLEGAL 1`, `GP_CRC 2`, `PB_CRC 3`).
- Turing C46F and later: `GP_ENTRY1_PRIV` removed, everything else unchanged.
- Hopper (Mesa C86F) and Blackwell (C96F, CA6F): adds `GP_ENTRY0_PB_EXTENDED_BASE_OPERAND 24:8` and
  `GP_ENTRY1_OPCODE_SET_PB_SEGMENT_EXTENDED_BASE 0x00000004`. `GET_HI` stays `7:0`. The headers do not
  describe the semantics. Most likely a control entry (LENGTH = 0) supplies VA bits above the 40 that
  GET/GET_HI hold, but that reading is `[derived]` and unverified.

Verbatim Blackwell C96F semaphore and GP_ENTRY defines
(https://github.com/NVIDIA/open-gpu-kernel-modules/blob/e6a2e01579fb/src/common/sdk/nvidia/inc/class/clc96f.h) `[NVIDIA-published]`:

```c
#define NVC96F_SEM_ADDR_LO                                         (0x0000005c)
#define NVC96F_SEM_ADDR_LO_OFFSET                                         31:2
#define NVC96F_SEM_ADDR_HI                                         (0x00000060)
#define NVC96F_SEM_ADDR_HI_OFFSET                                         24:0
#define NVC96F_SEM_PAYLOAD_LO                                      (0x00000064)
#define NVC96F_SEM_PAYLOAD_HI                                      (0x00000068)
#define NVC96F_SEM_EXECUTE                                         (0x0000006c)
#define NVC96F_SEM_EXECUTE_OPERATION                                       2:0
#define NVC96F_SEM_EXECUTE_OPERATION_ACQUIRE                        0x00000000
#define NVC96F_SEM_EXECUTE_OPERATION_RELEASE                        0x00000001
#define NVC96F_SEM_EXECUTE_RELEASE_WFI                                   20:20
#define NVC96F_SEM_EXECUTE_RELEASE_WFI_DIS                          0x00000000
#define NVC96F_SEM_EXECUTE_PAYLOAD_SIZE                                  24:24
#define NVC96F_SEM_EXECUTE_PAYLOAD_SIZE_32BIT                       0x00000000
#define NVC96F_GP_ENTRY__SIZE                                          8
#define NVC96F_GP_ENTRY0_FETCH                                       0:0
#define NVC96F_GP_ENTRY0_FETCH_UNCONDITIONAL                  0x00000000
#define NVC96F_GP_ENTRY0_FETCH_CONDITIONAL                    0x00000001
#define NVC96F_GP_ENTRY0_GET                                        31:2
#define NVC96F_GP_ENTRY0_OPERAND                                    31:0
#define NVC96F_GP_ENTRY0_PB_EXTENDED_BASE_OPERAND                   24:8
#define NVC96F_GP_ENTRY1_GET_HI                                      7:0
#define NVC96F_GP_ENTRY1_LEVEL                                       9:9
#define NVC96F_GP_ENTRY1_LEVEL_MAIN                           0x00000000
#define NVC96F_GP_ENTRY1_LEVEL_SUBROUTINE                     0x00000001
#define NVC96F_GP_ENTRY1_LENGTH                                    30:10
#define NVC96F_GP_ENTRY1_SYNC                                      31:31
#define NVC96F_GP_ENTRY1_SYNC_PROCEED                         0x00000000
#define NVC96F_GP_ENTRY1_SYNC_WAIT                            0x00000001
#define NVC96F_GP_ENTRY1_OPCODE                                      7:0
#define NVC96F_GP_ENTRY1_OPCODE_NOP                           0x00000000
#define NVC96F_GP_ENTRY1_OPCODE_ILLEGAL                       0x00000001
#define NVC96F_GP_ENTRY1_OPCODE_GP_CRC                        0x00000002
#define NVC96F_GP_ENTRY1_OPCODE_PB_CRC                        0x00000003
#define NVC96F_GP_ENTRY1_OPCODE_SET_PB_SEGMENT_EXTENDED_BASE  0x00000004
```

Verbatim Hopper additions (Mesa's clc86f.h) `[nouveau/Mesa]`:

```c
#define NVC86F_SEM_ADDR_HI_OFFSET                                         24:0
#define NVC86F_GP_ENTRY0_PB_EXTENDED_BASE_OPERAND                   24:8
#define NVC86F_GP_ENTRY1_OPCODE_SET_PB_SEGMENT_EXTENDED_BASE  0x00000004
```

### 5.4 Semaphores and GPU timestamps (for a GPU-side timeline)

**Pre-Volta host semaphores (SEMAPHOREA..D, 0x10..0x1c)** `[NVIDIA-published]`, as in the A06F block
above: `SEMAPHOREA_OFFSET_UPPER 7:0`, `SEMAPHOREB_OFFSET_LOWER 31:2`, `SEMAPHOREC_PAYLOAD 31:0`, and in
`SEMAPHORED`: `OPERATION` (`3:0` in A06F and A26F; `4:0` in A16F and from B06F, which adds
`OPERATION_REDUCTION 0x10`), `ACQUIRE_SWITCH 12:12`, `RELEASE_WFI 20:20`, `RELEASE_SIZE 24:24` with
`16BYTE 0x0` and `4BYTE 0x1`, and, in A16F and from B06F on, `REDUCTION 30:27` and `FORMAT 31:31`. The 16-byte form is value 0. A release that
does not set bit 24 therefore writes the 16-byte payload-plus-timestamp structure. `[derived]`
The `SEMAPHOREA..D` methods still appear in the C36F..C86F headers.

**Volta+ host semaphores (SEM_*, 0x5c..0x6c)**, verbatim from
https://github.com/NVIDIA/open-gpu-doc/blob/9fdf5c406200/classes/host/clc56f.h `[NVIDIA-published]`:

```c
#define NVC56F_SEM_ADDR_LO                                         (0x0000005c)
#define NVC56F_SEM_ADDR_LO_OFFSET                                         31:2
#define NVC56F_SEM_ADDR_HI                                         (0x00000060)
#define NVC56F_SEM_ADDR_HI_OFFSET                                          7:0
#define NVC56F_SEM_PAYLOAD_LO                                      (0x00000064)
#define NVC56F_SEM_PAYLOAD_LO_PAYLOAD                                     31:0
#define NVC56F_SEM_PAYLOAD_HI                                      (0x00000068)
#define NVC56F_SEM_PAYLOAD_HI_PAYLOAD                                     31:0
#define NVC56F_SEM_EXECUTE                                         (0x0000006c)
#define NVC56F_SEM_EXECUTE_OPERATION                                       2:0
#define NVC56F_SEM_EXECUTE_OPERATION_ACQUIRE                        0x00000000
#define NVC56F_SEM_EXECUTE_OPERATION_RELEASE                        0x00000001
#define NVC56F_SEM_EXECUTE_OPERATION_ACQ_STRICT_GEQ                 0x00000002
#define NVC56F_SEM_EXECUTE_OPERATION_ACQ_CIRC_GEQ                   0x00000003
#define NVC56F_SEM_EXECUTE_OPERATION_ACQ_AND                        0x00000004
#define NVC56F_SEM_EXECUTE_OPERATION_ACQ_NOR                        0x00000005
#define NVC56F_SEM_EXECUTE_OPERATION_REDUCTION                      0x00000006
#define NVC56F_SEM_EXECUTE_ACQUIRE_SWITCH_TSG                            12:12
#define NVC56F_SEM_EXECUTE_ACQUIRE_SWITCH_TSG_DIS                   0x00000000
#define NVC56F_SEM_EXECUTE_ACQUIRE_SWITCH_TSG_EN                    0x00000001
#define NVC56F_SEM_EXECUTE_RELEASE_WFI                                   20:20
#define NVC56F_SEM_EXECUTE_RELEASE_WFI_DIS                          0x00000000
#define NVC56F_SEM_EXECUTE_RELEASE_WFI_EN                           0x00000001
#define NVC56F_SEM_EXECUTE_PAYLOAD_SIZE                                  24:24
#define NVC56F_SEM_EXECUTE_PAYLOAD_SIZE_32BIT                       0x00000000
#define NVC56F_SEM_EXECUTE_PAYLOAD_SIZE_64BIT                       0x00000001
#define NVC56F_SEM_EXECUTE_RELEASE_TIMESTAMP                             25:25
#define NVC56F_SEM_EXECUTE_RELEASE_TIMESTAMP_DIS                    0x00000000
#define NVC56F_SEM_EXECUTE_RELEASE_TIMESTAMP_EN                     0x00000001
#define NVC56F_SEM_EXECUTE_REDUCTION                                     30:27
#define NVC56F_GP_ENTRY0_FETCH                                0:0
#define NVC56F_GP_ENTRY0_GET                                 31:2
#define NVC56F_GP_ENTRY0_OPERAND                             31:0
#define NVC56F_GP_ENTRY1_GET_HI                               7:0
#define NVC56F_GP_ENTRY1_LEVEL                                9:9
#define NVC56F_GP_ENTRY1_LENGTH                             30:10
#define NVC56F_GP_ENTRY1_SYNC                               31:31
#define NVC56F_GP_ENTRY1_OPCODE                               7:0
```

`SEM_ADDR_HI_OFFSET` is `7:0` from C36F to C76F and `24:0` in Hopper (Mesa C86F) and Blackwell (C96F).

**16-byte semaphore layout.** The Volta PBDMA manual
(https://github.com/NVIDIA/open-gpu-doc/blob/9fdf5c406200/manuals/volta/gv100/dev_pbdma.ref.txt,
section "Host Semaphore Methods" and the `SEM_EXECUTE` timestamp option) states the following,
paraphrased `[NVIDIA-published]`:
- A release with `RELEASE_TIMESTAMP_EN` writes 16 bytes and needs a 16-byte-aligned address.
  Misalignment raises `NV_PPBDMA_INTR_0_SEMAPHORE`.
- The timestamp is a nanosecond value snapped from `NV_PTIMER_TIME_1/0`, and it is written before
  the payload.
- The little-endian layout:

| bytes | PAYLOAD_SIZE=32BIT | PAYLOAD_SIZE=64BIT |
|---|---|---|
| 0..3 | payload[31:0] | payload[31:0] |
| 4..7 | 0 | payload[63:32] |
| 8..15 | timer[63:0] | timer[63:0] |

envytools describes the same 4-word "long semaphore" for G84+ host releases: `0x00` 32-bit
sequence, `0x04` 0, `0x08` 64-bit PTIMER timestamp
(https://github.com/envytools/envytools/blob/f102b82381f3/docs/hw/fifo/puller.rst). `[envytools]`

**Every place a GPU writes a timestamp** (candidates for timeline reconstruction):

| writer | how it is requested | classes | source |
|---|---|---|---|
| host, pre-Volta | `SEMAPHORED` `OPERATION_RELEASE` with `RELEASE_SIZE_16BYTE` (0) | A06F..C06F | cla06f.h `[NVIDIA-published]` |
| host, Volta+ | `SEM_EXECUTE` `OPERATION_RELEASE`/`REDUCTION` with `RELEASE_TIMESTAMP_EN` (bit 25) | C36F..CA6F | clc56f.h, clc96f.h, dev_pbdma.ref.txt `[NVIDIA-published]` |
| copy engine | `LAUNCH_DMA_SEMAPHORE_TYPE` = `RELEASE_FOUR_WORD_SEMAPHORE` (2); the alias `RELEASE_SEMAPHORE_WITH_TIMESTAMP` (2) from C7B5 | A0B5..CAB5 | dma-copy headers `[NVIDIA-published]` |
| compute engine | `SET_REPORT_SEMAPHORE_A..D` (0x1b00..0x1b0c), `D_OPERATION_RELEASE 0`, `D_STRUCTURE_SIZE_FOUR_WORDS 0` (`ONE_WORD 1`). A0C0..C9C0 have `A_OFFSET_UPPER 7:0`; CBC0..CEC0 have `24:0`. C7C0..CEC0 add `SET_REPORT_SEMAPHORE_PAYLOAD_LOWER/UPPER 0x158/0x15c`, `SET_REPORT_SEMAPHORE_ADDRESS_LOWER/UPPER 0x160/0x164` and `REPORT_SEMAPHORE_EXECUTE 0x168` | A0C0..CEC0 | compute headers `[NVIDIA-published]` |
| kernel completion | QMD `RELEASE0`/`RELEASE1` with `STRUCTURE_SIZE_FOUR_WORDS` (0). V03_00 and later also have `SEMAPHORE_TWO_WORDS` (2) and `PAYLOAD64B`. V04/V05 have up to three releases `RELEASE_SEMAPHORE0..2` | all QMD versions | qmd headers `[NVIDIA-published]` |

The byte layout of the copy-engine "four word" and compute "FOUR_WORDS" structures is not given in
any header or manual found. That they match the host 16-byte layout (payload at +0, 64-bit PTIMER
ns at +8) is `[derived]` and unverified for those engines. The GA102 CE manual
(https://github.com/NVIDIA/open-gpu-doc/blob/9fdf5c406200/manuals/ampere/ga102/dev_ce.ref.txt) has no
semaphore text.

---

## 6. CUDA binary formats

### 6.1 cubin ELF identification and e_flags

- `ELF_MACHINE(EM_CUDA, 190, "cuda", "NVIDIA CUDA architecture")`
  (https://github.com/llvm/llvm-project/blob/af6967c85227/llvm/include/llvm/BinaryFormat/ELF.def). `[LLVM]`
- OS ABI and ABI version, verbatim from https://github.com/llvm/llvm-project/blob/af6967c85227/llvm/include/llvm/BinaryFormat/ELF.h `[LLVM]`:

```c
  ELFOSABI_CUDA = 51,          // NVIDIA CUDA architecture.
  ELFOSABI_CUDA_V2 = 41,       // NVIDIA CUDA architecture.
...
// CUDA OS ABI Version identification.
enum {
  ELFABIVERSION_CUDA_V1 = 7,
  ELFABIVERSION_CUDA_V2 = 8,
};
```

- e_flags, verbatim from the same file `[LLVM]`:

```c
// NVPTX specific e_flags.
enum : unsigned {
  // Processor selection mask for EF_CUDA_SM* values prior to blackwell.
  EF_CUDA_SM = 0xff,

  // Processor selection mask for EF_CUDA_SM* values following blackwell.
  EF_CUDA_SM_MASK = 0xff00,

  // Processor selection mask for EF_CUDA_SM* values following blackwell.
  EF_CUDA_SM_OFFSET = 8,

  // SM based processor values.
  EF_CUDA_SM20 = 0x14,
  EF_CUDA_SM21 = 0x15,
  EF_CUDA_SM30 = 0x1e,
  EF_CUDA_SM32 = 0x20,
  EF_CUDA_SM35 = 0x23,
  EF_CUDA_SM37 = 0x25,
  EF_CUDA_SM50 = 0x32,
  EF_CUDA_SM52 = 0x34,
  EF_CUDA_SM53 = 0x35,
  EF_CUDA_SM60 = 0x3c,
  EF_CUDA_SM61 = 0x3d,
  EF_CUDA_SM62 = 0x3e,
  EF_CUDA_SM70 = 0x46,
  EF_CUDA_SM72 = 0x48,
  EF_CUDA_SM75 = 0x4b,
  EF_CUDA_SM80 = 0x50,
  EF_CUDA_SM86 = 0x56,
  EF_CUDA_SM87 = 0x57,
  EF_CUDA_SM88 = 0x58,
  EF_CUDA_SM89 = 0x59,
  EF_CUDA_SM90 = 0x5a,
  EF_CUDA_SM100 = 0x64,
  EF_CUDA_SM101 = 0x65,
  EF_CUDA_SM103 = 0x67,
  EF_CUDA_SM107 = 0x6b,
  EF_CUDA_SM110 = 0x6e,
  EF_CUDA_SM120 = 0x78,
  EF_CUDA_SM121 = 0x79,

  // Unified texture binding is enabled.
  EF_CUDA_TEXMODE_UNIFIED = 0x100,
  // Independent texture binding is enabled.
  EF_CUDA_TEXMODE_INDEPENDANT = 0x200,
  // The target is using 64-bit addressing.
  EF_CUDA_64BIT_ADDRESS = 0x400,
  // Set when using the sm_90a processor.
  EF_CUDA_ACCELERATORS_V1 = 0x800,
  // Undocumented software feature.
  EF_CUDA_SW_FLAG_V2 = 0x1000,

  // Virtual processor selection mask for EF_CUDA_VIRTUAL_SM* values.
  EF_CUDA_VIRTUAL_SM = 0xff0000,

  // Set when using an accelerator variant like sm_100a in the new ABI.
  EF_CUDA_ACCELERATORS = 0x8,
};
```

- Decoding rule, from `ELFObjectFileBase::getNVPTXCPUName()`
  (https://github.com/llvm/llvm-project/blob/af6967c85227/llvm/lib/Object/ELFObjectFile.cpp) `[LLVM]`:
  if `EI_ABIVERSION == ELFABIVERSION_CUDA_V1` (7) then `SM = e_flags & EF_CUDA_SM`, otherwise
  `SM = (e_flags & EF_CUDA_SM_MASK) >> EF_CUDA_SM_OFFSET`. The `a` suffix comes from
  `EF_CUDA_ACCELERATORS_V1` (0x800) for sm_90, and from `EF_CUDA_ACCELERATORS` (0x8) for
  sm_100/101/103/107/110/120/121. The SM value is the decimal SM number (0x5a = 90).
- In the new ABI, bits 0x100..0x800 of the old flags overlap the new SM field (0xff00). So the old
  `TEXMODE` and `64BIT_ADDRESS` flags cannot keep their meaning there. LLVM defines no V2
  equivalents. `[derived]`
- Not found: which CUDA toolkit release first emits `ELFOSABI_CUDA_V2` / ABI version 8 (LLVM only
  says "following blackwell"), and whether `EF_CUDA_VIRTUAL_SM` still applies in the V2 ABI.

### 6.2 `.nv.info` attributes (EIATTR)

Entry encoding (cricket `get_parm_for_kernel`, https://github.com/RWTH-ACS/cricket/blob/5d55bd582fc7/cpu/cpu-elf2.c) `[cricket]`:

```c
    struct __attribute__((__packed__)) nv_info_kernel_entry {
        uint8_t format;
        uint8_t attribute;
        uint16_t values_size;
        uint32_t values;
    };
```

with `#define EIFMT_NVAL 0x1`, `#define EIFMT_HVAL 0x3`, `#define EIFMT_SVAL 0x4` (same file).
CuAssembler adds `2 : 'EIFMT_BVAL'`
(https://github.com/cloudcores/CuAssembler/blob/96a9f72baf00/CuAsm/CuNVInfo.py) `[community-RE]`.
NVAL entries have no value. For HVAL the 16-bit value sits in the size field. For SVAL a
`values_size`-byte blob follows. That reading follows from cricket's parser, which steps by
`sizeof(entry) + values_size - 4` for SVAL. `[derived]`

`EIATTR_KPARAM_INFO` (0x17) value layout, cricket `[cricket]`: `uint32_t index; uint16_t ordinal;
uint16_t offset; uint16_t unknown:12; uint8_t cbank:6; uint16_t size:14;`. Cricket expects
`values_size == 0xc`.

Attribute id table. Names and ids come from denvdis
(https://github.com/redplait/denvdis/blob/0a39f82bc370/test/eiattrs.inc, extracted from NVIDIA
tools by its author) `[community-RE]`. They are cross-checked against cricket `#define EIATTR_*`
`[cricket]` and CuAssembler `EIATTR` keys `(id << 8) | EIFMT` `[community-RE]`. No NVIDIA-published
EIATTR list exists in any source checked.

| id | name (denvdis) | cricket | CuAssembler (name, EIFMT) |
|---|---|---|---|
| 0x01 | `EIATTR_PAD` |  |  |
| 0x02 | `EIATTR_IMAGE_SLOT` |  |  |
| 0x03 | `EIATTR_JUMPTABLE_RELOCS` |  |  |
| 0x04 | `EIATTR_CTAIDZ_USED` |  | `EIATTR_CTAIDZ_USED`, 1 |
| 0x05 | `EIATTR_MAX_THREADS` |  | `EIATTR_MAX_THREADS`, 4 |
| 0x06 | `EIATTR_IMAGE_OFFSET` |  |  |
| 0x07 | `EIATTR_IMAGE_SIZE` |  |  |
| 0x08 | `EIATTR_TEXTURE_NORMALIZED` |  |  |
| 0x09 | `EIATTR_SAMPLER_INIT` |  |  |
| 0x0a | `EIATTR_PARAM_CBANK` | `EIATTR_PARAM_CBANK` | `EIATTR_PARAM_CBANK`, 4 |
| 0x0b | `EIATTR_SMEM_PARAM_OFFSETS` |  |  |
| 0x0c | `EIATTR_CBANK_PARAM_OFFSETS` |  |  |
| 0x0d | `EIATTR_SYNC_STACK` |  |  |
| 0x0e | `EIATTR_TEXID_SAMPID_MAP` |  |  |
| 0x0f | `EIATTR_EXTERNS` | `EIATTR_EXTERNS` | `EIATTR_EXTERNS`, 4 |
| 0x10 | `EIATTR_REQNTID` |  | `EIATTR_REQNTID`, 4 |
| 0x11 | `EIATTR_FRAME_SIZE` | `EIATTR_FRAME_SIZE` | `EIATTR_FRAME_SIZE`, 4 |
| 0x12 | `EIATTR_MIN_STACK_SIZE` | `EIATTR_MIN_STACK_SIZE` | `EIATTR_MIN_STACK_SIZE`, 4 |
| 0x13 | `EIATTR_SAMPLER_FORCE_UNNORMALIZED` |  |  |
| 0x14 | `EIATTR_BINDLESS_IMAGE_OFFSETS` |  |  |
| 0x15 | `EIATTR_BINDLESS_TEXTURE_BANK` |  | `EIATTR_BINDLESS_TEXTURE_BANK`, 2 |
| 0x16 | `EIATTR_BINDLESS_SURFACE_BANK` |  | `EIATTR_BINDLESS_SURFACE_BANK`, 2 |
| 0x17 | `EIATTR_KPARAM_INFO` | `EIATTR_KPARAM_INFO` | `EIATTR_KPARAM_INFO`, 4 |
| 0x18 | `EIATTR_SMEM_PARAM_SIZE` |  |  |
| 0x19 | `EIATTR_CBANK_PARAM_SIZE` | `EIATTR_CBANK_PARAM_SIZE` | `EIATTR_CBANK_PARAM_SIZE`, 3 |
| 0x1a | `EIATTR_QUERY_NUMATTRIB` |  |  |
| 0x1b | `EIATTR_MAXREG_COUNT` | `EIATTR_MAX_REG_COUNT` | `EIATTR_MAXREG_COUNT`, 3 |
| 0x1c | `EIATTR_EXIT_INSTR_OFFSETS` | `EIATTR_EXIT_INSTR_OFFSETS` | `EIATTR_EXIT_INSTR_OFFSETS`, 4 |
| 0x1d | `EIATTR_S2RCTAID_INSTR_OFFSETS` | `EIATTR_S2RCTAID_INSTR_OFFSETS` | `EIATTR_S2RCTAID_INSTR_OFFSETS`, 4 |
| 0x1e | `EIATTR_CRS_STACK_SIZE` | `EIATTR_CRS_STACK_SIZE` | `EIATTR_CRS_STACK_SIZE`, 4 |
| 0x1f | `EIATTR_NEED_CNP_WRAPPER` |  | `EIATTR_NEED_CNP_WRAPPER`, 1 |
| 0x20 | `EIATTR_NEED_CNP_PATCH` |  | `EIATTR_NEED_CNP_PATCH`, 1 |
| 0x21 | `EIATTR_EXPLICIT_CACHING` |  | `EIATTR_EXPLICIT_CACHING`, 1 |
| 0x22 | `EIATTR_ISTYPEP_USED` |  |  |
| 0x23 | `EIATTR_MAX_STACK_SIZE` |  | `EIATTR_MAX_STACK_SIZE`, 4 |
| 0x24 | `EIATTR_SUQ_USED` |  |  |
| 0x25 | `EIATTR_LD_CACHEMOD_INSTR_OFFSETS` |  | `EIATTR_LD_CACHEMOD_INSTR_OFFSETS`, 4 |
| 0x26 | `EIATTR_LOAD_CACHE_REQUEST` |  |  |
| 0x27 | `EIATTR_ATOM_SYS_INSTR_OFFSETS` |  | `EIATTR_ATOM_SYS_INSTR_OFFSETS`, 4 |
| 0x28 | `EIATTR_COOP_GROUP_INSTR_OFFSETS` |  | `EIATTR_COOP_GROUP_INSTR_OFFSETS`, 4 |
| 0x29 | `EIATTR_COOP_GROUP_MASK_REGIDS` |  |  |
| 0x2a | `EIATTR_SW1850030_WAR` | `EIATTR_SW1850030_WAR` | `EIATTR_SW1850030_WAR`, 1 |
| 0x2b | `EIATTR_WMMA_USED` |  | `EIATTR_WMMA_USED`, 1 |
| 0x2c | `EIATTR_HAS_PRE_V10_OBJECT` |  |  |
| 0x2d | `EIATTR_ATOMF16_EMUL_INSTR_OFFSETS` |  |  |
| 0x2e | `EIATTR_ATOM16_EMUL_INSTR_REG_MAP` |  | `EIATTR_ATOM16_EMUL_INSTR_REG_MAP`, 4 |
| 0x2f | `EIATTR_REGCOUNT` | `EIATTR_REGCOUNT` | `EIATTR_REGCOUNT`, 4 |
| 0x30 | `EIATTR_SW2393858_WAR` | `EIATTR_SW2393858_WAR` | `EIATTR_SW2393858_WAR`, 1 |
| 0x31 | `EIATTR_INT_WARP_WIDE_INSTR_OFFSETS` |  | `EIATTR_INT_WARP_WIDE_INSTR_OFFSETS`, 4 |
| 0x32 | `EIATTR_SHARED_SCRATCH` |  |  |
| 0x33 | `EIATTR_STATISTICS` |  |  |
| 0x34 | `EIATTR_INDIRECT_BRANCH_TARGETS` | `EIATTR_INDIRECT_BRANCH_TARGETS` | `EIATTR_INDIRECT_BRANCH_TARGETS`, 4 |
| 0x35 | `EIATTR_SW2861232_WAR` |  | `EIATTR_SW2861232_WAR`, 1 |
| 0x36 | `EIATTR_SW_WAR` |  | `EIATTR_SW_WAR`, 4 |
| 0x37 | `EIATTR_CUDA_API_VERSION` | `EIATTR_CUDA_API_VERSION` | `EIATTR_CUDA_API_VERSION`, 4 |
| 0x38 | `EIATTR_NUM_MBARRIERS` |  |  |
| 0x39 | `EIATTR_MBARRIER_INSTR_OFFSETS` |  |  |
| 0x3a | `EIATTR_COROUTINE_RESUME_ID_OFFSETS` |  |  |
| 0x3b | `EIATTR_SAM_REGION_STACK_SIZE` |  |  |
| 0x3c | `EIATTR_PER_REG_TARGET_PERF_STATS` |  |  |
| 0x3d | `EIATTR_CTA_PER_CLUSTER` |  |  |
| 0x3e | `EIATTR_EXPLICIT_CLUSTER` |  |  |
| 0x3f | `EIATTR_MAX_CLUSTER_RANK` |  |  |
| 0x40 | `EIATTR_INSTR_REG_MAP` |  |  |
| 0x41 | `EIATTR_RESERVED_SMEM_USED` |  |  |
| 0x42 | `EIATTR_RESERVED_SMEM_0_SIZE` |  |  |
| 0x43 | `EIATTR_UCODE_SECTION_DATA` |  |  |
| 0x44 | `EIATTR_UNUSED_LOAD_BYTE_OFFSET` |  |  |
| 0x45 | `EIATTR_KPARAM_INFO_V2` |  |  |
| 0x46 | `EIATTR_SYSCALL_OFFSETS` |  |  |
| 0x47 | `EIATTR_SW_WAR_MEMBAR_SYS_INSTR_OFFSETS` |  |  |
| 0x48 | `EIATTR_GRAPHICS_GLOBAL_CBANK` |  |  |
| 0x49 | `EIATTR_SHADER_TYPE` |  |  |
| 0x4a | `EIATTR_VRC_CTA_INIT_COUNT` |  |  |
| 0x4b | `EIATTR_TOOLS_PATCH_FUNC` |  |  |
| 0x4c | `EIATTR_NUM_BARRIERS` |  |  |
| 0x4d | `EIATTR_TEXMODE_INDEPENDENT` |  |  |
| 0x4e | `EIATTR_PERF_STATISTICS` |  |  |
| 0x4f | `EIATTR_AT_ENTRY_FRAGMENTS` |  |  |
| 0x50 | `EIATTR_SPARSE_MMA_MASK` |  |  |
| 0x51 | `EIATTR_TCGEN05_1CTA_USED` |  |  |
| 0x52 | `EIATTR_TCGEN05_2CTA_USED` |  |  |
| 0x53 | `EIATTR_GEN_ERRBAR_AT_EXIT` |  |  |
| 0x54 | `EIATTR_REG_RECONFIG` |  |  |
| 0x55 | `EIATTR_ANNOTATIONS` |  |  |
| 0x56 | `EIATTR_SANITIZE` |  |  |
| 0x57 | `EIATTR_STACK_CANARY_TRAP_OFFSETS` |  |  |
| 0x58 | `EIATTR_STUB_FUNCTION_KIND` |  |  |
| 0x59 | `EIATTR_LOCAL_CTA_ASYNC_STORE_OFFSETS` |  |  |
| 0x5a | `EIATTR_MERCURY_FINALIZER_OPTIONS` |  |  |
| 0x5b | `EIATTR_BLOCKS_ARE_CLUSTERS` |  |  |
| 0x5c | `EIATTR_SANITIZE` |  |  |
| 0x5d | `EIATTR_SYSCALLS_FALLBACK` |  |  |
| 0x5e | `EIATTR_CUDA_REQ` |  |  |
| 0x5f | `EIATTR_MERCURY_ISA_VERSION` |  |  |
| 0x60 | `EIATTR_EXPORTED_FUNCTION` |  |  |
| 0x61 | `EIATTR_RTCORE_ENTRY` |  |  |
| 0x62 | `EIATTR_CLUSTER_LAUNCH_CONTROL_USED` |  |  |
| 0x63 | `EIATTR_LAUNCH_PRE_REG_ALLOC` |  |  |
| 0x64 | `EIATTR_MIN_PER_CTA_MEMORY_SIZE` |  |  |
| 0x65 | `EIATTR_IGNOREOOB_CP_ASYNC_BULK_INSTR_OFFSETS` |  |  |
| 0x66 | `EIATTR_LANGUAGE` |  |  |
| 0x67 | `EIATTR_WAR5829587_NEEDED` |  |  |
| 0x68 | `EIATTR_GRID_ATTRIBUTES` |  |  |
| 0x69 | `EIATTR_STACK_OFFSET` |  |  |
| 0x6a | `EIATTR_RT_LIVESTATE_SASS_MAP` |  |  |
| 0x6b | `EIATTR_NVSAL_SW_WAR` |  |  |
| 0x6c | `EIATTR_INSTR_OFFSETS` |  |  |
| 0x6d | `EIATTR_PREEXIT_USED` |  |  |

Notes: denvdis lists `EIATTR_SANITIZE` at both 0x56 and 0x5c. cricket names 0x1b `EIATTR_MAX_REG_COUNT`
where the other two use `EIATTR_MAXREG_COUNT`. No other naming conflicts among the overlapping ids.

### 6.3 Fatbin container

**Host-side wrapper** (the `__fatBinC_Wrapper_t` the CUDA runtime registers):
- ZLUDA reproduces the CUDA toolkit's struct in a comment: `int magic; int version; const unsigned long long* data;
  void *filename_or_fatbins; /* version 1: offline filename, version 2: array of prelinked fatbins */`
  (https://github.com/vosen/ZLUDA/blob/eb89ae3b23b2/cuda_types/src/dark_api.rs). Its Rust constants are
  `FatbincWrapper::MAGIC = 0x466243B1`, `VERSION_V1 = 0x1` and `VERSION_V2 = 0x2`. `[ZLUDA]`
- clang emits `struct { int magic, int version, void * gpu_binary, void * dont_care }` with
  `CudaFatMagic = 0x466243b1` and version 1. It places the wrapper in section `.nvFatBinSegment`
  (`__NV_CUDA,__fatbin` on macOS), "NVIDIA's cuobjdump looks for fatbins in this section". The fatbin
  bytes go in `.nv_fatbin`, or `__nv_relfatbin` for relocatable device code
  (https://github.com/llvm/llvm-project/blob/af6967c85227/clang/lib/CodeGen/CGCUDANV.cpp). `[LLVM]`
- cricket: `#define FATBIN_STRUCT_MAGIC 0x466243b1` (cpu-elf2.c). `[cricket]`

**Fatbin header** (start of `.nv_fatbin` data). Verbatim cricket
(https://github.com/RWTH-ACS/cricket/blob/5d55bd582fc7/cpu/cpu-elf2.c) `[cricket]`:

```c
#define FATBIN_TEXT_MAGIC   0xBA55ED50

struct  __attribute__((__packed__)) fat_elf_header
{
    uint32_t magic;
    uint16_t version;
    uint16_t header_size;
    uint64_t size;
};
```

Cricket requires `version == 1` and `header_size == sizeof(struct fat_elf_header)` (16). ZLUDA's
comment adds `#define OLD_STYLE_FATBIN_MAGIC 0x1EE55A01U` and describes `fatSize` as the "size of the
entire fat binary excluding this header". `[ZLUDA]`

**Per-entry header.** Two independent reverse-engineered layouts exist. They agree where marked:

| offset | cricket / cuda-fatbin-decompression `fat_text_header` | ZLUDA `FatbinFileHeader` | agree |
|---|---|---|---|
| 0x00 | `uint16_t kind` | `kind: c_ushort` (1 = PTX, 2 = ELF) | yes |
| 0x02 | `uint16_t unknown1` | `version: c_ushort` (`HEADER_VERSION_CURRENT = 0x101`) | position |
| 0x04 | `uint32_t header_size` | `header_size: c_uint` | yes |
| 0x08 | `uint64_t size` | `payload_size: c_uint`, `unknown0: c_uint` | low 32 bits |
| 0x10 | `uint32_t compressed_size` | `compressed_size: c_uint` | yes |
| 0x14 | `uint32_t unknown2` | `unknown1: c_uint` | position |
| 0x18 | `uint16_t minor; uint16_t major` | `unknown2: c_uint` | no |
| 0x1c | `uint32_t arch` | `sm_version: c_uint` | yes |
| 0x20 | `uint32_t obj_name_offset` | `bit_width: c_uint` | no |
| 0x24 | `uint32_t obj_name_len` | `unknown3: c_uint` | no |
| 0x28 | `uint64_t flags` | `flags: FatbinFileHeaderFlags` (u64) | yes |
| 0x30 | `uint64_t zero` | `unknown5: c_ulonglong` | position |
| 0x38 | `uint64_t decompressed_size` | `uncompressed_payload: c_ulonglong` | yes |

Sources: https://github.com/RWTH-ACS/cricket/blob/5d55bd582fc7/cpu/cpu-elf2.c `[cricket]`,
https://github.com/n-eiling/cuda-fatbin-decompression/blob/9b194a9aa526/fatbin-decompress.h (same struct) `[community-RE]`,
https://github.com/vosen/ZLUDA/blob/eb89ae3b23b2/cuda_types/src/dark_api.rs `[ZLUDA]`. Offsets are `[derived]` from the field sizes.
Cricket's comment on `decompressed_size` says there is an uncompressed footer, so the value is
generally smaller than `size`.

**Entry flags:**

| flag | value | cricket | ZLUDA |
|---|---|---|---|
| 64-bit | 0x1 | `FATBIN_FLAG_64BIT` | `Is64Bit` |
| debug | 0x2 | `FATBIN_FLAG_DEBUG` | `Debug` |
| CUDA | 0x4 | | `CUDA` |
| OpenCL | 0x8 | | `OpenCL` |
| Linux | 0x10 | `FATBIN_FLAG_LINUX` | `Linux` |
| Mac | 0x20 | | `Mac` |
| Windows | 0x40 | | `Windows` |
| deflate-compressed | 0x1000 | | `CompressedDeflate` |
| LZ4-compressed | 0x2000 | `FATBIN_FLAG_COMPRESS 0x0000000000002000LL` | `CompressedLz4` |
| ZSTD-compressed | 0x8000 | | `CompressedZstd` |

Decompression: ZLUDA decompresses LZ4 entries with `LZ4_decompress_safe` and ZSTD entries with
`zstd_safe::decompress` (https://github.com/vosen/ZLUDA/blob/eb89ae3b23b2/dark_api/src/fatbin.rs) `[ZLUDA]`.
cricket and cuda-fatbin-decompression implement their own LZ4-style decoder
(https://github.com/n-eiling/cuda-fatbin-decompression/blob/9b194a9aa526/fatbin-decompress.c). `[community-RE]`

NVIDIA documentation, `[NVIDIA-published]`:
- nvcc `--compress-mode {default|size|speed|balance|none}`: `default` is "currently equivalent to `speed`",
  and the option "is not compatible with drivers released before CUDA Toolkit's 12.4 Release". There
  is also `--no-compress` (https://docs.nvidia.com/cuda/cuda-compiler-driver-nvcc/index.html). Neither
  page names an algorithm.
- nvFatbin accepts `-compress=<bool>`, `-compress-all`, `-compress-mode=<mode>` (the same five modes)
  and `-concat`, "concatenated fatbin entries for improved compression of multi-architecture builds".
  It does not document the container layout or the algorithms (https://docs.nvidia.com/cuda/nvfatbin/index.html).

LLVM's own offload container (`OffloadBinary`, magic bytes `0x10 0xFF 0x10 0xAD`) is a different
format, not the NVIDIA fatbin
(https://github.com/llvm/llvm-project/blob/af6967c85227/llvm/include/llvm/Object/OffloadBinary.h). `[LLVM]`

Not found:
- An NVIDIA-published fatbin layout.
- Which `--compress-mode` maps to ZSTD vs LZ4.
- The CUDA version that introduced ZSTD (0x8000) or deflate (0x1000).
- The meaning of the unknown entry fields at 0x18/0x20/0x24/0x30.
- The `-concat` entry format.
- gpuocelot was not consulted (it predates compressed fatbins).
- Mesa has no fatbin parser.

---

## 7. What is missing or unverified

- The QMD version the proprietary driver writes for each class. Only NVK's choice is public, and
  Keto has confirmed Ampere V03_00. Turing is the open question: the header defines V02_03,
  while NVK writes V02_02.
- The full Blackwell host method list. The published C96F/CA6F headers omit NOP, ILLEGAL,
  SEMAPHOREA..D, NON_STALL_INTERRUPT, WFI, YIELD, SET_REFERENCE, CLEAR_FAULTED and every `DMA_*` define.
  The pushbuffer header format there relies on NVK practice (section 5.2).
- PBDMA manuals for Kepler, Maxwell and Pascal are not published. Only Volta GV100 and Ampere GA100
  `dev_pbdma.ref.txt` exist in open-gpu-doc.
- The semantics of `GP_ENTRY1_OPCODE_SET_PB_SEGMENT_EXTENDED_BASE` (Hopper and later).
- The byte layout of copy-engine and compute four-word semaphores (assumed equal to the host 16-byte layout).
- The chip for VOLTA_COMPUTE_B (C4C0), AMPERE_CHANNEL_GPFIFO_B outside Orin, KEPLER_CHANNEL_GPFIFO_C (A26F),
  and the many video, JPEG, OFA and VIC classes listed in section 3.2.
- Tegra Thor (Blackwell iGPU) classes. The nvgpu mirror branch used stops at GA10B, and nouveau has no Thor.
- envytools rnndb has no Volta+ class data. It was used only for the pre-GF100 long-semaphore format.
- cubin: the toolkit release that switched to ABI V2, and `EF_CUDA_VIRTUAL_SM` under V2. Fatbin: as listed in 6.3.

## 8. Notes against Keto's current tables

Checked against `keto/symbols/nvidia/_classes.json`, `keto/gpu/qmd.py` and `keto/gpu/pushbuf.py`
as read on 2026-11-17. `[derived]` from the sections above.

- All 47 class ids/names in `_classes.json` match an NVIDIA header define (section 3.1), so every
  `verified: false` entry can be backed by a header now. The generation labels "C4D1 Turing NVJPG" and
  "C6FA Ampere OFA" are not backed by any mapping source: nouveau lists no NVJPG for TU1xx and uses C7FA for GA10x.
- `_classes.json` provenance says "compute SEND_PCAS_A (0x2b4) is used from Volta onwards". In fact
  `SEND_PCAS_A 0x02b4` and `SEND_SIGNALING_PCAS_B 0x02bc` are defined identically from KEPLER_COMPUTE_A,
  and gallium uses them on Kepler (section 2.1).
- The compute method names are class-dependent (section 2.3):
  - `0x0214` is `SET_QMD_VIRTUALIZATION_BASE_A` only in C5C0..CBC0. It is `SET_SHADER_SHARED_MEMORY_WINDOW`
    in A0C0..C1C0 and undefined in C3C0, CDC0 and CEC0.
  - `0x029c` is `SET_QMD_VIRTUALIZATION_CONTROL` only in C5C0..CBC0, and `SET_SCG_RENDER_ENABLE_CONTROL`
    in B1C0..C1C0.
  - `0x02c0` exists from C6C0.
  - `0x0318/0x031c` exist from C0C0.
- The host method names are class-dependent (section 5.1):
  - `FB_FLUSH 0x24` exists only in A06F..B06F.
  - `MEM_OP_A/B` are absent in B06F.
  - `SEM_*` (0x5c..0x6c) and `CLEAR_FAULTED 0x84` exist from C36F.
  - `CRC_CHECK 0x7c` exists in A06F..C46F.
- Copy engine (section 4): `SET_SEMAPHORE_PAYLOAD_UPPER 0x24c` and `SET_MONITORED_FENCE_*` exist from C7B5,
  the secure-copy methods 0x500..0x53c from C8B5, and `SRC/DST_ORIGIN_X/Y 0x744..0x750` from C1B5.
  `PHYS_MODE_TARGET_PEERMEM (3)` exists from C6B5. `SET_SEMAPHORE_A_UPPER` widens 8, 17, then 25 bits.
- `qmd.py` V03_00: every bit range in the `V03_00` dict matches `clc6c0qmd.h` (section 1.4), including
  CB valid 640+i, CB stride 64, and `RELEASE0_PAYLOAD_UPPER 895:864`.
