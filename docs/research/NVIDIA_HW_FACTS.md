# NVIDIA GPU hardware facts for Keto (Kepler through Blackwell)

Research notes collected 2026-11-17 for extending Keto beyond Pascal..Blackwell.
Organized by topic, then by generation. Every fact carries its source URL and one tag:

| Tag | Meaning |
|---|---|
| **[NVIDIA-published]** | Text written by NVIDIA: `open-gpu-kernel-modules` (generated `swref/published` reference headers, and the RM driver source under `src/nvidia`), `open-gpu-doc` manuals, NVIDIA's Tegra `nvgpu` driver hardware headers (`hw_*.h`), `nvml.h`, NVIDIA CUDA web pages. Where the fact comes from driver *logic* instead of a reference header, the text says "(RM code)" or "(nvgpu)". |
| **[nouveau]** | Linux kernel nouveau driver (`drivers/gpu/drm/nouveau`). Mesa's nouveau/NVK userspace is also tagged [nouveau] and labelled "(Mesa)". |
| **[envytools]** | envytools documentation or rnndb XML. |
| **[derived]** | Computed or inferred by this document from the cited facts; not stated in any source. |

Code and `#define` excerpts below are copied verbatim from the files (MIT-licensed NVIDIA headers and nvgpu `hw_*.h`; nouveau and envytools excerpts are short quotations). They were extracted mechanically from the downloaded files, so whitespace is as in the source.

## Source snapshot

| Repository | Ref | Commit | Commit date |
|---|---|---|---|
| github.com/NVIDIA/open-gpu-kernel-modules | main | e6a2e01579fbbd1ca2ed43fef2ee2589e9bd8bd9 | 2026-11-05 |
| github.com/NVIDIA/open-gpu-doc | master | 9fdf5c4062007929d9f4e6cbad9c9771fe61b880 | 2026-06-10 |
| github.com/torvalds/linux (nouveau) | master | 141b164bbe186423e295b139e40e8e2d11cf1341 | 2026-11-16 |
| github.com/envytools/envytools | master | f102b82381f3f11cee113d16374c87091db039d9 | 2023-10-26 |
| github.com/OE4T/linux-nvgpu (public mirror of NVIDIA's L4T nvgpu driver) | patches-rel-36 | 21d928824dc7ca3dc17603a53b11edc6641ace2d | 2024-10-30 |
| github.com/NVIDIA/go-nvml (`gen/nvml/nvml.h`, NVML API 13) | main | 5e992702f9f516e8db7a0c34d3e462a87f48339d | 2026-11-10 |
| gitlab.freedesktop.org/mesa/mesa (`src/nouveau/winsys/nouveau_device.c`) | main | d967121a16974aee70f0d7abeb624283a09e0bea (last commit touching the file) | 2026-08-21 |

All URLs below are the raw URLs that were fetched; files on `main`/`master` can move after this date.

## Notation

- NVIDIA manual notation `(N*32+hi):(N*32+lo)` is bits hi..lo of 32-bit word N, i.e. byte offset `4*N` [NVIDIA-published convention, also stated in Keto `_layouts.json`].
- VER1 PDE/PTE fields are written as word0/word1 of an 8-byte entry. In a little-endian 64-bit view, word1 bit b is bit 32+b [derived].
- VER2/VER3 fields are written as absolute bit positions inside the 8- or 16-byte entry [NVIDIA-published].
- "Chipset" means the 9-bit value in `NV_PMC_BOOT_0` bits 28:20 (architecture 28:24 plus implementation 23:20), e.g. `0x0e4` for GK104 (see Topic 5).

---

# Topic 1: GMMU VER1 (Fermi, Kepler, Maxwell; optional on Pascal)

## 1.1 Which chips use VER1

- Fermi (GF1xx), Kepler (GK10x, GK110/GK110B, GK208/GK208B, GK20A) and Maxwell (GM10x, GM20x, GM20B) use the VER1 two-level format. nouveau binds `gk104_mmu_new` to GK104/GK106/GK107/GK110/GK110B/GK208/GK208B/GM107/GM108, `gk20a_mmu_new` to GK20A, `gm200_mmu_new` to GM200/GM204/GM206 and `gm20b_mmu_new` to GM20B; all of these use two-level descriptors (`gf100_vmm_desc_*`, `gk104_vmm_desc_*`, `gm200_vmm_desc_*`, shown in 1.7) [nouveau] https://raw.githubusercontent.com/torvalds/linux/master/drivers/gpu/drm/nouveau/nvkm/engine/device/base.c
- Pascal can run either VER1 or VER2; the instance block bit `NV_RAMIN_USE_NEW_PT_FORMAT` selects it (1.9) [NVIDIA-published]. nouveau always programs VER2 on Pascal (`gp100_vmm_join` sets bit 10) [nouveau].
- Volta and later use VER2 (or VER3 from Hopper). The RM comment says so explicitly (1.9) [NVIDIA-published (RM code)]. The unversioned VER1 `NV_MMU_PDE_*`/`NV_MMU_PTE_*` blocks still appear in the Volta, Turing, Ampere and Rubin `dev_mmu.h`, but no code path selects VER1 there [derived].

## 1.2 VER1 PDE (8 bytes, dual big/small pointer) - Maxwell GM107

Source [NVIDIA-published]: https://raw.githubusercontent.com/NVIDIA/open-gpu-kernel-modules/main/src/common/inc/swref/published/maxwell/gm107/dev_mmu.h

```c
#define NV_MMU_PDE_APERTURE_BIG                       (0*32+1):(0*32+0) /* RWXVF */
#define NV_MMU_PDE_APERTURE_BIG_INVALID                      0x00000000 /* RW--V */
#define NV_MMU_PDE_APERTURE_BIG_VIDEO_MEMORY                 0x00000001 /* RW--V */
#define NV_MMU_PDE_APERTURE_BIG_SYSTEM_COHERENT_MEMORY       0x00000002 /* RW--V */
#define NV_MMU_PDE_APERTURE_BIG_SYSTEM_NON_COHERENT_MEMORY   0x00000003 /* RW--V */
#define NV_MMU_PDE_SIZE                               (0*32+3):(0*32+2) /* RWXVF */
#define NV_MMU_PDE_SIZE_FULL                                 0x00000000 /* RW--V */
#define NV_MMU_PDE_SIZE_HALF                                 0x00000001 /* RW--V */
#define NV_MMU_PDE_SIZE_QUARTER                              0x00000002 /* RW--V */
#define NV_MMU_PDE_SIZE_EIGHTH                               0x00000003 /* RW--V */
#define NV_MMU_PDE_ADDRESS_BIG_SYS                   (0*32+31):(0*32+4) /* RWXVF */
#define NV_MMU_PDE_ADDRESS_BIG_VID                   (0*32+31-3):(0*32+4) /* RWXVF */
#define NV_MMU_PDE_APERTURE_SMALL                     (1*32+1):(1*32+0) /* RWXVF */
#define NV_MMU_PDE_APERTURE_SMALL_INVALID                    0x00000000 /* RW--V */
#define NV_MMU_PDE_APERTURE_SMALL_VIDEO_MEMORY               0x00000001 /* RW--V */
#define NV_MMU_PDE_APERTURE_SMALL_SYSTEM_COHERENT_MEMORY     0x00000002 /* RW--V */
#define NV_MMU_PDE_APERTURE_SMALL_SYSTEM_NON_COHERENT_MEMORY 0x00000003 /* RW--V */
#define NV_MMU_PDE_VOL_SMALL                          (1*32+2):(1*32+2) /* RWXVF */
#define NV_MMU_PDE_VOL_SMALL_TRUE                            0x00000001 /* RW--V */
#define NV_MMU_PDE_VOL_SMALL_FALSE                           0x00000000 /* RW--V */
#define NV_MMU_PDE_VOL_BIG                            (1*32+3):(1*32+3) /* RWXVF */
#define NV_MMU_PDE_VOL_BIG_TRUE                              0x00000001 /* RW--V */
#define NV_MMU_PDE_VOL_BIG_FALSE                             0x00000000 /* RW--V */
#define NV_MMU_PDE_ADDRESS_SMALL_SYS                 (1*32+31):(1*32+4) /* RWXVF */
#define NV_MMU_PDE_ADDRESS_SMALL_VID                 (1*32+31-3):(1*32+4) /* RWXVF */
#define NV_MMU_PDE_ADDRESS_SHIFT                             0x0000000c /*       */
#define NV_MMU_PDE__SIZE                                              8
```

The same unversioned PDE block is byte-identical in `pascal/gp100/dev_mmu.h`, `volta/gv100/dev_mmu.h` and `ampere/ga100/dev_mmu.h` (checked by diff) [NVIDIA-published]:
https://raw.githubusercontent.com/NVIDIA/open-gpu-kernel-modules/main/src/common/inc/swref/published/pascal/gp100/dev_mmu.h

## 1.3 VER1 PTE (8 bytes) - Maxwell GM107

Source [NVIDIA-published]: https://raw.githubusercontent.com/NVIDIA/open-gpu-kernel-modules/main/src/common/inc/swref/published/maxwell/gm107/dev_mmu.h

```c
#define NV_MMU_PTE_VALID                              (0*32+0):(0*32+0) /* RWXVF */
#define NV_MMU_PTE_VALID_TRUE                                       0x1 /* RW--V */
#define NV_MMU_PTE_VALID_FALSE                                      0x0 /* RW--V */
#define NV_MMU_PTE_PRIVILEGE                          (0*32+1):(0*32+1) /* RWXVF */
#define NV_MMU_PTE_PRIVILEGE_TRUE                                   0x1 /* RW--V */
#define NV_MMU_PTE_PRIVILEGE_FALSE                                  0x0 /* RW--V */
#define NV_MMU_PTE_READ_ONLY                          (0*32+2):(0*32+2) /* RWXVF */
#define NV_MMU_PTE_READ_ONLY_TRUE                                  0x1  /* RW--V */
#define NV_MMU_PTE_READ_ONLY_FALSE                                 0x0  /* RW--V */
#define NV_MMU_PTE_ENCRYPTED                          (0*32+3):(0*32+3) /* RWXVF */
#define NV_MMU_PTE_ENCRYPTED_TRUE                            0x00000001 /* R---V */
#define NV_MMU_PTE_ENCRYPTED_FALSE                           0x00000000 /* R---V */
#define NV_MMU_PTE_ADDRESS_SYS                      (0*32+31):(0*32+4) /* RWXVF */
#define NV_MMU_PTE_ADDRESS_VID                      (0*32+31-3):(0*32+4) /* RWXVF */
#define NV_MMU_PTE_ADDRESS_VID_PEER                (0*32+31):(0*32+32-3) /* RWXVF */
#define NV_MMU_PTE_ADDRESS_VID_PEER_0                       0x00000000 /* RW--V */
#define NV_MMU_PTE_ADDRESS_VID_PEER_1                       0x00000001 /* RW--V */
#define NV_MMU_PTE_ADDRESS_VID_PEER_2                       0x00000002 /* RW--V */
#define NV_MMU_PTE_ADDRESS_VID_PEER_3                       0x00000003 /* RW--V */
#define NV_MMU_PTE_ADDRESS_VID_PEER_4                       0x00000004 /* RW--V */
#define NV_MMU_PTE_ADDRESS_VID_PEER_5                       0x00000005 /* RW--V */
#define NV_MMU_PTE_ADDRESS_VID_PEER_6                       0x00000006 /* RW--V */
#define NV_MMU_PTE_ADDRESS_VID_PEER_7                       0x00000007 /* RW--V */
#define NV_MMU_PTE_VOL                                (1*32+0):(1*32+0) /* RWXVF */
#define NV_MMU_PTE_VOL_TRUE                                  0x00000001 /* RW--V */
#define NV_MMU_PTE_VOL_FALSE                                 0x00000000 /* RW--V */
#define NV_MMU_PTE_APERTURE                           (1*32+2):(1*32+1) /* RWXVF */
#define NV_MMU_PTE_APERTURE_VIDEO_MEMORY                     0x00000000 /* RW--V */
#define NV_MMU_PTE_APERTURE_PEER_MEMORY                      0x00000001 /* RW--V */
#define NV_MMU_PTE_APERTURE_SYSTEM_COHERENT_MEMORY           0x00000002 /* RW--V */
#define NV_MMU_PTE_APERTURE_SYSTEM_NON_COHERENT_MEMORY       0x00000003 /* RW--V */
#define NV_MMU_PTE_LOCK                               (1*32+3):(1*32+3) /* RWXVF */
#define NV_MMU_PTE_LOCK_TRUE                                        0x1 /* RW--V */
#define NV_MMU_PTE_LOCK_FALSE                                       0x0 /* RW--V */
#define NV_MMU_PTE_COMPTAGLINE                      (1*32+28):(1*32+12) /* RWXVF */
#define NV_MMU_PTE_READ_DISABLE                     (1*32+30):(1*32+30) /* RWXVF */
#define NV_MMU_PTE_READ_DISABLE_TRUE                               0x1  /* RW--V */
#define NV_MMU_PTE_READ_DISABLE_FALSE                              0x0  /* RW--V */
#define NV_MMU_PTE_WRITE_DISABLE                    (1*32+31):(1*32+31) /* RWXVF */
#define NV_MMU_PTE_WRITE_DISABLE_TRUE                              0x1  /* RW--V */
#define NV_MMU_PTE_WRITE_DISABLE_FALSE                             0x0  /* RW--V */
#define NV_MMU_PTE_ADDRESS_SHIFT                             0x0000000c /*       */
#define NV_MMU_PTE__SIZE                                             8
#define NV_MMU_PTE_KIND                              (1*32+11):(1*32+4) /* RWXVF */
```

VER1 KIND values listed in the same GM107 header:

```c
#define NV_MMU_PTE_KIND_PITCH                         0x00 /* R---V */
#define NV_MMU_PTE_KIND_GENERIC_16BX2                 0xfe /* R---V */
#define NV_MMU_PTE_KIND_C32_2CRA                      0xdb /* R---V */
#define NV_MMU_PTE_KIND_C32_MS4_2CBR                  0xe0 /* R---V */
#define NV_MMU_PTE_KIND_C32_MS4_2CBA                  0xe1 /* R---V */
#define NV_MMU_PTE_KIND_C32_MS4_2BRA                  0xe3 /* R---V */
#define NV_MMU_PTE_KIND_C32_MS8_MS16_2CRA             0xe5 /* R---V */
#define NV_MMU_PTE_KIND_C64_2CRA                      0xe9 /* R---V */
#define NV_MMU_PTE_KIND_C64_MS4_2CBR                  0xee /* R---V */
#define NV_MMU_PTE_KIND_C64_MS4_2CBA                  0xef /* R---V */
#define NV_MMU_PTE_KIND_C64_MS4_2BRA                  0xf1 /* R---V */
#define NV_MMU_PTE_KIND_C64_MS8_MS16_2CRA             0xf3 /* R---V */
#define NV_MMU_PTE_KIND_C128_2CR                      0xf5 /* R---V */
#define NV_MMU_PTE_KIND_C128_MS2_2CR                  0xf7 /* R---V */
#define NV_MMU_PTE_KIND_C128_MS4_2CR                  0xf9 /* R---V */
#define NV_MMU_PTE_KIND_C128_MS8_MS16_2CR             0xfb /* R---V */
#define NV_MMU_PTE_KIND_SMHOST_MESSAGE                             0xcb /* R---V */
```

There is no `ATOMIC_DISABLE` bit in any VER1 PTE definition; `NV_MMU_VER2_PTE_ATOMIC_DISABLE 7:7` exists only in VER2 [NVIDIA-published, gp100 `dev_mmu.h`].

### COMPTAGLINE width differs between headers

Apart from KIND values, the unversioned VER1 PTE block is identical (checked by diff) in the GM107, GP100, GV100, TU102 and GA100 headers except for `NV_MMU_PTE_COMPTAGLINE`; the Rubin GR100 header additionally narrows `NV_MMU_PTE_KIND` to `(1*32+7):(1*32+4)` [NVIDIA-published]. COMPTAGLINE per header:

GM107 (`maxwell/gm107/dev_mmu.h`, 17 bits, word1 28:12):
```c
#define NV_MMU_PTE_COMPTAGLINE                      (1*32+28):(1*32+12) /* RWXVF */
```
GP100 and GV100 (`pascal/gp100/dev_mmu.h`, `volta/gv100/dev_mmu.h`, 18 bits, word1 29:12):
```c
#define NV_MMU_PTE_COMPTAGLINE                      (1*32+18+11):(1*32+12) /* RWXVF */
```
TU102, GA100, GR100 (`turing/tu102/dev_mmu.h`, `ampere/ga100/dev_mmu.h`, `rubin/gr100/dev_mmu.h`, 20 bits, word1 31:12, overlapping READ_DISABLE/WRITE_DISABLE):
```c
#define NV_MMU_PTE_COMPTAGLINE                      (1*32+20+11):(1*32+12) /* RWXVF */
```
URLs: https://raw.githubusercontent.com/NVIDIA/open-gpu-kernel-modules/main/src/common/inc/swref/published/volta/gv100/dev_mmu.h , https://raw.githubusercontent.com/NVIDIA/open-gpu-kernel-modules/main/src/common/inc/swref/published/turing/tu102/dev_mmu.h , https://raw.githubusercontent.com/NVIDIA/open-gpu-kernel-modules/main/src/common/inc/swref/published/ampere/ga100/dev_mmu.h

For Kepler/Maxwell parsing use the GM107 17-bit field; Fermi agrees (envytools `TAG` 44..60, 1.5) [derived].

## 1.4 VER1 in a 64-bit little-endian view [derived from 1.2/1.3]

PTE (GM107):

| Bits | Field | Notes |
|---|---|---|
| 0 | VALID | |
| 1 | PRIVILEGE | |
| 2 | READ_ONLY | |
| 3 | ENCRYPTED | |
| 31:4 | ADDRESS_SYS (PA >> 12) | 28 bits, 40-bit system PA |
| 28:4 | ADDRESS_VID (PA >> 12) | 25 bits, 37-bit VRAM PA |
| 31:29 | ADDRESS_VID_PEER | peer index when APERTURE = PEER |
| 32 | VOL | |
| 34:33 | APERTURE | 0 VIDEO, 1 PEER, 2 SYS_COHERENT, 3 SYS_NON_COHERENT |
| 35 | LOCK | |
| 43:36 | KIND | |
| 60:44 | COMPTAGLINE | 61:44 on GP100/GV100 headers, 63:44 on TU102+ headers |
| 62 | READ_DISABLE | |
| 63 | WRITE_DISABLE | |

PDE:

| Bits | Field | Notes |
|---|---|---|
| 1:0 | APERTURE_BIG | 0 INVALID, 1 VIDEO, 2 SYS_COHERENT, 3 SYS_NON_COHERENT |
| 3:2 | SIZE | FULL/HALF/QUARTER/EIGHTH (see envytools naming in 1.5) |
| 31:4 | ADDRESS_BIG_SYS (>> 12) | big-page table pointer; 28:4 for VID |
| 33:32 | APERTURE_SMALL | same encoding as APERTURE_BIG |
| 34 | VOL_SMALL | |
| 35 | VOL_BIG | |
| 63:36 | ADDRESS_SMALL_SYS (>> 12) | small-page table pointer; 60:36 for VID |

## 1.5 Cross-checks: nvgpu (Kepler GK20A, Maxwell GM20B) and envytools (Fermi+)

NVIDIA's Tegra driver header for GK20A (Kepler) defines the same VER1 layout (note 17-bit comptagline and KIND at word1 11:4) [NVIDIA-published (nvgpu)]:
https://raw.githubusercontent.com/OE4T/linux-nvgpu/patches-rel-36/drivers/gpu/nvgpu/include/nvgpu/hw/gk20a/hw_gmmu_gk20a.h

```c
#define gmmu_pde_aperture_big_w()                                           (0U)
#define gmmu_pde_aperture_big_invalid_f()                                 (0x0U)
#define gmmu_pde_aperture_big_video_memory_f()                            (0x1U)
#define gmmu_pde_aperture_big_sys_mem_coh_f()                             (0x2U)
#define gmmu_pde_aperture_big_sys_mem_ncoh_f()                            (0x3U)
#define gmmu_pde_size_w()                                                   (0U)
#define gmmu_pde_size_full_f()                                            (0x0U)
#define gmmu_pde_address_big_sys_f(v)              ((U32(v) & 0xfffffffU) << 4U)
#define gmmu_pde_address_big_sys_w()                                        (0U)
#define gmmu_pde_aperture_small_w()                                         (1U)
#define gmmu_pde_aperture_small_invalid_f()                               (0x0U)
#define gmmu_pde_aperture_small_video_memory_f()                          (0x1U)
#define gmmu_pde_aperture_small_sys_mem_coh_f()                           (0x2U)
#define gmmu_pde_aperture_small_sys_mem_ncoh_f()                          (0x3U)
#define gmmu_pde_vol_small_w()                                              (1U)
#define gmmu_pde_vol_small_true_f()                                       (0x4U)
#define gmmu_pde_vol_small_false_f()                                      (0x0U)
#define gmmu_pde_vol_big_w()                                                (1U)
#define gmmu_pde_vol_big_true_f()                                         (0x8U)
#define gmmu_pde_vol_big_false_f()                                        (0x0U)
#define gmmu_pde_address_small_sys_f(v)            ((U32(v) & 0xfffffffU) << 4U)
#define gmmu_pde_address_small_sys_w()                                      (1U)
#define gmmu_pde_address_shift_v()                                 (0x0000000cU)
#define gmmu_pde__size_v()                                         (0x00000008U)
#define gmmu_pte__size_v()                                         (0x00000008U)
#define gmmu_pte_valid_w()                                                  (0U)
#define gmmu_pte_valid_true_f()                                           (0x1U)
#define gmmu_pte_valid_false_f()                                          (0x0U)
#define gmmu_pte_privilege_w()                                              (0U)
#define gmmu_pte_privilege_true_f()                                       (0x2U)
#define gmmu_pte_privilege_false_f()                                      (0x0U)
#define gmmu_pte_address_sys_f(v)                  ((U32(v) & 0xfffffffU) << 4U)
#define gmmu_pte_address_sys_w()                                            (0U)
#define gmmu_pte_address_vid_f(v)                  ((U32(v) & 0x1ffffffU) << 4U)
#define gmmu_pte_address_vid_w()                                            (0U)
#define gmmu_pte_vol_w()                                                    (1U)
#define gmmu_pte_vol_true_f()                                             (0x1U)
#define gmmu_pte_vol_false_f()                                            (0x0U)
#define gmmu_pte_aperture_w()                                               (1U)
#define gmmu_pte_aperture_video_memory_f()                                (0x0U)
#define gmmu_pte_aperture_sys_mem_coh_f()                                 (0x4U)
#define gmmu_pte_aperture_sys_mem_ncoh_f()                                (0x6U)
#define gmmu_pte_read_only_w()                                              (0U)
#define gmmu_pte_read_only_true_f()                                       (0x4U)
#define gmmu_pte_write_disable_w()                                          (1U)
#define gmmu_pte_write_disable_true_f()                            (0x80000000U)
#define gmmu_pte_read_disable_w()                                           (1U)
#define gmmu_pte_read_disable_true_f()                             (0x40000000U)
#define gmmu_pte_comptagline_s()                                           (17U)
#define gmmu_pte_comptagline_f(v)                   ((U32(v) & 0x1ffffU) << 12U)
#define gmmu_pte_comptagline_w()                                            (1U)
#define gmmu_pte_address_shift_v()                                 (0x0000000cU)
#define gmmu_pte_kind_f(v)                              ((U32(v) & 0xffU) << 4U)
#define gmmu_pte_kind_w()                                                   (1U)
#define gmmu_pte_kind_invalid_v()                                  (0x000000ffU)
#define gmmu_pte_kind_pitch_v()                                    (0x00000000U)
```

`hw_gmmu_gm20b.h` (GM20B) defines all of these `gmmu_pde_*`/`gmmu_pte_*` macros identically (checked by diff; same 17-bit `gmmu_pte_comptagline_f`) [NVIDIA-published (nvgpu)]: https://raw.githubusercontent.com/OE4T/linux-nvgpu/patches-rel-36/drivers/gpu/nvgpu/include/nvgpu/hw/gm20b/hw_gmmu_gm20b.h

envytools rnndb names the Fermi+ fields (`GF100_PDE`, `GF100_PTE`) [envytools]:
https://raw.githubusercontent.com/envytools/envytools/master/rnndb/memory/gf100_vm.xml

```xml
<bitset name="GF100_PDE">
	<bitfield pos="0" name="LPT_PRESENT"/>
	<!-- 1? -->
	<bitfield low="2" high="3" name="PT_SIZE">
		<value value="0" name="FULL"/>
		<value value="1" name="64M"/>
		<value value="2" name="32M"/>
		<value value="3" name="16M"/>
	</bitfield>
	<bitfield low="4" high="31" name="LPT_ADDRESS" shr="12"/>
	<bitfield pos="32" name="SPT_PRESENT"/>
	<!-- 33-35? -->
	<bitfield low="36" high="63" name="SPT_ADDRESS" shr="12"/>
</bitset>
<bitset name="GF100_PTE">
	<bitfield pos="0" name="PRESENT"/>
	<bitfield pos="1" name="SUPERVISOR_ONLY"/>
	<bitfield pos="2" name="READ_ONLY"/>
	<bitfield pos="3" name="ENCRYPTED"/> <!-- SYSRAM only -->
	<bitfield low="4" high="31" name="ADDRESS" shr="12"/>
	<!-- 32? -->
	<bitfield low="33" high="34" name="TARGET" type="g80_mem_target"/>
	<!-- 35? -->
	<bitfield low="36" high="43" name="STORAGE_TYPE" type="GF100_STORAGE_TYPE"/>
	<bitfield low="44" high="60" name="TAG"/>
</bitset>
```

envytools' prose pages for GF100 VM and PFIFO are empty stubs ("todo:: write me"): https://raw.githubusercontent.com/envytools/envytools/master/docs/hw/memory/gf100-vm.rst , https://raw.githubusercontent.com/envytools/envytools/master/docs/hw/fifo/gf100-pfifo.rst [envytools].

## 1.6 How nouveau writes VER1 entries (Fermi..Maxwell)

Source [nouveau]: https://raw.githubusercontent.com/torvalds/linux/master/drivers/gpu/drm/nouveau/nvkm/subdev/mmu/vmmgf100.c

PTE flag bits (`gf100_vmm_valid`): VALID bit 0, PRIV bit 1, RO bit 2, VOL bit 32, APERTURE 34:33, KIND 43:36, address is `addr >> 8` (i.e. PA>>12 at bit 4):

```c
	map->type |= BIT(0);
	map->type |= (u64)priv << 1;
	map->type |= (u64)  ro << 2;
	map->type |= (u64) vol << 32;
	map->type |= (u64)aper << 33;
	map->type |= (u64)kind << 36;
```

```c
gf100_vmm_pgt_pte(struct nvkm_vmm *vmm, struct nvkm_mmu_pt *pt,
		  u32 ptei, u32 ptes, struct nvkm_vmm_map *map, u64 addr)
{
	u64 base = (addr >> 8) | map->type;
	u64 data = base;

	if (map->ctag && !(map->next & (1ULL << 44))) {
		while (ptes--) {
			data = base | ((map->ctag >> 1) << 44);
			if (!(map->ctag++ & 1))
				data |= BIT_ULL(60);

			VMM_WO064(pt, vmm, ptei++ * 8, data);
			base += map->next;
		}
	} else {
		map->type += ptes * map->ctag;

		while (ptes--) {
			VMM_WO064(pt, vmm, ptei++ * 8, data);
			data += map->next;
		}
	}
}
```

On GM20x with 64 KiB pages nouveau also sets bit 60 (the top COMPTAGLINE bit) as the "CTL sub index" (which half of a 128 KiB compression page) [nouveau, consistent with the RM comment "On GM20X the MSB bit of the CTL field selects which half of a 128KB compression page is used" in https://raw.githubusercontent.com/NVIDIA/open-gpu-kernel-modules/main/src/nvidia/src/libraries/mmu/gmmu_fmt.c (RM code)].

PDE (`gf100_vmm_pgd_pde`): `pt[0]` is the big (LPT) table, `pt[1]` the small (SPT) table:

```c
gf100_vmm_pgd_pde(struct nvkm_vmm *vmm, struct nvkm_vmm_pt *pgd, u32 pdei)
{
	struct nvkm_vmm_pt *pgt = pgd->pde[pdei];
	struct nvkm_mmu_pt *pd = pgd->pt[0];
	struct nvkm_mmu_pt *pt;
	u64 data = 0;

	if ((pt = pgt->pt[0])) {
		switch (nvkm_memory_target(pt->memory)) {
		case NVKM_MEM_TARGET_VRAM: data |= 1ULL << 0; break;
		case NVKM_MEM_TARGET_HOST: data |= 2ULL << 0;
			data |= BIT_ULL(35); /* VOL */
			break;
		case NVKM_MEM_TARGET_NCOH: data |= 3ULL << 0; break;
		default:
			WARN_ON(1);
			return;
		}
		data |= pt->addr >> 8;
	}

	if ((pt = pgt->pt[1])) {
		switch (nvkm_memory_target(pt->memory)) {
		case NVKM_MEM_TARGET_VRAM: data |= 1ULL << 32; break;
		case NVKM_MEM_TARGET_HOST: data |= 2ULL << 32;
			data |= BIT_ULL(34); /* VOL */
			break;
		case NVKM_MEM_TARGET_NCOH: data |= 3ULL << 32; break;
		default:
			WARN_ON(1);
			return;
		}
		data |= pt->addr << 24;
	}

	nvkm_kmap(pd->memory);
	VMM_WO064(pd, vmm, pdei * 8, data);
	nvkm_done(pd->memory);
}
```

Invalid/sparse encodings used by nouveau (useful to classify non-valid entries in a dump) [nouveau]:
https://raw.githubusercontent.com/torvalds/linux/master/drivers/gpu/drm/nouveau/nvkm/subdev/mmu/vmmgk104.c , https://raw.githubusercontent.com/torvalds/linux/master/drivers/gpu/drm/nouveau/nvkm/subdev/mmu/vmmgm200.c

```c
gk104_vmm_lpt_invalid(struct nvkm_vmm *vmm,
		      struct nvkm_mmu_pt *pt, u32 ptei, u32 ptes)
{
	/* VALID_FALSE + PRIV tells the MMU to ignore corresponding SPTEs. */
	VMM_FO064(pt, vmm, ptei * 8, BIT_ULL(1) /* PRIV. */, ptes);
}
gm200_vmm_pgt_sparse(struct nvkm_vmm *vmm,
		     struct nvkm_mmu_pt *pt, u32 ptei, u32 ptes)
{
	/* VALID_FALSE + VOL tells the MMU to treat the PTE as sparse. */
	VMM_FO064(pt, vmm, ptei * 8, BIT_ULL(32) /* VOL. */, ptes);
}
gm200_vmm_pgd_sparse(struct nvkm_vmm *vmm,
		     struct nvkm_mmu_pt *pt, u32 pdei, u32 pdes)
{
	/* VALID_FALSE + VOL_BIG tells the MMU to treat the PDE as sparse. */
	VMM_FO064(pt, vmm, pdei * 8, BIT_ULL(35) /* VOL_BIG. */, pdes);
}
```

## 1.7 VER1 VA width and level split

nouveau descriptors: `{ type, bits, entry size, alignment }`, listed from the leaf upward [nouveau] (https://raw.githubusercontent.com/torvalds/linux/master/drivers/gpu/drm/nouveau/nvkm/subdev/mmu/vmmgf100.c):

```c
gf100_vmm_desc_17_12[] = {
	{ SPT, 15, 8, 0x1000, &gf100_vmm_pgt },
	{ PGD, 13, 8, 0x1000, &gf100_vmm_pgd },
	{}
};

static const struct nvkm_vmm_desc
gf100_vmm_desc_17_17[] = {
	{ LPT, 10, 8, 0x1000, &gf100_vmm_pgt },
	{ PGD, 13, 8, 0x1000, &gf100_vmm_pgd },
	{}
};

static const struct nvkm_vmm_desc
gf100_vmm_desc_16_12[] = {
	{ SPT, 14, 8, 0x1000, &gf100_vmm_pgt },
	{ PGD, 14, 8, 0x1000, &gf100_vmm_pgd },
	{}
};

static const struct nvkm_vmm_desc
gf100_vmm_desc_16_16[] = {
	{ LPT, 10, 8, 0x1000, &gf100_vmm_pgt },
	{ PGD, 14, 8, 0x1000, &gf100_vmm_pgd },
	{}
};
```

`gk104_vmm_desc_*` (Kepler, GM10x) and `gm200_vmm_desc_*` (GM20x) use the same bit counts (15/13, 10/13, 14/14, 10/14) [nouveau, vmmgk104.c and vmmgm200.c above].

NVIDIA's GM107 `dev_ram.h` gives a 40-bit address-space limit (`NV_RAMIN_ADR_LIMIT_HI (131*32+7):(131*32+0)` above `ADR_LIMIT_LO 31:12`, see 2.3) [NVIDIA-published].

Derived VER1 split (40-bit VA, 8-byte entries everywhere) [derived from the nouveau tables]:

| Big page | PD index (VA bits) | PD size | Big PT index | Big PT size | Small (4 KiB) PT index | Small PT size | One PDE covers |
|---|---|---|---|---|---|---|---|
| 128 KiB | 39:27 (13 bits) | 8192 x 8 B = 64 KiB | 26:17 (10 bits) | 8 KiB | 26:12 (15 bits) | 256 KiB | 128 MiB |
| 64 KiB | 39:26 (14 bits) | 16384 x 8 B = 128 KiB | 25:16 (10 bits) | 8 KiB | 25:12 (14 bits) | 128 KiB | 64 MiB |

nouveau also registers a page shift of 27 (128 MiB) on GM20x, flagged `NVKM_VMM_PAGE_Sxxx` (sparse only, not a mappable page size) [nouveau]:

```c
gm200_vmm_17 = {
	.join = gm200_vmm_join,
	.part = gf100_vmm_part,
	.aper = gf100_vmm_aper,
	.valid = gf100_vmm_valid,
	.flush = gf100_vmm_flush,
	.invalidate_pdb = gf100_vmm_invalidate_pdb,
	.page = {
		{ 27, &gm200_vmm_desc_17_17[1], NVKM_VMM_PAGE_Sxxx },
		{ 17, &gm200_vmm_desc_17_17[0], NVKM_VMM_PAGE_SVxC },
		{ 12, &gm200_vmm_desc_17_12[0], NVKM_VMM_PAGE_SVHx },
		{}
	}
};
```

## 1.8 VER1 big page size: where it is selected

- **Fermi, Kepler, GM10x: global, not stored in memory.** nouveau programs MMIO `0x100c80` bit 0 (1 = 64 KiB, 0 = 128 KiB) and defaults to 128 KiB (`default_bigpage = 17`) for gf100/gk104/gm107 FB [nouveau]:
  https://raw.githubusercontent.com/torvalds/linux/master/drivers/gpu/drm/nouveau/nvkm/subdev/fb/gf100.c , https://raw.githubusercontent.com/torvalds/linux/master/drivers/gpu/drm/nouveau/nvkm/subdev/fb/gk104.c , https://raw.githubusercontent.com/torvalds/linux/master/drivers/gpu/drm/nouveau/nvkm/subdev/fb/gm107.c

```c
gf100_fb_init_page(struct nvkm_fb *fb)
{
	struct nvkm_device *device = fb->subdev.device;
	switch (fb->page) {
	case 16: nvkm_mask(device, 0x100c80, 0x00000001, 0x00000001); break;
	case 17: nvkm_mask(device, 0x100c80, 0x00000001, 0x00000000); break;
	default:
		return -EINVAL;
	}
	return 0;
}
```

  A VRAM dump therefore does not say which split applies; a parser has to try both 64 KiB and 128 KiB splits and keep the one that validates [derived].
- **GM20x / GM20B: per instance block.** nouveau switches `0x100c80` to per-instance mode and sets RAMIN word 128 bit 11 for 64 KiB [nouveau]; NVIDIA's GM20B header names the bit [NVIDIA-published (nvgpu)]:
  https://raw.githubusercontent.com/torvalds/linux/master/drivers/gpu/drm/nouveau/nvkm/subdev/fb/gm200.c , https://raw.githubusercontent.com/OE4T/linux-nvgpu/patches-rel-36/drivers/gpu/nvgpu/include/nvgpu/hw/gm20b/hw_ram_gm20b.h

```c
gm200_fb_init_page(struct nvkm_fb *fb)
{
	struct nvkm_device *device = fb->subdev.device;
	switch (fb->page) {
	case 16: nvkm_mask(device, 0x100c80, 0x00001801, 0x00001001); break;
	case 17: nvkm_mask(device, 0x100c80, 0x00001801, 0x00000000); break;
	case  0: nvkm_mask(device, 0x100c80, 0x00001800, 0x00001800); break;
	default:
		return -EINVAL;
	}
	return 0;
}
gm200_vmm_join_(struct nvkm_vmm *vmm, struct nvkm_memory *inst, u64 base)
{
	if (vmm->func->page[1].shift == 16)
		base |= BIT_ULL(11);
	return gf100_vmm_join_(vmm, inst, base);
}
#define ram_in_big_page_size_f(v)                       ((U32(v) & 0x1U) << 11U)
#define ram_in_big_page_size_m()                              (U32(0x1U) << 11U)
#define ram_in_big_page_size_w()                                          (128U)
#define ram_in_big_page_size_128kb_f()                                    (0x0U)
#define ram_in_big_page_size_64kb_f()                                   (0x800U)
```

- **Pascal:** `NV_RAMIN_BIG_PAGE_SIZE` at word 128 bit 11 (0 = 128 KiB, 1 = 64 KiB) [NVIDIA-published, gp100 `dev_ram.h`, 2.4]. The RM VER2 level code accepts big page shift 16 or 17 (`NV_ASSERT_OR_RETURN_VOID(bigPageShift == 16 || bigPageShift == 17);`, https://raw.githubusercontent.com/NVIDIA/open-gpu-kernel-modules/main/src/nvidia/src/kernel/gpu/mmu/arch/pascal/kern_gmmu_fmt_gp10x.c) [NVIDIA-published (RM code)].

The RM's global table of supported formats and big page shifts [NVIDIA-published (RM code)], https://raw.githubusercontent.com/NVIDIA/open-gpu-kernel-modules/main/src/nvidia/src/libraries/mmu/gmmu_fmt.c :

```c
const NvU32 g_gmmuFmtVersions[GMMU_FMT_MAX_VERSION_COUNT] =
{
    GMMU_FMT_VERSION_1,
    GMMU_FMT_VERSION_2,
    GMMU_FMT_VERSION_3,
};
const NvU32 g_gmmuFmtBigPageShifts[GMMU_FMT_MAX_BIG_PAGE_SIZES] =
{
    16,
    17,
};
```

## 1.9 Selecting VER1 vs VER2 in the instance block, and the PDB field

Pascal `dev_ram.h` (word 128 = byte 0x200, word 129 = 0x204) [NVIDIA-published]:
https://raw.githubusercontent.com/NVIDIA/open-gpu-kernel-modules/main/src/common/inc/swref/published/pascal/gp100/dev_ram.h

```c
#define NV_RAMIN_PAGE_DIR_BASE_TARGET               (128*32+1):(128*32+0) /* RWXUF */
#define NV_RAMIN_PAGE_DIR_BASE_TARGET_VID_MEM                  0x00000000 /* RW--V */
#define NV_RAMIN_PAGE_DIR_BASE_TARGET_SYS_MEM_COHERENT         0x00000002 /* RW--V */
#define NV_RAMIN_PAGE_DIR_BASE_TARGET_SYS_MEM_NONCOHERENT      0x00000003 /* RW--V */
#define NV_RAMIN_PAGE_DIR_BASE_VOL                  (128*32+2):(128*32+2) /* RWXUF */
#define NV_RAMIN_PAGE_DIR_BASE_VOL_TRUE                        0x00000001 /* RW--V */
#define NV_RAMIN_PAGE_DIR_BASE_VOL_FALSE                       0x00000000 /* RW--V */
#define NV_RAMIN_USE_NEW_PT_FORMAT                (128*32+10):(128*32+10) /* RWXUF */
#define NV_RAMIN_USE_NEW_PT_FORMAT_FALSE                       0x00000000 /* RW--V */
#define NV_RAMIN_USE_NEW_PT_FORMAT_TRUE                        0x00000001 /* RW--V */
#define NV_RAMIN_BIG_PAGE_SIZE                    (128*32+11):(128*32+11) /* RWXUF */
#define NV_RAMIN_BIG_PAGE_SIZE_128KB                           0x00000000 /* RW--V */
#define NV_RAMIN_BIG_PAGE_SIZE_64KB                            0x00000001 /* RW--V */
#define NV_RAMIN_PAGE_DIR_BASE_LO                 (128*32+31):(128*32+12) /* RWXUF */
#define NV_RAMIN_PAGE_DIR_BASE_HI                  (129*32+31):(129*32+0) /* RWXUF */
#define NV_RAMIN_ADR_LIMIT_LO                     (130*32+31):(130*32+12) /* RWXUF */
#define NV_RAMIN_ADR_LIMIT_HI                      (131*32+31):(131*32+0) /* RWXUF */
```

The Volta+ manuals rename the same bit `NV_RAMIN_USE_VER2_PT_FORMAT (128*32+10):(128*32+10)` [NVIDIA-published], https://raw.githubusercontent.com/NVIDIA/open-gpu-doc/master/manuals/volta/gv100/dev_ram.ref.txt ; NVIDIA's GP10B header uses the same name [NVIDIA-published (nvgpu)], https://raw.githubusercontent.com/OE4T/linux-nvgpu/patches-rel-36/drivers/gpu/nvgpu/include/nvgpu/hw/gp10b/hw_ram_gp10b.h :

```c
#define ram_in_use_ver2_pt_format_f(v)                  ((U32(v) & 0x1U) << 10U)
#define ram_in_use_ver2_pt_format_m()                         (U32(0x1U) << 10U)
#define ram_in_use_ver2_pt_format_w()                                     (128U)
#define ram_in_use_ver2_pt_format_true_f()                              (0x400U)
#define ram_in_use_ver2_pt_format_false_f()                               (0x0U)
```

How the RM fills the main PDB. The open RM supports Turing and later; for all of them the HAL binds `kgmmuInstBlkPageDirBaseGet_GV100`, which calls `_GP100` for the main PDB (`FIFO_PDB_IDX_BASE`) [NVIDIA-published (RM code)], https://raw.githubusercontent.com/NVIDIA/open-gpu-kernel-modules/main/src/nvidia/src/kernel/gpu/mmu/arch/pascal/kern_gmmu_gp100.c :

```c
        *pOffsetLo = SF_OFFSET(NV_RAMIN_PAGE_DIR_BASE_LO);
        *pDataLo   = SF_NUM(_RAMIN_PAGE_DIR_BASE, _TARGET, aperture) |
                        ((pParams->bIsFaultReplayable) ?
                            SF_DEF(_RAMIN_PAGE_DIR_BASE, _FAULT_REPLAY_TEX, _ENABLED) |
                            SF_DEF(_RAMIN_PAGE_DIR_BASE, _FAULT_REPLAY_GCC, _ENABLED) :
                            SF_DEF(_RAMIN_PAGE_DIR_BASE, _FAULT_REPLAY_TEX, _DISABLED) |
                            SF_DEF(_RAMIN_PAGE_DIR_BASE, _FAULT_REPLAY_GCC, _DISABLED)) |
                        ((NULL != pFmt) && (GMMU_FMT_VERSION_2 == pFmt->version) ?
                            SF_DEF(_RAMIN, _USE_NEW_PT_FORMAT, _TRUE) :
                            SF_DEF(_RAMIN, _USE_NEW_PT_FORMAT, _FALSE)) |
                        ((bigPageSize == FERMI_BIG_PAGESIZE_64K) ?
                            SF_DEF(_RAMIN, _BIG_PAGE_SIZE, _64KB) :
                            SF_DEF(_RAMIN, _BIG_PAGE_SIZE, _128KB)) |
                        SF_NUM(_RAMIN_PAGE_DIR_BASE, _VOL, memdescGetVolatility(pPDB)) |
                        SF_NUM(_RAMIN_PAGE_DIR_BASE, _LO, addrLo);

        *pOffsetHi = SF_OFFSET(NV_RAMIN_PAGE_DIR_BASE_HI);
        *pDataHi   = SF_NUM(_RAMIN_PAGE_DIR_BASE, _HI, NvU64_HI32(physAdd));
```

Subcontext PDBs (Volta+), https://raw.githubusercontent.com/NVIDIA/open-gpu-kernel-modules/main/src/nvidia/src/kernel/gpu/mmu/arch/volta/kern_gmmu_gv100.c [NVIDIA-published (RM code)]:

```c
            // Volta only supports new page table format and 64KB big page size so
            // forcing _USE_VER2_PT_FORMAT to _TRUE and _BIG_PAGE_SIZE to 64KB.
            //
            *pDataLo =
                SF_IDX_NUM(_RAMIN_SC_PAGE_DIR_BASE, _TARGET, aperture,subctxId) |
                ((pParams->bIsFaultReplayable)?
                    SF_IDX_DEF(_RAMIN_SC_PAGE_DIR_BASE, _FAULT_REPLAY_TEX, _ENABLED,  subctxId) |
                    SF_IDX_DEF(_RAMIN_SC_PAGE_DIR_BASE, _FAULT_REPLAY_GCC, _ENABLED,  subctxId) :
                    SF_IDX_DEF(_RAMIN_SC_PAGE_DIR_BASE, _FAULT_REPLAY_TEX, _DISABLED, subctxId) |
                    SF_IDX_DEF(_RAMIN_SC_PAGE_DIR_BASE, _FAULT_REPLAY_GCC, _DISABLED, subctxId)) |
                SF_IDX_DEF(_RAMIN_SC, _USE_VER2_PT_FORMAT, _TRUE, subctxId) |
                SF_IDX_DEF(_RAMIN_SC, _BIG_PAGE_SIZE, _64KB, subctxId) |
```

Pre-Pascal (Kepler, Maxwell) instance blocks have no format bit at all: GM107 `dev_ram.h` and nvgpu `hw_ram_gk20a.h` define only TARGET/VOL/LO/HI and ADR_LIMIT in words 128..131 (2.2, 2.3) [NVIDIA-published]. Bits 10 and 11 of word 128 are not defined there (they lie below `PAGE_DIR_BASE_LO` 31:12), except bit 11 on GM20x (1.8) [derived].

Hopper and later: VER3 is implied by the chip, not by bit 10. The RM PDB code above writes `_USE_NEW_PT_FORMAT, _TRUE` only when `pFmt->version == GMMU_FMT_VERSION_2`, so it writes 0 for VER3 address spaces, while nouveau's `gh100_vmm` uses `gv100_vmm_join` -> `gp100_vmm_join`, which always sets bit 10 (1.10). The bit is therefore not a usable selector on Hopper+ [derived from NVIDIA-published (RM code) + nouveau].

## 1.10 How nouveau joins an address space to an instance block (all generations)

https://raw.githubusercontent.com/torvalds/linux/master/drivers/gpu/drm/nouveau/nvkm/subdev/mmu/vmmgf100.c , vmmgp100.c, vmmgv100.c [nouveau]:

```c
gf100_vmm_join_(struct nvkm_vmm *vmm, struct nvkm_memory *inst, u64 base)
{
	struct nvkm_mmu_pt *pd = vmm->pd->pt[0];

	switch (nvkm_memory_target(pd->memory)) {
	case NVKM_MEM_TARGET_VRAM: base |= 0ULL << 0; break;
	case NVKM_MEM_TARGET_HOST: base |= 2ULL << 0;
		base |= BIT_ULL(2) /* VOL. */;
		break;
	case NVKM_MEM_TARGET_NCOH: base |= 3ULL << 0; break;
	default:
		WARN_ON(1);
		return -EINVAL;
	}
	base |= pd->addr;

	nvkm_kmap(inst);
	nvkm_wo64(inst, 0x0200, base);
	nvkm_wo64(inst, 0x0208, vmm->limit - 1);
	nvkm_done(inst);
	return 0;
}
gp100_vmm_join(struct nvkm_vmm *vmm, struct nvkm_memory *inst)
{
	u64 base = BIT_ULL(10) /* VER2 */ | BIT_ULL(11) /* 64KiB */;
	if (vmm->replay) {
		base |= BIT_ULL(4); /* FAULT_REPLAY_TEX */
		base |= BIT_ULL(5); /* FAULT_REPLAY_GCC */
	}
	return gf100_vmm_join_(vmm, inst, base);
}
```

Note nouveau writes the VA limit (`vmm->limit - 1`) at RAMIN 0x208 on every generation, including Ampere+ where NVIDIA's RM no longer writes `ADR_LIMIT` (2.7) [nouveau; derived comparison].

## 1.11 Tegra notes (GK20A, GM20B)

- nouveau marks Tegra page sizes `NVKM_VMM_PAGE_xxHC` / `SxHC` (host memory, no VRAM) for GK20A and GM20B [nouveau], https://raw.githubusercontent.com/torvalds/linux/master/drivers/gpu/drm/nouveau/nvkm/subdev/mmu/vmmgk20a.c , https://raw.githubusercontent.com/torvalds/linux/master/drivers/gpu/drm/nouveau/nvkm/subdev/mmu/vmmgm20b.c . On these parts "VRAM" content lives in system RAM, so a Keto acquisition would come from a system memory image, and PTE apertures are system-memory apertures [derived].

---

# Topic 2: Instance block (RAMIN), RAMFC, USERD per generation

## 2.1 Common to Kepler..Blackwell

- Instance block is 4 KiB, 4 KiB aligned; RAMFC occupies its first 512 bytes (words 0..127); the page directory base is at word 128 (byte 0x200) [NVIDIA-published, GM107 `dev_ram.h` 2.3, Volta/Ampere manuals 2.5/2.7].
- RAMFC is the saved image of the PBDMA (host channel) registers; the Volta manual maps each `NV_RAMFC_*` to an `NV_PPBDMA_*` register (e.g. `NV_RAMFC_SIGNATURE` <-> `NV_PPBDMA_SIGNATURE(i)`, `NV_RAMFC_HCE_CTRL` <-> `NV_PPBDMA_HCE_CTRL(i)`) [NVIDIA-published], https://raw.githubusercontent.com/NVIDIA/open-gpu-doc/master/manuals/volta/gv100/dev_ram.ref.txt . On Volta/Ampere the RAMFC byte offset equals the PBDMA register offset minus the PBDMA base (SIGNATURE 0x40010 -> 0x10, GP_BASE 0x40048 -> 0x48, HCE_CTRL 0x400e4 -> 0xE4, SET_CHANNEL_INFO 0x400fc -> 0xFC) [derived from 2.5]. Blackwell keeps that correspondence for most fields (2.9).

## 2.2 Kepler (GK104, GK106, GK107, GK110, GK110B, GK208, GK208B, GK20A)

No NVIDIA reference header for discrete Kepler `dev_ram`/`dev_mmu` is published in open-gpu-kernel-modules (`kepler/gk104/` contains only `dev_timer.h`). The closest NVIDIA source is the nvgpu header for GK20A (Tegra K1, Kepler) [NVIDIA-published (nvgpu)]:
https://raw.githubusercontent.com/OE4T/linux-nvgpu/patches-rel-36/drivers/gpu/nvgpu/include/nvgpu/hw/gk20a/hw_ram_gk20a.h

```c
#define ram_in_ramfc_s()                                                 (4096U)
#define ram_in_ramfc_w()                                                    (0U)
#define ram_in_page_dir_base_target_f(v)                 ((U32(v) & 0x3U) << 0U)
#define ram_in_page_dir_base_target_w()                                   (128U)
#define ram_in_page_dir_base_target_vid_mem_f()                           (0x0U)
#define ram_in_page_dir_base_target_sys_mem_coh_f()                       (0x2U)
#define ram_in_page_dir_base_target_sys_mem_ncoh_f()                      (0x3U)
#define ram_in_page_dir_base_vol_w()                                      (128U)
#define ram_in_page_dir_base_vol_true_f()                                 (0x4U)
#define ram_in_page_dir_base_lo_f(v)                ((U32(v) & 0xfffffU) << 12U)
#define ram_in_page_dir_base_lo_w()                                       (128U)
#define ram_in_page_dir_base_hi_f(v)                    ((U32(v) & 0xffU) << 0U)
#define ram_in_page_dir_base_hi_w()                                       (129U)
#define ram_in_adr_limit_lo_f(v)                    ((U32(v) & 0xfffffU) << 12U)
#define ram_in_adr_limit_lo_w()                                           (130U)
#define ram_in_adr_limit_hi_f(v)                        ((U32(v) & 0xffU) << 0U)
#define ram_in_adr_limit_hi_w()                                           (131U)
#define ram_in_base_shift_v()                                      (0x0000000cU)
#define ram_in_alloc_size_v()                                      (0x00001000U)
#define ram_fc_size_val_v()                                        (0x00000200U)
#define ram_fc_gp_put_w()                                                   (0U)
#define ram_fc_userd_w()                                                    (2U)
#define ram_fc_userd_hi_w()                                                 (3U)
#define ram_fc_signature_w()                                                (4U)
#define ram_fc_gp_get_w()                                                   (5U)
#define ram_fc_gp_base_w()                                                 (18U)
#define ram_fc_gp_base_hi_w()                                              (19U)
#define ram_fc_hce_ctrl_w()                                                (57U)
#define ram_fc_chid_w()                                                    (58U)
#define ram_fc_chid_id_f(v)                            ((U32(v) & 0xfffU) << 0U)
#define ram_fc_chid_id_w()                                                  (0U)
#define ram_userd_base_shift_v()                                   (0x00000009U)
#define ram_userd_chan_size_v()                                    (0x00000200U)
#define ram_userd_put_w()                                                  (16U)
#define ram_userd_get_w()                                                  (17U)
#define ram_userd_ref_w()                                                  (18U)
#define ram_userd_put_hi_w()                                               (19U)
#define ram_userd_ref_threshold_w()                                        (20U)
#define ram_userd_top_level_get_w()                                        (22U)
#define ram_userd_top_level_get_hi_w()                                     (23U)
#define ram_userd_get_hi_w()                                               (24U)
#define ram_userd_gp_get_w()                                               (34U)
#define ram_userd_gp_put_w()                                               (35U)
#define ram_userd_gp_top_level_get_w()                                     (22U)
#define ram_userd_gp_top_level_get_hi_w()                                  (23U)
```

`ram_fc_chid_w() (58U)` with `ram_fc_chid_id_f` 11:0 means the channel ID is in RAMFC byte 0xE8, bits 11:0 [NVIDIA-published (nvgpu), byte offset derived].

PBDMA field encodings for GK20A (same `face` signature, USERD in 512-byte units, LIMIT2, HCE priv bit 5) [NVIDIA-published (nvgpu)], https://raw.githubusercontent.com/OE4T/linux-nvgpu/patches-rel-36/drivers/gpu/nvgpu/include/nvgpu/hw/gk20a/hw_pbdma_gk20a.h :

```c
#define pbdma_gp_base_hi_offset_f(v)                    ((U32(v) & 0xffU) << 0U)
#define pbdma_gp_base_hi_limit2_f(v)                   ((U32(v) & 0x1fU) << 16U)
#define pbdma_signature_hw_valid_f()                                   (0xfaceU)
#define pbdma_signature_sw_zero_f()                                       (0x0U)
#define pbdma_userd_target_vid_mem_f()                                    (0x0U)
#define pbdma_userd_target_sys_mem_coh_f()                                (0x2U)
#define pbdma_userd_target_sys_mem_ncoh_f()                               (0x3U)
#define pbdma_userd_addr_f(v)                       ((U32(v) & 0x7fffffU) << 9U)
#define pbdma_userd_hi_addr_f(v)                        ((U32(v) & 0xffU) << 0U)
#define pbdma_hce_ctrl_hce_priv_mode_yes_f()                             (0x20U)
```

Discrete Kepler, as written by nouveau (`gk104_chan_ramfc_write`, used for GK104..GK208 and, via `gm107_chan`, for Maxwell and Pascal) [nouveau], https://raw.githubusercontent.com/torvalds/linux/master/drivers/gpu/drm/nouveau/nvkm/engine/fifo/gk104.c :

```c
gk104_chan_ramfc_write(struct nvkm_chan *chan, u64 offset, u64 length, u32 devm, bool priv)
{
	const u64 userd = nvkm_memory_addr(chan->userd.mem) + chan->userd.base;
	const u32 limit2 = ilog2(length / 8);

	nvkm_kmap(chan->inst);
	nvkm_wo32(chan->inst, 0x08, lower_32_bits(userd));
	nvkm_wo32(chan->inst, 0x0c, upper_32_bits(userd));
	nvkm_wo32(chan->inst, 0x10, 0x0000face);
	nvkm_wo32(chan->inst, 0x30, 0xfffff902);
	nvkm_wo32(chan->inst, 0x48, lower_32_bits(offset));
	nvkm_wo32(chan->inst, 0x4c, upper_32_bits(offset) | (limit2 << 16));
	nvkm_wo32(chan->inst, 0x84, 0x20400000);
	nvkm_wo32(chan->inst, 0x94, 0x30000000 | devm);
	nvkm_wo32(chan->inst, 0x9c, 0x00000100);
	nvkm_wo32(chan->inst, 0xac, 0x0000001f);
	nvkm_wo32(chan->inst, 0xe4, priv ? 0x00000020 : 0x00000000);
	nvkm_wo32(chan->inst, 0xe8, chan->id);
	nvkm_wo32(chan->inst, 0xb8, 0xf8000000);
	nvkm_wo32(chan->inst, 0xf8, 0x10003080); /* 0x002310 */
	nvkm_wo32(chan->inst, 0xfc, 0x10000010); /* 0x002350 */
	nvkm_done(chan->inst);
	return 0;
}
```

USERD stride: 0x200 per channel on Kepler+ (`gk104_chan_userd .size = 0x200`), 0x1000 on Fermi (`gf100_chan_userd .size = 0x1000`) [nouveau], https://raw.githubusercontent.com/torvalds/linux/master/drivers/gpu/drm/nouveau/nvkm/engine/fifo/gf100.c :

```c
gf100_chan_userd = {
	.bar = NVKM_BAR1_FB,
	.size = 0x1000,
	.clear = gf100_chan_userd_clear,
};
gk104_chan_userd = {
	.bar = NVKM_BAR1_FB,
	.size = 0x200,
	.clear = gf100_chan_userd_clear,
};
```

Kepler..Pascal channel -> instance mapping is held in an MMIO channel table (`0x800000 + chid*8`, value `0x80000000 | inst >> 12`), not in VRAM [nouveau]:

```c
gk104_chan_bind_inst(struct nvkm_chan *chan)
{
	struct nvkm_device *device = chan->cgrp->runl->fifo->engine.subdev.device;

	nvkm_wr32(device, 0x800000 + (chan->id * 8), 0x80000000 | chan->inst->addr >> 12);
}
```

## 2.3 Maxwell (GM107, GM108, GM200, GM204, GM206, GM20B)

GM107 `dev_ram.h` (everything except `NV_PRAMIN`) [NVIDIA-published]:
https://raw.githubusercontent.com/NVIDIA/open-gpu-kernel-modules/main/src/common/inc/swref/published/maxwell/gm107/dev_ram.h

```c
#define NV_RAMIN_BASE_SHIFT                                      12 /*       */
#define NV_RAMIN_ALLOC_SIZE                                    4096 /*       */
#define NV_RAMIN_RAMFC                         (127*32+31):(0*32+0) /* RWXUF */
#define NV_RAMUSERD_PUT                        (16*32+31):(16*32+0) /* RWXUF */
#define NV_RAMUSERD_GET                        (17*32+31):(17*32+0) /* RWXUF */
#define NV_RAMUSERD_REF                        (18*32+31):(18*32+0) /* RWXUF */
#define NV_RAMUSERD_PUT_HI                     (19*32+31):(19*32+0) /* RWXUF */
#define NV_RAMUSERD_REF_THRESHOLD              (20*32+31):(20*32+0) /*       */
#define NV_RAMUSERD_TOP_LEVEL_GET              (22*32+31):(22*32+0) /* RWXUF */
#define NV_RAMUSERD_TOP_LEVEL_GET_HI           (23*32+31):(23*32+0) /* RWXUF */
#define NV_RAMUSERD_GET_HI                     (24*32+31):(24*32+0) /* RWXUF */
#define NV_RAMUSERD_GP_GET                     (34*32+31):(34*32+0) /* RWXUF */
#define NV_RAMUSERD_GP_PUT                     (35*32+31):(35*32+0) /* RWXUF */
#define NV_RAMUSERD_BASE_SHIFT                                    9 /*       */
#define NV_RAMUSERD_CHAN_SIZE                                   512 /*       */
#define NV_RAMUSERD_GP_TOP_LEVEL_GET           (22*32+31):(22*32+0) /* RWXUF */
#define NV_RAMUSERD_GP_TOP_LEVEL_GET_HI        (23*32+31):(23*32+0) /* RWXUF */
#define NV_RAMRL_BASE_SHIFT                                      12 /*       */
#define NV_RAMRL_ENTRY_TIMESLICE_SCALE_3                 0x00000003 /* RWI-V */
#define NV_RAMRL_ENTRY_TIMESLICE_TIMEOUT_128             0x00000080 /* RWI-V */
#define NV_RAMRL_ENTRY_SIZE                                       8 /*       */
#define NV_RAMRL_ENTRY_TSG_LENGTH_MAX                    0x00000020 /* RW--V */
#define NV_RAMIN_PAGE_DIR_BASE_TARGET               (128*32+1):(128*32+0) /* RWXUF */
#define NV_RAMIN_PAGE_DIR_BASE_TARGET_VID_MEM                  0x00000000 /* RW--V */
#define NV_RAMIN_PAGE_DIR_BASE_TARGET_SYS_MEM_COHERENT         0x00000002 /* RW--V */
#define NV_RAMIN_PAGE_DIR_BASE_TARGET_SYS_MEM_NONCOHERENT      0x00000003 /* RW--V */
#define NV_RAMIN_PAGE_DIR_BASE_VOL                  (128*32+2):(128*32+2) /* RWXUF */
#define NV_RAMIN_PAGE_DIR_BASE_VOL_TRUE                        0x00000001 /* RW--V */
#define NV_RAMIN_PAGE_DIR_BASE_VOL_FALSE                       0x00000000 /* RW--V */
#define NV_RAMIN_PAGE_DIR_BASE_LO                 (128*32+31):(128*32+12) /* RWXUF */
#define NV_RAMIN_PAGE_DIR_BASE_HI                   (129*32+7):(129*32+0) /* RWXUF */
#define NV_RAMIN_ADR_LIMIT_LO                     (130*32+31):(130*32+12) /* RWXUF */
#define NV_RAMIN_ADR_LIMIT_HI                       (131*32+7):(131*32+0) /* RWXUF */
#define NV_RAMFC                                                    /* ----G */
#define NV_RAMFC_GP_PUT                          (0*32+31):(0*32+0) /* RWXUF */
#define NV_RAMFC_GP_GET                          (5*32+31):(5*32+0) /* RWXUF */
#define NV_RAMFC_GP_BASE                       (18*32+31):(18*32+0) /* RWXUF */
#define NV_RAMFC_GP_BASE_HI                    (19*32+31):(19*32+0) /* RWXUF */
```

GPFIFO size field (`LIMIT2` = log2(entries)) [NVIDIA-published], https://raw.githubusercontent.com/NVIDIA/open-gpu-kernel-modules/main/src/common/inc/swref/published/maxwell/gm107/dev_esched_pbdma.h :

```c
#define NV_PBDMA_GP_BASE_RSVD                                                              2:0 /* RW-UF */
#define NV_PBDMA_GP_BASE_RSVD_ZERO                                                  0x00000000 /* RW--V */
#define NV_PBDMA_GP_BASE_HI(i)                                           (0x0000004C+(i)*8192) /* RW-4A */
#define NV_PBDMA_GP_BASE_HI__SIZE_1                                                          2 /*       */
#define NV_PBDMA_GP_BASE_HI_OFFSET                                                         7:0 /* RW-UF */
#define NV_PBDMA_GP_BASE_HI_OFFSET_ZERO                                             0x00000000 /* RW--V */
#define NV_PBDMA_GP_BASE_HI_LIMIT2                                                       20:16 /* RW-UF */
#define NV_PBDMA_GP_BASE_HI_LIMIT2_ZERO                                             0x00000000 /* RW--V */
```

GM20B vs GK20A in nvgpu: GM20B adds `ram_in_big_page_size` (1.8) and drops `ram_fc_pb_timeslice_w (63)` / `ram_userd_ref_threshold_w (20)`; everything else in `ram_in_*`, `ram_fc_*`, `ram_userd_*`, `ram_rl_*` is identical, including `ram_fc_chid_w() (58U)` [NVIDIA-published (nvgpu), compared by diff], https://raw.githubusercontent.com/OE4T/linux-nvgpu/patches-rel-36/drivers/gpu/nvgpu/include/nvgpu/hw/gm20b/hw_ram_gm20b.h .

## 2.4 Pascal (GP100, GP102, GP104, GP106, GP107, GP108, GP10B)

`gp100/dev_ram.h` RAMIN (shown in 1.9; adds FAULT_REPLAY_TEX/GCC bits 4/5, USE_NEW_PT_FORMAT bit 10, BIG_PAGE_SIZE bit 11, PAGE_DIR_BASE_HI widened to 31:0, ADR_LIMIT_HI 31:0) [NVIDIA-published], https://raw.githubusercontent.com/NVIDIA/open-gpu-kernel-modules/main/src/common/inc/swref/published/pascal/gp100/dev_ram.h

GP10B (nvgpu) differences from GM20B [NVIDIA-published (nvgpu)], https://raw.githubusercontent.com/OE4T/linux-nvgpu/patches-rel-36/drivers/gpu/nvgpu/include/nvgpu/hw/gp10b/hw_ram_gp10b.h :

```c
#define ram_in_page_dir_base_fault_replay_tex_f(v)       ((U32(v) & 0x1U) << 4U)
#define ram_in_page_dir_base_fault_replay_gcc_f(v)       ((U32(v) & 0x1U) << 5U)
#define ram_in_adr_limit_hi_f(v)                  ((U32(v) & 0xffffffffU) << 0U)
#define ram_fc_allowed_syncpoints_w()                                      (58U)
#define ram_fc_chid_w()                                                    (58U)
#define ram_fc_config_w()                                                  (61U)
```

(Word 58 is named both `allowed_syncpoints` and `chid` on GP10B.) RAMFC/USERD offsets are otherwise unchanged from Kepler/Maxwell: signature word 4 (0x10), USERD words 2/3, GP_BASE words 18/19, HCE_CTRL word 57 (0xE4) [NVIDIA-published (nvgpu)]. nouveau uses `gk104_chan_ramfc_write` for all Pascal (`gp100_fifo` -> `gm107_chan`) [nouveau].

## 2.5 Volta (GV100, GV11B)

Volta RAMIN/RAMFC/USERD are already verified in Keto from https://raw.githubusercontent.com/NVIDIA/open-gpu-doc/master/manuals/volta/gv100/dev_ram.ref.txt [NVIDIA-published]. Subcontext fields as published in `volta/gv100/dev_ram.h` (64 subcontext PDB slots at word 168 + 4i, i.e. byte 0x2A0 + 16i; valid mask at word 166 = 0x298) [NVIDIA-published], https://raw.githubusercontent.com/NVIDIA/open-gpu-kernel-modules/main/src/common/inc/swref/published/volta/gv100/dev_ram.h :

```c
#define NV_RAMIN_ENABLE_ATS                        (135*32+31):(135*32+31) /* RWXUF */
#define NV_RAMIN_PASID                 (135*32+(20-1)):(135*32+0) /* RWXUF */
#define NV_RAMIN_SC_PAGE_DIR_BASE_TARGET(i)             ((168+(i)*4)*32+1):((168+(i)*4)*32+0) /* RWXUF */
#define NV_RAMIN_SC_PAGE_DIR_BASE_TARGET__SIZE_1                         64 /*       */
#define NV_RAMIN_SC_PAGE_DIR_BASE_TARGET_VID_MEM                  0x00000000 /* RW--V */
#define NV_RAMIN_SC_PAGE_DIR_BASE_TARGET_INVALID                  0x00000001 /* RW--V */ // Note: INVALID should match PEER
#define NV_RAMIN_SC_PAGE_DIR_BASE_TARGET_SYS_MEM_COHERENT         0x00000002 /* RW--V */
#define NV_RAMIN_SC_PAGE_DIR_BASE_TARGET_SYS_MEM_NONCOHERENT      0x00000003 /* RW--V */
#define NV_RAMIN_SC_USE_VER2_PT_FORMAT(i)          ((168+(i)*4)*32+10):((168+(i)*4)*32+10) /* RWXUF */
#define NV_RAMIN_SC_BIG_PAGE_SIZE(i)                    ((168+(i)*4)*32+11):((168+(i)*4)*32+11) /* RWXUF */
#define NV_RAMIN_SC_PAGE_DIR_BASE_LO(i)                ((168+(i)*4)*32+31):((168+(i)*4)*32+12) /* RWXUF */
#define NV_RAMIN_SC_PAGE_DIR_BASE_HI(i)                 ((169+(i)*4)*32+31):((169+(i)*4)*32+0) /* RWXUF */
#define NV_RAMIN_SC_PDB_VALID(i)             (166*32+i):(166*32+i) /* RWXUF */
```

PBDMA encodings on Volta (signature value and class id, HCE priv bit, USERD address units, LIMIT2, and SET_CHANNEL_INFO with bits 31:16 *reserved*, i.e. no CHID) [NVIDIA-published], https://raw.githubusercontent.com/NVIDIA/open-gpu-doc/master/manuals/volta/gv100/dev_pbdma.ref.txt :

```c
#define NV_PPBDMA_GP_BASE_HI(i)               (0x0004004c+(i)*8192) /* RW-4A */
#define NV_PPBDMA_GP_BASE_HI_OFFSET                             7:0 /* RW-UF */
#define NV_PPBDMA_GP_BASE_HI_LIMIT2                           20:16 /* RW-UF */
#define NV_PPBDMA_SIGNATURE(i)                (0x00040010+(i)*8192) /* RW-4A */
#define NV_PPBDMA_SIGNATURE_HW                                 15:0 /* RW-UF */
#define NV_PPBDMA_SIGNATURE_HW_VALID                     0x0000face /* RW--V */
#define NV_PPBDMA_SIGNATURE_HW_HOST_CLASS_ID                 50031 /* RW--V */
#define NV_PPBDMA_SIGNATURE_SW                                31:16 /* RW-UF */
#define NV_PPBDMA_USERD(i)                    (0x00040008+(i)*8192) /* RW-4A */
#define NV_PPBDMA_USERD_TARGET                                  1:0 /* RW-UF */
#define NV_PPBDMA_USERD_ADDR            31:9 /* RW-UF */
#define NV_PPBDMA_USERD_HI(i)                 (0x0004000c+(i)*8192) /* RW-4A */
#define NV_PPBDMA_USERD_HI_ADDR                                 7:0 /* RW-UF */
#define NV_PPBDMA_SET_CHANNEL_INFO(i)             (0x000400fc+(i)*8192) /* RW-4A */
#define NV_PPBDMA_SET_CHANNEL_INFO_SCG_TYPE                         0:0 /*       */
#define NV_PPBDMA_SET_CHANNEL_INFO_VEID     ((6-1)+8):8 /*       */
#define NV_PPBDMA_SET_CHANNEL_INFO_RESERVED                        31:16 /*       */
#define NV_PPBDMA_HCE_CTRL(i)                 (0x000400e4+(i)*8192) /* RW-4A */
#define NV_PPBDMA_HCE_CTRL_HCE_PRIV_MODE                        5:5 /* RW-UF */
```

GV11B (Xavier) channel ID: nvgpu still defines RAMFC word 58 (0xE8) as CHID, and SET_CHANNEL_INFO at word 63 [NVIDIA-published (nvgpu)], https://raw.githubusercontent.com/OE4T/linux-nvgpu/patches-rel-36/drivers/gpu/nvgpu/include/nvgpu/hw/gv11b/hw_ram_gv11b.h :

```c
#define ram_in_page_dir_base_hi_f(v)              ((U32(v) & 0xffffffffU) << 0U)
#define ram_in_engine_wfi_veid_w()                                        (134U)
#define ram_fc_userd_w()                                                    (2U)
#define ram_fc_userd_hi_w()                                                 (3U)
#define ram_fc_chid_w()                                                    (58U)
#define ram_fc_chid_id_f(v)                            ((U32(v) & 0xfffU) << 0U)
#define ram_fc_config_w()                                                  (61U)
#define ram_fc_set_channel_info_w()                                        (63U)
#define ram_rl_entry_size_v()                                      (0x00000010U)
```

nouveau's Volta/Turing RAMFC writer (USERD at 0x08/0x0C, signature, CHID at 0xE8, CONFIG 0xF4) [nouveau], https://raw.githubusercontent.com/torvalds/linux/master/drivers/gpu/drm/nouveau/nvkm/engine/fifo/gv100.c :

```c
gv100_chan_ramfc_write(struct nvkm_chan *chan, u64 offset, u64 length, u32 devm, bool priv)
{
	const u64 userd = nvkm_memory_addr(chan->userd.mem) + chan->userd.base;
	const u32 limit2 = ilog2(length / 8);

	nvkm_kmap(chan->inst);
	nvkm_wo32(chan->inst, 0x008, lower_32_bits(userd));
	nvkm_wo32(chan->inst, 0x00c, upper_32_bits(userd));
	nvkm_wo32(chan->inst, 0x010, 0x0000face);
	nvkm_wo32(chan->inst, 0x030, 0x7ffff902);
	nvkm_wo32(chan->inst, 0x048, lower_32_bits(offset));
	nvkm_wo32(chan->inst, 0x04c, upper_32_bits(offset) | (limit2 << 16));
	nvkm_wo32(chan->inst, 0x084, 0x20400000);
	nvkm_wo32(chan->inst, 0x094, 0x30000000 | devm);
	nvkm_wo32(chan->inst, 0x0e4, priv ? 0x00000020 : 0x00000000);
	nvkm_wo32(chan->inst, 0x0e8, chan->id);
	nvkm_wo32(chan->inst, 0x0f4, 0x00001000 | (priv ? 0x00000100 : 0x00000000));
	nvkm_wo32(chan->inst, 0x0f8, 0x10003080);
	nvkm_mo32(chan->inst, 0x218, 0x00000000, 0x00000000);
	nvkm_done(chan->inst);
	return 0;
}
```

## 2.6 Turing (TU102, TU104, TU106, TU116, TU117)

The TU104 manual's RAMIN/RAMFC/USERD definitions are identical to GV100 apart from reserved words (`NV_RAMFC_RESERVED26` removed, `NV_RAMFC_RESERVED62` added) [NVIDIA-published, compared by diff], https://raw.githubusercontent.com/NVIDIA/open-gpu-doc/master/manuals/turing/tu104/dev_ram.ref.txt . Key lines:

```c
#define NV_RAMFC_GP_PUT                          (0*32+31):(0*32+0) /* RWXUF */
#define NV_RAMFC_USERD                           (2*32+31):(2*32+0) /* RWXUF */
#define NV_RAMFC_USERD_HI                        (3*32+31):(3*32+0) /* RWXUF */
#define NV_RAMFC_SIGNATURE                       (4*32+31):(4*32+0) /* RWXUF */
#define NV_RAMFC_GP_GET                          (5*32+31):(5*32+0) /* RWXUF */
#define NV_RAMFC_GP_BASE                       (18*32+31):(18*32+0) /* RWXUF */
#define NV_RAMFC_GP_BASE_HI                    (19*32+31):(19*32+0) /* RWXUF */
#define NV_RAMFC_HCE_CTRL                      (57*32+31):(57*32+0) /* RWXUF */
#define NV_RAMFC_CONFIG                        (61*32+31):(61*32+0) /* RWXUF */
#define NV_RAMFC_SET_CHANNEL_INFO              (63*32+31):(63*32+0) /* RWXUF */
```

Turing adds a channel ID field to SET_CHANNEL_INFO [NVIDIA-published], https://raw.githubusercontent.com/NVIDIA/open-gpu-kernel-modules/main/src/common/inc/swref/published/turing/tu102/dev_pbdma.h :

```c
#define NV_PPBDMA_SET_CHANNEL_INFO_VEID     ((6-1)+8):8 /*       */
#define NV_PPBDMA_SET_CHANNEL_INFO_CHID      (12+15):16 /*       */
```

The RM writes the CHID there (Turing; same code for GA100..GH100 in `kfifoInitRamfcChid_GA100`) [NVIDIA-published (RM code)], https://raw.githubusercontent.com/NVIDIA/open-gpu-kernel-modules/main/src/nvidia/src/kernel/gpu/fifo/arch/turing/kernel_fifo_tu102.c :

```c
kfifoInitRamfcChid_TU102
(
    OBJGPU           *pGpu,
    KernelFifo       *pKernelFifo,
    KernelChannel    *pKernelChannel,
    NvU8             *pInstMem
)
{
    NvU32          chId;
    NvU32          data;

    NV_ASSERT_OR_RETURN(pKernelChannel != NULL, NV_ERR_INVALID_CHANNEL);

    chId = pKernelChannel->ChID;

    NV_ASSERT(!gpumgrGetBcEnabledStatus(pGpu));

    data = MEM_RD32(pInstMem + SF_OFFSET(NV_RAMFC_SET_CHANNEL_INFO));
    data = FLD_SET_DRF_NUM(_PPBDMA, _SET_CHANNEL_INFO, _CHID, chId, data);
    MEM_WR32(pInstMem + SF_OFFSET(NV_RAMFC_SET_CHANNEL_INFO), data);

    return NV_OK;
}
kfifoInitRamfcSignature_TU102
(
    OBJGPU     *pGpu,
    KernelFifo *pKernelFifo,
    NvU8       *pInstMem
)
{
    MEM_WR32( pInstMem + SF_OFFSET( NV_RAMFC_SIGNATURE ),
              DRF_DEF( _PBDMA, _SIGNATURE, _HW, _VALID ) |
              DRF_DEF( _PBDMA, _SIGNATURE, _SW, _ZERO  ) );
}
```

So on Turing..Hopper, CHID = RAMFC 0xFC bits 27:16 and VEID = bits 13:8 [derived]. nouveau additionally writes the CHID to 0xE8 on Volta, Turing and Ampere (2.5, 2.7) [nouveau].

## 2.7 Ampere and Ada (GA100, GA102, GA103, GA104, GA106, GA107, GA10B, AD102..AD107)

The GA100 manual removes USERD from RAMFC (words 2/3 become `RESERVED2/3`; USERD is now only referenced from the runlist entry) and repurposes words 48+ as METHOD/DATA pairs [NVIDIA-published], https://raw.githubusercontent.com/NVIDIA/open-gpu-doc/master/manuals/ampere/ga100/dev_ram.ref.txt :

```c
#define NV_RAMFC_GP_PUT                          (0*32+31):(0*32+0) /* RW-UF */
#define NV_RAMFC_MEM_OP_A                        (1*32+31):(1*32+0) /* RW-UF */
#define NV_RAMFC_RESERVED2                       (2*32+31):(2*32+0) /* RW-UF */
#define NV_RAMFC_RESERVED3                       (3*32+31):(3*32+0) /* RW-UF */
#define NV_RAMFC_SIGNATURE                       (4*32+31):(4*32+0) /* RW-UF */
#define NV_RAMFC_GP_GET                          (5*32+31):(5*32+0) /* RW-UF */
#define NV_RAMFC_GP_BASE                       (18*32+31):(18*32+0) /* RW-UF */
#define NV_RAMFC_GP_BASE_HI                    (19*32+31):(19*32+0) /* RW-UF */
#define NV_RAMFC_TARGET                        (43*32+31):(43*32+0) /* RW-UF */
#define NV_RAMFC_RESERVED44                    (44*32+31):(44*32+0) /* RW-UF */
#define NV_RAMFC_METHOD(i)                     ((48+(i)*2)*32+31):((48+(i)*2)*32+0) /* RW-UF */
#define NV_RAMFC_DATA(i)                       ((49+(i)*2)*32+31):((49+(i)*2)*32+0) /* RW-UF */
#define NV_RAMFC_HCE_CTRL                      (57*32+31):(57*32+0) /* RW-UF */
#define NV_RAMFC_CONFIG                        (61*32+31):(61*32+0) /* RW-UF */
#define NV_RAMFC_SET_CHANNEL_INFO              (63*32+31):(63*32+0) /* RW-UF */
```

Ampere RAMIN (no `ADR_LIMIT`; `PAGE_DIR_BASE_TARGET_INVALID` = 1; ENGINE_WFI_VEID at word 134 = 0x218) [NVIDIA-published], same URL:

```c
#define NV_RAMIN_PAGE_DIR_BASE_TARGET               (128*32+1):(128*32+0) /* RWXUF */
#define NV_RAMIN_PAGE_DIR_BASE_VOL                  (128*32+2):(128*32+2) /* RWXUF */
#define NV_RAMIN_USE_VER2_PT_FORMAT             (128*32+10):(128*32+10) /*       */
#define NV_RAMIN_BIG_PAGE_SIZE                    (128*32+11):(128*32+11) /* RWXUF */
#define NV_RAMIN_PAGE_DIR_BASE_LO                 (128*32+31):(128*32+12) /* RWXUF */
#define NV_RAMIN_PAGE_DIR_BASE_HI                  (129*32+31):(129*32+0) /* RWXUF */
#define NV_RAMIN_ENGINE_WFI_VEID             (134*32+(6-1)):(134*32+0) /*       */
#define NV_RAMIN_PASID                 (135*32+(20-1)):(135*32+0) /* RWXUF */
#define NV_RAMIN_ENG_METHOD_BUFFER_ADDR_LO                   (136*32+31):(136*32+0)  /* RWXUF */
#define NV_RAMIN_ENG_METHOD_BUFFER_ADDR_HI                   (137*32+(((49-1)-32))):(137*32+0)  /* RWXUF */
```

Of the chips the open RM supports, it writes `ADR_LIMIT` only on Turing (`kgmmuInstBlkVaLimitGet_GV100` -> `_GP100`); for Ampere and later `kgmmuInstBlkVaLimitGet` is a stub returning offset 0 [NVIDIA-published (RM code)], https://raw.githubusercontent.com/NVIDIA/open-gpu-kernel-modules/main/src/nvidia/generated/g_kern_gmmu_nvoc.c :

```c
    // kgmmuInstBlkVaLimitGet -- halified (2 hals) body
    if (( ((chipHal_HalVarIdx >> 5) == 1UL) && ((1UL << (chipHal_HalVarIdx & 0x1f)) & 0x000003e0UL) )) /* ChipHal: TU102 | TU104 | TU106 | TU116 | TU117 */
    {
        pThis->__kgmmuInstBlkVaLimitGet__ = &kgmmuInstBlkVaLimitGet_GV100;
    }
    else
    {
        pThis->__kgmmuInstBlkVaLimitGet__ = &kgmmuInstBlkVaLimitGet_f03539;
```

Ampere PBDMA (class id 50543 = 0xC56F, CHID in SET_CHANNEL_INFO) [NVIDIA-published], https://raw.githubusercontent.com/NVIDIA/open-gpu-doc/master/manuals/ampere/ga100/dev_pbdma.ref.txt :

```c
#define NV_PPBDMA_GP_BASE_HI_LIMIT2                           20:16 /* RWXUF */
#define NV_PPBDMA_SIGNATURE_HW_VALID                     0x0000face /* RW--V */
#define NV_PPBDMA_SIGNATURE_HW_HOST_CLASS_ID                 50543 /* RW--V */
#define NV_PPBDMA_SET_CHANNEL_INFO_VEID     ((6-1)+8):8 /*       */
#define NV_PPBDMA_SET_CHANNEL_INFO_CHID                       27:16 /*       */
#define NV_PPBDMA_SET_CHANNEL_INFO_RESERVED                    31:27 /*       */
#define NV_PPBDMA_HCE_CTRL_HCE_PRIV_MODE                        5:5 /* RWXUF */
```

Published deltas [NVIDIA-published]: https://raw.githubusercontent.com/NVIDIA/open-gpu-kernel-modules/main/src/common/inc/swref/published/ampere/ga100/dev_ram.h , https://raw.githubusercontent.com/NVIDIA/open-gpu-kernel-modules/main/src/common/inc/swref/published/ampere/ga10b/dev_ram.h , https://raw.githubusercontent.com/NVIDIA/open-gpu-kernel-modules/main/src/common/inc/swref/published/ada/ad102/dev_ram.h

```c
#define NV_RAMUSERD_GP_GET                     (34*32+31):(34*32+0) /* RW-UF */
#define NV_RAMUSERD_GP_PUT                     (35*32+31):(35*32+0) /* RW-UF */
#define NV_RAMFC_INTR_NOTIFY                   (62*32+31):(62*32+0) /* RW-UF */
#define NV_RAMFC_SET_CHANNEL_INFO              (63*32+31):(63*32+0) /* RW-UF */
#define NV_RAMIN_ENGINE_WFI_VEID             (134*32+(6-1)):(134*32+0) /*       */
#define NV_RAMIN_ENGINE_CTXSW_FW_MAGIC_VALUE        (131*32+31):(131*32+0) /* RWXUF */
#define NV_RAMIN_ENGINE_CTXSW_FW_MAGIC_VALUE_V                  0xcafeca11 /* RW--V */
#define NV_RAMFC_SET_CHANNEL_INFO              (63*32+31):(63*32+0) /* RW-UF */
```

GA10B (Orin) instance blocks carry the magic `0xcafeca11` at RAMIN word 131 (byte 0x20C) [NVIDIA-published]; the RM writes it through `kgmmuInstBlkMagicValueGet_GA10B` (2.9 shows it is also used for Blackwell/Rubin) [NVIDIA-published (RM code)], https://raw.githubusercontent.com/NVIDIA/open-gpu-kernel-modules/main/src/nvidia/src/kernel/gpu/mmu/arch/ampere/kern_gmmu_ga10b.c :

```c
    *pOffset = SF_OFFSET(NV_RAMIN_ENGINE_CTXSW_FW_MAGIC_VALUE);
    *pData   = NV_RAMIN_ENGINE_CTXSW_FW_MAGIC_VALUE_V;
```

GA10B nvgpu header (no `ram_fc_userd`, 16-byte runlist entries) [NVIDIA-published (nvgpu)], https://raw.githubusercontent.com/OE4T/linux-nvgpu/patches-rel-36/drivers/gpu/nvgpu/include/nvgpu/hw/ga10b/hw_ram_ga10b.h :

```c
#define ram_fc_size_val_v()                                        (0x00000200U)
#define ram_fc_signature_w()                                                (4U)
#define ram_fc_gp_base_w()                                                 (18U)
#define ram_fc_gp_base_hi_w()                                              (19U)
#define ram_fc_hce_ctrl_w()                                                (57U)
#define ram_fc_set_channel_info_w()                                        (63U)
```

nouveau's Ampere RAMFC writer (no USERD; CHID still also written at 0xE8; 0xF8 = interrupt notify) [nouveau], https://raw.githubusercontent.com/torvalds/linux/master/drivers/gpu/drm/nouveau/nvkm/engine/fifo/ga100.c :

```c
ga100_chan_ramfc_write(struct nvkm_chan *chan, u64 offset, u64 length, u32 devm, bool priv)
{
	const u32 limit2 = ilog2(length / 8);

	nvkm_kmap(chan->inst);
	nvkm_wo32(chan->inst, 0x010, 0x0000face);
	nvkm_wo32(chan->inst, 0x030, 0x7ffff902);
	nvkm_wo32(chan->inst, 0x048, lower_32_bits(offset));
	nvkm_wo32(chan->inst, 0x04c, upper_32_bits(offset) | (limit2 << 16));
	nvkm_wo32(chan->inst, 0x084, 0x20400000);
	nvkm_wo32(chan->inst, 0x094, 0x30000000 | devm);
	nvkm_wo32(chan->inst, 0x0e4, priv ? 0x00000020 : 0x00000000);
	nvkm_wo32(chan->inst, 0x0e8, chan->id);
	nvkm_wo32(chan->inst, 0x0f4, 0x00001000 | (priv ? 0x00000100 : 0x00000000));
	nvkm_wo32(chan->inst, 0x0f8, 0x80000000 | chan->cgrp->runl->nonstall.vector);
	nvkm_mo32(chan->inst, 0x218, 0x00000000, 0x00000000);
	nvkm_done(chan->inst);
	return 0;
}
```

## 2.8 Hopper (GH100)

Published `dev_ram.h` deltas: GPFIFO LIMIT2 moves to `NV_RAMFC_GP_INFO` (word 41 = 0xA4); ENGINE_WFI_PTR_HI and ENG_METHOD_BUFFER_ADDR_HI widen for 57-bit VAs; runlist USERD_PTR_HI_HW widens to 20 bits [NVIDIA-published], https://raw.githubusercontent.com/NVIDIA/open-gpu-kernel-modules/main/src/common/inc/swref/published/hopper/gh100/dev_ram.h :

```c
#define NV_RAMRL_ENTRY_CHAN_USERD_PTR_LO      (31+0*32):(8+0*32) /* RWXUF */
#define NV_RAMRL_ENTRY_CHAN_USERD_PTR_HI_HW   (19+1*32):(0+1*32) /* RWXUF */
#define NV_RAMFC                                                    /* ----G */
#define NV_RAMFC_GP_BASE                         (18*32+31):(18*32+0) /* RW-UF */
#define NV_RAMFC_GP_BASE_HI                      (19*32+31):(19*32+0) /* RW-UF */
#define NV_RAMFC_GP_INFO                         (41*32+31):(41*32+0) /* RW-UF */
#define NV_RAMFC_GP_PUT                          (0*32+31):(0*32+0) /* RW-UF */
#define NV_RAMFC_GP_GET                          (5*32+31):(5*32+0) /* RW-UF */
#define NV_RAMIN_ENGINE_CS                       (132*32+3):(132*32+3) /*       */
#define NV_RAMIN_ENGINE_CS_WFI                              0x00000000 /*       */
#define NV_RAMIN_ENGINE_CS_FG                               0x00000001 /*       */
#define NV_RAMIN_ENGINE_WFI_TARGET               (132*32+1):(132*32+0) /*       */
#define NV_RAMIN_ENGINE_WFI_TARGET_LOCAL_MEM                0x00000000 /*       */
#define NV_RAMIN_ENGINE_WFI_TARGET_SYS_MEM_COHERENT         0x00000002 /*       */
#define NV_RAMIN_ENGINE_WFI_TARGET_SYS_MEM_NONCOHERENT      0x00000003 /*       */
#define NV_RAMIN_ENGINE_WFI_MODE                 (132*32+2):(132*32+2) /*       */
#define NV_RAMIN_ENGINE_WFI_MODE_PHYSICAL                   0x00000000 /*       */
#define NV_RAMIN_ENGINE_WFI_MODE_VIRTUAL                    0x00000001 /*       */
#define NV_RAMIN_ENGINE_WFI_PTR_LO               (132*32+31):(132*32+12) /*       */
#define NV_RAMIN_ENGINE_WFI_PTR_HI               (133*32+25):(133*32+0) /*       */
#define NV_RAMIN_ENGINE_WFI_VEID             (134*32+(6-1)):(134*32+0) /*       */
#define NV_RAMIN_ENG_METHOD_BUFFER_ADDR_LO       (136*32+31):(136*32+0)  /* RWXUF */
#define NV_RAMIN_ENG_METHOD_BUFFER_ADDR_HI       (137*32+(((57-1)-32))):(137*32+0)  /* RWXUF */
#define NV_RAMFC_INTR_NOTIFY_CTRL              (62*32+31):(62*32+0) /* RW-UF */
```

```c
#define NV_PBDMA_GP_BASE_HI                                  0x04c /* RW-4R */
#define NV_PBDMA_GP_BASE_HI_OFFSET                            24:0 /* RWXUF */
#define NV_PBDMA_GP_INFO                                     0x0a4 /* RW-4R */
#define NV_PBDMA_GP_INFO_PB_SEGMENT_EXTENDED_BASE             24:8 /* RWXUF */
#define NV_PBDMA_GP_INFO_LIMIT2                                4:0 /* RWXUF */
```
(https://raw.githubusercontent.com/NVIDIA/open-gpu-kernel-modules/main/src/common/inc/swref/published/hopper/gh100/dev_esched_pbdma.h)

RM GPFIFO writer for GH100 [NVIDIA-published (RM code)], https://raw.githubusercontent.com/NVIDIA/open-gpu-kernel-modules/main/src/nvidia/src/kernel/gpu/fifo/arch/hopper/kernel_fifo_gh100.c :

```c
kfifoWriteRamfcGpfifo_GH100
(
    OBJGPU        *pGpu,
    KernelFifo    *pKernelFifo,
    NvU8          *pInstMem,
    NvU64         gpFifoOffset,
    NvU32         gpFifoEntries
)
{
    // GPBASE
    NV_ASSERT(FLD_TEST_DRF(_PBDMA, _GP_BASE, _RSVD, _ZERO, NvU64_LO32(gpFifoOffset)));
    MEM_WR32(pInstMem + SF_OFFSET(NV_RAMFC_GP_BASE), NvU64_LO32(gpFifoOffset));

    MEM_WR32(pInstMem + SF_OFFSET(NV_RAMFC_GP_BASE_HI),
                 DRF_NUM(_PBDMA, _GP_BASE_HI, _OFFSET, NvU64_HI32(gpFifoOffset)));

    MEM_WR32(pInstMem + SF_OFFSET(NV_RAMFC_GP_INFO),
             DRF_NUM(_PBDMA, _GP_INFO, _LIMIT2, nvLogBase2(gpFifoEntries) |
             DRF_NUM(_PBDMA, _GP_INFO, _PB_SEGMENT_EXTENDED_BASE, 0)));

    MEM_WR32(pInstMem + SF_OFFSET(NV_RAMFC_GP_PUT), 0);
    MEM_WR32(pInstMem + SF_OFFSET(NV_RAMFC_GP_GET), 0);
}
```

For comparison, Turing..Ada use the GM107 writer (LIMIT2 in GP_BASE_HI 20:16) [NVIDIA-published (RM code)], https://raw.githubusercontent.com/NVIDIA/open-gpu-kernel-modules/main/src/nvidia/src/kernel/gpu/fifo/arch/maxwell/kernel_fifo_gm107.c :

```c
kfifoWriteRamfcGpfifo_GM107
(
    OBJGPU        *pGpu,
    KernelFifo    *pKernelFifo,
    NvU8          *pInstMem,
    NvU64         gpFifoOffset,
    NvU32         gpFifoEntries
)
{
    // GPBASE
    NV_ASSERT(FLD_TEST_DRF(_PBDMA, _GP_BASE, _RSVD, _ZERO, NvU64_LO32(gpFifoOffset)));
    MEM_WR32( pInstMem + SF_OFFSET( NV_RAMFC_GP_BASE ), NvU64_LO32( gpFifoOffset ) );

    MEM_WR32( pInstMem + SF_OFFSET( NV_RAMFC_GP_BASE_HI ),
              DRF_NUM( _PBDMA, _GP_BASE_HI, _OFFSET, NvU64_HI32( gpFifoOffset ) ) |
              DRF_NUM( _PBDMA, _GP_BASE_HI, _LIMIT2, nvLogBase2( gpFifoEntries ) ) );

    MEM_WR32( pInstMem + SF_OFFSET( NV_RAMFC_GP_PUT), 0 );
    MEM_WR32( pInstMem + SF_OFFSET( NV_RAMFC_GP_GET), 0 );
}
```

GH100 keeps the Turing offsets for SIGNATURE (0x10), PB_HEADER, HCE_CTRL (0xE4), CONFIG (0xF4) and SET_CHANNEL_INFO/CHID (0xFC): the HAL binds GH100 to the `_TU102`/`_GA100` RAMFC functions (2.9 table) [NVIDIA-published (RM code)].

## 2.9 Blackwell (GB100, GB102, GB110, GB112, GB10B, GB10C, GB202..GB207, GB20B, GB20C) and Rubin (GR100, GR102)

**RAMFC is rearranged on Blackwell.** `blackwell/gb100/dev_ram.h` [NVIDIA-published], https://raw.githubusercontent.com/NVIDIA/open-gpu-kernel-modules/main/src/common/inc/swref/published/blackwell/gb100/dev_ram.h :

```c
#define NV_RAMFC                                                    /* ----G */
#define NV_RAMFC_PB_SEGMENT_EXTENDED_BASE        (23*32+31):(23*32+0) /* RW-UF */
#define NV_RAMFC_GP_BASE                         (36*32+31):(36*32+0) /* RW-UF */
#define NV_RAMFC_GP_BASE_HI                      (37*32+31):(37*32+0) /* RW-UF */
#define NV_RAMFC_GP_GET                          (38*32+31):(38*32+0) /* RW-UF */
#define NV_RAMFC_MISC_FETCH_STATE                (45*32+31):(45*32+0) /* RW-UF */
#define NV_RAMFC_DEBUG_STATE(i)        (((i)+48)*32+31):(((i)+48)*32+0) /* RW-UF */
#define NV_RAMFC_DEBUG_STATE__SIZE_1   4 /*       */
#define NV_RAMFC_DEBUG_STATE_RAMFC_INDEX_gp_put                         0x00000000 /*       */
#define NV_RAMFC_DEBUG_STATE_RAMFC_INDEX_gp_peek                        0x00000001 /*       */
#define NV_RAMFC_DEBUG_STATE_RAMFC_INDEX_gp_fetch                       0x00000002 /*       */
#define NV_RAMFC_DEBUG_STATE_RAMFC_INDEX_hdr_shadow                     0x00000003 /*       */
#define NV_RAMFC_SIGNATURE                                              (14*32+31):(14*32+0) /* RW-UF */
#define NV_RAMFC_PB_HEADER                       (8*32+31):(8*32+0) /* RW-UF */
#define NV_RAMFC_HCE_CTRL                        (21*32+31):(21*32+0) /* RW-UF */
#define NV_RAMFC_MISC_EXECUTE_STATE              (20*32+31):(20*32+0) /* RW-UF */
#define NV_RAMFC_INTR_NOTIFY_CTRL                (19*32+31):(19*32+0) /* RW-UF */
#define NV_RAMFC_SET_CHANNEL_INFO                (22*32+31):(22*32+0) /* RW-UF */
#define NV_RAMIN_ENGINE_WFI_VEID             (134*32+(6-1)):(134*32+0) /*       */
#define NV_RAMFC_SUBDEVICE                       (15*32+31):(15*32+0) /* RW-UF */
#define NV_RAMUSERD_GP_PUT                     (35*32+31):(35*32+0) /* RW-UF */
```

Matching PBDMA field encodings [NVIDIA-published], https://raw.githubusercontent.com/NVIDIA/open-gpu-kernel-modules/main/src/common/inc/swref/published/blackwell/gb100/dev_esched_pbdma.h :

```c
#define NV_PBDMA_GP_BASE                                     0x090 /* RW-4R */
#define NV_PBDMA_GP_BASE_HI                                  0x094 /* RW-4R */
#define NV_PBDMA_GP_BASE_HI_OFFSET                            24:0 /* RWXUF */
#define NV_PBDMA_MISC_FETCH_STATE                            0x0b4 /* RW-4R */
#define NV_PBDMA_MISC_FETCH_STATE_GP_INFO_LIMIT2                      28:24 /* RWXUF */
#define NV_PBDMA_SIGNATURE                                   0x038 /* RW-4R */
#define NV_PBDMA_SIGNATURE_HW                                 15:0 /* RWXUF */
#define NV_PBDMA_SIGNATURE_HW_VALID                     0x0000face /* RW--V */
#define NV_PBDMA_SIGNATURE_HW_HOST_CLASS_ID                 51567 /* RW--V */
#define NV_PBDMA_SIGNATURE_SW                                31:16 /* RWXUF */
#define NV_PBDMA_SIGNATURE_SW_ZERO                      0x00000000 /* RW--V */
#define NV_PBDMA_PB_HEADER                                   0x420 /* RW-4R */
#define NV_PBDMA_HCE_CTRL                                    0x054 /* RW-4R */
#define NV_PBDMA_HCE_CTRL_HCE_PRIV_MODE                        5:5 /* RWXUF */
#define NV_PBDMA_HCE_CTRL_HCE_PRIV_MODE_NO              0x00000000 /* RW--V */
#define NV_PBDMA_HCE_CTRL_HCE_PRIV_MODE_YES             0x00000001 /* RW--V */
#define NV_PBDMA_SET_CHANNEL_INFO_VEID                       13:8 /* RWXUF */
#define NV_PBDMA_SET_CHANNEL_INFO_CHID                       27:16 /* R--VF */
```

RM code that fills these fields [NVIDIA-published (RM code)], https://raw.githubusercontent.com/NVIDIA/open-gpu-kernel-modules/main/src/nvidia/src/kernel/gpu/fifo/arch/blackwell/kernel_fifo_gb100.c :

```c
kfifoWriteRamfcGpfifo_GB100
(
    OBJGPU        *pGpu,
    KernelFifo    *pKernelFifo,
    NvU8          *pInstMem,
    NvU64         gpFifoOffset,
    NvU32         gpFifoEntries
)
{
    NvU32   fetchState;

    // GPBASE
    NV_ASSERT(FLD_TEST_DRF(_PBDMA, _GP_BASE, _RSVD, _ZERO, NvU64_LO32(gpFifoOffset)));
    MEM_WR32(pInstMem + SF_OFFSET(NV_RAMFC_GP_BASE), NvU64_LO32(gpFifoOffset));

    MEM_WR32(pInstMem + SF_OFFSET(NV_RAMFC_GP_BASE_HI),
             DRF_NUM(_PBDMA, _GP_BASE_HI, _OFFSET, NvU64_HI32(gpFifoOffset)));

    // Checking LIMIT2 width is sufficient to store nvLogBase2(gpFifoEntries)
    NV_ASSERT_OR_RETURN_VOID((nvLogBase2(gpFifoEntries) &
                DRF_MASK(NV_PBDMA_MISC_FETCH_STATE_GP_INFO_LIMIT2)) == nvLogBase2(gpFifoEntries));

    fetchState = MEM_RD32(pInstMem + SF_OFFSET(NV_RAMFC_MISC_FETCH_STATE));
    fetchState = FLD_SET_DRF_NUM(_PBDMA, _MISC_FETCH_STATE, _GP_INFO_LIMIT2, nvLogBase2(gpFifoEntries), fetchState);
    MEM_WR32(pInstMem + SF_OFFSET(NV_RAMFC_MISC_FETCH_STATE), fetchState);

    MEM_WR32(pInstMem + SF_OFFSET(NV_RAMFC_PB_SEGMENT_EXTENDED_BASE),
             DRF_NUM(_PBDMA, _PB_SEGMENT_EXTENDED_BASE, _VALUE, 0));

    // Assuming RAMFC debug state is enabled
    MEM_WR32(pInstMem + SF_OFFSET(NV_RAMFC_DEBUG_STATE(NV_RAMFC_DEBUG_STATE_RAMFC_INDEX_gp_put)), 0);
    MEM_WR32(pInstMem + SF_OFFSET(NV_RAMFC_GP_GET), 0);
}
kfifoInitRamfcSignature_GB100
(
    OBJGPU     *pGpu,
    KernelFifo *pKernelFifo,
    NvU8       *pInstMem
)
{
    MEM_WR32( pInstMem + SF_OFFSET( NV_RAMFC_SIGNATURE ),
              DRF_DEF( _PBDMA, _SIGNATURE, _HW, _VALID ) |
              DRF_DEF( _PBDMA, _SIGNATURE, _SW, _ZERO  ) );
}
void kfifoInitHceRamfcState_GB100
(
    OBJGPU        *pGpu,
    KernelFifo    *pKernelFifo,
    KernelChannel *pKernelChannel,
    NvU8          *pInstMem
)
{
    if (pKernelChannel->bHcePrivMode)
        MEM_WR32(pInstMem + SF_OFFSET(NV_RAMFC_HCE_CTRL),
                  DRF_DEF(_PBDMA, _HCE_CTRL, _HCE_PRIV_MODE, _YES));
    else
        MEM_WR32(pInstMem + SF_OFFSET(NV_RAMFC_HCE_CTRL),
                  DRF_DEF(_PBDMA, _HCE_CTRL, _HCE_PRIV_MODE, _NO));
}
```

Which chips use which RAMFC writer (generated HAL bindings; the `else` branch covers every chip not listed, i.e. GB1xx, GB2xx and GR1xx) [NVIDIA-published (RM code)], https://raw.githubusercontent.com/NVIDIA/open-gpu-kernel-modules/main/src/nvidia/generated/g_kernel_fifo_nvoc.c :

```c
    // kfifoWriteRamfcGpfifo -- halified (4 hals) body
    if (( ((chipHal_HalVarIdx >> 5) == 1UL) && ((1UL << (chipHal_HalVarIdx & 0x1f)) & 0x04000000UL) )) /* ChipHal: GH100 */
    {
        pThis->__kfifoWriteRamfcGpfifo__ = &kfifoWriteRamfcGpfifo_GH100;
    }
    else if (( ((chipHal_HalVarIdx >> 5) == 3UL) && ((1UL << (chipHal_HalVarIdx & 0x1f)) & 0x0000e000UL) )) /* ChipHal: T234D | T238D | T264D */
    {
        pThis->__kfifoWriteRamfcGpfifo__ = &kfifoWriteRamfcGpfifo_d44104;
    }
    else if (( ((chipHal_HalVarIdx >> 5) == 1UL) && ((1UL << (chipHal_HalVarIdx & 0x1f)) & 0x01f0ffe0UL) )) /* ChipHal: TU102 | TU104 | TU106 | TU116 | TU117 | GA100 | GA102 | GA103 | GA104 | GA106 | GA107 | AD102 | AD103 | AD104 | AD106 | AD107 */
    {
        pThis->__kfifoWriteRamfcGpfifo__ = &kfifoWriteRamfcGpfifo_GM107;
    }
    else
    {
        pThis->__kfifoWriteRamfcGpfifo__ = &kfifoWriteRamfcGpfifo_GB100;
    // kfifoInitRamfcSignature -- halified (3 hals) body
    if (( ((chipHal_HalVarIdx >> 5) == 3UL) && ((1UL << (chipHal_HalVarIdx & 0x1f)) & 0x0000e000UL) )) /* ChipHal: T234D | T238D | T264D */
    {
        // NVOC_UNREACHABLE, NULL-initialized.
    }
    else if (( ((chipHal_HalVarIdx >> 5) == 1UL) && ((1UL << (chipHal_HalVarIdx & 0x1f)) & 0x05f0ffe0UL) )) /* ChipHal: TU102 | TU104 | TU106 | TU116 | TU117 | GA100 | GA102 | GA103 | GA104 | GA106 | GA107 | AD102 | AD103 | AD104 | AD106 | AD107 | GH100 */
    {
        pThis->__kfifoInitRamfcSignature__ = &kfifoInitRamfcSignature_TU102;
    }
    else
    {
        pThis->__kfifoInitRamfcSignature__ = &kfifoInitRamfcSignature_GB100;
    // kfifoInitRamfcChid -- halified (5 hals) body
    if (( ((chipHal_HalVarIdx >> 5) == 3UL) && ((1UL << (chipHal_HalVarIdx & 0x1f)) & 0x0000e000UL) )) /* ChipHal: T234D | T238D | T264D */
    {
        // NVOC_UNREACHABLE, NULL-initialized.
    }
    else if (( ((chipHal_HalVarIdx >> 5) == 1UL) && ((1UL << (chipHal_HalVarIdx & 0x1f)) & 0x000003e0UL) )) /* ChipHal: TU102 | TU104 | TU106 | TU116 | TU117 */
    {
        pThis->__kfifoInitRamfcChid__ = &kfifoInitRamfcChid_TU102;
    }
    else if (( ((chipHal_HalVarIdx >> 5) == 2UL) && ((1UL << (chipHal_HalVarIdx & 0x1f)) & 0x000000feUL) )) /* ChipHal: GB202 | GB203 | GB205 | GB206 | GB207 | GB20B | GB20C */
    {
        pThis->__kfifoInitRamfcChid__ = &kfifoInitRamfcChid_ac1694;
    }
    else if (( ((chipHal_HalVarIdx >> 5) == 1UL) && ((1UL << (chipHal_HalVarIdx & 0x1f)) & 0x05f0fc00UL) )) /* ChipHal: GA100 | GA102 | GA103 | GA104 | GA106 | GA107 | AD102 | AD103 | AD104 | AD106 | AD107 | GH100 */
    {
        pThis->__kfifoInitRamfcChid__ = &kfifoInitRamfcChid_GA100;
    }
    else
    {
        pThis->__kfifoInitRamfcChid__ = &kfifoInitRamfcChid_GB100;
```

`kfifoInitRamfcChid_ac1694` (GB20x) is an inline no-op that returns `NV_OK` (https://raw.githubusercontent.com/NVIDIA/open-gpu-kernel-modules/main/src/nvidia/generated/g_kernel_fifo_nvoc.h), so the RM does not store the CHID in RAMFC on GB20x [NVIDIA-published (RM code)]. `kfifoInitRamfcSubctx_GB202` likewise only sets `NV_RAMIN_ENGINE_WFI_VEID` (no SET_CHANNEL_INFO write) [NVIDIA-published (RM code)], https://raw.githubusercontent.com/NVIDIA/open-gpu-kernel-modules/main/src/nvidia/src/kernel/gpu/fifo/arch/blackwell/kernel_fifo_gb202.c .

GB202 / GB10B published deltas [NVIDIA-published], https://raw.githubusercontent.com/NVIDIA/open-gpu-kernel-modules/main/src/common/inc/swref/published/blackwell/gb202/dev_ram.h , https://raw.githubusercontent.com/NVIDIA/open-gpu-kernel-modules/main/src/common/inc/swref/published/blackwell/gb10b/dev_ram.h :

```c
#define NV_RAMIN_ENGINE_TOTAL_NUM_TPCS           (130*32+31):(130*32+0) /* RWXUF */
#define NV_RAMRL_ENTRY_CHAN_RUNQUEUE_SELECTOR_RUNQUEUE1         0x00000001 /*       */
#define NV_RAMFC                                                    /* ----G */
#define NV_RAMRL_ENTRY_BASE_SHIFT                8 /*       */
#define NV_RAMFC_MISC_EXECUTE_STATE              (20*32+31):(20*32+0) /* RW-UF */
#define NV_RAMIN_ENGINE_WFI_VEID             (134*32+(6-1)):(134*32+0) /*       */
#define NV_RAMRL_ENTRY_CHAN_USERD_PTR_LO                                              (31+0*32):(8+0*32) /* RWXUF */
#define NV_RAMRL_ENTRY_CHAN_USERD_PTR_HI_HW  (19+1*32):(0+1*32) /* RWXUF */
```

Instance-block magic on Blackwell and Rubin (RAMIN 0x20C = `0xcafeca11`, from the GA10B macro) [NVIDIA-published (RM code)], https://raw.githubusercontent.com/NVIDIA/open-gpu-kernel-modules/main/src/nvidia/generated/g_kern_gmmu_nvoc.c :

```c
    // kgmmuInstBlkMagicValueGet -- halified (2 hals) body
    if (( ((chipHal_HalVarIdx >> 5) == 1UL) && ((1UL << (chipHal_HalVarIdx & 0x1f)) & 0xf8000000UL) ) ||
        ( ((chipHal_HalVarIdx >> 5) == 2UL) && ((1UL << (chipHal_HalVarIdx & 0x1f)) & 0x000060ffUL) )) /* ChipHal: GB100 | GB102 | GB10B | GB10C | GB110 | GB112 | GB202 | GB203 | GB205 | GB206 | GB207 | GB20B | GB20C | GR100 | GR102 */
    {
        pThis->__kgmmuInstBlkMagicValueGet__ = &kgmmuInstBlkMagicValueGet_GA10B;
```

nouveau has no Hopper/Blackwell RAMFC writer of its own: GH100, GB10x and GB20x are bound to `ga102_fifo_new` plus a GSP-RM entry (`.gsp = gh100/gb100/gb202_gsp_new`), and `engine/fifo/gb202.c` only adds a doorbell-handle helper (`BIT(30) | (runl->id << 16) | chan->id`) [nouveau], https://raw.githubusercontent.com/torvalds/linux/master/drivers/gpu/drm/nouveau/nvkm/engine/device/base.c , https://raw.githubusercontent.com/torvalds/linux/master/drivers/gpu/drm/nouveau/nvkm/engine/fifo/gb202.c . Whether RAMFC is then filled by nouveau's `ga100_chan_ramfc_write` or by GSP-RM was not determined here.

## 2.10 Summary: byte offsets inside the 4 KiB instance block [derived from 2.2..2.9]

| Field | Kepler, Maxwell, Pascal (incl. GK20A/GM20B/GP10B) | Volta (GV100/GV11B) | Turing | Ampere, Ada (incl. GA10B) | Hopper | Blackwell GB1xx, Rubin | Blackwell GB2xx |
|---|---|---|---|---|---|---|---|
| GP_PUT | 0x00 | 0x00 | 0x00 | 0x00 | 0x00 | 0xC0 (`DEBUG_STATE(gp_put)`, "assuming RAMFC debug state is enabled") | same as GB1xx |
| USERD lo/hi | 0x08 / 0x0C | 0x08 / 0x0C | 0x08 / 0x0C | reserved (runlist only) | not defined | not defined | not defined |
| SIGNATURE (low 16 bits = 0xFACE) | 0x10 | 0x10 | 0x10 | 0x10 | 0x10 | 0x38 | 0x38 |
| GP_GET | 0x14 | 0x14 | 0x14 | 0x14 | 0x14 | 0x98 | 0x98 |
| GP_BASE lo / hi | 0x48 / 0x4C | 0x48 / 0x4C | 0x48 / 0x4C | 0x48 / 0x4C | 0x48 / 0x4C (hi 24:0) | 0x90 / 0x94 (hi 24:0) | 0x90 / 0x94 |
| LIMIT2 (log2 GPFIFO entries) | 0x4C bits 20:16 | 0x4C 20:16 | 0x4C 20:16 | 0x4C 20:16 | 0xA4 bits 4:0 | 0xB4 bits 28:24 | 0xB4 28:24 |
| HCE_CTRL (priv = bit 5) | 0xE4 | 0xE4 | 0xE4 | 0xE4 | 0xE4 | 0x54 | 0x54 |
| CHID | 0xE8 bits 11:0 (nvgpu; nouveau) | 0xE8 (nvgpu GV11B; nouveau) | 0xFC bits 27:16 (RM); 0xE8 (nouveau) | 0xFC 27:16 (RM); 0xE8 (nouveau) | 0xFC 27:16 (RM) | 0x58 bits 27:16 (RM) | not written by RM |
| VEID | - | (0xFC 13:8 per manual) | 0xFC 13:8; RAMIN 0x218 5:0 | same | same | 0x58 13:8; RAMIN 0x218 | RAMIN 0x218 only |
| PDB lo / hi | 0x200 / 0x204 | 0x200 / 0x204 | 0x200 / 0x204 | 0x200 / 0x204 | 0x200 / 0x204 | 0x200 / 0x204 | 0x200 / 0x204 |
| ADR_LIMIT lo / hi | 0x208 / 0x20C | 0x208 / 0x20C | 0x208 / 0x20C | not written by RM | not written by RM | 0x20C = 0xcafeca11 magic | 0x208 = TOTAL_NUM_TPCS, 0x20C = magic |
| Subcontext PDB valid / table | - | 0x298 / 0x2A0 + 16i (i < 64) | same | same | same | same (RM uses the GV100 macros for all Volta+) | same |

GA10B also has the 0x20C magic. HCE_CTRL privilege bit is bit 5 everywhere (`NV_PPBDMA_HCE_CTRL_HCE_PRIV_MODE 5:5`, `NV_PBDMA_HCE_CTRL_HCE_PRIV_MODE 5:5`, nvgpu `0x20`).

## 2.11 USERD (unchanged Kepler..Blackwell)

The GA100 manual list [NVIDIA-published], https://raw.githubusercontent.com/NVIDIA/open-gpu-doc/master/manuals/ampere/ga100/dev_ram.ref.txt :

```c
#define NV_RAMUSERD                                                 /* ----G */
#define NV_RAMUSERD_BASE_SHIFT             9 /*       */
#define NV_RAMUSERD_CHAN_SIZE               512 /*       */
#define NV_RAMUSERD_PUT                        (16*32+31):(16*32+0) /* RW-UF */
#define NV_RAMUSERD_GET                        (17*32+31):(17*32+0) /* RW-UF */
#define NV_RAMUSERD_REF                        (18*32+31):(18*32+0) /* RW-UF */
#define NV_RAMUSERD_PUT_HI                     (19*32+31):(19*32+0) /* RW-UF */
#define NV_RAMUSERD_REF_THRESHOLD              (20*32+31):(20*32+0) /*       */
#define NV_RAMUSERD_TOP_LEVEL_GET              (22*32+31):(22*32+0) /* RW-UF */
#define NV_RAMUSERD_TOP_LEVEL_GET_HI           (23*32+31):(23*32+0) /* RW-UF */
#define NV_RAMUSERD_GET_HI                     (24*32+31):(24*32+0) /* RW-UF */
#define NV_RAMUSERD_GP_GET                     (34*32+31):(34*32+0) /* RW-UF */
#define NV_RAMUSERD_GP_PUT                     (35*32+31):(35*32+0) /* RW-UF */
```

GM107 `dev_ram.h` (2.3) and nvgpu GK20A (2.2) list the same word numbers (PUT 16, GET 17, REF 18, PUT_HI 19, TOP_LEVEL_GET 22/23, GET_HI 24, GP_GET 34, GP_PUT 35) [NVIDIA-published]. GB100 `dev_ram.h` republishes only `NV_RAMUSERD_GP_PUT (35*32+31):(35*32+0)` (2.9); the remaining Blackwell USERD words are not republished and are assumed unchanged [derived]. Fermi's USERD block uses the same offsets in nouveau's clear routine but a 0x1000 stride (2.2) [nouveau].

---

# Topic 3: Runlist entry formats

## 3.1 Fermi (GF1xx) - for completeness

8 bytes: word0 = CHID, word1 = 0x00000004 [nouveau], https://raw.githubusercontent.com/torvalds/linux/master/drivers/gpu/drm/nouveau/nvkm/engine/fifo/gf100.c :

```c
gf100_runl_insert_chan(struct nvkm_chan *chan, struct nvkm_memory *memory, u64 offset)
{
	nvkm_wo32(memory, offset + 0, chan->id);
	nvkm_wo32(memory, offset + 4, 0x00000004);
}
```

## 3.2 Kepler (GK104/GK106/GK107, GK110/GK110B, GK208/GK208B, GK20A) - 8-byte entries

NVIDIA's GK20A header [NVIDIA-published (nvgpu)], https://raw.githubusercontent.com/OE4T/linux-nvgpu/patches-rel-36/drivers/gpu/nvgpu/include/nvgpu/hw/gk20a/hw_ram_gk20a.h :

```c
#define ram_rl_entry_size_v()                                      (0x00000008U)
#define ram_rl_entry_chid_f(v)                         ((U32(v) & 0xfffU) << 0U)
#define ram_rl_entry_id_f(v)                           ((U32(v) & 0xfffU) << 0U)
#define ram_rl_entry_type_f(v)                          ((U32(v) & 0x1U) << 13U)
#define ram_rl_entry_type_chid_f()                                        (0x0U)
#define ram_rl_entry_type_tsg_f()                                      (0x2000U)
#define ram_rl_entry_timeslice_scale_f(v)               ((U32(v) & 0xfU) << 14U)
#define ram_rl_entry_timeslice_scale_v(r)                  (((r) >> 14U) & 0xfU)
#define ram_rl_entry_timeslice_scale_3_f()                             (0xc000U)
#define ram_rl_entry_timeslice_timeout_f(v)            ((U32(v) & 0xffU) << 18U)
#define ram_rl_entry_timeslice_timeout_v(r)               (((r) >> 18U) & 0xffU)
#define ram_rl_entry_timeslice_timeout_128_f()                      (0x2000000U)
#define ram_rl_entry_tsg_length_f(v)                   ((U32(v) & 0x3fU) << 26U)
#define ram_rl_entry_tsg_length_max_v()                            (0x00000020U)
```

nouveau writers [nouveau], https://raw.githubusercontent.com/torvalds/linux/master/drivers/gpu/drm/nouveau/nvkm/engine/fifo/gk104.c , https://raw.githubusercontent.com/torvalds/linux/master/drivers/gpu/drm/nouveau/nvkm/engine/fifo/gk110.c :

```c
gk104_runl_insert_chan(struct nvkm_chan *chan, struct nvkm_memory *memory, u64 offset)
{
	nvkm_wo32(memory, offset + 0, chan->id);
	nvkm_wo32(memory, offset + 4, 0x00000000);
}
gk110_runl_insert_cgrp(struct nvkm_cgrp *cgrp, struct nvkm_memory *memory, u64 offset)
{
	nvkm_wo32(memory, offset + 0, (cgrp->chan_nr << 26) | (128 << 18) |
				      (3 << 14) | 0x00002000 | cgrp->id);
	nvkm_wo32(memory, offset + 4, 0x00000000);
}
```

nouveau uses TSG (channel group) headers from GK110 on (`gk110_runl` is used by GK110/GK110B, GK208/GK208B and GK20A; plain GK104/GK106/GK107 use `gk104_runl` without `insert_cgrp`) [nouveau], https://raw.githubusercontent.com/torvalds/linux/master/drivers/gpu/drm/nouveau/nvkm/engine/fifo/gk208.c , https://raw.githubusercontent.com/torvalds/linux/master/drivers/gpu/drm/nouveau/nvkm/engine/fifo/gk20a.c .

Kepler channel entries carry **no instance pointer** (word1 = 0); the instance block of a CHID is only in the MMIO channel table (2.2) [nouveau].

Derived decode for 8-byte entries, word0 [derived from nvgpu + nouveau]:

| Bits | Channel entry (TYPE=0) | TSG header (TYPE=1) |
|---|---|---|
| 11:0 | CHID | TSGID |
| 13 | TYPE = 0 | TYPE = 1 (`0x2000`) |
| 14 | RUNQUEUE (Pascal, nouveau `chan->runq << 14`) | - |
| 17:14 | - | TIMESLICE_SCALE (nouveau writes 3) |
| 25:18 | - | TIMESLICE_TIMEOUT (nouveau writes 128) |
| 31:26 | - | TSG_LENGTH (number of following channel entries; max 0x20) |

## 3.3 Maxwell and Pascal - 8-byte entries with instance pointer

GM107 `dev_ram.h` publishes only the constants [NVIDIA-published], https://raw.githubusercontent.com/NVIDIA/open-gpu-kernel-modules/main/src/common/inc/swref/published/maxwell/gm107/dev_ram.h :

```c
#define NV_RAMRL_BASE_SHIFT                                      12 /*       */
#define NV_RAMRL_ENTRY_TIMESLICE_SCALE_3                 0x00000003 /* RWI-V */
#define NV_RAMRL_ENTRY_TIMESLICE_TIMEOUT_128             0x00000080 /* RWI-V */
#define NV_RAMRL_ENTRY_SIZE                                       8 /*       */
#define NV_RAMRL_ENTRY_TSG_LENGTH_MAX                    0x00000020 /* RW--V */
```

nouveau writes the instance block address (`inst >> 12`) in word1 from GM107 on, and the runqueue at bit 14 on Pascal [nouveau], https://raw.githubusercontent.com/torvalds/linux/master/drivers/gpu/drm/nouveau/nvkm/engine/fifo/gm107.c , https://raw.githubusercontent.com/torvalds/linux/master/drivers/gpu/drm/nouveau/nvkm/engine/fifo/gp100.c :

```c
gm107_runl_insert_chan(struct nvkm_chan *chan, struct nvkm_memory *memory, u64 offset)
{
	nvkm_wo32(memory, offset + 0, chan->id);
	nvkm_wo32(memory, offset + 4, chan->inst->addr >> 12);
}
gp100_runl_insert_chan(struct nvkm_chan *chan, struct nvkm_memory *memory, u64 offset)
{
	nvkm_wo32(memory, offset + 0, chan->id | chan->runq << 14);
	nvkm_wo32(memory, offset + 4, chan->inst->addr >> 12);
}
```

TSG headers on Maxwell/Pascal reuse `gk110_runl_insert_cgrp` [nouveau]. The nvgpu GM20B and GP10B `ram_rl_entry_*` definitions are identical to GK20A and do **not** define the word1 instance pointer [NVIDIA-published (nvgpu), compared by diff]; the word1 instance pointer is nouveau-only evidence.

## 3.4 Volta and Turing - 16-byte entries

Already verified in Keto from the GV100 manual (https://raw.githubusercontent.com/NVIDIA/open-gpu-doc/master/manuals/volta/gv100/dev_ram.ref.txt) and nouveau `gv100_runl_insert_*` [NVIDIA-published, nouveau]. Differences found between manuals [NVIDIA-published, compared by diff]:
- GV100: `NV_RAMRL_ENTRY_ID_HW 11:0`, `NV_RAMRL_ENTRY_ID_MAX (4096-1)`; no `TSG_GFID`.
- TU104 (https://raw.githubusercontent.com/NVIDIA/open-gpu-doc/master/manuals/turing/tu104/dev_ram.ref.txt): adds `NV_RAMRL_ENTRY_CHAN_USERD_PTR_HI_HW (7+1*32):(0+1*32)` and `NV_RAMRL_ENTRY_TSG_GFID (11+0*32):(4+0*32)`.
- GA100 (3.5): `NV_RAMRL_ENTRY_ID_HW 10:0`, `NV_RAMRL_ENTRY_ID_MAX (2048-1)`, adds `NV_RAMRL_ENTRY_CHAN_INST_TARGET_FB_BIND_SHIFT 28`.

nouveau [nouveau], https://raw.githubusercontent.com/torvalds/linux/master/drivers/gpu/drm/nouveau/nvkm/engine/fifo/gv100.c :

```c
gv100_runl_insert_chan(struct nvkm_chan *chan, struct nvkm_memory *memory, u64 offset)
{
	const u64 user = nvkm_memory_addr(chan->userd.mem) + chan->userd.base;
	const u64 inst = chan->inst->addr;

	nvkm_wo32(memory, offset + 0x0, lower_32_bits(user) | chan->runq << 1);
	nvkm_wo32(memory, offset + 0x4, upper_32_bits(user));
	nvkm_wo32(memory, offset + 0x8, lower_32_bits(inst) | chan->id);
	nvkm_wo32(memory, offset + 0xc, upper_32_bits(inst));
}
gv100_runl_insert_cgrp(struct nvkm_cgrp *cgrp, struct nvkm_memory *memory, u64 offset)
{
	nvkm_wo32(memory, offset + 0x0, (128 << 24) | (3 << 16) | 0x00000001);
	nvkm_wo32(memory, offset + 0x4, cgrp->chan_nr);
	nvkm_wo32(memory, offset + 0x8, cgrp->id);
	nvkm_wo32(memory, offset + 0xc, 0x00000000);
}
```

## 3.5 Ampere, Ada - 16-byte entries

Full GA100 manual definition [NVIDIA-published], https://raw.githubusercontent.com/NVIDIA/open-gpu-doc/master/manuals/ampere/ga100/dev_ram.ref.txt :

```c
#define NV_RAMRL_ENTRY_RANGE                          0xF:0x00000000 /* RW--M */
#define NV_RAMRL_ENTRY                                               /* ----G */
#define NV_RAMRL_ENTRY_SIZE                                       16 /*       */
#define NV_RAMRL_ENTRY_BASE_SHIFT                                 12 /*       */
#define NV_RAMRL_ENTRY_TYPE                        (0+0*32):(0+0*32) /* RWXUF */
#define NV_RAMRL_ENTRY_TYPE_CHAN                          0x00000000 /* RW--V */
#define NV_RAMRL_ENTRY_TYPE_TSG                           0x00000001 /* RW--V */
#define NV_RAMRL_ENTRY_ID                         (11+2*32):(0+2*32) /* RWXUF */
#define NV_RAMRL_ENTRY_ID_HW                      10:0 /* RWXUF */
#define NV_RAMRL_ENTRY_ID_MAX              (2048-1) /* RW--V */
#define NV_RAMRL_ENTRY_CHAN_RUNQUEUE_SELECTOR      (1+0*32):(1+0*32) /* RWXUF */
#define NV_RAMRL_ENTRY_CHAN_INST_TARGET                   (5+0*32):(4+0*32) /* RWXUF */
#define NV_RAMRL_ENTRY_CHAN_INST_TARGET_VID_MEM                  0x00000000 /* RW--V */
#define NV_RAMRL_ENTRY_CHAN_INST_TARGET_SYS_MEM_COHERENT         0x00000002 /* RW--V */
#define NV_RAMRL_ENTRY_CHAN_INST_TARGET_SYS_MEM_NONCOHERENT      0x00000003 /* RW--V */
#define NV_RAMRL_ENTRY_CHAN_USERD_TARGET                  (7+0*32):(6+0*32) /* RWXUF */
#define NV_RAMRL_ENTRY_CHAN_USERD_TARGET_VID_MEM                 0x00000000 /* RW--V */
#define NV_RAMRL_ENTRY_CHAN_USERD_TARGET_VID_MEM_NVLINK_COHERENT 0x00000001 /* RW--V */
#define NV_RAMRL_ENTRY_CHAN_USERD_TARGET_SYS_MEM_COHERENT        0x00000002 /* RW--V */
#define NV_RAMRL_ENTRY_CHAN_USERD_TARGET_SYS_MEM_NONCOHERENT     0x00000003 /* RW--V */
#define NV_RAMRL_ENTRY_CHAN_USERD_PTR_LO          (31+0*32):(8+0*32) /* RWXUF */
#define NV_RAMRL_ENTRY_CHAN_USERD_PTR_HI          (31+1*32):(0+1*32) /* RWXUF */
#define NV_RAMRL_ENTRY_CHAN_USERD_PTR_HI_HW        (7+1*32):(0+1*32) /* RWXUF */
#define NV_RAMRL_ENTRY_CHAN_CHID                  (11+2*32):(0+2*32) /* RWXUF */
#define NV_RAMRL_ENTRY_CHAN_INST_PTR_LO          (31+2*32):(12+2*32) /* RWXUF */
#define NV_RAMRL_ENTRY_CHAN_INST_PTR_HI           (31+3*32):(0+3*32) /* RWXUF */
#define NV_RAMRL_ENTRY_CHAN_INST_PTR_ALIGN_SHIFT                  12 /*       */
#define NV_RAMRL_ENTRY_CHAN_USERD_PTR_ALIGN_SHIFT                  8 /*       */
#define NV_RAMRL_ENTRY_CHAN_INST_TARGET_FB_BIND_SHIFT             28 /*       */
#define NV_RAMRL_ENTRY_TSG_GFID                   (11+0*32):(4+0*32) /* RWXUF */
#define NV_RAMRL_ENTRY_TSG_TIMESLICE_SCALE       (19+0*32):(16+0*32) /* RWXUF */
#define NV_RAMRL_ENTRY_TSG_TIMESLICE_SCALE_3              0x00000003 /* RWI-V */
#define NV_RAMRL_ENTRY_TSG_TIMESLICE_TIMEOUT     (31+0*32):(24+0*32) /* RWXUF */
#define NV_RAMRL_ENTRY_TSG_TIMESLICE_TIMEOUT_128          0x00000080 /* RWI-V */
#define NV_RAMRL_ENTRY_TSG_TIMESLICE_TIMEOUT_1            0x00000000 /* RW--V */
#define NV_RAMRL_ENTRY_TSG_LENGTH                  (7+1*32):(0+1*32) /* RWXUF */
#define NV_RAMRL_ENTRY_TSG_LENGTH_INIT                    0x00000000 /* RW--V */
#define NV_RAMRL_ENTRY_TSG_LENGTH_MIN                     0x00000001 /* RW--V */
#define NV_RAMRL_ENTRY_TSG_LENGTH_MAX                     0x00000080 /* RW--V */
#define NV_RAMRL_ENTRY_TSG_TSGID                  (11+2*32):(0+2*32) /* RWXUF */
```

Published deltas [NVIDIA-published]: GA100 `dev_ram.h` keeps `NV_RAMRL_ENTRY_BASE_SHIFT 12`; GA102 changes the runlist base alignment:
https://raw.githubusercontent.com/NVIDIA/open-gpu-kernel-modules/main/src/common/inc/swref/published/ampere/ga102/dev_ram.h

```c
#define NV_RAMRL_ENTRY_CHAN_USERD_PTR_LO         (31+0*32):(8+0*32) /* RWXUF */
#define NV_RAMRL_ENTRY_CHAN_USERD_PTR_HI_HW       (7+1*32):(0+1*32) /* RWXUF */
#define NV_RAMRL_ENTRY_BASE_SHIFT                                12 /*       */
#define NV_RAMRL_ENTRY_BASE_SHIFT                                 10 /*       */
```

GA10B (Orin) nvgpu definition (same layout) [NVIDIA-published (nvgpu)], https://raw.githubusercontent.com/OE4T/linux-nvgpu/patches-rel-36/drivers/gpu/nvgpu/include/nvgpu/hw/ga10b/hw_ram_ga10b.h :

```c
#define ram_rl_entry_size_v()                                      (0x00000010U)
#define ram_rl_entry_type_channel_v()                              (0x00000000U)
#define ram_rl_entry_type_tsg_v()                                  (0x00000001U)
#define ram_rl_entry_chan_runqueue_selector_f(v)         ((U32(v) & 0x1U) << 1U)
#define ram_rl_entry_chan_inst_target_f(v)               ((U32(v) & 0x3U) << 4U)
#define ram_rl_entry_chan_inst_target_sys_mem_ncoh_v()             (0x00000003U)
#define ram_rl_entry_chan_inst_target_sys_mem_coh_v()              (0x00000002U)
#define ram_rl_entry_chan_inst_target_vid_mem_v()                  (0x00000000U)
#define ram_rl_entry_chan_userd_target_f(v)              ((U32(v) & 0x3U) << 6U)
#define ram_rl_entry_chan_userd_target_vid_mem_v()                 (0x00000000U)
#define ram_rl_entry_chan_userd_target_sys_mem_coh_v()             (0x00000002U)
#define ram_rl_entry_chan_userd_target_sys_mem_ncoh_v()            (0x00000003U)
#define ram_rl_entry_chan_userd_ptr_lo_f(v)         ((U32(v) & 0xffffffU) << 8U)
#define ram_rl_entry_chan_userd_ptr_hi_f(v)       ((U32(v) & 0xffffffffU) << 0U)
#define ram_rl_entry_chid_f(v)                         ((U32(v) & 0xfffU) << 0U)
#define ram_rl_entry_chan_inst_ptr_lo_f(v)          ((U32(v) & 0xfffffU) << 12U)
#define ram_rl_entry_chan_inst_ptr_hi_f(v)        ((U32(v) & 0xffffffffU) << 0U)
#define ram_rl_entry_tsg_timeslice_scale_f(v)           ((U32(v) & 0xfU) << 16U)
#define ram_rl_entry_tsg_timeslice_timeout_f(v)        ((U32(v) & 0xffU) << 24U)
#define ram_rl_entry_tsg_length_f(v)                    ((U32(v) & 0xffU) << 0U)
#define ram_rl_entry_tsg_length_max_v()                            (0x00000080U)
#define ram_rl_entry_tsg_tsgid_f(v)                    ((U32(v) & 0xfffU) << 0U)
#define ram_rl_entry_chan_userd_ptr_align_shift_v()                (0x00000008U)
#define ram_rl_entry_chan_inst_ptr_align_shift_v()                 (0x0000000cU)
```

nouveau uses the gv100 entry writers for GA100/GA10x/AD10x and submits runlists through per-runlist registers (`runl->addr + 0x080/0x084/0x088`) [nouveau], https://raw.githubusercontent.com/torvalds/linux/master/drivers/gpu/drm/nouveau/nvkm/engine/fifo/ga100.c .

## 3.6 Hopper, Blackwell, Rubin - 16-byte entries

- The RM uses one entry-size function (`kfifoRunlistGetEntrySize_GV100`, returning `NV_RAMRL_ENTRY_SIZE` = 16) for every non-display chip, so the 16-byte entry continues through Blackwell and Rubin [NVIDIA-published (RM code)], https://raw.githubusercontent.com/NVIDIA/open-gpu-kernel-modules/main/src/nvidia/generated/g_kernel_fifo_nvoc.c :

```c
    // kfifoRunlistGetEntrySize -- halified (2 hals) body
    if (( ((chipHal_HalVarIdx >> 5) == 3UL) && ((1UL << (chipHal_HalVarIdx & 0x1f)) & 0x0000e000UL) )) /* ChipHal: T234D | T238D | T264D */
    {
        // NVOC_UNREACHABLE, NULL-initialized.
    }
    else
    {
        pThis->__kfifoRunlistGetEntrySize__ = &kfifoRunlistGetEntrySize_GV100;
    // kfifoRunlistGetBaseShift -- halified (5 hals) body
    if (( ((chipHal_HalVarIdx >> 5) == 1UL) && ((1UL << (chipHal_HalVarIdx & 0x1f)) & 0x00000400UL) )) /* ChipHal: GA100 */
    {
        pThis->__kfifoRunlistGetBaseShift__ = &kfifoRunlistGetBaseShift_GA100;
    }
    else if (( ((chipHal_HalVarIdx >> 5) == 3UL) && ((1UL << (chipHal_HalVarIdx & 0x1f)) & 0x0000e000UL) )) /* ChipHal: T234D | T238D | T264D */
    {
        // NVOC_UNREACHABLE, NULL-initialized.
    }
    else if (( ((chipHal_HalVarIdx >> 5) == 1UL) && ((1UL << (chipHal_HalVarIdx & 0x1f)) & 0x000003e0UL) )) /* ChipHal: TU102 | TU104 | TU106 | TU116 | TU117 */
    {
        pThis->__kfifoRunlistGetBaseShift__ = &kfifoRunlistGetBaseShift_GM107;
    }
    else if (( ((chipHal_HalVarIdx >> 5) == 2UL) && ((1UL << (chipHal_HalVarIdx & 0x1f)) & 0x000000feUL) )) /* ChipHal: GB202 | GB203 | GB205 | GB206 | GB207 | GB20B | GB20C */
    {
        pThis->__kfifoRunlistGetBaseShift__ = &kfifoRunlistGetBaseShift_GB202;
    }
    else
    {
        pThis->__kfifoRunlistGetBaseShift__ = &kfifoRunlistGetBaseShift_GA102;
```

- Base shift per chip [derived from the bindings and headers]: Turing 12 (GM107 function), GA100 12, GA102..Ada, Hopper, GB10x 10 (GA102 header), GB20x 8 (GB202 header).
- Hopper and GB10B widen `CHAN_USERD_PTR_HI_HW` to bits 19:0 of word1 (2.8, 2.9) [NVIDIA-published]. GA100's is 7:0.
- GB20x adds `NV_RAMRL_ENTRY_CHAN_RUNQUEUE_SELECTOR_RUNQUEUE1 0x00000001` and `NV_RAMRL_ENTRY_BASE_SHIFT 8` (2.9) [NVIDIA-published]; the RM rejects SCG type `RUNQUEUE1` on runqueue 0 (`kfifoValidateSCGTypeAndRunqueue_GB202`) [NVIDIA-published (RM code)].
- No other field change for Hopper/Blackwell runlist entries is published; field positions other than those above are assumed equal to GA100 [derived].

---

# Topic 4: Hopper and Blackwell MMU; VER2/VER3 level splits

## 4.1 Format versions per chip

- `g_gmmuFmtVersions` = {1, 2, 3} (1.8). No VER4 exists in the published headers or the RM sources [NVIDIA-published (RM code)].
- Supported versions: `kgmmuFmtIsVersionSupported_GP10X` returns true only for VER2 (Turing, Ampere, Ada); `kgmmuFmtIsVersionSupported_GH10X` only for VER3 [NVIDIA-published (RM code)], https://raw.githubusercontent.com/NVIDIA/open-gpu-kernel-modules/main/src/nvidia/src/kernel/gpu/mmu/arch/pascal/kern_gmmu_gp100.c , https://raw.githubusercontent.com/NVIDIA/open-gpu-kernel-modules/main/src/nvidia/src/kernel/gpu/mmu/arch/hopper/kern_gmmu_gh100.c .
- Family init binding (GH100 family = every chip not listed, i.e. GH100, GB1xx, GB2xx, GR1xx) [NVIDIA-published (RM code)], https://raw.githubusercontent.com/NVIDIA/open-gpu-kernel-modules/main/src/nvidia/generated/g_kern_gmmu_nvoc.c :

```c
    // kgmmuFmtFamiliesInit -- halified (3 hals) body
    if (( ((chipHal_HalVarIdx >> 5) == 3UL) && ((1UL << (chipHal_HalVarIdx & 0x1f)) & 0x0000e000UL) )) /* ChipHal: T234D | T238D | T264D */
    {
        pThis->__kgmmuFmtFamiliesInit__ = &kgmmuFmtFamiliesInit_GM200;
    }
    else if (( ((chipHal_HalVarIdx >> 5) == 1UL) && ((1UL << (chipHal_HalVarIdx & 0x1f)) & 0x01f0ffe0UL) )) /* ChipHal: TU102 | TU104 | TU106 | TU116 | TU117 | GA100 | GA102 | GA103 | GA104 | GA106 | GA107 | AD102 | AD103 | AD104 | AD106 | AD107 */
    {
        pThis->__kgmmuFmtFamiliesInit__ = &kgmmuFmtFamiliesInit_GV100;
    }
    else
    {
        pThis->__kgmmuFmtFamiliesInit__ = &kgmmuFmtFamiliesInit_GH100;
```

- nouveau uses `gh100_mmu_new` for GH100, GB100, GB102 and GB202..GB207 [nouveau], https://raw.githubusercontent.com/torvalds/linux/master/drivers/gpu/drm/nouveau/nvkm/engine/device/base.c .

## 4.2 Level split per chip (RM)

Level-init binding [NVIDIA-published (RM code)], https://raw.githubusercontent.com/NVIDIA/open-gpu-kernel-modules/main/src/nvidia/generated/g_kern_gmmu_nvoc.c :

```c
    // kgmmuFmtInitLevels -- halified (5 hals) body
    if (( ((chipHal_HalVarIdx >> 5) == 1UL) && ((1UL << (chipHal_HalVarIdx & 0x1f)) & 0x04000000UL) )) /* ChipHal: GH100 */
    {
        pThis->__kgmmuFmtInitLevels__ = &kgmmuFmtInitLevels_GH10X;
    }
    else if (( ((chipHal_HalVarIdx >> 5) == 3UL) && ((1UL << (chipHal_HalVarIdx & 0x1f)) & 0x0000e000UL) )) /* ChipHal: T234D | T238D | T264D */
    {
        pThis->__kgmmuFmtInitLevels__ = &kgmmuFmtInitLevels_d44104;
    }
    else if (( ((chipHal_HalVarIdx >> 5) == 1UL) && ((1UL << (chipHal_HalVarIdx & 0x1f)) & 0x000003e0UL) )) /* ChipHal: TU102 | TU104 | TU106 | TU116 | TU117 */
    {
        pThis->__kgmmuFmtInitLevels__ = &kgmmuFmtInitLevels_GP10X;
    }
    else if (( ((chipHal_HalVarIdx >> 5) == 1UL) && ((1UL << (chipHal_HalVarIdx & 0x1f)) & 0x01f0fc00UL) )) /* ChipHal: GA100 | GA102 | GA103 | GA104 | GA106 | GA107 | AD102 | AD103 | AD104 | AD106 | AD107 */
    {
        pThis->__kgmmuFmtInitLevels__ = &kgmmuFmtInitLevels_GA10X;
    }
    else
    {
        pThis->__kgmmuFmtInitLevels__ = &kgmmuFmtInitLevels_GB10X;
```

VER2, Pascal/Volta/Turing (`kgmmuFmtInitLevels_GP10X`), https://raw.githubusercontent.com/NVIDIA/open-gpu-kernel-modules/main/src/nvidia/src/kernel/gpu/mmu/arch/pascal/kern_gmmu_fmt_gp10x.c :

```c
 *  PD3 [48:47]
 *  |
 *  v
 *  PD2 [46:38]
 *  |
 *  v
 *  PD1 [37:29]
 *  |
 *  v
 *  PD0 [28:21] / PT_LARGE [28:21] (2MB page)
 *  |        \
 *  |         \
 *  v          v
 *  PT_SMALL  PT_BIG (64KB page)
 *  [20:12]   [20:16]
 */
```

VER2, Ampere/Ada (`kgmmuFmtInitLevels_GA10X`: PD1 may hold a 512 MiB PTE), https://raw.githubusercontent.com/NVIDIA/open-gpu-kernel-modules/main/src/nvidia/src/kernel/gpu/mmu/arch/ampere/kern_gmmu_fmt_ga10x.c :

```c
 *  PD3 [48:47]
 *  |
 *  v
 *  PD2 [46:38]
 *  |
 *  v
 *  PD1 [37:29] / PT_512M [37:29] (512MB page)
 *  |
 *  v
 *  PD0 [28:21] / PT_HUGE [28:21] (2MB page)
 *  |        \
 *  |         \
 *  v          v
 *  PT_SMALL  PT_BIG (64KB page)
 *  [20:12]   [20:16]
 */
    // Page directory 1 can now hold a PTE pointing to a 512MB Page
    pLevels[2].bPageTable = NV_TRUE;
```

VER3, Hopper (`kgmmuFmtInitLevels_GH10X`), https://raw.githubusercontent.com/NVIDIA/open-gpu-kernel-modules/main/src/nvidia/src/kernel/gpu/mmu/arch/hopper/kern_gmmu_fmt_gh10x.c :

```c
 *  NUM_VA_BITS = 57
 *
 *  PD4[56]
 *  |
 *  v
 *  PD3 [55:47]
 *  |
 *  v
 *  PD2 [46:38]
 *  |
 *  v
 *  PD1 [37:29] / PT_512M [37:29] (512MB page)
 *  |
 *  v
 *  PD0 [28:21] / PT_LARGE [28:21] (2MB page)
 *  |                       \
 *  |                        \
 *  v                         v
 *  PT_SMALL       PT_BIG (64KB page)
 *  [20:12]               [20:16]
 */
    // Page directory 1 can hold a PTE pointing to a 512MB Page
    pLevels[3].bPageTable     = NV_TRUE;
    pLevels[4].entrySize      = NV_MMU_VER3_DUAL_PDE__SIZE;
```

VER3, Blackwell and Rubin (`kgmmuFmtInitLevels_GB10X`: PD2 may hold a 256 GiB PTE), https://raw.githubusercontent.com/NVIDIA/open-gpu-kernel-modules/main/src/nvidia/src/kernel/gpu/mmu/arch/blackwell/kern_gmmu_fmt_gb10x.c :

```c
 *  NUM_VA_BITS = 57
 *
 *  PD4[56]
 *  |
 *  v
 *  PD3 [55:47]
 *  |
 *  v
 *  PD2 [46:38] / PT_256GB [46:38] (256GB Page)
 *  |
 *  v
 *  PD1 [37:29] / PT_512M [37:29] (512MB page)
 *  |
 *  v
 *  PD0 [28:21] / PT_LARGE [28:21] (2MB page)
 *  |                       \
 *  |                        \
 *  v                         v
 *  PT_SMALL       PT_BIG (64KB page)
 *  [20:12]               [20:16]
 */
    // Page directory 1 can now hold a PTE pointing to a 256GB Page
    pLevels[2].bPageTable = NV_TRUE;
```

(The GB10X comment says "Page directory 1" but the code sets `pLevels[2]`, which is PD2 [46:38]; the ASCII diagram above it labels PD2 as `PT_256GB` [NVIDIA-published].)

Derived tables [derived from the RM code above]:

| Format | Levels (VA bits) | Entry sizes | VA width |
|---|---|---|---|
| VER2 | PD3 48:47, PD2 46:38, PD1 37:29, PD0 28:21 (16-byte dual PDE), big PT 20:16 (20:17 for 128 KiB), small PT 20:12 | 8 B except PD0 16 B | 49 bits |
| VER3 | PD4 56, PD3 55:47, PD2 46:38, PD1 37:29, PD0 28:21 (16-byte dual PDE), big PT 20:16, small PT 20:12 | 8 B except PD0 16 B | 57 bits |

## 4.3 nouveau VER3 (GH100) descriptors

https://raw.githubusercontent.com/torvalds/linux/master/drivers/gpu/drm/nouveau/nvkm/subdev/mmu/vmmgh100.c [nouveau] (leaf first; bits 5/8/9/9/9/1 = 64 KiB PT, PD0, PD1, PD2, PD3, PD4):

```c
gh100_vmm_desc_16[] = {
	{ LPT, 5,  8, 0x0100, &gh100_vmm_desc_lpt },
	{ PGD, 8, 16, 0x1000, &gh100_vmm_desc_pd0 },
	{ PGD, 9,  8, 0x1000, &gh100_vmm_desc_pd1 },
	{ PGD, 9,  8, 0x1000, &gh100_vmm_desc_pd1 },
	{ PGD, 9,  8, 0x1000, &gh100_vmm_desc_pd1 },
	{ PGD, 1,  8, 0x1000, &gh100_vmm_desc_pd1 },
	{}
};
gh100_vmm = {
	.join = gv100_vmm_join,
	.part = gf100_vmm_part,
	.aper = gf100_vmm_aper,
	.valid = gp100_vmm_valid,
	.valid2 = gh100_vmm_valid,
	.flush = tu102_vmm_flush,
	.page = {
		{ 56, &gh100_vmm_desc_16[5], NVKM_VMM_PAGE_Sxxx },
		{ 47, &gh100_vmm_desc_16[4], NVKM_VMM_PAGE_Sxxx },
		{ 38, &gh100_vmm_desc_16[3], NVKM_VMM_PAGE_Sxxx },
		{ 29, &gh100_vmm_desc_16[2], NVKM_VMM_PAGE_SVxC },
		{ 21, &gh100_vmm_desc_16[1], NVKM_VMM_PAGE_SVxC },
		{ 16, &gh100_vmm_desc_16[0], NVKM_VMM_PAGE_SVxC },
		{ 12, &gh100_vmm_desc_12[0], NVKM_VMM_PAGE_SVHx },
		{}
	}
};
```

nouveau VER2 (Pascal..Ada) page list stops at 2 MiB (47/38/29 are sparse-only), https://raw.githubusercontent.com/torvalds/linux/master/drivers/gpu/drm/nouveau/nvkm/subdev/mmu/vmmgp100.c [nouveau]:

```c
gp100_vmm = {
	.join = gp100_vmm_join,
	.part = gf100_vmm_part,
	.aper = gf100_vmm_aper,
	.valid = gp100_vmm_valid,
	.flush = gp100_vmm_flush,
	.mthd = gp100_vmm_mthd,
	.invalidate_pdb = gp100_vmm_invalidate_pdb,
	.page = {
		{ 47, &gp100_vmm_desc_16[4], NVKM_VMM_PAGE_Sxxx },
		{ 38, &gp100_vmm_desc_16[3], NVKM_VMM_PAGE_Sxxx },
		{ 29, &gp100_vmm_desc_16[2], NVKM_VMM_PAGE_Sxxx },
		{ 21, &gp100_vmm_desc_16[1], NVKM_VMM_PAGE_SVxx },
		{ 16, &gp100_vmm_desc_16[0], NVKM_VMM_PAGE_SVxx },
		{ 12, &gp100_vmm_desc_12[0], NVKM_VMM_PAGE_SVHx },
		{}
	}
};
```

A 2 MiB PTE in PD0 is written into the first 8 bytes of the 16-byte dual-PDE slot with the upper 8 bytes zero [nouveau]:

```c
gp100_vmm_pd0_pte(struct nvkm_vmm *vmm, struct nvkm_mmu_pt *pt,
		  u32 ptei, u32 ptes, struct nvkm_vmm_map *map, u64 addr)
{
	u64 data = (addr >> 4) | map->type;

	if (map->ctag)
		data |= gp100_vmm_pte_comptagline_base(addr);

	while (ptes--) {
		VMM_WO128(pt, vmm, ptei++ * 0x10, data, 0ULL);
		data += map->next;
	}
}
```

## 4.4 VER3 field reminders and Blackwell/Rubin `dev_mmu.h` changes

VER3 PDE/PTE (Hopper) is already verified in Keto from https://raw.githubusercontent.com/NVIDIA/open-gpu-kernel-modules/main/src/common/inc/swref/published/hopper/gh100/dev_mmu.h [NVIDIA-published]. Key lines:

```c
#define NV_MMU_VER3_PDE_IS_PTE                                           0:0 /* RWXVF */
#define NV_MMU_VER3_PDE_APERTURE                                         2:1 /* RWXVF */
#define NV_MMU_VER3_PDE_PCF                                                                        5:3 /* RWXVF */
#define NV_MMU_VER3_PDE_ADDRESS                                             51:12 /* RWXVF */
#define NV_MMU_VER3_PDE__SIZE                                              8
#define NV_MMU_VER3_DUAL_PDE_ADDRESS_BIG                                     51:8 /* RWXVF */
#define NV_MMU_VER3_DUAL_PDE_ADDRESS_SMALL                                 115:76 /* RWXVF */
#define NV_MMU_VER3_DUAL_PDE__SIZE                                             16
#define NV_MMU_VER3_PTE_VALID                                            0:0 /* RWXVF */
#define NV_MMU_VER3_PTE_APERTURE                                         2:1 /* RWXVF */
#define NV_MMU_VER3_PTE_PCF                                                                        7:3 /* RWXVF */
#define NV_MMU_VER3_PTE_KIND                                           11:8 /* RWXVF */
#define NV_MMU_VER3_PTE_ADDRESS                                         51:12 /* RWXVF */
#define NV_MMU_VER3_PTE_PEER_ID                63:(64-3) /* RWXVF */
#define NV_MMU_VER3_PTE__SIZE                                              8
```

Blackwell `gb202/dev_mmu.h` and `gb20b/dev_mmu.h` contain only KIND values; they are identical to GH100's `NV_MMU_PTE_KIND_*` list and add `NV_MMU_CLIENT_KIND` (compared by diff) [NVIDIA-published], https://raw.githubusercontent.com/NVIDIA/open-gpu-kernel-modules/main/src/common/inc/swref/published/blackwell/gb202/dev_mmu.h , https://raw.githubusercontent.com/NVIDIA/open-gpu-kernel-modules/main/src/common/inc/swref/published/blackwell/gb20b/dev_mmu.h :

```c
#define NV_MMU_PTE_KIND_INVALID                       0x07 /* R---V */
#define NV_MMU_PTE_KIND_PITCH                         0x00 /* R---V */
#define NV_MMU_PTE_KIND_GENERIC_MEMORY                                                  0x6 /* R---V */
#define NV_MMU_PTE_KIND_Z16                                                             0x1 /* R---V */
#define NV_MMU_PTE_KIND_S8                                                              0x2 /* R---V */
#define NV_MMU_PTE_KIND_S8Z24                                                           0x3 /* R---V */
#define NV_MMU_PTE_KIND_ZF32_X24S8                                                      0x4 /* R---V */
#define NV_MMU_PTE_KIND_Z24S8                                                           0x5 /* R---V */
#define NV_MMU_PTE_KIND_GENERIC_MEMORY_COMPRESSIBLE                                     0x8 /* R---V */
#define NV_MMU_PTE_KIND_GENERIC_MEMORY_COMPRESSIBLE_DISABLE_PLC                         0x9 /* R---V */
#define NV_MMU_PTE_KIND_S8_COMPRESSIBLE_DISABLE_PLC                                     0xA /* R---V */
#define NV_MMU_PTE_KIND_Z16_COMPRESSIBLE_DISABLE_PLC                                    0xB /* R---V */
#define NV_MMU_PTE_KIND_S8Z24_COMPRESSIBLE_DISABLE_PLC                                  0xC /* R---V */
#define NV_MMU_PTE_KIND_ZF32_X24S8_COMPRESSIBLE_DISABLE_PLC                             0xD /* R---V */
#define NV_MMU_PTE_KIND_Z24S8_COMPRESSIBLE_DISABLE_PLC                                  0xE /* R---V */
#define NV_MMU_PTE_KIND_SMSKED_MESSAGE                                                  0xF /* R---V */
#define NV_MMU_CLIENT_KIND                                    2:0 /* RWXVF */
#define NV_MMU_CLIENT_KIND_Z16                                0x1 /* R---V */
#define NV_MMU_CLIENT_KIND_S8                                 0x2 /* R---V */
#define NV_MMU_CLIENT_KIND_S8Z24                              0x3 /* R---V */
#define NV_MMU_CLIENT_KIND_ZF32_X24S8                         0x4 /* R---V */
#define NV_MMU_CLIENT_KIND_Z24S8                              0x5 /* R---V */
#define NV_MMU_CLIENT_KIND_GENERIC_MEMORY                     0x6 /* R---V */
#define NV_MMU_CLIENT_KIND_INVALID                            0x7 /* R---V */
```

No `blackwell/gb100/dev_mmu.h` is published; the GB100 PTE/PDE formats come from the GH10X format code via the HAL bindings (4.1, 4.2) [NVIDIA-published (RM code)].

Rubin `gr100/dev_mmu.h` adds aperture-specific VER3 address aliases (VRAM limited to 40-bit PA) [NVIDIA-published], https://raw.githubusercontent.com/NVIDIA/open-gpu-kernel-modules/main/src/common/inc/swref/published/rubin/gr100/dev_mmu.h :

```c
#define NV_MMU_VER3_PTE_ADDRESS_SYS                                     51:12 /* RWXVF */
#define NV_MMU_VER3_PTE_ADDRESS_PEER                                    51:12 /* RWXVF */
#define NV_MMU_VER3_PTE_ADDRESS_VID                                     39:12 /* RWXVF */
```

Rubin's header also republishes a full VER2 block (with enum values) under both `NV_MMU_VER2_*` and `NV_MMU_NEW_*` names; its VER2 PTE COMPTAGLINE is `(20+35):36` like Turing [NVIDIA-published].

## 4.5 VER2 COMPTAGLINE width per generation

```c
#define NV_MMU_VER2_PTE_COMPTAGLINE   (18+35):36 /* RWXVF */
#define NV_MMU_VER2_PTE_COMPTAGLINE                          (20+35):36 /* RWXVF */
```

GP100/GV100: 18 bits at 53:36; TU102 and later: 20 bits at 55:36 [NVIDIA-published, gp100/gv100/tu102 `dev_mmu.h`]. The RM installs the comptagline field only for Turing, Ampere and Ada (`kgmmuFmtInitPteComptagLine_TU10X`) [NVIDIA-published (RM code)]. nvgpu: GP10B/GV11B 18 bits, GA10B 20 bits (`gmmu_new_pte_comptagline_f` masks 0x3ffff / 0xfffff) [NVIDIA-published (nvgpu)]. Because `NV_MMU_VER2_PTE_ADDRESS_SYS 53:8` overlaps COMPTAGLINE, the RM uses the VID address field for sysmem on Tegra ("unified aperture") [NVIDIA-published (RM code), kern_gmmu_fmt_gp10x.c comment].

---

# Topic 5: Chip identification

## 5.1 NV_PMC_BOOT_0 / NV_PMC_BOOT_42 encoding

Volta manual (fields of `NV_PMC_BOOT_0` at MMIO 0x0) [NVIDIA-published], https://raw.githubusercontent.com/NVIDIA/open-gpu-doc/master/manuals/volta/gv100/dev_master.ref.txt :

```c
#define NV_PMC_BOOT_0_ID                                       31:0 /*       */
#define NV_PMC_BOOT_0_MINOR_REVISION                            3:0 /* R--VF */
#define NV_PMC_BOOT_0_MAJOR_REVISION                            7:4 /* R--VF */
#define NV_PMC_BOOT_0_RESERVED_0                               11:8 /*       */
#define NV_PMC_BOOT_0_IMPLEMENTATION                          23:20 /* R--VF */
#define NV_PMC_BOOT_0_ARCHITECTURE                            28:24 /* R--VF */
```

Architecture codes as listed in the GA100 manual [NVIDIA-published], https://raw.githubusercontent.com/NVIDIA/open-gpu-doc/master/manuals/ampere/ga100/dev_boot.ref.txt :

```c
#define NV_PMC_BOOT_0_ARCHITECTURE_GF100                 0x0000000C /* R---V */
#define NV_PMC_BOOT_0_ARCHITECTURE_GF110                 0x0000000D /* R---V */
#define NV_PMC_BOOT_0_ARCHITECTURE_GK100                 0x0000000E /* R---V */
#define NV_PMC_BOOT_0_ARCHITECTURE_GK110                 0x0000000F /* R---V */
#define NV_PMC_BOOT_0_ARCHITECTURE_GK200                 0x00000010 /* R---V */
#define NV_PMC_BOOT_0_ARCHITECTURE_GM000                 0x00000011 /* R---V */
#define NV_PMC_BOOT_0_ARCHITECTURE_GM100                 0x00000011 /* R---V */
#define NV_PMC_BOOT_0_ARCHITECTURE_GM200                 0x00000012 /* R---V */
#define NV_PMC_BOOT_0_ARCHITECTURE_GP100                 0x00000013 /* R---V */
#define NV_PMC_BOOT_0_ARCHITECTURE_GV100                 0x00000014 /* R---V */
#define NV_PMC_BOOT_0_ARCHITECTURE_GV110                 0x00000015 /* R---V */
#define NV_PMC_BOOT_0_ARCHITECTURE_TU100                 0x00000016 /* R---V */
#define NV_PMC_BOOT_0_ARCHITECTURE_TU110                 0x00000016 /* R---V */
#define NV_PMC_BOOT_0_ARCHITECTURE_GA100                 0x00000017 /* R---V */
```

`NV_PMC_BOOT_42` (MMIO 0xA00, Pascal+) exposes the same chip ID as one 9-bit field [NVIDIA-published], same URL:

```c
#define NV_PMC_BOOT_42_MINOR_EXTENDED_REVISION                 11:8 /* R-XVF */
#define NV_PMC_BOOT_42_MINOR_REVISION                         15:12 /* R-XVF */
#define NV_PMC_BOOT_42_MAJOR_REVISION                         19:16 /* R-XVF */
#define NV_PMC_BOOT_42_IMPLEMENTATION                         23:20 /*       */
#define NV_PMC_BOOT_42_ARCHITECTURE                           28:24 /*       */
#define NV_PMC_BOOT_42_CHIP_ID                                28:20 /* R-XVF */
#define NV_PMC_BOOT_42_CHIP_ID_GP000                     0x00000131 /* R---V */
#define NV_PMC_BOOT_42_CHIP_ID_GP100                     0x00000130 /* R---V */
#define NV_PMC_BOOT_42_CHIP_ID_GP102                     0x00000132 /* R---V */
#define NV_PMC_BOOT_42_CHIP_ID_GP104                     0x00000134 /* R---V */
#define NV_PMC_BOOT_42_CHIP_ID_GP104V                    0x00000139 /* R---V */
#define NV_PMC_BOOT_42_CHIP_ID_GP106                     0x00000136 /* R---V */
#define NV_PMC_BOOT_42_CHIP_ID_GP107                     0x00000137 /* R---V */
#define NV_PMC_BOOT_42_CHIP_ID_GP108                     0x00000138 /* R---V */
#define NV_PMC_BOOT_42_CHIP_ID_GP108V                    0x0000013A /* R---V */
#define NV_PMC_BOOT_42_CHIP_ID_GV100                     0x00000140 /* R---V */
#define NV_PMC_BOOT_42_CHIP_ID_GV10B                     0x0000014B /* R---V */
#define NV_PMC_BOOT_42_CHIP_ID_TU100                     0x00000160 /* R---V */
#define NV_PMC_BOOT_42_CHIP_ID_TU102                     0x00000162 /* R---V */
#define NV_PMC_BOOT_42_CHIP_ID_TU104                     0x00000164 /* R---V */
#define NV_PMC_BOOT_42_CHIP_ID_TU105                     0x00000165 /* R---V */
#define NV_PMC_BOOT_42_CHIP_ID_TU106                     0x00000166 /* R---V */
#define NV_PMC_BOOT_42_CHIP_ID_TU107                     0x00000167 /* R---V */
#define NV_PMC_BOOT_42_CHIP_ID_TU117                     0x00000167 /* R---V */
#define NV_PMC_BOOT_42_CHIP_ID_TU116                     0x00000168 /* R---V */
#define NV_PMC_BOOT_42_CHIP_ID_GA100                     0x00000170 /* R---V */
```

The TU104 manual adds `NV_PMC_BOOT_42_CHIP_ID_TU102 0x162`, `TU104 0x164`, `TU105 0x165`, `TU106 0x166`, `TU107/TU117 0x167`, `TU116 0x168` (also present in the GA100 list above) [NVIDIA-published], https://raw.githubusercontent.com/NVIDIA/open-gpu-doc/master/manuals/turing/tu104/dev_master.ref.txt .

For Hopper and Blackwell only the register offsets are published (`NV_PMC_BOOT_0 0x00000000`, `NV_PMC_ZB_BOOT_0 0x00000000`, `NV_PMC_ZB_BOOT_42 0x00000A00`; no field definitions) [NVIDIA-published], https://raw.githubusercontent.com/NVIDIA/open-gpu-kernel-modules/main/src/common/inc/swref/published/hopper/gh100/dev_pmc.h , https://raw.githubusercontent.com/NVIDIA/open-gpu-kernel-modules/main/src/common/inc/swref/published/blackwell/gb100/dev_pmc_zb.h . The RM identifies Turing+ chips by `NV_PMC_BOOT_42` architecture + implementation [NVIDIA-published (RM code)], https://raw.githubusercontent.com/NVIDIA/open-gpu-kernel-modules/main/src/nvidia/generated/g_hal_archimpl.h :

```c
    { NV_PMC_BOOT_42_ARCHITECTURE_GH100, NV_PMC_BOOT_42_IMPLEMENTATION_0,   0x0 } , // GH100
    { NV_PMC_BOOT_42_ARCHITECTURE_GB100, NV_PMC_BOOT_42_IMPLEMENTATION_0,   0x0 } , // GB100
    { NV_PMC_BOOT_42_ARCHITECTURE_GB100, NV_PMC_BOOT_42_IMPLEMENTATION_2,   0x0 } , // GB102
    { NV_PMC_BOOT_42_ARCHITECTURE_GB100, NV_PMC_BOOT_42_IMPLEMENTATION_B,   0x0 } , // GB10B
    { NV_PMC_BOOT_42_ARCHITECTURE_GB100, NV_PMC_BOOT_42_IMPLEMENTATION_C,   0x0 } , // GB10C
    { NV_PMC_BOOT_42_ARCHITECTURE_GB100, NV_PMC_BOOT_42_IMPLEMENTATION_3,   0x0 } , // GB110
    { NV_PMC_BOOT_42_ARCHITECTURE_GB100, NV_PMC_BOOT_42_IMPLEMENTATION_4,   0x0 } , // GB112
    { NV_PMC_BOOT_42_ARCHITECTURE_GB200, NV_PMC_BOOT_42_IMPLEMENTATION_2,   0x0 } , // GB202
    { NV_PMC_BOOT_42_ARCHITECTURE_GB200, NV_PMC_BOOT_42_IMPLEMENTATION_3,   0x0 } , // GB203
    { NV_PMC_BOOT_42_ARCHITECTURE_GB200, NV_PMC_BOOT_42_IMPLEMENTATION_5,   0x0 } , // GB205
    { NV_PMC_BOOT_42_ARCHITECTURE_GB200, NV_PMC_BOOT_42_IMPLEMENTATION_6,   0x0 } , // GB206
    { NV_PMC_BOOT_42_ARCHITECTURE_GB200, NV_PMC_BOOT_42_IMPLEMENTATION_7,   0x0 } , // GB207
    { NV_PMC_BOOT_42_ARCHITECTURE_GB200, NV_PMC_BOOT_42_IMPLEMENTATION_B,   0x0 } , // GB20B
    { NV_PMC_BOOT_42_ARCHITECTURE_GB200, NV_PMC_BOOT_42_IMPLEMENTATION_C,   0x0 } , // GB20C
    { NV_PMC_BOOT_42_ARCHITECTURE_GR100, NV_PMC_BOOT_42_IMPLEMENTATION_0,   0x0 } , // GR100
    { NV_PMC_BOOT_42_ARCHITECTURE_GR100, NV_PMC_BOOT_42_IMPLEMENTATION_2,   0x0 } , // GR102
```

nvgpu (Kepler..Ampere Tegra) uses the same BOOT_0 split [NVIDIA-published (nvgpu)], https://raw.githubusercontent.com/OE4T/linux-nvgpu/patches-rel-36/drivers/gpu/nvgpu/include/nvgpu/hw/gk20a/hw_mc_gk20a.h :

```c
#define mc_boot_0_r()                                              (0x00000000U)
#define mc_boot_0_architecture_v(r)                       (((r) >> 24U) & 0x1fU)
#define mc_boot_0_implementation_v(r)                      (((r) >> 20U) & 0xfU)
#define mc_boot_0_major_revision_v(r)                       (((r) >> 4U) & 0xfU)
#define mc_boot_0_minor_revision_v(r)                       (((r) >> 0U) & 0xfU)
```

nouveau decodes BOOT_0 bits 28:20 as the chipset and maps families (incl. `0x1a0` GB10x, `0x1b0` GB20x) [nouveau], https://raw.githubusercontent.com/torvalds/linux/master/drivers/gpu/drm/nouveau/nvkm/engine/device/base.c :

```c
	/* determine chipset and derive architecture from it */
	if ((boot0 & 0x1f000000) > 0) {
		device->chipset = (boot0 & 0x1ff00000) >> 20;
		device->chiprev = (boot0 & 0x000000ff);
		switch (device->chipset & 0x1f0) {
		case 0x010: {
			if (0x461 & (1 << (device->chipset & 0xf)))
				device->card_type = NV_10;
			else
				device->card_type = NV_11;
			device->chiprev = 0x00;
			break;
		}
		case 0x020: device->card_type = NV_20; break;
		case 0x030: device->card_type = NV_30; break;
		case 0x040:
		case 0x060: device->card_type = NV_40; break;
		case 0x050:
		case 0x080:
		case 0x090:
		case 0x0a0: device->card_type = NV_50; break;
		case 0x0c0:
		case 0x0d0: device->card_type = NV_C0; break;
		case 0x0e0:
		case 0x0f0:
		case 0x100: device->card_type = NV_E0; break;
		case 0x110:
		case 0x120: device->card_type = GM100; break;
		case 0x130: device->card_type = GP100; break;
		case 0x140: device->card_type = GV100; break;
		case 0x160: device->card_type = TU100; break;
		case 0x170: device->card_type = GA100; break;
		case 0x180: device->card_type = GH100; break;
		case 0x190: device->card_type = AD100; break;
		case 0x1a0: device->card_type = GB10x; break;
		case 0x1b0: device->card_type = GB20x; break;
```

envytools `PMC.ID` (= BOOT_0) for NV10+ [envytools], https://raw.githubusercontent.com/envytools/envytools/master/rnndb/bus/pmc.xml :

```xml
		<reg32 offset="0x000" name="ID" variants="NV10-">
			<bitfield low="0" high="7" name="STEPPING"/>
			<bitfield low="16" high="19" name="DEVICE_ID" variants="NV10:G92"/>
			<bitfield low="15" high="19" name="DEVICE_ID" variants="G92:GF119"/>
			<bitfield low="12" high="17" name="DEVICE_ID" variants="GF119-"/>
			<bitfield low="20" high="28" name="CHIPSET" type="chipset"/>
			<bitfield low="29" high="31" name="FOUNDRY">
				<value value="0" name="TSMC"/>
				<value value="1" name="UMC"/>
				<value value="2" name="IBM"/>
			</bitfield>
		</reg32>
```

## 5.2 Architecture and implementation constants (RM)

https://raw.githubusercontent.com/NVIDIA/open-gpu-kernel-modules/main/src/common/inc/swref/published/nv_arch.h [NVIDIA-published]:

```c
#define GPU_ARCHITECTURE_MAXWELL         GPU_ARCHITECTURE(_CLASSIC, 0x0110)
#define GPU_ARCHITECTURE_MAXWELL2        GPU_ARCHITECTURE(_CLASSIC, 0x0120)
#define GPU_ARCHITECTURE_PASCAL          GPU_ARCHITECTURE(_CLASSIC, 0x0130)
#define GPU_ARCHITECTURE_VOLTA           GPU_ARCHITECTURE(_CLASSIC, 0x0140)
#define GPU_ARCHITECTURE_VOLTA2          GPU_ARCHITECTURE(_CLASSIC, 0x0150)
#define GPU_ARCHITECTURE_TURING          GPU_ARCHITECTURE(_CLASSIC, 0x0160)
#define GPU_ARCHITECTURE_AMPERE          GPU_ARCHITECTURE(_CLASSIC, 0x0170)
#define GPU_ARCHITECTURE_HOPPER          GPU_ARCHITECTURE(_CLASSIC, 0x0180)
#define GPU_ARCHITECTURE_ADA             GPU_ARCHITECTURE(_CLASSIC, 0x0190)
#define GPU_ARCHITECTURE_BLACKWELL_GB1XX GPU_ARCHITECTURE(_CLASSIC, 0x01A0)

#define GPU_ARCHITECTURE_BLACKWELL_GB2XX GPU_ARCHITECTURE(_CLASSIC, 0x01B0)

#define GPU_ARCHITECTURE_RUBIN_GR1XX     GPU_ARCHITECTURE(_CLASSIC, 0x1C0)

#define GPU_ARCHITECTURE_T12X            GPU_ARCHITECTURE(_TEGRA,   0x0040)
#define GPU_ARCHITECTURE_T13X            GPU_ARCHITECTURE(_TEGRA,   0x0013)
#define GPU_ARCHITECTURE_T21X            GPU_ARCHITECTURE(_TEGRA,   0x0021)
#define GPU_ARCHITECTURE_T18X            GPU_ARCHITECTURE(_TEGRA,   0x0018)
#define GPU_ARCHITECTURE_T19X            GPU_ARCHITECTURE(_TEGRA,   0x0019)
#define GPU_ARCHITECTURE_T23X            GPU_ARCHITECTURE(_TEGRA,   0x0023)

#define GPU_ARCHITECTURE_T26X            GPU_ARCHITECTURE(_TEGRA, 0x0026)
#define GPU_IMPLEMENTATION_GM108         0x08
#define GPU_IMPLEMENTATION_GM107         0x07
#define GPU_IMPLEMENTATION_GM200         0x00
#define GPU_IMPLEMENTATION_GM204         0x04
#define GPU_IMPLEMENTATION_GM206         0x06

#define GPU_IMPLEMENTATION_GP100         0x00
#define GPU_IMPLEMENTATION_GP102         0x02
#define GPU_IMPLEMENTATION_GP104         0x04
#define GPU_IMPLEMENTATION_GP106         0x06
#define GPU_IMPLEMENTATION_GP107         0x07
#define GPU_IMPLEMENTATION_GP108         0x08

#define GPU_IMPLEMENTATION_GV100         0x00
#define GPU_IMPLEMENTATION_GV11B         0x0B

#define GPU_IMPLEMENTATION_TU102         0x02
#define GPU_IMPLEMENTATION_TU104         0x04
#define GPU_IMPLEMENTATION_TU106         0x06
#define GPU_IMPLEMENTATION_TU116         0x08    // TU116 has implementation ID 8 in HW
#define GPU_IMPLEMENTATION_TU117         0x07

#define GPU_IMPLEMENTATION_GA100         0x00
#define GPU_IMPLEMENTATION_GA102         0x02
#define GPU_IMPLEMENTATION_GA103         0x03
#define GPU_IMPLEMENTATION_GA104         0x04
#define GPU_IMPLEMENTATION_GA106         0x06
#define GPU_IMPLEMENTATION_GA107         0x07
#define GPU_IMPLEMENTATION_GA102F        0x0F

#define GPU_IMPLEMENTATION_GH100         0x00
#define GPU_IMPLEMENTATION_AD102         0x02
#define GPU_IMPLEMENTATION_AD103         0x03
#define GPU_IMPLEMENTATION_AD104         0x04
#define GPU_IMPLEMENTATION_AD106         0x06
#define GPU_IMPLEMENTATION_AD107         0x07

#define GPU_IMPLEMENTATION_GB100         0x00
#define GPU_IMPLEMENTATION_GB102         0x02

#define GPU_IMPLEMENTATION_GB10B         0x0B

#define GPU_IMPLEMENTATION_GB10C         0x0C

#define GPU_IMPLEMENTATION_GB110         0x03

#define GPU_IMPLEMENTATION_GB112         0x04

#define GPU_IMPLEMENTATION_GB202         0x02

#define GPU_IMPLEMENTATION_GB203         0x03

#define GPU_IMPLEMENTATION_GB205         0x05

#define GPU_IMPLEMENTATION_GB206         0x06

#define GPU_IMPLEMENTATION_GB207         0x07

#define GPU_IMPLEMENTATION_GB20B         0x0B

#define GPU_IMPLEMENTATION_GB20C         0x0C

#define GPU_IMPLEMENTATION_GR100         0x00

#define GPU_IMPLEMENTATION_GR102         0x02

#define GPU_IMPLEMENTATION_T124          0x00
#define GPU_IMPLEMENTATION_T132          0x00
#define GPU_IMPLEMENTATION_T210          0x00
#define GPU_IMPLEMENTATION_T186          0x00
#define GPU_IMPLEMENTATION_T194          0x00
#define GPU_IMPLEMENTATION_T234          0x04
#define GPU_IMPLEMENTATION_T234D         0x05

#define GPU_IMPLEMENTATION_T264D         0x05

#define GPU_IMPLEMENTATION_T238D         0x0B
```

(`GPU_ARCHITECTURE_*` is the RM's 24-bit value; its top nine bits shifted down are the BOOT_0 chipset prefix, e.g. 0x0170 -> 0x17x for Ampere [derived, consistent with the manual values above and nouveau].)

## 5.3 Tegra GPU IDs

nvgpu [NVIDIA-published (nvgpu)], https://raw.githubusercontent.com/OE4T/linux-nvgpu/patches-rel-36/drivers/gpu/nvgpu/include/nvgpu/gk20a.h :

```c
#define GK20A_GPUID(arch, impl) ((u32) ((arch) | (impl)))
#define GK20A_GPUID_GK20A   0x000000EAU
#define GK20A_GPUID_GM20B   0x0000012BU
#define GK20A_GPUID_GM20B_B 0x0000012EU
#define NVGPU_GPUID_GP10B   0x0000013BU
#define NVGPU_GPUID_GV11B   0x0000015BU
#define NVGPU_GPUID_GV100   0x00000140U
#define NVGPU_GPUID_TU104   0x00000164U
#define NVGPU_GPUID_GA100   0x00000170U
#define NVGPU_GPUID_GA10B   0x0000017BU
```

envytools table rows (chipset in column 4) for Kepler..Turing [envytools], https://raw.githubusercontent.com/envytools/envytools/master/docs/hw/gpu.rst :

```text
core  hda   id   name        TPCs MPs/TPC PARTs date       notes
core  hda   usb   id    name   GPCs TPCs PARTs MCs ZCULLs PCOPYs HEADs UNK7 PPCs SUBPs SPOONs CE0 CE1 CE2 date
pciid pciid pciid                   /GPC           /GPC                     /GPC /PART
118X* 0e0a  \-    0xe4  GK104  4    2    4     4   4      3      4     \-   1    4     3      ?   3   3   22.03.2012
0fcX* 0e1b  \-    0xe7  GK107  1    2    2     2   4      3      4     \-   1    4     3      3   ?   3   24.04.2012
11cX+ 0e0b  \-    0xe6  GK106  3    2    3     3   4      3      4     \-   1    4     3      3   ?   3   22.04.2012
100X+ 0e1a  \-    0xf0  GK110  5    3    6     6   4      3      4     \-   2    4     3      ?   ?   ?   21.02.2013
100X+ 0e1a  \-    0xf1  GK110B 5    3    6     6   4      3      4     \-   2    4     3      ?   3   3   07.11.2013
128X+ 0e0f  \-    0x108 GK208  1    2    1     1   4      3      4     \-   1    2     2      3   ?   3   19.02.2013
128X+ 0e0f  \-    0x106 GK208B 1    2    1     1   4      3      4     \-   1?   2?    2?     3   ?   3   ???
\-    \-    \-    0xea  GK20A  1    1    1     1   4      3      \-[4] \-   1    1     1      \-? \-? 3   ?
138X+ 0fbc  \-    0x117 GM107  1    5    2     2   4      3      4     1    2    4     2      3   ?   3   18.02.2014
134X+ \???? \-    0x118 GM108  1    3    1     1   4      3      4     0    ?    ?     2      3   ?   3   ?
13cX+ 0fbb  \-    0x124 GM204  ?    ?    ?     ?   ?      ?      ?     ?    ?    ?     ?      ?   ?   ?   ?
17cX+ 0fb0  \-    0x120 GM200  ?    ?    ?     ?   ?      ?      ?     ?    ?    ?     ?      ?   ?   ?   ?
140X+ 0fba  \-    0x126 GM206  ?    ?    ?     ?   ?      ?      ?     ?    ?    ?     ?      ?   ?   ?   ?
\-    \-    \-    0x12b GM20B  ?    ?    ?     ?   ?      ?      ?     ?    ?    ?     ?      ?   ?   ?   ?
158X# \???? \-    0x130 GP100  ?    ?    ?     ?   ?      ?      ?     ?    ?    ?     ?      ?   ?   ?   ?
1b0X# 10ef  \-    0x132 GP102  ?    ?    ?     ?   ?      ?      ?     ?    ?    ?     ?      ?   ?   ?   ?
1b8X# 10f0  \-    0x134 GP104  4    5    4     4   4      4      4     2    ?    ?     ?      ?   ?   ?   ?
1c0X# 10f1  \-    0x136 GP106  ?    ?    ?     ?   ?      ?      ?     ?    ?    ?     ?      ?   ?   ?   ?
1c8X# 0fb9  \-    0x137 GP107  ?    ?    ?     ?   ?      ?      ?     ?    ?    ?     ?      ?   ?   ?   10.25.2016
1d0X# 0fb8  \-    0x138 GP108  ?    ?    ?     ?   ?      ?      ?     ?    ?    ?     ?      ?   ?   ?   ?
10e5* \-    \-    0x13b GP10B  ?    ?    ?     ?   ?      ?      ?     ?    ?    ?     ?      ?   ?   ?   14.03.2017
1d8X# 10f2  \-    0x140 GV100  6    7    ?     ?   ?      ?      ?     ?    ?    ?     ?      ?   ?   ?   12.07.2017
\-    \-    \-    0x15b GV11B  ?    ?    ?     ?   ?      ?      ?     ?    ?    ?     ?      ?   ?   ?   03.06.2018
1e0X# 10f7  1ad6  0x162 TU102  6    6    ?     ?   ?      ?      ?     ?    ?    ?     ?      ?   ?   ?   27.09.2018
1e8X# 10f8  1ad8  0x164 TU104  6    4    ?     ?   ?      ?      ?     ?    ?    ?     ?      ?   ?   ?   20.09.2018
1f0X# 10f9  1ada  0x166 TU106  3    6    ?     ?   ?      ?      ?     ?    ?    ?     ?      ?   ?   ?   17.10.2018
218X# 1aeb  \-    0x168 TU116  3    4    ?     ?   ?      ?      ?     ?    ?    ?     ?      ?   ?   ?   22.02.2019
1f8X# ????  \-    0x167 TU117  2    4    ?     ?   ?      ?      ?     ?    ?    ?     ?      ?   ?   ?   23.04.2019
```

## 5.4 Chip table

Chipset = BOOT_0[28:20]. "nouveau mmu/fifo" = constructor names in nouveau `engine/device/base.c` [nouveau]. CC = CUDA compute capability. NVML = `NVML_DEVICE_ARCH_*` value (5.5).

| Chipset | Chip | Generation | Source of ID | nouveau mmu / fifo | GMMU format | CUDA CC | NVML arch |
|---|---|---|---|---|---|---|---|
| 0x0E4 | GK104 | Kepler | nouveau, envytools | gk104 / gk104 | VER1 | 3.0 | 2 |
| 0x0E6 | GK106 | Kepler | nouveau, envytools | gk104 / gk104 | VER1 | 3.0 | 2 |
| 0x0E7 | GK107 | Kepler | nouveau, envytools | gk104 / gk104 | VER1 | 3.0 | 2 |
| 0x0EA | GK20A (Tegra K1) | Kepler | nouveau, envytools, nvgpu | gk20a / gk20a | VER1 | 3.2 | 2 |
| 0x0F0 | GK110 | Kepler | nouveau, envytools | gk104 / gk110 | VER1 | 3.5 | 2 |
| 0x0F1 | GK110B | Kepler | nouveau, envytools | gk104 / gk110 | VER1 | 3.5 | 2 |
| not found | GK210 | Kepler | listed by name only in envytools | - | VER1 [derived] | 3.7 (Tesla K80) | 2 |
| 0x106 | GK208B | Kepler | nouveau, envytools | gk104 / gk208 | VER1 | 3.5 | 2 |
| 0x108 | GK208 | Kepler | nouveau, envytools | gk104 / gk208 | VER1 | 3.5 | 2 |
| 0x117 | GM107 | Maxwell | nouveau, envytools | gk104 / gm107 | VER1 | 5.0 | 3 |
| 0x118 | GM108 | Maxwell | nouveau, envytools | gk104 / gm107 | VER1 | 5.0 | 3 |
| 0x120 | GM200 | Maxwell | nouveau, envytools | gm200 / gm200 | VER1 | 5.2 | 3 |
| 0x124 | GM204 | Maxwell | nouveau, envytools | gm200 / gm200 | VER1 | 5.2 | 3 |
| 0x126 | GM206 | Maxwell | nouveau, envytools | gm200 / gm200 | VER1 | 5.2 | 3 |
| 0x12B | GM20B (Tegra X1) | Maxwell | nouveau, envytools, nvgpu | gm20b / gm200 | VER1 | 5.3 | 3 |
| 0x12E | GM20B_B | Maxwell | nvgpu only | - | VER1 [derived] | 5.3 [derived] | 3 |
| 0x130 | GP100 | Pascal | nouveau, manual, envytools | gp100 / gp100 | VER1 or VER2 | 6.0 | 4 |
| 0x132 | GP102 | Pascal | nouveau, manual | gp100 / gp100 | VER1 or VER2 | 6.1 | 4 |
| 0x134 | GP104 | Pascal | nouveau, manual | gp100 / gp100 | VER1 or VER2 | 6.1 | 4 |
| 0x136 | GP106 | Pascal | nouveau, manual | gp100 / gp100 | VER1 or VER2 | 6.1 | 4 |
| 0x137 | GP107 | Pascal | nouveau, manual | gp100 / gp100 | VER1 or VER2 | 6.1 | 4 |
| 0x138 | GP108 | Pascal | nouveau, manual | gp100 / gp100 | VER1 or VER2 | 6.1 | 4 |
| 0x13B | GP10B (Tegra X2) | Pascal | nouveau, envytools, nvgpu | gp10b / gp100 | VER1 or VER2 | 6.2 | 4 |
| 0x140 | GV100 | Volta | nouveau, manual, nvgpu | gv100 / gv100 | VER2 | 7.0 | 5 |
| 0x14B | GV10B | Volta | manual (`CHIP_ID_GV10B`) only | - | VER2 [derived] | unknown | 5 |
| 0x15B | GV11B (Xavier) | Volta | nvgpu, envytools | - (not in nouveau) | VER2 | 7.2 | 5 |
| 0x162 | TU102 | Turing | nouveau, manual | tu102 / tu102 | VER2 | 7.5 | 6 |
| 0x164 | TU104 | Turing | nouveau, manual | tu102 / tu102 | VER2 | 7.5 | 6 |
| 0x166 | TU106 | Turing | nouveau, manual | tu102 / tu102 | VER2 | 7.5 | 6 |
| 0x167 | TU117 | Turing | nouveau, manual | tu102 / tu102 | VER2 | 7.5 | 6 |
| 0x168 | TU116 | Turing | nouveau, manual | tu102 / tu102 | VER2 | 7.5 | 6 |
| 0x170 | GA100 | Ampere | nouveau, manual, nvgpu | tu102 / ga100 | VER2 | 8.0 | 7 |
| 0x172 | GA102 | Ampere | nouveau | tu102 / ga102 | VER2 | 8.6 | 7 |
| 0x173 | GA103 | Ampere | nouveau | tu102 / ga102 | VER2 | 8.6 | 7 |
| 0x174 | GA104 | Ampere | nouveau | tu102 / ga102 | VER2 | 8.6 | 7 |
| 0x176 | GA106 | Ampere | nouveau | tu102 / ga102 | VER2 | 8.6 | 7 |
| 0x177 | GA107 | Ampere | nouveau | tu102 / ga102 | VER2 | 8.6 | 7 |
| 0x17B | GA10B (Orin) | Ampere | nvgpu, Mesa | - (not in nouveau) | VER2 | 8.7 | 7 |
| 0x17F | GA102F | Ampere | [derived] from nv_arch.h impl 0x0F | - | VER2 [derived] | unknown | 7 |
| 0x180 | GH100 | Hopper | nouveau | gh100 / ga102 | VER3 | 9.0 | 9 |
| 0x192 | AD102 | Ada | nouveau | tu102 / ga102 | VER2 | 8.9 | 8 |
| 0x193 | AD103 | Ada | nouveau | tu102 / ga102 | VER2 | 8.9 | 8 |
| 0x194 | AD104 | Ada | nouveau | tu102 / ga102 | VER2 | 8.9 | 8 |
| 0x196 | AD106 | Ada | nouveau | tu102 / ga102 | VER2 | 8.9 | 8 |
| 0x197 | AD107 | Ada | nouveau | tu102 / ga102 | VER2 | 8.9 | 8 |
| 0x1A0 | GB100 | Blackwell | nouveau | gh100 / ga102 | VER3 | 10.x (Mesa: 10.0) | 10 |
| 0x1A2 | GB102 | Blackwell | nouveau | gh100 / ga102 | VER3 | 10.x (Mesa: 10.0) | 10 |
| 0x1A3 | GB110 | Blackwell | [derived] RM arch GB100 + impl 3 | - | VER3 | not confirmed per chip | 10 |
| 0x1A4 | GB112 | Blackwell | [derived] RM arch GB100 + impl 4 | - | VER3 | not confirmed per chip | 10 |
| 0x1AB | GB10B | Blackwell (Tegra) | [derived] RM arch GB100 + impl 0xB | - | VER3 | not confirmed per chip | 10 |
| 0x1AC | GB10C | Blackwell | [derived] RM arch GB100 + impl 0xC | - | VER3 | not confirmed per chip | 10 |
| 0x1B2 | GB202 | Blackwell | nouveau | gh100 / ga102 | VER3 | 12.0 | 10 |
| 0x1B3 | GB203 | Blackwell | nouveau | gh100 / ga102 | VER3 | 12.0 | 10 |
| 0x1B5 | GB205 | Blackwell | nouveau | gh100 / ga102 | VER3 | 12.0 | 10 |
| 0x1B6 | GB206 | Blackwell | nouveau | gh100 / ga102 | VER3 | 12.0 | 10 |
| 0x1B7 | GB207 | Blackwell | nouveau | gh100 / ga102 | VER3 | 12.0 | 10 |
| 0x1BB | GB20B | Blackwell (Tegra) | [derived] RM arch GB200 + impl 0xB | - | VER3 | not confirmed per chip | 10 |
| 0x1BC | GB20C | Blackwell | [derived] RM arch GB200 + impl 0xC | - | VER3 | not confirmed per chip | 10 |
| 0x1C0 / 0x1C2 | GR100 / GR102 | Rubin | [derived] RM arch GR100 + impl 0/2 | - | VER3 | unknown | 13 |

Notes on the table:
- "manual" = `NV_PMC_BOOT_42_CHIP_ID_*` in the Volta/Turing/Ampere manuals (5.1) [NVIDIA-published]. The manuals also list `GP000 0x131`, `GP104V 0x139`, `GP108V 0x13A`, `TU100 0x160`, `TU105 0x165`.
- [derived] IDs are architecture prefix (from `nv_arch.h` and nouveau's `0x1a0`/`0x1b0` families) combined with `GPU_IMPLEMENTATION_*` from `nv_arch.h` and the `g_hal_archimpl.h` pairing (5.1, 5.2). No source lists these numeric chipset values directly.
- GMMU format column: from 1.1, 4.1 and the RM HAL bindings; Tegra parts not handled by open RM or nouveau (GV11B, GA10B) are assigned by architecture [derived], and their nvgpu headers define VER2 (`gmmu_new_*`) fields [NVIDIA-published (nvgpu)].
- CUDA CC sources: 5.6.
- Product names in parentheses for Tegra (Tegra K1/X1/X2, Xavier, Orin) are the commonly used names; the nvgpu sources give only the GPUID. Which Blackwell chip is in Jetson Thor (CC 11.0), DGX Spark GB10 (CC 12.1) or B300 (CC 10.3) is **not stated in any source collected here** [derived gap].

## 5.5 NVML architecture IDs

https://raw.githubusercontent.com/NVIDIA/go-nvml/main/gen/nvml/nvml.h [NVIDIA-published]:

```c
#define NVML_DEVICE_ARCH_KEPLER    2 //!< Devices based on the NVIDIA Kepler architecture
#define NVML_DEVICE_ARCH_MAXWELL   3 //!< Devices based on the NVIDIA Maxwell architecture
#define NVML_DEVICE_ARCH_PASCAL    4 //!< Devices based on the NVIDIA Pascal architecture
#define NVML_DEVICE_ARCH_VOLTA     5 //!< Devices based on the NVIDIA Volta architecture
#define NVML_DEVICE_ARCH_TURING    6 //!< Devices based on the NVIDIA Turing architecture
#define NVML_DEVICE_ARCH_AMPERE    7 //!< Devices based on the NVIDIA Ampere architecture
#define NVML_DEVICE_ARCH_ADA       8 //!< Devices based on the NVIDIA Ada architecture
#define NVML_DEVICE_ARCH_HOPPER    9 //!< Devices based on the NVIDIA Hopper architecture

#define NVML_DEVICE_ARCH_BLACKWELL 10 //!< Devices based on the NVIDIA Blackwell architecture

#define NVML_DEVICE_ARCH_DLA       11 //!< Devices based on the NVIDIA DLA architecture.
#define NVML_DEVICE_ARCH_DLA2      12 //!< Devices based on the NVIDIA DLA2 architecture.

#define NVML_DEVICE_ARCH_RUBIN     13 //!< Devices based on the NVIDIA Rubin architecture.

#define NVML_DEVICE_ARCH_NPU3      15 //!< Devices based on the NVIDIA NPU3 architecture.

#define NVML_DEVICE_ARCH_UNKNOWN   0xffffffff //!< Anything else, presumably something newer
```

(Value 14 is not defined in this header.)

## 5.6 CUDA compute capability

Per chipset (coarse, used by NVK) [nouveau (Mesa)], https://gitlab.freedesktop.org/mesa/mesa/-/raw/main/src/nouveau/winsys/nouveau_device.c :

```c
sm_for_chipset(uint16_t chipset)
{
   if (chipset >= 0x1b0)
      return 120;
   else if (chipset >= 0x1a0)
      return 100;
   else if (chipset >= 0x190)
      return 89;
   // GH100 is older than AD10X, but is SM90
   else if (chipset >= 0x180)
      return 90;
   else if (chipset == 0x17b)
      return 87;
   else if (chipset >= 0x172)
      return 86;
   else if (chipset >= 0x170)
      return 80;
   else if (chipset >= 0x160)
      return 75;
   else if (chipset >= 0x14b)
      return 72;
   else if (chipset >= 0x140)
      return 70;
   else if (chipset >= 0x13b)
      return 62;
   else if (chipset >= 0x132)
      return 61;
   else if (chipset >= 0x130)
      return 60;
   else if (chipset >= 0x12b)
      return 53;
   else if (chipset >= 0x120)
      return 52;
   else if (chipset >= 0x110)
      return 50;
   // TODO: 37
   else if (chipset >= 0x0f0)
      return 35;
   else if (chipset >= 0x0ea)
      return 32;
   else if (chipset >= 0x0e0)
      return 30;
   // GF110 is SM20
   else if (chipset == 0x0c8)
      return 20;
   else if (chipset >= 0x0c1)
      return 21;
   else if (chipset >= 0x0c0)
      return 20;
   else if (chipset >= 0x0a3)
      return 12;
   // GT200 is SM13
   else if (chipset >= 0x0a0)
      return 13;
   else if (chipset >= 0x080)
      return 11;
   // this has to be == because 0x63 is older than 0x50 and has no compute
   else if (chipset == 0x050)
      return 10;
   // no compute
   return 0x00;
}
```

Per product [NVIDIA-published]:
- https://developer.nvidia.com/cuda-gpus : 12.1 GB10 (DGX Spark), RTX Spark N1X; 12.0 GeForce RTX 50 series, RTX PRO Blackwell; 11.0 Jetson T5000/T4000; 10.3 GB300, B300; 10.0 GB200, B200; 9.0 GH200, H200, H100; 8.9 L4/L40/RTX 40; 8.7 Jetson AGX Orin / Orin NX / Orin Nano; 8.6 A40/A10/RTX 30; 8.0 A100, A30; 7.5 T4, RTX 20, GTX 16.
- https://developer.nvidia.com/cuda/gpus/legacy : 3.0 GTX 680/670; 3.2 Jetson TK1; 3.5 Tesla K40/K20, GTX TITAN/780 Ti/780, GT 730; 3.7 Tesla K80; 5.0 GTX 750 Ti; 5.2 Tesla M40/M60, GTX TITAN X/980/970; 5.3 Jetson Nano; 6.0 Tesla P100; 6.1 GTX 1080/1070/1060/1050; 6.2 Jetson TX2; 7.0 V100, TITAN V, Quadro GV100; 7.2 Jetson AGX Xavier / Xavier NX.

Mesa's table is coarse for Blackwell: it maps every `0x1a?` chip to SM 10.0 and every `0x1b?` chip to SM 12.0, while NVIDIA lists 10.3 (B300), 11.0 (Thor) and 12.1 (GB10) products [derived comparison]. Mesa has no SM 3.7 case (`// TODO: 37`).

---

# Topic 6: Page sizes per generation

| Generation | Format | Small page | Big page | Page at PD0 | Page at PD1 | Page at PD2 | Source |
|---|---|---|---|---|---|---|---|
| Fermi, Kepler, GM10x | VER1 | 4 KiB | 128 KiB (default) or 64 KiB, chosen globally by MMIO 0x100c80 bit 0 | - | - | - | [nouveau] 1.7, 1.8 |
| GM20x, GM20B | VER1 | 4 KiB | 64 KiB or 128 KiB per instance block (RAMIN 0x200 bit 11 = 1 for 64 KiB) | - | - | - | [nouveau], [NVIDIA-published (nvgpu)] 1.8 |
| Pascal (VER1 mode) | VER1 | 4 KiB | 64/128 KiB (`NV_RAMIN_BIG_PAGE_SIZE`) | - | - | - | [NVIDIA-published] 1.9 |
| Pascal (VER2 mode), Volta, Turing | VER2 | 4 KiB | 64 KiB (the `GP10X` level code also accepts 128 KiB; Volta+ subcontext PDBs are forced to 64 KiB) | 2 MiB | - | - | [NVIDIA-published (RM code)] 1.8, 1.9, 4.2 |
| Ampere, Ada | VER2 | 4 KiB | 64 KiB | 2 MiB | 512 MiB (RM `GA10X`) | - | [NVIDIA-published (RM code)] 4.2 |
| Hopper | VER3 | 4 KiB | 64 KiB | 2 MiB | 512 MiB | - | [NVIDIA-published (RM code)], [nouveau] 4.2, 4.3 |
| Blackwell, Rubin | VER3 | 4 KiB | 64 KiB | 2 MiB | 512 MiB | 256 GiB (RM `GB10X`) | [NVIDIA-published (RM code)] 4.2 |

Notes:
- nouveau never maps 512 MiB pages on Pascal..Ada (shift 29 is sparse-only in `gp100_vmm`) but does on GH100 and later (`{ 29, ..., NVKM_VMM_PAGE_SVxC }`) [nouveau, 4.3]. A dump parser should still accept a PD1 PTE on Ampere/Ada because the RM may create one [derived].
- VER2/VER3 tell a PTE apart from a PDE at a dual-role level by bit 0 (`VALID` / `IS_PTE`) [NVIDIA-published: `NV_MMU_VER3_PDE_IS_PTE 0:0`, Rubin's `NV_MMU_NEW_PDE_IS_PTE 0:0`; RM `gmmuFmtEntryIsPte` reads the PTE VALID bit for levels that are both PT and PD (https://raw.githubusercontent.com/NVIDIA/open-gpu-kernel-modules/main/src/nvidia/src/libraries/mmu/gmmu_fmt.c)].
- Physical address reach [derived from the field widths]: VER1 PTE 40-bit system / 37-bit VRAM; VER2 58-bit system / 37-bit VRAM; VER3 52-bit (Rubin header: 40-bit VRAM alias).

---

# Implications for Keto [derived]

These follow from the facts above; they are not statements from any source.

1. A RAMFC signature scan at +0x10 finds Kepler..Hopper channels but misses Blackwell and Rubin, where the signature (`0x0000face` in bits 15:0) is at +0x38 and GPFIFO base/LIMIT2 are at 0x90/0x94/0xB4.
2. The current `volta_plus` layout reads USERD from RAMFC 0x08/0x0C; those words are reserved from Ampere on. On Ampere+ USERD comes only from the runlist entry (`CHAN_USERD_PTR_LO/HI`).
3. The current `chid_hint` 0xE8 is NVIDIA-documented for Kepler..Volta (nvgpu `ram_fc_chid_w() (58U)`); on Turing..Hopper use SET_CHANNEL_INFO 0xFC bits 27:16, on GB1xx/GR1xx 0x58 bits 27:16, and on GB2xx there is no RAMFC CHID.
4. Hopper GPFIFO size comes from 0xA4 bits 4:0, not 0x4C bits 20:16.
5. Pre-Volta runlists are parseable from GM107 on (8-byte entries with `inst >> 12` in word1, per nouveau); Kepler runlists carry only CHIDs.
6. VER1 needs a 40-bit, two-level walker with both big-page splits; the instance block does not record the big page size before GM20x.
7. The format version is implied by chipset: VER1 for Fermi..Maxwell, RAMIN bit 10 for Pascal, VER2 for Volta..Ada, VER3 for Hopper+ (bit 10 is not reliable there).
8. `0xcafeca11` at RAMIN+0x20C is an extra instance-block signature on GA10B and on Blackwell/Rubin (RM-written).

---

# Not found / open questions

- **Discrete Kepler reference headers:** NVIDIA publishes no `dev_mmu.h`/`dev_ram.h` for GK104/GK110/GK208 (only `kepler/gk104/dev_timer.h`). Kepler facts rely on nvgpu GK20A (same architecture) and nouveau.
- **GK210 chipset ID:** not found in nouveau, envytools (name only) or NVIDIA headers.
- **Meaning of `NV_MMU_PDE_SIZE` (FULL/HALF/QUARTER/EIGHTH):** NVIDIA gives only the names; envytools calls it `PT_SIZE` (FULL/64M/32M/16M). Which page table it truncates is not stated.
- **Maxwell/Pascal 8-byte runlist word1:** the instance pointer comes from nouveau only; NVIDIA's GM107/nvgpu headers do not define word1 fields.
- **Hopper/Blackwell full manuals:** only delta headers are published. Blackwell USERD words other than GP_PUT, and Blackwell RAMFC fields other than those listed in 2.9 (for example PB_GET/PB_PUT, semaphores), are not published.
- **GB20x channel ID in RAMFC:** the RM does not write it; no other source gives a location.
- **BOOT_0 field layout on Hopper/Blackwell/Rubin:** only offsets are published; the 28:24/23:20 split is inferred from nouveau's decoding of `0x180`/`0x1a0`/`0x1b0`.
- **Numeric chipset IDs for GB110, GB112, GB10B, GB10C, GB20B, GB20C, GR100, GR102:** derived, not listed anywhere.
- **Chip to product mapping for Thor, GB10 (DGX Spark), B300, GB102:** not found in a primary source; per-chip CUDA CC for these is therefore unconfirmed.
- **GV10B (0x14B)** appears only as a manual constant; no driver supports it and its CC is unknown.
- **GA10B/GV11B GMMU level split:** not in open RM (disabled HAL) or nouveau; assumed equal to the discrete chip of the same architecture.
- **envytools** has no written content for GF100+ VM or PFIFO (stub pages); only the rnndb bitsets and the chip table were usable.
- **nouveau on GSP chips** (Turing+ with GSP firmware) may have RAMFC filled by GSP-RM rather than by the nouveau writers quoted here; the quoted nouveau RAMFC writers are authoritative only for the non-GSP paths.
