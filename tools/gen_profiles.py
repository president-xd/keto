#!/usr/bin/env python3
"""Regenerate keto/symbols/nvidia/<arch>.json from one sourced table.

Sources (all collected in docs/research/): chip table, NVML architecture ids and CUDA
compute capabilities from NVIDIA_HW_FACTS.md section 5; page-table format per chip
from section 4.1; structure layouts from section 2.10; engine classes per chip from
NVIDIA_COMMAND_FACTS.md section 0.
"""

import json
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "keto", "symbols", "nvidia")

MMU_NOTES = {
    "v1": "GMMU VER1 (40-bit VA, dual big/small PDE, 64/128 KiB big pages): NVIDIA published maxwell/gm107 dev_mmu.h; "
          "split from nouveau gf100/gk104/gm200 VMM descriptors (NVIDIA_HW_FACTS.md 1.2-1.8).",
    "v2": "GMMU VER2 PDE/dual-PDE/PTE: NVIDIA published pascal/gp100 dev_mmu.h; 5-level split 2/9/9/8/9(+12); 2 MiB pages "
          "at PD0, 512 MiB at PD1 (Ampere+) (NVIDIA_HW_FACTS.md 4.2, topic 6).",
    "v3": "GMMU VER3 incl. PCF: NVIDIA published hopper/gh100 dev_mmu.h; 6-level split 1/9/9/9/8/9(+12) per RM/nouveau "
          "gh100 descriptors; Blackwell adds 256 GiB pages at PD2 (NVIDIA_HW_FACTS.md 4.2-4.4).",
}

PROFILES = {
    "kepler": dict(architecture="Kepler", family="GK10x/GK110/GK208/GK20A", nvml_arch=2, cc=["3.0", "3.2", "3.5", "3.7"],
                   chipsets={"0x0e4": "GK104", "0x0e6": "GK106", "0x0e7": "GK107", "0x0ea": "GK20A (Tegra K1)",
                             "0x0f0": "GK110", "0x0f1": "GK110B", "0x106": "GK208B", "0x108": "GK208"},
                   mmu=dict(format="v1", va_bits=40, big_page_sizes=[131072, 65536]), layout="kepler",
                   classes={"host": "0xA06F", "compute": "0xA0C0", "copy": "0xA0B5", "3d": "0xA097"},
                   names=["GTX 6", "GTX 7", "GT 7", "Tesla K", "Quadro K", "TITAN Black", "TITAN Z", "GK1", "GK2"]),
    "maxwell": dict(architecture="Maxwell", family="GM10x/GM20x/GM20B", nvml_arch=3, cc=["5.0", "5.2", "5.3"],
                    chipsets={"0x117": "GM107", "0x118": "GM108", "0x120": "GM200", "0x124": "GM204", "0x126": "GM206",
                              "0x12b": "GM20B (Tegra X1)", "0x12e": "GM20B_B"},
                    mmu=dict(format="v1", va_bits=40, big_page_sizes=[131072, 65536]), layout="maxwell_pascal",
                    classes={"host": "0xB06F", "compute": "0xB1C0", "copy": "0xB0B5", "3d": "0xB197"},
                    names=["GTX 9", "GTX 750", "GTX 745", "Tesla M", "Quadro M", "TITAN X (Maxwell)", "GM1", "GM2"]),
    "pascal": dict(architecture="Pascal", family="GP10x/GP10B", nvml_arch=4, cc=["6.0", "6.1", "6.2"],
                   chipsets={"0x130": "GP100", "0x132": "GP102", "0x134": "GP104", "0x136": "GP106", "0x137": "GP107",
                             "0x138": "GP108", "0x13b": "GP10B (Tegra X2)"},
                   mmu=dict(format="v2", va_bits=49, big_page_sizes=[65536, 131072]), layout="maxwell_pascal",
                   classes={"host": "0xC06F", "compute": "0xC1C0", "copy": "0xC0B5", "3d": "0xC197"},
                   names=["GTX 10", "GT 1030", "Quadro P", "Tesla P", "TITAN X", "TITAN Xp", "GP10"]),
    "volta": dict(architecture="Volta", family="GV100/GV11B", nvml_arch=5, cc=["7.0", "7.2"],
                  chipsets={"0x140": "GV100", "0x14b": "GV10B", "0x15b": "GV11B (Xavier)"},
                  mmu=dict(format="v2", va_bits=49, big_page_sizes=[65536]), layout="volta",
                  classes={"host": "0xC36F", "compute": "0xC3C0", "copy": "0xC3B5", "3d": "0xC397"},
                  names=["V100", "TITAN V", "Quadro GV100", "GV10"]),
    "turing": dict(architecture="Turing", family="TU10x/TU11x", nvml_arch=6, cc=["7.5"],
                   chipsets={"0x162": "TU102", "0x164": "TU104", "0x166": "TU106", "0x167": "TU117", "0x168": "TU116"},
                   mmu=dict(format="v2", va_bits=49, big_page_sizes=[65536]), layout="turing",
                   classes={"host": "0xC46F", "compute": "0xC5C0", "copy": "0xC5B5", "3d": "0xC597"},
                   names=["RTX 20", "GTX 16", "TITAN RTX", "Quadro RTX", "Tesla T4", "T400", "T600", "T1000", "TU10", "TU11"]),
    "ampere": dict(architecture="Ampere", family="GA100/GA10x/GA10B", nvml_arch=7, cc=["8.0", "8.6", "8.7"],
                   chipsets={"0x170": "GA100", "0x172": "GA102", "0x173": "GA103", "0x174": "GA104", "0x176": "GA106",
                             "0x177": "GA107", "0x17b": "GA10B (Orin)"},
                   mmu=dict(format="v2", va_bits=49, big_page_sizes=[65536]), layout="ampere",
                   classes={"host": "0xC56F", "compute": "0xC7C0", "copy": "0xC7B5", "3d": "0xC797"},
                   names=["RTX 30", "A100", "A30", "A40", "A10", "A16", "A2", "RTX A", "GA10"]),
    "ada": dict(architecture="Ada Lovelace", family="AD10x", nvml_arch=8, cc=["8.9"],
                chipsets={"0x192": "AD102", "0x193": "AD103", "0x194": "AD104", "0x196": "AD106", "0x197": "AD107"},
                mmu=dict(format="v2", va_bits=49, big_page_sizes=[65536]), layout="ampere",
                classes={"host": "0xC56F", "compute": "0xC9C0", "copy": "0xC7B5", "3d": "0xC997"},
                names=["RTX 40", "RTX 4050", "RTX 4060", "RTX 4070", "RTX 4080", "RTX 4090", "L4", "L40", "RTX 2000 Ada",
                       "RTX 4000 Ada", "RTX 5000 Ada", "RTX 6000 Ada", "AD10"]),
    "hopper": dict(architecture="Hopper", family="GH100", nvml_arch=9, cc=["9.0"],
                   chipsets={"0x180": "GH100"},
                   mmu=dict(format="v3", va_bits=57, big_page_sizes=[65536]), layout="hopper",
                   classes={"host": "0xC86F", "compute": "0xCBC0", "copy": "0xC8B5", "3d": "0xCB97"},
                   names=["H100", "H200", "H800", "H20", "GH100", "GH200"]),
    "blackwell": dict(architecture="Blackwell", family="GB10x/GB20x", nvml_arch=10,
                      cc=["10.0", "10.1", "10.3", "11.0", "12.0", "12.1"],
                      chipsets={"0x1a0": "GB100", "0x1a2": "GB102", "0x1a3": "GB110 (derived id)",
                                "0x1a4": "GB112 (derived id)", "0x1ab": "GB10B (derived id)", "0x1ac": "GB10C (derived id)",
                                "0x1b2": "GB202", "0x1b3": "GB203", "0x1b5": "GB205", "0x1b6": "GB206", "0x1b7": "GB207",
                                "0x1bb": "GB20B (derived id)", "0x1bc": "GB20C (derived id)"},
                      mmu=dict(format="v3", va_bits=57, big_page_sizes=[65536]), layout="blackwell",
                      classes={"host": "0xC96F", "compute": "0xCDC0", "copy": "0xC9B5", "3d": "0xCD97",
                               "host_gb20x": "0xCA6F", "compute_gb20x": "0xCEC0", "copy_gb20x": "0xCAB5"},
                      names=["RTX 50", "RTX PRO 6000 Blackwell", "B100", "B200", "B300", "GB200", "GB300", "GB20"]),
    "rubin": dict(architecture="Rubin", family="GR10x", nvml_arch=13, cc=[],
                  chipsets={"0x1c0": "GR100 (derived id)", "0x1c2": "GR102 (derived id)"},
                  mmu=dict(format="v3", va_bits=57, big_page_sizes=[65536]), layout="blackwell",
                  classes={"host": "0xC96F", "compute": "0xCDC0", "copy": "0xC9B5", "3d": "0xCD97"},
                  names=["Rubin", "GR10"]),
}


def main():
    for name, p in PROFILES.items():
        prov = [MMU_NOTES[p["mmu"]["format"]],
                "Chipset ids (NV_PMC_BOOT_0[28:20]), NVML architecture ids and CUDA compute capabilities: "
                "docs/research/NVIDIA_HW_FACTS.md section 5 (ids marked 'derived' are not listed by any source).",
                "Engine classes per chip: docs/research/NVIDIA_COMMAND_FACTS.md section 0 (nouveau/GSP-RM/nvgpu tables).",
                "QMD version is read from each descriptor (all published layouts V00_06..V05_00 are decoded)."]
        if name == "pascal":
            prov.append("Pascal instance blocks select VER1 or VER2 page tables individually (RAMIN bit 10); both are walked.")
        if name in ("kepler", "maxwell"):
            prov.append("Before GM20x the big page size is a global register (default 128 KiB), not in the instance "
                        "block: override with --big-page 64K if the driver was configured for 64 KiB.")
        if name == "rubin":
            prov.append("Rubin: chip ids derived and classes assumed equal to Blackwell - forward-compatibility only.")
        doc = {"format": "keto-profile/1", "name": name, "vendor": "nvidia", "architecture": p["architecture"],
               "family": p["family"], "nvml_arch": p["nvml_arch"], "compute_capabilities": p["cc"],
               "chipsets": p["chipsets"], "name_patterns": p["names"], "mmu": p["mmu"], "layout": p["layout"],
               "qmd": "auto", "classes": p["classes"], "provenance": prov}
        with open(os.path.join(OUT, name + ".json"), "w", encoding="utf-8") as fh:
            json.dump(doc, fh, indent=2)
    print("wrote %d profiles" % len(PROFILES))


if __name__ == "__main__":
    main()
