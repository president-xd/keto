# Acquisition

`keto acquire --method <m> --out evidence.keto [...]` always produces a `.keto` container with device identity,
acquisition notes and per-segment SHA-256. Verify it any time with `keto -f evidence.keto verify`.

## Methods

| Method | What it captures | Touches GPU memory? | Platforms |
|---|---|---|---|
| `snapshot` | The live state that every live plugin would query: NVML device state, GPU processes and their `/proc` records (environments reduced to GPU-relevant variables), driver/module/firmware files, loader configs, kernel log (`dmesg`/`journalctl`, if permitted), package verification output | No | Linux, WSL; NVML parts on Windows |
| `cuda` | Uninitialised device allocations copied back with `cuMemcpyDtoH`. Each segment is keyed by its CUDA VA. Records zero/non-zero statistics and adds a snapshot unless `--no-snapshot` | Allocates and reads only its own allocations (`--size`, or `--all-free` minus `--reserve` for the desktop) | Anywhere `libcuda` / `nvcuda.dll` loads |
| `import` | Wraps an existing dump produced by another tool (hypervisor, PCIe DMA hardware, GPU debugger) with metadata and hashes. `--space vram\|sysmem\|bar1\|rom ...`, `--address` | No | Any |
| `process` | The readable address space of GPU processes through `/proc/<pid>/mem` (`--pid`, repeatable, or `--gpu-processes`), keyed by virtual address, with the mapping list. Analyse with `nvidia.artifactscan` | No | Linux, WSL (root or a descendant process) |
| `kcore` | Physical RAM of the running Linux/WSL2 kernel through `/proc/kcore` (the source AVML uses), all-zero pages omitted, plus the kernel's BTF, the symbols the host plugins need, the banner and the KASLR translation parameters, so `host.*` / `wsl.*` plugins run offline on any OS | No | Linux, WSL (root) |

## Forensic soundness

- Snapshot collection is read-only and uses only an allow-list of read-only commands (`dpkg --verify`, `rpm -V`,
  `modinfo`, `dmesg`, `journalctl`, `nvidia-smi`, `lspci`...).
- `cuda` changes device state in a bounded way: it creates one context and allocates the requested memory.
  Document this in your case notes as you would for any live-response tool.
- Writing GPU registers (e.g. moving the PRAMIN window to read arbitrary VRAM) is **not** implemented. It
  changes state that the running driver depends on, and it is not forensically sound. Use a hypervisor or DMA
  capture and `--method import` instead.

## Platform finding: WSL2 / WDDM scrubs device memory

On this project's reference machine (RTX 4050 Laptop GPU, driver 592.82, CUDA 13.1, WSL2), every byte of
uninitialised allocations read back as zero. The Windows driver clears device memory before handing it to
a new allocation, so residual-data recovery from *another* process is not possible from user mode there. The
`cuda` method states this explicitly in the container notes (`nonzero_bytes: 0`). On native Linux drivers the
same command reports whatever remanence is present.

## Host RAM from other tools

Any physical RAM image (LiME from AVML or LiME, raw) can be analysed with the `host.*` / `wsl.*` plugins when the
kernel's BTF (`/sys/kernel/btf/vmlinux`) and `/proc/kallsyms` from the **same boot** are supplied:
`keto --host-image ram.lime wsl.dxgprocs --btf vmlinux.btf --kallsyms kallsyms.txt`. The kernel's physical load
address is recovered from the `linux_banner` string and confirmed against the `phys_base` variable in the image.

Measured on the reference machine (WSL2 kernel 6.18, 16 GiB): `acquire --method kcore` stored 2.8 GiB of non-zero
pages in 50 s; `wsl.dxgprocs` on that image takes under 1 s and returns the same objects as the live walk.

## Live triage without acquisition

`keto --live <plugin>` runs any live plugin directly. `keto --snapshot snap.json <plugin>` replays a JSON
snapshot written with `keto acquire --method snapshot --json-snapshot snap.json`.
