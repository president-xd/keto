# Acquisition

`keto acquire --method <m> --out evidence.keto [...]` always produces a `.keto` container with device identity,
acquisition notes and per-segment SHA-256, and prints its **evidence fingerprint**: record it in the case notes.
Verify any container (snapshot containers included) at any time with `keto -f evidence.keto verify`, or against the
recorded value with `verify --expected-fingerprint <hex>` (docs/FORMATS.md, Integrity).

`acquire` never overwrites an existing file unless `--force` is given, never writes over its own input, checks the
input before creating the output, and records `acquisition.status` (`complete` or `incomplete: <error>`) so an
interrupted acquisition cannot pass for a complete one.

## Methods

| Method | What it captures | Touches GPU memory? | Platforms |
|---|---|---|---|
| `snapshot` | The live state that every live plugin would query: NVML device state; on Linux the `/proc` records of **every** process (the cross-view plugins such as `rawioctl` and `capture` examine all processes, not only GPU ones; environments are reduced to GPU/loader-relevant variables); on Windows the process list, module lists of all processes, and for GPU processes their command lines, GPU-relevant environment variables (from the PEB), image path and debug flag, plus the NVIDIA registry keys (driver parameters, services, Khronos OpenCL/Vulkan loader keys, display-class filters), the loaded-driver list and the version, Authenticode status and SHA-256 of NVIDIA driver files (several hundred MB hashed, so a Windows snapshot takes a minute or more); on Linux driver/module/firmware files, loader configs, kernel log (`dmesg`/`journalctl`, if permitted), package verification output. `nvidia.procscan` and `nvidia.malware.libhooks` read process memory and are not recorded (they refuse on a snapshot). Plugins that do not apply to the platform are listed in `plugins_not_applicable`, failures in `plugin_errors` | No | Linux, WSL, Windows |
| `cuda` | Uninitialised device allocations copied back with `cuMemcpyDtoH`. Each segment is keyed by its CUDA VA. Records zero/non-zero statistics and adds a snapshot unless `--no-snapshot` | Allocates and reads only its own allocations (`--size`, or `--all-free` minus `--reserve` for the desktop) | Anywhere `libcuda` / `nvcuda.dll` loads |
| `import` | Wraps an existing dump produced by another tool (hypervisor, PCIe DMA hardware, GPU debugger) with metadata and hashes. `--space vram\|sysmem\|bar1\|rom ...`, `--address`. No device identity is recorded (the dump may come from any machine, and a wrong identity would select the wrong profile); `--live-device` records this machine's GPU when the dump was taken from it | No | Any |
| `process` | The readable address space of GPU processes, keyed by virtual address, with the mapping list (`--pid`, repeatable, or `--gpu-processes`). Linux/WSL: `/proc/<pid>/mem` (root or a descendant process). Windows: `VirtualQueryEx` + `ReadProcessMemory` over committed regions, with protection, type and backing file (same user, or Administrator); GPU processes are chosen from the Windows GPU counters and loaded GPU compute runtimes. Analyse with `nvidia.artifactscan` / `nvidia.envscan` | No | Linux, WSL, Windows |
| `kcore` | Physical RAM of the running Linux/WSL2 kernel through `/proc/kcore` (the source AVML uses), all-zero pages omitted, plus the kernel's BTF, the symbols the host plugins need, the banner and the KASLR translation parameters, so `host.*` / `wsl.*` plugins run offline on any OS | No | Linux, WSL (root) |

## Forensic soundness

- Snapshot collection is read-only and runs only allow-listed read-only *invocations*: the program and its
  arguments are both checked (e.g. `dpkg-query -W`, `dpkg --verify`, `rpm -V`, `journalctl -k`, `dmesg`), so a
  destructive verb of an allowed program (`dmesg -C`, `nvidia-smi -r`) is refused.
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

Measured on the reference machine (WSL2 kernel 6.18, 16 GiB RAM, a CUDA process running): `acquire --method kcore`
read the 16,202 MiB of RAM in 20.7 s (about 800 MiB/s) and stored 1,199 MiB (1.26 GB file) with a 264 MB peak
resident size. The output is roughly the RAM actually in use: pages that are all zero are omitted, and so are RAM
pages identical to a page already written to the output file (the image would otherwise capture its own output
through the page cache; written data is also synced and dropped from the cache every 64 MiB). The count is
recorded as `kernel.own_pages_omitted`. Files deleted just before an acquisition (a previous image, say) are still
imaged as stale free pages, so back-to-back acquisitions are larger. Segments are capped at 16 MiB, so memory use
does not grow with long runs of data.

`--phys-range START-END` (repeatable) acquires only the given physical ranges and `--max-bytes N` stops once N
bytes of non-zero data are stored. A limited or interrupted acquisition (Ctrl-C included) records
`kernel.acquired_ranges`, and analysis then refuses to read outside them instead of returning zeros.

On such an image `wsl.dxgprocs` takes about 1.3 s and returns the same objects as the live walk: the recorded
`phys_base` is used after a cheap check at its expected location (the full banner scan runs only if that fails).

## Live triage without acquisition

`keto --live <plugin>` runs any live plugin directly. `keto --snapshot snap.json <plugin>` replays a JSON
snapshot written with `keto acquire --method snapshot --json-snapshot snap.json`.
