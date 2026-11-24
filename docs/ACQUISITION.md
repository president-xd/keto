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
| `pramin` | Physical VRAM through the BAR0 PRAMIN window: the window register (`NV_PBUS_BAR0_WINDOW` 0x1700 up to Ada, `NV_XAL_EP_BAR0_WINDOW` 0x10fd40 on Hopper/Blackwell/Rubin) is moved over VRAM and the 1 MiB aperture at BAR0+0x700000 is read with 32-bit loads. Space `vram`, keyed by VRAM physical address, every page stored (zero pages too); metadata records the chip (BOOT_0/BOOT_42), VRAM size and its source, the window register before/after, window events, PRI-error pages and (with `--passes`) pages that changed. See the SOP below | Reads all of VRAM; **writes one register** (the window: saved, verified, restored) | Linux on bare metal (root). Validated against an emulator only |

| `livedump` | A Windows live kernel memory dump (`NtSystemDebugControl` SysDbgGetLiveKernelDump, the facility behind Task Manager's "Create live kernel memory dump"), converted page by page into space `sysmem` keyed by physical address. `--include-user-pages` adds user-mode memory (needed for `windows.kernel.envars` and `procdump`), `--hypervisor-pages` hypervisor pages, `--keep-dump` keeps Windows' own `.dmp`. Metadata: the dump header (`memory_image`), the original file's SHA-256 (`acquisition.source_digest`) and the kernel's PDB identity (`windows.kernel`). On the reference machine (32 GB RAM, kernel only) Windows wrote 2.75 GB in 2.4 s | No; Windows builds a consistent snapshot without a third-party driver | Windows 8.1+ (elevated) |

`import --space sysmem` converts any memory image keto.formats.memimage recognises (crash and live dumps,
hiberfil.sys, QEMU/VirtualBox ELF cores, VMware snapshots, LiME) the same way, instead of copying its bytes.

## Forensic soundness

- Snapshot collection is read-only and runs only allow-listed read-only *invocations*: the program and its
  arguments are both checked (e.g. `dpkg-query -W`, `dpkg --verify`, `rpm -V`, `journalctl -k`, `dmesg`), so a
  destructive verb of an allowed program (`dmesg -C`, `nvidia-smi -r`) is refused.
- `cuda` changes device state in a bounded way: it creates one context and allocates the requested memory.
  Document this in your case notes as you would for any live-response tool.
- `pramin` writes exactly one GPU register, the BAR0 window, and puts it back. A bound GPU driver uses the same
  window and caches its position without re-reading it, so moving the window under it can corrupt VRAM: the
  method refuses while a driver is bound unless `--allow-bound-driver` is given (SOP below). Where the driver
  cannot be unbound, a hypervisor or DMA capture imported with `--method import` touches the GPU less.

## PRAMIN acquisition SOP (`--method pramin`)

Register addresses, fields, error values and the Linux checks are cited in
[research/NVIDIA_HW_FACTS.md](research/NVIDIA_HW_FACTS.md), Topic 7. **The method has been validated against an
emulated BAR0 (`keto/testing/fakebar0.py`) only, never on real hardware.**

1. **Boot bare-metal Linux as root** (an examiner live system is best). WSL2 exposes no PCI device; other OSes are
   refused.
2. **Free the window.** Stop the display server and every GPU user (`nvidia-smi` lists them;
   `systemctl stop nvidia-persistenced`), then unbind the driver:
   `echo 0000:01:00.0 > /sys/bus/pci/drivers/nvidia/unbind` (or `nouveau`, `nova`...). Record the time and the
   commands: unbinding runs the driver's teardown, which changes GPU state and may clear parts of VRAM (not
   measured). On machines that power idle GPUs down, keep the device powered first
   (`echo on > /sys/bus/pci/devices/0000:01:00.0/power/control`): Keto refuses any power state but D0.
   **VM passthrough (`vfio-pci`)**: pause the VM for the whole acquisition (`virsh suspend <domain>`), resume it
   afterwards. Keto proceeds with a warning; a running guest's driver races the window.
3. **Check the kernel.** `cat /sys/kernel/security/lockdown` must show `[none]`: any lockdown level blocks
   user-space BAR access (mmap fails with EPERM; disable Secure Boot for the examiner boot if it enforces
   lockdown). If BAR0 is still claimed by a driver, a kernel with `CONFIG_IO_STRICT_DEVMEM=y` refuses the mmap
   with EINVAL unless booted with `iomem=relaxed`; unbinding releases the claim. PCI memory decoding must be on
   (COMMAND bit 1; `echo 1 > /sys/bus/pci/devices/<bdf>/enable`).
4. **Acquire:** `sudo python3 keto.py acquire --method pramin --pci 0000:01:00.0 --out vram.keto` and record the
   printed fingerprint. `--pci` is required when several NVIDIA GPUs are present. `--start`/`--length` limit the
   range (whole 4 KiB pages); `--passes 2` re-reads the range and lists the pages that changed between passes
   (only pass 1 is stored); `--bulk-mmio` uses memcpy instead of 32-bit loads (faster, but the CPU may issue wider
   loads to BAR0; not validated). `--vram-size` is needed on Kepler..Volta when NVML cannot give the size.
5. **Afterwards** rebind the driver or reboot. If Keto reports that the window could not be restored, reboot
   before trusting the driver.

What the method checks and records, and when it refuses:

- Refuses (nothing written, no output file): not Linux, not root, kernel lockdown, no/several NVIDIA display or
  3D controllers without `--pci`, `--pci` naming a non-NVIDIA or non-display function, power state other than
  D0, memory decoding off, BAR0 smaller than the aperture, resource0 mmap refused (EPERM: lockdown; EINVAL:
  exclusive iomem), a bound driver without `--allow-bound-driver`, a chip without a cited window register
  (Fermi and older, integrated GPUs, unknown chip IDs), BOOT_0 reading all-ones/a PRI error/the SEC_FAULT pattern,
  and an unknown VRAM size (cited register first, then NVML for that PCI address, then `--vram-size`; the source
  is recorded and a conflicting `--vram-size` is reported and ignored).
- Window discipline: the register is read before the first write; every write is a read-modify-write of the
  BASE/TARGET fields and is read back and verified; after every 64 KiB aperture read the register is read again;
  a block read while someone else had moved the window is discarded and read again (4 retries, then the
  acquisition stops), and each event goes to `pramin.window_events`. The window is restored on normal end,
  exceptions and SIGINT/SIGTERM/SIGHUP (the handlers only set a flag checked between aperture reads, so the
  restore cannot be cut short); SIGKILL or power loss leaves it where it was. If another agent moved the window,
  its last value is restored, because that is what its cached window position says. `window_before`,
  `window_after`, `window_restored_to`, `window_restore_verified` are in the metadata.
- Data: `acquisition.status` is `complete` or `incomplete: <reason>`; `pramin.acquired_ranges` lists what was
  read. Every page is stored, zero pages included (the VRAM layer reads only what the container holds, so
  analysis never sees zeros outside the acquired ranges). Pages made only of PRI error words (cited code list)
  are stored as read and listed in `pramin.error_ranges`; a page of all-ones is data unless BOOT_0 no longer
  reads its value, in which case the acquisition stops (GPU lost).
- `--allow-bound-driver` RISKS: while Keto holds the window, every PRAMIN access the driver makes reaches
  Keto's window position: driver writes then land in the wrong VRAM (corruption), and the driver or GPU can
  hang. Driver moves of the window are detected and retried, but a move and move-back between two checks is
  invisible (only `--passes 2` can show it as changed pages). The run prints a warning and records
  `pramin.driver_active: true` and the driver's name; treat such an image as smeared and the machine as altered.

Throughput, measured on the reference machine (Windows 11 / WSL2, no NVIDIA PCI device available to Linux; ranges
over repeated runs on a loaded machine): the real accessor reads an ordinary RAM-backed file mapping in 64 KiB
blocks at 80-112 MiB/s (Windows, Python 3.13) and 122-185 MiB/s (WSL2 Ubuntu 22.04, Python 3.10) with 32-bit
loads, and at 24-37 GiB/s with `--bulk-mmio`; a single register read costs 0.3-0.5 us. A full 64 MiB acquisition
of the synthetic image through the emulator runs at 320-410 MiB/s. These numbers measure Keto's own overhead only.
On hardware each 32-bit load of BAR0 is a non-posted PCIe read, so real throughput will be far lower; it was not
measured.

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
