# Keto

**GPU memory forensics for NVIDIA GPUs, modelled on Volatility 3.**

Malware increasingly runs work on the GPU to stay out of reach of EDRs and memory scanners: loaders decrypt their
payload in an OpenCL kernel (CoffeeLoader/ArmouryLoader), droppers gate on GPU presence (GPUGate), miners hide in
GPU time, and research rootkits keep code and stolen data in VRAM. Keto brings the Volatility workflow
(acquire, identify, enumerate, cross-view, extract, timeline, report) to that blind spot.

Its *processes* are GPU channels and contexts, its *page tables* are the GMMU's, its *DLLs* are CUDA kernels, and
its *command history* is the pushbuffer stream. It analyses VRAM images offline, finds GPU payloads in host RAM and
process dumps, reads the host kernel's GPU objects from Linux/WSL2 RAM images, triages live Linux, WSL2 and Windows
systems, and records live state into hashed evidence containers that replay offline.

- Pure standard-library Python ≥ 3.8 (Windows, Linux, WSL, macOS for offline analysis). Optional: `yara-python`,
  `zstandard` (zstd-compressed fatbins on Python < 3.14).
- **Every NVIDIA generation from Kepler to Blackwell**: GMMU VER1/VER2/VER3 page tables, each generation's
  instance-block/RAMFC layout, Kepler/Maxwell/Volta+ runlist formats, 115 header-verified engine classes, and QMD
  launch descriptors V00_06 to V05_00. The profile is detected from metadata, banners, or the structures in the
  image alone (engine class ids, QMD version bytes, RAMFC layout).
- 110 plugins, each documenting **what it does, how it does it, and its Volatility 3 counterpart**. All 167
  Volatility 3 plugins are mapped to a GPU counterpart in [docs/VOLATILITY_MAPPING.md](docs/VOLATILITY_MAPPING.md).
- Findings are scored, mapped to MITRE ATT&CK in `keto report`, and backed by shipped YARA rules
  (`yarascan --builtin`) and Sigma rules (`keto sigma`).

## Quick start

```bash
python keto.py list                                   # every plugin with what/how/analogue
python keto.py synth -o demo/                          # build a ground-truth synthetic VRAM image
python keto.py -f demo/synthetic.keto nvidia.info
python keto.py -f demo/synthetic.keto -r pretty nvidia.chanscan
python keto.py -f demo/synthetic.keto --host-image demo/synthetic_host.lime -r pretty nvidia.malware.exfil
python keto.py -f demo/synthetic.keto -o out/ nvidia.surfaces          # recover framebuffers as PNG
python keto.py -f demo/synthetic.keto -o out/ report                   # every detector -> report.json/.html
python keto.py --live -r pretty nvidia.pslist                         # live GPU processes (Linux/WSL)
python keto.py --live -r pretty windows.gpuprocs                      # live GPU triage on Windows
python keto.py acquire --method snapshot --out triage.keto             # record live state
python keto.py -f triage.keto nvidia.malware.gpuxview                  # ...and analyse it offline later
sudo python3 keto.py acquire --method kcore --out ram.keto             # Linux/WSL2 RAM + BTF + symbols
python keto.py -f ram.keto wsl.dxgprocs                                # GPU process tree from host RAM
python keto.py sigma --out sigma/                                     # Sigma rules for the SIEM
```

Installed as a package (`pip install .`) the command is `keto`.

## What it can analyse

| Evidence | How it is obtained | Plugins that use it |
|---|---|---|
| Physical VRAM image | external dump (hypervisor, PCIe DMA, GPU debugger) imported with `keto acquire --method import` | all `nvidia.*` image plugins |
| CUDA residual memory | `keto acquire --method cuda`: uninitialised allocations copied back (remanence test) | scanners (cubins, PTX, secrets, keys, surfaces) |
| Process memory | `keto acquire --method process --gpu-processes` (Linux/WSL), or any process dump | `nvidia.artifactscan` (GPU code incl. OpenCL/SPIR-V/DXBC, pushbuffers, QMDs, with provenance and baselines) |
| Host RAM image (raw/LiME) | `--host-image`; resolves GPU mappings of system memory, and is scanned for GPU code | `nvidia.sysmemmap`, `nvidia.artifactscan` |
| Linux / WSL2 kernel memory | `keto acquire --method kcore`, or AVML/LiME + `--btf`/`--kallsyms`, or `--kcore` live | `host.kernel`, `host.pslist`, `wsl.dxgprocs`, `wsl.dxgallocs` |
| JIT cache on disk | `%APPDATA%\NVIDIA\ComputeCache`, `~/.nv/ComputeCache` | `nvidia.jitcache` |
| Live system | NVML + CUDA via ctypes, `/proc`, `/sys`, Windows Toolhelp/PDH/registry, allow-listed read-only commands | live plugins |
| Live snapshot | `keto acquire --method snapshot`: every live query recorded, replayed byte-identically | all live plugins, offline |

## How a VRAM image is analysed

1. **Instance blocks** are found by the RAMFC hardware signature `0xFACE`, the GPU's equivalent of a pool tag
   (`nvidia.chanscan`), using the detected generation's layout.
2. **Runlists** (the scheduler's TSG/channel lists) are found and walked (`nvidia.runlist`): 16-byte Volta+
   entries, 8-byte Maxwell/Pascal entries anchored on instance pointers, and Kepler entries resolved through the
   CHID each RAMFC holds. Comparing them with the scan exposes torn-down or hidden channels
   (`nvidia.malware.chanxview`).
3. Each channel's **page directory** turns into a GMMU layer (VER1 two-level with 64/128 KiB big pages for
   Kepler/Maxwell, VER2 five-level for Pascal..Ada, VER3 six-level for Hopper/Blackwell). Every GPU virtual address
   space then reads like a process address space (`nvidia.mappings`, `nvidia.memmap`, `nvidia.ptwalk`).
4. **GPFIFO rings → pushbuffers → methods** are decoded with the engine class tables, which yields the command
   history (`nvidia.pushbuf`): copies (`nvidia.copies`), kernel launches with decoded **QMDs** of every version
   (`nvidia.launches`, pre-Volta program offsets resolved through `SET_PROGRAM_REGION`), semaphores and
   interrupts. Timestamped semaphore releases give a GPU-clock timeline (`nvidia.gputimeline`).
5. **Kernel code** is identified by matching cubin `.text` sections (from the image, the host image or
   `--reference` binaries) against VRAM, and launches are resolved to kernel names (`nvidia.kernels`).
6. Detectors look for abuse:
   - W^X-violating GPU code (`nvidia.malware.malfind`), orphan SASS (`nvidia.malware.sassfind`) and unknown-code
     launches (`nvidia.malware.suspiciouslaunch`)
   - page-table exposure and cross-context sharing (`nvidia.malware.ptcheck`), DMA to host RAM
     (`nvidia.malware.exfil`)
   - host payloads hidden in VRAM: executables, script stagers, shellcode, file systems and archives
     (`nvidia.malware.hostcode`)
   - miners and crackers (`nvidia.malware.miner`), XRGB and opaque framebuffers (`nvidia.surfaces`)

## Beyond VRAM

- **Host side of GPU malware**: `nvidia.artifactscan` sweeps host RAM and process dumps for fatbins, cubins, PTX,
  OpenCL C source, SPIR-V, DXBC/DXIL, pushbuffers and QMDs; it flags the XOR-with-modulo-key decryptor shape used
  by OpenCL loaders and suppresses known-good code with hash baselines.
- **WSL2 kernel**: `wsl.dxgprocs` lists every process the GPU paravirtualisation driver knows (including those in
  PID namespaces, exited/hidden ones and unlinked objects) with devices, contexts, hardware queues and allocations;
  `wsl.dxgallocs` dumps and scans guest pages shared with the GPU.
- **Windows**: `windows.gpuprocs` (GPU runtimes per process, per-process GPU engines and memory, windowless
  compute, loader paths), `nvidia.malware.watchdog` (TDR tampering).
- **Accounting and bypass**: `nvidia.malware.unaccounted` (GPU memory/activity no process owns),
  `nvidia.malware.rawaccess` (GPU bound to vfio-pci, VFIO handles, raw BAR mappings), compute-mode and ECC
  (Rowhammer exposure) checks.

## Documentation

- [docs/PLUGIN_REFERENCE.md](docs/PLUGIN_REFERENCE.md): every plugin, what and how (generated from code).
- [docs/VOLATILITY_MAPPING.md](docs/VOLATILITY_MAPPING.md): every Volatility 3 plugin and its GPU counterpart.
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): framework design (layers, profiles, discovery, live sources, host memory).
- [docs/FORMATS.md](docs/FORMATS.md): evidence container, profile format, decoded NVIDIA structures and their sources.
- [docs/ACQUISITION.md](docs/ACQUISITION.md): acquisition methods, forensic soundness, platform findings.
- [docs/research/](docs/research/): verified hardware and command-stream facts with sources, host-side detection
  research, and the survey of prior work with the gap analysis this release closes.

## Testing

```bash
python -m unittest discover -s tests -v
```

220 tests, passing on Python 3.10, 3.13 and 3.14 (Windows, Ubuntu, Kali):

- the same ground-truth scenario built with **each generation's** structures (Kepler, Maxwell, Pascal, Volta,
  Turing, Ampere, Ada, Hopper, Blackwell), checked end to end: profile detection from structures alone, channels,
  runlists, address spaces, page sizes, launches, copies, QMD versions, the GPU timeline and malfind;
- a synthetic Linux kernel image (KASLR, 4-level walks with a 2 MiB page, decoy banners) for the BTF reader and
  the dxgkrnl cross-view;
- real data: QMDs written by the NVIDIA 592.82 driver, a JIT-compiled cubin, NVIDIA library fatbins, and (as root on
  Linux) the live kernel through `/proc/kcore`;
- live plugins against a fake Linux and Windows system, with snapshot record/replay round trips.

## Scope and honesty notes

- NVIDIA only (by design). Structure layouts are verified against NVIDIA's published headers where they exist;
  every profile records its provenance (`profileinfo --provenance`), and unverified facts are labelled.
- QMD V05_01 (Blackwell sub-task form) is recognised but shown raw. Blackwell USERD words other than GP_PUT are
  assumed unchanged. GB2xx RAMFC holds no CHID.
- Under Windows/WSL2 (WDDM) the driver scrubs device memory between allocations, so CUDA residual capture returns
  zeros there, and physical VRAM cannot be acquired from inside WSL2. WDDM does not report per-process GPU memory to
  NVML, so the memory accounting cross-view is not possible there (the plugin says so).
- Host kernel memory support covers Linux/WSL2 on x86-64. Native-Linux NVIDIA RM objects (`g_resServ`, NVOC) and
  Windows kernel GPU objects (`_EPROCESS.DxgProcess`) are researched in docs/research/HOST_SIDE_DETECTION.md but not
  implemented: they could not be validated on the project's hardware.
- Licence: see `pyproject.toml` (currently marked proprietary pending the owner's choice).
