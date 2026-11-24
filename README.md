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
  launch descriptors V00_06 to V05_01. The profile is detected from metadata, banners, or the structures in the
  image alone (engine class ids, QMD version bytes, RAMFC layout); a `--profile` that contradicts the evidence is
  reported. Pushbuffer methods are named for the host, copy, compute, inline-to-memory, 3D, 2D and video classes
  from NVIDIA's published class headers.
- 116 plugins, each documenting **what it does, how it does it, and its Volatility 3 counterpart**. Each of the 167
  Volatility 3 plugins is mapped in [docs/VOLATILITY_MAPPING.md](docs/VOLATILITY_MAPPING.md): 114 to a plugin
  that declares it as its analogue, 53 by investigative role only (structures with no GPU twin, e.g. Windows
  desktops or macOS kauth; there is no NVIDIA driver on current macOS, so the `mac.*` rows are role analogies).
- Evidence containers carry per-segment hashes and a header digest over the metadata and segment table; `acquire`
  prints an evidence fingerprint to record outside the container, never overwrites existing files, and `verify`
  checks every container, live snapshots included.
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
python keto.py acquire --method snapshot --out triage.keto             # record live state (prints a fingerprint)
python keto.py -f triage.keto verify --expected-fingerprint <printed>  # chain of custody
python keto.py -f triage.keto nvidia.malware.gpuxview                  # ...and analyse it offline later
sudo python3 keto.py acquire --method kcore --out ram.keto             # Linux/WSL2 RAM + BTF + symbols
python keto.py -f ram.keto wsl.dxgprocs                                # GPU process tree from host RAM
python keto.py sigma --out sigma/                                     # Sigma rules for the SIEM
```

Installed as a package (`pip install .`, which works offline: Keto builds with an in-tree, standard-library-only
backend) the command is `keto`. `--workers N` sets how many processes scan large images (default: up to 8).

## What it can analyse

| Evidence | How it is obtained | Plugins that use it |
|---|---|---|
| Physical VRAM image | external dump (hypervisor, PCIe DMA, GPU debugger) imported with `keto acquire --method import`, or `keto acquire --method pramin` (bare-metal Linux, root, driver unbound: reads VRAM through the BAR0 PRAMIN window; validated against an emulator only, see docs/ACQUISITION.md) | all `nvidia.*` image plugins |
| CUDA residual memory | `keto acquire --method cuda`: uninitialised allocations copied back (remanence test) | scanners (cubins, PTX, secrets, keys, surfaces) |
| Process memory | `keto acquire --method process --gpu-processes` (Linux/WSL via /proc, Windows via ReadProcessMemory), or any process dump | `nvidia.artifactscan` (GPU code incl. OpenCL/SPIR-V/DXBC, pushbuffers, QMDs, with provenance and baselines) |
| Host RAM image (raw/LiME) | `--host-image`; resolves GPU mappings of system memory, and is scanned for GPU code | `nvidia.sysmemmap`, `nvidia.artifactscan` |
| Linux / WSL2 kernel memory | `keto acquire --method kcore`, or AVML/LiME + `--btf`/`--kallsyms`, or `--kcore` live | `host.kernel`, `host.pslist`, `wsl.dxgprocs`, `wsl.dxgallocs` |
| Windows kernel memory | `keto acquire --method livedump` (elevated, no third-party driver), or any raw image, crash/live dump, hiberfil.sys, QEMU/VirtualBox ELF core or VMware snapshot; symbols from a local PDB/ISF, or derived from the kernel itself when none is available | `windows.kernel.*` (docs/WINDOWS.md) |
| JIT and shader caches on disk | `%APPDATA%\NVIDIA\ComputeCache`, `~/.nv/ComputeCache`, `%LOCALAPPDATA%\D3DSCache`, NVIDIA DX/GL caches (collected with `--path`, or this machine's by default) | `nvidia.jitcache`, `nvidia.shadercache` |
| Live system | NVML + CUDA via ctypes, `/proc`, `/sys`, Windows Toolhelp/PDH/registry, allow-listed read-only commands | live plugins |
| Live snapshot | `keto acquire --method snapshot`: every live query recorded, replayed byte-identically | all live plugins offline, except the two that read process memory (`nvidia.procscan`, `nvidia.malware.libhooks`), which refuse on a snapshot |

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
   - option ROM / VBIOS anomalies (`nvidia.vbios`): image-chain and PCIR consistency, vendor/device mismatches,
     checksums, trailing data, BIT/version consistency, and comparison with a known-good ROM or hash list
     (`--known-good`). Firmware signatures are not verified.

## Beyond VRAM

- **Host side of GPU malware**: `nvidia.artifactscan` sweeps host RAM and process dumps for fatbins, cubins, PTX,
  OpenCL C source, SPIR-V, DXBC/DXIL, pushbuffers and QMDs; it flags the XOR-with-modulo-key decryptor shape used
  by OpenCL loaders and suppresses known-good code with hash baselines.
- **WSL2 kernel**: `wsl.dxgprocs` lists every process the GPU paravirtualisation driver knows (including those in
  PID namespaces, exited/hidden ones and unlinked objects) with devices, contexts, hardware queues and allocations;
  `wsl.dxgallocs` dumps and scans guest pages shared with the GPU.
- **Windows kernel memory** (docs/WINDOWS.md): `windows.kernel.pslist` / `psscan` (processes, including ones
  unlinked from the active list) / `modules` / `handles` / `vadinfo` / `envars` / `driverirp` (dispatch entries
  outside their driver, framework dispatch recognised) / `gpuprocs` (graphics-kernel process objects, GPU runtimes,
  GPU device handles, hidden GPU processes) / `procdump` (a process as a container for `nvidia.artifactscan`).
  Works without network access: when no PDB for the build is available, types are derived from the kernel image
  (accessor machine code, structural checks, layouts stable from Windows 10 1809 to 11 25H2).
- **Windows**: `windows.gpuprocs` (GPU runtimes per process with Authenticode status of the image and each GPU
  runtime DLL and its path, command lines from the PEB, per-process GPU engines and memory per named adapter,
  windowless compute, loader paths), `nvidia.malware.watchdog` (TDR tampering), process capture with
  `acquire --method process`. The generic live plugins have Windows implementations too: GPU processes and their
  tree, command lines and environments (`nvidia.pslist`, `pstree`, `cmdline`, `envars`, `libs`), injection,
  masquerading, deleted images, capture libraries, NVIDIA kernel drivers and display-class filter drivers
  (`nvidia.driver`, `nvidia.modules`), driver registry parameters, services, OpenCL/Vulkan loader registrations
  (`nvidia.autostart`), per-user compute caches, profiling and debugger exposure, Authenticode integrity of NVIDIA
  files, process-memory GPU payload scans (`nvidia.procscan`), relocation-aware in-memory patch detection of
  NVIDIA DLLs (`nvidia.malware.libhooks`) and GPU use without any GPU user-mode driver (`nvidia.malware.rawioctl`).
  `nvidia.handles` lists each process's open handles to GPU objects and files (DxgKrnl/NVIDIA devices, the CUDA
  driver's kernel archive opened at cuInit, shader and JIT caches in use, NVIDIA capture components), with name
  queries isolated in a timed-out worker so a blocked file object cannot hang the run. Linux-only concepts refuse
  with what to run instead: device nodes (`nvidia.devnodes`), container runtimes (`nvidia.containers`), VFIO binding
  (`nvidia.malware.rawaccess`).
- **Host page ownership**: `nvidia.malware.hostpages` (which process or kernel region owns each host page the GPU
  maps), `wsl.dxgpageowners` (pages behind WSL2 GPU allocations).
- **Execution evidence on disk**: `nvidia.shadercache` (D3D, NVIDIA DX/GL and Mesa shader caches: which programs
  ran GPU shaders, when, on which adapter; the D3D cache records the program, while NVIDIA DX/GL caches of recent
  drivers record no program name and are listed per cache directory), `nvidia.jitcache` (CUDA JIT cache),
  `nvidia.envscan` (injection and loader variables in any image, ASCII and UTF-16). Without `--path` these read
  the analyst machine's own caches, so `timeliner` only includes them for `--live`.
- **Accounting and bypass**: `nvidia.malware.unaccounted` (GPU memory/activity no process owns, from NVML or the
  Windows GPU counters), `nvidia.malware.scraper` / `nvidia.malware.fillscan` (remanence scraping),
  `nvidia.malware.rawaccess` (GPU bound to vfio-pci, VFIO handles, raw BAR mappings), compute-mode and ECC
  (Rowhammer exposure) checks.

## Documentation

- [docs/PLUGIN_REFERENCE.md](docs/PLUGIN_REFERENCE.md): every plugin, what and how (generated from code).
- [docs/VOLATILITY_MAPPING.md](docs/VOLATILITY_MAPPING.md): every Volatility 3 plugin and its GPU counterpart.
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): framework design (layers, profiles, discovery, live sources, host memory).
- [docs/FORMATS.md](docs/FORMATS.md): evidence container, profile format, decoded NVIDIA structures and their sources.
- [docs/ACQUISITION.md](docs/ACQUISITION.md): acquisition methods, forensic soundness, platform findings.
- [docs/WINDOWS.md](docs/WINDOWS.md): Windows kernel memory: inputs, kernel location, symbols and the self-profile.
- [docs/research/](docs/research/): verified hardware and command-stream facts with sources, host-side detection
  research, and the survey of prior work with the gap analysis this release closes.

## Testing

```bash
python -m unittest discover -s tests -v
```

529 tests, passing on Python 3.10 (Ubuntu/WSL2, as root, including the live `/proc/kcore` tests), 3.13 (Windows)
and 3.14 (Kali), from the source tree and from an offline `pip install`; GitHub Actions runs them on Linux and
Windows for Python 3.8 and 3.10–3.14:

- the same ground-truth scenario built with **each generation's** structures (Kepler, Maxwell, Pascal, Volta,
  Turing, Ampere, Ada, Hopper, Blackwell, Rubin), checked end to end: profile detection from structures alone,
  channels, runlists, address spaces, page sizes, launches, copies, QMD versions, the GPU timeline and malfind;
- hostile and damaged evidence: truncated parser input at the end of an image, decompression bombs (deflate, LZ4,
  zstd), tampered and truncated containers, no false channels/QMDs/surfaces on random data and system DLLs;
- exact scanning at worker-part and chunk boundaries (multi-process vs single-process results are identical);
- a synthetic Linux kernel image (KASLR, 4-level walks with a 2 MiB page, decoy banners) for the BTF reader and
  the dxgkrnl cross-view;
- real data: QMDs written by the NVIDIA 592.82 driver, a JIT-compiled cubin, NVIDIA library fatbins, and (as root on
  Linux) the live kernel through `/proc/kcore`;
- live plugins against a fake Linux and Windows system, with snapshot record/replay round trips;
- a synthetic Windows x64 kernel (non-contiguous frames, low stub, self-referencing PML4, transition/prototype/
  page-file PTEs, DKOM-unlinked and exited processes, handle tables, VAD trees, a hooked and a KMDF driver) analysed
  with a symbol file and with the self-profile, as a raw image and as a live-kernel crash dump;
- the PDB reader on real Microsoft PDBs, the self-profile's accessor decoder on the machine's real `ntoskrnl.exe`,
  and the Xpress/Huffman/LZNT1 decoders byte for byte against Windows' own `RtlCompressBuffer`;
- PRAMIN acquisition against an emulated BAR0 (window discipline, races, PRI errors, VRAM plugins on the result).

## Scope and honesty notes

- NVIDIA only (by design). Structure layouts are verified against NVIDIA's published headers where they exist;
  every profile records its provenance (`profileinfo --provenance`), and unverified facts are labelled.
- The VRAM structure pipeline (channels, runlists, page tables, pushbuffers, launches) is tested against synthetic
  images that `keto synth` builds from the same published layouts the parsers read, plus real QMDs, cubins and
  fatbins; it has not been validated against a physical VRAM dump from real hardware. The Rubin profile assumes
  Blackwell's classes and layouts (forward compatibility only).
- Raw zstd frames are scanned for embedded cubins. In the NVIDIA 610.91 `nvcuda64.dll` the seven `28 B5 2F FD`
  hits are not frames but 32-bit immediates of x86 `mov`/`cmp` instructions in the library's own zstd decoder (the
  driver's 936 cubins there are stored uncompressed and are found directly); they fail to decode and are ignored.
- QMD V05_01 (Blackwell task with sub-tasks) is decoded from the published layout; each sub-task's program is
  analysed as its own launch. Blackwell USERD words other than GP_PUT are assumed unchanged. GB2xx RAMFC holds no
  CHID.
- Under Windows/WSL2 (WDDM) the driver scrubs device memory between allocations, so CUDA residual capture returns
  zeros there, and physical VRAM cannot be acquired from inside WSL2. WDDM does not report per-process GPU memory to
  NVML, so the memory accounting cross-view is not possible there (the plugin says so).
- Host kernel memory covers Linux/WSL2 and Windows on x86-64. Windows analysis was validated on a live dump of a
  real Windows 11 build 26300 kernel without a PDB: process IDs, parents and creation times match the running
  system for every surviving process, and every running driver is in the module list. The internals of
  `dxgkrnl.sys` objects are not public (no types in its PDB), so the Windows GPU view uses
  `_EPROCESS.DxgProcess`, handles and mapped GPU runtimes. Native-Linux NVIDIA RM objects (`g_resServ`, NVOC) are
  researched in docs/research/HOST_SIDE_DETECTION.md but not implemented: they could not be validated here.
- Licence: see `pyproject.toml` (currently marked proprietary pending the owner's choice).
