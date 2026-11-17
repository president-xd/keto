# Related work: GPU-resident malware, GPU memory forensics, acquisition and detection

Compiled 2026-11-17 for Keto 1.0.0 (97 plugins; see [../PLUGIN_REFERENCE.md](../PLUGIN_REFERENCE.md)).
This document surveys prior work so Keto can reuse what already exists and see what it still lacks.
The host-side view (NVIDIA RM objects in RAM, WDDM/dxgkrnl, ETW, WSL2) is covered in more depth in the
sibling document [HOST_SIDE_DETECTION.md](HOST_SIDE_DETECTION.md). This document links to it rather than
repeating it.

**Verification legend.** Every source below was opened during this research, either by the author of this
document or by a delegated research pass, unless it carries a tag:

- **[secondary]**: only press or third-party coverage was opened, not the primary source.
- **[metadata]**: only an index or DOI record was seen, not the full text.
- **[UNVERIFIED]**: could not be opened. The claim is reported, not checked.

GitHub repository status and licences were checked on 2026-11-17 through the GitHub API.

Each entry gives:
- **Cite:** the citation.
- **Technique:** the method in one or two sentences.
- **Artefacts:** the structures or traces it relies on or leaves.
- **Code:** whether code is public, and its licence.
- **Keto:** what to reuse, and what Keto must be able to detect.

Entry IDs ([M*], [F*], [A*], [D*]) are referenced from the gap analysis in section 6.

## Key takeaways

1. **GPU evasion is now seen in the wild, and the samples run on Windows and use OpenCL.**
   - Three families are documented: CoffeeLoader/ArmouryLoader (2024-2025), GPUGate/HijackLoader (2025-2026) and a 2026 offensive talk that keeps the payload in VRAM.
   - In every case the GPU decrypts a payload, or gates its decryption, to defeat sandboxes and memory scanners.
   - Keto's live side is Linux/WSL only, and its code scanners know CUDA (cubin, fatbin, PTX) but not OpenCL C source, SPIR-V or DXBC/DXIL.
2. **GPU cryptojacking is the most common real abuse.**
   - Recent campaigns: ShadowRay 2.0 (2025), GHOST/ComfyUI (2026) and a Microsoft-reported 2026 campaign.
   - They lock the GPU (`nvidia-smi -c EXCLUSIVE_PROCESS`), masquerade as kernel threads (`kworker/0:0`, `nv_uvm_<hex>`), hide with an `LD_PRELOAD` rootkit, and hide GPU usage from dashboards.
   - Keto already covers most of these indicators on Linux.
3. **The research model of GPU anti-forensics is unchanged since 2015.** Villani et al. defined four anti-forensic techniques: unlimited execution, process-less, context-less and inconsistent memory mapping.
   - Keto covers context-less execution: `chanxview`, `orphanchans`.
   - It does not cover process-less execution: nothing links a channel to its PID offline.
   - It does not cover inconsistent mapping: nothing cross-views GPU system-memory PTEs against the host process's own mappings.
   - It does not cover unlimited execution: no watchdog/TDR tamper check.
4. **Bowen, Case, Baggili and Richard (DFRWS USA 2024) is the closest prior work.**
   - They recover NVIDIA RM (NVOC) objects, including the GPU accounting history, from host RAM.
   - Their code repository is now 404.
   - They name physical VRAM imaging as future work, which is exactly where Keto sits.
5. **There is still no supported, forensically sound full-VRAM acquisition path for NVIDIA.**
   - The only public real-world NVIDIA VRAM and RAM pair is the DFRWS 2015 challenge corpus. It was captured on a Maxwell GPU (GTX 860M) with an NVIDIA-patched 343.13 driver.
   - Keto profiles start at Pascal, so it cannot parse that image.
6. **Detection content for GPU abuse barely exists.**
   - SigmaHQ, Elastic and Splunk have only command-line or driver-load cryptominer rules.
   - Nothing in them uses GPU telemetry.
   - ATT&CK mentions GPUs in only a few procedure examples and detection analytics (see section 4).

---

## 1) GPU malware techniques

### Overview

| ID | Work (year) | API | Where the malicious state lives | Host footprint | Keto today |
|---|---|---|---|---|---|
| M1 | Vasiliadis et al., GPU-assisted malware (2010/2015) | CUDA | XOR/decryption keys in device memory; packed code in host-mapped buffer | controlling process, pinned host buffer | AES schedules only; no XOR-kernel or host-mapped-exec check |
| M2 | Ladakis et al., GPU keylogger (2013) | CUDA | keystroke log in VRAM; GPU DMA to keyboard buffer | one-shot LKM, controller process, PTE rewrite | `sysmemmap` lists host windows, no ownership cross-view |
| M3 | Jellyfish / Demon / WIN_JELLY (2015) | OpenCL | data buffers in VRAM | `LD_PRELOAD`, LKM, OpenCL ICD | `envars`, `injection`, `autostart` (Linux) |
| M4 | Zhu et al., discrete GPU security (2017) | CUDA + driver patch / Falcon microcode | GPU mapping of host kernel memory; microcode | patched `nvidia.ko` in memory | `libhooks` covers user-mode libraries only |
| M5 | Forum-sold VRAM PoC (Aug 2021) | OpenCL 2.0, Windows | code stored and executed from GPU memory (claimed) | unknown | none on Windows |
| M6 | CoffeeLoader / ArmouryLoader packer (2024-2025) | OpenCL, Windows | OpenCL XOR-decrypt kernel; decoded shellcode buffer | `OpenCL.dll`, packer process | none on Windows |
| M7 | GPUGate / HijackLoader (2025-2026) | OpenCL, Windows | GPU-gated key (misdirection) | `OpenCL.dll`, .NET loader | none |
| M8 | "Cloak and Filter" (Hack.lu 2026) | compute shaders, Windows | encrypted payload in VRAM, decrypted on demand | Cloud Filter API placeholders | none |
| M9 | GPU cryptojacking (ShadowRay 2.0, GHOST, MS 2026, REF1695) | CUDA/OpenCL miners | mining kernels | miner processes, masquerade, rootkit | `miner`, `cryptojack`, `computecache`, `masquerade` (Linux) |
| M10 | GPU Rowhammer (GPUHammer 2025, GPUThor 2026) | CUDA | bit flips in GDDR6 | none specific | `ecc` shows counters, no policy flag |

### [M1] Vasiliadis, Polychronakis, Ioannidis: "GPU-Assisted Malware"

**Cite:**
- MALWARE 2010 (IEEE), pp. 1-6, DOI 10.1109/MALWARE.2010.5665801. PDF: https://nsl.cs.columbia.edu/papers/2010/gpumalware.malware10.pdf
- Extended in Int. J. Inf. Secur. 14:289-297 (2015), DOI 10.1007/s10207-014-0262-9 **[metadata]**: the full text was not opened, so how the journal version differs is unknown.

**Technique:** CUDA implementations of two code-armouring methods.
- **Self-unpacking:** the GPU XOR-decrypts the packed binary inside a page-locked host buffer that is mapped into the GPU address space.
- **Run-time polymorphism:** each function is decrypted on demand by the GPU and re-encrypted after it returns with a fresh random key. The keys are held in device memory that the CPU cannot reach.
- **Other points:** GPU code does not run in VM- or emulator-based analysis systems. The authors also predict password-cracking botnets and malicious framebuffer access.

**Artefacts:**
- PTX/cubin of a tiny XOR kernel; the paper shows the PTX.
- Key material in device memory.
- A pinned host buffer that the GPU writes and the CPU then executes.
- A controlling host process.

**Code:** none published.

**Keto:**
- Must flag compute kernels whose only work is XOR with a modulo-indexed key (from PTX, SASS or OpenCL source).
- Must flag GPU-writable system-memory windows whose host pages are later executable in the controlling process; this needs the host image.
- `nvidia.aeskeys` finds AES schedules but not raw XOR keys.

### [M2] Ladakis, Koromilas, Vasiliadis, Polychronakis, Ioannidis: "You Can Type, but You Can't Hide: A Stealthy GPU-based Keylogger"

**Cite:** EuroSec 2013. https://www.syssec-project.eu/m/page-media/3/ladakis-eurosec13.pdf

**Technique:**
- A loadable kernel module scans low (kmalloc) memory for the USB Request Block of a keyboard. Its tests: `transfer_dma` aligned to 0x20, and `dev->product` containing "usb" and "keyboard".
- The module rewrites the page-table entry of a dummy page in the controller process so that it points at the 8-byte usbhid keyboard buffer. Byte 0 holds the modifiers, byte 1 is reserved, bytes 2-7 hold scancodes.
- This "tricks" CUDA into giving the GPU DMA access to that buffer. The controller then `munmap`s the page, so the host process no longer accounts for it, while the GPU keeps reading it by physical address.
- The GPU polls the buffer at intervals under 100 ms. It stores the keystrokes as ASCII in device memory and runs credit-card regexes over them on the GPU.
- CPU and GPU utilisation is about 0.1%.
- Defences the authors propose: GPU code analysis (cuda-gdb, cuda-memcheck), DMA side effects (Stewin), and GPU utilisation or access-pattern profiling.

**Artefacts:**
- A GPU system-memory PTE that targets a host page the controlling process does not map.
- A long-running polling kernel.
- A keystroke log and scancode-to-ASCII table in VRAM.

**Code:** none from the authors. The third-party Demon PoC is covered in [M3].

**Keto:**
- `nvidia.sysmemmap` already lists GPU windows onto host RAM.
- It must also cross-check each host PFN against the owning process's own mappings (the "inconsistent memory mapping" of [F1]).
- It should classify target pages: HID report shape, kernel slab.
- It should scan VRAM for keystroke-log and scancode-table patterns.

### [M3] Team Jellyfish: Jellyfish (Linux GPU rootkit), Demon (GPU keylogger), WIN_JELLY (Windows RAT)

**Cite:**
- SecurityWeek, 2015-05-08: https://www.securityweek.com/poc-linux-rootkit-uses-gpu-evade-detection **[secondary]**
- Demon repository: https://github.com/FluffyPancakes/Demon (README opened; last push 2015-05-15).
- Intel Security / McAfee Labs Threats Report, August 2015, section "GPU malware: separating fact from fiction", via SecurityWeek: https://www.securityweek.com/gpu-malware-not-difficult-detect-intel-security **[secondary]**. The report PDF was not opened.

**Technique:**
- **Jellyfish:** a userland rootkit. It combines the Jynx `LD_PRELOAD` technique with OpenCL buffers kept on the GPU. The developers claimed DMA snooping of host memory and persistence across warm reboots.
- **Demon:** implements [M2]. A kernel module (`module_scan`) finds the USB keyboard buffer and then unloads itself. Captured data is moved to GPU memory with OpenCL (`demon.cl`) and the file is deleted.
- **Intel's assessment:**
  - All of these PoCs need a CPU host process, and mapping physical memory needs Ring 0.
  - On Windows, GPU code left orphaned by deleting its driver and parent process triggers a TDR reset.
  - Changing TDR settings to prevent that reset is itself suspicious.

**Artefacts:**
- `LD_PRELOAD` / `/etc/ld.so.preload`.
- An OpenCL ICD loaded in a non-graphics process.
- A transient LKM.
- VRAM buffers holding logged data.
- TDR registry tampering on Windows.

**Code:**
- Demon: GPL-2.0 (GitHub API).
- Jellyfish: `github.com/x0r1/jellyfish` now returns 404.

**Keto:**
- Linux host indicators are covered: `nvidia.envars`, `nvidia.malware.injection`, `nvidia.autostart`.
- Missing: a Windows TDR tamper check (gap G7).
- Missing: a residual scan for OpenCL-held keystroke buffers.
- Do not copy Demon code, since Keto is proprietary and Demon is GPL. It can be run in a lab to produce ground-truth images.

### [M4] Zhu, Kim, Rozhanski, Hu, Witchel, Silberstein: "Understanding the Security of Discrete GPUs"

**Cite:** GPGPU-10 (2017), DOI 10.1145/3038228.3038233. https://www.cs.utexas.edu/users/witchel/pubs/zhu17gpgpu-security.pdf

**Technique** (Fermi Tesla C2050/C2075). The paper describes four attacks:
1. **PixelVault:** breaks this "GPU as secure co-processor" design. cuda-gdb can attach to a running kernel and read its registers, and the instruction cache can be invalidated through MMIO.
2. **Driver backdoor:** an LKM patches the in-memory `nvidia.ko` so that a trigger sequence of erroneous `cudaHostRegister()` calls lets an unprivileged process map *any* host page into the GPU, including `task_struct` and `cred`. GPU kernels then escalate privileges or patch read-only code. The LKM unloads itself afterwards.
3. **Microcode:** malicious microcode is loaded into the context-switch (HUB) Falcon. It watches GPU memory for a trigger string and DMAs into host memory with Falcon `xfer` instructions.
4. **IOTLB:** stale IOTLB entries keep host pages reachable for hours after they are unmapped.

The authors expect newer GPUs to reject unsigned microcode.

**Artefacts:**
- GPU PTEs whose system-aperture targets are host kernel objects.
- A modified driver text section in host RAM.
- Falcon microcode.
- No process or VMA on the host for the mapped kernel page.

**Code:** none published.

**Keto:**
- Flag system-memory PTEs that target host kernel memory. With `--host-image`, classify the target page as kernel text, `cred`, `task_struct` or slab.
- Hash and compare the `nvidia.ko` text in host RAM against the on-disk module (gap G4).
- The firmware hashing in `nvidia.driver` is a start for microcode integrity.

### [M5] Hacker-forum PoC that stores and runs code in GPU memory (August 2021)

**Cite:**
- KitGuru, 2021-09-02: https://www.kitguru.net/components/graphic-cards/joao-silva/new-malware-can-hide-within-gpu-memory-buffer/ **[secondary]**. The original BleepingComputer article was not opened; Tom's Hardware, TechSpot and TechPowerUp returned truncated pages or 403.

**Technique (seller's claims only):**
- Allocates GPU memory, stores code there and executes it from there, to evade antivirus that scans system RAM.
- Windows only, OpenCL 2.0 or later.
- Tested on Intel UHD 620/630, GTX 740M, GTX 1650 and RX 5700.
- The seller said it differs from Jellyfish and does not rely on code being mapped back to userspace.
- Posted 2021-08-08 and reported sold 2021-08-25. vx-underground promised a demonstration; no demonstration or code was found.
- OpenCL 2.0 shared virtual memory as the mechanism is **an inference, not stated anywhere**.

**Artefacts:** unknown. Plausibly x86 code bytes in VRAM and an OpenCL context owned by the loader.

**Code:** none public.

**Keto:**
- `nvidia.malware.hostcode` finds PE/ELF/Mach-O images and script stagers in VRAM, but not position-independent shellcode.
- The live side has no Windows support.

### [M6] CoffeeLoader and the Armoury (ArmouryLoader) GPU packer

**Cite:**
- B. Stone-Gross, Zscaler ThreatLabz, "CoffeeLoader: A Brew of Stealthy Techniques", 2025-03-26: https://www.zscaler.com/blogs/security-research/coffeeloader-brew-stealthy-techniques
- Antiy CERT, "Comprehensive Analysis of ArmouryLoader", 2025-07-08: https://www.antiy.net/p/comprehensive-analysis-of-armouryloader-series-analysis-of-typical-loader-families-five%EF%BB%BF/

**Technique:**
- **GPU stage:** the packer XORs two hard-coded 32-byte strings to derive a key. It passes the key to an OpenCL kernel named `f` (key, encoded input, output, key size), which computes `c[i] = a[i] ^ b[i % d]`. The decoded, self-modifying shellcode is copied back to the CPU and executed.
- **Packer:** masquerades as ASUS Armoury Crate. It was first seen in 2024 (VirusTotal upload 2024-09-12) and also packs SmokeLoader.
- **Rest of the chain:** call-stack spoofing, sleep obfuscation, Windows fibers, CFG exceptions, CMSTPLUA UAC bypass and DGA fallback.
- Zscaler says the OpenCL code is probably based on an open-source PoC.

**Artefacts:**
- OpenCL C source text, passed to `clCreateProgramWithSource`, in the packer's memory.
- The driver-compiled kernel and the input and output buffers in VRAM.
- `OpenCL.dll` loaded by a process that does no graphics.
- Decrypted shellcode in a host buffer.

**Code:** malware; IOCs only.

**Keto:**
- Scan host and VRAM images for OpenCL C kernel source and its NVIDIA-compiled PTX/SASS.
- Classify "XOR with modulo key" decryptor kernels.
- Scan VRAM output buffers for shellcode.
- On Windows, flag GPU runtime loads by non-graphics processes (gaps G1 and G2).

### [M7] GPUGate / HijackLoader delivered through repo-squatted GitHub Desktop installers

**Cite:**
- Arctic Wolf (Usatenko, Grimm, Faires, Melikov), 2025-09-05: https://arcticwolf.com/resources/blog/gpugate-malware-malicious-github-desktop-implants-use-hardware-specific-decryption-abuse-google-ads-target-western-europe/
- T. Webb, GMO Cybersecurity by Ierae, 2026-01-22: https://gmo-cybersecurity.com/blog/revisiting-gpugate-repo-squatting-and-opencl-deception-to-deliver-hijackloader/

**Technique:**
- Arctic Wolf's description: an OpenCL kernel (its source XOR-encoded with 0x5A) checks that the GPU device name is at least 10 characters long. It then selects one of two hard-coded AES-128 keys for an AES-CBC (zero IV) .NET payload.
- GMO's correction: the OpenCL path is **misdirection with defects**, and the kernel never runs.
  - `clCreateBuffer` is called with `host_ptr` NULL.
  - `clSetKernelArg` receives handles by value, which returns `CL_INVALID_MEM_OBJECT`.
  - `clEnqueueNDRangeKernel` then returns `CL_INVALID_KERNEL_ARGS`.
- The real key was recovered by debugging on a physical RTX 3050 Ti.
- The practical effect is anti-sandbox: sandboxes often lack `OpenCL.dll`, which raises `DllNotFoundException`.
- GMO publishes YARA rule `MAL_Loader_WIN_1`. It requires a .NET single-file bundle marker plus OpenCL error strings such as "No OpenCL platforms found" and "generate_key".

**Artefacts:**
- Host strings and the OpenCL API import sequence.
- No meaningful VRAM state, because the kernel fails.

**Code:** malware; GMO YARA rule (licence not stated).

**Keto:**
- Shows that "uses the GPU" can mean "probes for a GPU". Host-side indicators matter more here than VRAM.
- Useful as a negative control: an OpenCL context with failed launches.

### [M8] D. Shandalov (Palo Alto Networks): "Cloak and Filter: Weaponizing the GPU and Windows Cloud Filter for File-less Execution and Privilege Escalation"

**Cite:** Hack.lu 2026, 2026-10-21. https://pretalx.com/hack-lu-2026/talk/KQCEEC/ (abstract only).

**Technique:**
- The encrypted payload is kept in VRAM and decrypted on demand by a simple XOR compute shader.
- It is delivered by hydrating Cloud Filter API (CFAPI) placeholders, so it never needs a normal user-mode allocation and never triggers a kernel I/O callback.
- Demonstrations: shellcode execution, process creation from a known-malicious sample, and a SYSTEM escalation through a DLL placeholder.
- The author suggests monitoring sync-root registration and "non-graphical compute shader" use.

**Artefacts:**
- An encrypted blob and a compiled compute shader (DXIL or SPIR-V, compiled to SASS) in VRAM.
- CFAPI sync-root registry entries.

**Code:** none announced.

**Keto:**
- Add DXBC/DXIL and SPIR-V container scanning next to cubin/PTX.
- Add Windows evidence of D3D or Vulkan compute contexts in processes that never present a frame (gaps G1 and G2).

### [M9] GPU cryptojacking families (2024-2026)

| Source | GPU-specific behaviour |
|---|---|
| Oligo Security (A. Lumelsky, G. Elbaz), "ShadowRay 2.0", 2025-11-18: https://www.oligo.security/blog/shadowray-2-0-attackers-turn-ai-against-itself-in-global-campaign-that-hijacks-ai-into-self-propagating-botnet | Exploits CVE-2023-48022 (Ray Jobs API, unauthenticated). Counts GPUs with `ray.cluster_resources()` and `nvidia-smi`. Caps use at about 60%. **23.9 GB of GPU memory in use while the Ray dashboard showed 0% GPU.** Rigel 1.22.3 GPU miner plus XMRig. Renames its process `kworker/0:0` via `/proc/$$/comm`. Binaries `rigel`, `python3.7.3`, `/usr/lib/dev/systemdev/dns-filter`. Kills competing miners. Blocks pool ports with iptables. Persists via cron and init scripts. |
| Censys ARC (M. Ellzey), "Hackers Are Attempting to Turn ComfyUI Servers Into a Cryptomining Proxy Botnet", 2026-04-06 (updated 04-08): https://censys.com/blog/comfyui-servers-cryptomining-proxy-botnet/ | Runs `nvidia-smi -c EXCLUSIVE_PROCESS` on every GPU and enables persistence mode, so only the miner can hold a context. lolMiner, Conflux Octopus, `cfx.kryptex.network:8027`. GPU miner stored as `.gpu` and run as `nv_uvm_<hex>`. Kill list covers about 100 rival-miner patterns (lolminer, gminer, nbminer, t-rex, rigel, ...). `readdir()` `LD_PRELOAD` rootkit via `/etc/ld.so.preload`. `chattr +i`. A "GPU Performance Monitor" ComfyUI node re-downloads the payload every 6 hours. |
| Microsoft Defender Experts, "Poisoned search results: GPU mining cryptojacking campaign ...", 2026-05-26: https://microsoft.com/en-us/security/blog/2026/05/26/poisoned-search-results-gpu-mining-cryptojacking-campaign-abusing-screenconnect-microsoft-net-utilities | Hollows .NET utilities (InstallUtil, RegAsm, RegSvcs, MSBuild, AppLaunch, AddInProcess, aspnet_compiler). Downloads gminer, lolMiner or SRBMiner-MULTI. Registration data includes GPU model and vendor (integrated or discrete). Adds Defender exclusions. Mutex `Global\D3F4E2A1_Svc`. Its KQL hunting queries are not GPU-specific. |
| Elastic Security Labs, REF1695 "Fake Installers to Monero", 2026-03-31 (opened by a delegated pass) | PureMiner loads `nvapi64.dll` and `atiadlxx.dll`/`atiadlxy.dll` to profile the GPU. The XMRig loader stops the miner while any of 35 analysis tools run. |
| MITRE ATT&CK T1496.001 Compute Hijacking (v1.0, modified 2025-04-15) | The only GPU text is the ShadowRay procedure (C0045). |

**Artefacts:**
- Miner names and stratum/pool strings.
- Hashing kernels (Octopus, KawPow, ...) in the JIT cache and in VRAM.
- Compute mode set to EXCLUSIVE_PROCESS with persistence mode on.
- GPU memory or utilisation without a visible owner.
- Kernel-thread masquerade names.
- Utilisation throttling.

**Code:** none needed. The IOCs are in the reports.

**Keto:**
- Already covered:
  - `indicators/miners.py` contains lolminer, gminer, srbminer, rigel, nbminer, t-rex, bzminer, teamredminer, nanominer, onezerominer, xmrig, kryptex and octopus.
  - `nvidia.malware.masquerade` catches comm/exe mismatches.
  - `nvidia.malware.gpuxview` catches NVML-versus-`/proc` hiding.
  - `nvidia.autostart` flags `ld.so.preload`.
- Missing:
  - An audit of compute mode and its owner.
  - "GPU memory used but no process / dashboard reports 0%" (ShadowRay).
  - Duty-cycle detection for throttled miners.
  - Windows coverage.

### [M10] GPU Rowhammer: GPUHammer (2025) and GPUThor (2026)

**Cite:**
- The Hacker News, 2025-07: https://thehackernews.com/2025/07/gpuhammer-new-rowhammer-attack-variant.html
- The Hacker News, 2026-08: https://thehackernews.com/2026/08/gputhor-rowhammer-defeats-ecc-on-nvidia.html

Both are **[secondary]**, from search summaries; the papers and NVIDIA's advisory were not opened.

**Technique:** Rowhammer bit flips in GDDR6, demonstrated on an RTX A6000.
- NVIDIA's guidance is to enable system-level ECC (`nvidia-smi -e 1`).
- GPUThor reportedly defeats ECC on some cards.

**Artefacts:** ECC SBE/DBE bursts and retired or remapped rows.

**Keto:**
- `nvidia.ecc` already reads the counters.
- Add a policy flag for ECC disabled on GDDR6 data-centre or workstation parts, and burst detection.

---

## 2) GPU memory forensics and remanence

### [F1] Balzarotti, Di Pietro, Villani: "The Impact of GPU-Assisted Malware on Memory Forensics: A Case Study"

**Cite:** DFRWS EU 2015. https://www.s3.eurecom.fr/docs/dfrws15_villani.pdf. DOI 10.1016/j.diin.2015.05.010, as reported by a delegated pass.

**Technique:** Defines four anti-forensic techniques and tests them on Intel integrated GPUs (i915/Beignet, Linux).

| Technique | Privilege | What the malware does |
|---|---|---|
| Unlimited Code Execution | user | Disables the i915 hangcheck watchdog (`/sys/module/i915/parameters/enable_hangcheck`), so a GPU kernel can run indefinitely. |
| Process-less execution | superuser | The kernel keeps running after its host process exits. Buffer objects and the hardware context remain in the driver, but the PID is gone. |
| Inconsistent Memory Mapping | superuser | The GPU page table maps pages that the OS page table of the process does not, as the keylogger [M2] does. |
| Context-less execution | kernel + driver knowledge | DKOM: the context is removed from the `drm_i915_private` context list with `i915_gem_context_unreference()` and zeroed. |

**Artefacts the paper parses:**
- GGTT/PPGTT, dumped through MMIO on BAR2.
- The hangcheck flag.
- GEM buffer-object lists.
- The context list.
- The register file through BAR0, especially RING HEAD and RING TAIL.

For GPUs with dedicated memory, the authors note that more of this state moves into device memory, which needs "a specialized tool" and vendor support.

**Code:** the authors say they wrote custom tools and Volatility plugins. **Whether they were released is [UNVERIFIED].**

**Keto:**
- This is the threat model Keto's cross-views should be scored against.
- Context-less execution is covered by `chanxview` and `orphanchans`.
- Process-less execution needs a channel-to-PID link from the host image (gap G3).
- Inconsistent mapping needs a host-ownership cross-view of system-memory PTEs (gap G4).
- Unlimited execution needs a watchdog/TDR tamper check plus a persistent-kernel check (gap G7).

### [F2] DFRWS 2015 Forensics Challenge (GPU malware)

**Cite:** https://github.com/dfrws/dfrws2015-challenge. README and file tree opened; last push 2021-08-14; no licence file.

**Contents:**
- `NILES.gpu.bz2`: the VRAM image.
- `NILES.lime.bz2`: the host RAM image (LiME).
- Both are hosted on Dropbox with MD5 hashes. **Whether the links still work was not checked.**
- A Volatility 2.4 profile for Xubuntu 14.04.
- `fillgpu`: a CUDA tool that loads a file into device memory, used to test dump tools.
- The GPU keylogger, user and kernel parts, USB keyboards only.
- The GPU malware source (`source.zip`).
- `nvidia-dump-fb-1.0`.
- Two partial solutions.

**The acquisition tool:** `dump_fb -o <start> -s <len> -f <file> -g <GPU-UUID>` (4 KiB aligned, root).
- It needs a patched 343.13 driver. Bowen et al. say NVIDIA produced that patch.
- It was tested on the GTX 750 Ti and the GTX 860M, which is the Lenovo Y50 in the scenario. Both are Maxwell.

**Keto:**
- This is the only public, real NVIDIA VRAM and RAM pair with known GPU malware, and the right regression corpus.
- It needs a Maxwell profile. Keto covers Pascal to Blackwell, and Maxwell's GMMU format predates VER2; that is an inference not checked against the image.
- It also needs a `dump_fb` import note (gap G6).

### [F3] Di Pietro, Lombardi, Villani: "CUDA Leaks"

**Cite:**
- arXiv 1305.7383 (2013), opened via ar5iv: https://ar5iv.labs.arxiv.org/html/1305.7383
- Journal version: "CUDA Leaks: A Detailed Hack for CUDA and a (Partial) Fix", ACM TECS 15(1):1-25 (2016), DOI 10.1145/2801153 **[metadata]**.

**Technique:** Three leaks on Fermi (Tesla C2050) and Kepler (GT 640), Linux:
- **Shared memory:** read by the next kernel. The FIFO scheduling order is shown with `%smid`.
- **Global memory:** an attacker reallocates the same amount of memory without initialising it, and gets the whole buffer.
- **Registers:** spilled into global memory by over-reserving registers in PTX; Kepler only.
- **Case study:** the AES key or plaintext of SSLShader was recovered about 30% of the time on Kepler and 12% on Fermi.
- **Fixes proposed:** zero shared memory inside the kernel, zero global memory in the runtime, and fix register-spill placement.

**Artefacts:** freed global memory and residual key schedules.

**Code:** none published.

**Keto:** supports the existing `nvidia.residual` and `nvidia.aeskeys` design. No new capability needed.

### [F4] Lee, Kim, Kim, Kim: "Stealing Webpages Rendered on Your Browser by Exploiting GPU Vulnerabilities"

**Cite:** IEEE S&P 2014, pp. 19-33, DOI 10.1109/SP.2014.9. https://sangho.cv/papers/lee:gpu.pdf

**Technique:**
- Neither NVIDIA nor AMD GPUs initialise newly allocated memory.
- The attacks dump memory during the victim's run and right after its context ends.
- On a GTX 780, Chromium and Firefox webpage textures were found as 32-bit pixels stored as **0x00RRGGBB (alpha byte zero)**, in a hardware "rearranged" (tiled) layout that the authors did not de-tile.
- They identify visited pages by pixel-sequence matching (Jaccard index) and RGB-histogram matching, with up to 95.4% accuracy.
- **Defences proposed:** clear newly allocated pages, as WebGL does, and clear local and private memory at context switch. Their measurement: 79 µs to clear, against NVIDIA's 25 µs context-switch target.

**Artefacts:** texture residue in freed VRAM.

**Code:** none published.

**Keto:**
- `nvidia.surfaces` already de-tiles block-linear layouts, which goes beyond Lee.
- Its auto-detector only accepts blocks whose alpha byte is 0xFF (90% threshold), so it **misses XRGB textures with alpha 0x00** like the ones Lee recovered (gap G10).

### [F5] Zhou, Diao, Liu, Li, Zhang, Liu: "Vulnerable GPU Memory Management: Towards Recovering Raw Data from GPU"

**Cite:** PoPETs 2017(2):57-73, DOI 10.1515/popets-2017-0016. https://petsymposium.org/popets/2017/popets-2017-0016.php. Full text opened via ar5iv: https://ar5iv.labs.arxiv.org/html/1605.06610

**Technique:**
- **Capture:** OpenCL fills free VRAM with 0xff, polls the free-memory counter, and dumps the residue when it jumps. It confirms the victim from the process list.
- **Reconstruction:**
  1. Drop all-0xff and all-0x00 4 KiB blocks, then merge consecutive blocks into tiles.
  2. Keep 4-byte pixels whose alpha byte is mostly 0x00 or 0xff, with a 20% threshold.
  3. Find the row width from the period of the FFT amplitude spectrum.
  4. Find the leading offset by column dissimilarity.
- **Targets:** Chrome, Adobe Reader, GIMP and Matlab.
- **Hardware:** AMD HD 6350 and R7 250X, and NVIDIA GTX 750 (driver 340.29, the Matlab test).
- **VM passthrough:** in QEMU, 25 of 29 images were fully recovered, because the GPU is not reset between VMs.

**Artefacts:** freed VRAM, and the attacker's 0xff fill pattern.

**Code:** none published.

**Keto:**
- Reuse the FFT, or a cheaper autocorrelation, for row-width detection, and accept alpha 0x00 (gap G10).
- Add a "remanence scraper" detector: a process that allocates almost all free VRAM, and large regions of uniform fill bytes in an image (gap G13).

### [F6] Bellekens et al.: data remanence of CUDA global memory

**Cite:** DISSECT 2015 (delegated pass). https://strathprints.strath.ac.uk/53209/1/Bellekens_etal_DISSECT2015_data_remanence_digital_forensic_investigation_CUDA.pdf

**Findings:**
- The allocate-and-copy-back method recovered global memory on GTX 295, K20m and Tegra K1.
- `nvidia-smi` GPU reset did **not** clear memory; a hard host reboot did.

**Keto:** put the lifetime facts in `ACQUISITION.md` (a reset does not clear memory; a cold boot does), and reuse them in triage SOPs.

### [F7] Zhang, Yang, Rogers, Hansen: "Forensically Sound Retrieval and Recovery of Images from GPU Memory"

**Cite:** ICDF2C 2015, LNICST 157. https://eudl.eu/pdf/10.1007/978-3-319-25512-5_5 **[UNVERIFIED]**: the page returned HTTP 403.

**Reported:** Windows Photo Viewer images were recovered from NVIDIA memory. The authors are reported to conclude that more work is needed on whether GPU acquisition can be forensically sound.

### [F8] Naghibijouybari, Neupane, Qian, Abu-Ghazaleh: "Rendered Insecure: GPU Side Channel Attacks are Practical"

**Cite:** ACM CCS 2018, DOI 10.1145/3243734.3243831. https://www.cs.ucr.edu/~nael/pubs/ccs18.pdf

**Technique:** Spy processes use three channels:
- The OpenGL `NVX_gpu_memory_info` query (`GPU_MEMORY_INFO_CURRENT_AVAILABLE_VIDMEM_NVX`).
- CUPTI performance counters.
- Timing.

The paper demonstrates three attacks:
1. Fingerprinting websites.
2. Recovering password-box keystroke timing from 128 KiB allocation events.
3. Extracting neural-network parameters with a CUDA spy.

The hardware was a GTX 745 (Maxwell) and a Titan V. The authors propose limiting the rate and precision of these calls.

NVIDIA's fix is tracked as CVE-2018-6260: GPU performance counters can be restricted to administrators with `NVreg_RestrictProfilingToAdminUsers` / `RmProfilingAdminOnly`. **This is from the NVD and NVIDIA ERR_NVGPUCTRPERM pages seen in search results; NVIDIA bulletin 4772 itself was not opened.**

**Keto:**
- `nvidia.profiling` already checks the parameter and finds CUPTI and nvperf users.
- A live detector for high-rate memory-info polling would need API tracing and is low priority.

### [F9] Trail of Bits (H. Khlaaf, T. Sorensen): "LeftoverLocals"

**Cite:** 2024-01-16, CVE-2023-4969. https://blog.trailofbits.com/2024/01/16/leftoverlocals-listening-to-llm-responses-through-leaked-gpu-local-memory/

**Technique:**
- A "listener" kernel copies uninitialised workgroup-local memory into a global buffer.
- A "writer" kernel plants canary values to test whether a platform leaks.
- The PoC uses OpenCL, Vulkan (SPIR-V) and Metal.
- Affected: Apple, AMD, Qualcomm and some Imagination GPUs. **NVIDIA, Arm and Intel were reported not affected.**

**Code:** `trailofbits/LeftoverLocalsRelease`, Apache-2.0.

**Keto:** low priority while Keto is NVIDIA-only. If AMD or Apple support is added, reuse the listener approach for live local-memory remanence tests.

### [F10] Bowen, Case, Baggili, Richard: "A step in a new direction: NVIDIA GPU kernel driver memory forensics"

**Cite:** FSI: Digital Investigation 49 (2024) 301760, DFRWS USA 2024. Open access, CC BY-NC-ND. https://par.nsf.gov/servlets/purl/10572190

**Technique:**
- Uses NVIDIA's open-gpu-kernel-modules to recover **NVOC** objects from host RAM. Every NVOC object's first member points to its `NVOC_RTTI`, which points to an `NVOC_CLASS_DEF` holding the class ID, size and name.
- Volatility 2.6 plugins:
  - `CheckNvidia`: uses `module_kset` and `pNVRM_ID`.
  - An `NVOC_CLASS_DEF` scan over module pages, against known class IDs plus a heuristic.
  - A reverse structure lookup, for example `OBJGPU`, class ID 0x7ef3cb.
  - A GPU-accounting parser for the `GpuAccounting` NVOC object, which holds start and end times and live and dead PIDs.
- NVSYMMAP maps symbols between the open and closed driver flavours through kallsyms.
- **Limitations stated:** accounting is off by default.
- **Future work stated:** physical VRAM imaging. The paper notes that the only physical VRAM capture so far came from an NVIDIA patch for DFRWS 2015.

**Code:** the cited repository `github.com/LSUACL/GPU-Forensics` (plugins, NVSYMMAP, memory snippets) **returns 404** (GitHub API, 2026-11-17).

**Keto:**
- This is the closest prior work and is complementary: Bowen works from RAM, Keto from VRAM.
- Reuse the NVOC RTTI/class-definition scanning idea to tie channels and address spaces to PIDs.
- Parse `GpuAccounting` from a host image, so accounting history is available offline (gaps G3 and G15).
- [HOST_SIDE_DETECTION.md](HOST_SIDE_DETECTION.md) section 1.2 details the RM object model.

### [F11] Volatility 3 `linux.graphics.fbdev`

**Cite:** Volatility Foundation, plugin version 1.0.0 (2024), Volatility Software License 1.0. https://volatility3.readthedocs.io/en/latest/_modules/volatility3/plugins/linux/graphics/fbdev.html

**Technique:** Walks `num_registered_fb` / `registered_fb` to each `fb_info`, reads `screen_base` through the kernel address space, and writes a PNG. It handles bitfield pixel formats, including absent alpha, and saves FOURCC formats raw.

**Keto:** this is the host-side analogue of `nvidia.surfaces`, already mapped in `VOLATILITY_MAPPING.md`. Reuse the idea of honouring the declared bitfields, and accept surfaces with no alpha.

### [F12] Yan, Karlin, Grant: "Revealing NVIDIA Closed-Source Driver Command Streams for CPU-GPU Runtime Behavior Insight"

**Cite:** arXiv 2604.26889 (2026-04-29). https://arxiv.org/abs/2604.26889 (abstract only).

**Technique:** Captures the command streams that the closed userspace driver submits. It combines the open kernel driver, instrumentation of the memory-mapping path, and a hardware watchpoint on the userspace doorbell mapping. Case studies cover DMA submission modes and CUDA Graphs.

**Code:** none stated.

**Keto:** an independent source of ground-truth pushbuffer streams for validating `nvidia.pushbuf`, `nvidia.copies` and `nvidia.launches`. The doorbell-watchpoint idea is too intrusive for forensics.

### [F13] "From Bytes to Behavior: Request-Level Attribution from Live GPU Hidden States"

**Cite:** arXiv 2611.18272 (2026). https://arxiv.org/abs/2611.18272 (opened by a delegated pass; authors not re-checked).

**Technique:** Attaches cuda-gdb 13.0 to live LLM-serving processes to read hidden-state tensors and attribute requests.
- Tested on 33 decoder-only models.
- The authors call it "non-modifying but not non-intrusive".
- The process slows down 46-192x, and ptrace is required.

**Keto:** evidence that cuda-gdb is a workable per-process acquisition path. It also shows that AI-workload VRAM, such as KV caches and activations, is an evidence class `nvidia.residual` could classify.

### [F14] nbdkit `vram` plugin

**Cite:** libguestfs nbdkit, plugin added in nbdkit 1.46, BSD-style licence, Red Hat. https://libguestfs.org/nbdkit-vram-plugin.1.html

**Technique:** Exposes OpenCL-allocated VRAM as a network block device. The data is volatile and is lost when nbdkit exits.

**Keto:** a benign, dual-use example of whole filesystems living in VRAM. `nvidia.residual` and `nvidia.malware.hostcode` should recognise filesystem and archive signatures (ext4/NTFS/FAT superblocks, ZIP/7z) in VRAM (gap G14).

---

## 3) Acquisition methods

Sources in this section were opened by a delegated research pass unless marked. The table at the end is the
summary.

### [A1] envytools `nva` tools (PRAMIN / BAR access)

**Cite:**
- Tool sources: https://raw.githubusercontent.com/envytools/envytools/master/nva/README, `nva/nvadownload.c`
- envytools docs: https://envytools.readthedocs.io/en/latest/hw/bus/bars.html and `hw/mmio.html`
- Kernel nova-core PRAMIN doc: https://docs.kernel.org/gpu/nova/core/pramin.html

**Method:**
- `nvadownload <addr> <len>` reads physical VRAM (G80 and later).
- For each address it writes the window base `0x1700 = addr >> 16`, then reads `BAR0 + 0x700000 + (addr & 0xffff)`. It never restores 0x1700.
- The nova doc names 0x1700 `NV_PBUS_BAR0_WINDOW`: TARGET in bits 25:24 (0 is VRAM), address bits 39:16 in bits 23:0, a 1 MiB window, 64 KiB alignment. The doc says this is "current as of the Ampere family".
- Other tools:
  - `nvagetbios` reads the VBIOS.
  - `nvafakebios` uploads a VBIOS, so it writes.
  - `nvaupload` writes VRAM.

**Reach:** all of physical VRAM, including RM-private regions.

**Soundness:** poor. It writes a register for every read, races the driver, and the README warns the tools can hang the machine.

**Licence:** MIT (GitHub API).

**Keto:** do not implement this. Document a dead-box SOP and import the result with base-offset and 0x1700 before/after metadata.

### [A2] nouveau debugfs / nvkm

**Cite:**
- https://raw.githubusercontent.com/torvalds/linux/master/drivers/gpu/drm/nouveau/nouveau_debugfs.c
- GSP log patch, 2024: https://lists.freedesktop.org/archives/nouveau/2024-November/046143.html

**Method:**
- debugfs files `vbios.rom`, `strap_peek`, `pstate` and `gpuva` (the VA-region table).
- GSP-RM logs `loginit`, `logintr`, `logrm` and `logpmu`.

**Reach:** no VRAM dump file.

**Keto:** import `vbios.rom` as the `rom` segment, and keep `gpuva` and the GSP logs as sidecars.

### [A3] PCIe DMA: PCILeech / MemProcFS; Thunderclap

**Cite:**
- https://github.com/ufrisk/pcileech (AGPL-3.0)
- MemProcFS (AGPL-3.0, GitHub API)
- LeechCore FPGA wiki
- Markettos et al., "Thunderclap", NDSS 2019

**Reach:** host RAM. Reading a GPU BAR peer-to-peer is not documented **[UNVERIFIED]**.

**Requirement:** the IOMMU or Windows Kernel DMA Protection must be off.

**Keto:** already supported as a `sysmem` import. Do not link the AGPL code; run the tools externally.

### [A4] sysfs BARs, VFIO, hypervisors, ReBAR

**Cite:**
- https://docs.kernel.org/PCI/sysfs-pci.html
- https://docs.kernel.org/driver-api/vfio.html
- https://learn.microsoft.com/en-gb/windows-hardware/drivers/display/resizable-bar-support
- https://libvmi.com/

**Method:** `/sys/bus/pci/devices/<bdf>/resource1` (BAR1) is mmap-only for memory BARs.

**Reach:**
- On NVIDIA, BAR1 is translated by the GPU's own MMU, so it shows only what the driver mapped.
- Resizable BAR enlarges the aperture, not the mapping.
- The `RMForceStaticBar1=1` registry option may map all of VRAM statically **[UNVERIFIED]**.

**VFIO:** means unbinding `nvidia.ko`, which destroys the live driver state; it is a dead-box method.

**Hypervisors:** LibVMI reads guest RAM only. Whether QEMU dumps a passed-through BAR is **[UNVERIFIED]**.

**Confidential computing:** H100 CC mode blocks host access to protected VRAM **[UNVERIFIED]**.

### [A5] Userspace driver over VFIO: tinygrad "NV" PCI interface

**Cite:** source read directly:
- https://raw.githubusercontent.com/tinygrad/tinygrad/master/tinygrad/runtime/support/system.py
- https://raw.githubusercontent.com/tinygrad/tinygrad/master/tinygrad/runtime/support/nv/nvdev.py

tinygrad is MIT.

**Method:**
- tinygrad can drive an NVIDIA GPU with no `nvidia.ko`. It binds the device to `vfio-pci` and opens `/dev/vfio/<group>`, then boots the GSP and Falcon itself.
- It builds GMMU VER2/VER3 page tables directly in VRAM, using encoders/decoders for PDE, dual PDE and PTE with an aperture field.
- It selects MMU version 3 when the architecture is 0x1a or later.

**Reach:** for acquisition, this proves full programmatic VRAM access without the vendor driver.

**Soundness:** initialising the GPU certainly changes state; whether boot scrubs VRAM is **unknown, not tested**.

**Detection relevance:** GPU work done this way is invisible to NVML and to `/dev/nvidia*` (gap G8).

### [A6] NVIDIA tools

**cuda-gdb core dumps**
- **Cite:** https://docs.nvidia.com/cuda/cuda-gdb/index.html, and the CUDA driver API coredump group.
- **Switches:**
  - `CUDA_ENABLE_COREDUMP_ON_EXCEPTION` and `CUDA_COREDUMP_FILE` (`%h %p %t`).
  - `CUDA_ENABLE_USER_TRIGGERED_COREDUMP` with `CUDA_COREDUMP_PIPE`.
  - `CUDA_COREDUMP_GENERATION_FLAGS`: `skip_global_memory`, `skip_shared_memory`, `gzip_compress` and others.
  - The equivalent API is `cuCoredumpSetAttribute[Global]`.
- **Output:** an ELF `.nvcudmp`, opened with `target cudacore`. It covers only the process's own contexts.
- **Section layout:** UNVERIFIED.

**compute-sanitizer**
- **Cite:** https://docs.nvidia.com/compute-sanitizer/ComputeSanitizer/index.html
- `initcheck` reports reads of uninitialised memory.
- `--generate-coredump` covers faulting threads only.

**Nsight Aftermath**
- **Cite:** https://developer.nvidia.com/nsight-aftermath
- **Output:** a `.nv-gpudmp` mini-dump with warps, the faulting unit and the MMU fault.
- **Format:** undocumented; it can be decoded only with the `GFSDK_Aftermath_GpuCrashDump_*` decoder. It holds no VRAM.

**nvidia-bug-report.sh / NvDebugDump**
- **Cite:**
  - https://download.nvidia.com/XFree86/Linux-x86/384.59/README/nvidia-debugdump.html
  - open RM `src/nvidia/src/kernel/diagnostics/nv_debug_dump.c`
  - `ctrl0000nvd.h`
- The dump is protobuf (`NVDEBUG_NVDUMP`), fetched with `NV0000_CTRL_CMD_NVD_GET_DUMP` (0x602) and the NVLOG calls (0x604-0x606). It holds RM state but no VRAM.

**Licence:** open-gpu-kernel-modules files are MIT, and the linked module is dual MIT/GPLv2 (`COPYING`).

**Keto:**
- Add an `.nvcudmp` importer.
- Add an NvDebugDump protobuf decoder that takes field names from the open headers.
- `nvidia.bugreport` already parses the text report.

### [A7] Windows (WDDM)

**Cite:**
- https://learn.microsoft.com/windows-hardware/drivers/debugger/task-manager-live-dump
- https://learn.microsoft.com/en-us/windows-hardware/drivers/display/tdr-debuggability-improvements
- https://microsoft.github.io/DirectX-Specs/d3d/D3D12GpuDumps.html (preview spec v0.03)

**What exists:**
- Live kernel dumps, including Task Manager live dumps.
- TDR dumps carrying an opaque IHV blob, through `DxgkDdiCollectDbgInfo`.
- D3D12 GPU dumps (`.dxdmp`).

None of these is documented to contain VRAM. A `!dxgkdx`-style debugger extension is **[UNVERIFIED]**.

**Keto platform finding** (see [../ACQUISITION.md](../ACQUISITION.md)): on WDDM the driver scrubs device memory, so CUDA residual capture returns zeros.

### [A8] Research capture methods

| Paper | Capture method |
|---|---|
| [F3] CUDA Leaks, [F6] Bellekens et al. | CUDA allocate-and-copy-back of freed memory |
| [F5] Zhou et al. | OpenCL fill-and-poll |
| [F9] LeftoverLocals | listener kernel |
| [F1] Villani et al. | LiME/pmem skip PCI "Reserved" ranges; Intel GTT/PPGTT reached through BAR2 MMIO |
| [F10] Bowen et al. | host RAM only (Surge Collect). Notes that userland CUDA/OpenCL capture changes RAM and possibly VRAM |
| [F2] DFRWS 2015 | NVIDIA-patched driver plus `dump_fb` |

### Comparison

| Method | Reach | Platform | Privilege | State change | Keto import |
|---|---|---|---|---|---|
| PRAMIN window (`nvadownload`) | all physical VRAM | Linux | raw BAR0 | writes 0x1700 on every read | raw import exists; add base and window metadata |
| sysfs `resource1` (BAR1) mmap | BAR1-mapped pages only | Linux | root | low (reads) | add `bar1` acquisition with BAR1 size/ReBAR metadata |
| VFIO region read / tinygrad-style userspace driver | BAR0/BAR1, potentially all VRAM | Linux | root, driver unbind | high (driver unbound; GPU re-initialised) | raw import; SOP needed |
| `dump_fb` + patched 343.13 driver | VRAM range | Linux, Maxwell era | root | patched driver | raw import; Maxwell profile missing |
| PCILeech / FPGA | host RAM | any (hardware) | physical access | none on GPU | `sysmem` (exists) |
| cuda-gdb `.nvcudmp` | the process's own contexts | Linux (Windows via Nsight) | user/ptrace | halts the app | new ELF adapter |
| CUDA/OpenCL remanence | freed allocations | Linux (zeros on WDDM) | user | allocates VRAM | `cuda` (exists) |
| NvDebugDump / bug report | RM state, logs | Linux | root | low | protobuf adapter; text parser exists |
| Aftermath `.nv-gpudmp` | fault metadata | Windows/Linux | user | none | JSON sidecar via SDK |
| nouveau debugfs | VBIOS, GSP logs, VA list | Linux, nouveau | root | none | `rom` segment plus sidecars |
| Windows live / TDR / `.dxdmp` dumps | host kernel; opaque IHV blob | Windows | admin | low | `sysmem`; IHV blob opaque |

---

## 4) Detection and telemetry

Opened by a delegated research pass unless marked. Two Sigma rule IDs (`66c3b204-...`, `9069ea3c-...`) and the
Elastic licence were re-checked against the raw repository files.

### [D1] NVML

**Cite:** https://docs.nvidia.com/deploy/nvml-api/api/group__nvmlDeviceQueries.html and `group__nvmlAccountingStats.html`

**Security-relevant calls:**
- Process lists, including `nvmlDeviceGetRunningProcessDetailList` on Hopper and later.
- `nvmlDeviceGetProcessUtilization` and `nvmlDeviceGetProcessesUtilizationInfo`.
- FBC and encoder sessions.
- Compute mode and persistence mode.
- BAR1 memory info.
- Remapped rows.
- `nvmlDeviceGetConfComputeGpuAttestationReport`.

**Documented caveats:**
- The compute process list shows only processes with an active context; OpenGL and DirectX processes are not listed.
- Turning accounting on needs root.
- Accounting entries survive process exit in a circular buffer.

**Keto:** already uses most of these.
- Add a compute-mode/owner audit.
- Add `RunningProcessDetailList`.
- Add attestation-report capture on CC-capable parts.

### [D2] DCGM and dcgm-exporter

**Cite:**
- https://docs.nvidia.com/datacenter/dcgm/latest/user-guide/feature-overview.html
- `NVIDIA/dcgm-exporter` `etc/default-counters.csv`

Both projects are Apache-2.0.

**What DCGM provides:**
- Job and PID statistics (`dcgmi stats`): energy, maximum memory, SM and memory utilisation, PCIe traffic, ECC and Xid.
- A policy and health engine.
- Profiling metrics such as `DCGM_FI_PROF_SM_ACTIVE`, `DRAM_ACTIVE` and `PCIE_TX/RX_BYTES`.

The profiling metrics are **device-level**. That makes them useful for finding activity that no process owns.

**Keto:** ingest `dcgmi stats --pid -v` output and a dcgm-exporter `/metrics` scrape with `urllib`, then cross-view the results against the process lists (gap G5).

### [D3] nvidia-smi

**Cite:** https://docs.nvidia.com/deploy/nvidia-smi/index.html

**Relevant modes:**
- `pmon`: per-process SM, memory, encoder and decoder utilisation, plus framebuffer memory.
- `--query-compute-apps` and `--query-accounted-apps`.

Whether non-root users see other users' processes is **[UNVERIFIED]**.

**Attacker use:** `nvidia-smi -c EXCLUSIVE_PROCESS`, `nvidia-smi` probes for GPU presence ([M9]) and `nvidia-smi -e` ([M10]).

### [D4] Windows GPU telemetry

**Microsoft-Windows-DxgKrnl ETW**
- Provider GUID `{802EC45A-1E99-4B83-9920-87C98277BA9D}`.
- Keywords: Base, Profiler, Resource, Memory, GPUScheduler, GPUVA, VirtualGpu, HardwareSchedulingLog, Present and PerfData.
- **Source:** read locally with `logman query providers Microsoft-Windows-DxgKrnl` on Windows 11 build 26200. No Microsoft page lists them, and event IDs were not checked.

**GPUView / WPR**
- **Cite:** https://learn.microsoft.com/windows-hardware/drivers/display/using-gpuview
- WPR has a built-in "GPU" profile.
- The capture contains command-buffer submissions, resource create/destroy/lock/bind events and DMA timings.

**Performance counters**
- `\GPU Engine(*)\Utilization Percentage` and `Running Time`.
- `\GPU Process Memory(*)\Dedicated Usage` and `Shared Usage`.
- Instance names have the form `pid_<pid>_luid_..._eng_<n>_engtype_<type>`. Counter sets were listed locally; the Microsoft doc URL returned 404.
- Task Manager's GPU view is built from VidSch and VidMm data and needs WDDM 2.0 or later (DirectX blog, 2017-07-21).

**TDR registry**
- **Cite:** https://learn.microsoft.com/en-us/windows-hardware/drivers/display/tdr-registry-keys
- Values under `HKLM\System\CurrentControlSet\Control\GraphicsDrivers`: `TdrLevel=0` turns detection off, `TdrDebugMode=1` ignores timeouts, and `TdrDelay` defaults to 2 s.
- Microsoft says end users should not change these keys. Intel's 2015 analysis ([M3]) treats a change as an indicator.

**More detail:** [HOST_SIDE_DETECTION.md](HOST_SIDE_DETECTION.md) section 2.

**Keto:** there is no Windows live source. This is the largest coverage gap (gap G1).

### [D5] Detection content

| Rule set | Licence | GPU-relevant content found |
|---|---|---|
| SigmaHQ | DRL 1.1 | Rules (only the first two IDs below were re-checked against raw files):<br>- "Potential Crypto Mining Activity" `66c3b204-9f88-4d0a-a7f7-8a57d521ca55`: `--donate-level=0`, `stratum+tcp://`, `--nicehash`, `--algo=rx/0`<br>- "Linux Crypto Mining Indicators" `9069ea3c-b213-4c52-be13-86506a227ab1`<br>- auditd coinminer `071d5e5a-...`<br>- mining-pool DNS `fa5b1358-...`<br>- miner user agent `fa935401-...`<br>- vulnerable WinRing0 driver `1a42dfa6-...`<br>- WMIC GPU/driver discovery `9d5a1274-...`<br>- Electron `--gpu-launcher` `378a05d8-...`<br>**No rule mentions CUDA, OpenCL, `--cuda`/`--opencl` or GPU utilisation.** `nvidia-smi` appears only as a false-positive filter. |
| Elastic detection-rules | Elastic License 2.0 | - "Suspicious Mining Process Creation Event" `e2258f48-...`<br>- "Shell or Suspicious Process Spawned by Ray Worker" `fc7b9873-...` (names GPU cryptomining)<br>- ECS cryptomining<br>- swap modification (T1496.001)<br>Nothing based on GPU telemetry. |
| Splunk security_content | Apache-2.0 | - "XMRIG Driver Loaded" (WinRing0; moved to `removed/`)<br>- suspicious driver path<br>- `xmrig` and `cloud_cryptomining` stories<br>Zero hits for nvidia or CUDA. |
| GMO YARA `MAL_Loader_WIN_1` ([M7]) | not stated | OpenCL error strings plus a .NET bundle marker. |
| Microsoft Defender + Intel TDT (MS Security blog, 2021-04-26) | n/a | CPU-PMU machine learning for CoinMiner, which can offload inference to the integrated GPU. It does not detect GPU mining. Intel "Accelerated Memory Scanning" (memory scanning on the iGPU) is **[secondary/UNVERIFIED]**. |

### [D6] ATT&CK, ATLAS, D3FEND (fetched November 2026)

**ATT&CK pages with GPU text:**
- T1496.001 Compute Hijacking: the ShadowRay procedure.
- T1110.002 Password Cracking: the analytic mentions "GPU invocation".
- T1218.015 Electron Applications: `--gpu-launcher`.
- T1082 System Information Discovery: several families collect video-card information.

**ATT&CK pages with no GPU text:** T1027, T1140, T1564, T1620, T1056.001, T1113, T1014, T1574.006, T1497, T1542 and T1055. The mapping below is this document's suggestion, not ATT&CK's. T1036 and T1068 pages were not checked.

| Technique | Applies to |
|---|---|
| T1027 / T1140 | GPU packers ([M1], [M6]) |
| T1497 | GPU-gated sandbox evasion ([M6], [M7]) |
| T1056.001 | GPU keylogging ([M2]) |
| T1113 | NvFBC, framebuffer access |
| T1014 / T1574.006 | `LD_PRELOAD` rootkits, CUDA/NVTX injection |
| T1564 | data hidden in VRAM ([M5], [M8]) |
| T1542 | VBIOS/firmware |
| T1036 | masquerade |
| T1068 | driver backdoor ([M4]) |

**MITRE ATLAS:** AML.T0008.000 (GPU workspaces), AML.T0010.000 (Hardware, formerly "GPU Hardware"), AML.T0034 Cost Harvesting, and AML.CS0023 ShadowRay.

**D3FEND** (MIT): has the artefact classes `GraphicsProcessingUnit`, `GraphicsCardFirmware` and `ComputeDeviceEvent`, but no GPU-specific countermeasure.

### [D7] Academic detection

| Work | Status | Finding |
|---|---|---|
| Loutfi, "SMMDecoy" (ICISSP 2019, DOI 10.5220/0007578505800587) | opened | Detects GPU keyloggers by planting decoy keystrokes from SMM. |
| Pott, Gulmezoglu, Eisenbarth (CODASPY '23, DOI 10.1145/3577923.3583655) | landing page opened | CPU-counter miner detection fails once mining moves to the GPU. Adding GPU metrics reaches 99.86%. |
| Tanana, arXiv 2408.14554 (2024) | opened | Per-application GPU load and VRAM features. About 80% true positives at about 20% false positives. |
| Almusaddar et al., "ShadowScope", arXiv 2509.00300 (2025) | opened | GPU kernel validation from side-channel signals. |
| Koromilas et al., "GRIM" (RAID 2016) | **[metadata]** | The GPU as a kernel-integrity monitor. |
| Xiao et al., "MagTracer" (MobiCom 2023) | **[UNVERIFIED]** | |

---

## 5) Reusable open-source assets and licences

Keto's `pyproject.toml` declares it **proprietary**. Facts, formats and ideas can be reused freely. *Code* can
be copied only from permissive licences (MIT, BSD, Apache-2.0), with attribution. Copyleft code (GPL, AGPL) must not
be linked or copied; run such tools externally and import their output. CC BY-NC-ND and Elastic License 2.0 carry
use restrictions.

| Asset | Licence (as checked) | What to reuse |
|---|---|---|
| NVIDIA `open-gpu-doc` | MIT | Class headers (method names), `dev_mmu` / `dev_ram` field layouts, QMD headers. Already the provenance source for Keto profiles. Use it for QMD V04/V05 and pre-Pascal MMU formats. |
| NVIDIA `open-gpu-kernel-modules` | MIT per file; module dual MIT/GPLv2 (`COPYING`) | NVOC class IDs and object layouts ([F10]). `GpuAccounting`. `nv_debug_dump.c` and the `ctrl0000nvd.h` NvDebugDump protobuf ([A6]). Xid sources. |
| Mesa `src/nouveau/headers` (`nv_push_dump.c`, `class_parser.py`, `update-from-open-gpu-doc.py`) | MIT (SPDX header in `nv_push_dump.c`) | A reference pushbuffer dumper, and a generator that turns open-gpu-doc class headers into method-name tables. Cross-check `nvidia.pushbuf`'s class database against it. |
| tinygrad (`runtime/ops_nv.py`, `runtime/autogen/nv_570/580/610/615.py`, `support/nv/nvdev.py`, `support/system.py`) | MIT | Python bit-field tables for QMD V03_00 and **V05_00 (Blackwell)**, GPFIFO/doorbell submission, GMMU VER2/VER3 PDE/PTE encode-decode, VFIO access. Gives ground truth for profile tests and the missing QMD versions (gap G12). |
| envytools (`rnndb`, `nvbios`, `envydis`, `demmt`, `nva`) | MIT (GitHub API; the README does not state it) | rnndb register/method/structure XML. `nvbios` VBIOS structure decoding to extend `nvidia.vbios`. `envydis` for older ISAs. `nva` only as an external dead-box tool. |
| CuAssembler | MIT | SASS instruction encodings, to improve `sassfind` / `malfind` code detection beyond epilogue heuristics. |
| Volatility 3 (`linux.graphics.fbdev` and the framework) | Volatility Software License 1.0 | Plugin conventions, already mirrored. Pixel-bitfield handling ([F11]). Do not copy code without checking VSL compatibility. |
| DFRWS 2015 challenge corpus | No licence file; submissions had to be free software | `NILES.gpu`, `NILES.lime`, `fillgpu`, keylogger, malware source, `nvidia-dump-fb` patch: a regression corpus ([F2]). |
| trailofbits `LeftoverLocalsRelease` | Apache-2.0 | Listener/writer kernels for local-memory remanence tests (non-NVIDIA). |
| `FluffyPancakes/Demon` | GPL-2.0 | Lab-only ground-truth generation for GPU-keylogger artefacts. **No code reuse.** |
| `AbdouRoumi/GpuAbuser-Malware` | MIT (per README; LICENSE file not opened) | OpenCL payload-decryption and anti-debug samples, for ground-truth images of [M6]-style packers. |
| NVIDIA DCGM, dcgm-exporter | Apache-2.0 | Field IDs and metric names for ingestion ([D2]). |
| SigmaHQ rules | DRL 1.1 (attribution) | Miner command-line and pool indicators. Format to emit Keto-derived Sigma rules. |
| Splunk `security_content` | Apache-2.0 | Detection YAML schema and miner stories. |
| Elastic `detection-rules` | Elastic License 2.0 | Reference only. Avoid redistribution inside a hosted service. |
| PCILeech, MemProcFS | AGPL-3.0 | External acquisition tools only. |
| nbdkit `vram` plugin | BSD-style | A benign VRAM-resident filesystem generator for tests ([F14]). |
| Bowen et al. paper | CC BY-NC-ND | Knowledge only. Its code repository is 404. |
| MITRE ATT&CK / ATLAS; D3FEND | ATT&CK terms of use (not re-checked); D3FEND MIT (per delegated pass) | Technique IDs for tagging findings. |

---

## 6) Gap analysis for Keto

### Already covered (do not rebuild)

| Capability | Plugins | Motivated by |
|---|---|---|
| Linux injection and persistence | `envars`, `injection`, `autostart` | Jellyfish, GHOST |
| Masquerade and hidden GPU processes | `masquerade`, `gpuxview` | ShadowRay, GHOST |
| Miner names, pools and algorithms | `miner`, `cryptojack`, `computecache` | [M9] |
| Context-less and hidden channels | `chanxview`, `orphanchans`, `runlist` | [F1] |
| Remanence and AES schedules | `residual`, `aeskeys` | [F3], [F4], [F5] |
| Block-linear de-tiling | `surfaces` | beyond [F4] |
| Profiling exposure | `profiling` | [F8] |
| Host executables in VRAM | `hostcode` | [M5] |
| Driver/library integrity, user mode | `libhooks`, `integrity` | |
| Xid and bug-report parsing | `xid`, `bugreport` | |

### Ranked gaps

Ranking weighs (1) evidence that the technique is used in the wild or is the documented research threat model,
(2) how blind Keto is today, and (3) cost.

| # | Missing capability | Motivating sources | One-line implementation idea |
|---|---|---|---|
| G1 | **Windows live triage of GPU use** (all in-the-wild GPU-evasion samples are Windows) | [M5] [M6] [M7] [M8] [M9] MS 2026; [D4]; HOST_SIDE_DETECTION.md section 2 | Add a Windows live source: PDH `GPU Engine` / `GPU Process Memory` per PID, enumerate modules (`OpenCL.dll`, `nvcuda.dll`, `nvapi64.dll`, `d3d12.dll` + compute) per process via Toolhelp/PSAPI over ctypes, and flag GPU-engine use by processes with no window, no signature, or living in temp/installer paths. |
| G2 | **Non-CUDA GPU code and GPU-decryptor detection** (OpenCL C source, SPIR-V, DXBC/DXIL; XOR-with-modulo-key kernels; GPU-gate strings) | [M1] [M6] [M7] [M8]; GMO YARA | Extend the code scanners: regex for `__kernel void` + `get_global_id`, SPIR-V magic `0x07230203`, `DXBC` containers (format facts from the specs, not re-verified here) in host and VRAM images; classify tiny kernels whose body is `out[i] = in[i] ^ key[i % n]`; ship the GMO OpenCL error-string set as built-in indicators. |
| G3 | **Channel-to-PID attribution offline (process-less execution)** | [F1] process-less; [F10] NVOC objects; HOST_SIDE_DETECTION.md sections 1.2-1.3 | Add a host-image plugin that scans `nvidia.ko` data for `NVOC_CLASS_DEF` / `NVOC_RTTI` chains, walks RM client and channel objects to their PID, and joins them with `chanscan` instance blocks by instance address and page-directory base. |
| G4 | **GPU-to-host mapping ownership cross-view (inconsistent mapping, keylogger, driver backdoor)** | [M2] [M4] [F1] | For every `SYSTEM_*` aperture PTE, take the host PFN from `--host-image`, check it against the controlling process's pinned/mapped pages (from a Volatility 3 `linux.proc.Maps` / pagemap JSON export, or live `/proc/<pid>/pagemap`), and flag PFNs that the process does not own or that look like kernel text, `cred`, `task_struct` or HID URB buffers. |
| G5 | **GPU activity without an owner** (process-less, dashboard-hidden, throttled miners) | [F1]; ShadowRay 2.0 (23.9 GB used, 0% shown); [D2] device-level DCGM | Live cross-view: device memory used and SM activity (NVML, DCGM `PROF_SM_ACTIVE`) against the sum over NVML/`/proc` processes. Alert when the residual exceeds a threshold. Ingest `dcgmi stats` and the dcgm-exporter `/metrics` endpoint. |
| G6 | **Pre-Pascal profile + DFRWS 2015 regression corpus** | [F2] (Maxwell GTX 860M, `dump_fb`); [F10] | Add a Maxwell/Kepler profile (old GMMU format, RAMFC and runlist layouts from open-gpu-doc / envytools rnndb; verify first) and a test that parses `NILES.gpu` and `NILES.lime` and finds the challenge's keylogger and malware. |
| G7 | **Watchdog-tamper and persistent-kernel detection (unlimited execution)** | [F1] hangcheck; [M3] Intel/TDR; [D4] TDR keys | Flag `TdrLevel=0`, `TdrDebugMode=1` and large `TdrDelay` on Windows, and i915 `enable_hangcheck=0` or NVIDIA watchdog-off settings on Linux. Offline, diff two acquisitions to find channels whose launch or semaphore state did not advance while the engine stayed busy. |
| G8 | **Driverless / raw-device GPU access** (userspace drivers, VFIO, sysfs BAR mmap) | [A5] tinygrad NV-over-VFIO; [A4] | Live: list processes with `/dev/vfio/*` fds or mappings of `/sys/bus/pci/devices/<nvidia bdf>/resource*`; flag NVIDIA functions bound to `vfio-pci` on a host that is not a hypervisor. Such work bypasses NVML, `/dev/nvidia*` and `rawioctl`. |
| G9 | **ATT&CK tagging and Sigma export of findings** | [D5] (no GPU content in SigmaHQ, Elastic or Splunk); [D6] | Add a static `finding -> [Txxxx]` map emitted in JSON/JSONL, plus a renderer that writes Sigma YAML for host-observable findings: `nvidia-smi -c EXCLUSIVE_PROCESS`, `--cuda`/`--opencl` miner flags, `OpenCL.dll` loaded by installers, `nv_uvm_*` names. |
| G10 | **XRGB / alpha-0x00 surfaces and robust row-width detection** | [F4] (Chromium textures `0x00RRGGBB`); [F5] (alpha mostly 0x00 or 0xff, FFT width) | In `nvidia.surfaces` auto mode, accept blocks whose every 4th byte is constant 0x00 or 0xFF, and estimate the width by autocorrelation (stdlib) before the smoothness search. |
| G11 | **Compute-mode / exclusive-ownership audit** | [M9] GHOST (`EXCLUSIVE_PROCESS` + persistence mode) | In `nvidia.malware.cryptojack`, flag `EXCLUSIVE_PROCESS` or `EXCLUSIVE_THREAD` when the owning context belongs to a masqueraded, deleted-exe or non-allow-listed process, and record when the mode differs from the site baseline. |
| G12 | **QMD V04/V05 (Hopper/Blackwell) decoding** | tinygrad autogen tables (`NVCEC0_QMDV05_00`); open-gpu-doc | Generate field tables from open-gpu-doc (cross-check against tinygrad's MIT tables). Replace the raw display in `nvidia.launches` / `qmdscan` for V04/V05. |
| G13 | **Remanence-scraper detection** | [F4] end-of-context dump; [F5] fill-0xff-and-poll; [F3] | Live: flag processes whose GPU memory is close to the device's free memory, or that poll memory info at high rate. Offline: report large uniform fill regions (0xFF, 0x11...) owned by one address space. |
| G14 | **Shellcode and filesystem signatures in VRAM** | [M5] [M6] [M8] [F14] | Extend `hostcode` / `residual` classifiers with x86-64 shellcode heuristics (PEB-walk sequences, API-hash constants such as ROR13/DJB2) and filesystem/archive magics (ext4, NTFS, FAT, ZIP, 7z). |
| G15 | **Offline GPU accounting history from RAM** | [F10] `GpuAccounting` NVOC object | Part of G3: parse the accounting object from a host image so exited GPU processes are visible without live NVML. |
| G16 | **Additional acquisition adapters** | [A4] [A6] [A2] | `keto acquire --method bar1` (mmap `resource1`, record BAR1 size and ReBAR state, label unmapped ranges); a cuda-gdb `.nvcudmp` ELF importer; an NvDebugDump protobuf decoder; nouveau `vbios.rom` and GSP-log sidecars. |
| G17 | **Kernel-driver integrity in host images** | [M4] (in-memory `nvidia.ko` patch) | Compare `nvidia.ko` `.text` in `--host-image` against the on-disk module of the same `srcversion` (relocation-aware). Live: compare against `/sys/module/nvidia/sections`. |
| G18 | **ECC policy flag for Rowhammer exposure** | [M10] [secondary] | In `nvidia.ecc`, flag ECC disabled on GDDR6 data-centre or workstation boards and bursts of corrected errors or row remaps. |


### Status of the gaps (2026-11-17)

| Gap | Status | Where |
|---|---|---|
| G1 | Done for live triage and snapshots | `windows.gpuprocs` (Toolhelp32 modules, PDH GPU Engine / GPU Process Memory, visible windows) |
| G2 | Done | OpenCL C, SPIR-V and DXBC/DXIL in `nvidia.artifactscan`; XOR-with-modulo decryptor shape in OpenCL, SPIR-V and PTX; YARA `KETO_OpenCL_*`, `KETO_SPIRV_Module`, `KETO_DXBC_Shader` |
| G3 / G15 | Done for WSL2 | `wsl.dxgprocs` (dxgprocess with PID/namespace PID, cross-view with tasks and /dev/dxg handles); native-Linux NVOC/RM walk not implemented (no native Linux NVIDIA host to validate on) |
| G4 | Open | |
| G5 | Done | `nvidia.malware.unaccounted` (NVML used memory and utilisation vs per-process lists; WDDM limitation reported) |
| G6 | Profiles done; corpus not ingested | Kepler/Maxwell profiles, VER1 page tables, gk104/gm107 runlists, per-generation tests; the DFRWS 2015 image was not downloaded |
| G7 | Done | `nvidia.malware.watchdog` (TDR registry, i915 hang check, NVIDIA RegistryDwords); Sigma `tdr_disabled` |
| G8 | Done (live Linux) | `nvidia.malware.rawaccess` |
| G9 | Done | ATT&CK in `keto report`; `keto sigma` writes 9 rules |
| G10 | Partly | alpha 0x00 (XRGB) surfaces accepted; row width still found by the smoothness search, not autocorrelation |
| G11 | Done | exclusive compute mode in `nvidia.malware.cryptojack` |
| G12 | Done | QMD V00_06 .. V05_00 decoded (V05_01 raw) |
| G13, G16, G17 | Open | |
| G14 | Done | shellcode idioms, file systems and archives in `nvidia.malware.hostcode` |
| G18 | Done | ECC-off / pending-off / corrected bursts / remap failures in `nvidia.ecc` |

---

## Appendix: verification notes

- **Primary sources opened in full or in relevant part:**
  - Papers: [M1] 2010, [M2], [M4], [F1], [F3] arXiv, [F4], [F5] arXiv, [F8], [F10].
  - Vendor and research blogs: [M6] Zscaler and Antiy, [M7] Arctic Wolf and GMO, [M9] Oligo, Censys and Microsoft, [F9].
  - Repositories: the Demon README, the [F2] README, Mesa and tinygrad sources, [F11], [F14].
- **Opened only as an abstract or listing:** [M8], [F12], the PoPETs listing for [F5], [F13] (delegated).
- **Secondary only:** [M3] Jellyfish and the Intel 2015 analysis, [M5], [M10].
- **Metadata only:** the IJIS 2015 version of [M1], the ACM TECS version of [F3], GRIM.
- **UNVERIFIED:**
  - Papers and pages: [F7], MagTracer, Intel Accelerated Memory Scanning (first-hand).
  - Repositories and tools: the Jellyfish repository (404), LSUACL/GPU-Forensics (404), whether the [F1] plugins were released.
  - Acquisition claims: the `RMForceStaticBar1` effect, QEMU BAR capture, H100 CC host blocking, the `.nvcudmp` section layout.
  - Detection claims: DxgKrnl event IDs.
- **Delegated passes:** sections 3 and 4 and some licence facts were gathered by two delegated research passes that opened the cited pages. Their own UNVERIFIED markings are kept above.
