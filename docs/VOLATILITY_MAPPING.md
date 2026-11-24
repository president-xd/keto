# Volatility 3 -> Keto coverage map

Every working Volatility 3 plugin listed in the supplied reference (167), with the Keto plugin(s) that answer the same forensic question on an NVIDIA GPU.

- **declared analogue** (114): the Keto plugin names this Volatility plugin as its counterpart.
- **by role** (53): the OS structure has no literal GPU twin (Windows desktops, Linux page cache, macOS kauth...), so the mapping is to the plugin that fills the same investigative role, with the reason.
- **unmapped** (0).
- The 28 deprecated Volatility alias names forward to the plugins above.
- A mapping says which Keto plugin answers the same question; it does not mean the Keto plugin runs on that Volatility plugin's OS. NVIDIA ships no driver for current macOS, so every `mac.*` row is a role analogy, and many `linux.*`/`windows.*` live analogues run only on that OS (docs/PLUGIN_REFERENCE.md says which).

| Volatility 3 plugin | Keto counterpart(s) | Basis |
|---|---|---|
| `banners` | `banners`, `host.kernel` | declared analogue |
| `configwriter` | `configwriter` | declared analogue |
| `frameworkinfo` | `frameworkinfo` | declared analogue |
| `isfinfo` | `profileinfo` | declared analogue |
| `layerwriter` | `layerwriter`, `nvidia.addrspaces` | declared analogue |
| `regexscan` | `regexscan` | declared analogue |
| `timeliner` | `nvidia.gputimeline`, `timeliner` | declared analogue |
| `vmscan` | `nvidia.mig` | declared analogue |
| `yarascan` | `yarascan` | declared analogue |
| `windows.info` | `nvidia.devices`, `nvidia.info`, `windows.kernel.info` | declared analogue |
| `windows.crashinfo` | `nvidia.bugreport`, `nvidia.info`, `nvidia.xid` | declared analogue |
| `windows.kpcrs` | `nvidia.contexts`, `nvidia.engines` | declared analogue |
| `windows.virtmap` | `nvidia.vamap` | declared analogue |
| `windows.pslist` | `nvidia.pslist`, `nvidia.runlist`, `windows.gpuprocs`, `windows.kernel.gpuprocs`, `windows.kernel.procdump`, `windows.kernel.pslist` | declared analogue |
| `windows.psscan` | `nvidia.chanscan`, `windows.kernel.psscan` | declared analogue |
| `windows.pstree` | `nvidia.chantree`, `nvidia.pstree` | declared analogue |
| `windows.cmdline` | `nvidia.cmdline` | declared analogue |
| `windows.envars` | `nvidia.envars`, `nvidia.envscan`, `windows.kernel.envars` | declared analogue |
| `windows.sessions` | `nvidia.sessions` | declared analogue |
| `windows.joblinks` | `nvidia.tsglist` | declared analogue |
| `windows.threads` | `nvidia.gpfifo`, `nvidia.launches` | declared analogue |
| `windows.thrdscan` | `nvidia.qmdscan` | declared analogue |
| `windows.suspended_threads` | `nvidia.pending` | declared analogue |
| `windows.debugregisters` | `nvidia.debugger` | declared analogue |
| `windows.orphan_kernel_threads` | `nvidia.orphanchans` | declared analogue |
| `windows.privileges` | `nvidia.privileges` | declared analogue |
| `windows.getsids` | `nvidia.pslist`, `nvidia.devnodes` | by role: who owns GPU work: process UIDs and GPU device-node ownership |
| `windows.getservicesids` | `nvidia.daemons` | by role: identity/state of GPU service processes |
| `windows.dlllist` | `nvidia.kernels`, `nvidia.libs`, `windows.gpuprocs`, `windows.kernel.gpuprocs` | declared analogue |
| `windows.modules` | `nvidia.driver`, `nvidia.modules`, `windows.kernel.modules` | declared analogue |
| `windows.modscan` | `nvidia.cubinscan` | declared analogue |
| `windows.unloadedmodules` | `nvidia.fatbinscan` | declared analogue |
| `windows.pedump` | `nvidia.cubindump` | declared analogue |
| `windows.pe_symbols` | `nvidia.symbols` | declared analogue |
| `windows.iat` | `nvidia.imports` | declared analogue |
| `windows.verinfo` | `nvidia.cubininfo` | declared analogue |
| `windows.vadinfo` | `nvidia.addrspaces`, `nvidia.mappings`, `windows.kernel.vadinfo` | declared analogue |
| `windows.vadwalk` | `nvidia.ptwalk` | declared analogue |
| `windows.memmap` | `nvidia.memmap`, `windows.kernel.procdump` | declared analogue |
| `windows.vadyarascan` | `nvidia.procscan`, `nvidia.vayarascan` | declared analogue |
| `windows.vadregexscan` | `nvidia.varegexscan` | declared analogue |
| `windows.strings` | `nvidia.strings` | declared analogue |
| `windows.bigpools` | `nvidia.physmap` | declared analogue |
| `windows.poolscanner` | `nvidia.artifactscan`, `nvidia.physmap` | declared analogue |
| `windows.handles` | `nvidia.handles`, `windows.kernel.gpuprocs`, `windows.kernel.handles` | declared analogue |
| `windows.filescan` | `nvidia.ptxscan` | declared analogue |
| `windows.mutantscan` | `nvidia.semaphores` | declared analogue |
| `windows.symlinkscan` | `nvidia.sysmemmap` | declared analogue |
| `windows.dumpfiles` | `nvidia.copies`, `nvidia.dumpfiles` | declared analogue |
| `windows.mftscan.MFTScan` | `nvidia.computecache`, `nvidia.strings` | by role: file-system records of GPU use (JIT/shader cache entries) and file paths left in VRAM |
| `windows.mftscan.ADS` | `nvidia.malware.hostcode` | declared analogue |
| `windows.mftscan.ResidentData` | `nvidia.residual` | declared analogue |
| `windows.ssdt` | `nvidia.classes` | declared analogue |
| `windows.callbacks` | `nvidia.notifiers` | declared analogue |
| `windows.timers` | `nvidia.timeslices` | declared analogue |
| `windows.driverscan` | `nvidia.driver` | declared analogue |
| `windows.driverirp` | `nvidia.devnodes`, `windows.kernel.driverirp` | declared analogue |
| `windows.devicetree` | `nvidia.devicetree`, `nvidia.devnodes` | declared analogue |
| `windows.mbrscan` | `nvidia.vbios` | declared analogue |
| `windows.netscan` | `nvidia.malware.exfil`, `nvidia.nvlink` | declared analogue |
| `windows.netstat` | `nvidia.nvlink` | declared analogue |
| `windows.svcscan` | `nvidia.autostart`, `nvidia.daemons` | declared analogue |
| `windows.svclist` | `nvidia.daemons` | declared analogue |
| `windows.registry.hivelist` | `nvidia.params`, `nvidia.autostart` | by role: the driver's configuration stores (module parameters / registry dwords, loader configs) |
| `windows.registry.hivescan` | `nvidia.params`, `nvidia.autostart` | by role: as hivelist: every configuration source of the GPU stack |
| `windows.registry.printkey` | `nvidia.malware.watchdog`, `nvidia.params` | declared analogue |
| `windows.registry.userassist` | `nvidia.accounting` | declared analogue |
| `windows.registry.amcache` | `nvidia.accounting`, `nvidia.computecache`, `nvidia.jitcache`, `nvidia.shadercache` | declared analogue |
| `windows.registry.scheduled_tasks` | `nvidia.autostart` | declared analogue |
| `windows.registry.hashdump` | `nvidia.secrets` | declared analogue |
| `windows.registry.lsadump` | `nvidia.secrets`, `nvidia.aeskeys` | by role: secrets and key material present in GPU memory |
| `windows.registry.cachedump` | `nvidia.secrets` | by role: cached credential material in GPU memory |
| `windows.registry.getcellroutine` | `nvidia.malware.ptcheck` | declared analogue |
| `windows.cmdscan` | `nvidia.pbscan`, `nvidia.pushbuf` | declared analogue |
| `windows.consoles` | `nvidia.pushbuf` | declared analogue |
| `windows.shimcachemem` | `nvidia.computecache`, `nvidia.jitcache`, `nvidia.shadercache` | declared analogue |
| `windows.truecrypt` | `nvidia.aeskeys` | declared analogue |
| `windows.windowstations` | `nvidia.surfaces`, `nvidia.sessions` | by role: what was on screen: render targets and capture sessions |
| `windows.desktops` | `nvidia.surfaces` | by role: recovered framebuffers / render targets |
| `windows.deskscan` | `nvidia.surfaces` | by role: carving surfaces, including unreferenced ones |
| `windows.windows` | `nvidia.surfaces` | declared analogue |
| `windows.malware.malfind` | `nvidia.malware.malfind`, `nvidia.malware.sassfind`, `nvidia.procscan` | declared analogue |
| `windows.malware.hollowprocesses` | `nvidia.malware.codeintegrity` | declared analogue |
| `windows.malware.ldrmodules` | `nvidia.malware.cubinxview`, `nvidia.malware.injection` | declared analogue |
| `windows.malware.pebmasquerade` | `nvidia.malware.masquerade` | declared analogue |
| `windows.malware.processghosting` | `nvidia.malware.deletedexe`, `nvidia.malware.hostcode` | declared analogue |
| `windows.malware.psxview` | `nvidia.malware.chanxview`, `nvidia.malware.gpuxview`, `nvidia.malware.unaccounted`, `wsl.dxgprocs` | declared analogue |
| `windows.malware.suspicious_threads` | `nvidia.malware.suspiciouslaunch` | declared analogue |
| `windows.malware.unhooked_system_calls` | `nvidia.malware.libhooks` | declared analogue |
| `windows.malware.direct_system_calls` | `nvidia.malware.rawioctl` | declared analogue |
| `windows.malware.indirect_system_calls` | `nvidia.malware.rawioctl` | declared analogue |
| `windows.malware.drivermodule` | `nvidia.malware.integrity` | declared analogue |
| `windows.malware.skeleton_key_check` | `nvidia.malware.injection` | declared analogue |
| `windows.malware.svcdiff` | `nvidia.daemons` | by role: running GPU daemons vs installed service units |
| `windows.etwpatch` | `nvidia.malware.integrity` | declared analogue |
| `linux.pslist` | `host.pslist`, `nvidia.gpfifo`, `nvidia.pslist`, `wsl.dxgprocs` | declared analogue |
| `linux.psscan` | `nvidia.chanscan` | declared analogue |
| `linux.pidhashtable` | `nvidia.runlist` | declared analogue |
| `linux.pstree` | `nvidia.chantree`, `nvidia.pstree` | declared analogue |
| `linux.psaux` | `nvidia.cmdline` | declared analogue |
| `linux.envars` | `nvidia.envars`, `nvidia.envscan` | declared analogue |
| `linux.capabilities` | `nvidia.containers`, `nvidia.privileges` | declared analogue |
| `linux.ptrace` | `nvidia.debugger` | declared analogue |
| `linux.pscallstack` | `nvidia.launches` | declared analogue |
| `linux.kthreads` | `nvidia.privileges`, `nvidia.chantree` | by role: kernel-owned (privileged) GPU channels |
| `linux.boottime` | `nvidia.gputimeline` | declared analogue |
| `linux.bash` | `nvidia.pushbuf` | declared analogue |
| `linux.proc.Maps` | `nvidia.malware.rawaccess`, `nvidia.mappings`, `nvidia.memmap`, `wsl.dxgallocs`, `wsl.dxgpageowners` | declared analogue |
| `linux.elfs` | `nvidia.cubindump` | declared analogue |
| `linux.library_list` | `nvidia.kernels`, `nvidia.libs` | declared analogue |
| `linux.vmaregexscan` | `nvidia.varegexscan` | declared analogue |
| `linux.vmayarascan` | `nvidia.vayarascan` | declared analogue |
| `linux.lsof` | `host.pslist`, `nvidia.handles`, `nvidia.malware.rawaccess` | declared analogue |
| `linux.mountinfo` | `nvidia.containers` | declared analogue |
| `linux.pagecache.Files` | `nvidia.computecache` | by role: files cached by the GPU stack (JIT/shader caches) |
| `linux.pagecache.InodePages` | `nvidia.cubindump`, `nvidia.dumpfiles` | by role: extract cached content to files |
| `linux.pagecache.RecoverFs` | `nvidia.dumpfiles` | by role: bulk recovery of every carvable object with a manifest |
| `linux.sockstat` | `nvidia.malware.exfil` | declared analogue |
| `linux.sockscan` | `nvidia.sysmemmap`, `nvidia.copies` | by role: channels through which data leaves the GPU (host-memory windows, DMA) |
| `linux.ip.Addr` | `nvidia.devicetree`, `nvidia.nvlink` | by role: the GPU's interconnect endpoints (PCIe, NVLink peers) |
| `linux.ip.Link` | `nvidia.nvlink`, `nvidia.devicetree` | by role: link state and speed |
| `linux.lsmod` | `nvidia.modules` | declared analogue |
| `linux.module_extract` | `nvidia.cubindump` | by role: rebuild loaded GPU modules (cubins) as files |
| `linux.kallsyms` | `nvidia.symbols` | by role: symbol tables of loaded GPU code |
| `linux.kmsg` | `nvidia.xid` | declared analogue |
| `linux.iomem` | `nvidia.physmap`, `nvidia.devicetree` | by role: physical memory map: VRAM ownership, BARs |
| `linux.vmcoreinfo` | `nvidia.info`, `configwriter` | by role: identity table of the image (device, driver, layout) |
| `linux.ebpf` | `nvidia.kernels`, `nvidia.launches` | by role: programs loaded into and executed by the device |
| `linux.graphics.fbdev` | `nvidia.surfaces` | declared analogue |
| `linux.tracing.perf_events` | `nvidia.profiling` | declared analogue |
| `linux.malware.malfind` | `nvidia.malware.malfind` | declared analogue |
| `linux.malware.check_syscall` | `nvidia.malware.libhooks`, `nvidia.classes` | by role: hooked dispatch paths: CUDA/NVML entry points, engine class bindings |
| `linux.malware.check_idt` | `nvidia.notifiers` | by role: interrupt / notification paths from the GPU |
| `linux.malware.check_afinfo` | `nvidia.malware.libhooks`, `nvidia.malware.integrity` | by role: tampering with the user-mode stack used to hide activity (e.g. NVML hiding miners) |
| `linux.malware.check_creds` | `nvidia.malware.ptcheck` | by role: isolation failures: physical pages shared across GPU contexts |
| `linux.malware.check_modules` | `nvidia.modules` | declared analogue |
| `linux.malware.hidden_modules` | `nvidia.malware.sassfind` | declared analogue |
| `linux.malware.modxview` | `nvidia.malware.cubinxview` | declared analogue |
| `linux.malware.keyboard_notifiers` | `nvidia.malware.capture` | by role: input/output spying via the GPU (screen capture sessions) |
| `linux.malware.netfilter` | `nvidia.malware.exfil` | by role: traffic leaving the device |
| `linux.malware.tty_check` | `nvidia.malware.capture` | by role: terminal/screen sniffing via frame-buffer capture |
| `linux.malware.process_spoofing` | `nvidia.malware.masquerade` | declared analogue |
| `linux.tracing.ftrace` | `nvidia.profiling`, `nvidia.malware.injection` | by role: function tracing / interposition (CUPTI, injection hooks) |
| `linux.tracing.tracepoints` | `nvidia.profiling` | by role: probes attached to GPU execution (profilers, perf counters) |
| `mac.pslist` | `nvidia.pslist`, `nvidia.runlist` | by role: process / channel lists |
| `mac.pstree` | `nvidia.pstree`, `nvidia.chantree` | by role: process / channel trees |
| `mac.psaux` | `nvidia.cmdline` | by role: command lines |
| `mac.bash` | `nvidia.pushbuf` | by role: command history |
| `mac.proc_maps` | `nvidia.mappings` | declared analogue |
| `mac.malfind` | `nvidia.malware.malfind` | by role: injected code |
| `mac.lsof` | `nvidia.handles` | by role: open device handles |
| `mac.list_files` | `nvidia.computecache`, `nvidia.cubinscan` | by role: cached files / code objects |
| `mac.mount` | `nvidia.containers` | by role: namespaces / containers with GPU access |
| `mac.netstat` | `nvidia.nvlink`, `nvidia.copies` | by role: communication endpoints and transfers |
| `mac.ifconfig` | `nvidia.nvlink`, `nvidia.devicetree` | by role: interfaces and links |
| `mac.dmesg` | `nvidia.xid` | by role: kernel log (NVRM / Xid) |
| `mac.lsmod` | `nvidia.modules` | by role: loaded kernel modules |
| `mac.check_syscall` | `nvidia.malware.libhooks` | by role: hooked entry points |
| `mac.check_trap_table` | `nvidia.malware.libhooks`, `nvidia.notifiers` | by role: hooked trap / notification paths |
| `mac.check_sysctl` | `nvidia.params` | by role: tunables and their handlers |
| `mac.kauth_scopes` | `nvidia.malware.injection`, `nvidia.profiling` | by role: authorisation / interposition hooks |
| `mac.kauth_listeners` | `nvidia.malware.injection`, `nvidia.profiling` | by role: listeners attached to GPU processes |
| `mac.kevents` | `nvidia.semaphores`, `nvidia.notifiers` | by role: event / synchronisation objects |
| `mac.socket_filters` | `nvidia.malware.exfil` | by role: filters on data leaving the device |
| `mac.timers` | `nvidia.timeslices` | declared analogue |
| `mac.trustedbsd` | `nvidia.privileges`, `nvidia.malware.ptcheck` | by role: policy / privilege enforcement |
| `mac.vfsevents` | `nvidia.profiling`, `nvidia.malware.capture` | by role: processes watching GPU activity |

