# Volatility 3 plugin names (input of tools/gen_docs.py)

The Volatility 3 plugin list that docs/VOLATILITY_MAPPING.md is generated against: plugin names and the
deprecated alias names with their replacements (names only, taken from the Volatility 3 plugin reference).

## 1. Framework / OS-independent plugins (9)

| Plugin |
|---|
| `banners` |
| `configwriter` |
| `frameworkinfo` |
| `isfinfo` |
| `layerwriter` |
| `regexscan` |
| `timeliner` |
| `vmscan` |
| `yarascan` |

## 2. Windows plugins (86)

| Plugin |
|---|

### 2.1 System information

| Plugin |
|---|
| `windows.info` |
| `windows.crashinfo` |
| `windows.kpcrs` |
| `windows.virtmap` |

### 2.2 Processes, threads & tokens

| Plugin |
|---|
| `windows.pslist` |
| `windows.psscan` |
| `windows.pstree` |
| `windows.cmdline` |
| `windows.envars` |
| `windows.sessions` |
| `windows.joblinks` |
| `windows.threads` |
| `windows.thrdscan` |
| `windows.suspended_threads` |
| `windows.debugregisters` |
| `windows.orphan_kernel_threads` |
| `windows.privileges` |
| `windows.getsids` |
| `windows.getservicesids` |

### 2.3 DLLs, kernel modules & PE files

| Plugin |
|---|
| `windows.dlllist` |
| `windows.modules` |
| `windows.modscan` |
| `windows.unloadedmodules` |
| `windows.pedump` |
| `windows.pe_symbols` |
| `windows.iat` |
| `windows.verinfo` |

### 2.4 Process memory & scanning

| Plugin |
|---|
| `windows.vadinfo` |
| `windows.vadwalk` |
| `windows.memmap` |
| `windows.vadyarascan` |
| `windows.vadregexscan` |
| `windows.strings` |
| `windows.bigpools` |
| `windows.poolscanner` |

### 2.5 Handles, objects & files

| Plugin |
|---|
| `windows.handles` |
| `windows.filescan` |
| `windows.mutantscan` |
| `windows.symlinkscan` |
| `windows.dumpfiles` |
| `windows.mftscan.MFTScan` |
| `windows.mftscan.ADS` |
| `windows.mftscan.ResidentData` |

### 2.6 Kernel, drivers & hooks

| Plugin |
|---|
| `windows.ssdt` |
| `windows.callbacks` |
| `windows.timers` |
| `windows.driverscan` |
| `windows.driverirp` |
| `windows.devicetree` |
| `windows.mbrscan` |

### 2.7 Network

| Plugin |
|---|
| `windows.netscan` |
| `windows.netstat` |

### 2.8 Services

| Plugin |
|---|
| `windows.svcscan` |
| `windows.svclist` |

### 2.9 Registry (`windows.registry.*`)

| Plugin |
|---|
| `windows.registry.hivelist` |
| `windows.registry.hivescan` |
| `windows.registry.printkey` |
| `windows.registry.userassist` |
| `windows.registry.amcache` |
| `windows.registry.scheduled_tasks` |
| `windows.registry.hashdump` |
| `windows.registry.lsadump` |
| `windows.registry.cachedump` |
| `windows.registry.getcellroutine` |

### 2.10 User activity, console & GUI

| Plugin |
|---|
| `windows.cmdscan` |
| `windows.consoles` |
| `windows.shimcachemem` |
| `windows.truecrypt` |
| `windows.windowstations` |
| `windows.desktops` |
| `windows.deskscan` |
| `windows.windows` |

### 2.11 Malware & rootkit detection (`windows.malware.*` and related)

| Plugin |
|---|
| `windows.malware.malfind` |
| `windows.malware.hollowprocesses` |
| `windows.malware.ldrmodules` |
| `windows.malware.pebmasquerade` |
| `windows.malware.processghosting` |
| `windows.malware.psxview` |
| `windows.malware.suspicious_threads` |
| `windows.malware.unhooked_system_calls` |
| `windows.malware.direct_system_calls` |
| `windows.malware.indirect_system_calls` |
| `windows.malware.drivermodule` |
| `windows.malware.skeleton_key_check` |
| `windows.malware.svcdiff` |
| `windows.etwpatch` |

## 3. Linux plugins (49)

| Plugin |
|---|

### 3.1 Processes

| Plugin |
|---|
| `linux.pslist` |
| `linux.psscan` |
| `linux.pidhashtable` |
| `linux.pstree` |
| `linux.psaux` |
| `linux.envars` |
| `linux.capabilities` |
| `linux.ptrace` |
| `linux.pscallstack` |
| `linux.kthreads` |
| `linux.boottime` |
| `linux.bash` |

### 3.2 Process memory & libraries

| Plugin |
|---|
| `linux.proc.Maps` |
| `linux.elfs` |
| `linux.library_list` |
| `linux.vmaregexscan` |
| `linux.vmayarascan` |

### 3.3 Files & filesystems

| Plugin |
|---|
| `linux.lsof` |
| `linux.mountinfo` |
| `linux.pagecache.Files` |
| `linux.pagecache.InodePages` |
| `linux.pagecache.RecoverFs` |

### 3.4 Network

| Plugin |
|---|
| `linux.sockstat` |
| `linux.sockscan` |
| `linux.ip.Addr` |
| `linux.ip.Link` |

### 3.5 Kernel, modules & logs

| Plugin |
|---|
| `linux.lsmod` |
| `linux.module_extract` |
| `linux.kallsyms` |
| `linux.kmsg` |
| `linux.iomem` |
| `linux.vmcoreinfo` |
| `linux.ebpf` |
| `linux.graphics.fbdev` |
| `linux.tracing.perf_events` |

### 3.6 Malware & rootkit detection (`linux.malware.*`, `linux.tracing.*`)

| Plugin |
|---|
| `linux.malware.malfind` |
| `linux.malware.check_syscall` |
| `linux.malware.check_idt` |
| `linux.malware.check_afinfo` |
| `linux.malware.check_creds` |
| `linux.malware.check_modules` |
| `linux.malware.hidden_modules` |
| `linux.malware.modxview` |
| `linux.malware.keyboard_notifiers` |
| `linux.malware.netfilter` |
| `linux.malware.tty_check` |
| `linux.malware.process_spoofing` |
| `linux.tracing.ftrace` |
| `linux.tracing.tracepoints` |

## 4. macOS plugins (23)

| Plugin |
|---|
| `mac.pslist` |
| `mac.pstree` |
| `mac.psaux` |
| `mac.bash` |
| `mac.proc_maps` |
| `mac.malfind` |
| `mac.lsof` |
| `mac.list_files` |
| `mac.mount` |
| `mac.netstat` |
| `mac.ifconfig` |
| `mac.dmesg` |
| `mac.lsmod` |
| `mac.check_syscall` |
| `mac.check_trap_table` |
| `mac.check_sysctl` |
| `mac.kauth_scopes` |
| `mac.kauth_listeners` |
| `mac.kevents` |
| `mac.socket_filters` |
| `mac.timers` |
| `mac.trustedbsd` |
| `mac.vfsevents` |

## 5. Deprecated alias names (28)

| Alias | Replacement |
|---|---|
| `windows.amcache` | `windows.registry.amcache` |
| `windows.cachedump` | `windows.registry.cachedump` |
| `windows.hashdump` | `windows.registry.hashdump` |
| `windows.lsadump` | `windows.registry.lsadump` |
| `windows.scheduled_tasks` | `windows.registry.scheduled_tasks` |
| `windows.direct_system_calls` | `windows.malware.direct_system_calls` |
| `windows.indirect_system_calls` | `windows.malware.indirect_system_calls` |
| `windows.drivermodule` | `windows.malware.drivermodule` |
| `windows.hollowprocesses` | `windows.malware.hollowprocesses` |
| `windows.ldrmodules` | `windows.malware.ldrmodules` |
| `windows.malfind` | `windows.malware.malfind` |
| `windows.processghosting` | `windows.malware.processghosting` |
| `windows.psxview` | `windows.malware.psxview` |
| `windows.skeleton_key_check` | `windows.malware.skeleton_key_check` |
| `windows.suspicious_threads` | `windows.malware.suspicious_threads` |
| `windows.svcdiff` | `windows.malware.svcdiff` |
| `windows.unhooked_system_calls` | `windows.malware.unhooked_system_calls` |
| `linux.check_afinfo` | `linux.malware.check_afinfo` |
| `linux.check_creds` | `linux.malware.check_creds` |
| `linux.check_idt` | `linux.malware.check_idt` |
| `linux.check_modules` | `linux.malware.check_modules` |
| `linux.check_syscall` | `linux.malware.check_syscall` |
| `linux.hidden_modules` | `linux.malware.hidden_modules` |
| `linux.keyboard_notifiers` | `linux.malware.keyboard_notifiers` |
| `linux.malfind` | `linux.malware.malfind` |
| `linux.modxview` | `linux.malware.modxview` |
| `linux.netfilter` | `linux.malware.netfilter` |
| `linux.tty_check` | `linux.malware.tty_check` |
