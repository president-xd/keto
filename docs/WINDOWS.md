# Windows kernel memory

Keto analyses Windows x64 physical memory natively (pure standard library, any host OS): processes, kernel
modules, handles, VADs, environment blocks, driver dispatch tables and a GPU view, typed through the imaged
kernel's own PDB. Plugins are named `windows.kernel.*`; the live Windows plugins (`windows.gpuprocs` and the
`nvidia.*` live plugins) are unchanged.

## Inputs

Give the image with `--host-image` (it becomes the `sysmem` layer) or `-f`:

| Input | How it is read |
|---|---|
| Raw physical RAM (WinPmem, DumpIt raw, Magnet RAM Capture, FTK Imager, Belkasoft) | as is |
| Crash and live kernel dumps (`MEMORY.DMP`, Task Manager live dumps, `acquire --method livedump`, DumpIt .dmp) | `keto.formats.windump` (docs/FORMATS.md) |
| Hibernation files (`hiberfil.sys`) | `keto.formats.hiber` |
| ELF cores (QEMU `dump-guest-memory`, VirtualBox `dumpvmcore`) | `keto.formats.elfcore` |
| VMware `.vmem` with its `.vmss` / `.vmsn` | `keto.formats.vmware` |
| A `.keto` container with `sysmem` segments | the container |

## Locating the kernel

`windows.kernel.info` shows what was found and how. In order:

1. `--dtb` and `--kernel-base`, when given.
2. What the format recorded: a crash dump's DirectoryTableBase and PsLoadedModuleList, or a CPU's CR3 recorded
   by a hibernation file, ELF core or VMware snapshot.
3. The x64 low stub (`_PROCESSOR_START_BLOCK` in the first MiB: CR3 at +0xA0, a kernel entry address at +0x70).
4. A page whose upper-half PML4 entry maps the page itself (Windows' self-referencing entry).

A DTB is accepted only if it maps `KUSER_SHARED_DATA` (0xFFFFF78000000000) with NtMajorVersion 10 and a
system root path. The kernel base is the page whose PE CodeView record names `ntkrnlmp.pdb`. Both 4- and
5-level paging are supported; CR3 PCID bits are ignored.

## Symbols

The CodeView record gives the PDB name, GUID and age. Keto looks the PDB up in local symbol stores and never
downloads during analysis:

* `--pdb FILE` or `--isf FILE` (Volatility 3 ISF, `.json`, `.json.xz`, `.json.gz`);
* `--symbols-dir DIR` (symbol-store layout `ntkrnlmp.pdb/<GUID><age>/ntkrnlmp.pdb`, or a Volatility symbol
  pack `windows/ntkrnlmp.pdb/<GUID-age>.json.xz`);
* Keto's cache (`KETO_SYMBOLS`, else `%LOCALAPPDATA%\keto\symbols` or `~/.cache/keto/symbols`), local stores
  named in `_NT_SYMBOL_PATH`, WinDbg's `C:\ProgramData\Dbg\sym`, `C:\Symbols` and the Windows SDK debugger's
  `sym` folder.

A symbol file whose GUID differs from the image is refused.

**Without any symbol file** (the symbol server is blocked, or the lab is air-gapped) Keto types the kernel from
the image itself, so every analyst runs the same commands and gets the same core results. This is the
*self-profile*, and `windows.kernel.info` notes it and every derivation:

* `_EPROCESS` members are decoded from the machine code of ntoskrnl's exported accessors (`PsGetProcessId`,
  `PsGetProcessImageFileName`, `PsGetProcessDxgProcess`, ...), so they are exact for the imaged build;
* ObjectTable, VadRoot and the image path are found by structural checks on the image's own data;
* the object-header cookie, the type table and the root object directory are recovered from the System process
  and the exported type objects;
* everything else uses layouts that did not change from Windows 10 1809 to Windows 11 25H2, and `_MMVAD_FLAGS`
  uses a per-build table checked against the image (docs/research/WINDOWS_LAYOUTS.md).

The self-profile gives the same rows as the PDB for every plugin, except the thread count in `pslist` (no
accessor reads it). It needs the kernel's export table and accessor code to be resident in the image; if they
are not, Keto says so and asks for a PDB. `--self-profile` forces it, to compare with a PDB.

To get the PDB once, on any machine with network access:

```
keto -f image.dmp pdb info            # prints the PDB name, key and download URL
keto pdb fetch --name ntkrnlmp.pdb --key <GUID><age>
keto pdb fetch --pe C:\Windows\System32\ntoskrnl.exe   # for the machine you are on
```

`keto pdb fetch` is the only Keto command that uses the network. It sends the PDB file name and the build's
GUID/age to the symbol server, nothing about the case, and stores the file only after checking it is a PDB
with the requested GUID.

## Plugins

| Plugin | What it shows | Volatility analogue |
|---|---|---|
| `windows.kernel.info` | image format, DTB and its source, kernel base, PDB identity, build, dump header facts | `windows.info` |
| `windows.kernel.pslist` | active process list with times, path, session, WoW64 and the DxgKrnl process object | `windows.pslist` |
| `windows.kernel.psscan` | `_EPROCESS` found by pool tag, marked listed / unlinked (hidden) / exited | `windows.psscan` |
| `windows.kernel.modules` | kernel modules with PDB identity; the GPU driver stack marked | `windows.modules` |
| `windows.kernel.handles` | handles with type, access and name; GPU devices and driver files classified | `windows.handles` |
| `windows.kernel.vadinfo` | VADs with protection and mapped file | `windows.vadinfo` |
| `windows.kernel.envars` | GPU, CUDA-injection and loader variables, with `nvidia.envscan` severities | `windows.envars` |
| `windows.kernel.driverirp` | IRP dispatch entries outside their driver and ntoskrnl | `windows.driverirp` |
| `windows.kernel.gpuprocs` | GPU process view; `--hidden` adds running processes unlinked from the list | - |
| `windows.kernel.procdump` | a process's resident memory as a `.keto` process container | `windows.memmap --dump` |

The `procdump` container has the same layout as `acquire --method process`, so `nvidia.artifactscan`,
`nvidia.envscan` and the other process-dump plugins run on it unchanged.

## Acquisition on Windows

`keto acquire --method livedump --out case.keto` takes a live kernel memory dump through
`NtSystemDebugControl(SysDbgGetLiveKernelDump)` (the facility behind Task Manager's "Create live kernel memory
dump"). It needs an elevated prompt (SeDebugPrivilege) and no third-party driver. Windows builds the dump from a
consistent snapshot. `--include-user-pages` adds user-mode memory, `--hypervisor-pages` adds hypervisor
pages. Keto then copies every page into the container's `sysmem` space and records the dump header, the
original dump's SHA-256 and the kernel's PDB identity. `--keep-dump` keeps the original `.dmp` next to it.

Full raw physical RAM needs a signed memory-acquisition driver (WinPmem, DumpIt, Magnet RAM Capture). Import
the result with `keto acquire --method import --space sysmem`, or analyse it directly with `--host-image`.

## Limits

* **GPU objects inside `dxgkrnl.sys`.** `DXGPROCESS`, `DXGDEVICE` and `DXGALLOCATION` are private C++ classes,
  and Microsoft's public `dxgkrnl.pdb` carries no type information (docs/research/HOST_SIDE_DETECTION.md, §2.1).
  Keto uses what the public kernel PDB does expose: `_EPROCESS.DxgProcess` (a process's graphics-kernel
  presence), handles to `\Device\DxgKrnl` and NVIDIA devices, the GPU runtimes each process maps, and the
  integrity of the GPU drivers' dispatch tables. NVIDIA publishes no PDBs for `nvlddmkm.sys`.
* **Memory that is not resident.** Pages in the page file, in the memory-compression store, or behind
  prototype PTEs (shared sections) are reported as not resident, never guessed. Transition pages (standby or
  modified lists) are read.
* **psscan.** psscan needs the object body in the same physical page as its pool header. A process whose body
  crosses into another page is still found through the list walk; one that is also unlinked is reported with
  only the members in its first page ("partial").
* **Validation.** The engine is tested on synthetic kernel images with deliberately non-contiguous frames, with a
  symbol file and with the self-profile, which must give identical rows. The PDB reader is tested on real
  Microsoft PDBs. The accessor decoder is tested on the real ntoskrnl of a 24H2 machine, where it reproduces the
  published 25H2 offsets.

## Validation on a real kernel

A live kernel dump of the project's reference machine (Windows 11 build 26300, 12 CPUs, 32 GB, kernel pages only,
2.75 GB) was analysed with no PDB, then compared with what the running system reported a few minutes later:

* the self-profile derived ObjectTable 0x300, SeAuditProcessCreationInfo 0x350, VadRoot 0x558 and the twelve
  accessor members, matching the published 25H2 layout; the `_MMVAD_FLAGS` layout was chosen from 707
  image-backed and 655 other VADs (PrivateMemory set on 205 of them, bit 21);
* `pslist` found 331 processes; of the 260 PIDs still present, all 259 with the same image name had the same
  parent PID and the same creation time to the second (the remaining PID had been reused after its process exited);
* `modules` found 268 modules; all 218 running drivers WMI reports are among them;
* `psscan` found 330 processes by pool tag, all on the active list (no false "hidden process");
* `driverirp` reported two entries: VMware's USB host-connection monitor (`hcmon.sys`) redirecting `USBXHCI` and
  `USBHUB3` dispatch, a real cross-driver redirection by installed software; every GPU driver dispatched through
  itself, ntoskrnl or dxgkrnl;
* timings: `info` 1.8 s, `pslist` 0.3 s, `psscan` 2.0 s, `handles` 3.5 s, `gpuprocs` 7 s, `report` 8.3 s.

That run exposed and fixed: a VadRoot heuristic that accepted a `_KPROCESS` pointer (now it requires a real tree),
the `_MMVAD_FLAGS` choice for a build newer than the table, the one-byte `KeNumberProcessors`, `driverirp` flagging
framework dispatch (KMDF, NDIS, port and class drivers) and two framework slowdowns on sparse images: the layer's
starts list was rebuilt on every read (405 s, now 0.6 s) and the parallel scanner made one task per run of pages
(437 s, now 1.4 s).
