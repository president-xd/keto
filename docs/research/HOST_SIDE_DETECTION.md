# Recovering GPU activity from host-side evidence

Research notes for Keto and a planned Volatility 3 bridge. Compiled 2026-11-17.

Defenders rarely hold a VRAM image. They usually hold host evidence: a Linux or Windows RAM image, process
dumps, disk triage, and EDR/ETW telemetry. Code that runs on the GPU still needs a host process, a kernel-driver
client, memory objects and (usually) a code object loaded through a user-mode runtime. This document records,
per evidence type, which host structures and files carry that activity, with exact names and sources.

**Provenance tags used below**

| Tag | Meaning |
|---|---|
| **[S]** | Read in the cited source code, specification or vendor document (URL given). |
| **[L]** | Observed on the project's test machine on 2026-11-17: Windows 11 build 26200, WSL2 kernel `6.18.33.2-microsoft-standard-WSL2`, NVIDIA Ada GPU. One machine, so a format may differ on other driver versions. |
| **[P]** | Stated in a peer-reviewed paper (cited). |
| **[U]** | Unverified or inferred. Treat as a hypothesis to test. |

Linux NVIDIA sources were read from `NVIDIA/open-gpu-kernel-modules` branch `main`, which is driver
**620.70.06** at the time of reading. NVOC-generated headers live under `src/nvidia/generated/`. Field lists are
abridged to what matters forensically. Numeric offsets are deliberately not given for Linux; they must come from
an ISF built for the exact driver build.

---

## 0. Key findings

1. **Linux NVIDIA RM clients carry the owning PID and process name.** `RmClient.ProcID` is `current->tgid` and
   `RmClient.name` is `current->comm` at allocation time [S]. Every RM client is reachable from the global
   `g_resServ` (`RsServer`) through 1024 hash buckets, and also from the global list `g_clientListBehindGpusLock`
   [S]. `KernelChannel.ProcessID` copies the client's `ProcID` [S]. So a Linux RAM image can answer "which PID
   owns which GPU channel and memory object", even after the process has exited or been unlinked.
2. **NVOC objects are self-describing in RAM.** Each RM object starts with a pointer to `NVOC_RTTI`, which points
   to `NVOC_CLASS_DEF` (class ID, size, name). The class definitions are exported in kallsyms as
   `__nvoc_class_def_<Class>` [S][P]. That gives a scan method that needs no full ISF. Bowen et al. (DFRWS USA 2024)
   built Volatility 2.6 plugins on this, but their repository now returns 404 [L].
3. **nvidia-uvm keeps a global list of per-process VA spaces.** The anchor is `g_uvm_global.va_spaces.list`. Each
   `uvm_va_space_t` holds its `mm_struct` (`va_space_mm.mm`), its managed or external ranges, and the user channels
   registered per GPU with their `hw_runlist_id` and `hw_channel_id` [S]. The channel IDs link host evidence to
   Keto's VRAM-side `chanscan` and `runlist`.
4. **WSL2 is the easiest target.** `dxgkrnl` is built into the WSL2 kernel, the kernel ships BTF that contains the
   `dxg*` types, kallsyms exposes `dxgdrv` and `dxgk_fops`, and `/proc/kcore` exists, so AVML can acquire memory
   [S][L]. The structures form a clean tree: `dxgdrv.dxgglobal->plisthead` → `dxgprocess`
   (`pid`/`tgid`/`vpid`/`nspid`) → adapter → device → context → hwqueue / allocation [S].
5. **Windows links GPU state to processes in `_EPROCESS.DxgProcess`.** The field is in the public kernel PDB, at
   offset `0x6E0` on 24H2 and build 26200 [S][L]. The DXG object layouts behind it are not public. Microsoft's
   public PDBs carry names and addresses only [S].
6. **DxgKrnl ETW identifies GPU processes, devices, contexts, queues, allocations and every DMA/queue packet**,
   including the kernel `DxgProcess` pointer and the PID. The provider also has rundown (`DCStart`) events [L].
   This can join ETW to a RAM image. No public evidence was found that mainstream EDRs consume this provider.
7. **The CUDA JIT ComputeCache keeps the full PTX text and the compiled cubin of every JIT-compiled kernel**,
   indexed by a 64-bit hash, on both Windows and Linux/WSL [L]. The format is undocumented. Its layout was decoded
   here (§4.4) and is simple enough for a pure-stdlib parser.

---

## 1. Linux: NVIDIA kernel driver (open-gpu-kernel-modules)

Licensing: the repository is "MIT except where noted" (`COPYING`), with GPL/MIT dual-licensed glue [S].
Since R560 the open modules are the default for Turing and newer GPUs. Maxwell, Pascal and Volta still need the
proprietary modules, whose RM symbols are scrubbed to `_nvXXXXXXrm` [S][P].

- https://github.com/NVIDIA/open-gpu-kernel-modules
- https://developer.nvidia.com/blog/nvidia-transitions-fully-towards-open-source-gpu-kernel-modules/

### 1.1 Linux glue layer (`kernel-open/`)

**Per-device state.** Defined in `kernel-open/common/inc/nv-linux.h` and `kernel-open/common/inc/nv.h` [S].

`nv_linux_state_t` (`struct nv_linux_state_s`) has these fields:

| Field | Meaning |
|---|---|
| `nv_state` | The embedded `nv_state_t`. It must be the first member. |
| `pci_dev` | The device's `struct pci_dev`. |
| `minor_num` | The device minor number, as in `/dev/nvidiaN`. |
| `next` | The next device. The global list `nv_linux_devices` is singly linked through this field. |
| `open_files` | A `struct list_head` of `nv_linux_file_private_t.entry`. `nv_add_open_file()` adds each open file to it under `mmap_lock`. |
| `proc_dir`, `drm`, `numa_info`, `rc_timer`, `ldata_lock`, `mmap_lock` | Other per-device state. |

`nv_state_t` fields:

| Field | Meaning |
|---|---|
| `priv` | Points to RM-private data. |
| `os_state` | Points back to the `nv_linux_state_t`. |
| `pci_info` | Domain, bus, slot and function. |
| `gpu_id` | GPU identifier. |
| `nv_uuid_cache.uuid[]` | Cached GPU UUID. |
| `bars[NV_GPU_NUM_BARS]`, `regs` | BAR apertures and the register aperture. |

Globals in `kernel-open/nvidia/nv.c` [S]:

| Global | Meaning |
|---|---|
| `nv_linux_devices` | Head of the device list. |
| `nv_ctl_device` | The `nv_linux_state_t` for `/dev/nvidiactl`. |
| `nvidia_fops` | The `file_operations` structure for both `nvidia` and `nvidiactl`. |

**Per open file.** `file->private_data` points to an `nv_linux_file_private_t` (`NV_GET_LINUX_FILE_PRIVATE`) [S].

| Field | Meaning |
|---|---|
| `nvfp` | The embedded `nv_file_private_t`, which is the first member. RM uses its address as the client's OS key (§1.2). |
| `nvptr` | The owning `nv_linux_state_t`. |
| `free_list` | List of `nv_alloc_t` allocations. |
| `file_mapping_list` | Mapping contexts. Each has `context.memArea.pRanges[]`, the physical ranges mapped into the process. |
| `entry` | Links into `nvl->open_files`. |
| `attached_gpus`, `num_attached_gpus` | GPUs attached to this file. |
| `event_data_head` | Pending events. |

`nv_file_private_t` fields [S]: `handles`, `maxHandles`, `deviceInstance`, `gpuInstanceId`, `ctl_nvfp` (the
control fd this device fd was registered to), `register_or_refcount`, and `bCleanupRmapi`.

**Mappings into user space** (`kernel-open/nvidia/nv-mmap.c`) [S]. VMAs created by mmap on an nvidia device file
have `vm_ops == &nv_vm_ops`. `vm_private_data` (`NV_VMA_PRIVATE`) points to an `nv_alloc_t`, which has:

| Field | Meaning |
|---|---|
| `pid` | Owning PID. |
| `num_pages`, `size` | Allocation size. |
| `page_table` | An array of `nvidia_pte_t {phys_addr, virt_addr}`. |
| `user_pages` | Pinned user pages. |
| `flags` | Bitfield including `contig`, `user`, `peer_io`, `unencrypted` and `carveout`. |

This shows exactly which physical host pages a process shares with the GPU. It is the host side of Keto's
`nvidia.sysmemmap` and `nvidia.malware.exfil`.

### 1.2 Resource Manager (RM) object model (`src/nvidia/`)

All RM objects are NVOC C "classes". Each struct begins with a union `{ __nvoc_metadata_ptr | __nvoc_rtti }`,
followed by the base-class sub-objects (`__nvoc_base_<Parent>`) and then data members [S].

**Resource server.** Sources: `src/nvidia/generated/g_rs_server_nvoc.h`, `g_resserv_nvoc.h` and
`src/nvidia/src/kernel/rmapi/rmapi.c` [S].

- **Global:** `RsServer g_resServ;` in `rmapi.c`.
- **`RsServer` fields:**

  | Field | Meaning |
  |---|---|
  | `privilegeLevel` | Server privilege level. |
  | `pClientSortedList` | An array of `RS_CLIENT_HANDLE_BUCKET_COUNT = 0x400` intrusive lists, indexed by `hClient & RS_CLIENT_HANDLE_BUCKET_MASK (0x3FF)`. |
  | `clientHandleBase` | `RS_CLIENT_HANDLE_BASE = 0xC1D00000`; internal clients use `0xC1E00000`. |
  | `activeClientCount`, `activeResourceCount` | Live object counts. |
  | `disabledClientList` | Clients being torn down. |
  | `shareMap` | Shared resources. |

- **`CLIENT_ENTRY` fields:** `pLock`, `pClient` (`struct RsClient *`), `hClient`, `lockOwnerTid`, `refCount`,
  `bPendingFree`, and `node` (`ListNode {pPrev, pNext}`).
- **List container** (`src/nvidia/inc/libraries/containers/list.h`) [S]: `ListBase {pHead, pTail, count, nodeOffset}`.
  The value address is the node address minus `nodeOffset`.
  - **Caveat:** checked builds (`PORT_IS_CHECKED_BUILD`) add `ListNode.pList`, so an ISF must come from a
    release-configuration build.

**Client.** Sources: `src/nvidia/generated/g_rs_client_nvoc.h` and `g_client_nvoc.h` [S].

`RsClient` fields:

| Field | Meaning |
|---|---|
| `hClient` | Client handle. |
| `type` | User or kernel client. |
| `bActive`, `bDisabled` | State flags. |
| `resourceMap` | An `RsRefMap` of `RsResourceRef`. |
| `handleRangeStart`, `handleRangeSize` | Handle range. |
| `pendingFreeList` | Objects pending free. |

`RmClient` derives from `RsClient`. Its fields:

| Field | Meaning |
|---|---|
| `__nvoc_base_RsClient` | The embedded `RsClient`. Recover the `RmClient` with `container_of`. |
| `ProcID` | Owning PID. |
| `SubProcessID`, `SubProcessName[100]` | Sub-process (vGPU) identity. |
| `name[100]` | Process name. |
| `pOSInfo` | OS key that ties the client to a file (see below). |
| `pOsPidInfo` | OS PID reference. |
| `cachedPrivilege`, `bIsRootNonPriv` | Privilege state. |
| `pSecurityToken`, `pUserInfo` | Security context. |
| `ClientDebuggerState` | Debugger state. |
| `imexChannel` | IMEX channel. |
| `Flags` | Client flags. |

How `rmclientConstruct_IMPL` fills these (`src/nvidia/src/kernel/rmapi/client.c`) [S]:

- `ProcID = osGetCurrentProcess()`, and `os_get_current_process()` returns `current->tgid`
  (`kernel-open/nvidia/os-interface.c`).
- `name` comes from `osGetCurrentProcessName()`, which copies `current->comm`.
- `ProcID` can be overridden by `procIDOverride` or a vGPU process token, so a mismatch between `name` and the
  task with that PID is itself a finding.
- `pOSInfo = pSecInfo->clientOSInfo`. In `arch/nvalloc/unix/src/escape.c` this is `nvfp->ctl_nvfp`, falling back
  to `nvfp`. That ties every client to an open `/dev/nvidiactl` or `/dev/nvidiaN` file.
- Further globals: `g_clientListBehindGpusLock` (an `RmClientList` of `RmClient*`) and `g_osInfoList` (an
  `OsInfoMap` multimap keyed by `pOSInfo`).

**Resource tree** (`src/nvidia/generated/g_rs_resource_nvoc.h`) [S]. Each `RsResourceRef` has:

| Field | Meaning |
|---|---|
| `pClient` | Owning client. |
| `pResource` | The actual object. |
| `externalClassId` | The class the user allocated. |
| `internalClassId` | The NVOC class ID. |
| `pParentRef`, `hResource` | Parent and handle. |
| `depth` | Depth in the tree. |
| `childRefMap` | Children, keyed by `(internalClassId << 32 \| handle)`. |
| `cpuMappings` | CPU mappings of this object. |
| `sharePolicyList`, `depRefList` | Sharing and dependencies. |

Useful `externalClassId` values, read from `src/common/sdk/nvidia/inc/class/` [S]:

| Class | ID |
|---|---|
| `NV01_ROOT` (the client) | `0x0` |
| `NV01_DEVICE_0` | `0x80` |
| `NV20_SUBDEVICE_0` | `0x2080` |
| `NV01_MEMORY_SYSTEM` | `0x3E` |
| `NV01_MEMORY_LOCAL_USER` (VRAM) | `0x40` |
| `NV01_MEMORY_SYSTEM_OS_DESCRIPTOR` | `0x71` |
| `FERMI_VASPACE_A` | `0x90F1` |
| `KEPLER_CHANNEL_GROUP_A` | `0xA06C` |
| `AMPERE_CHANNEL_GPFIFO_A` | `0xC56F` |
| `BLACKWELL_CHANNEL_GPFIFO_A` | `0xC96F` |
| `NV_MEMORY_FABRIC` | `0xF8` |
| `NV_MEMORY_MULTICAST_FABRIC` | `0xFD` |

`NV01_MEMORY_SYSTEM_OS_DESCRIPTOR` wraps an existing user virtual-address range for GPU access. A descriptor
pointing into another process's memory, or into a non-heap mapping, is a strong DMA-abuse lead [U].

**Channels** [S]. `KernelChannel` (`g_kernel_channel_nvoc.h`) fields:

| Field | Meaning |
|---|---|
| `ChID` | Channel ID. |
| `runlistId` | Runlist the channel is on. |
| `ProcessID`, `SubProcessID` | Owning process. `kernel_channel.c` sets them from `pRmClient->ProcID` and `SubProcessID`. |
| `engineType` | Engine the channel targets. |
| `pKernelChannelGroup`, `pKernelChannelGroupApi` | Owning channel group (TSG). |
| `hVASpace`, `pVAS` | GPU virtual address space. |
| `pInstSubDeviceMemDesc[8]` | The instance block, which Keto finds in VRAM by the `0xFACE` signature. |
| `pUserdSubDeviceMemDesc[8]` | USERD memory. |
| `pFifoHalData[8]` | HAL-specific FIFO data. |
| `bUvmOwned`, `bGspOwned` | Ownership flags. |
| `subctxId`, `vaSpaceId` | Sub-context and VA-space IDs. |
| `pErrContextMemDesc` | Error-notifier memory. |
| `bCCSecureChannel` | Confidential-computing channel. |

`KernelChannelGroup` (`g_kernel_channel_group_nvoc.h`) fields: `grpID`, `runlistId`, `chanCount`, `engineType`,
`pVAS`, `gfid`, `pChanList`, `timesliceUs`, `tsgUniqueId`.

Per GPU, `KernelFifo.ppChidMgr[numChidMgrs]` → `CHID_MGR {runlistId, pFifoDataHeap, pGlobalChIDHeap,
numChannels, pChanGrpTree}` (`g_kernel_fifo_nvoc.h`) [S].

The `Kernel*` prefix marks the CPU-side ("kernel RM") half of objects whose physical counterpart runs in GSP
firmware on GSP-enabled GPUs. The client, channel and memory bookkeeping above is therefore in host RAM, but
GSP-internal state is not [U, inferred from naming and the README's GSP requirement].

**Memory** [S].

`Memory` (`g_mem_nvoc.h`) fields: `pDevice`, `pSubDevice`, `pGpu`, `Length`, `HeapOwner`, `pMemDesc`,
`KernelVAddr`, `Attr`, `Attr2`, `Type`, `Flags`, `tag`, `gpuAcctSessionId`.

`MEMORY_DESCRIPTOR` (`g_mem_desc_nvoc.h`) fields:

| Field | Meaning |
|---|---|
| `pGpu` | Owning GPU. |
| `_addressSpace` | `ADDR_SYSMEM=1`, `ADDR_FBMEM=2`, `ADDR_VIRTUAL=4` or `ADDR_FABRIC_V2=6`. |
| `Size`, `ActualSize` | Allocation size. |
| `PageCount`, `_pageSize` | Page count and page size. |
| `_flags` | Descriptor flags. |
| `_pteKind` | PTE kind. |
| `RefCount`, `DupCount` | Reference counts. |
| `allocTag` | Allocation tag. |
| `_pParentDescriptor` | Parent descriptor. |
| `pPmaAllocInfo` | PMA allocation info. |
| `_kernelMapping` | Kernel mapping. |
| `_pteArray[1]` | A trailing variable-length array of physical addresses. |

For `ADDR_FBMEM`, `_pteArray` gives the VRAM physical pages. For `ADDR_SYSMEM` it gives the host pages. This
correlates directly with Keto's GMMU walks.

**GPUs** [S]. `OBJSYS *g_pSys` (`src/kernel/core/system.c`) → `OBJGPUMGR.gpuHandleIDList[32]`, whose entries are
`{gpuInstance, pGpu}` → `OBJGPU`.

**Accounting** [S][P]. `GpuAccounting.gpuInstanceInfo[32]` holds `isAccountingEnabled`, `liveProcAcctInfo` and
`deadProcAcctInfo`. These contain `GPUACCT_PROC_ENTRY {procId, procType, gpuUtil, maxFbUsage, startTime,
endTime}`, a history that includes dead processes. Accounting is off by default [P].

**NVOC self-description (scan without an ISF).** Defined in `src/nvidia/inc/libraries/nvoc/rtti.h` and
`prelude.h` [S].

- Object layout: object → `NVOC_RTTI {pClassDef, dtor, offset}` → `NVOC_CLASS_DEF {classInfo, objCreatefn,
  pCastInfo, pExportInfo}`.
- `NVOC_CLASS_INFO {size, classId:24, visibility:2, providerId, name}`.
  - `name` is present because the RM is built with `NV_PRINTF_STRINGS_ALLOWED=1` (`src/nvidia/Makefile`).
  - The `size` field gives each object's size without DWARF.
- Class IDs (`__nvoc_class_id_*`) [S]:

  | Class | ID |
  |---|---|
  | `RmClient` | `0xB23D83` |
  | `RsClient` | `0x8F87E5` |
  | `KernelChannel` | `0x5D8D70` |
  | `KernelChannelGroup` | `0xEC6DE1` |
  | `KernelChannelGroupApi` | `0x2B5B80` |
  | `Memory` | `0x4789F2` |
  | `VideoMemory` | `0xED948F` |
  | `SystemMemory` | `0x007A98` |
  | `OsDescMemory` | `0xB3DACD` |
  | `Device` | `0xE0AC20` |
  | `Subdevice` | `0x4B01B3` |
  | `OBJGPU` | `0x7EF3CB` (also reported by Bowen et al. [P]) |
  | `GpuAccounting` | `0x0F1350` |

- The scan method published by Bowen et al. [P]:
  1. Resolve `__nvoc_class_def_<Class>` from module kallsyms.
  2. Find the pointer-sized words that point to it. These are the `NVOC_RTTI` / `NVOC_METADATA__<Class>`
     structures.
  3. Find the objects whose first quadword points to that RTTI.

  They report 171 class definitions in the open 525 driver and 330 in the closed one. Closed-driver class
  definitions are scrubbed alphabetically, from `_nv001924rm` to `_nv002253rm` [P].

### 1.3 Linking GPU objects to a Linux process (RAM image)

The process linkage, as a chain:

```
task_struct (pid/tgid, comm)
  └─ files → struct file f_op == &nvidia_fops  (or dentry nvidiactl / nvidiaN)
        └─ private_data → nv_linux_file_private_t
              ├─ nvfp  (== RmClient.pOSInfo; reverse via g_osInfoList)
              ├─ free_list → nv_alloc_t {pid, page_table[]}
              └─ file_mapping_list → memArea.pRanges[] (physical ranges mmapped)
  └─ mm → VMAs with vm_ops == &nv_vm_ops → vm_private_data = nv_alloc_t

g_resServ.pClientSortedList[0..0x3FF] → CLIENT_ENTRY.pClient → RmClient {ProcID, name, pOSInfo}
     └─ resourceMap → RsResourceRef tree: Device(0x80) → Subdevice(0x2080) / VASpace(0x90F1)
                       / ChannelGroup(0xA06C) → Channel(0xC56F...) → KernelChannel {ChID, runlistId, ProcessID}
                       / Memory(0x3E, 0x40, 0x71) → MEMORY_DESCRIPTOR {_addressSpace, _pteArray[]}
```

Cross-views that this enables:

- **RM clients without a live task.** An `RmClient` whose `ProcID` has no task, or whose `name` differs from the
  task's `comm`. This is Villani et al.'s "process-less" GPU execution case [P].
- **Device files without RM clients.** Files opened on nvidia devices that have no RM clients.
- **Channels against VRAM.** `KernelChannel.ChID` and `runlistId` compared with Keto's VRAM-side
  `chanscan` and `runlist` results. A channel present in VRAM but missing from RM is hidden or torn down.
- **DMA reach.** `nv_alloc_t` and `MEMORY_DESCRIPTOR` sysmem pages compared with the GMMU sysmem PTEs that
  Keto resolves.

### 1.4 nvidia-uvm (unified memory)

Sources: `kernel-open/nvidia-uvm/uvm_va_space.h`, `uvm_va_range.h`, `uvm_range_tree.h`, `uvm_user_channel.h`,
`uvm_global.h`/`.c`, `uvm_fd_type.h`/`.c` and `uvm_va_space_mm.h` [S].

**Global anchor.** `uvm_global_t g_uvm_global` → `va_spaces {lock, list}` → `uvm_va_space_t.list_node`. It also
holds `parent_gpus[]`.

**Per open file.** `filp->private_data` is a tagged pointer. The low `UVM_FD_TYPE_BITS = 3` bits are the type:
`UVM_FD_UNINITIALIZED=0`, `INITIALIZING=1`, `VA_SPACE=2`, `MM=3`, `TEST=4`. The pointer is
`private_data & ~7`.

**`uvm_va_space_t` fields:**

| Field | Meaning |
|---|---|
| `registered_gpus`, `registered_gpu_va_spaces` | GPUs and GPU VA spaces registered with this VA space. |
| `va_range_tree` | A `uvm_range_tree_t {rb_root, head}` of nodes `{start, end, rb_node, list}`. |
| `gpu_va_spaces[UVM_ID_MAX_GPUS]` | Per-GPU VA spaces. |
| `va_space_mm` | `uvm_va_space_mm_t`. Its `mm` field is the owning `mm_struct`, which links back to the task. |
| `tools` | UVM tools event queues and counters, used by profilers and debuggers via `nvidia-uvm-tools`. |
| `user_channels_stopped`, `initialization_flags`, `hmm`, `ats` | Other state. |

**`uvm_va_range_t` fields:** `va_space`, `node` (start/end), and `type`. The type is one of `MANAGED`,
`EXTERNAL`, `DMA_BUF`, `CHANNEL`, `SKED_REFLECTED` or `SEMAPHORE_POOL`.

- Managed ranges add `blocks`, `vma_wrapper` and `policy`.
- External ranges add `mapped_gpus`, `gpu_ranges[]` and `retained_mask`.

**`uvm_gpu_va_space_t` fields:** `va_space`, `gpu`, `state`, `duped_gpu_va_space`, `page_tables`
(`uvm_page_tree_t`, the GPU page directory this VA space uses), `registered_channels`, `channel_va_ranges`.

**`uvm_user_channel_t` fields:**

| Field | Meaning |
|---|---|
| `gpu_va_space`, `gpu` | Owning GPU VA space and GPU. |
| `user_rm_channel` | The RM client and channel handles. |
| `engine_type` | Engine the channel targets. |
| `subctx_id` | Sub-context ID. |
| `hw_runlist_id`, `hw_channel_id` | Hardware runlist and channel IDs. |
| `work_submission_token` | Doorbell token. |
| `resources[]`, `channel_ranges` | Channel resources and their VA ranges. |
| `list_node` | Links into `gpu_va_space.registered_channels`. |

Forensic use: this layer yields per-process managed-memory ranges, which CPU VAs are GPU-shared, the GPU page-tree
root, and the hardware channel and runlist IDs. A hidden UVM user, or a channel registered with UVM but missing
from RM, is an inconsistency worth reporting.

### 1.5 Feasibility with Volatility 3

**Globals.** Module globals can be resolved from the in-image module kallsyms: `nv_linux_devices`,
`nv_ctl_device`, `nvidia_fops`, `nv_vm_ops`, `g_resServ`, `g_clientListBehindGpusLock`, `g_osInfoList`, `g_pSys`,
`g_uvm_global` and `__nvoc_class_def_*`. Volatility 3's `framework/symbols/linux/kallsyms.py` walks each module's
ELF symtab from memory (`get_modules_symbols`, `module_lookup_address`) [S]. This works on open modules. On
closed modules the RM names are scrubbed [P].

**Types need DWARF for the exact build.** dwarf2json accepts several `--elf` inputs, with later files taking
precedence [S]. Build notes:

- **Linux glue.** `kernel-open/Kbuild` adds `-g` only when `NV_BUILD_TYPE=debug` [S].
- **RM core.** `src/nvidia/Makefile` with `DEBUG=1` adds `-gsplit-dwarf` [S]. That produces `.dwo` files,
  which dwarf2json does not read [P].
- **Recommended path.** Build a release configuration with plain `-g` added, and run dwarf2json on `nvidia.ko`
  and `nvidia-uvm.ko` [U, not yet tried]. Do not use `DEBUG=1` for an ISF: it also defines `DEBUG=1` and can
  change layouts.
- **Module BTF.** If the distribution kernel has `CONFIG_DEBUG_INFO_BTF_MODULES`, a module built with debug info
  gets `.BTF`. btf2json could then supply types [U]. Typical DKMS builds have no debug info, so expect none.

**Existing symbol repositories.** None was found that covers the NVIDIA modules.

- Abyss-W4tcher/volatility3-symbols covers distribution kernels only: AlmaLinux, Debian, Kali, Rocky and Ubuntu.
  It publishes stable `banners/banners.json` for `--remote-isf-url` and states no license [S].
- The repository warns that its `raw/master/<Distro>/...` paths stop working on 2026-11-21, so use only the
  banners URLs [S].
- **Practical plan:** keep a small per-driver-version "NVIDIA ISF overlay" (types only). Resolve symbols through
  kallsyms, with NVOC RTTI scanning as the fallback when no overlay exists.

**Overall feasibility:**

- **High** for open modules, given an overlay ISF.
- **Medium** with NVOC scanning only. Class IDs and sizes come for free; member offsets do not.
- **Low** for closed modules, where only the NVOC sizes and IDs survive.

---

## 2. Windows: dxgkrnl / WDDM and ETW

### 2.1 Kernel objects and the EPROCESS link

**The `EPROCESS` link** [S][L].

- `_EPROCESS.DxgProcess` (`VOID*`) is at offset `0x6E0` on Windows 11 24H2 (Vergilius). `Win32Process` is at
  `0x298`.
- On the test machine (build 26200), the exported `PsGetProcessDxgProcess` reads `mov rax,[rcx+6E0h]; ret` and
  `PsSetProcessDxgProcess` writes the same offset [L, `ntoskrnl.exe` export bytes].
- The field comes from the public kernel PDB, so Volatility 3's Windows ISF already has it.
- A non-null `DxgProcess` means the process has a graphics-kernel (D3DKMT) presence. Many GUI processes have
  one, so use it as a filter, not a verdict.
- Sources:
  - https://www.vergiliusproject.com/kernels/x64/windows-11/24h2/_EPROCESS

**Object names.** The objects are `DXGPROCESS`, `DXGDEVICE`, `DXGCONTEXT`, `DXGALLOCATION`, `DXGADAPTER` and
`DXGRESOURCE`. They are C++ classes in `dxgkrnl.sys`, with scheduling in `dxgmms2.sys`. Method names appear in
public write-ups, for example `DXGDEVICE::CreateAllocation` behind `D3DKMTCreateAllocation` (ZDI) [S].

**Object layouts are not public.** Microsoft states that a public (stripped) PDB contains function names,
addresses and FPO data only. It has no type information [S]. The test machine's `dxgkrnl.sys` references
`dxgkrnl.pdb` with GUID+age `B2547D7BE392E74ED23CBE216DAE62231` [L]. That PDB can give method and global
addresses, but layouts must be reverse-engineered for each build. Volatility 3's `windows.netscan` sets the
precedent: hand-maintained type JSON per `tcpip.sys` version, plus `PDBUtility.symbol_table_from_pdb` for
globals [S].

**Driver-side process objects.** WDDM 2.x drivers receive `DxgkDdiCreateProcess` with `DXGK_CREATEPROCESSFLAGS`.
The flags are `SystemProcess`, `GdiProcess`, `VirtualMachineProcess`, `VirtualMachineWorkerProcess` and
`SessionIsolatedContainer`. Microsoft documents that "each virtual machine Dxgkrnl process will belong to the same
EPROCESS as the same virtual machine worker process" [S]. Consequence: on the Windows host, GPU work from WSL2
or Hyper-V guests is attributed to the VM worker process, not to the guest process [U for WSL2 specifically].

**Handle types.** The WSL2 port (§3) mirrors the Windows handle-type enum: adapter, device, resource,
allocation, context, sync object, paging queue, hwqueue and so on. This suggests a similar per-process handle
table in Windows [U].

**NVIDIA `nvlddmkm.sys`.** No PDBs are available. The NVIDIA Driver Symbol Server hosts binaries only: "no PDBs
will be distributed" [S].

### 2.2 ETW: Microsoft-Windows-DxgKrnl

**Provider** [L]: `Microsoft-Windows-DxgKrnl {802EC45A-1E99-4B83-9920-87C98277BA9D}`.

Keywords:

| Keyword | Value |
|---|---|
| `Base` | `0x1` |
| `Profiler` | `0x2` |
| `References` | `0x4` |
| `Resource` | `0x40` |
| `Memory` | `0x80` |
| `DriverEvents` | `0x400` |
| `GPUScheduler` | `0x8000` |
| `DxgKrnl` | `0x10000` |
| `GPUVA` | `0x100000` |
| `VidMmWorkerThread` | `0x200000` |
| `VirtualGpu` | `0x800000` |
| `HardwareSchedulingLog` | `0x4000000` |
| `Present` | `0x8000000` |
| `PerfData` | `0x20000000` |

The channel bits include `/Performance` (`0x4000000000000000`). Source: `logman query providers
Microsoft-Windows-DxgKrnl` [L].

Events most useful for forensics, from `Get-WinEvent -ListProvider` on build 26200 [L]. Opcode 1 is Start, 2 is
Stop, and 3 is the `DCStart` rundown. For example, Adapter is IDs 24, 25 and 26.

| Event (IDs) | Fields |
|---|---|
| Process Start/Stop/DCStart (471–473, 477, 491, 492) | `DxgProcess`, `ProcessId`, `HostProcessHandle`, `ProcessFlags` |
| Device Start/Stop/DCStart (27–29) | `hProcessId`, `pDxgAdapter`, `ClientType`, `hDevice`, `DxgProcess`, `VirtualGpu` |
| Context Start/Stop/DCStart (30–32) | `hDevice`, `NodeOrdinal` (engine), `EngineAffinity`, `DmaBufferSize`, `hContext`, `ParentDxgContext` |
| HwQueue Start/Stop/DCStart (422–424) | `hContext`, `hHwQueue`, `ParentDxgHwQueue` |
| AdapterAllocation (33–35), keyword `Resource` | `hProcessId`, `hDevice`, `allocSize`, segments, `Format`, `Width`/`Height`, `pSectionObject`, `PageTableOrDirectory` |
| DeviceAllocation (36–38) | `hProcessId`, `hDevice`, `hVidMmAlloc`, `hDxgResource`, `pVirtualAddress` |
| ProcessAllocation (225, 226), keyword `Memory` | `Handle`, `Size`, `Mapping`, `ProcessId` |
| DmaPacket (175, 176) | `hContext`, `PacketType`, `uliSubmissionId`, `ulQueueSubmitSequence`, `pDmaBuffer`, `QuantumStatus` |
| QueuePacket (178, 180) | `hContext`, `PacketType`, `SubmitSequence`, `DmaBufferSize`, `bPreempted`, `bTimeouted`, `pQueuePacket` |
| TerminateAllocation (39), ProcessTerminateAllocation (40) | `hVidMmAlloc` |

Uses:

- **Joining ETW to a RAM image.** The `DxgProcess` and `ProcessId` pair in the Process events maps a kernel
  pointer to a PID. The same pointer appears in `_EPROCESS.DxgProcess`.
- **Snapshots.** The rundown (`DCStart`) events give a point-in-time listing of every GPU process, device,
  context, queue and allocation. This is ETW's equivalent of `pslist`. Triggering rundown with an ETW
  capture-state request is standard ETW practice, but was not tested here [U].
- **GPU timelines.** DmaPacket and QueuePacket events per `hContext` give a per-process compute timeline. A
  long-running context that never presents is miner-like.

**GPUView.** `log.cmd` records these streams into `Merged.etl`. It ships with the Windows Performance Toolkit
(ADK) [S]. https://learn.microsoft.com/en-us/windows-hardware/drivers/display/using-gpuview

**Performance counters.** These are live or recordable, not historical [L]:

- Counter sets: `GPU Engine` (Utilization Percentage, Running Time), `GPU Process Memory` (Dedicated, Shared,
  Local, Non Local, Total Committed), `GPU Adapter Memory`, `GPU Local Adapter Memory` and `GPU Non Local
  Adapter Memory`.
- Instance names embed the PID, for example `pid_10632_luid_0x00000000_0x00011E2C_phys_0_eng_0_engtype_3D`.
- Task Manager's data "is gathered directly from VidSch and VidMm" [S].
  https://devblogs.microsoft.com/directx/gpus-in-the-task-manager/

**NVIDIA CUDA ETW** [L]. The driver package installs `nvcudaETW.xml`, which declares provider `NV CUDA`
`{675d0d6b-2a12-4703-85d1-d36829575a1c}`. The manifest defines no events. Whether `nvcuda64.dll` emits
TraceLogging events under this GUID is unknown [U].

**EDR use.** No public documentation was found showing that mainstream EDRs consume the DxgKrnl provider [U].

- Published GPU-cryptojacking detection uses per-application GPU load and memory. Tanana (2024) reports 80%
  detection with 20% false positives in a VM test [S]. https://arxiv.org/abs/2408.14554
- Rule sets match on command lines (§5).
- Malware that suppresses ETW is covered by Volatility 3's `windows.etwpatch` plugin, which exists [S].

---

## 3. WSL2: Linux `dxgkrnl` (`drivers/hv/dxgkrnl`)

Source: `microsoft/WSL2-Linux-Kernel` branch `linux-msft-wsl-6.18.y`, files `dxgkrnl.h`, `dxgmodule.c`,
`dxgprocess.c`, `hmgr.h`/`.c` and `ioctl.c` [S].
https://github.com/microsoft/WSL2-Linux-Kernel/tree/linux-msft-wsl-6.18.y/drivers/hv/dxgkrnl

### 3.1 Object tree

The structures form this tree:

```
struct dxgdriver dxgdrv  (global; .dxgglobal)                         [kallsyms: dxgdrv, dxgk_fops - L]
 └─ struct dxgglobal { plisthead (list of dxgprocess.plistentry), plistmutex,
                      adapter_list_head, vgpu_ch_list_head, host_event_list_head,
                      dxgdevice (miscdevice "dxg"), num_adapters, vmbus_ver,
                      map_guest_pages_enabled, async_msg_enabled }
     └─ struct dxgprocess { plistentry, pid, tgid, vpid (pid in its own namespace), nspid (pid_namespace*),
                            process_kref, handle_table, local_handle_table (struct hmgrtable),
                            host_handle (d3dkmthandle on the Windows host), process_adapter_list_head }
         └─ struct dxgprocess_adapter { adapter, process, device_list_head, refcount, ... }
             ├─ struct dxgadapter { host_handle, adapter_state, host_adapter_luid, host_vgpu_luid, luid,
             │                      device_description[80] (UTF-16), device_instance_id[], compute_only,
             │                      pci_dev, adapter_process_list_head, shared_resource_list_head }
             └─ struct dxgdevice { object_state, adapter, process, handle, execution_state,
                                   context_list_head, alloc_list_head, resource_list_head,
                                   pqueue_list_head, syncobj_list_head }
                 ├─ struct dxgcontext  { device, process, handle, device_handle, hwqueue_list_head }
                 │    └─ struct dxghwqueue { context, process, handle, progress_fence_sync_object,
                 │                           progress_fence_mapped_address }
                 ├─ struct dxgresource { handle, device, process, alloc_list_head, private_runtime_handle,
                 │                       shared_owner }
                 ├─ struct dxgallocation { device|resource, process, alloc_handle, num_pages,
                 │                         cpu_address, cpu_address_refcount, pages (struct page**),
                 │                         gpadl, priv_drv_data, flags: resource_owner, cpu_address_mapped,
                 │                         cached, handle_valid }
                 └─ struct dxgpagingqueue { device, process, handle, syncobj_handle, mapped_address }
```

**Handle table** (`hmgr.h`/`hmgr.c`) [S]. `struct hmgrtable {process, entry_table, free_handle_list_head,
table_size, free_count}`. Each `struct hmgrentry {object | free-list indices, type:6, unique, instance,
destroyed}`.

`HMGRENTRY_TYPE_*` values:

| Value | Type |
|---|---|
| 1 | `DXGADAPTER` |
| 2 | `DXGSHAREDRESOURCE` |
| 3 | `DXGDEVICE` |
| 4 | `DXGRESOURCE` |
| 5 | `DXGALLOCATION` |
| 6 | `DXGOVERLAY` |
| 7 | `DXGCONTEXT` |
| 8 | `DXGSYNCOBJECT` |
| 9 | `DXGKEYEDMUTEX` |
| 10 | `DXGPAGINGQUEUE` |
| 11 | `DXGDEVICESYNCOBJECT` |
| 12 | `DXGPROCESS` |
| 13 | `DXGSHAREDVMOBJECT` |
| 14 | `DXGPROTECTEDSESSION` |
| 15 | `DXGHWQUEUE` |
| 16 | `DXGREMOTEBUNDLEOBJECT` |
| 17 | `DXGCOMPOSITIONSURFACEOBJECT` |
| 18 | `DXGCOMPOSITIONSURFACEPROXY` |
| 19 | `DXGTRACKEDWORKLOAD` |

Walking the handle table recovers objects even when they have been unlinked from the device lists. The `unique`
and `destroyed` bits help age them.

**`/dev/dxg` file mapping** [S]. `dxgk_open()` finds or creates the `dxgprocess` by matching
`entry->tgid == current->tgid` on `plisthead`, then sets `f->private_data = process`. `dxgk_fops` is the
`file_operations`. `dxgprocess_create()` fills `pid`, `tgid`, `vpid = task_pid_vnr(current)` and
`nspid = task_active_pid_ns(current)`.

**ioctls** (`ioctl.c`) [S]. For example, `LX_DXCREATECONTEXTVIRTUAL` (0x04), `LX_DXCREATEALLOCATION` (0x06),
`LX_DXSUBMITCOMMAND` (0x0f), `LX_DXCREATEHWQUEUE` (0x18) and `LX_DXSUBMITCOMMANDTOHWQUEUE` (0x34). They are
forwarded to the Windows host over VMBus.

### 3.2 What an investigator learns

What the structures show:

- **Which processes used the GPU.** Every process that opened `/dev/dxg`, with its global PID and its
  in-container PID and namespace. A container that runs CUDA shows up here even if its PID namespace hides it.
- **What each process created.** Adapters used (by description and LUID), and the number of devices, contexts
  and hardware queues. A compute context plus a hardware queue means the process submitted GPU work.
- **Allocations.** Their sizes, and for CPU-visible allocations the guest pages (`pages[]`, `cpu_address`). You
  can dump the contents of shared or system-memory GPU allocations from the guest RAM image.
- **Inconsistencies.** A `dxgprocess` with no matching task means the process exited or was hidden. A task
  holding a `/dev/dxg` file whose `private_data` is not on `plisthead` is unlinked.

What the guest does not hold:

- GPU page tables, command buffers' execution state, or kernels. Work executes on the Windows host's dxgkrnl and
  `nvlddmkm`, under the VM worker process (§2.1).
- CUDA in WSL2 goes through `/usr/lib/wsl/lib/libcuda.so` and `/dev/dxg`, not `/dev/nvidia*`. The host driver
  store also ships `libcuda.so.1.1`, `libnvdxdlkernels.so` and `libnvidia-ptxjitcompiler.so.1` for this path [L].

### 3.3 Feasibility on the project's test machine

**Kernel configuration** (`arch/x86/configs/config-wsl`) [S]:

- `CONFIG_DXGKRNL=y`: dxgkrnl is built in, not a module.
- `CONFIG_DEBUG_INFO=y` and `CONFIG_DEBUG_INFO_BTF=y`.
- `CONFIG_KALLSYMS_ALL=y`.
- `CONFIG_PROC_KCORE=y` and `CONFIG_STRICT_DEVMEM=y`.
- `CONFIG_RANDOMIZE_BASE=y`, so KASLR is on.

**Observed on the running kernel `6.18.33.2-microsoft-standard-WSL2`** [L]:

- `/sys/kernel/btf/vmlinux` (6.7 MB) contains the type names `dxgprocess`, `dxgglobal`, `dxgallocation`,
  `dxghwqueue` and `hmgrentry`.
- `/proc/kallsyms` lists `dxgdrv` and `dxgk_fops`.
- `/proc/kcore` exists, readable by root.

**Acquisition.** AVML tries `/proc/kcore`, then `/dev/crash`, then `/dev/mem`, and writes LiME output. It is
MIT-licensed [S]. https://github.com/microsoft/avml

**Symbols.** btf2json (vobst) builds a Volatility 3 ISF from BTF plus `System.map`, with no debug kernel needed.
Its author calls it a prototype, and global-variable types are mostly missing from BTF [S].
https://lolcads.github.io/posts/2024/11/btf2json and https://github.com/vobst/btf2json

- Workflow: take the BTF and kallsyms from the same boot as the image, and the banner from `/proc/version`
  [U, not yet run].
- dwarf2json is the alternative, using a self-built WSL kernel with the same configuration, but the banner and
  layouts must match exactly.

**Feasibility:** high. This is the best first target for a Volatility 3 bridge, because it can be validated end
to end on the project machine.

---

## 4. User-mode artefacts (CUDA, OpenCL, Vulkan)

### 4.1 CUDA executables and loaded modules

**Sections and registration.** From clang's `CGCUDANV.cpp` (`llvm/llvm-project`), which mirrors nvcc's layout
[S]:

- The fatbin data is in section `.nv_fatbin` (`__nv_relfatbin` for relocatable device code).
- The wrapper `__fatbinwrap*` is in `.nvFatBinSegment`. Its layout is `{u32 magic 0x466243B1, u32 version,
  u64 data, u64 filename_or_fatbins}`.
- The module ID is in `__nv_module_id`.
- Host start-up calls, in order:
  1. `__cudaRegisterFatBinary(&wrapper)` returns a `void**` handle.
  2. `__cudaRegisterFunction(handle, hostStub, deviceName, ...)` runs per kernel. The device kernel names are
     plain strings in `.rodata`.
  3. `__cudaRegisterVar(...)` runs per variable.
  4. `__cudaRegisterFatBinaryEnd(handle)` runs on newer toolkits.
  5. `__cudaUnregisterFatBinary` runs at exit.

  https://github.com/llvm/llvm-project/blob/main/clang/lib/CodeGen/CGCUDANV.cpp
- The fatbin header `{u32 0xBA55ED50, u16 version, u16 header_size, u64 size}` is already parsed by
  `keto/formats/fatbin.py`, which follows the `cricket` project.

**In a process dump.** Scan mapped images for the wrapper magic, follow `data` to the fatbin, and extract cubins
and PTX. Keto's `nvidia.artifactscan` already does this. The device-function name strings passed to
`__cudaRegisterFunction` let you label kernels without disassembly [U for locating them heuristically].

**Runtime bookkeeping.** `libcudart` and `libcuda` keep their module and function lists in undocumented internal
structures [U]. The documented way to enumerate them is live, in-process only (CUDA Driver API) [S]:

- `cuModuleGetFunctionCount` and `cuModuleEnumerateFunctions`. Under lazy loading these return possibly partially
  loaded handles; see `cuModuleGetLoadingMode` and `cuFuncIsLoaded`.
- `cuLibraryGetKernelCount` and `cuLibraryEnumerateKernels`.
- `cuFuncGetName` and `cuKernelGetName`.

https://docs.nvidia.com/cuda/cuda-driver-api/cuda_driver_api/group__CUDA__MODULE.html

**CUPTI.** Resource callbacks `CUPTI_CBID_RESOURCE_MODULE_LOADED`, `..._MODULE_UNLOAD_STARTING` and
`..._MODULE_PROFILED` deliver `CUpti_ModuleResourceData {moduleId, cubinSize, pCubin}`. CUPTI documents this as
the way to obtain JIT-compiled cubins [S].

- https://docs.nvidia.com/cupti/main/main.html
- https://docs.nvidia.com/cupti/api/structCUpti__ModuleResourceData.html

**cuda-checkpoint.** When a process is suspended, "device memory is copied to the host, into allocations managed
by the CUDA driver". This needs driver 550 or later, and the tool is under the NVIDIA SDK EULA [S]. A process
dump taken after a checkpoint therefore contains the process's VRAM contents.
https://github.com/NVIDIA/cuda-checkpoint

### 4.2 Injection hooks

**`CUDA_INJECTION64_PATH`** (and `...32_PATH`). The CUDA driver loads this library at initialisation and calls
`InitializeInjection`. That behaviour is documented in CUPTI samples and tutorials, but no dedicated NVIDIA
specification page was found [U for the official specification].

- Hexacorn documents it as a Windows persistence and injection vector: "Beyond good ol' Run key, Part 107",
  2019-06-07, https://www.hexacorn.com/blog/2019/06/07/beyond-good-ol-run-key-part-107/ [S].

**`NVTX_INJECTION64_PATH`** (and `...32_PATH`). The NVTX loader loads this library and calls
`InitializeInjectionNvtx2`. The search order is in `c/include/nvtx3/nvtxDetail/nvtxInit.h` [S]:

- the environment variable first;
- then, on Android only, `libNvtxInjection64.so`;
- then a weak symbol `InitializeInjectionNvtx2_fnptr` for static injection.

CUPTI documents the NVTX entry points `InitializeInjectionNvtx`, `InitializeInjectionNvtx2` and
`InitializeInjectionNvtxExtension` [S]. https://github.com/NVIDIA/NVTX

**Host-evidence check.** Read the process environment from the RAM image (Volatility `linux.envars` or
`windows.envars`), and on Windows also the persistent environment keys in the registry. Flag these variables
when they point outside the CUDA or Nsight install paths. Keto already does this for live systems
(`nvidia.envars`, `nvidia.malware.injection`).

### 4.3 JIT cache: CUDA ComputeCache

**Location** [S] (CUDA Programming Guide, environment variables):

- Default path: `%APPDATA%\NVIDIA\ComputeCache` on Windows, `~/.nv/ComputeCache` on Linux.
- `CUDA_CACHE_PATH` relocates it, `CUDA_CACHE_DISABLE=1` disables it, and `CUDA_CACHE_MAXSIZE` caps it (256 MiB
  in the example). The same cache stores finalized cubins.
- `CUDA_FORCE_PTX_JIT` and `CUDA_DISABLE_PTX_JIT` change whether JIT happens at all.

A relocated or disabled cache on a GPU-heavy host is an anti-forensics indicator.

https://docs.nvidia.com/cuda/cuda-programming-guide/05-appendices/environment-variables.html

**Format.** Undocumented by NVIDIA, and no public reverse-engineering was found. The layout below was decoded
on the test machine and is consistent on Windows (47 entries) and WSL2 (3 entries) [L].

```
index  (little-endian)
  +0  u32 version   = 0x41
  +4  u32 count
  +8  u64 total     = sum of entry payload sizes
  +16 count × { u64 key_hash; u64 payload_size }
  (file size == 16 + 16*count)

entry file path = <root>/<hex16(key_hash)[0]>/<hex16[1]>/<hex16[2:16]>     e.g. 0/4/0b5b4328bb4583
entry file
  +0   u32 version  = 0x41
  +4   u64 text_len
  +12  u64 cubin_len
  +20  u64 hash (differs from key_hash)
  +28  text[text_len]   compiler build stamp (e.g. "Jun  3 2026" + time), "HOST64", target "sm_89",
                        CRLF padding, then the full PTX source (".version 9.0 / .target sm_89 ...")
  +28+text_len  cubin[cubin_len]  ELF ("\x7fELF") — the finalized SASS
  file size == 28 + text_len + cubin_len ; index payload_size == text_len + cubin_len
```

Forensic value:

- Every JIT-compiled kernel, including PTX-only payloads and OpenCL or JIT malware, leaves its full PTX and the
  final cubin on disk.
- File modification times give a timeline.
- The cubins can be fed to Keto's `--reference` matching to name kernels found in VRAM.

The build stamp and field semantics may change between driver versions, so the parser must validate sizes [U].

### 4.4 OpenCL

`clGetProgramInfo(CL_PROGRAM_BINARIES)` returns "the program binaries (could be an executable binary, compiled
binary or library binary)" for each device [S].
https://registry.khronos.org/OpenCL/specs/3.0-unified/html/OpenCL_API.html

On NVIDIA these binaries are PTX text, and NVIDIA OpenCL kernels are JIT-compiled through the same PTX JIT and
ComputeCache [U]. The NVIDIA ICDs are `nvopencl64.dll`/`OpenCL64.dll` in the driver store and `OpenCL.dll` in
System32 [L].

Detection: PTX text (`.version`, `.target sm_`) in process memory or ComputeCache, together with loaded OpenCL
modules.

A 2021 forum-sale claim of a Windows "GPU-resident" malware PoC requiring OpenCL 2.0 was found only in
secondary reporting and was not verified [U].

### 4.5 Vulkan

**SPIR-V modules** start with the magic number `0x07230203` [S].
https://registry.khronos.org/SPIR-V/specs/unified1/SPIRV.html

**Pipeline caches** begin with `VkPipelineCacheHeaderVersionOne {u32 headerSize, u32 headerVersion, u32 vendorID,
u32 deviceID, u8 pipelineCacheUUID[16]}`. The structure is 32 bytes and always little-endian [S]. NVIDIA's
`vendorID` is PCI vendor `0x10DE` [U, standard PCI ID, not re-read here].
https://registry.khronos.org/vulkan/specs/latest/man/html/VkPipelineCacheHeaderVersionOne.html

**NVIDIA shader disk cache.** On Linux, OpenGL uses `__GL_SHADER_DISK_CACHE_PATH`, falling back to
`$XDG_CACHE_HOME/nvidia/GLCache` or `~/.cache/nvidia/GLCache`. Older drivers used `~/.nv/GLCache` [S, NVIDIA
README 570.133.07]. Whether Vulkan uses the same cache on Linux is not stated there [U].
https://download.nvidia.com/XFree86/Linux-x86_64/570.133.07/README/openglenvvariables.html

On Windows, `%LOCALAPPDATA%\NVIDIA\DXCache` (with `*.nvph` files) and `%LOCALAPPDATA%\NVIDIA\GLCache` exist on
the test machine [L]. Their formats are unknown [U].

---

## 5. Existing tooling and detection content

### Research and plugins

**Bowen, Case, Baggili, Richard**, "A step in a new direction: NVIDIA GPU kernel driver memory forensics", FSI:
Digital Investigation 49 (DFRWS USA 2024) [P].

- They built Volatility 2.6 plugins: CheckNvidia (uses `module_kset` and `pNVRM_ID`), an NVOC_CLASS_DEF scan, a
  reverse structure lookup, and a GPU accounting parser.
- They also built the NVSYMMAP tool, which maps open-source to closed-source symbols. They tested driver 525.
- The code was published at `github.com/LSUACL/GPU-Forensics`, which returns 404 as of 2026-11-17 [L].

https://par.nsf.gov/servlets/purl/10572190 and
https://dfrws.org/presentation/a-step-in-a-new-direction-nvidia-gpu-kernel-driver-memory-forensics/

**Villani, Balzarotti, Di Pietro**, "The impact of GPU-assisted malware on memory forensics: A case study",
DFRWS USA 2015, Intel i915 and Beignet OpenCL [P].

- Anti-forensic techniques studied: unlimited execution (disable hangcheck), process-less execution (kill the
  host process after submission), inconsistent CPU/GPU mapping, and context-less execution.
- Host artefacts identified: the `struct drm_i915_private` context list, the GEM buffer-object lists, and the
  ring head/tail registers.
- Their conclusion: "to find which host processes are using the GPU, the system memory is enough".

https://www.s3.eurecom.fr/docs/dfrws15_villani.pdf

**Volatility 3.** There are no GPU-related plugins in the 2025 Plugin Contest results [S]. The building blocks
Keto can rely on exist in `develop` [S]:

- `linux.lsof`, `linux.proc` (Maps), `linux.lsmod`, `linux.kallsyms`, `linux.module_extract`
- `windows.pslist`, `windows.dlllist`, `windows.vadyarascan`, `windows.etwpatch`
- `yarascan`

https://volatilityfoundation.org/the-2025-volatility-plugin-contest-results-are-in/

**Rekall and MemProcFS.** No GPU, NVIDIA or dxgkrnl plugin was found [S for the searches; absence is not
proof]. MemProcFS is AGPL-3.0 and supports Python and C plugins [S].

### Rule sets

Licences were checked in each repository's LICENSE file [S].

| Source | Licence | GPU/miner relevance |
|---|---|---|
| `Neo23x0/signature-base` | Detection Rule License 1.1 (attribution) | `yara/pua_xmrig_monero_miner.yar`, `yara/crime_crypto_miner.yar` |
| `elastic/protections-artifacts` | Elastic License 2.0 (source-available, not OSI; check its terms before redistributing) | `yara/rules/Linux_Cryptominer_Xmrig.yar`, `Multi_Cryptominer_Xmrig.yar`, `Linux_Cryptominer_*.yar` |
| `Yara-Rules/rules` | GPL-2.0 (last push 2024) | generic malware and miner rules |
| `reversinglabs/reversinglabs-yara-rules` | MIT | generic |
| `SigmaHQ/sigma` | DRL 1.1 | `proc_creation_lnx_crypto_mining.yml`, `lnx_auditd_coinminer.yml` and `proc_creation_win_susp_crypto_mining_monero.yml`, all T1496 and command-line based (e.g. `--donate-level=0`, `--algo=rx/0`) |
| `elastic/detection-rules` | Elastic License 2.0 | no GPU-telemetry rule found |
| `splunk/security_content` | Apache-2.0 | `detections/web/zscaler_cryptominer_downloaded_threat_blocked.yml` |

None of the public rules found uses GPU telemetry (DxgKrnl, NVML, RM state). They detect miners by command line,
network activity or file content.

### MITRE ATT&CK

- **T1496 Resource Hijacking** (v2.0, modified 2025-10-24) has sub-techniques .001 Compute Hijacking,
  .002 Bandwidth, .003 SMS Pumping and .004 Cloud Service [S].
- **T1496.001** (v1.0) lists campaign **ShadowRay (C0045)**: "threat actors leveraged graphics processing units
  (GPU) on compromised nodes for cryptocurrency mining". Its detection strategy is DET0540 [S].
- ATT&CK has no GPU-execution or GPU-hiding technique.
- For Keto findings: CUDA and NVTX injection fits T1574 Hijack Execution Flow and T1055 Process Injection,
  and process-less GPU execution fits T1564 Hide Artifacts. These mappings are our proposal, not MITRE's [U].
- https://attack.mitre.org/techniques/T1496/ and https://attack.mitre.org/techniques/T1496/001/

---

## 6. Recommended Keto features (ranked)

Ranking weighs evidence availability, implementation cost in pure-stdlib Python, and robustness across driver
versions.

| # | Feature (proposed name) | One-line implementation idea | Evidence needed |
|---|---|---|---|
| 1 | `host.computecache` | Parse the ComputeCache `index` and entries (§4.3). Emit hash, mtime, target `sm_XX`, PTX entry points (`.entry` names) and cubin. Feed the cubins into the `--reference` kernel matcher and the PTX into the existing scanners. | Disk triage of `%APPDATA%\NVIDIA\ComputeCache` or `~/.nv/ComputeCache` (also WSL `/home/*/.nv/ComputeCache`) |
| 2 | `wsl.dxgprocs` (Volatility 3 bridge plugin, and Keto import) | Walk `dxgdrv.dxgglobal->plisthead` → `dxgprocess` → adapter, device, context, hwqueue, allocation, and the `hmgrtable` entries. Cross-view with task list and `/dev/dxg` files (`f_op == dxgk_fops`, `private_data`). Optionally dump `dxgallocation.pages[]`. | WSL2 RAM image (AVML via `/proc/kcore`, LiME) plus an ISF from btf2json, using BTF and kallsyms from the same boot |
| 3 | `linux.nvidia.rmclients` (bridge) | Iterate `g_resServ.pClientSortedList[0..0x3FF]` → `RmClient {ProcID, name, pOSInfo}` → `RsResourceRef` tree, labelled by `externalClassId`. Emit per-PID devices, channels (`ChID`, `runlistId`) and memory (`_addressSpace`, size). Flag RM clients with no task or with a name mismatch, and nvidia fds with no client. | Linux RAM image, kallsyms from memory, and an NVIDIA overlay ISF built from the open modules with `-g` |
| 4 | `linux.nvidia.nvocscan` (fallback for #3) | Scan module data for objects whose first quadword points to the RTTI of `__nvoc_class_def_{RmClient,KernelChannel,Memory}`. Use `NVOC_CLASS_INFO.size` and `.name`, and read `ProcID` and `ChID` through small per-version offset tables. | Linux RAM image; no ISF required |
| 5 | `windows.gpuprocs` (bridge) | List processes with non-null `_EPROCESS.DxgProcess`. Mark those that load `nvcuda.dll`/`nvcuda64.dll`, `nvptxJitCompiler64.dll`, `nvopencl64.dll`/`OpenCL.dll`, `vulkan-1.dll` or `nvapi64.dll`, and VAD-scan them with Keto's fatbin, PTX, SPIR-V and cubin scanners. | Windows RAM image (public `ntkrnlmp.pdb` only) |
| 6 | `etw.dxgkrnl` import plus `timeliner` integration | Ingest a DxgKrnl trace exported to CSV/XML (`tracerpt`) and build Process/Device/Context/HwQueue lifetimes, per-context DmaPacket/QueuePacket busy time and allocation totals per PID. Join `DxgProcess` pointers to #5. | ETL from GPUView `log.cmd`, WPR, or EDR ETW export |
| 7 | `linux.nvidia.uvm` (bridge) | Walk `g_uvm_global.va_spaces.list` → per `mm` managed and external ranges and the registered user channels (`hw_runlist_id`, `hw_channel_id`). Cross-view those IDs against VRAM `chanscan` and `runlist`. | Linux RAM image plus the NVIDIA overlay ISF (`nvidia-uvm.ko`) |
| 8 | `linux.nvidia.dmamap` (bridge) | From VMAs with `vm_ops == nv_vm_ops` and from `Memory`/`MEMORY_DESCRIPTOR` sysmem `_pteArray`, list the host physical pages each PID shares with the GPU. Diff against GMMU sysmem PTEs in `nvidia.sysmemmap` and `nvidia.malware.exfil`. Flag `NV01_MEMORY_SYSTEM_OS_DESCRIPTOR (0x71)` objects. | Linux RAM image plus the overlay ISF; VRAM image optional for the diff |
| 9 | Process-dump enrichment in `nvidia.artifactscan` | Add SPIR-V module, `VkPipelineCacheHeaderVersionOne` (vendor `0x10DE`) and `__cudaRegisterFunction` kernel-name string extraction. Add an "injection environment" extractor (`CUDA_`/`NVTX_INJECTION*`) for host images. | Process dump or RAM image |
| 10 | `linux.nvidia.gpuacct` | Parse `GpuAccounting.gpuInstanceInfo[].{live,dead}ProcAcctInfo` for a PID history with start and end times, including exited processes. | Linux RAM image plus the overlay ISF; only useful if accounting was enabled (off by default) |
| 11 | Shipped detection content | Sigma rules for the CUDA/NVTX injection variables (process environment and Windows persistent-environment registry keys) and for ComputeCache relocation or disabling on GPU hosts. Map the rules to ATT&CK as proposed in §5. Reference, but do not vendor, ELv2 rules; DRL 1.1 rules may be adapted with attribution. | EDR or process-creation logs, registry |

**Architectural note.** Keto is pure stdlib and is not a Volatility plugin. The low-friction design is a
separate Volatility 3 plugin package, items 2, 3, 5, 7, 8 and 10, that writes JSON or JSONL into a Keto
evidence container. Keto's existing `--host-image` cross-view plugins then consume it. Items 1, 4 (with
Keto's own LiME layer and kallsyms carving), 6 and 9 can be implemented natively in Keto.

---

## 7. Sources opened

**NVIDIA Linux driver and SDK**

- https://github.com/NVIDIA/open-gpu-kernel-modules, files under:
  - `kernel-open/common/inc/nv-linux.h`, `nv.h`
  - `kernel-open/nvidia/nv.c`, `nv-mmap.c`, `os-interface.c`, `kernel-open/Kbuild`
  - `kernel-open/nvidia-uvm/uvm_va_space.h`, `uvm_va_space_mm.h`, `uvm_va_range.h`, `uvm_range_tree.h`,
    `uvm_user_channel.h`, `uvm_global.h`, `uvm_global.c`, `uvm_fd_type.h`, `uvm_fd_type.c`, `uvm.c`
  - `src/nvidia/generated/g_client_nvoc.h`, `g_rs_server_nvoc.h`, `g_rs_client_nvoc.h`, `g_rs_resource_nvoc.h`,
    `g_resserv_nvoc.h`, `g_kernel_channel_nvoc.h`, `g_kernel_channel_group_nvoc.h`, `g_kernel_fifo_nvoc.h`,
    `g_mem_desc_nvoc.h`, `g_mem_nvoc.h`, `g_gpu_mgr_nvoc.h`, `g_gpu_acct_nvoc.h`, other `g_*_nvoc.h` for class IDs
  - `src/nvidia/src/kernel/rmapi/client.c`, `rmapi.c`, `src/nvidia/src/kernel/core/system.c`,
    `src/nvidia/src/kernel/gpu_mgr/gpu_mgr.c`, `src/nvidia/src/kernel/gpu/fifo/kernel_channel.c`
  - `src/nvidia/src/libraries/resserv/src/rs_server.c`, `src/nvidia/arch/nvalloc/unix/src/escape.c`, `os.c`
  - `src/nvidia/inc/libraries/nvoc/rtti.h`, `prelude.h`, `containers/list.h`
  - `src/common/sdk/nvidia/inc/class/*.h`, `src/nvidia/Makefile`, `utils.mk`, `README.md`, `COPYING`
- https://developer.nvidia.com/blog/nvidia-transitions-fully-towards-open-source-gpu-kernel-modules/
- https://developer.nvidia.com/nvidia-driver-symbol-server
- https://docs.nvidia.com/cuda/cuda-programming-guide/05-appendices/environment-variables.html
- https://docs.nvidia.com/cuda/cuda-driver-api/cuda_driver_api/group__CUDA__MODULE.html, `group__CUDA__LIBRARY.html`,
  `group__CUDA__EXEC.html`
- https://docs.nvidia.com/cupti/main/main.html
- https://docs.nvidia.com/cupti/api/structCUpti__ModuleResourceData.html
- https://github.com/NVIDIA/NVTX (`c/include/nvtx3/nvtxDetail/nvtxInit.h`)
- https://github.com/NVIDIA/cuda-checkpoint
- https://download.nvidia.com/XFree86/Linux-x86_64/570.133.07/README/openglenvvariables.html

**WSL2 and Volatility**

- https://github.com/microsoft/WSL2-Linux-Kernel (branch `linux-msft-wsl-6.18.y`): `drivers/hv/dxgkrnl/*`,
  `arch/x86/configs/config-wsl`
- https://github.com/volatilityfoundation/dwarf2json
- https://github.com/volatilityfoundation/volatility3 (`framework/symbols/linux/kallsyms.py`,
  `framework/symbols/windows/pdbutil.py`, `plugins/windows/netscan.py`, the plugin files listed in §5)
- https://volatility3.readthedocs.io/en/latest/_modules/volatility3/framework/symbols/linux/kallsyms.html
- https://github.com/Abyss-W4tcher/volatility3-symbols
- https://lolcads.github.io/posts/2024/11/btf2json
- https://github.com/microsoft/avml

**Windows**

- https://www.vergiliusproject.com/kernels/x64/windows-11/24h2/_EPROCESS
- https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/public-and-private-symbols
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/d3dkmddi/ns-d3dkmddi-_dxgk_createprocessflags
- https://learn.microsoft.com/en-us/windows-hardware/drivers/display/using-gpuview
- https://devblogs.microsoft.com/directx/gpus-in-the-task-manager/
- https://www.thezdi.com/blog/2018/12/4/directx-to-the-kernel
- https://gengstah.github.io/wiki/kernel/directx/
- Local, read-only:
  - `logman query providers Microsoft-Windows-DxgKrnl`
  - `Get-WinEvent -ListProvider Microsoft-Windows-DxgKrnl`
  - `Get-Counter -ListSet "GPU*"`
  - `ntoskrnl.exe` and `dxgkrnl.sys` export and debug directories
  - the NVIDIA driver store file list and `nvcudaETW.xml`

**Khronos and other specifications**

- https://github.com/llvm/llvm-project/blob/main/clang/lib/CodeGen/CGCUDANV.cpp
- https://registry.khronos.org/OpenCL/specs/3.0-unified/html/OpenCL_API.html
- https://registry.khronos.org/SPIR-V/specs/unified1/SPIRV.html
- https://registry.khronos.org/vulkan/specs/latest/man/html/VkPipelineCacheHeaderVersionOne.html

**Papers, blogs and ATT&CK**

- https://www.s3.eurecom.fr/docs/dfrws15_villani.pdf
- https://par.nsf.gov/servlets/purl/10572190
- https://dfrws.org/presentation/a-step-in-a-new-direction-nvidia-gpu-kernel-driver-memory-forensics/
- https://arxiv.org/abs/2408.14554
- https://www.hexacorn.com/blog/2019/06/07/beyond-good-ol-run-key-part-107/
- https://volatilityfoundation.org/the-2025-volatility-plugin-contest-results-are-in/
- https://attack.mitre.org/techniques/T1496/
- https://attack.mitre.org/techniques/T1496/001/

**Rule repositories** (LICENSE files and the paths named in §5)

- https://github.com/Neo23x0/signature-base
- https://github.com/elastic/protections-artifacts
- https://github.com/Yara-Rules/rules
- https://github.com/reversinglabs/reversinglabs-yara-rules
- https://github.com/SigmaHQ/sigma
- https://github.com/elastic/detection-rules
- https://github.com/splunk/security_content
- https://github.com/ufrisk/MemProcFS
