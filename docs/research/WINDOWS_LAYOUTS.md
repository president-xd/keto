# Windows x64 kernel layouts used without a PDB

`keto.winmem.selfprofile` types a Windows kernel image when no PDB or ISF for its build is available. It takes
the layouts in this note from the Vergilius Project (structure pages reconstructed from Microsoft's public PDBs),
read for Windows 10 1607, 1809, 2004 and Windows 11 22H2, 24H2, 25H2 (and the remaining structures for 1809 and
25H2, the two ends of the range). Members that move between builds are not taken from here: they are decoded
from the imaged kernel's own code or found in its data (see the module docstring).

Source pattern: `https://www.vergiliusproject.com/kernels/x64/<windows-10|windows-11>/<version>/<STRUCT>`.

## Identical from Windows 10 1809 to Windows 11 25H2

| Structure | Members (offset) |
|---|---|
| `_HANDLE_TABLE` (0x80) | NextHandleNeedingPool 0x0, TableCode 0x8, QuotaProcess 0x10, UniqueProcessId 0x28 |
| `_HANDLE_TABLE_ENTRY` (0x10) | qword 0: Unlocked:1 @0, RefCnt:16 @1, Attributes:3 @17, ObjectPointerBits:44 @20; dword 8: GrantedAccessBits:25 @0 |
| `_OBJECT_HEADER` (0x38) | TypeIndex 0x18, InfoMask 0x1A, Body 0x30 |
| `_OBJECT_HEADER_NAME_INFO` (0x20) | Directory 0x0, Name 0x8 |
| `_OBJECT_TYPE` | Name 0x10, Index 0x28 (size 0xD8 in 1809, 0xE0 in 25H2) |
| `_FILE_OBJECT` (0xD8) | DeviceObject 0x8, FileName 0x58 |
| `_DRIVER_OBJECT` (0x150) | DriverStart 0x18, DriverSize 0x20, DriverName 0x38, MajorFunction[28] 0x70 |
| `_OBJECT_DIRECTORY` (0x158) | HashBuckets[37] 0x0 |
| `_OBJECT_DIRECTORY_ENTRY` (0x18) | ChainLink 0x0, Object 0x8 |
| `_KLDR_DATA_TABLE_ENTRY` (0xA0) | InLoadOrderLinks 0x0, DllBase 0x30, SizeOfImage 0x40, FullDllName 0x48, BaseDllName 0x58 |
| `_KPROCESS` | DirectoryTableBase 0x28 (size 0x2D8 in 1809, 0x1C8 in 25H2) |
| `_PEB` | Ldr 0x18, ProcessParameters 0x20 |
| `_PEB_LDR_DATA` (0x58) | InLoadOrderModuleList 0x10 |
| `_LDR_DATA_TABLE_ENTRY` | DllBase 0x30, FullDllName 0x48, BaseDllName 0x58 |
| `_RTL_USER_PROCESS_PARAMETERS` | ImagePathName 0x60, CommandLine 0x70, Environment 0x80, EnvironmentSize 0x3F0 |
| `_CLIENT_ID` (0x10) | UniqueProcess 0x0, UniqueThread 0x8 |
| `_CONTROL_AREA` (0x80) | FilePointer 0x40 (`_EX_FAST_REF`) |

Identical from 1607 to 25H2 (all six builds read): `_MMVAD_SHORT` (0x40) VadNode 0x0, StartingVpn 0x18,
EndingVpn 0x1C, StartingVpnHigh 0x20, EndingVpnHigh 0x21, u (flags) 0x30; `_MMVAD` (0x88) Core 0x0,
Subsection 0x48; `_SUBSECTION` (0x38) ControlArea 0x0.

## Moving between builds

| Member | 1809 | 25H2 | Keto derives it from |
|---|---|---|---|
| `_EPROCESS.UniqueProcessId` | 0x2E0 | 0x1D0 | `PsGetProcessId` |
| `_EPROCESS.ActiveProcessLinks` | 0x2E8 | 0x1D8 | UniqueProcessId + 8, checked by walking the list from `PsInitialSystemProcess` |
| `_EPROCESS.ImageFileName` | 0x450 | 0x338 | `PsGetProcessImageFileName` |
| `_EPROCESS.Peb` | 0x3F8 | 0x2E0 | `PsGetProcessPeb` |
| `_EPROCESS.DxgProcess` | 0x7B0 | 0x6E0 | `PsGetProcessDxgProcess` |
| `_EPROCESS.Session` | 0x400 | 0x2E8 | `PsGetProcessSessionId` (then SessionId from the same code) |
| `_EPROCESS.ObjectTable` | 0x418 | 0x300 | the member whose `_HANDLE_TABLE` points back at the process |
| `_EPROCESS.VadRoot` | 0x628 | 0x558 | the member pointing at a parentless VAD with a user range |
| `_EPROCESS.SeAuditProcessCreationInfo` | 0x468 | 0x350 | the member pointing at a `\Device\` path |
| `_ETHREAD.Cid` | 0x638 | 0x508 | `PsGetThreadId` (UniqueThread) - 8 |

On this project's test machine (build 26100) the decoder read UniqueProcessId 0x1D0, ImageFileName 0x338,
Peb 0x2E0, DxgProcess 0x6E0, Session 0x2E8 and Cid 0x508 from `ntoskrnl.exe`, the 25H2 values above, and
Win32Process 0x298, the value docs/research/HOST_SIDE_DETECTION.md records for 24H2. On that build
`PsGetProcessExitTime` reads the current process (`gs:[188h]` -> `KTHREAD.ApcState.Process` at +0xB8 -> ExitTime),
which the decoder follows.

## `_MMVAD_FLAGS` (differs in every build)

| Build | VadType | Protection | PrivateMemory |
|---|---|---|---|
| 1607 (14393) | 3 bits @0 | 5 bits @3 | @15 |
| 1809 (17763) | 3 bits @0 | 5 bits @3 | @14 |
| 2004 (19041; also 20H2-22H2 of Windows 10) | 3 bits @4 | 5 bits @7 | @20 |
| 22H2 (22621), 24H2 (26100), 25H2 (26200) | 3 bits @4 | 5 bits @7 | @21 |

For a build outside this table, and to confirm a listed one, Keto scores each layout on the image's own
image-backed VADs, which must decode as VadType 2 (VadImageMap), PrivateMemory 0 and Protection 7
(EXECUTE_WRITECOPY).
