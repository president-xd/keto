"""Sigma rules for host-observable traces of GPU abuse (``keto sigma -o DIR`` writes them as YAML).

The public rule sets (SigmaHQ, Elastic, Splunk) have no GPU-specific detections; these cover what endpoint
telemetry can see of the techniques Keto finds in memory: GPU miners' command lines, exclusive-compute and
persistence-mode changes, GPU runtimes loaded from dropper locations (OpenCL/CUDA loaders such as CoffeeLoader
and GPUGate), GPU watchdog (TDR) tampering, CUDA/NVTX injection variables, JIT-cache tampering and binding an
NVIDIA GPU to vfio-pci. Each rule carries ATT&CK tags and the Keto plugin that confirms it in memory.
"""

from __future__ import annotations

import os
from typing import Dict, List

AUTHOR = "Keto"
DATE = "2026-11-17"

RULES: List[Dict] = [
    {"name": "gpu_miner_cli_win", "id": "73ab74ea-5a21-5274-a6dc-fa19e19ef336",
     "title": "GPU Cryptocurrency Miner Command Line (Windows)",
     "description": "Process started with command-line options of GPU miners (CUDA/OpenCL device selection, "
                    "GPU mining algorithms, stratum pool URLs).",
     "logsource": {"category": "process_creation", "product": "windows"},
     "detection": {"selection_gpu": {"CommandLine|contains": ["--cuda", "--opencl", "--no-cpu", "--cuda-devices",
                                                             "--opencl-devices"]},
                   "selection_pool": {"CommandLine|contains": ["stratum+tcp://", "stratum+ssl://", "stratum2+tcp://"]},
                   "selection_algo": {"CommandLine|contains": [" -a ethash", " -a kawpow", " -a etchash",
                                                              " -a autolykos2", " --algo kawpow", " --algo ethash"]},
                   "condition": "selection_pool or (selection_gpu and selection_algo)"},
     "tags": ["attack.impact", "attack.t1496"], "level": "high",
     "falsepositives": ["Sanctioned mining or GPU benchmarking"],
     "confirm": "nvidia.malware.miner, nvidia.malware.cryptojack, windows.gpuprocs"},
    {"name": "gpu_miner_cli_lnx", "id": "63f173e9-2468-5e43-a90a-a1774f4ac8cc",
     "title": "GPU Cryptocurrency Miner Command Line (Linux)",
     "description": "Process started with command-line options of GPU miners.",
     "logsource": {"category": "process_creation", "product": "linux"},
     "detection": {"selection_gpu": {"CommandLine|contains": ["--cuda", "--opencl", "--no-cpu", "--cuda-devices"]},
                   "selection_pool": {"CommandLine|contains": ["stratum+tcp://", "stratum+ssl://", "stratum2+tcp://"]},
                   "selection_algo": {"CommandLine|contains": [" -a ethash", " -a kawpow", " -a etchash",
                                                              " -a autolykos2", " --algo kawpow", " --algo ethash"]},
                   "condition": "selection_pool or (selection_gpu and selection_algo)"},
     "tags": ["attack.impact", "attack.t1496"], "level": "high",
     "falsepositives": ["Sanctioned mining or GPU benchmarking"],
     "confirm": "nvidia.malware.miner, nvidia.malware.cryptojack"},
    {"name": "nvidia_smi_exclusive_lnx", "id": "3d048514-4aff-5205-a76a-25e10c694848",
     "title": "NVIDIA GPU Set to Exclusive Compute or Persistence Mode (Linux)",
     "description": "nvidia-smi switches a GPU to an exclusive compute mode or enables persistence mode, as GPU "
                    "cryptojacking campaigns do to monopolise the device.",
     "logsource": {"category": "process_creation", "product": "linux"},
     "detection": {"selection_img": {"Image|endswith": "/nvidia-smi"},
                   "selection_args": {"CommandLine|contains": ["-c EXCLUSIVE_PROCESS", "-c 3", "--compute-mode=3",
                                                              "--compute-mode=EXCLUSIVE_PROCESS", "-c EXCLUSIVE_THREAD",
                                                              "-pm 1", "--persistence-mode=1"]},
                   "condition": "selection_img and selection_args"},
     "tags": ["attack.impact", "attack.t1496"], "level": "medium",
     "falsepositives": ["HPC/ML cluster provisioning"], "confirm": "nvidia.devices, nvidia.malware.cryptojack"},
    {"name": "nvidia_smi_exclusive_win", "id": "0f04e9dd-c4d1-5d3e-8645-fc61bd1011d8",
     "title": "NVIDIA GPU Set to Exclusive Compute or Persistence Mode (Windows)",
     "description": "nvidia-smi switches a GPU to an exclusive compute mode or enables persistence mode.",
     "logsource": {"category": "process_creation", "product": "windows"},
     "detection": {"selection_img": {"Image|endswith": "\\nvidia-smi.exe"},
                   "selection_args": {"CommandLine|contains": ["-c EXCLUSIVE_PROCESS", "-c 3", "--compute-mode=3",
                                                              "--compute-mode=EXCLUSIVE_PROCESS", "-c EXCLUSIVE_THREAD",
                                                              "-pm 1", "--persistence-mode=1"]},
                   "condition": "selection_img and selection_args"},
     "tags": ["attack.impact", "attack.t1496"], "level": "medium",
     "falsepositives": ["Workstation provisioning"], "confirm": "nvidia.devices"},
    {"name": "gpu_runtime_user_path", "id": "ace1bf3d-4c67-5a8b-af55-f5030861e97a",
     "title": "GPU Compute Runtime Loaded From a User-Writable Location",
     "description": "An executable in a temp, download, public or AppData folder loads the OpenCL or CUDA runtime: "
                    "GPU-based loaders decrypt payloads on the GPU (CoffeeLoader/ArmouryLoader) or use OpenCL "
                    "presence as an anti-sandbox gate (GPUGate/HijackLoader).",
     "logsource": {"category": "image_load", "product": "windows"},
     "detection": {"selection_dll": {"ImageLoaded|endswith": ["\\OpenCL.dll", "\\nvcuda.dll", "\\nvopencl64.dll",
                                                             "\\nvopencl32.dll", "\\nvptxJitCompiler64.dll"]},
                   "selection_path": {"Image|contains": ["\\AppData\\Local\\", "\\AppData\\LocalLow\\",
                                                         "\\AppData\\Roaming\\", "\\Windows\\Temp\\",
                                                         "\\Downloads\\", "\\Users\\Public\\", "\\ProgramData\\"]},
                   # per-user installs (VS Code, Discord...) live in AppData\Local\Programs: not a loader location
                   "filter_installed": {"Image|contains": "\\AppData\\Local\\Programs\\"},
                   "condition": "selection_dll and selection_path and not filter_installed"},
     "tags": ["attack.defense-evasion", "attack.t1027", "attack.t1140"], "level": "medium",
     "falsepositives": ["Portable GPU tools run from a download folder",
                        "Per-user applications installed outside AppData\\Local\\Programs"],
     "confirm": "windows.gpuprocs, nvidia.artifactscan (OpenCL source / decryptor kernels)"},
    {"name": "tdr_disabled", "id": "c13f00f7-fd71-58ff-b76e-9e5c6a91ea83",
     "title": "GPU Timeout Detection and Recovery Disabled",
     "description": "TdrLevel set to 0 or TdrDebugMode set to 1 lets GPU kernels run without limit (persistent GPU "
                    "code, long-running miners).",
     "logsource": {"category": "registry_set", "product": "windows"},
     "detection": {"selection_level": {"TargetObject|endswith": "\\Control\\GraphicsDrivers\\TdrLevel",
                                       "Details": "DWORD (0x00000000)"},
                   "selection_debug": {"TargetObject|endswith": "\\Control\\GraphicsDrivers\\TdrDebugMode",
                                       "Details": "DWORD (0x00000001)"},
                   "condition": "selection_level or selection_debug"},
     "tags": ["attack.defense-evasion", "attack.t1562", "attack.impact", "attack.t1496"], "level": "high",
     "falsepositives": ["GPU driver/compute development machines"], "confirm": "nvidia.malware.watchdog"},
    {"name": "cuda_injection_env", "id": "b2ac3423-17a3-5392-ae86-c077b70b33e8",
     "title": "Persistent CUDA/NVTX Injection Library Variable",
     "description": "CUDA_INJECTION64_PATH or NVTX_INJECTION64_PATH set in the persistent environment makes every "
                    "CUDA process load an attacker library (profiler/injection hook abuse).",
     "logsource": {"category": "registry_set", "product": "windows"},
     "detection": {"selection": {"TargetObject|endswith": ["\\Environment\\CUDA_INJECTION64_PATH",
                                                           "\\Environment\\NVTX_INJECTION64_PATH",
                                                           "\\Environment\\NVTX_INJECTION32_PATH"]},
                   "condition": "selection"},
     "tags": ["attack.persistence", "attack.t1574", "attack.privilege-escalation"], "level": "high",
     "falsepositives": ["Nsight/profiler installations"], "confirm": "nvidia.envars, nvidia.malware.injection"},
    {"name": "computecache_tamper", "id": "3f85063f-51a3-5cc0-80ab-0388b8b85f14",
     "title": "CUDA JIT Compute Cache Disabled or Relocated",
     "description": "CUDA_CACHE_DISABLE or CUDA_CACHE_PATH set persistently removes or hides the ComputeCache, "
                    "which otherwise keeps the PTX and cubin of every JIT-compiled kernel.",
     "logsource": {"category": "registry_set", "product": "windows"},
     "detection": {"selection": {"TargetObject|endswith": ["\\Environment\\CUDA_CACHE_DISABLE",
                                                           "\\Environment\\CUDA_CACHE_PATH"]},
                   "condition": "selection"},
     "tags": ["attack.defense-evasion", "attack.t1070"], "level": "medium",
     "falsepositives": ["Build servers"], "confirm": "nvidia.computecache, nvidia.jitcache"},
    {"name": "vfio_bind", "id": "9700e9c9-6b0c-5861-880c-2fda818341b9",
     "title": "GPU Rebound to vfio-pci",
     "description": "A PCI function is handed to vfio-pci (driver_override / bind): on a host that is not a "
                    "hypervisor this lets user space drive the GPU directly, invisible to NVML and the driver.",
     "logsource": {"category": "process_creation", "product": "linux"},
     "detection": {"selection_target": {"CommandLine|contains": ["/drivers/vfio-pci/bind", "/drivers/vfio-pci/new_id"]},
                   "selection_override": {"CommandLine|contains|all": ["driver_override", "vfio-pci"]},
                   "condition": "selection_target or selection_override"},
     "tags": ["attack.defense-evasion", "attack.t1564"], "level": "medium",
     "falsepositives": ["Virtualisation hosts configuring GPU pass-through"], "confirm": "nvidia.malware.rawaccess"},
]


def _scalar(v) -> str:
    s = str(v)
    if s == "" or any(c in s for c in ":#{}[],&*!|>'\"%@`\\") or s.strip() != s or s.lower() in ("yes", "no", "true",
                                                                                                   "false", "null"):
        return "'" + s.replace("'", "''") + "'"
    return s


def _emit(obj, indent=0) -> List[str]:
    pad = "    " * indent
    out = []
    for k, v in obj.items():
        if isinstance(v, dict):
            out.append("%s%s:" % (pad, k))
            out += _emit(v, indent + 1)
        elif isinstance(v, list):
            out.append("%s%s:" % (pad, k))
            out += ["%s    - %s" % (pad, _scalar(x)) for x in v]
        else:
            out.append("%s%s: %s" % (pad, k, _scalar(v)))
    return out


def to_yaml(rule: Dict) -> str:
    doc = {"title": rule["title"], "id": rule["id"], "status": "experimental", "description": rule["description"],
           "references": ["https://attack.mitre.org/techniques/%s/" % t.split(".")[1].upper()
                          for t in rule["tags"] if t.startswith("attack.t")],
           "author": AUTHOR, "date": DATE, "tags": rule["tags"], "logsource": rule["logsource"],
           "detection": rule["detection"], "falsepositives": rule["falsepositives"], "level": rule["level"]}
    return "\n".join(_emit(doc)) + "\n# confirm in memory with: %s\n" % rule["confirm"]


def write_all(out_dir: str) -> List[str]:
    os.makedirs(out_dir, exist_ok=True)
    paths = []
    for r in RULES:
        p = os.path.join(out_dir, "keto_%s.yml" % r["name"])
        with open(p, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(to_yaml(r))
        paths.append(p)
    return paths
