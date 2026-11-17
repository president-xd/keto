/*
   Keto GPU threat rules.
   Scope: GPU memory images, host RAM images and process dumps.
   Tags: format = GPU payload container (informational on its own; context decides),
         miner / cracker = abuse indicators.
*/

rule KETO_CUDA_Fatbin_Container : format
{
    meta:
        description = "CUDA fat binary header (magic 0xBA55ED50, version 1) - a GPU code container"
        reference = "fatbin layout as documented by the cricket project; validated on NVIDIA driver 592.82 libraries"
    strings:
        $hdr = { 50 ED 55 BA 01 00 10 00 }
    condition:
        $hdr
}

rule KETO_CUDA_Fatbin_Wrapper : format
{
    meta:
        description = "__nv_fatbinwrap descriptor (magic 0x466243B1) as registered by __cudaRegisterFatBinary"
    strings:
        $w1 = { B1 43 62 46 01 00 00 00 }
        $w2 = { B1 43 62 46 02 00 00 00 }
    condition:
        any of them
}

rule KETO_CUDA_Cubin_ELF : format
{
    meta:
        description = "ELF64 image with e_machine EM_CUDA (190): compiled NVIDIA GPU code"
    strings:
        $elf = { 7F 45 4C 46 02 01 01 ?? ?? 00 00 00 00 00 00 00 ?? 00 BE 00 }
    condition:
        $elf
}

rule KETO_PTX_Module : format
{
    meta:
        description = "PTX (NVIDIA virtual ISA) source text, JIT-compiled at load time"
    strings:
        $v = /\.version [0-9]+\.[0-9]+/
        $t = /\.target sm_[0-9]+/
        $e = /\.(visible )?\.entry [A-Za-z_$][A-Za-z0-9_$]*/
    condition:
        $v and $t and $e
}

rule KETO_GPU_Miner_Kernel : miner
{
    meta:
        description = "Kernel / function names of GPU cryptocurrency-mining algorithms"
        attack = "T1496"
    strings:
        $a1 = "ethash_search" ascii
        $a2 = "ethash_calculate_dag_item" ascii
        $a3 = "progpow_search" ascii
        $a4 = "kawpow" ascii nocase
        $a5 = "autolykos" ascii nocase
        $a6 = "kheavyhash" ascii nocase
        $a7 = "cryptonight" ascii nocase
        $a8 = "equihash" ascii nocase
        $a9 = "octopus_search" ascii
        $a10 = "fishhash" ascii nocase
        $a11 = "blake3_search" ascii
        $a12 = "randomx" ascii nocase
    condition:
        any of them
}

rule KETO_Mining_Pool_Protocol : miner
{
    meta:
        description = "Stratum mining-pool protocol strings (miner configuration or traffic buffers)"
        attack = "T1496"
    strings:
        $s1 = "stratum+tcp://" ascii nocase
        $s2 = "stratum+ssl://" ascii nocase
        $s3 = "stratum2+tcp://" ascii nocase
        $m1 = "\"mining.subscribe\"" ascii
        $m2 = "\"mining.authorize\"" ascii
        $m3 = "\"mining.notify\"" ascii
        $m4 = "eth_submitWork" ascii
    condition:
        any of them
}

rule KETO_GPU_Miner_Software : miner
{
    meta:
        description = "Names / banners of common GPU miner programs"
        attack = "T1496"
    strings:
        $p1 = "xmrig" ascii nocase fullword
        $p2 = "lolMiner" ascii nocase
        $p3 = "T-Rex" ascii fullword
        $p4 = "NBMiner" ascii nocase
        $p5 = "PhoenixMiner" ascii nocase
        $p6 = "TeamRedMiner" ascii nocase
        $p7 = "ethminer" ascii nocase fullword
        $p8 = "SRBMiner" ascii nocase
        $p9 = "BzMiner" ascii nocase
        $p10 = "gminer" ascii nocase fullword
    condition:
        any of them
}

rule KETO_GPU_Password_Cracker_Kernel : cracker
{
    meta:
        description = "hashcat-style GPU kernel names (mXXXXX_m04 / _s08 / _init / _loop / _comp)"
    strings:
        $k = /m[0-9]{5}_(m04|m08|m16|s04|s08|s16|init|loop|comp)\b/
    condition:
        $k
}

rule KETO_OpenCL_Kernel_Source : format
{
    meta:
        description = "OpenCL C kernel source text (passed to clCreateProgramWithSource) - GPU code in host memory"
    strings:
        $k1 = "__kernel void" ascii
        $k2 = "get_global_id(" ascii
        $g = "__global" ascii
    condition:
        $k1 and ($k2 or $g)
}

rule KETO_OpenCL_XOR_Decryptor_Kernel : loader
{
    meta:
        description = "OpenCL kernel that XORs a buffer with a modulo-indexed key (out[i] = in[i] ^ key[i % n]): the GPU decryption stage of CoffeeLoader/ArmouryLoader-style packers"
        reference = "Zscaler ThreatLabz CoffeeLoader (2025-03-26); Antiy CERT ArmouryLoader (2025-07-08)"
    strings:
        $k = "__kernel" ascii
        $id = "get_global_id" ascii
        $x = /\^\s*\w+\s*\[[^\]\n]{0,40}%[^\]\n]{0,40}\]/ ascii
    condition:
        $k and $id and $x
}

rule KETO_OpenCL_Host_Loader : loader
{
    meta:
        description = "Host code that builds and runs OpenCL programs from source together with a GPU-probing error path (anti-sandbox GPU gating seen in GPUGate/HijackLoader droppers); review in context - legitimate OpenCL applications also match the API set"
        reference = "Arctic Wolf GPUGate (2025-09-05); GMO Cybersecurity by Ierae (2026-01-22)"
    strings:
        $a1 = "clGetPlatformIDs" ascii
        $a2 = "clCreateProgramWithSource" ascii
        $a3 = "clBuildProgram" ascii
        $a4 = "clEnqueueNDRangeKernel" ascii
        $a5 = "clEnqueueReadBuffer" ascii
        $e1 = "No OpenCL platforms found" ascii wide nocase
        $e2 = "OpenCL.dll" ascii wide nocase
    condition:
        4 of ($a*) and any of ($e*)
}

rule KETO_SPIRV_Module : format
{
    meta:
        description = "SPIR-V module header (magic 0x07230203, version 1.x, schema 0) - Vulkan/OpenCL GPU code"
    strings:
        $h = { 03 02 23 07 00 ?? 01 00 [8] 00 00 00 00 }
    condition:
        $h
}

rule KETO_DXBC_Shader : format
{
    meta:
        description = "Direct3D shader container (DXBC, version 1) - informational; compute shaders in anonymous memory deserve review"
    strings:
        $h = { 44 58 42 43 [16] 01 00 00 00 }
    condition:
        $h
}
