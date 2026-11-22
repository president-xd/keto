"""Cryptocurrency-mining and password-cracking indicators for GPU workloads."""

from __future__ import annotations

import re
from typing import List, Tuple

#: hashing algorithms whose kernel names appear in GPU miners' cubins/PTX
ALGORITHMS = ["ethash", "etchash", "kawpow", "progpow", "firopow", "autolykos", "octopus", "kheavyhash",
              "heavyhash", "karlsenhash", "pyrinhash", "nexapow", "zelhash", "beamhash", "equihash", "cuckoo",
              "cuckatoo", "cuckaroo", "cryptonight", "randomx", "argon2", "blake3", "blake2b", "sha256d",
              "scrypt", "x16r", "x16rv2", "lyra2", "verthash", "dynexsolve", "xelishash", "fishhash", "sha3x",
              "kangaroo12", "ironfish", "alephium", "abelian", "meowpow", "evrprogpow"]
#: miner software names (process names, banners, user agents)
MINER_SOFTWARE = ["xmrig", "t-rex", "trex", "lolminer", "nbminer", "gminer", "phoenixminer", "teamredminer",
                  "ethminer", "nanominer", "bzminer", "rigel", "srbminer", "ccminer", "cpuminer", "onezerominer",
                  "wildrig", "excavator", "nicehash", "hiveos", "minerstat", "miniz", "kawpowminer", "xmr-stak"]
POOL_MARKERS = ["stratum+tcp://", "stratum+ssl://", "stratum2+tcp://", "stratum1+tcp://", "mining.subscribe",
                "mining.authorize", "mining.notify", "eth_submitWork", "eth_getWork", "2miners.com", "f2pool",
                "ethermine", "nanopool", "herominers", "unmineable", "moneroocean", "supportxmr", "hashvault",
                "miningpoolhub", "flypool", "woolypooly", "kryptex", "zergpool", "prohashing", "mining-dutch"]
#: password-cracker kernel naming schemes
CRACKER_PATTERNS = [(re.compile(r"\bm\d{5}_(?:m|s)(?:04|08|16)\b"), "hashcat kernel"),
                    (re.compile(r"\bm\d{5}_(?:init|loop|comp|hook\d+|aux\d)\b"), "hashcat kernel"),
                    (re.compile(r"\bamp_a[0135]\b"), "hashcat amplifier"),
                    (re.compile(r"\bhashcat\b", re.I), "hashcat string"),
                    (re.compile(r"\bjohn the ripper\b", re.I), "John the Ripper string")]
GPU_MALWARE_POC = ["jellyfish", "win_jelly", "demon keylogger"]
#: hash primitives used by miners AND by ordinary software (password hashing, file hashing, sandboxes, CI tools):
#: on their own they are not mining evidence outside GPU kernel names, and even there only a weak hint
GENERIC_ALGORITHMS = {"argon2", "scrypt", "blake2b", "blake3", "sha256d", "kangaroo12", "cuckoo", "octopus",
                      "lyra2", "equihash", "sha3x"}
#: miner names that are also ordinary words or libraries (miniz is a zlib library, excavator a word...): they count
#: only as the executable itself (a command-line token / path basename), not anywhere in a string
AMBIGUOUS_SOFTWARE = {"miniz", "rigel", "excavator", "trex", "hiveos", "nicehash", "minerstat"}
#: coin names among ALGORITHMS: mining evidence in GPU kernel names, not in wallets, web pages or command lines
COIN_NAMES = {"alephium", "ironfish", "abelian"}
#: algorithm ids in xmrig/SRBMiner syntax ("--algo rx/0")
ALGO_IDS = ["rx/0", "rx/wow", "rx/arq", "rx/graft", "rx/sfx", "rx/keva", "rx/yada", "cn/r", "cn/0", "cn/1", "cn/2",
            "cn/half", "cn/fast", "cn/rto", "cn/rwz", "cn/zls", "cn/double", "cn/ccx", "cn-lite/1", "cn-heavy/0",
            "cn-heavy/xhv", "cn-pico", "argon2/chukwa", "argon2/chukwav2", "argon2/ninja", "ghostrider", "astrobwt"]
CONTEXTS = ("any", "kernel", "process", "string")

def strong_anchors() -> List[bytes]:
    """Few, distinctive literals: cheap enough to sweep a multi-GB image."""
    return [s.encode() for s in ("stratum+tcp://", "stratum+ssl://", "stratum2+tcp://", "mining.subscribe",
                                 "mining.authorize", "eth_submitwork", "xmrig", "t-rex", "lolminer", "nbminer",
                                 "phoenixminer", "teamredminer", "ethminer", "nanominer", "bzminer", "srbminer",
                                 "nicehash", "hashcat")]


def all_anchors() -> List[bytes]:
    return sorted({w.lower().encode() for w in ALGORITHMS + MINER_SOFTWARE + POOL_MARKERS + GPU_MALWARE_POC})


_ALG_RE = re.compile(r"(?i)(?<![a-z0-9])(%s)(?:_|\b|[A-Z0-9])" % "|".join(sorted(map(re.escape, ALGORITHMS),
                                                                                key=len, reverse=True)))
_SOFT_RE = re.compile(r"(?i)\b(%s)\b" % "|".join(map(re.escape, MINER_SOFTWARE)))
_POOL_RE = re.compile(r"(?i)(%s)" % "|".join(map(re.escape, POOL_MARKERS)))
BYTES_RE = re.compile(("(?i)(%s)" % "|".join(map(re.escape, ALGORITHMS + MINER_SOFTWARE + POOL_MARKERS +
                                                GPU_MALWARE_POC))).encode())


_ALGO_ARG_RE = re.compile(r"(?i)(?:--algo(?:rithm)?|--coin|(?<!\w)-a)(?:\s+|=)['\"]?([\w./-]+)")
_ALGO_ID_RE = re.compile(r"(?i)(?<![\w/])(%s)(?![\w/])" % "|".join(map(re.escape, sorted(ALGO_IDS, key=len,
                                                                                         reverse=True))))
# the executable itself: the first command token, or the basename of a path
_EXE_TOKEN_RE = re.compile(r"(?i)(?:^[\"']?|[\\/])(%s)(?:\.exe)?(?=$|[\s\"'])" % "|".join(map(re.escape,
                                                                                            AMBIGUOUS_SOFTWARE)))


def classify(text: str, context: str = "any") -> List[Tuple[str, str]]:
    """Return ``[(category, indicator)]`` for a kernel name, command line or string.

    ``context`` says what ``text`` is, so ordinary words are not taken for mining evidence:

    * ``"kernel"``: a GPU kernel / PTX entry name. Distinctive mining algorithms are ``miner-algorithm``; generic
      hash primitives (argon2, blake3, scrypt...) are only ``hash-primitive`` (a weak hint).
    * ``"process"``: a process name, path, command line, environment or mapped file. Generic primitives count
      only as an explicit ``--algo``/``-a`` argument; ambiguous names (miniz, rigel...) only as the executable.
    * ``"string"``: text carved from memory: pool markers, distinctive miner names and algorithms only.
    * ``"any"`` (default): every indicator, as names and substrings."""
    if context not in CONTEXTS:
        raise ValueError("unknown context %r" % context)
    out = []
    for m in _ALG_RE.finditer(text):
        alg = m.group(1).lower()
        if alg in GENERIC_ALGORITHMS and context != "any":
            if context == "kernel":
                out.append(("hash-primitive", alg))
            continue
        if alg in COIN_NAMES and context in ("process", "string"):
            continue
        out.append(("miner-algorithm", alg))
    if context in ("any", "process", "string"):
        for m in _ALGO_ID_RE.finditer(text):
            out.append(("miner-algorithm", m.group(1).lower()))
    if context == "process":  # an explicit algorithm argument is mining evidence even for generic/coin names
        known = set(ALGORITHMS)
        for m in _ALGO_ARG_RE.finditer(text):
            alg = m.group(1).lower()
            if alg.split("/")[0] in known:
                out.append(("miner-algorithm", alg))
    for m in _SOFT_RE.finditer(text):
        name = m.group(1).lower()
        if name in AMBIGUOUS_SOFTWARE and context != "any":
            continue
        out.append(("miner-software", name))
    if context == "process":
        for m in _EXE_TOKEN_RE.finditer(text):
            out.append(("miner-software", m.group(1).lower()))
    for m in _POOL_RE.finditer(text):
        out.append(("mining-pool", m.group(1).lower()))
    for rx, label in CRACKER_PATTERNS:
        for m in rx.finditer(text):
            out.append(("password-cracker", "%s (%s)" % (m.group(0), label)))
    low = text.lower()
    for poc in GPU_MALWARE_POC:
        if poc in low:
            out.append(("gpu-malware-poc", poc))
    return sorted(set(out))
