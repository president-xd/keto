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


def classify(text: str) -> List[Tuple[str, str]]:
    """Return ``[(category, indicator)]`` for a kernel name, command line or string."""
    out = []
    for m in _ALG_RE.finditer(text):
        out.append(("miner-algorithm", m.group(1).lower()))
    for m in _SOFT_RE.finditer(text):
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
