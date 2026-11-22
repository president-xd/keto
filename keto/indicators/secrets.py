"""Credential / secret patterns worth finding in GPU memory (staging buffers,
inference inputs, leaked host pages). Output is redacted by default.

Each pattern carries literal anchors so scanning stays fast on multi-gigabyte
images (see ``framework.scanners.AnchoredScanner``)."""

from __future__ import annotations

import re
from typing import Iterator, Tuple

from keto.framework.scanners import AnchoredScanner

# (name, anchors (lower-case; matched case-insensitively), regex, bytes to look back from the anchor)
PATTERNS = [
    ("pem-private-key", [b"-----begin "],
     re.compile(rb"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----"
                rb"[\s\S]{16,8192}?-----END [A-Z ]*PRIVATE KEY(?: BLOCK)?-----"), 0),
    ("aws-access-key-id", [b"akia", b"asia", b"agpa", b"aida", b"aroa", b"anpa"],
     re.compile(rb"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[0-9A-Z]{16}\b"), 0),
    ("aws-secret-key", [b"aws_secret_access_key"],
     re.compile(rb"(?i)aws_secret_access_key\s*[=:]\s*[A-Za-z0-9/+=]{40}"), 0),
    ("github-token", [b"ghp_", b"gho_", b"ghu_", b"ghs_", b"ghr_"], re.compile(rb"\bgh[pousr]_[A-Za-z0-9]{36,255}\b"), 0),
    ("slack-token", [b"xox"], re.compile(rb"\bxox[abposr]-[A-Za-z0-9-]{10,72}\b"), 0),
    ("google-api-key", [b"aiza"], re.compile(rb"\bAIza[0-9A-Za-z_\-]{35}\b"), 0),
    ("jwt", [b"eyj"], re.compile(rb"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"), 0),
    ("bearer-token", [b"bearer "], re.compile(rb"(?i)authorization:\s*bearer\s+[A-Za-z0-9._~+/=-]{16,}"), 40),
    ("unix-crypt-hash", [b"$1$", b"$2a$", b"$2b$", b"$2y$", b"$5$", b"$6$", b"$y$", b"$gy$", b"$7$"],
     re.compile(rb"\$(?:1|2[abxy]|5|6|y|gy|7)\$[./A-Za-z0-9$]{8,}[./A-Za-z0-9]{16,}"), 0),
    ("ntlm-pwdump", [b":::"], re.compile(rb"[\w.$-]{1,64}:\d{1,10}:[0-9a-fA-F]{32}:[0-9a-fA-F]{32}:::"), 160),
    ("openai-style-key", [b"sk-"], re.compile(rb"\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}\b"), 0),
    # snake_case keys too (db_password, client_secret); the value must be printable ASCII without quotes, so
    # random bytes after "pwd:" in noise do not qualify
    ("password-assignment", [b"password", b"passwd", b"pwd=", b"pwd:", b"secret=", b"secret:", b"secret ",
                             b"password ", b"pwd "],
     re.compile(rb"(?i)(?<![a-z0-9])(?:[a-z0-9]+_)*(?:password|passwd|pwd|secret)(?:_[a-z0-9]+)*\s*[=:]\s*['\"]?"
                rb"[\x21\x23-\x26\x28-\x7e]{6,64}"), 48),
]
MAX_LEN = 8192 + 256


def _not_working_directory(text: bytes) -> bool:
    """``PWD=/home/user`` is the shell's current-directory variable, not a password (ODBC ``PWD=secret`` is)."""
    return not re.match(rb"(?i)pwd\s*=\s*['\"]?(?:/|~|[a-z]:[\\/]|\\\\)", text)


VALIDATORS = {"password-assignment": _not_working_directory}


class ValidatedScanner(AnchoredScanner):
    """An AnchoredScanner whose matches must also pass ``validator(match bytes)`` (module-level, so the scanner
    stays picklable for the multi-process path)."""

    def __init__(self, anchors, regex, validator, **kw):
        super().__init__(anchors, regex, **kw)
        self.validator = validator

    def __call__(self, data, data_offset):
        for off, m in super().__call__(data, data_offset):
            if self.validator(m.group()):
                yield off, m

    def scan_region(self, buf, start, end, base):
        for off, m in super().scan_region(buf, start, end, base):
            if self.validator(m.group()):
                yield off, m


def redact(text: str, keep: int = 4) -> str:
    if len(text) <= keep * 2:
        return "*" * len(text)
    return text[:keep] + "*" * min(len(text) - 2 * keep, 24) + text[-keep:]


def scanners():
    out = []
    for name, anchors, rx, back in PATTERNS:
        kw = dict(before=back, after=MAX_LEN if name == "pem-private-key" else 600, ignore_case=True)
        if name in VALIDATORS:
            out.append((name, ValidatedScanner(anchors, rx, VALIDATORS[name], **kw)))
        else:
            out.append((name, AnchoredScanner(anchors, rx, **kw)))
    return out


def find(data: bytes, base: int = 0) -> Iterator[Tuple[int, str, str]]:
    for name, sc in scanners():
        for off, m in sc(data, base):
            yield off, name, m.group().decode("utf-8", "replace")
