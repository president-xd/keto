"""In-tree PEP 517 / PEP 660 build backend for Keto, standard library only.

``pip install .`` (and ``pip install -e .``) needs no setuptools and no network: the package is pure Python, so the
wheel is the ``keto`` tree (``.py``, ``.json`` profiles, ``.yar`` rules) plus ``*.dist-info`` metadata
(METADATA, WHEEL, entry_points.txt, RECORD) as specified by PEP 427 / core metadata 2.1.
"""

from __future__ import annotations

import base64
import hashlib
import os
import re
import tarfile
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
NAME = "keto"
DATA_EXT = (".py", ".json", ".yar")
TAG = "py3-none-any"


def _version() -> str:
    with open(os.path.join(ROOT, NAME, "__init__.py"), encoding="utf-8") as fh:
        return re.search(r'__version__\s*=\s*"([^"]+)"', fh.read()).group(1)


def _metadata() -> str:
    with open(os.path.join(ROOT, "README.md"), encoding="utf-8") as fh:
        readme = fh.read()
    lines = ["Metadata-Version: 2.1", "Name: %s" % NAME, "Version: %s" % _version(),
             "Summary: GPU memory forensics framework for NVIDIA GPUs, modelled on Volatility 3",
             "License: Proprietary - all rights reserved by the project owner",
             "Requires-Python: >=3.8", "Classifier: Programming Language :: Python :: 3",
             "Classifier: Topic :: Security", "Classifier: Topic :: System :: Recovery Tools",
             "Classifier: Environment :: Console", "Provides-Extra: yara",
             'Requires-Dist: yara-python>=4.3; extra == "yara"', "Description-Content-Type: text/markdown", ""]
    return "\n".join(lines) + "\n" + readme


def _package_files():
    base = os.path.join(ROOT, NAME)
    for dp, dns, fns in os.walk(base):
        dns[:] = sorted(d for d in dns if d != "__pycache__")
        for fn in sorted(fns):
            if fn.endswith(DATA_EXT):
                full = os.path.join(dp, fn)
                yield full, os.path.relpath(full, ROOT).replace(os.sep, "/")


def _record_line(arcname: str, data: bytes) -> str:
    digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
    return "%s,sha256=%s,%d" % (arcname, digest, len(data))


def _write_wheel(wheel_directory: str, files) -> str:
    version = _version()
    distinfo = "%s-%s.dist-info" % (NAME, version)
    path = os.path.join(wheel_directory, "%s-%s-%s.whl" % (NAME, version, TAG))
    record = []
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        def add(arcname, data):
            zi = zipfile.ZipInfo(arcname, date_time=(2026, 1, 1, 0, 0, 0))
            zi.compress_type = zipfile.ZIP_DEFLATED
            zi.external_attr = 0o644 << 16
            zf.writestr(zi, data)
            record.append(_record_line(arcname, data))

        for arcname, data in files:
            add(arcname, data)
        add(distinfo + "/METADATA", _metadata().encode("utf-8"))
        add(distinfo + "/WHEEL", ("Wheel-Version: 1.0\nGenerator: keto_build\nRoot-Is-Purelib: true\nTag: %s\n"
                                  % TAG).encode())
        add(distinfo + "/entry_points.txt", b"[console_scripts]\nketo = keto.cli:main\n")
        record.append(distinfo + "/RECORD,,")
        zf.writestr(distinfo + "/RECORD", "\n".join(record) + "\n")
    return os.path.basename(path)


# -- PEP 517 hooks -----------------------------------------------------------------------------------------------
def get_requires_for_build_wheel(config_settings=None):
    return []


def get_requires_for_build_sdist(config_settings=None):
    return []


def get_requires_for_build_editable(config_settings=None):
    return []


def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):
    files = []
    for full, arc in _package_files():
        with open(full, "rb") as fh:
            files.append((arc, fh.read()))
    return _write_wheel(wheel_directory, files)


def build_editable(wheel_directory, config_settings=None, metadata_directory=None):
    """PEP 660: a wheel holding only a .pth file that puts the source tree on sys.path."""
    return _write_wheel(wheel_directory, [("__editable__.%s.pth" % NAME, (ROOT + "\n").encode("utf-8"))])


def build_sdist(sdist_directory, config_settings=None):
    version = _version()
    stem = "%s-%s" % (NAME, version)
    path = os.path.join(sdist_directory, stem + ".tar.gz")
    with tarfile.open(path, "w:gz", format=tarfile.PAX_FORMAT) as tf:
        for rel in ("pyproject.toml", "README.md", "keto.py"):
            tf.add(os.path.join(ROOT, rel), arcname="%s/%s" % (stem, rel))
        for sub in ("tools", "tests", "docs"):
            for dp, dns, fns in os.walk(os.path.join(ROOT, sub)):
                dns[:] = [d for d in dns if d != "__pycache__"]
                for fn in fns:
                    full = os.path.join(dp, fn)
                    tf.add(full, arcname="%s/%s" % (stem, os.path.relpath(full, ROOT).replace(os.sep, "/")))
        for full, arc in _package_files():
            tf.add(full, arcname="%s/%s" % (stem, arc))
        pkg = "Metadata-Version: 2.1\nName: %s\nVersion: %s\n" % (NAME, version)
        import io
        info = tarfile.TarInfo("%s/PKG-INFO" % stem)
        info.size = len(pkg)
        tf.addfile(info, io.BytesIO(pkg.encode()))
    return os.path.basename(path)
