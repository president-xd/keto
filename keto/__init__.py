"""Keto: a GPU memory forensics framework (NVIDIA), modelled on Volatility 3.

The package is pure standard-library Python so it runs anywhere an analyst has
Python 3.8+: offline analysis works on Windows, Linux and macOS; live triage and
acquisition talk to the NVIDIA driver through ``ctypes`` (NVML and the CUDA
driver API) and to Linux through ``/proc`` and ``/sys``.
"""

__version__ = "1.0.0"
__all__ = ["__version__"]
