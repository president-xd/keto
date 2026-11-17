"""Exception hierarchy shared by every part of Keto."""


class KetoError(Exception):
    """Base class for all framework errors."""


class InvalidAddressException(KetoError):
    """An address could not be read from a layer."""

    def __init__(self, layer_name, address, message=None):
        self.layer_name = layer_name
        self.address = address
        super().__init__(message or "Address 0x%x is not valid in layer %s" % (address, layer_name))


class PagedInvalidAddressException(InvalidAddressException):
    """A GPU virtual address did not translate (no valid PDE/PTE on the walk)."""

    def __init__(self, layer_name, address, level, entry=None, message=None):
        self.level = level
        self.entry = entry
        msg = message or "GPU VA 0x%x does not translate in %s (stopped at %s, entry=%s)" % (
            address, layer_name, level, "0x%x" % entry if entry is not None else "n/a")
        super().__init__(layer_name, address, msg)


class UnsupportedError(KetoError):
    """The requested feature is not available for this image, profile or platform."""


class RequirementError(KetoError):
    """A plugin requirement (image, live system, option) is not satisfied."""


class LiveSourceError(KetoError):
    """Live-system access failed (missing driver, permission, platform)."""


class FormatError(KetoError):
    """A file or in-memory structure does not match the expected format."""
