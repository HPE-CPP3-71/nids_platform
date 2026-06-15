"""
Platform-specific exceptions.
"""

from __future__ import annotations


class NIDSPlatformError(Exception):
    """
    Base exception for all platform errors.
    """


class RegistryError(NIDSPlatformError):
    """
    Raised when registry operations fail.
    """


class PluginValidationError(NIDSPlatformError):
    """
    Raised when plugin validation fails.
    """


class ConfigurationError(NIDSPlatformError):
    """
    Raised when configuration validation fails.
    """