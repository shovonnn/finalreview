class FinalReviewError(Exception):
    """Base exception for finalreview."""


class ConfigurationError(FinalReviewError):
    """Raised when configuration is invalid."""

class ProviderError(FinalReviewError):
    """Raised when a configured provider cannot complete the request."""


class ScanRuntimeError(FinalReviewError):
    """Raised when scanning fails for a non-provider reason."""