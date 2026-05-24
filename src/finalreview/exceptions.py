class FinalReviewError(Exception):
    """Base exception for finalreview."""


class ConfigurationError(FinalReviewError):
    """Raised when configuration is invalid."""


class ScanRuntimeError(FinalReviewError):
    """Raised when scanning fails for a non-provider reason."""