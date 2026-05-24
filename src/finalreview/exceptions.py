class FinalReviewError(Exception):
    """Base exception for finalreview."""


class ConfigurationError(FinalReviewError):
    """Raised when configuration is invalid."""
