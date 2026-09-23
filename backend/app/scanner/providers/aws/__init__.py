"""
AWS Cloud Provider Package with strict read-only guarantees.
"""

from app.scanner.providers.aws.provider import AWSProvider
from app.scanner.providers.aws.client_factory import AWSClientFactory
from app.scanner.providers.aws.read_only_guard import (
    AWS_READ_ONLY,
    assert_read_only_operation,
    AWSReadOnlyViolationError,
)

__all__ = [
    "AWSProvider",
    "AWSClientFactory",
    "AWS_READ_ONLY",
    "assert_read_only_operation",
    "AWSReadOnlyViolationError",
]
