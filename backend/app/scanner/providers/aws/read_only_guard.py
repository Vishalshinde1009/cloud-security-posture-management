"""
Read-Only Guard for AWS Provider Integration.
Strictly ensures only non-mutating AWS API calls (list, describe, get, head) are invoked.
"""

import logging
from typing import Tuple

logger = logging.getLogger("cspm.aws.guard")

AWS_READ_ONLY: bool = True

ALLOWED_READ_ONLY_PREFIXES: Tuple[str, ...] = (
    "list_",
    "describe_",
    "get_",
    "head_",
)

FORBIDDEN_MUTATING_PREFIXES: Tuple[str, ...] = (
    "create_",
    "put_",
    "delete_",
    "update_",
    "modify_",
    "authorize_",
    "revoke_",
    "attach_",
    "detach_",
    "tag_",
    "untag_",
    "start_",
    "stop_",
    "reboot_",
    "terminate_",
    "add_",
    "remove_",
    "enable_",
    "disable_",
    "register_",
    "deregister_",
    "purchase_",
    "run_",
)


class AWSReadOnlyViolationError(PermissionError):
    """Raised when an attempt is made to execute a mutating or non-whitelisted AWS operation."""
    pass


def assert_read_only_operation(method_name: str) -> None:
    """
    Validates that the specified AWS SDK method name complies with strict read-only posture.
    Raises AWSReadOnlyViolationError if a mutating operation is attempted.
    """
    method_lower = method_name.lower()

    for forbidden in FORBIDDEN_MUTATING_PREFIXES:
        if method_lower.startswith(forbidden):
            err_msg = (
                f"SECURITY VIOLATION: Mutating AWS operation '{method_name}' is strictly forbidden. "
                f"CSPM operates in 100% read-only mode."
            )
            logger.critical(err_msg)
            raise AWSReadOnlyViolationError(err_msg)

    if not any(method_lower.startswith(prefix) for prefix in ALLOWED_READ_ONLY_PREFIXES):
        err_msg = (
            f"SECURITY VIOLATION: Operation '{method_name}' does not match allowed read-only prefixes "
            f"({', '.join(ALLOWED_READ_ONLY_PREFIXES)})."
        )
        logger.critical(err_msg)
        raise AWSReadOnlyViolationError(err_msg)
