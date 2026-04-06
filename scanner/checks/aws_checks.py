"""Backward-compatible import path for AWS checks.

New code should import from `scanner.checks.aws`.
"""

from scanner.checks.aws import (
    IAMRoleTrustPolicyCheck,
    IAMRoleWildcardPolicyCheck,
    IAMUserMfaCheck,
    IAMWildcardPolicyCheck,
    S3EncryptionCheck,
    S3PublicExposureCheck,
    SecurityGroupExposureCheck,
)

__all__ = [
    "S3PublicExposureCheck",
    "S3EncryptionCheck",
    "IAMUserMfaCheck",
    "IAMWildcardPolicyCheck",
    "IAMRoleTrustPolicyCheck",
    "IAMRoleWildcardPolicyCheck",
    "SecurityGroupExposureCheck",
]
