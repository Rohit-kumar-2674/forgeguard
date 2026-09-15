from forgeguard.checks.actions import GitHubActionsCheck
from forgeguard.checks.dependencies import LockfileCheck
from forgeguard.checks.documentation import CommunityFilesCheck
from forgeguard.checks.secrets import SecretPatternsCheck

BUILTIN_CHECKS = (CommunityFilesCheck, GitHubActionsCheck, SecretPatternsCheck, LockfileCheck)

__all__ = ["BUILTIN_CHECKS"]

