"""Importing this package registers every check. The engine sorts them into ASD order."""

from e8checker.checks import (  # noqa: F401  (imported for their registration side effects)
    admin,
    app_control,
    hardening,
    office_macros,
    organisational,
    patching,
    supporting,
)
from e8checker.checks.base import REGISTRY, CheckSpec

__all__ = ["REGISTRY", "CheckSpec"]
