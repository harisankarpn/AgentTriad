"""
GCP Credentials Resolver Shim (`poc/services/gcp_auth.py`).

Preserves 100% backward compatibility for existing callers (`from services.gcp_auth
import get_gcp_credentials`) while delegating to the cloud-agnostic `CloudAuthBroker`
in `poc/services/auth_broker.py`.
"""

from __future__ import annotations

from typing import Any, Optional

from services.auth_broker import (
    CLOUD_PLATFORM_SCOPES,
    AuthVerificationError,
    CloudAuthBroker,
    auth_broker,
)


def get_gcp_credentials() -> Optional[Any]:
    """Returns credentials with `cloud-platform` scope for Vertex AI and Cloud Logging."""
    return auth_broker.get_gcp_credentials()


__all__ = [
    "CLOUD_PLATFORM_SCOPES",
    "AuthVerificationError",
    "CloudAuthBroker",
    "auth_broker",
    "get_gcp_credentials",
]
