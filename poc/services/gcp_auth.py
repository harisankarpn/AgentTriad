"""
GCP Credentials Resolver for Cloud Run and Local VM Development.

On Cloud Run (`K_SERVICE` set), uses standard Application Default Credentials (ADC)
with `cloud-platform` scope. On local GCE dev VMs where the default compute
metadata server has restricted OAuth scopes, falls back to the active `gcloud`
service account (`core-sa@stack-cognizant.iam.gserviceaccount.com`).
"""

from __future__ import annotations

import os
import subprocess
from typing import Any, Optional

import google.auth
import google.oauth2.credentials


CLOUD_PLATFORM_SCOPES = ["https://www.googleapis.com/auth/cloud-platform"]


def get_gcp_credentials() -> Optional[Any]:
    """Returns credentials with `cloud-platform` scope for Vertex AI and Cloud Logging."""
    # If running on Cloud Run or explicit key file is set, use standard ADC first
    if os.getenv("K_SERVICE") or os.getenv("GOOGLE_APPLICATION_CREDENTIALS"):
        try:
            creds, _ = google.auth.default(scopes=CLOUD_PLATFORM_SCOPES)
            return creds
        except Exception:
            pass

    # Try active gcloud CLI account token (e.g., core-sa@stack-cognizant.iam.gserviceaccount.com)
    try:
        token = (
            subprocess.check_output(
                ["gcloud", "auth", "print-access-token"],
                stderr=subprocess.DEVNULL,
                timeout=5,
            )
            .decode("utf-8")
            .strip()
        )
        if token:
            return google.oauth2.credentials.Credentials(token=token)
    except Exception:
        pass

    try:
        creds, _ = google.auth.default(scopes=CLOUD_PLATFORM_SCOPES)
        return creds
    except Exception:
        return None
