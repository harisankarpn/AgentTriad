"""
Cloud Strategy Factory (`poc/providers/cloud_factory.py`).

Resolves the concrete `DatabaseCloudAdapter` or `ComputeCloudAdapter` strategy based on
`target_cloud` (`gcp` | `aws` | `azure`, defaulting to `CLOUD_PROVIDER` or `"gcp"`).
"""

from __future__ import annotations

import os
from typing import Optional

from providers.aws.cloud_adapters import AWSComputeCloudAdapter, AWSDatabaseCloudAdapter
from providers.azure.cloud_adapters import AzureComputeCloudAdapter, AzureDatabaseCloudAdapter
from providers.base_cloud import ComputeCloudAdapter, DatabaseCloudAdapter
from providers.gcp.cloud_adapters import GCPComputeCloudAdapter, GCPDatabaseCloudAdapter


def normalize_target_cloud(target_cloud: Optional[str] = None) -> str:
    raw = (target_cloud or os.getenv("CLOUD_PROVIDER") or "gcp").strip().lower()
    if raw in ("gcp", "google", "google_cloud"):
        return "gcp"
    if raw in ("aws", "amazon"):
        return "aws"
    if raw in ("azure", "microsoft", "azurerm"):
        return "azure"
    raise ValueError(
        f"Unsupported target_cloud={target_cloud!r}. Expected one of: gcp, aws, azure."
    )


def get_database_cloud_adapter(target_cloud: Optional[str] = None) -> DatabaseCloudAdapter:
    cloud = normalize_target_cloud(target_cloud)
    if cloud == "aws":
        return AWSDatabaseCloudAdapter()
    if cloud == "azure":
        return AzureDatabaseCloudAdapter()
    return GCPDatabaseCloudAdapter()


def get_compute_cloud_adapter(target_cloud: Optional[str] = None) -> ComputeCloudAdapter:
    cloud = normalize_target_cloud(target_cloud)
    if cloud == "aws":
        return AWSComputeCloudAdapter()
    if cloud == "azure":
        return AzureComputeCloudAdapter()
    return GCPComputeCloudAdapter()
