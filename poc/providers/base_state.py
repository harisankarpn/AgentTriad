"""
Abstract State & Distributed Lock Port Interfaces (`poc/providers/base_state.py`).

Defines cloud-agnostic Ports (Abstract Base Classes) for:
  1. `SessionStoreAdapter`    — Durable multi-session chat history persistence
  2. `DistributedLockAdapter` — Concurrency `.tflock` leases & temporal hysteresis freezes

Concrete adapters reside under:
  - `poc/providers/gcp/`      (e.g., `GCPFirestoreSessionAdapter`)
  - `poc/providers/generic/`  (e.g., `PostgresSessionAdapter`, `RedisLockAdapter`, `InMemory*`, `LocalFile*`)
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional


class SessionStoreAdapter(ABC):
    """Port interface for persisting per-user multi-session chat records."""

    @property
    @abstractmethod
    def backend_name(self) -> str:
        """Human-readable backend identifier (e.g., 'Cloud Firestore', 'PostgreSQL', 'Redis', 'In-Memory')."""

    @abstractmethod
    def read_user_record(self, user_key: str) -> Optional[Dict[str, Any]]:
        """
        Reads the persisted user session record for `user_key`.

        Returns a dict containing:
          `user_email`, `user_name`, `active_session_id`, `updated_at`, `sessions`
        or `None` if no record exists or the backend is unreachable.
        """

    @abstractmethod
    def write_user_record(self, user_key: str, record: Dict[str, Any]) -> bool:
        """Persists the user session record for `user_key`. Returns True when committed."""

    @abstractmethod
    def delete_user_record(self, user_key: str) -> bool:
        """Deletes the persisted record for `user_key` if present. Returns True on success."""

    @abstractmethod
    def get_status(self) -> Dict[str, Any]:
        """Returns backend health and configuration metadata for `/api/state` and `/api/atlas/sessions`."""


class DistributedLockAdapter(ABC):
    """Port interface for distributed `.tflock` leases and temporal hysteresis freeze timers."""

    @property
    @abstractmethod
    def backend_name(self) -> str:
        """Human-readable lock backend identifier (e.g., 'Redis', 'Local File', 'In-Memory')."""

    @abstractmethod
    def acquire_or_renew_lock(
        self,
        lock_key: str,
        incident_id: str,
        holder: str = "Atlas • Lead Orchestrator",
        ttl_seconds: int = 600,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Acquires a new lease or renews an existing lease with TTL, returning the lock record."""

    @abstractmethod
    def release_lock(self, lock_key: str) -> Dict[str, Any]:
        """Releases an active lease by `lock_key` and returns release metadata."""

    @abstractmethod
    def get_lock(self, lock_key: str) -> Optional[Dict[str, Any]]:
        """Returns the active (non-expired) lock record for `lock_key`, or `None`."""

    @abstractmethod
    def list_active_locks(self) -> List[Dict[str, Any]]:
        """Returns all currently active (non-expired) lock records."""

    @abstractmethod
    def set_hysteresis_freeze(self, workload_key: str, duration_seconds: int = 2700) -> float:
        """Sets an anti-flapping temporal hysteresis freeze and returns its expiry UNIX timestamp."""

    @abstractmethod
    def get_hysteresis_freeze(self, workload_key: str) -> Optional[float]:
        """Returns the active freeze expiration UNIX timestamp for `workload_key`, or `None` if expired/unset."""

    @abstractmethod
    def list_hysteresis_freezes(self) -> Dict[str, float]:
        """Returns `{workload_key: expiry_epoch}` for all active (non-expired) freezes."""

    @abstractmethod
    def get_status(self) -> Dict[str, Any]:
        """Returns lock backend health and configuration metadata for `/api/harness/status`."""
