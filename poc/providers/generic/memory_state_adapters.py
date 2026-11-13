"""
In-Memory and Local-File State & Lock Adapters (`poc/providers/generic/memory_state_adapters.py`).

Provides:
  - `InMemorySessionAdapter` — Zero-dependency in-memory `SessionStoreAdapter` (`AAAS_STATE_BACKEND=memory`)
  - `LocalFileLockAdapter`   — Existing in-memory + `/tmp/aaas_tf_locks/*.tflock.json` `DistributedLockAdapter`
  - `InMemoryLockAdapter`    — Pure in-memory `DistributedLockAdapter` (no disk I/O)
"""

from __future__ import annotations

import copy
import datetime
import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from providers.base_state import DistributedLockAdapter, SessionStoreAdapter


class InMemorySessionAdapter(SessionStoreAdapter):
    """Pure in-memory session store adapter (zero cloud or disk I/O)."""

    def __init__(self) -> None:
        self._store: Dict[str, Dict[str, Any]] = {}

    @property
    def backend_name(self) -> str:
        return "In-Memory"

    def read_user_record(self, user_key: str) -> Optional[Dict[str, Any]]:
        rec = self._store.get(user_key)
        return copy.deepcopy(rec) if rec is not None else None

    def write_user_record(self, user_key: str, record: Dict[str, Any]) -> bool:
        self._store[user_key] = copy.deepcopy(record)
        return True

    def delete_user_record(self, user_key: str) -> bool:
        self._store.pop(user_key, None)
        return True

    def get_status(self) -> Dict[str, Any]:
        return {
            "backend": self.backend_name,
            "state_backend_mode": "memory",
            "database": "memory://aaas_user_sessions",
            "collection": "aaas_user_sessions",
            "status": "MEMORY_ACTIVE",
            "users_cached": len(self._store),
        }


class LocalFileLockAdapter(DistributedLockAdapter):
    """
    Preserves existing local/in-memory `.tflock` lease & temporal hysteresis behavior
    (extracted from `poc/services/agent_harness.py`).
    """

    def __init__(
        self,
        lock_dir: Optional[Path] = None,
        state_bucket: Optional[str] = None,
        persist_to_disk: bool = True,
    ) -> None:
        self.persist_to_disk = persist_to_disk
        self.lock_dir = lock_dir or Path("/tmp/aaas_tf_locks")
        self.state_bucket = state_bucket or os.getenv("AAAS_TF_STATE_BUCKET", "agent-triad-tf-state")
        if self.persist_to_disk:
            self.lock_dir.mkdir(parents=True, exist_ok=True)
        self._locks: Dict[str, Dict[str, Any]] = {}
        self._lock_expiries: Dict[str, float] = {}
        self._hysteresis_freezes: Dict[str, float] = {}

    @property
    def backend_name(self) -> str:
        return "Local File (.tflock)" if self.persist_to_disk else "In-Memory"

    def _prune_expired(self) -> None:
        now = time.time()
        expired_locks = [k for k, exp in self._lock_expiries.items() if exp <= now]
        for k in expired_locks:
            self._lock_expiries.pop(k, None)
            self._locks.pop(k, None)
        expired_freezes = [w for w, exp in self._hysteresis_freezes.items() if exp <= now]
        for w in expired_freezes:
            self._hysteresis_freezes.pop(w, None)

    def acquire_or_renew_lock(
        self,
        lock_key: str,
        incident_id: str,
        holder: str = "Atlas • Lead Orchestrator",
        ttl_seconds: int = 600,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        self._prune_expired()
        now = time.time()
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        expires_epoch = now + ttl_seconds
        expires_iso = datetime.datetime.fromtimestamp(expires_epoch, tz=datetime.timezone.utc).isoformat()
        gcs_uri = f"gs://{self.state_bucket}/{lock_key}.tflock"
        lock_uri = gcs_uri if self.persist_to_disk else f"memory://tflock/{lock_key}"

        existing = self._locks.get(lock_key)
        action = "RENEWED_5M_LEASE" if existing else "ACQUIRED_10M_LEASE"

        lock_record: Dict[str, Any] = {
            "lock_id": f"tflock-{hashlib.sha1(lock_key.encode()).hexdigest()[:10]}",
            "lock_key": lock_key,
            "lock_uri": lock_uri,
            "gcs_uri": gcs_uri,
            "lock_backend": self.backend_name,
            "incident_id": incident_id,
            "holder": holder,
            "status": "RENEWED" if existing else "ACQUIRED",
            "action": action,
            "acquired_at": existing["acquired_at"] if existing else now_iso,
            "renewed_at": now_iso,
            "expires_at": expires_iso,
            "ttl_seconds": ttl_seconds,
        }
        if metadata:
            lock_record["metadata"] = dict(metadata)

        self._locks[lock_key] = lock_record
        self._lock_expiries[lock_key] = expires_epoch

        if self.persist_to_disk:
            try:
                lock_file = self.lock_dir / f"{lock_key}.tflock.json"
                lock_file.write_text(json.dumps(lock_record, indent=2), encoding="utf-8")
            except Exception:
                pass

        return dict(lock_record)

    def release_lock(self, lock_key: str) -> Dict[str, Any]:
        self._prune_expired()
        record = self._locks.pop(lock_key, None)
        self._lock_expiries.pop(lock_key, None)
        if self.persist_to_disk:
            try:
                lock_file = self.lock_dir / f"{lock_key}.tflock.json"
                if lock_file.exists():
                    lock_file.unlink()
            except Exception:
                pass

        gcs_uri = f"gs://{self.state_bucket}/{lock_key}.tflock"
        return {
            "lock_key": lock_key,
            "lock_uri": gcs_uri if self.persist_to_disk else f"memory://tflock/{lock_key}",
            "gcs_uri": gcs_uri,
            "lock_backend": self.backend_name,
            "status": "RELEASED",
            "released_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "previous_lock": record,
        }

    def get_lock(self, lock_key: str) -> Optional[Dict[str, Any]]:
        self._prune_expired()
        rec = self._locks.get(lock_key)
        return dict(rec) if rec is not None else None

    def list_active_locks(self) -> List[Dict[str, Any]]:
        self._prune_expired()
        return [dict(v) for v in self._locks.values()]

    def set_hysteresis_freeze(self, workload_key: str, duration_seconds: int = 2700) -> float:
        self._prune_expired()
        expiry = time.time() + duration_seconds
        self._hysteresis_freezes[workload_key] = expiry
        return expiry

    def get_hysteresis_freeze(self, workload_key: str) -> Optional[float]:
        self._prune_expired()
        return self._hysteresis_freezes.get(workload_key)

    def list_hysteresis_freezes(self) -> Dict[str, float]:
        self._prune_expired()
        return dict(self._hysteresis_freezes)

    def get_status(self) -> Dict[str, Any]:
        self._prune_expired()
        return {
            "backend": self.backend_name,
            "state_backend_mode": "local" if self.persist_to_disk else "memory",
            "status": "LOCAL_LOCK_ACTIVE" if self.persist_to_disk else "MEMORY_LOCK_ACTIVE",
            "lock_dir": str(self.lock_dir) if self.persist_to_disk else None,
            "active_locks_count": len(self._locks),
            "active_hysteresis_freezes_count": len(self._hysteresis_freezes),
        }


class InMemoryLockAdapter(LocalFileLockAdapter):
    """Pure in-memory distributed lock & hysteresis adapter (`AAAS_STATE_BACKEND=memory`)."""

    def __init__(self, state_bucket: Optional[str] = None) -> None:
        super().__init__(state_bucket=state_bucket, persist_to_disk=False)
