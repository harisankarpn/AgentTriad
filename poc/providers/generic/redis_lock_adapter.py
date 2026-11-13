"""
Cloud-Agnostic Redis Lock & Session Adapters (`RedisLockAdapter` / `RedisLockStore` & `RedisSessionAdapter`).

Implements distributed `.tflock` leases (with atomic Redis `EX` TTL) and 45-minute
temporal hysteresis anti-flapping freezes across multi-replica deployments on any cloud
(AWS ElastiCache, Azure Cache for Redis, GCP Memorystore, or self-hosted Redis/Valkey).

Uses lazy optional `redis` import (or an injected Redis-compatible client for testing) and
degrades cleanly to an in-memory TTL fallback if Redis is not installed or unreachable.
"""

from __future__ import annotations

import copy
import datetime
import hashlib
import json
import os
import time
from typing import Any, Dict, List, Optional

from providers.base_state import DistributedLockAdapter, SessionStoreAdapter


def _connect_redis_client(redis_url: str) -> Optional[Any]:
    if not redis_url:
        return None
    try:
        import redis  # type: ignore[import-not-found]

        client = redis.Redis.from_url(
            redis_url,
            decode_responses=True,
            socket_connect_timeout=2.5,
            socket_timeout=2.5,
        )
        client.ping()
        return client
    except Exception:
        return None


class RedisLockAdapter(DistributedLockAdapter):
    """Cloud-agnostic Redis implementation of `DistributedLockAdapter`."""

    def __init__(
        self,
        redis_url: Optional[str] = None,
        key_prefix: Optional[str] = None,
        redis_client: Optional[Any] = None,
        state_bucket: Optional[str] = None,
    ) -> None:
        self.redis_url = (redis_url or os.getenv("AAAS_REDIS_URL") or os.getenv("REDIS_URL") or "").strip()
        self.key_prefix = (key_prefix or os.getenv("AAAS_REDIS_PREFIX") or "aaas:").strip()
        self.state_bucket = state_bucket or os.getenv("AAAS_TF_STATE_BUCKET", "agent-triad-tf-state")
        self._client: Optional[Any] = redis_client
        self._client_checked: bool = redis_client is not None
        self._fallback_locks: Dict[str, Dict[str, Any]] = {}
        self._fallback_lock_expiries: Dict[str, float] = {}
        self._fallback_freezes: Dict[str, float] = {}
        if redis_client is not None:
            self._status = "REDIS_CONNECTED"
        elif self.redis_url:
            self._status = "REDIS_READY"
        else:
            self._status = "REDIS_URL_NOT_CONFIGURED_FALLBACK"

    @property
    def backend_name(self) -> str:
        return "Redis"

    def _get_client(self) -> Optional[Any]:
        if self._client is not None:
            return self._client
        if not self._client_checked:
            self._client_checked = True
            self._client = _connect_redis_client(self.redis_url)
            if self._client is not None:
                self._status = "REDIS_CONNECTED"
            elif self.redis_url:
                self._status = "REDIS_FALLBACK_MEMORY"
        return self._client

    def _lock_redis_key(self, lock_key: str) -> str:
        return f"{self.key_prefix}tflock:{lock_key}"

    def _freeze_redis_key(self, workload_key: str) -> str:
        return f"{self.key_prefix}hysteresis:{workload_key}"

    def _prune_fallback(self) -> None:
        now = time.time()
        for k in [k for k, exp in self._fallback_lock_expiries.items() if exp <= now]:
            self._fallback_lock_expiries.pop(k, None)
            self._fallback_locks.pop(k, None)
        for w in [w for w, exp in self._fallback_freezes.items() if exp <= now]:
            self._fallback_freezes.pop(w, None)

    def acquire_or_renew_lock(
        self,
        lock_key: str,
        incident_id: str,
        holder: str = "Atlas • Lead Orchestrator",
        ttl_seconds: int = 600,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        self._prune_fallback()
        rkey = self._lock_redis_key(lock_key)
        now = time.time()
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        expires_epoch = now + ttl_seconds
        expires_iso = datetime.datetime.fromtimestamp(expires_epoch, tz=datetime.timezone.utc).isoformat()

        existing = self.get_lock(lock_key)
        action = "RENEWED_5M_LEASE" if existing else "ACQUIRED_10M_LEASE"
        lock_uri = f"redis://{rkey}"

        lock_record: Dict[str, Any] = {
            "lock_id": f"tflock-{hashlib.sha1(lock_key.encode()).hexdigest()[:10]}",
            "lock_key": lock_key,
            "lock_uri": lock_uri,
            # Preserve `gcs_uri` key for 100% backward compatibility with `gke_remediator.py`
            "gcs_uri": lock_uri,
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

        client = self._get_client()
        if client is not None:
            try:
                client.set(rkey, json.dumps(lock_record, ensure_ascii=False), ex=ttl_seconds)
                self._status = "REDIS_CONNECTED"
            except Exception:
                self._status = "REDIS_FALLBACK_MEMORY"

        self._fallback_locks[lock_key] = lock_record
        self._fallback_lock_expiries[lock_key] = expires_epoch
        return dict(lock_record)

    def release_lock(self, lock_key: str) -> Dict[str, Any]:
        self._prune_fallback()
        rkey = self._lock_redis_key(lock_key)
        prev = self.get_lock(lock_key)

        client = self._get_client()
        if client is not None:
            try:
                client.delete(rkey)
                self._status = "REDIS_CONNECTED"
            except Exception:
                self._status = "REDIS_FALLBACK_MEMORY"

        self._fallback_locks.pop(lock_key, None)
        self._fallback_lock_expiries.pop(lock_key, None)
        lock_uri = f"redis://{rkey}"
        return {
            "lock_key": lock_key,
            "lock_uri": lock_uri,
            "gcs_uri": lock_uri,
            "lock_backend": self.backend_name,
            "status": "RELEASED",
            "released_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "previous_lock": prev,
        }

    def get_lock(self, lock_key: str) -> Optional[Dict[str, Any]]:
        self._prune_fallback()
        rkey = self._lock_redis_key(lock_key)
        client = self._get_client()
        if client is not None:
            try:
                raw = client.get(rkey)
                self._status = "REDIS_CONNECTED"
                if raw is None:
                    self._fallback_locks.pop(lock_key, None)
                    return None
                if isinstance(raw, bytes):
                    raw = raw.decode("utf-8")
                parsed = json.loads(raw)
                return parsed if isinstance(parsed, dict) else None
            except Exception:
                self._status = "REDIS_FALLBACK_MEMORY"

        rec = self._fallback_locks.get(lock_key)
        return dict(rec) if rec is not None else None

    def list_active_locks(self) -> List[Dict[str, Any]]:
        self._prune_fallback()
        client = self._get_client()
        if client is not None:
            try:
                pattern = f"{self.key_prefix}tflock:*"
                keys = list(client.scan_iter(match=pattern)) if hasattr(client, "scan_iter") else list(client.keys(pattern))
                locks: List[Dict[str, Any]] = []
                for k in keys:
                    raw = client.get(k)
                    if not raw:
                        continue
                    if isinstance(raw, bytes):
                        raw = raw.decode("utf-8")
                    parsed = json.loads(raw)
                    if isinstance(parsed, dict):
                        locks.append(parsed)
                self._status = "REDIS_CONNECTED"
                return locks
            except Exception:
                self._status = "REDIS_FALLBACK_MEMORY"

        return [dict(v) for v in self._fallback_locks.values()]

    def set_hysteresis_freeze(self, workload_key: str, duration_seconds: int = 2700) -> float:
        self._prune_fallback()
        expiry = time.time() + duration_seconds
        fkey = self._freeze_redis_key(workload_key)
        client = self._get_client()
        if client is not None:
            try:
                client.set(fkey, str(expiry), ex=duration_seconds)
                self._status = "REDIS_CONNECTED"
            except Exception:
                self._status = "REDIS_FALLBACK_MEMORY"
        self._fallback_freezes[workload_key] = expiry
        return expiry

    def get_hysteresis_freeze(self, workload_key: str) -> Optional[float]:
        self._prune_fallback()
        fkey = self._freeze_redis_key(workload_key)
        client = self._get_client()
        if client is not None:
            try:
                raw = client.get(fkey)
                self._status = "REDIS_CONNECTED"
                if raw is None:
                    self._fallback_freezes.pop(workload_key, None)
                    return None
                val = float(raw.decode("utf-8") if isinstance(raw, bytes) else raw)
                return val if val > time.time() else None
            except Exception:
                self._status = "REDIS_FALLBACK_MEMORY"
        return self._fallback_freezes.get(workload_key)

    def list_hysteresis_freezes(self) -> Dict[str, float]:
        self._prune_fallback()
        now = time.time()
        client = self._get_client()
        if client is not None:
            try:
                prefix = f"{self.key_prefix}hysteresis:"
                pattern = f"{prefix}*"
                keys = list(client.scan_iter(match=pattern)) if hasattr(client, "scan_iter") else list(client.keys(pattern))
                freezes: Dict[str, float] = {}
                for k in keys:
                    k_str = k.decode("utf-8") if isinstance(k, bytes) else str(k)
                    raw = client.get(k)
                    if not raw:
                        continue
                    exp = float(raw.decode("utf-8") if isinstance(raw, bytes) else raw)
                    if exp > now:
                        freezes[k_str[len(prefix):]] = exp
                self._status = "REDIS_CONNECTED"
                return freezes
            except Exception:
                self._status = "REDIS_FALLBACK_MEMORY"
        return dict(self._fallback_freezes)

    def get_status(self) -> Dict[str, Any]:
        return {
            "backend": self.backend_name,
            "state_backend_mode": "redis",
            "status": self._status,
            "key_prefix": self.key_prefix,
            "active_locks_count": len(self.list_active_locks()),
            "active_hysteresis_freezes_count": len(self.list_hysteresis_freezes()),
        }


class RedisSessionAdapter(SessionStoreAdapter):
    """Cloud-agnostic Redis KV session store adapter for `AAAS_STATE_BACKEND=redis`."""

    def __init__(
        self,
        redis_url: Optional[str] = None,
        key_prefix: Optional[str] = None,
        redis_client: Optional[Any] = None,
        ttl_seconds: int = 86400 * 30,
    ) -> None:
        self.redis_url = (redis_url or os.getenv("AAAS_REDIS_URL") or os.getenv("REDIS_URL") or "").strip()
        self.key_prefix = (key_prefix or os.getenv("AAAS_REDIS_PREFIX") or "aaas:").strip()
        self.ttl_seconds = ttl_seconds
        self._client: Optional[Any] = redis_client
        self._client_checked: bool = redis_client is not None
        self._fallback_memory: Dict[str, Dict[str, Any]] = {}
        if redis_client is not None:
            self._status = "REDIS_CONNECTED"
        elif self.redis_url:
            self._status = "REDIS_READY"
        else:
            self._status = "REDIS_URL_NOT_CONFIGURED_FALLBACK"

    @property
    def backend_name(self) -> str:
        return "Redis"

    def _get_client(self) -> Optional[Any]:
        if self._client is not None:
            return self._client
        if not self._client_checked:
            self._client_checked = True
            self._client = _connect_redis_client(self.redis_url)
            if self._client is not None:
                self._status = "REDIS_CONNECTED"
            elif self.redis_url:
                self._status = "REDIS_FALLBACK_MEMORY"
        return self._client

    def _session_key(self, user_key: str) -> str:
        return f"{self.key_prefix}sessions:{user_key}"

    def read_user_record(self, user_key: str) -> Optional[Dict[str, Any]]:
        client = self._get_client()
        if client is not None:
            try:
                raw = client.get(self._session_key(user_key))
                self._status = "REDIS_CONNECTED"
                if not raw:
                    return None
                if isinstance(raw, bytes):
                    raw = raw.decode("utf-8")
                parsed = json.loads(raw)
                if isinstance(parsed, dict):
                    self._fallback_memory[user_key] = copy.deepcopy(parsed)
                    return parsed
                return None
            except Exception:
                self._status = "REDIS_FALLBACK_MEMORY"
        rec = self._fallback_memory.get(user_key)
        return copy.deepcopy(rec) if rec is not None else None

    def write_user_record(self, user_key: str, record: Dict[str, Any]) -> bool:
        self._fallback_memory[user_key] = copy.deepcopy(record)
        client = self._get_client()
        if client is None:
            return False
        try:
            client.set(self._session_key(user_key), json.dumps(record, ensure_ascii=False), ex=self.ttl_seconds)
            self._status = "REDIS_CONNECTED"
            return True
        except Exception:
            self._status = "REDIS_FALLBACK_MEMORY"
            return False

    def delete_user_record(self, user_key: str) -> bool:
        self._fallback_memory.pop(user_key, None)
        client = self._get_client()
        if client is None:
            return False
        try:
            client.delete(self._session_key(user_key))
            self._status = "REDIS_CONNECTED"
            return True
        except Exception:
            self._status = "REDIS_FALLBACK_MEMORY"
            return False

    def get_status(self) -> Dict[str, Any]:
        return {
            "backend": self.backend_name,
            "state_backend_mode": "redis",
            "database": f"redis://{self.key_prefix}sessions",
            "collection": f"{self.key_prefix}sessions",
            "status": self._status,
        }


# Alias matching AGENTS.md target architecture naming
RedisLockStore = RedisLockAdapter
