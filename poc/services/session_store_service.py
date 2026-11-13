"""
Pluggable Multi-Backend Session Store Service for the AaaS Command Center.

Controlled by `AAAS_STATE_BACKEND=firestore|postgres|redis|memory` (default: `firestore`):
  - `firestore`: `GCPFirestoreSessionAdapter` (`projects/{project}/databases/(default)/documents/aaas_user_sessions`)
                 with in-memory + local `/tmp` JSON fallback cache (100% backward-compatible default)
  - `postgres`:  `PostgresSessionAdapter` (cloud-agnostic PostgreSQL via `AAAS_POSTGRES_DSN` / `DATABASE_URL`)
  - `redis`:     `RedisSessionAdapter` (cloud-agnostic Redis KV via `AAAS_REDIS_URL` / `REDIS_URL`)
  - `memory`:    `InMemorySessionAdapter` (zero-dependency pure in-memory store)
"""

from __future__ import annotations

import datetime
import json
import os
import re
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from providers.base_state import SessionStoreAdapter
from providers.gcp.firestore_session_adapter import GCPFirestoreSessionAdapter
from providers.generic.memory_state_adapters import InMemorySessionAdapter
from providers.generic.postgres_session_adapter import PostgresSessionAdapter
from providers.generic.redis_lock_adapter import RedisSessionAdapter

PROJECT_ID = os.getenv("GCP_PROJECT_ID", "agent-triad")
FIRESTORE_DB = "(default)"
FIRESTORE_BASE_URL = (
    f"https://firestore.googleapis.com/v1/projects/{PROJECT_ID}/databases/{FIRESTORE_DB}/documents"
)
LOCAL_CACHE_FILE = Path("/tmp/aaas_firestore_sessions_cache.json")
MAX_SESSIONS_PER_USER = 25


def create_session_store_adapter(backend: Optional[str] = None) -> SessionStoreAdapter:
    """Factory returning a concrete `SessionStoreAdapter` based on `AAAS_STATE_BACKEND`."""
    mode = (
        backend
        or os.getenv("AAAS_SESSION_BACKEND")
        or os.getenv("AAAS_STATE_BACKEND")
        or "firestore"
    ).strip().lower()

    if mode in ("firestore", "gcp"):
        return GCPFirestoreSessionAdapter(
            project_id=os.getenv("GCP_PROJECT_ID", PROJECT_ID),
            database=FIRESTORE_DB,
        )
    if mode in ("postgres", "postgresql"):
        return PostgresSessionAdapter()
    if mode == "redis":
        return RedisSessionAdapter()
    if mode in ("memory", "in-memory"):
        return InMemorySessionAdapter()

    raise ValueError(
        f"Unsupported AAAS_STATE_BACKEND={mode!r} for SessionStoreService. "
        "Expected one of: firestore, postgres, redis, memory."
    )


class SessionStoreService:
    """
    Manages persistent multi-session chat history per signed-in user via a pluggable
    `SessionStoreAdapter` (defaulting to Google Cloud Firestore for 100% backward compatibility).
    """

    def __init__(
        self,
        adapter: Optional[SessionStoreAdapter] = None,
        backend: Optional[str] = None,
    ) -> None:
        self.adapter: SessionStoreAdapter = adapter or create_session_store_adapter(backend)
        self._use_local_cache: bool = isinstance(self.adapter, GCPFirestoreSessionAdapter)
        self._memory_users: Dict[str, Dict[str, Any]] = {}
        if self._use_local_cache:
            self._load_local_cache()

    def _load_local_cache(self) -> None:
        if not self._use_local_cache:
            return
        if LOCAL_CACHE_FILE.exists():
            try:
                data = json.loads(LOCAL_CACHE_FILE.read_text(encoding="utf-8"))
                if isinstance(data, dict) and isinstance(data.get("users"), dict):
                    self._memory_users = data["users"]
            except Exception:
                pass

    def _save_local_cache(self) -> None:
        if not self._use_local_cache:
            return
        try:
            LOCAL_CACHE_FILE.write_text(
                json.dumps({"users": self._memory_users}, ensure_ascii=False),
                encoding="utf-8",
            )
        except Exception:
            pass

    @staticmethod
    def _user_doc_id(email: str) -> str:
        clean = (email or "harisankar@google.com").strip().lower()
        slug = re.sub(r"[^a-z0-9]+", "_", clean).strip("_")
        return slug or "default_operator"

    def _read_firestore_user_doc(self, user_key: str) -> Optional[Dict[str, Any]]:
        """Reads user record from the active `SessionStoreAdapter` (kept under legacy name for compatibility)."""
        return self.adapter.read_user_record(user_key)

    def _write_firestore_user_doc(self, user_key: str, record: Dict[str, Any]) -> bool:
        """Persists user record to in-memory cache, optional local cache, and active `SessionStoreAdapter`."""
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        record["updated_at"] = now_iso
        sessions = record.get("sessions", [])[:MAX_SESSIONS_PER_USER]
        record["sessions"] = sessions
        self._memory_users[user_key] = record
        self._save_local_cache()
        return self.adapter.write_user_record(user_key, record)

    @staticmethod
    def build_session_object(
        user_email: str,
        user_name: str,
        messages: List[Dict[str, Any]],
        session_id: Optional[str] = None,
        title: Optional[str] = None,
        created_at: Optional[str] = None,
    ) -> Dict[str, Any]:
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        sid = session_id or f"sess-{uuid.uuid4().hex[:8]}"

        derived_title = (title or "").strip()
        if not derived_title or derived_title == "New Chat Session":
            first_user_msg = next(
                (m.get("text", "").strip() for m in messages if m.get("role") == "user" and m.get("text")),
                "",
            )
            if first_user_msg:
                clean_one_line = " ".join(first_user_msg.split())
                derived_title = clean_one_line[:52] + ("..." if len(clean_one_line) > 52 else "")
            else:
                derived_title = "New Chat Session"

        last_spec = next(
            (
                m["specialist_worker"].get("name")
                for m in reversed(messages)
                if m.get("role") == "assistant"
                and isinstance(m.get("specialist_worker"), dict)
                and m.get("id") != "atlas-welcome"
            ),
            "Atlas • Lead Orchestrator",
        )
        user_msg_count = sum(1 for m in messages if m.get("role") == "user")

        return {
            "session_id": sid,
            "title": derived_title,
            "user_email": user_email,
            "user_name": user_name,
            "created_at": created_at or now_iso,
            "updated_at": now_iso,
            "message_count": len(messages),
            "user_message_count": user_msg_count,
            "last_specialist": last_spec,
            "messages": list(messages),
        }

    def get_or_init_user_sessions(
        self,
        user_email: str,
        user_name: str,
        default_messages: List[Dict[str, Any]],
        sync_from_firestore: bool = True,
    ) -> Dict[str, Any]:
        user_key = self._user_doc_id(user_email)
        record = self._memory_users.get(user_key)

        if sync_from_firestore or not record:
            remote_doc = self._read_firestore_user_doc(user_key)
            if remote_doc and remote_doc.get("sessions"):
                record = remote_doc
                self._memory_users[user_key] = record
                self._save_local_cache()

        if not record or not record.get("sessions"):
            initial_session = self.build_session_object(
                user_email=user_email,
                user_name=user_name,
                messages=default_messages,
                title="New Chat Session",
            )
            record = {
                "user_email": user_email,
                "user_name": user_name,
                "active_session_id": initial_session["session_id"],
                "updated_at": initial_session["updated_at"],
                "sessions": [initial_session],
            }
            self._write_firestore_user_doc(user_key, record)
            return record

        record["user_name"] = user_name or record.get("user_name", "Hari")
        record["user_email"] = user_email or record.get("user_email", "harisankar@google.com")
        active_id = record.get("active_session_id")
        if not any(s.get("session_id") == active_id for s in record["sessions"]):
            record["active_session_id"] = record["sessions"][0]["session_id"]
        return record

    def save_active_session_messages(
        self,
        user_email: str,
        user_name: str,
        session_id: str,
        messages: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        user_key = self._user_doc_id(user_email)
        record = self.get_or_init_user_sessions(
            user_email=user_email,
            user_name=user_name,
            default_messages=messages,
            sync_from_firestore=False,
        )
        sessions: List[Dict[str, Any]] = record.get("sessions", [])
        existing = next((s for s in sessions if s.get("session_id") == session_id), None)

        updated_session = self.build_session_object(
            user_email=user_email,
            user_name=user_name,
            messages=messages,
            session_id=session_id,
            title=existing.get("title") if existing else None,
            created_at=existing.get("created_at") if existing else None,
        )

        remaining = [s for s in sessions if s.get("session_id") != session_id]
        record["sessions"] = [updated_session] + remaining
        record["active_session_id"] = session_id
        record["user_name"] = user_name
        record["user_email"] = user_email
        self._write_firestore_user_doc(user_key, record)
        return updated_session

    def create_new_session(
        self,
        user_email: str,
        user_name: str,
        default_messages: List[Dict[str, Any]],
        title: Optional[str] = None,
    ) -> Dict[str, Any]:
        user_key = self._user_doc_id(user_email)
        record = self.get_or_init_user_sessions(
            user_email=user_email,
            user_name=user_name,
            default_messages=default_messages,
            sync_from_firestore=False,
        )
        sessions: List[Dict[str, Any]] = record.get("sessions", [])

        # Create a brand new session at the top of the user's history
        new_sess = self.build_session_object(
            user_email=user_email,
            user_name=user_name,
            messages=default_messages,
            title=title or "New Chat Session",
        )
        record["sessions"] = [new_sess] + sessions[: MAX_SESSIONS_PER_USER - 1]
        record["active_session_id"] = new_sess["session_id"]
        self._write_firestore_user_doc(user_key, record)
        return record

    def select_session(
        self,
        user_email: str,
        user_name: str,
        session_id: str,
        default_messages: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        user_key = self._user_doc_id(user_email)
        record = self.get_or_init_user_sessions(
            user_email=user_email,
            user_name=user_name,
            default_messages=default_messages,
            sync_from_firestore=False,
        )
        target = next((s for s in record.get("sessions", []) if s.get("session_id") == session_id), None)
        if not target:
            raise ValueError(f"Chat session {session_id} not found")
        record["active_session_id"] = session_id
        self._write_firestore_user_doc(user_key, record)
        return target

    def delete_session(
        self,
        user_email: str,
        user_name: str,
        session_id: str,
        default_messages: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        user_key = self._user_doc_id(user_email)
        record = self.get_or_init_user_sessions(
            user_email=user_email,
            user_name=user_name,
            default_messages=default_messages,
            sync_from_firestore=False,
        )
        remaining = [s for s in record.get("sessions", []) if s.get("session_id") != session_id]
        if not remaining:
            fresh = self.build_session_object(
                user_email=user_email,
                user_name=user_name,
                messages=default_messages,
                title="New Chat Session",
            )
            remaining = [fresh]
        record["sessions"] = remaining
        if record.get("active_session_id") == session_id:
            record["active_session_id"] = remaining[0]["session_id"]
        self._write_firestore_user_doc(user_key, record)
        return record

    def clear_all_sessions(
        self,
        user_email: str,
        user_name: str,
        default_messages: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        user_key = self._user_doc_id(user_email)
        fresh = self.build_session_object(
            user_email=user_email,
            user_name=user_name,
            messages=default_messages,
            title="New Chat Session",
        )
        record = {
            "user_email": user_email,
            "user_name": user_name,
            "active_session_id": fresh["session_id"],
            "updated_at": fresh["updated_at"],
            "sessions": [fresh],
        }
        self._write_firestore_user_doc(user_key, record)
        return record

    def get_status(self) -> Dict[str, Any]:
        return self.adapter.get_status()


session_store_service = SessionStoreService()
