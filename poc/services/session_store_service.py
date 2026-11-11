"""
Cloud Firestore + Local Fallback Session Store Service for the AaaS Command Center.

Persists user chat sessions (`aaas_user_sessions/{user_key}`) and OAuth configuration
(`aaas_config/oauth`) in the `agent-triad` Cloud Firestore `(default)` database, with an
in-memory and local JSON cache for low-latency reads and offline/test resilience.
"""

from __future__ import annotations

import datetime
import json
import os
import re
import subprocess
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx

PROJECT_ID = os.getenv("GCP_PROJECT_ID", "agent-triad")
FIRESTORE_DB = "(default)"
FIRESTORE_BASE_URL = (
    f"https://firestore.googleapis.com/v1/projects/{PROJECT_ID}/databases/{FIRESTORE_DB}/documents"
)
LOCAL_CACHE_FILE = Path("/tmp/aaas_firestore_sessions_cache.json")
MAX_SESSIONS_PER_USER = 25


class SessionStoreService:
    """
    Manages persistent multi-session chat history per signed-in Google SSO user
    backed by Google Cloud Firestore (`projects/agent-triad/databases/(default)`).
    """

    def __init__(self) -> None:
        self._memory_users: Dict[str, Dict[str, Any]] = {}
        self._cached_token: Optional[str] = None
        self._cached_token_expiry: float = 0.0
        self._prefer_gcloud_cli_token: bool = False
        self._firestore_status: str = "FIRESTORE_READY"
        self._load_local_cache()

    def _load_local_cache(self) -> None:
        if LOCAL_CACHE_FILE.exists():
            try:
                data = json.loads(LOCAL_CACHE_FILE.read_text(encoding="utf-8"))
                if isinstance(data, dict) and isinstance(data.get("users"), dict):
                    self._memory_users = data["users"]
            except Exception:
                pass

    def _save_local_cache(self) -> None:
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

    def _get_access_token(self, force_gcloud: bool = False) -> Optional[str]:
        now = time.time()
        if not force_gcloud and self._cached_token and now < self._cached_token_expiry:
            return self._cached_token

        if not force_gcloud and not self._prefer_gcloud_cli_token:
            try:
                import google.auth
                import google.auth.transport.requests

                creds, _ = google.auth.default(
                    scopes=[
                        "https://www.googleapis.com/auth/cloud-platform",
                        "https://www.googleapis.com/auth/datastore",
                    ]
                )
                creds.refresh(google.auth.transport.requests.Request())
                if creds.token:
                    self._cached_token = creds.token
                    self._cached_token_expiry = now + 1800
                    return self._cached_token
            except Exception:
                pass

        # Fallback for local GCE workstations where metadata server scopes are restricted
        try:
            tok = subprocess.check_output(
                ["gcloud", "auth", "print-access-token"],
                text=True,
                stderr=subprocess.DEVNULL,
                timeout=4.0,
            ).strip()
            if tok:
                self._prefer_gcloud_cli_token = True
                self._cached_token = tok
                self._cached_token_expiry = now + 1800
                return self._cached_token
        except Exception:
            pass

        return None

    def _firestore_request(
        self,
        method: str,
        doc_path: str,
        json_body: Optional[Dict[str, Any]] = None,
    ) -> Optional[httpx.Response]:
        token = self._get_access_token()
        if not token:
            self._firestore_status = "LOCAL_CACHE_ONLY"
            return None

        url = f"{FIRESTORE_BASE_URL}/{doc_path.lstrip('/')}"
        try:
            with httpx.Client(timeout=4.5) as client:
                resp = client.request(
                    method=method,
                    url=url,
                    headers={"Authorization": f"Bearer {token}"},
                    json=json_body,
                )
                if resp.status_code == 403 and "ACCESS_TOKEN_SCOPE_INSUFFICIENT" in resp.text:
                    alt_token = self._get_access_token(force_gcloud=True)
                    if alt_token and alt_token != token:
                        resp = client.request(
                            method=method,
                            url=url,
                            headers={"Authorization": f"Bearer {alt_token}"},
                            json=json_body,
                        )
                if resp.status_code in (200, 404):
                    self._firestore_status = "CLOUD_FIRESTORE_SYNCED"
                return resp
        except Exception:
            self._firestore_status = "LOCAL_FALLBACK"
            return None

    def _read_firestore_user_doc(self, user_key: str) -> Optional[Dict[str, Any]]:
        resp = self._firestore_request("GET", f"aaas_user_sessions/{user_key}")
        if not resp or resp.status_code != 200:
            return None
        try:
            doc = resp.json()
            fields = doc.get("fields", {})
            sessions_raw = fields.get("sessions_json", {}).get("stringValue", "[]")
            sessions = json.loads(sessions_raw)
            if not isinstance(sessions, list):
                sessions = []
            return {
                "user_email": fields.get("user_email", {}).get("stringValue", ""),
                "user_name": fields.get("user_name", {}).get("stringValue", ""),
                "active_session_id": fields.get("active_session_id", {}).get("stringValue", ""),
                "updated_at": fields.get("updated_at", {}).get("stringValue", ""),
                "sessions": sessions,
            }
        except Exception:
            return None

    def _write_firestore_user_doc(self, user_key: str, record: Dict[str, Any]) -> bool:
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        record["updated_at"] = now_iso
        sessions = record.get("sessions", [])[:MAX_SESSIONS_PER_USER]
        record["sessions"] = sessions
        self._memory_users[user_key] = record
        self._save_local_cache()

        firestore_payload = {
            "fields": {
                "user_email": {"stringValue": str(record.get("user_email", ""))},
                "user_name": {"stringValue": str(record.get("user_name", ""))},
                "active_session_id": {"stringValue": str(record.get("active_session_id", ""))},
                "updated_at": {"stringValue": now_iso},
                "sessions_json": {"stringValue": json.dumps(sessions, ensure_ascii=False)},
            }
        }
        resp = self._firestore_request("PATCH", f"aaas_user_sessions/{user_key}", json_body=firestore_payload)
        return bool(resp and resp.status_code == 200)

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
        return {
            "backend": "Cloud Firestore",
            "database": f"projects/{PROJECT_ID}/databases/{FIRESTORE_DB}",
            "collection": "aaas_user_sessions",
            "status": self._firestore_status,
        }


session_store_service = SessionStoreService()
