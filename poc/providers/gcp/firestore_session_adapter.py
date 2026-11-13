"""
GCP Cloud Firestore Session Store Adapter (`GCPFirestoreSessionAdapter`).

Extracted from `poc/services/session_store_service.py` to preserve 100% backward-compatible
Google Cloud Firestore REST API persistence (`projects/{project_id}/databases/(default)/documents/aaas_user_sessions/{user_key}`)
behind the cloud-agnostic `SessionStoreAdapter` interface.
"""

from __future__ import annotations

import datetime
import json
import os
import subprocess
import time
from typing import Any, Dict, Optional

import httpx

from providers.base_state import SessionStoreAdapter


class GCPFirestoreSessionAdapter(SessionStoreAdapter):
    """Persists per-user chat session records to Google Cloud Firestore via REST API."""

    def __init__(
        self,
        project_id: Optional[str] = None,
        database: str = "(default)",
        collection: str = "aaas_user_sessions",
    ) -> None:
        self.project_id = project_id or os.getenv("GCP_PROJECT_ID", "agent-triad")
        self.database = database
        self.collection = collection
        self.base_url = (
            f"https://firestore.googleapis.com/v1/projects/{self.project_id}"
            f"/databases/{self.database}/documents"
        )
        self._cached_token: Optional[str] = None
        self._cached_token_expiry: float = 0.0
        self._prefer_gcloud_cli_token: bool = False
        self._status: str = "FIRESTORE_READY"

    @property
    def backend_name(self) -> str:
        return "Cloud Firestore"

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
            self._status = "LOCAL_CACHE_ONLY"
            return None

        url = f"{self.base_url}/{doc_path.lstrip('/')}"
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
                    self._status = "CLOUD_FIRESTORE_SYNCED"
                return resp
        except Exception:
            self._status = "LOCAL_FALLBACK"
            return None

    def read_user_record(self, user_key: str) -> Optional[Dict[str, Any]]:
        resp = self._firestore_request("GET", f"{self.collection}/{user_key}")
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

    def write_user_record(self, user_key: str, record: Dict[str, Any]) -> bool:
        now_iso = record.get("updated_at") or datetime.datetime.now(datetime.timezone.utc).isoformat()
        sessions = record.get("sessions", [])
        firestore_payload = {
            "fields": {
                "user_email": {"stringValue": str(record.get("user_email", ""))},
                "user_name": {"stringValue": str(record.get("user_name", ""))},
                "active_session_id": {"stringValue": str(record.get("active_session_id", ""))},
                "updated_at": {"stringValue": str(now_iso)},
                "sessions_json": {"stringValue": json.dumps(sessions, ensure_ascii=False)},
            }
        }
        resp = self._firestore_request("PATCH", f"{self.collection}/{user_key}", json_body=firestore_payload)
        return bool(resp and resp.status_code == 200)

    def delete_user_record(self, user_key: str) -> bool:
        resp = self._firestore_request("DELETE", f"{self.collection}/{user_key}")
        return bool(resp and resp.status_code in (200, 404))

    def get_status(self) -> Dict[str, Any]:
        return {
            "backend": self.backend_name,
            "state_backend_mode": "firestore",
            "database": f"projects/{self.project_id}/databases/{self.database}",
            "collection": self.collection,
            "status": self._status,
        }
