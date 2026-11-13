"""
Cloud-Agnostic PostgreSQL Session Store Adapter (`PostgresSessionAdapter` / `PostgresSessionStore`).

Persists per-user multi-session chat history in any standard PostgreSQL database
(AWS RDS/Aurora, Azure Database for PostgreSQL, Cloud SQL, Neon, or self-hosted Postgres)
via `AAAS_POSTGRES_DSN` / `DATABASE_URL`.

Uses lazy optional driver discovery (`psycopg` v3 -> `psycopg2` -> `sqlalchemy`) and degrades
cleanly to an in-memory fallback when no DSN, driver, or live database is configured.
"""

from __future__ import annotations

import copy
import datetime
import json
import os
import re
from typing import Any, Callable, Dict, Optional

from providers.base_state import SessionStoreAdapter

_VALID_IDENT_RE = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*$")


class PostgresSessionAdapter(SessionStoreAdapter):
    """Cloud-agnostic PostgreSQL implementation of `SessionStoreAdapter`."""

    def __init__(
        self,
        dsn: Optional[str] = None,
        table_name: Optional[str] = None,
        connection_factory: Optional[Callable[[], Any]] = None,
    ) -> None:
        self.dsn = (dsn or os.getenv("AAAS_POSTGRES_DSN") or os.getenv("DATABASE_URL") or "").strip()
        raw_table = (table_name or os.getenv("AAAS_POSTGRES_SESSIONS_TABLE") or "aaas_user_sessions").strip()
        if not _VALID_IDENT_RE.match(raw_table):
            raise ValueError(f"Invalid PostgreSQL table identifier: {raw_table!r}")
        self.table_name = raw_table
        self._connection_factory = connection_factory
        self._fallback_memory: Dict[str, Dict[str, Any]] = {}
        self._schema_initialized: bool = False
        self._driver_name: Optional[str] = None
        self._sqlalchemy_engine: Optional[Any] = None
        self._status: str = "POSTGRES_READY" if (self.dsn or connection_factory) else "POSTGRES_DSN_NOT_CONFIGURED_FALLBACK"

    @property
    def backend_name(self) -> str:
        return "PostgreSQL"

    def _open_dbapi_connection(self) -> Optional[Any]:
        if self._connection_factory is not None:
            self._driver_name = "injected"
            return self._connection_factory()

        if not self.dsn:
            self._status = "POSTGRES_DSN_NOT_CONFIGURED_FALLBACK"
            return None

        # 1. Try psycopg (v3)
        try:
            import psycopg  # type: ignore[import-not-found]

            self._driver_name = "psycopg"
            return psycopg.connect(self.dsn, connect_timeout=4)
        except ImportError:
            pass
        except Exception:
            self._status = "POSTGRES_FALLBACK_MEMORY"
            return None

        # 2. Try psycopg2
        try:
            import psycopg2  # type: ignore[import-not-found]

            self._driver_name = "psycopg2"
            return psycopg2.connect(self.dsn, connect_timeout=4)
        except ImportError:
            pass
        except Exception:
            self._status = "POSTGRES_FALLBACK_MEMORY"
            return None

        # 3. Try SQLAlchemy raw DBAPI connection (supports any installed dialect, e.g. pg8000 / sqlite for testing)
        try:
            import sqlalchemy

            if self._sqlalchemy_engine is None:
                self._sqlalchemy_engine = sqlalchemy.create_engine(self.dsn, pool_pre_ping=True)
            self._driver_name = "sqlalchemy"
            return self._sqlalchemy_engine.raw_connection()
        except ImportError:
            self._status = "POSTGRES_DRIVER_MISSING_FALLBACK"
            return None
        except Exception:
            self._status = "POSTGRES_FALLBACK_MEMORY"
            return None

    def _placeholder(self) -> str:
        if self._driver_name == "sqlalchemy" and self.dsn.startswith("sqlite"):
            return "?"
        if self._driver_name == "injected":
            return "?"
        return "%s"

    def _ensure_schema(self, conn: Any) -> None:
        if self._schema_initialized:
            return
        ddl = (
            f"CREATE TABLE IF NOT EXISTS {self.table_name} ("
            "user_key TEXT PRIMARY KEY, "
            "user_email TEXT NOT NULL, "
            "user_name TEXT NOT NULL, "
            "active_session_id TEXT NOT NULL, "
            "updated_at TEXT NOT NULL, "
            "sessions_json TEXT NOT NULL"
            ")"
        )
        cur = conn.cursor()
        try:
            cur.execute(ddl)
            conn.commit()
            self._schema_initialized = True
        finally:
            cur.close()

    def read_user_record(self, user_key: str) -> Optional[Dict[str, Any]]:
        conn = self._open_dbapi_connection()
        if conn is None:
            rec = self._fallback_memory.get(user_key)
            return copy.deepcopy(rec) if rec is not None else None

        try:
            self._ensure_schema(conn)
            ph = self._placeholder()
            cur = conn.cursor()
            try:
                cur.execute(
                    f"SELECT user_email, user_name, active_session_id, updated_at, sessions_json "
                    f"FROM {self.table_name} WHERE user_key = {ph}",
                    (user_key,),
                )
                row = cur.fetchone()
            finally:
                cur.close()
            self._status = "POSTGRES_CONNECTED"
            if not row:
                return None
            sessions = json.loads(row[4]) if isinstance(row[4], str) else row[4]
            if not isinstance(sessions, list):
                sessions = []
            record = {
                "user_email": str(row[0] or ""),
                "user_name": str(row[1] or ""),
                "active_session_id": str(row[2] or ""),
                "updated_at": str(row[3] or ""),
                "sessions": sessions,
            }
            self._fallback_memory[user_key] = copy.deepcopy(record)
            return record
        except Exception:
            self._status = "POSTGRES_FALLBACK_MEMORY"
            rec = self._fallback_memory.get(user_key)
            return copy.deepcopy(rec) if rec is not None else None
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def write_user_record(self, user_key: str, record: Dict[str, Any]) -> bool:
        now_iso = str(record.get("updated_at") or datetime.datetime.now(datetime.timezone.utc).isoformat())
        sessions_json = json.dumps(record.get("sessions", []), ensure_ascii=False)
        self._fallback_memory[user_key] = copy.deepcopy(record)

        conn = self._open_dbapi_connection()
        if conn is None:
            return False

        try:
            self._ensure_schema(conn)
            ph = self._placeholder()
            cur = conn.cursor()
            try:
                cur.execute(
                    f"INSERT INTO {self.table_name} "
                    "(user_key, user_email, user_name, active_session_id, updated_at, sessions_json) "
                    f"VALUES ({ph}, {ph}, {ph}, {ph}, {ph}, {ph}) "
                    "ON CONFLICT (user_key) DO UPDATE SET "
                    "user_email = EXCLUDED.user_email, "
                    "user_name = EXCLUDED.user_name, "
                    "active_session_id = EXCLUDED.active_session_id, "
                    "updated_at = EXCLUDED.updated_at, "
                    "sessions_json = EXCLUDED.sessions_json",
                    (
                        user_key,
                        str(record.get("user_email", "")),
                        str(record.get("user_name", "")),
                        str(record.get("active_session_id", "")),
                        now_iso,
                        sessions_json,
                    ),
                )
                conn.commit()
            finally:
                cur.close()
            self._status = "POSTGRES_CONNECTED"
            return True
        except Exception:
            self._status = "POSTGRES_FALLBACK_MEMORY"
            return False
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def delete_user_record(self, user_key: str) -> bool:
        self._fallback_memory.pop(user_key, None)
        conn = self._open_dbapi_connection()
        if conn is None:
            return False

        try:
            self._ensure_schema(conn)
            ph = self._placeholder()
            cur = conn.cursor()
            try:
                cur.execute(f"DELETE FROM {self.table_name} WHERE user_key = {ph}", (user_key,))
                conn.commit()
            finally:
                cur.close()
            self._status = "POSTGRES_CONNECTED"
            return True
        except Exception:
            self._status = "POSTGRES_FALLBACK_MEMORY"
            return False
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def get_status(self) -> Dict[str, Any]:
        redacted_dsn = "configured" if self.dsn else "not_configured"
        return {
            "backend": self.backend_name,
            "state_backend_mode": "postgres",
            "database": f"postgres://{self.table_name} ({redacted_dsn})",
            "collection": self.table_name,
            "driver": self._driver_name or "lazy",
            "status": self._status,
        }


# Alias matching AGENTS.md target architecture naming
PostgresSessionStore = PostgresSessionAdapter
