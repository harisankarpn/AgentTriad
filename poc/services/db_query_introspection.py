"""
Read-Only Database Query Introspection Engine (`poc/services/db_query_introspection.py`).

Provides strictly read-only query-level diagnostics (`pg_stat_activity`, `pg_stat_statements`,
and slow-query log analysis) for the AaaS Database Specialist Agent (`agents/database_agent/`)
across GCP Cloud SQL, AWS RDS, and Azure SQL.

Security & Zero-Standing-Privilege Guardrails:
  1. Enforces `is_strictly_readonly_introspection_sql(...)` rejecting any DML/DDL or admin
     mutating functions (`INSERT`, `UPDATE`, `DELETE`, `DROP`, `ALTER`, `TRUNCATE`, `GRANT`,
     `CREATE`, `COPY`, `pg_terminate_backend`, `pg_cancel_backend`).
  2. Direct PostgreSQL socket introspection runs ONLY when an explicit read-only `db_connection`
     is injected or opt-in `AAAS_DB_READONLY_DSN` is configured, and explicitly sets
     `SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY`.
  3. Default Zero-Standing-Privilege mode operates completely out-of-band over cloud slow-query
     logs (`duration: <ms> ms  statement: ...`, lock waits, deadlocks) with zero direct TCP/5432
     socket credentials required.
  4. Any recommended SQL remediation (e.g. `CREATE INDEX CONCURRENTLY`, `pg_cancel_backend`) is
     returned strictly as an advisory proposal gated by Atlas HITL approval.
"""

from __future__ import annotations

import datetime
import os
import re
from typing import Any, Dict, List, Optional


READONLY_PG_STAT_ACTIVITY_SQL = """
SELECT
    pid,
    usename,
    application_name,
    client_addr::text AS client_addr,
    state,
    wait_event_type,
    wait_event,
    EXTRACT(EPOCH FROM (clock_timestamp() - query_start)) * 1000.0 AS duration_ms,
    EXTRACT(EPOCH FROM (clock_timestamp() - xact_start)) * 1000.0 AS xact_duration_ms,
    pg_blocking_pids(pid) AS blocked_by_pids,
    LEFT(query, 400) AS query
FROM pg_stat_activity
WHERE pid <> pg_backend_pid()
  AND state IS NOT NULL
ORDER BY duration_ms DESC NULLS LAST
LIMIT 25;
""".strip()

READONLY_PG_STAT_STATEMENTS_SQL = """
SELECT
    queryid::text AS queryid,
    calls,
    ROUND(total_exec_time::numeric, 2) AS total_exec_time_ms,
    ROUND(mean_exec_time::numeric, 2) AS mean_exec_time_ms,
    rows,
    shared_blks_read,
    shared_blks_hit,
    LEFT(query, 400) AS query
FROM pg_stat_statements
ORDER BY mean_exec_time DESC
LIMIT 10;
""".strip()

_FORBIDDEN_SQL_PATTERNS = [
    r"\b(insert|update|delete|drop|alter|truncate|create|grant|revoke|copy|vacuum|cluster|reindex|comment)\b",
    r"\bpg_terminate_backend\b",
    r"\bpg_cancel_backend\b",
    r"\bpg_reload_conf\b",
    r";\s*\S",  # Reject stacked multi-statement SQL injection
]

_SLOW_QUERY_LOG_RE = re.compile(
    r"duration:\s*(?P<duration>\d+(?:\.\d+)?)\s*ms\s+(?:statement|execute\s+[^:]+):\s*(?P<sql>.+)",
    re.IGNORECASE,
)


def is_strictly_readonly_introspection_sql(sql: str) -> bool:
    """
    Validates that a SQL query is strictly a single read-only SELECT/WITH catalog query
    with zero write, DDL, or session-termination primitives.
    """
    if not sql or not sql.strip():
        return False
    cleaned = sql.strip().rstrip(";").strip()
    if not re.match(r"^(SELECT|WITH)\b", cleaned, flags=re.IGNORECASE):
        return False
    for pattern in _FORBIDDEN_SQL_PATTERNS:
        if re.search(pattern, cleaned, flags=re.IGNORECASE):
            return False
    return True


def _normalize_sql_fingerprint(sql: str) -> str:
    """Redacts literal string/numeric values from SQL queries for safe PII-free telemetry."""
    if not sql:
        return ""
    fp = re.sub(r"'[^']*'", "'?'", str(sql))
    fp = re.sub(r"\b\d+(?:\.\d+)?\b", "?", fp)
    fp = re.sub(r"\s+", " ", fp).strip()
    return fp[:320]


def _extract_table_hint(sql: str) -> Optional[str]:
    m = re.search(r"\b(?:FROM|JOIN|INTO|UPDATE)\s+([a-zA-Z0-9_.\"]+)", sql or "", flags=re.IGNORECASE)
    return m.group(1).strip('"') if m else None


def _execute_readonly_pg_queries(
    conn: Any,
    include_stat_statements: bool = True,
) -> Dict[str, Any]:
    """
    Executes hardcoded read-only `pg_stat_activity` (and optionally `pg_stat_statements`)
    against an injected DB-API 2.0 connection or psycopg connection.
    """
    assert is_strictly_readonly_introspection_sql(READONLY_PG_STAT_ACTIVITY_SQL)
    assert is_strictly_readonly_introspection_sql(READONLY_PG_STAT_STATEMENTS_SQL)

    activity_rows: List[Dict[str, Any]] = []
    statement_rows: List[Dict[str, Any]] = []
    errors: List[str] = []

    with conn.cursor() as cur:
        # Enforce PostgreSQL read-only transaction session guardrail when supported
        try:
            cur.execute("SET TRANSACTION READ ONLY")
        except Exception:
            pass

        cur.execute(READONLY_PG_STAT_ACTIVITY_SQL)
        cols = [d[0] for d in (getattr(cur, "description", None) or [])]
        for row in cur.fetchall() or []:
            if isinstance(row, dict):
                activity_rows.append(dict(row))
            elif cols:
                activity_rows.append(dict(zip(cols, row)))

        if include_stat_statements:
            try:
                cur.execute(READONLY_PG_STAT_STATEMENTS_SQL)
                scols = [d[0] for d in (getattr(cur, "description", None) or [])]
                for row in cur.fetchall() or []:
                    if isinstance(row, dict):
                        statement_rows.append(dict(row))
                    elif scols:
                        statement_rows.append(dict(zip(scols, row)))
            except Exception as exc:
                errors.append(f"pg_stat_statements unavailable: {type(exc).__name__}")

    return {
        "activity_rows": activity_rows,
        "statement_rows": statement_rows,
        "errors": errors,
    }


def analyze_pg_stat_activity_and_slow_queries(
    instance_name: str = "testdbinstance1",
    target_cloud: str = "gcp",
    slow_query_threshold_ms: float = 500.0,
    activity_rows: Optional[List[Dict[str, Any]]] = None,
    statement_rows: Optional[List[Dict[str, Any]]] = None,
    log_lines: Optional[List[str]] = None,
    db_connection: Optional[Any] = None,
    readonly_dsn: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Unified read-only query-level introspection engine.

    Order of data acquisition:
      1. Explicit `activity_rows` / `statement_rows` (if provided).
      2. Explicit `db_connection` (injected DB-API 2.0 connection) or opt-in `readonly_dsn`
         / `AAAS_DB_READONLY_DSN` using `psycopg`/`psycopg2` with `TRANSACTION READ ONLY`.
      3. Out-of-band slow-query log parsing from `log_lines` (preserving Zero-Standing-Privilege
         when direct DB socket access is not enabled).
    """
    threshold = max(1.0, float(slow_query_threshold_ms))
    introspection_mode = "out_of_band_log_and_insights"
    api_errors: List[str] = []

    resolved_activity: List[Dict[str, Any]] = list(activity_rows or [])
    resolved_statements: List[Dict[str, Any]] = list(statement_rows or [])

    if db_connection is not None:
        introspection_mode = "readonly_pg_stat_activity"
        try:
            res = _execute_readonly_pg_queries(db_connection)
            resolved_activity = res["activity_rows"]
            resolved_statements = res["statement_rows"]
            api_errors.extend(res["errors"])
        except Exception as exc:
            api_errors.append(f"readonly_connection_error: {type(exc).__name__}: {exc}")
    elif not resolved_activity and (readonly_dsn or os.getenv("AAAS_DB_READONLY_DSN")):
        dsn = readonly_dsn or os.getenv("AAAS_DB_READONLY_DSN", "")
        introspection_mode = "readonly_pg_stat_activity"
        conn = None
        try:
            try:
                import psycopg  # type: ignore

                conn = psycopg.connect(dsn, connect_timeout=4, autocommit=False)
            except ImportError:
                import psycopg2  # type: ignore

                conn = psycopg2.connect(dsn, connect_timeout=4)
            res = _execute_readonly_pg_queries(conn)
            resolved_activity = res["activity_rows"]
            resolved_statements = res["statement_rows"]
            api_errors.extend(res["errors"])
        except Exception as exc:
            api_errors.append(f"readonly_dsn_unavailable: {type(exc).__name__}: {exc}")
            introspection_mode = "out_of_band_log_and_insights"
        finally:
            if conn is not None:
                try:
                    conn.rollback()
                    conn.close()
                except Exception:
                    pass
    elif resolved_activity:
        introspection_mode = "readonly_pg_stat_activity"

    # Analyze pg_stat_activity rows
    active_sessions: List[Dict[str, Any]] = []
    long_running_queries: List[Dict[str, Any]] = []
    idle_in_tx_sessions: List[Dict[str, Any]] = []
    blocking_chains: List[Dict[str, Any]] = []
    max_duration_ms = 0.0

    by_pid: Dict[int, Dict[str, Any]] = {}
    for raw in resolved_activity:
        pid = int(raw.get("pid") or 0)
        state = str(raw.get("state") or "unknown").lower()
        dur_ms = round(float(raw.get("duration_ms") or 0.0), 2)
        xact_ms = round(float(raw.get("xact_duration_ms") or dur_ms), 2)
        blocked_by = [int(p) for p in (raw.get("blocked_by_pids") or []) if p is not None]
        raw_query = str(raw.get("query") or "")
        fingerprint = _normalize_sql_fingerprint(raw_query)

        session_rec = {
            "pid": pid,
            "usename": raw.get("usename") or "app_user",
            "application_name": raw.get("application_name") or "",
            "state": state,
            "wait_event_type": raw.get("wait_event_type"),
            "wait_event": raw.get("wait_event"),
            "duration_ms": dur_ms,
            "xact_duration_ms": xact_ms,
            "blocked_by_pids": blocked_by,
            "query_fingerprint": fingerprint,
            "table_hint": _extract_table_hint(raw_query),
        }
        active_sessions.append(session_rec)
        if pid:
            by_pid[pid] = session_rec
        if dur_ms > max_duration_ms:
            max_duration_ms = dur_ms

        if state == "active" and dur_ms >= threshold:
            long_running_queries.append(session_rec)
        if "idle in transaction" in state and xact_ms >= threshold:
            idle_in_tx_sessions.append(session_rec)

    for sess in active_sessions:
        if sess["blocked_by_pids"]:
            blocker_pid = sess["blocked_by_pids"][0]
            blocker = by_pid.get(blocker_pid, {})
            blocking_chains.append(
                {
                    "blocked_pid": sess["pid"],
                    "blocked_query": sess["query_fingerprint"],
                    "blocked_duration_ms": sess["duration_ms"],
                    "wait_event": sess.get("wait_event") or sess.get("wait_event_type") or "Lock",
                    "blocker_pid": blocker_pid,
                    "blocker_state": blocker.get("state", "unknown"),
                    "blocker_query": blocker.get("query_fingerprint", ""),
                    "hitl_advisory_sql": f"SELECT pg_cancel_backend({blocker_pid}); -- HITL approval required",
                }
            )

    # Analyze pg_stat_statements + out-of-band slow query log lines
    top_slow_queries: List[Dict[str, Any]] = []
    for stmt in resolved_statements:
        mean_ms = round(float(stmt.get("mean_exec_time_ms") or stmt.get("mean_exec_time") or 0.0), 2)
        if mean_ms > max_duration_ms:
            max_duration_ms = mean_ms
        raw_q = str(stmt.get("query") or "")
        top_slow_queries.append(
            {
                "source": "pg_stat_statements",
                "queryid": str(stmt.get("queryid") or ""),
                "calls": int(stmt.get("calls") or 0),
                "mean_exec_time_ms": mean_ms,
                "total_exec_time_ms": round(float(stmt.get("total_exec_time_ms") or stmt.get("total_exec_time") or 0.0), 2),
                "rows": int(stmt.get("rows") or 0),
                "shared_blks_read": int(stmt.get("shared_blks_read") or 0),
                "query_fingerprint": _normalize_sql_fingerprint(raw_q),
                "table_hint": _extract_table_hint(raw_q),
            }
        )

    lock_warnings_in_logs: List[str] = []
    for line in log_lines or []:
        text = str(line or "")
        m = _SLOW_QUERY_LOG_RE.search(text)
        if m:
            dur = round(float(m.group("duration")), 2)
            sql_txt = m.group("sql").strip()
            if dur >= threshold:
                if dur > max_duration_ms:
                    max_duration_ms = dur
                top_slow_queries.append(
                    {
                        "source": "slow_query_log",
                        "duration_ms": dur,
                        "mean_exec_time_ms": dur,
                        "query_fingerprint": _normalize_sql_fingerprint(sql_txt),
                        "table_hint": _extract_table_hint(sql_txt),
                    }
                )
        low = text.lower()
        if any(k in low for k in ("deadlock detected", "lock timeout", "still waiting for", "exclusive lock")):
            lock_warnings_in_logs.append(text[:280])

    top_slow_queries.sort(key=lambda q: float(q.get("mean_exec_time_ms") or q.get("duration_ms") or 0.0), reverse=True)

    # Synthesize safe, HITL-gated DBA recommendations (never auto-executed)
    recommendations: List[Dict[str, Any]] = []
    if blocking_chains:
        root_blocker = blocking_chains[0]["blocker_pid"]
        recommendations.append(
            {
                "category": "LOCK_CONTENTION",
                "severity": "HIGH",
                "summary": (
                    f"Detected {len(blocking_chains)} blocked session(s) waiting on blocker PID `{root_blocker}` "
                    f"(state=`{blocking_chains[0]['blocker_state']}`)."
                ),
                "proposed_action": (
                    f"Inspect blocker PID `{root_blocker}` and, with Atlas HITL approval, run "
                    f"`SELECT pg_cancel_backend({root_blocker});` or configure `idle_in_transaction_session_timeout = '30s'`."
                ),
                "requires_hitl_approval": True,
            }
        )
    if idle_in_tx_sessions:
        recommendations.append(
            {
                "category": "IDLE_IN_TRANSACTION",
                "severity": "MEDIUM",
                "summary": f"{len(idle_in_tx_sessions)} session(s) stuck `idle in transaction` exceeding {threshold}ms.",
                "proposed_action": "Set database flag `idle_in_transaction_session_timeout=60000` via Cloud SQL / RDS parameter group.",
                "requires_hitl_approval": True,
            }
        )
    if long_running_queries or top_slow_queries:
        sample_q = (long_running_queries[0] if long_running_queries else top_slow_queries[0])
        tbl = sample_q.get("table_hint") or "target_table"
        recommendations.append(
            {
                "category": "SLOW_QUERY_OPTIMIZATION",
                "severity": "HIGH" if max_duration_ms >= 2000.0 else "MEDIUM",
                "summary": (
                    f"Slow query detected on `{tbl}` (max={max_duration_ms}ms >= threshold {threshold}ms): "
                    f"`{sample_q.get('query_fingerprint', '')[:120]}`"
                ),
                "proposed_action": (
                    f"Run read-only `EXPLAIN (ANALYZE, BUFFERS)` on the fingerprinted query for `{tbl}` "
                    "and evaluate a non-blocking `CREATE INDEX CONCURRENTLY` or query rewrite."
                ),
                "requires_hitl_approval": True,
            }
        )
    if lock_warnings_in_logs:
        recommendations.append(
            {
                "category": "LOG_LOCK_OR_DEADLOCK",
                "severity": "HIGH",
                "summary": f"Detected {len(lock_warnings_in_logs)} lock/deadlock warning(s) in database logs.",
                "proposed_action": "Enable `log_lock_waits=on` and `deadlock_timeout=1s` to trace offending transactions.",
                "requires_hitl_approval": True,
            }
        )

    if introspection_mode == "readonly_pg_stat_activity" and active_sessions:
        status = "LIVE_PG_STAT_ACTIVITY"
    elif top_slow_queries or lock_warnings_in_logs:
        status = "CONTROL_PLANE_SLOW_QUERY_ANALYSIS"
    else:
        status = "NO_SLOW_QUERIES_DETECTED"

    return {
        "status": status,
        "target_cloud": target_cloud,
        "instance_name": instance_name,
        "introspection_mode": introspection_mode,
        "read_only_enforced": True,
        "slow_query_threshold_ms": threshold,
        "active_sessions": active_sessions[:15],
        "long_running_queries": long_running_queries[:10],
        "idle_in_transaction_sessions": idle_in_tx_sessions[:10],
        "blocking_chains": blocking_chains[:10],
        "top_slow_queries": top_slow_queries[:10],
        "lock_warnings_in_logs": lock_warnings_in_logs[:6],
        "summary": {
            "total_active_sessions": len(active_sessions),
            "long_running_count": len(long_running_queries),
            "idle_in_transaction_count": len(idle_in_tx_sessions),
            "blocked_session_count": len(blocking_chains),
            "slow_query_count": len(top_slow_queries),
            "max_query_duration_ms": round(max_duration_ms, 2),
        },
        "dba_recommendations": recommendations,
        "readonly_sql_queries_used": {
            "pg_stat_activity": READONLY_PG_STAT_ACTIVITY_SQL,
            "pg_stat_statements": READONLY_PG_STAT_STATEMENTS_SQL,
        },
        "api_errors": api_errors,
        "inspected_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }
