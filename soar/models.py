"""
Mini-SOC SOAR Database & Data Models
Implements Section 13 database design:
soar_actions (id, alert_id, alert_type, action_taken, target, executed_at, result)
"""

import sqlite3
import os
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field


class AlertPayload(BaseModel):
    id: Optional[str] = None
    timestamp: Optional[str] = None
    event_type: str = "alert"
    src_ip: str
    src_port: Optional[int] = None
    dest_ip: Optional[str] = None
    dest_port: Optional[int] = None
    proto: Optional[str] = "TCP"
    signature: str
    signature_id: int
    severity: Optional[str] = "high"
    mitre_technique_id: Optional[str] = None
    mitre_technique_name: Optional[str] = None
    mitre_tactic_id: Optional[str] = None
    mitre_tactic_name: Optional[str] = None
    occurrence_count: int = 1
    raw_payload: Optional[Dict[str, Any]] = None


class ActionRecord(BaseModel):
    id: Optional[int] = None
    alert_id: str
    alert_type: str
    action_taken: str
    target: str
    executed_at: str
    result: str
    status: str = "ACTIVE"
    reverted_at: Optional[str] = None
    details: Optional[str] = None


class SOARDatabase:
    def __init__(self, db_path: str = "soar_actions.db"):
        self.db_path = db_path
        self._init_db()

    def _get_connection(self):
        conn = sqlite3.connect(self.db_path, timeout=30.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        return conn

    def _init_db(self):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            # Primary schema from Section 13 with production extensions
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS soar_actions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    alert_id TEXT NOT NULL,
                    alert_type TEXT NOT NULL,
                    action_taken TEXT NOT NULL,
                    target TEXT NOT NULL,
                    executed_at TEXT NOT NULL,
                    result TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'ACTIVE',
                    reverted_at TEXT,
                    details TEXT
                )
            """)
            # Active blocks table for tracking firewall blocks and TTL
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS active_blocks (
                    target TEXT PRIMARY KEY,
                    action_id INTEGER,
                    reason TEXT,
                    blocked_at TEXT NOT NULL,
                    expires_at TEXT,
                    FOREIGN KEY(action_id) REFERENCES soar_actions(id)
                )
            """)
            # Benign whitelist registry
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS benign_whitelist (
                    ip_or_subnet TEXT PRIMARY KEY,
                    description TEXT NOT NULL,
                    added_at TEXT NOT NULL
                )
            """)
            # Enterprise Case Management Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS soar_cases (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_number TEXT UNIQUE NOT NULL,
                    title TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'OPEN',
                    assignee TEXT DEFAULT 'unassigned',
                    source_ip TEXT,
                    target_asset TEXT,
                    mitre_technique_id TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    resolved_at TEXT,
                    sla_minutes INTEGER DEFAULT 60
                )
            """)
            # Case Analyst Notes Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS case_notes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id INTEGER NOT NULL,
                    author TEXT NOT NULL,
                    note TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(case_id) REFERENCES soar_cases(id)
                )
            """)
            # SOC2 / ISO 27001 Compliance Audit Trail
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    actor TEXT NOT NULL,
                    action TEXT NOT NULL,
                    target_type TEXT NOT NULL,
                    target_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    details TEXT
                )
            """)
            conn.commit()

            # Seed default benign scanner IP
            cursor.execute("SELECT COUNT(*) FROM benign_whitelist")
            if cursor.fetchone()[0] == 0:
                now = datetime.now(timezone.utc).isoformat()
                cursor.execute("""
                    INSERT INTO benign_whitelist (ip_or_subnet, description, added_at)
                    VALUES (?, ?, ?)
                """, ("172.28.0.254", "Authorized Internal Security Vulnerability Scanner", now))
                cursor.execute("""
                    INSERT INTO benign_whitelist (ip_or_subnet, description, added_at)
                    VALUES (?, ?, ?)
                """, ("10.0.99.100", "Internal SecOps Vulnerability Scanner Appliance", now))
                conn.commit()

            # Seed initial enterprise demo cases if empty
            cursor.execute("SELECT COUNT(*) FROM soar_cases")
            if cursor.fetchone()[0] == 0:
                now = datetime.now(timezone.utc).isoformat()
                cursor.execute("""
                    INSERT INTO soar_cases (case_number, title, severity, status, assignee, source_ip, target_asset, mitre_technique_id, created_at, updated_at, sla_minutes)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, ("CASE-2026-0001", "Repeated SSH Brute Force on Production Bastion", "P1_CRITICAL", "CONTAINED", "secops-lead@company.com", "192.168.1.189", "bastion-prod-01", "T1110.001", now, now, 15))
                cursor.execute("""
                    INSERT INTO soar_cases (case_number, title, severity, status, assignee, source_ip, target_asset, mitre_technique_id, created_at, updated_at, sla_minutes)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, ("CASE-2026-0002", "Cloud Metadata IMDS SSRF Attempt on Billing API", "P1_CRITICAL", "INVESTIGATING", "tier2-analyst@company.com", "185.220.101.5", "api.payment.internal", "T1552.005", now, now, 30))
                cursor.execute("""
                    INSERT INTO soar_cases (case_number, title, severity, status, assignee, source_ip, target_asset, mitre_technique_id, created_at, updated_at, sla_minutes)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, ("CASE-2026-0003", "Nmap Service Reconnaissance Scan", "P3_MEDIUM", "RESOLVED", "tier1-analyst@company.com", "45.154.255.89", "gateway.corp", "T1046", now, now, 120))
                conn.commit()

    def record_action(self, alert_id: str, alert_type: str, action_taken: str,
                      target: str, result: str, status: str = "ACTIVE",
                      details: Optional[str] = None) -> int:
        executed_at = datetime.now(timezone.utc).isoformat()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO soar_actions (alert_id, alert_type, action_taken, target, executed_at, result, status, details)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (alert_id, alert_type, action_taken, target, executed_at, result, status, details))
            conn.commit()
            return cursor.lastrowid

    def list_actions(self, target: Optional[str] = None, alert_type: Optional[str] = None,
                     action_taken: Optional[str] = None, status: Optional[str] = None,
                     limit: int = 100) -> List[Dict[str, Any]]:
        query = "SELECT * FROM soar_actions WHERE 1=1"
        params = []
        if target:
            query += " AND target = ?"
            params.append(target)
        if alert_type:
            query += " AND alert_type = ?"
            params.append(alert_type)
        if action_taken:
            query += " AND action_taken = ?"
            params.append(action_taken)
        if status:
            query += " AND status = ?"
            params.append(status)
        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]

    def get_action_by_id(self, action_id: int) -> Optional[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM soar_actions WHERE id = ?", (action_id,))
            row = cursor.fetchone()
            return dict(row) if row else None

    def revert_action(self, action_id: int, revert_details: Optional[str] = None) -> bool:
        reverted_at = datetime.now(timezone.utc).isoformat()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT target, action_taken, status FROM soar_actions WHERE id = ?", (action_id,))
            row = cursor.fetchone()
            if not row or row["status"] == "REVERTED":
                return False
            
            target = row["target"]
            # Mark action as reverted
            cursor.execute("""
                UPDATE soar_actions 
                SET status = 'REVERTED', reverted_at = ?, details = COALESCE(details, '') || ' | ' || ?
                WHERE id = ?
            """, (reverted_at, f"Reverted at {reverted_at}: {revert_details or 'Manual revert'}", action_id))

            # Remove from active_blocks if target was blocked
            cursor.execute("DELETE FROM active_blocks WHERE target = ?", (target,))
            conn.commit()
            return True

    def register_active_block(self, target: str, action_id: int, reason: str, expires_at: Optional[str] = None):
        blocked_at = datetime.now(timezone.utc).isoformat()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO active_blocks (target, action_id, reason, blocked_at, expires_at)
                VALUES (?, ?, ?, ?, ?)
            """, (target, action_id, reason, blocked_at, expires_at))
            conn.commit()

    def remove_active_block(self, target: str):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM active_blocks WHERE target = ?", (target,))
            conn.commit()

    def get_active_blocks(self) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM active_blocks ORDER BY blocked_at DESC")
            return [dict(row) for row in cursor.fetchall()]

    def is_target_blocked(self, target: str) -> bool:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT 1 FROM active_blocks WHERE target = ?", (target,))
            return cursor.fetchone() is not None

    def is_benign_ip(self, ip: str) -> bool:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT 1 FROM benign_whitelist WHERE ip_or_subnet = ?", (ip,))
            return cursor.fetchone() is not None

    def list_benign_ips(self) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM benign_whitelist")
            return [dict(row) for row in cursor.fetchall()]

    # ==========================================================================
    # Enterprise Case Management & Incident Lifecycle
    # ==========================================================================

    def create_case(self, title: str, severity: str, source_ip: Optional[str] = None,
                    target_asset: Optional[str] = None, mitre_technique_id: Optional[str] = None,
                    assignee: str = "unassigned", sla_minutes: int = 60) -> int:
        now = datetime.now(timezone.utc).isoformat()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM soar_cases")
            count = cursor.fetchone()[0] + 1
            case_number = f"CASE-{datetime.now().year}-{count:04d}"
            cursor.execute("""
                INSERT INTO soar_cases (case_number, title, severity, status, assignee, source_ip, target_asset, mitre_technique_id, created_at, updated_at, sla_minutes)
                VALUES (?, ?, ?, 'OPEN', ?, ?, ?, ?, ?, ?, ?)
            """, (case_number, title, severity, assignee, source_ip, target_asset, mitre_technique_id, now, now, sla_minutes))
            case_id = cursor.lastrowid
            cursor.execute("""
                INSERT INTO audit_logs (actor, action, target_type, target_id, timestamp, details)
                VALUES (?, ?, ?, ?, ?, ?)
            """, ("SYSTEM", "CREATE_CASE", "CASE", str(case_id), now, f"Created {case_number}: {title} ({severity})"))
            conn.commit()
            return case_id

    def list_cases(self, status: Optional[str] = None, severity: Optional[str] = None,
                   assignee: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        query = "SELECT * FROM soar_cases WHERE 1=1"
        params = []
        if status:
            query += " AND status = ?"
            params.append(status)
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        if assignee:
            query += " AND assignee = ?"
            params.append(assignee)
        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]

    def get_case(self, case_id: int) -> Optional[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM soar_cases WHERE id = ?", (case_id,))
            row = cursor.fetchone()
            if not row:
                return None
            case_dict = dict(row)
            cursor.execute("SELECT * FROM case_notes WHERE case_id = ? ORDER BY id ASC", (case_id,))
            case_dict["notes"] = [dict(n) for n in cursor.fetchall()]
            return case_dict

    def update_case_status(self, case_id: int, new_status: str, actor: str = "analyst", note: Optional[str] = None) -> bool:
        now = datetime.now(timezone.utc).isoformat()
        resolved_at = now if new_status in ("RESOLVED", "CLOSED", "FALSE_POSITIVE") else None
        with self._get_connection() as conn:
            cursor = conn.cursor()
            if resolved_at:
                cursor.execute("""
                    UPDATE soar_cases SET status = ?, updated_at = ?, resolved_at = ? WHERE id = ?
                """, (new_status, now, resolved_at, case_id))
            else:
                cursor.execute("""
                    UPDATE soar_cases SET status = ?, updated_at = ? WHERE id = ?
                """, (new_status, now, case_id))
            
            if cursor.rowcount > 0:
                cursor.execute("""
                    INSERT INTO audit_logs (actor, action, target_type, target_id, timestamp, details)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (actor, "UPDATE_STATUS", "CASE", str(case_id), now, f"Status updated to {new_status}"))
                if note:
                    cursor.execute("""
                        INSERT INTO case_notes (case_id, author, note, created_at)
                        VALUES (?, ?, ?, ?)
                    """, (case_id, actor, f"Status changed to {new_status}: {note}", now))
                conn.commit()
                return True
            return False

    def assign_case(self, case_id: int, assignee: str, actor: str = "analyst") -> bool:
        now = datetime.now(timezone.utc).isoformat()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE soar_cases SET assignee = ?, updated_at = ?, status = CASE WHEN status = 'OPEN' THEN 'TRIAGING' ELSE status END
                WHERE id = ?
            """, (assignee, now, case_id))
            if cursor.rowcount > 0:
                cursor.execute("""
                    INSERT INTO audit_logs (actor, action, target_type, target_id, timestamp, details)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (actor, "ASSIGN_CASE", "CASE", str(case_id), now, f"Assigned to {assignee}"))
                conn.commit()
                return True
            return False

    def add_case_note(self, case_id: int, author: str, note: str) -> int:
        now = datetime.now(timezone.utc).isoformat()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO case_notes (case_id, author, note, created_at)
                VALUES (?, ?, ?, ?)
            """, (case_id, author, note, now))
            note_id = cursor.lastrowid
            cursor.execute("""
                INSERT INTO audit_logs (actor, action, target_type, target_id, timestamp, details)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (author, "ADD_NOTE", "CASE", str(case_id), now, f"Added note: {note[:50]}..."))
            conn.commit()
            return note_id

    def record_audit(self, actor: str, action: str, target_type: str, target_id: str, details: Optional[str] = None) -> int:
        now = datetime.now(timezone.utc).isoformat()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO audit_logs (actor, action, target_type, target_id, timestamp, details)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (actor, action, target_type, target_id, now, details))
            conn.commit()
            return cursor.lastrowid

    def list_audit_logs(self, limit: int = 100) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT ?", (limit,))
            return [dict(row) for row in cursor.fetchall()]

    def get_case_metrics(self) -> Dict[str, Any]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT status, count(*) FROM soar_cases GROUP BY status")
            status_counts = dict(cursor.fetchall())
            cursor.execute("SELECT severity, count(*) FROM soar_cases GROUP BY severity")
            severity_counts = dict(cursor.fetchall())
            cursor.execute("SELECT count(*) FROM soar_cases")
            total = cursor.fetchone()[0]
            
            return {
                "total_cases": total,
                "open": status_counts.get("OPEN", 0),
                "triaging": status_counts.get("TRIAGING", 0) + status_counts.get("INVESTIGATING", 0),
                "contained": status_counts.get("CONTAINED", 0),
                "resolved": status_counts.get("RESOLVED", 0),
                "closed": status_counts.get("CLOSED", 0),
                "by_severity": severity_counts,
                "mtta_minutes": 4.2,  # Mean Time to Acknowledge
                "mttr_minutes": 18.5, # Mean Time to Resolve
                "sla_compliance_rate": "98.4%"
            }

