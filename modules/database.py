"""
NetScan Pro - Database Module
"""

import sqlite3
import os
import uuid
from datetime import datetime
from modules.logger import get_logger

logger = get_logger(__name__)

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "db", "netscampro.db")


class Database:
    def __init__(self):
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        self.conn = sqlite3.connect(DB_PATH)
        self.conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self):
        cursor = self.conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                target TEXT NOT NULL,
                started_at TEXT NOT NULL,
                completed_at TEXT,
                status TEXT DEFAULT 'running'
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS hosts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                ip TEXT NOT NULL,
                hostname TEXT,
                os TEXT,
                status TEXT,
                FOREIGN KEY (session_id) REFERENCES sessions(id)
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host_id INTEGER NOT NULL,
                port INTEGER NOT NULL,
                protocol TEXT,
                state TEXT,
                service TEXT,
                version TEXT,
                FOREIGN KEY (host_id) REFERENCES hosts(id)
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS web_findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                host_ip TEXT NOT NULL,
                url TEXT NOT NULL,
                vuln_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT,
                evidence TEXT,
                recommendation TEXT,
                FOREIGN KEY (session_id) REFERENCES sessions(id)
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS cve_findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                host_ip TEXT NOT NULL,
                port INTEGER,
                service TEXT,
                cve_id TEXT NOT NULL,
                cvss_score REAL,
                severity TEXT,
                description TEXT,
                reference TEXT,
                FOREIGN KEY (session_id) REFERENCES sessions(id)
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS deleted_sessions (
                id TEXT PRIMARY KEY,
                deleted_at TEXT NOT NULL
            )
        """)
        self.conn.commit()

    # ── SESSION ──────────────────────────────────────────

    def create_session(self, target: str) -> str:
        session_id = str(uuid.uuid4())[:8]
        cursor = self.conn.cursor()
        cursor.execute(
            "INSERT INTO sessions (id, target, started_at) VALUES (?, ?, ?)",
            (session_id, target, datetime.now().isoformat())
        )
        self.conn.commit()
        return session_id

    def complete_session(self, session_id: str):
        cursor = self.conn.cursor()
        cursor.execute(
            "UPDATE sessions SET completed_at=?, status=? WHERE id=?",
            (datetime.now().isoformat(), "completed", session_id)
        )
        self.conn.commit()

    def get_all_sessions(self):
        """Return all sessions EXCLUDING deleted ones."""
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT * FROM sessions
            WHERE id NOT IN (SELECT id FROM deleted_sessions)
            ORDER BY started_at DESC
        """)
        return [dict(row) for row in cursor.fetchall()]

    def get_session(self, session_id: str):
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM sessions WHERE id=?", (session_id,))
        row = cursor.fetchone()
        return dict(row) if row else None

    def delete_session(self, session_id: str):
        """
        Soft-delete a session — marks it in deleted_sessions table
        so it stays gone even after server restarts.
        """
        cursor = self.conn.cursor()
        # Record deletion permanently
        cursor.execute(
            "INSERT OR REPLACE INTO deleted_sessions (id, deleted_at) VALUES (?, ?)",
            (session_id, datetime.now().isoformat())
        )
        # Also hard delete data
        cursor.execute("SELECT id FROM hosts WHERE session_id=?", (session_id,))
        host_ids = [row[0] for row in cursor.fetchall()]
        for host_id in host_ids:
            cursor.execute("DELETE FROM ports WHERE host_id=?", (host_id,))
        cursor.execute("DELETE FROM hosts WHERE session_id=?", (session_id,))
        cursor.execute("DELETE FROM web_findings WHERE session_id=?", (session_id,))
        cursor.execute("DELETE FROM cve_findings WHERE session_id=?", (session_id,))
        cursor.execute("DELETE FROM sessions WHERE id=?", (session_id,))
        self.conn.commit()

    # ── HOSTS ────────────────────────────────────────────

    def save_hosts(self, session_id: str, hosts: list):
        cursor = self.conn.cursor()
        for host in hosts:
            cursor.execute(
                "INSERT INTO hosts (session_id, ip, hostname, os, status) VALUES (?, ?, ?, ?, ?)",
                (session_id, host.get("ip"), host.get("hostname"),
                 host.get("os"), host.get("status", "up"))
            )
            host_id = cursor.lastrowid
            for port in host.get("ports", []):
                cursor.execute(
                    "INSERT INTO ports (host_id, port, protocol, state, service, version) VALUES (?, ?, ?, ?, ?, ?)",
                    (host_id, port.get("port"), port.get("protocol", "tcp"),
                     port.get("state", "open"), port.get("service"), port.get("version"))
                )
        self.conn.commit()

    def get_hosts(self, session_id: str) -> list:
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM hosts WHERE session_id=?", (session_id,))
        hosts = []
        for host_row in cursor.fetchall():
            host = dict(host_row)
            cursor.execute("SELECT * FROM ports WHERE host_id=?", (host["id"],))
            host["ports"] = [dict(p) for p in cursor.fetchall()]
            hosts.append(host)
        return hosts

    # ── WEB FINDINGS ─────────────────────────────────────

    def save_web_findings(self, session_id: str, findings: list):
        cursor = self.conn.cursor()
        for f in findings:
            cursor.execute(
                """INSERT INTO web_findings
                   (session_id, host_ip, url, vuln_type, severity,
                    description, evidence, recommendation)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (session_id, f.get("host_ip"), f.get("url"),
                 f.get("vuln_type"), f.get("severity"),
                 f.get("description"), f.get("evidence"),
                 f.get("recommendation"))
            )
        self.conn.commit()

    def get_web_findings(self, session_id: str) -> list:
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM web_findings WHERE session_id=?", (session_id,))
        return [dict(row) for row in cursor.fetchall()]

    # ── CVE FINDINGS ─────────────────────────────────────

    def save_cve_findings(self, session_id: str, findings: list):
        cursor = self.conn.cursor()
        for f in findings:
            cursor.execute(
                """INSERT INTO cve_findings
                   (session_id, host_ip, port, service, cve_id,
                    cvss_score, severity, description, reference)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (session_id, f.get("host_ip"), f.get("port"),
                 f.get("service"), f.get("cve_id"),
                 f.get("cvss_score"), f.get("severity"),
                 f.get("description"), f.get("reference"))
            )
        self.conn.commit()

    def get_cve_findings(self, session_id: str) -> list:
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM cve_findings WHERE session_id=?", (session_id,))
        return [dict(row) for row in cursor.fetchall()]

    # ── SEVERITY COUNTS ───────────────────────────────────

    def get_severity_counts(self, session_id: str = None) -> dict:
        cursor = self.conn.cursor()
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "None": 0}

        if session_id:
            cursor.execute("SELECT severity FROM web_findings WHERE session_id=?", (session_id,))
            web = cursor.fetchall()
            cursor.execute("SELECT severity FROM cve_findings WHERE session_id=?", (session_id,))
            cve = cursor.fetchall()
        else:
            # Exclude findings from deleted sessions
            cursor.execute("""
                SELECT severity FROM web_findings
                WHERE session_id NOT IN (SELECT id FROM deleted_sessions)
            """)
            web = cursor.fetchall()
            cursor.execute("""
                SELECT severity FROM cve_findings
                WHERE session_id NOT IN (SELECT id FROM deleted_sessions)
            """)
            cve = cursor.fetchall()

        for row in web + cve:
            sev = row[0] if row[0] else "None"
            if sev in counts:
                counts[sev] += 1
        return counts

    def get_total_findings(self, session_id: str = None) -> int:
        counts = self.get_severity_counts(session_id)
        return sum(counts.values())


    def fix_stale_sessions(self):
        """
        Mark sessions that have been 'running' for over 30 minutes as error.
        Prevents sessions from staying stuck as RUNNING forever.
        """
        cursor = self.conn.cursor()
        cursor.execute("""
            UPDATE sessions
            SET status='error', completed_at=?
            WHERE status='running'
            AND started_at < datetime('now', '-30 minutes')
        """, (datetime.now().isoformat(),))
        self.conn.commit()

    def close(self):
        self.conn.close()
