import sqlite3
import json
from datetime import datetime, timezone

DB_PATH = "threat_intel.db"


# Connect to database
def db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con


# Create database tables
def init_db():
    with db() as con:

        # 1. Community reports
        con.execute("""
            CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url_key TEXT NOT NULL UNIQUE,
                reason TEXT NOT NULL,
                reports_count INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL
            )
        """)

        # 2. Website scan history
        con.execute("""
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scanned_url TEXT NOT NULL,
                final_url TEXT,
                risk_score INTEGER NOT NULL,
                risk_level TEXT NOT NULL,
                findings TEXT,
                scanned_at TEXT NOT NULL
            )
        """)

        # Faster history searches
        con.execute("""
            CREATE INDEX IF NOT EXISTS idx_scan_date
            ON scan_history(scanned_at)
        """)


# Save scan results
def save_scan(data):
    with db() as con:
        cursor = con.execute("""
            INSERT INTO scan_history (
                scanned_url,
                final_url,
                risk_score,
                risk_level,
                findings,
                scanned_at
            )
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            data["scanned_url"],
            data.get("final_url"),
            data["risk_score"],
            data["risk_level"],
            json.dumps(data["findings"]),
            data["scanned_at"]
        ))

        return cursor.lastrowid


# Get previous scans
def get_scan_history(limit=50):
    with db() as con:
        rows = con.execute("""
            SELECT * FROM scan_history
            ORDER BY id DESC
            LIMIT ?
        """, (limit,)).fetchall()

        results = []

        for row in rows:
            item = dict(row)
            item["findings"] = json.loads(item["findings"] or "[]")
            results.append(item)

        return results


# Get one scan using its ID
def get_scan_by_id(scan_id):
    with db() as con:
        row = con.execute("""
            SELECT * FROM scan_history
            WHERE id = ?
        """, (scan_id,)).fetchone()

        if row is None:
            return None

        item = dict(row)
        item["findings"] = json.loads(item["findings"] or "[]")
        return item