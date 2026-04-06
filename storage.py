import sqlite3

DB_PATH = "/app/ids/ids.db"

def init_ids_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS ids_log (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT DEFAULT (datetime('now','localtime')),
            ip          TEXT,
            method      TEXT,
            path        TEXT,
            payload     TEXT,
            score       INTEGER,
            decision    TEXT,
            factors     TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS ip_history (
            ip           TEXT PRIMARY KEY,
            attempts     INTEGER DEFAULT 0,
            last_seen    TEXT,
            banned_until TEXT
        )
    """)
    conn.commit()
    conn.close()

def log_request(ip, method, path, payload, score, decision, factors):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        INSERT INTO ids_log (ip, method, path, payload, score, decision, factors)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (ip, method, path, str(payload)[:500], score, decision, factors))
    conn.commit()
    conn.close()

def get_ip_attempts(ip):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    row = conn.execute(
        "SELECT attempts, banned_until FROM ip_history WHERE ip=?", (ip,)
    ).fetchone()
    conn.close()
    return row

def increment_ip_attempts(ip):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        INSERT INTO ip_history (ip, attempts, last_seen)
        VALUES (?, 1, datetime('now','localtime'))
        ON CONFLICT(ip) DO UPDATE SET
            attempts  = attempts + 1,
            last_seen = datetime('now','localtime')
    """, (ip,))
    conn.commit()
    conn.close()

def ban_ip(ip, minutes):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        INSERT INTO ip_history (ip, attempts, banned_until)
        VALUES (?, 1, datetime('now','localtime', ?))
        ON CONFLICT(ip) DO UPDATE SET
            banned_until = datetime('now','localtime', ?)
    """, (ip, f"+{minutes} minutes", f"+{minutes} minutes"))
    conn.commit()
    conn.close()

def is_ip_banned(ip):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    row = conn.execute(
        "SELECT banned_until FROM ip_history WHERE ip=?", (ip,)
    ).fetchone()
    conn.close()
    if not row or not row["banned_until"]:
        return False
    check = sqlite3.connect(DB_PATH)
    result = check.execute(
        "SELECT datetime('now','localtime') < ? as still_banned",
        (row["banned_until"],)
    ).fetchone()
    check.close()
    return bool(result and result[0])