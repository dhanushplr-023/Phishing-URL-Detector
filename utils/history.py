import sqlite3
from pathlib import Path

DATABASE_PATH = "database/scans.db"


# ==========================================
# CREATE DATABASE
# ==========================================

def initialize_database():

    Path("database").mkdir(
        exist_ok=True
    )

    connection = sqlite3.connect(
        DATABASE_PATH
    )

    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            url TEXT NOT NULL,

            score INTEGER NOT NULL,

            status TEXT NOT NULL,

            scan_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    connection.commit()
    connection.close()


# ==========================================
# SAVE SCAN
# ==========================================

def save_scan(url, score, status):

    connection = sqlite3.connect(
        DATABASE_PATH
    )

    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO scans
        (
            url,
            score,
            status
        )
        VALUES (?, ?, ?)
    """, (
        url,
        score,
        status
    ))

    connection.commit()
    connection.close()


# ==========================================
# GET ALL SCANS
# ==========================================

def get_all_scans():

    connection = sqlite3.connect(
        DATABASE_PATH
    )

    connection.row_factory = sqlite3.Row

    cursor = connection.cursor()

    cursor.execute("""
        SELECT *
        FROM scans
        ORDER BY scan_time DESC
    """)

    rows = cursor.fetchall()

    connection.close()

    return [
        dict(row)
        for row in rows
    ]


# ==========================================
# GET STATS
# ==========================================

def get_statistics():

    connection = sqlite3.connect(
        DATABASE_PATH
    )

    cursor = connection.cursor()

    cursor.execute(
        "SELECT COUNT(*) FROM scans"
    )

    total = cursor.fetchone()[0]

    cursor.execute("""
        SELECT COUNT(*)
        FROM scans
        WHERE status='SAFE'
    """)

    safe = cursor.fetchone()[0]

    cursor.execute("""
        SELECT COUNT(*)
        FROM scans
        WHERE status='WARNING'
    """)

    warning = cursor.fetchone()[0]

    cursor.execute("""
        SELECT COUNT(*)
        FROM scans
        WHERE status='DANGER'
    """)

    danger = cursor.fetchone()[0]

    connection.close()

    return {
        "total": total,
        "safe": safe,
        "warning": warning,
        "danger": danger
    }


# ==========================================
# DELETE ALL SCANS
# ==========================================

def clear_history():

    connection = sqlite3.connect(
        DATABASE_PATH
    )

    cursor = connection.cursor()

    cursor.execute(
        "DELETE FROM scans"
    )

    connection.commit()
    connection.close()