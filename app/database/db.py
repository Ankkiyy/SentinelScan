from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path
from typing import Any

DB_PATH = Path(os.getenv("SENTINELSCAN_DB_PATH", "sentinelscan.db"))


def get_connection() -> sqlite3.Connection:
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def init_db() -> None:
    with get_connection() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_url TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        connection.commit()


def save_scan(payload: dict[str, Any]) -> int:
    init_db()
    target_url = payload.get("target", "")
    payload_json = json.dumps(payload, ensure_ascii=False)

    with get_connection() as connection:
        cursor = connection.execute(
            "INSERT INTO scans (target_url, payload_json) VALUES (?, ?)",
            (target_url, payload_json),
        )
        connection.commit()
        return int(cursor.lastrowid)


def fetch_scan_by_id(scan_id: int) -> dict[str, Any] | None:
    init_db()

    with get_connection() as connection:
        row = connection.execute(
            "SELECT id, target_url, payload_json, created_at FROM scans WHERE id = ?",
            (scan_id,),
        ).fetchone()

    if row is None:
        return None

    payload = json.loads(row["payload_json"])
    payload.update(
        {
            "scan_id": row["id"],
            "created_at": row["created_at"],
            "target_url": row["target_url"],
        }
    )
    return payload
