"""Persistencia del poller de Trend Vision One: cursor + deduplicacion.

Destino en el repo: src/tv1_state.py

Sigue el patron de src/state.py (sqlite3 stdlib + asyncio.to_thread, sin deps
nuevas) y reutiliza su _connect/_now. Vive en la misma DB (state.db).

Tablas:
  tv1_poller_state      - key/value; hoy una sola key: 'cursor' (ISO8601 del
                          ultimo ciclo exitoso). Si la API falla, el cursor NO
                          avanza y el proximo ciclo re-consulta la misma ventana.
  tv1_processed_alerts  - Workbench IDs ya procesados. Necesaria porque el
                          poller consulta con solape hacia atras (a proposito,
                          para no perder alertas en el borde de la ventana),
                          asi que VA a ver repetidas: el INSERT OR IGNORE es
                          el arbitro de "nueva vs ya vista".
"""
from __future__ import annotations

import asyncio
import logging

from src.state import _connect, _now

logger = logging.getLogger("soc-l1")

TV1_SCHEMA = """
CREATE TABLE IF NOT EXISTS tv1_poller_state (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tv1_processed_alerts (
    alert_id TEXT PRIMARY KEY,
    processed_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_tv1_processed_at ON tv1_processed_alerts(processed_at);
"""

_CURSOR_KEY = "cursor"
# Retencion del registro de dedup: mas que suficiente mientras el solape de
# polling sea de minutos. Se purga oportunisticamente en cada init.
_PROCESSED_RETENTION_DAYS = 30


# ===== Sync helpers (corren bajo asyncio.to_thread) =====


def _init_tv1_sync(db_path: str) -> None:
    with _connect(db_path) as conn:
        conn.executescript(TV1_SCHEMA)
        # Purga oportunistica de IDs viejos (evita crecimiento infinito)
        conn.execute(
            "DELETE FROM tv1_processed_alerts "
            f"WHERE processed_at < datetime('now', '-{_PROCESSED_RETENTION_DAYS} days')"
        )


def _get_cursor_sync(db_path: str) -> str | None:
    with _connect(db_path) as conn:
        row = conn.execute(
            "SELECT value FROM tv1_poller_state WHERE key = ?", (_CURSOR_KEY,)
        ).fetchone()
        return row["value"] if row else None


def _set_cursor_sync(db_path: str, value: str) -> None:
    with _connect(db_path) as conn:
        conn.execute(
            "INSERT INTO tv1_poller_state (key, value, updated_at) VALUES (?, ?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
            (_CURSOR_KEY, value, _now()),
        )


def _mark_processed_sync(db_path: str, alert_id: str) -> bool:
    """INSERT OR IGNORE del Workbench ID. True si es nuevo, False si ya estaba."""
    with _connect(db_path) as conn:
        cur = conn.execute(
            "INSERT OR IGNORE INTO tv1_processed_alerts (alert_id, processed_at) VALUES (?, ?)",
            (alert_id, _now()),
        )
        return cur.rowcount > 0


# ===== Async wrappers publicas =====


async def init_tv1_tables(db_path: str) -> None:
    """Crea las tablas del poller si no existen. Llamar una vez al startup."""
    await asyncio.to_thread(_init_tv1_sync, db_path)
    logger.info("tv1_state: tablas del poller inicializadas en %s", db_path)


async def get_tv1_cursor(db_path: str) -> str | None:
    """ISO8601 del ultimo ciclo exitoso, o None si nunca corrio."""
    return await asyncio.to_thread(_get_cursor_sync, db_path)


async def set_tv1_cursor(db_path: str, value: str) -> None:
    """Avanza el cursor. Llamar SOLO tras un ciclo exitoso."""
    await asyncio.to_thread(_set_cursor_sync, db_path, value)


async def mark_tv1_processed(db_path: str, alert_id: str) -> bool:
    """Registra el Workbench ID. True si es nuevo (procesar), False si es repetido (skip)."""
    return await asyncio.to_thread(_mark_processed_sync, db_path, alert_id)
