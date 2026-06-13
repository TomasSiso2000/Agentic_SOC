"""Poller de Trend Vision One: trae Workbench alerts y las inyecta al pipeline.

Destino en el repo: src/tv1_poller.py

Diseno:
- Background task asyncio lanzada desde el lifespan de main.py.
- Cada ciclo: leer cursor -> consultar /v3.0/workbench/alerts desde
  (cursor - solape) -> dedup por Workbench ID -> normalize_tv1 -> pipeline.
- El pipeline se inyecta como callback (process_alert_fn) para evitar el
  import circular con main.py. En produccion es _run_triage_in_background.
- El cursor avanza SOLO si el ciclo termino bien: si la API de TV1 fallo,
  el proximo ciclo re-consulta la misma ventana (no se pierden alertas).
- El solape hacia atras es deliberado (alertas que llegan justo en el borde
  de la ventana); la tabla tv1_processed_alerts deduplica las repetidas.
- Las alertas se procesan secuencialmente (await, no create_task): un poller
  no tiene el apuro del webhook (que responde 202) y asi una rafaga de
  alertas no dispara N pipelines OpenAI en paralelo.
- El loop NUNCA muere por una excepcion de un ciclo (salvo CancelledError,
  que es el shutdown ordenado del servicio).
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import Awaitable, Callable, Protocol

from src.config import Settings
from src.models import NormalizedAlert
from src.normalize_tv1 import normalize_tv1
from src.tools.visionone import VisionOneClient, VisionOneError, WorkbenchAlert
from src.tv1_state import get_tv1_cursor, mark_tv1_processed, set_tv1_cursor

logger = logging.getLogger("soc-l1")

# Orden de severidades para construir el filtro server-side "minimo X".
_SEVERITY_ORDER = ["low", "medium", "high", "critical"]

# Callback que dispara el pipeline: en produccion, main._run_triage_in_background
ProcessAlertFn = Callable[[NormalizedAlert, Settings], Awaitable[None]]


def build_severity_filter(min_severity: str) -> str | None:
    """'medium' -> "severity eq 'medium' or severity eq 'high' or severity eq 'critical'".

    Vacio o invalido -> None (sin filtro server-side: se traen todas).
    """
    sev = (min_severity or "").strip().lower()
    if not sev:
        return None
    if sev not in _SEVERITY_ORDER:
        logger.warning(
            "tv1: TV1_MIN_SEVERITY=%r invalido (esperado: %s) - sin filtro",
            min_severity, "/".join(_SEVERITY_ORDER),
        )
        return None
    levels = _SEVERITY_ORDER[_SEVERITY_ORDER.index(sev):]
    return " or ".join(f"severity eq '{s}'" for s in levels)


async def poll_once(
    settings: Settings,
    client: VisionOneClient,
    process_alert_fn: ProcessAlertFn,
) -> tuple[int, int]:
    """Un ciclo de polling. Devuelve (alertas_traidas, alertas_nuevas).

    Levanta VisionOneError si la API fallo (el caller decide; el cursor NO
    se avanzo, asi que no se pierde nada).
    """
    db = settings.state_db_path
    cycle_start = datetime.now(timezone.utc)

    cursor = await get_tv1_cursor(db)
    if cursor:
        window_start = datetime.fromisoformat(cursor) - timedelta(
            seconds=settings.tv1_poll_overlap_seconds
        )
    else:
        # Primer ciclo: ventana corta hacia atras. NO hacemos backfill historico
        # a proposito: arrancar el servicio no debe disparar el pipeline (y la
        # facturacion de OpenAI) para todo el backlog de Workbench.
        window_start = cycle_start - timedelta(
            minutes=settings.tv1_initial_lookback_minutes
        )
        logger.info(
            "🛰️ tv1: primer ciclo - lookback inicial de %d min (sin backfill)",
            settings.tv1_initial_lookback_minutes,
        )

    alerts = await client.get_workbench_alerts(
        start=window_start,
        tmv1_filter=build_severity_filter(settings.tv1_min_severity),
    )

    new_count = 0
    for wb in alerts:
        if not await mark_tv1_processed(db, wb.id):
            continue  # repetida por el solape: ya procesada en un ciclo anterior
        new_count += 1
        await _process_one(wb, settings, process_alert_fn)

    # Ciclo exitoso: el cursor avanza al inicio de ESTE ciclo (no a "ahora"),
    # asi el proximo ciclo cubre tambien lo que llego mientras procesabamos.
    await set_tv1_cursor(db, cycle_start.isoformat())

    if alerts:
        logger.info(
            "✅ TV1_POLL | fetched=%d new=%d window_start=%s",
            len(alerts), new_count, window_start.isoformat(timespec="seconds"),
        )
    return len(alerts), new_count


async def _process_one(
    wb: WorkbenchAlert, settings: Settings, process_alert_fn: ProcessAlertFn
) -> None:
    """Normaliza una Workbench alert y la manda al pipeline.

    Cualquier error queda contenido a ESTA alerta: el ciclo sigue con las demas
    (el ID ya quedo marcado como procesado: semantica at-most-once).
    """
    try:
        # Round-trip a dict con las keys originales de la API (camelCase) para
        # que normalize_tv1 reciba el mismo shape que el JSON crudo.
        raw = wb.model_dump(by_alias=True, mode="json")
        alert = normalize_tv1(raw)
    except Exception:
        logger.exception("tv1: normalize fallo para workbench id=%s", wb.id)
        return

    logger.info(
        "alert accepted | id=%s source=%s severity=%s host=%s users=%s files=%s",
        alert.alert_id,
        alert.source,
        alert.severity_source,
        alert.device.hostname,
        len(alert.users_involved),
        len(alert.files),
    )

    if not settings.enable_triage:
        logger.info("tv1: ENABLE_TRIAGE=false - alerta %s solo logueada", alert.alert_id)
        return

    try:
        await process_alert_fn(alert, settings)
    except Exception:
        # _run_triage_in_background ya maneja sus errores; esto es el cinturon
        # por si el callback cambia en el futuro.
        logger.exception("tv1: pipeline fallo para alerta id=%s", alert.alert_id)


async def run_tv1_poller(settings: Settings, process_alert_fn: ProcessAlertFn) -> None:
    """Loop infinito del poller. Lanzar con asyncio.create_task desde el lifespan.

    Shutdown: cancelar la task (CancelledError corta el loop y cierra el client).
    """
    if not settings.tv1_configured():
        logger.warning(
            "tv1: poller deshabilitado - faltan TV1_BASE_URL y/o TV1_API_TOKEN"
        )
        return

    client = VisionOneClient(
        base_url=settings.tv1_base_url, token=settings.tv1_api_token
    )
    logger.info(
        "🛰️ tv1: poller iniciado | interval=%ds overlap=%ds min_severity=%r",
        settings.tv1_poll_interval_seconds,
        settings.tv1_poll_overlap_seconds,
        settings.tv1_min_severity or "todas",
    )
    try:
        while True:
            try:
                await poll_once(settings, client, process_alert_fn)
            except asyncio.CancelledError:
                raise
            except VisionOneError as e:
                # 401: token vencido -> esto necesita un humano, log fuerte.
                level = logging.ERROR if e.status_code == 401 else logging.WARNING
                logger.log(
                    level,
                    "🛑 tv1: ciclo fallido (%s) - cursor NO avanzado, reintento en %ds",
                    e, settings.tv1_poll_interval_seconds,
                )
            except Exception:
                logger.exception(
                    "🛑 tv1: error inesperado en ciclo - reintento en %ds",
                    settings.tv1_poll_interval_seconds,
                )
            await asyncio.sleep(settings.tv1_poll_interval_seconds)
    except asyncio.CancelledError:
        logger.info("tv1: poller detenido (shutdown)")
        raise
    finally:
        await client.aclose()
