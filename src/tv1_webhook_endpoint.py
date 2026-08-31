"""Endpoint FastAPI que recibe el webhook de Trend Vision One.

Destino en el repo: src/tv1_webhook_endpoint.py

SEGURIDAD (importante): a diferencia del poller (que sale a buscar y verifica
el destino via TLS), este endpoint ESPERA conexiones entrantes -> es una puerta
al mundo y hay que autenticar el ORIGEN. El webhook de Workbench NO ofrece firma
HMAC (a diferencia del de Conformity), asi que aplicamos defensa en capas:

  1. Token en la URL: /webhook/tv1-alert/{token}. Solo Trend (configurado con
     esa URL) y nosotros conocemos el token. Comparacion en tiempo constante.
  2. Allowlist de IPs (opcional): restringe a los rangos de origen de Trend.
  3. HTTPS: el token viaja en la URL, asi que en prod SIEMPRE detras de TLS.

Esto es MENOS fuerte que el HMAC del webhook de Wazuh (que ademas valida
integridad del payload). Es una limitacion del webhook de Trend, documentada.
Si Trend confirma que hay firma, se puede endurecer despues.
"""
from __future__ import annotations

import ipaddress
import logging
import secrets
from typing import Any, Awaitable, Callable

from fastapi import APIRouter, Request, Response, status

from src.models import NormalizedAlert
from src.normalize_tv1_webhook import normalize_tv1_webhook

logger = logging.getLogger("soc-l1")

ProcessAlertFn = Callable[[NormalizedAlert, Any], Awaitable[None]]


def _client_ip_allowed(request: Request, allowed_cidrs: list[str]) -> bool:
    """True si la IP del cliente cae en algun CIDR de la allowlist.

    Lista vacia = sin restriccion de IP (solo protege el token). Respeta
    X-Forwarded-For por si hay reverse proxy delante.
    """
    if not allowed_cidrs:
        return True
    fwd = request.headers.get("x-forwarded-for")
    client_ip = fwd.split(",")[0].strip() if fwd else (
        request.client.host if request.client else ""
    )
    try:
        addr = ipaddress.ip_address(client_ip)
    except ValueError:
        return False
    for cidr in allowed_cidrs:
        try:
            if addr in ipaddress.ip_network(cidr.strip(), strict=False):
                return True
        except ValueError:
            continue
    return False


def build_tv1_webhook_router(
    expected_token: str,
    process_alert_fn: ProcessAlertFn,
    settings: Any,
    allowed_cidrs: list[str] | None = None,
) -> APIRouter:
    """Crea el router del webhook. Se incluye en la app FastAPI del proyecto.

    Args:
        expected_token: el token secreto que debe venir en la URL.
        process_alert_fn: el callback del pipeline (_run_triage_in_background).
        settings: se pasa tal cual al callback.
        allowed_cidrs: rangos IP permitidos (vacio = sin restriccion).
    """
    router = APIRouter()
    cidrs = allowed_cidrs or []

    @router.post("/webhook/tv1-alert/{token}")
    async def receive_tv1_webhook(token: str, request: Request) -> Response:
        # 1. Token: comparacion en tiempo constante (evita timing attacks)
        if not expected_token or not secrets.compare_digest(token, expected_token):
            logger.warning("🛑 tv1-webhook: token invalido (rechazado 403)")
            return Response(status_code=status.HTTP_403_FORBIDDEN)

        # 2. Allowlist de IP
        if not _client_ip_allowed(request, cidrs):
            logger.warning("🛑 tv1-webhook: IP no permitida (rechazado 403)")
            return Response(status_code=status.HTTP_403_FORBIDDEN)

        # 3. Parseo del body
        try:
            body: dict[str, Any] = await request.json()
        except Exception:
            logger.warning("🛑 tv1-webhook: body no es JSON valido (400)")
            return Response(status_code=status.HTTP_400_BAD_REQUEST)

        # 4. Normalizacion
        try:
            alert = normalize_tv1_webhook(body)
        except Exception:
            logger.exception("🛑 tv1-webhook: fallo la normalizacion (400)")
            return Response(status_code=status.HTTP_400_BAD_REQUEST)

        logger.info(
            "alert accepted | id=%s source=%s severity=%s host=%s users=%s files=%s",
            alert.alert_id, alert.source, alert.severity_source,
            alert.device.hostname, len(alert.users_involved), len(alert.files),
        )

        # 5. Disparar el pipeline (igual que el poller y el webhook de Wazuh)
        if getattr(settings, "enable_triage", False):
            try:
                await process_alert_fn(alert, settings)
            except Exception:
                logger.exception("tv1-webhook: pipeline fallo id=%s", alert.alert_id)
        else:
            logger.info("tv1-webhook: ENABLE_TRIAGE=false - alerta %s solo logueada",
                        alert.alert_id)

        # 202: recibido y encolado. Respondemos rapido para no hacer esperar a Trend.
        return Response(status_code=status.HTTP_202_ACCEPTED)

    return router
