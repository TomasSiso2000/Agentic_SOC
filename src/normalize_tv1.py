"""Normaliza Workbench alerts de Trend Vision One a NormalizedAlert.

Destino en el repo: src/normalize_tv1.py

Espejo de normalize.py pero para la fuente TV1: el poller (Fase 3) recibe el
JSON crudo de /v3.0/workbench/alerts y esta funcion lo convierte al schema
comun que consumen los agents. Los agents nunca ven el formato raw de TV1.

Requiere agregar "tv1_workbench" al Literal AlertSource en src/models.py.
"""
from __future__ import annotations

import ipaddress
from typing import Any

from src.models import (
    Device,
    FileEvidence,
    NormalizedAlert,
    Network,
    Threat,
    User,
    WazuhRule,
)
from src.tools.visionone import HostEntityValue, WorkbenchAlert

# --- Cuentas built-in de Windows: NO van al lookup LDAP del Enricher ---
# Prefijos de dominio "de sistema" (incluye variantes de Windows en espanol).
_BUILTIN_DOMAIN_PREFIXES = (
    "nt authority\\",
    "autoridad nt\\",          # Windows es-ES / es-AR
    "nt service\\",
    "builtin\\",
    "window manager\\",
    "font driver host\\",
)
# Nombres de cuenta de sistema (sin dominio), case-insensitive.
_BUILTIN_ACCOUNT_NAMES = {
    "system",
    "sistema",
    "local service",
    "servicio local",
    "network service",
    "servicio de red",
    "anonymous logon",
    "inicio de sesion anonimo",
}

# Severidad TV1 -> Severity interno. Coinciden 1:1; el fallback "medium"
# cubre valores futuros desconocidos sin romper el pipeline.
_SEVERITY_MAP = {
    "info": "informational",
    "informational": "informational",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
}

# Nivel Wazuh sintetico por severidad, consistente con _severity_from_level()
# de normalize.py (>=12 critical, >=9 high, >=6 medium). Ayuda a que cualquier
# logica basada en level se comporte coherente aunque la fuente no sea Wazuh.
_SYNTHETIC_LEVEL = {
    "informational": 2,
    "low": 4,
    "medium": 7,
    "high": 10,
    "critical": 13,
}


def _parse_account(raw_account: str) -> User | None:
    """'DOMINIO\\usuario' | 'usuario@dominio' | 'usuario' -> User, o None si es built-in.

    Filtramos cuentas de sistema (SYSTEM, LOCAL SERVICE, etc.) y cuentas de
    maquina (terminan en $): no existen como usuarios en AD y solo harian
    ruido/fallos en el ldap_search_user del Enricher.
    """
    value = (raw_account or "").strip()
    if not value:
        return None

    lowered = value.lower()
    if lowered.startswith(_BUILTIN_DOMAIN_PREFIXES):
        return None

    domain: str | None = None
    sam = value
    if "\\" in value:
        domain, _, sam = value.partition("\\")
    elif "@" in value:
        sam, _, domain = value.partition("@")

    sam = sam.strip()
    if not sam:
        return None
    if sam.lower() in _BUILTIN_ACCOUNT_NAMES:
        return None
    if sam.endswith("$"):  # cuenta de maquina (COMPUTADORA$)
        return None

    return User(sam=sam, domain=(domain or None), role="event_user")


def _classify_host_ips(ips: list[str]) -> tuple[str | None, str | None]:
    """Separa las IPs del host en (interna, externa).

    Primera IPv4 privada -> interna; primera IP global -> externa.
    Se ignoran link-local (fe80::, 169.254.x) y valores no parseables.
    """
    internal: str | None = None
    external: str | None = None
    for raw_ip in ips:
        try:
            addr = ipaddress.ip_address(raw_ip)
        except ValueError:
            continue
        if addr.is_link_local or addr.is_loopback:
            continue
        if addr.is_private and internal is None:
            internal = raw_ip
        elif addr.is_global and external is None:
            external = raw_ip
    return internal, external


def _device_from_alert(alert: WorkbenchAlert) -> Device:
    """Primer host del impactScope -> Device. Sin host, Device vacio."""
    for entity in alert.impact_scope.entities:
        if entity.is_host and isinstance(entity.entity_value, HostEntityValue):
            internal, external = _classify_host_ips(entity.entity_value.ips)
            return Device(
                hostname=entity.entity_value.name or None,
                internal_ip=internal,
                external_ip=external,
            )
    return Device()


def _files_from_indicators(alert: WorkbenchAlert) -> list[FileEvidence]:
    """Indicators de archivo -> FileEvidence.

    - type 'fullpath'           -> path (+ name derivado del basename)
    - type/field con 'sha256'   -> sha256
    Se deduplican por valor (TV1 suele repetir el mismo path en N eventos).
    """
    files: list[FileEvidence] = []
    seen: set[str] = set()
    for ind in alert.indicators:
        if not isinstance(ind.value, str) or not ind.value:
            continue
        key = f"{ind.type}:{ind.value}"
        if key in seen:
            continue

        ind_kind = f"{ind.type} {ind.field}".lower()
        if ind.type == "fullpath":
            name = ind.value.replace("\\", "/").rsplit("/", 1)[-1] or None
            files.append(FileEvidence(name=name, path=ind.value))
            seen.add(key)
        elif "sha256" in ind_kind:
            files.append(FileEvidence(sha256=ind.value.lower()))
            seen.add(key)
    return files


def _dst_ip_from_indicators(alert: WorkbenchAlert) -> str | None:
    """Primer indicator de tipo IP (si lo hay) como IP de destino."""
    for ind in alert.indicators:
        if ind.type == "ip" and isinstance(ind.value, str) and ind.value:
            return ind.value
    return None


def normalize_tv1(raw_payload: dict[str, Any]) -> NormalizedAlert:
    """Convierte el JSON crudo de una Workbench alert en un NormalizedAlert."""
    alert = WorkbenchAlert.model_validate(raw_payload)

    severity = _SEVERITY_MAP.get(alert.severity.lower(), "medium")

    # Usuarios: cuentas del impactScope, filtrando built-ins y de maquina.
    # Deduplicado por (sam, domain) preservando orden.
    users: list[User] = []
    seen_users: set[tuple[str, str | None]] = set()
    for raw_account in alert.account_names():
        user = _parse_account(raw_account)
        if user is None:
            continue
        dedup_key = (user.sam.lower(), (user.domain or "").lower() or None)
        if dedup_key in seen_users:
            continue
        seen_users.add(dedup_key)
        users.append(user)

    device = _device_from_alert(alert)

    network = Network(
        src_ip_internal=device.internal_ip,
        src_ip_external=device.external_ip,
        dst_ip=_dst_ip_from_indicators(alert),
    )

    threat = Threat(
        provider="Trend Vision One",
        display_name=alert.model or None,
        incident_id=alert.incident_id or None,
        alert_url=alert.workbench_link or None,
    )

    # El "detection model" de TV1 ocupa el lugar de la rule de Wazuh.
    matched_names = [r.name for r in alert.matched_rules if r.name]
    wazuh_rule = WazuhRule(
        id=None,
        level=_SYNTHETIC_LEVEL[severity],
        description=alert.model or (matched_names[0] if matched_names else "TV1 Workbench alert"),
        groups=["tv1"] + ([alert.alert_provider.lower()] if alert.alert_provider else []),
    )

    title = alert.model or alert.description or "TV1 Workbench alert"

    return NormalizedAlert(
        source="tv1_workbench",
        alert_id=alert.id,
        timestamp=alert.created_date_time.isoformat(),
        wazuh_rule=wazuh_rule,
        severity_source=severity,
        title=title,
        category=f"tv1_{alert.model_type}" if alert.model_type else "tv1_workbench",
        device=device,
        users_involved=users,
        files=_files_from_indicators(alert),
        network=network,
        threat=threat,
        raw=raw_payload,
    )
