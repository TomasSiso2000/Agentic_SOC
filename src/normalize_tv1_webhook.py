"""Parser + normalizer del WEBHOOK de Trend Vision One (Workbench alerts).

Destino en el repo: src/normalize_tv1_webhook.py

IMPORTANTE: el webhook manda un formato TOTALMENTE distinto al de la API v3.0.
Este modulo NO comparte modelos con visionone.py (que es para la API). Por eso
es un archivo aparte. La diferencia clave, con el poller vs webhook:

  API v3.0 (poller):  JSON anidado limpio, campos camelCase (severity, id...)
  Webhook:            envoltorio {businessId, data, title, type} donde 'data'
                      es un STRING que contiene otro JSON, con campos "humanos"
                      ("Model severity", "Workbench ID", "Highlighted Objects").

Limitaciones del webhook respecto a la API (datos reales, no suposiciones):
  - Trae file_sha1, NO file_sha256 (la API daba sha256).
  - "Highlighted Objects" viene topeado (la doc dice max 10; hay Total/Display Count).
  - Requiere activar 'Expanded impact scope details' e 'Include highlighted objects'.

Reutiliza los helpers de mapeo de src/normalize_tv1.py (category, verdict,
built-ins) para no duplicar la logica ya validada en la Fase 5.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from src.models import (
    Device,
    FileEvidence,
    Network,
    NormalizedAlert,
    Threat,
    User,
    WazuhRule,
)
# Reutilizamos la logica de mapeo ya probada en la Fase 5
from src.normalize_tv1 import (
    _BUILTIN_ACCOUNT_NAMES,
    _BUILTIN_DOMAIN_PREFIXES,
    _CATEGORY_KEYWORDS,
    _SYNTHETIC_LEVEL,
    _classify_host_ips,
)

logger = logging.getLogger("soc-l1")

_SEVERITY_MAP = {
    "info": "informational", "informational": "informational",
    "low": "low", "medium": "medium", "high": "high", "critical": "critical",
}


# ---------------------------------------------------------------------------
# Modelos del formato webhook (distintos a los de la API)
# ---------------------------------------------------------------------------

class WebhookHost(BaseModel):
    model_config = ConfigDict(extra="ignore", populate_by_name=True)
    hostname: str = Field(default="", alias="Hostname")
    ips: list[str] = Field(default_factory=list, alias="Ips")
    guid: str = Field(default="", alias="Guid")


class WebhookImpactScope(BaseModel):
    model_config = ConfigDict(extra="ignore", populate_by_name=True)
    desktops: list[WebhookHost] = Field(default_factory=list, alias="Endpoint - Desktops")
    servers: list[WebhookHost] = Field(default_factory=list, alias="Endpoint - Servers")
    accounts: list[Any] = Field(default_factory=list, alias="Accounts")


class WebhookHighlightedObject(BaseModel):
    model_config = ConfigDict(extra="ignore", populate_by_name=True)
    object_type: str = Field(default="", alias="Object Type")
    object_field: str = Field(default="", alias="Object Field")
    custom_value: str = Field(default="", alias="Custom Value")
    risk_level: str = Field(default="", alias="Risk Level")


class WebhookHighlightedDetail(BaseModel):
    model_config = ConfigDict(extra="ignore", populate_by_name=True)
    total_count: int = Field(default=0, alias="Total Count")
    display_count: int = Field(default=0, alias="Display Count")
    objects: list[WebhookHighlightedObject] = Field(
        default_factory=list, alias="Highlighted Objects"
    )


class WebhookAlertData(BaseModel):
    """El JSON que viene DENTRO del campo 'data' (como string) del body."""
    model_config = ConfigDict(extra="ignore", populate_by_name=True)
    score: int = Field(default=0, alias="Score")
    workbench_id: str = Field(alias="Workbench ID")
    model: str = Field(default="", alias="Model")
    model_severity: str = Field(default="", alias="Model severity")
    created: str = Field(default="", alias="Created")
    impact_scope: WebhookImpactScope = Field(
        default_factory=WebhookImpactScope, alias="Impact scope details"
    )
    highlighted: WebhookHighlightedDetail = Field(
        default_factory=WebhookHighlightedDetail, alias="Highlighted object detail"
    )
    link: str = Field(default="", alias="Link")


class WebhookEnvelope(BaseModel):
    """El body de nivel superior del webhook."""
    model_config = ConfigDict(extra="ignore")
    businessId: str = ""
    businessName: str = ""
    data: str  # OJO: string que contiene JSON
    title: str = ""
    type: str = ""

    def parse_data(self) -> WebhookAlertData:
        """Segundo parseo: el 'data' es un JSON serializado como string."""
        return WebhookAlertData.model_validate(json.loads(self.data))


# ---------------------------------------------------------------------------
# Helpers de extraccion de los "Highlighted Objects"
# ---------------------------------------------------------------------------

def _highlighted_by_field(data: WebhookAlertData, field: str) -> str | None:
    """Primer Custom Value cuyo Object Field coincide (ej. 'fileHash', 'malName')."""
    for obj in data.highlighted.objects:
        if obj.object_field == field and obj.custom_value:
            return obj.custom_value
    return None


def _highlighted_by_type(data: WebhookAlertData, obj_type: str) -> str | None:
    """Primer Custom Value cuyo Object Type coincide (ej. 'file_sha1', 'fullpath')."""
    for obj in data.highlighted.objects:
        if obj.object_type == obj_type and obj.custom_value:
            return obj.custom_value
    return None


def _clean_defanged(value: str | None) -> str | None:
    """Trend 'defangea' indicadores en el webhook: eicar[.]com -> eicar.com.

    Revierte [.] y hxxp para que el valor sea utilizable aguas abajo
    (VirusTotal, etc.). Solo afecta la representacion, no el dato.
    """
    if not value:
        return value
    return value.replace("[.]", ".").replace("hxxp://", "http://").replace("hxxps://", "https://")


def _category_from_model_str(model: str, detection_name: str | None) -> str:
    """Mismo criterio que la Fase 5 pero sobre strings sueltos (el webhook no
    trae modelType, asi que el fallback es 'tv1_webhook')."""
    haystack = " ".join(p.lower() for p in (model, detection_name) if p)
    for keywords, category in _CATEGORY_KEYWORDS:
        if any(keyword in haystack for keyword in keywords):
            return category
    return "tv1_webhook"


def _parse_account_webhook(raw: str) -> User | None:
    """Igual criterio de filtrado de built-ins que normalize_tv1._parse_account."""
    value = (raw or "").strip()
    if not value:
        return None
    if value.lower().startswith(_BUILTIN_DOMAIN_PREFIXES):
        return None
    domain: str | None = None
    sam = value
    if "\\" in value:
        domain, _, sam = value.partition("\\")
    elif "@" in value:
        sam, _, domain = value.partition("@")
    sam = sam.strip()
    if not sam or sam.lower() in _BUILTIN_ACCOUNT_NAMES or sam.endswith("$"):
        return None
    return User(sam=sam, domain=(domain or None), role="event_user")


# ---------------------------------------------------------------------------
# Normalizer principal
# ---------------------------------------------------------------------------

def normalize_tv1_webhook(raw_body: dict[str, Any]) -> NormalizedAlert:
    """Convierte el body crudo de un webhook de Workbench en NormalizedAlert.

    Hace el DOBLE parseo (envelope -> data) y mapea al mismo schema interno que
    el poller, de modo que el pipeline no distingue el origen (salvo por
    source='tv1_webhook').
    """
    envelope = WebhookEnvelope.model_validate(raw_body)
    data = envelope.parse_data()

    severity = _SEVERITY_MAP.get(data.model_severity.lower(), "medium")

    # --- Host / device ---
    all_hosts = data.impact_scope.desktops + data.impact_scope.servers
    device = Device()
    if all_hosts:
        host = all_hosts[0]
        internal, external = _classify_host_ips(host.ips)
        device = Device(hostname=host.hostname or None,
                        internal_ip=internal, external_ip=external)

    network = Network(src_ip_internal=device.internal_ip,
                      src_ip_external=device.external_ip)

    # --- Usuarios (filtrando built-ins) ---
    users: list[User] = []
    for acc in data.impact_scope.accounts:
        acc_str = acc if isinstance(acc, str) else (
            acc.get("Account") or acc.get("name") if isinstance(acc, dict) else None
        )
        if acc_str:
            u = _parse_account_webhook(acc_str)
            if u:
                users.append(u)

    # --- Archivo (fusionado, como en la Fase 5) ---
    detection_name = _highlighted_by_field(data, "malName")
    filename = _clean_defanged(_highlighted_by_field(data, "fileName"))
    fullpath = _clean_defanged(_highlighted_by_type(data, "fullpath"))
    sha1 = _highlighted_by_type(data, "file_sha1")
    sha256 = _highlighted_by_type(data, "file_sha256")  # por si algun dia viene
    act_result = _highlighted_by_field(data, "actResult")

    verdict = None
    if act_result:
        low = act_result.lower()
        if "pass" in low or "not blocked" in low:
            verdict = "not_blocked"
        elif any(w in low for w in ("block", "quarantin", "clean", "delet", "terminat")):
            verdict = "blocked"
        else:
            verdict = act_result

    files: list[FileEvidence] = []
    if filename or fullpath or sha1 or sha256:
        files.append(FileEvidence(
            name=filename or (fullpath.replace("\\", "/").rsplit("/", 1)[-1] if fullpath else None),
            path=fullpath,
            sha1=sha1.lower() if sha1 else None,
            sha256=sha256.lower() if sha256 else None,
            verdict=verdict,
        ))

    threat = Threat(
        provider="Trend Vision One",
        family=detection_name,
        display_name=data.model or None,
        alert_url=data.link or None,
    )

    wazuh_rule = WazuhRule(
        id=None,
        level=_SYNTHETIC_LEVEL[severity],
        description=data.model or "TV1 Webhook alert",
        groups=["tv1", "webhook"],
    )

    created = data.created or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    return NormalizedAlert(
        source="tv1_webhook",
        alert_id=data.workbench_id,
        timestamp=created,
        wazuh_rule=wazuh_rule,
        severity_source=severity,
        title=data.model or "TV1 Webhook alert",
        category=_category_from_model_str(data.model, detection_name),
        device=device,
        users_involved=users,
        files=files,
        network=network,
        threat=threat,
        raw=raw_body,
    )
