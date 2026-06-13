"""
Cliente Trend Vision One (API v3.0) + modelos Pydantic de Workbench alerts.

Destino en el repo: src/tools/visionone.py

Convenciones del proyecto:
- httpx async (mismo patron que wazuh_api.py / fortigate.py)
- Pydantic v2
- NOTA sobre extra=: los modelos de RESPUESTA de TV1 usan extra="ignore"
  (Trend agrega campos al schema con frecuencia; un field nuevo inofensivo
  no debe romper el poller). El extra="forbid" del proyecto aplica a los
  modelos INTERNOS (NormalizedAlert, etc.), que son los que ven los agents.
"""

import logging
from datetime import datetime, timezone
from typing import Any

import httpx
from pydantic import BaseModel, ConfigDict, Field

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 30.0
MAX_PAGES = 20  # corte de seguridad: nunca seguir nextLink infinitamente


# ---------------------------------------------------------------------------
# Modelos de respuesta (calcados del fixture real, schemaVersion 1.22)
# ---------------------------------------------------------------------------

class Tv1ResponseModel(BaseModel):
    """Base para todo lo que viene de la API de TV1: tolerante a campos nuevos."""
    model_config = ConfigDict(extra="ignore", populate_by_name=True)


class HostEntityValue(Tv1ResponseModel):
    """entityValue cuando entityType == 'host'."""
    guid: str = ""
    name: str = ""
    ips: list[str] = Field(default_factory=list)


class ImpactScopeEntity(Tv1ResponseModel):
    """Una entidad afectada (host, account, emailAddress, etc.).

    OJO: entityValue es polimorfico en la API real:
      - account       -> str   (ej. "EXAMPLE\\usuario" o "NT AUTHORITY\\SYSTEM")
      - host          -> dict  ({guid, name, ips})
    Pydantic intenta los tipos de la union en orden.
    """
    entity_type: str = Field(alias="entityType")
    entity_value: str | HostEntityValue = Field(alias="entityValue")
    entity_id: str = Field(default="", alias="entityId")
    related_entities: list[str] = Field(default_factory=list, alias="relatedEntities")
    related_indicator_ids: list[int] = Field(default_factory=list, alias="relatedIndicatorIds")
    provenance: list[str] = Field(default_factory=list)

    @property
    def is_host(self) -> bool:
        return self.entity_type == "host"

    @property
    def is_account(self) -> bool:
        return self.entity_type == "account"


class ImpactScope(Tv1ResponseModel):
    entities: list[ImpactScopeEntity] = Field(default_factory=list)
    desktop_count: int = Field(default=0, alias="desktopCount")
    server_count: int = Field(default=0, alias="serverCount")
    account_count: int = Field(default=0, alias="accountCount")
    email_address_count: int = Field(default=0, alias="emailAddressCount")


class Indicator(Tv1ResponseModel):
    """Un indicador del alert. 'value' puede ser str u objeto segun el type
    (en el fixture: command_line / fullpath / user_account son str)."""
    id: int
    type: str
    field: str = ""
    value: str | dict[str, Any]
    related_entities: list[str] = Field(default_factory=list, alias="relatedEntities")
    filter_ids: list[str] = Field(default_factory=list, alias="filterIds")
    provenance: list[str] = Field(default_factory=list)


class MatchedEvent(Tv1ResponseModel):
    uuid: str = ""
    matched_date_time: str = Field(default="", alias="matchedDateTime")
    type: str = ""


class MatchedFilter(Tv1ResponseModel):
    id: str = ""
    name: str = ""
    matched_date_time: str = Field(default="", alias="matchedDateTime")
    mitre_technique_ids: list[str] = Field(default_factory=list, alias="mitreTechniqueIds")
    matched_events: list[MatchedEvent] = Field(default_factory=list, alias="matchedEvents")


class MatchedRule(Tv1ResponseModel):
    id: str = ""
    name: str = ""
    matched_filters: list[MatchedFilter] = Field(default_factory=list, alias="matchedFilters")


class WorkbenchAlert(Tv1ResponseModel):
    """Una Workbench alert completa (schemaVersion 1.22)."""
    id: str
    schema_version: str = Field(default="", alias="schemaVersion")
    status: str = ""                      # "Open" / "Closed" / "In Progress"
    investigation_status: str = Field(default="", alias="investigationStatus")
    investigation_result: str = Field(default="", alias="investigationResult")
    severity: str = ""                    # low / medium / high / critical
    score: int = 0
    model: str = ""                       # nombre del detection model
    model_id: str = Field(default="", alias="modelId")
    model_type: str = Field(default="", alias="modelType")
    alert_provider: str = Field(default="", alias="alertProvider")
    description: str = ""
    incident_id: str = Field(default="", alias="incidentId")
    workbench_link: str = Field(default="", alias="workbenchLink")
    created_date_time: datetime = Field(alias="createdDateTime")
    updated_date_time: datetime | None = Field(default=None, alias="updatedDateTime")
    impact_scope: ImpactScope = Field(default_factory=ImpactScope, alias="impactScope")
    indicators: list[Indicator] = Field(default_factory=list)
    matched_rules: list[MatchedRule] = Field(default_factory=list, alias="matchedRules")

    # -- Helpers de extraccion (los usara normalize.py en Fase 2) --

    def host_names(self) -> list[str]:
        """Nombres de los hosts afectados."""
        return [
            e.entity_value.name
            for e in self.impact_scope.entities
            if e.is_host and isinstance(e.entity_value, HostEntityValue) and e.entity_value.name
        ]

    def account_names(self) -> list[str]:
        """Cuentas afectadas, crudas (ej. 'EXAMPLE\\usuario', 'NT AUTHORITY\\SYSTEM').

        El filtrado de cuentas built-in (SYSTEM, etc.) y el parseo a
        sAMAccountName son responsabilidad del normalizer, no del cliente.
        """
        return [
            e.entity_value
            for e in self.impact_scope.entities
            if e.is_account and isinstance(e.entity_value, str) and e.entity_value
        ]


class WorkbenchAlertsPage(Tv1ResponseModel):
    """Una pagina de GET /v3.0/workbench/alerts."""
    items: list[WorkbenchAlert] = Field(default_factory=list)
    next_link: str | None = Field(default=None, alias="nextLink")
    total_count: int | None = Field(default=None, alias="totalCount")


# ---------------------------------------------------------------------------
# Cliente
# ---------------------------------------------------------------------------

class VisionOneError(Exception):
    """Error de la API de TV1 con contexto util para logs."""

    def __init__(self, message: str, status_code: int | None = None):
        super().__init__(message)
        self.status_code = status_code


class VisionOneClient:
    """Cliente async minimo para la API v3.0 de Trend Vision One.

    Uso:
        client = VisionOneClient(base_url=..., token=...)
        alerts = await client.get_workbench_alerts(start=dt)
        await client.aclose()
    """

    def __init__(
        self,
        base_url: str,
        token: str,
        timeout: float = DEFAULT_TIMEOUT,
        transport: httpx.AsyncBaseTransport | None = None,
    ):
        self._base_url = base_url.rstrip("/")
        self._client = httpx.AsyncClient(
            headers={"Authorization": f"Bearer {token}"},
            timeout=timeout,
            transport=transport,
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    async def get_workbench_alerts(
        self,
        start: datetime,
        end: datetime | None = None,
        tmv1_filter: str | None = None,
        date_time_target: str = "createdDateTime",
        max_pages: int = MAX_PAGES,
    ) -> list[WorkbenchAlert]:
        """Trae Workbench alerts desde `start`, siguiendo nextLink.

        Args:
            start: inicio de la ventana (se convierte a UTC).
            end: fin opcional de la ventana.
            tmv1_filter: filtro server-side via header TMV1-Filter,
                ej. "severity eq 'high' or severity eq 'critical'".
            date_time_target: campo de fecha a filtrar
                ("createdDateTime" para backfill, "lastUpdatedDateTime"
                sera lo correcto para el cursor del poller en Fase 3).
        """
        params: dict[str, str] | None = {
            "startDateTime": _iso_utc(start),
            "dateTimeTarget": date_time_target,
            "orderBy": f"{date_time_target} desc",
        }
        if end is not None:
            params["endDateTime"] = _iso_utc(end)

        headers: dict[str, str] = {}
        if tmv1_filter:
            headers["TMV1-Filter"] = tmv1_filter

        url = f"{self._base_url}/v3.0/workbench/alerts"
        alerts: list[WorkbenchAlert] = []

        for page_num in range(1, max_pages + 1):
            page = await self._get_page(url, params=params, headers=headers)
            alerts.extend(page.items)
            logger.debug(
                "🔎 TOOL tv1_workbench_alerts(page=%d) ↳ %d items", page_num, len(page.items)
            )
            if not page.next_link:
                break
            # nextLink viene como URL absoluta con todos los params incluidos
            url, params = page.next_link, None
        else:
            logger.warning(
                "🛑 tv1: corte por max_pages=%d con nextLink pendiente "
                "(¿ventana demasiado grande?)", max_pages,
            )

        return alerts

    async def _get_page(
        self,
        url: str,
        params: dict[str, str] | None,
        headers: dict[str, str],
    ) -> WorkbenchAlertsPage:
        try:
            resp = await self._client.get(url, params=params, headers=headers)
        except httpx.HTTPError as exc:
            raise VisionOneError(f"error de red contra TV1: {exc}") from exc

        if resp.status_code == 401:
            raise VisionOneError("TV1 401: token invalido o vencido", 401)
        if resp.status_code == 403:
            raise VisionOneError(
                "TV1 403: rol sin permiso Workbench 'View' o region equivocada", 403
            )
        if resp.status_code == 429:
            raise VisionOneError("TV1 429: rate limit", 429)
        if resp.status_code != 200:
            raise VisionOneError(
                f"TV1 {resp.status_code}: {resp.text[:300]}", resp.status_code
            )

        return WorkbenchAlertsPage.model_validate(resp.json())


def _iso_utc(dt: datetime) -> str:
    """datetime -> '2026-06-12T14:43:32Z' (la API exige UTC con Z)."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
