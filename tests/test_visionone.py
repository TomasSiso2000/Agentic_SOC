"""
Tests del cliente Vision One (Fase 1).

Destino en el repo: tests/test_visionone.py
(ajustar el import segun el layout: from src.tools.visionone import ...)

Convenciones del proyecto: respx para HTTP mocking, NO live API calls.
Fixture: tests/fixtures/tv1_workbench_completa.json (alerta real anonimizada).
"""

import json
from datetime import datetime, timezone
from pathlib import Path

import httpx
import pytest
import respx

from src.tools.visionone import  (
    HostEntityValue,
    VisionOneClient,
    VisionOneError,
    WorkbenchAlert,
)

FIXTURES = Path(__file__).parent / "fixtures"
BASE_URL = "https://api.xdr.trendmicro.com"
ALERTS_URL = f"{BASE_URL}/v3.0/workbench/alerts"


@pytest.fixture
def raw_alert() -> dict:
    with open(FIXTURES / "tv1_workbench_completa.json", encoding="utf-8") as fh:
        return json.load(fh)


@pytest.fixture
def client() -> VisionOneClient:
    return VisionOneClient(base_url=BASE_URL, token="test-token")


# ---------------------------------------------------------------------------
# Modelos: validacion contra el fixture real
# ---------------------------------------------------------------------------

class TestWorkbenchAlertModel:
    def test_parsea_fixture_completo(self, raw_alert):
        alert = WorkbenchAlert.model_validate(raw_alert)
        assert alert.id == "WB-62495-20260612-00000"
        assert alert.severity == "high"
        assert alert.score == 60
        assert alert.model == "Test"
        assert alert.schema_version == "1.22"
        assert alert.created_date_time.tzinfo is not None  # datetime aware

    def test_entity_value_polimorfico(self, raw_alert):
        """account -> str, host -> objeto {guid, name, ips}."""
        alert = WorkbenchAlert.model_validate(raw_alert)
        accounts = [e for e in alert.impact_scope.entities if e.is_account]
        hosts = [e for e in alert.impact_scope.entities if e.is_host]

        assert accounts and isinstance(accounts[0].entity_value, str)
        assert hosts and isinstance(hosts[0].entity_value, HostEntityValue)
        assert hosts[0].entity_value.name  # el host del fixture tiene nombre
        assert hosts[0].entity_value.ips   # y al menos una IP

    def test_helper_host_names(self, raw_alert):
        alert = WorkbenchAlert.model_validate(raw_alert)
        names = alert.host_names()
        assert len(names) == 1
        assert names[0]  # no vacio

    def test_helper_account_names_devuelve_crudo(self, raw_alert):
        """El cliente NO filtra built-ins: eso es responsabilidad del normalizer."""
        alert = WorkbenchAlert.model_validate(raw_alert)
        accounts = alert.account_names()
        assert "NT AUTHORITY\\SYSTEM" in accounts

    def test_indicators_del_fixture(self, raw_alert):
        alert = WorkbenchAlert.model_validate(raw_alert)
        assert len(alert.indicators) == 40
        tipos = {i.type for i in alert.indicators}
        assert {"command_line", "fullpath", "user_account"} <= tipos

    def test_campo_desconocido_no_rompe(self, raw_alert):
        """Trend agrega campos seguido: extra='ignore' debe tolerarlos."""
        raw_alert["campoNuevoDeTrend2027"] = {"foo": "bar"}
        alert = WorkbenchAlert.model_validate(raw_alert)  # no debe levantar
        assert alert.id == "WB-62495-20260612-00000"


# ---------------------------------------------------------------------------
# Cliente: HTTP mockeado con respx
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestVisionOneClient:
    @respx.mock
    async def test_una_pagina(self, client, raw_alert):
        respx.get(ALERTS_URL).mock(
            return_value=httpx.Response(200, json={"items": [raw_alert]})
        )
        alerts = await client.get_workbench_alerts(
            start=datetime(2026, 6, 1, tzinfo=timezone.utc)
        )
        assert len(alerts) == 1
        assert alerts[0].id == "WB-62495-20260612-00000"
        await client.aclose()

    @respx.mock
    async def test_sigue_next_link(self, client, raw_alert):
        """Pagina 1 con nextLink -> pagina 2 sin nextLink. Deben juntarse."""
        page2_url = f"{ALERTS_URL}?skipToken=abc123"
        alert2 = dict(raw_alert, id="WB-99999-20260612-00001")

        route1 = respx.get(ALERTS_URL, params__contains={"dateTimeTarget": "createdDateTime"}).mock(
            return_value=httpx.Response(
                200, json={"items": [raw_alert], "nextLink": page2_url}
            )
        )
        route2 = respx.get(ALERTS_URL, params__contains={"skipToken": "abc123"}).mock(
            return_value=httpx.Response(200, json={"items": [alert2]})
        )

        alerts = await client.get_workbench_alerts(
            start=datetime(2026, 6, 1, tzinfo=timezone.utc)
        )
        assert route1.called and route2.called
        assert [a.id for a in alerts] == [
            "WB-62495-20260612-00000",
            "WB-99999-20260612-00001",
        ]
        await client.aclose()

    @respx.mock
    async def test_manda_header_tmv1_filter(self, client):
        route = respx.get(ALERTS_URL).mock(
            return_value=httpx.Response(200, json={"items": []})
        )
        await client.get_workbench_alerts(
            start=datetime(2026, 6, 1, tzinfo=timezone.utc),
            tmv1_filter="severity eq 'high'",
        )
        sent = route.calls.last.request
        assert sent.headers["TMV1-Filter"] == "severity eq 'high'"
        assert sent.headers["Authorization"] == "Bearer test-token"
        await client.aclose()

    @respx.mock
    async def test_params_de_fecha(self, client):
        route = respx.get(ALERTS_URL).mock(
            return_value=httpx.Response(200, json={"items": []})
        )
        await client.get_workbench_alerts(
            start=datetime(2026, 6, 1, 12, 30, 0, tzinfo=timezone.utc),
            end=datetime(2026, 6, 2, tzinfo=timezone.utc),
        )
        params = dict(httpx.QueryParams(route.calls.last.request.url.query))
        assert params["startDateTime"] == "2026-06-01T12:30:00Z"
        assert params["endDateTime"] == "2026-06-02T00:00:00Z"
        assert params["dateTimeTarget"] == "createdDateTime"
        await client.aclose()

    @respx.mock
    @pytest.mark.parametrize("status,esperado", [(401, 401), (403, 403), (429, 429), (500, 500)])
    async def test_errores_http(self, client, status, esperado):
        respx.get(ALERTS_URL).mock(return_value=httpx.Response(status, text="boom"))
        with pytest.raises(VisionOneError) as exc_info:
            await client.get_workbench_alerts(
                start=datetime(2026, 6, 1, tzinfo=timezone.utc)
            )
        assert exc_info.value.status_code == esperado
        await client.aclose()

    @respx.mock
    async def test_corte_por_max_pages(self, client, raw_alert):
        """Si nextLink nunca se agota, max_pages evita el loop infinito."""
        respx.get(ALERTS_URL).mock(
            return_value=httpx.Response(
                200, json={"items": [raw_alert], "nextLink": ALERTS_URL}
            )
        )
        alerts = await client.get_workbench_alerts(
            start=datetime(2026, 6, 1, tzinfo=timezone.utc), max_pages=3
        )
        assert len(alerts) == 3  # una por pagina, corto en 3
        await client.aclose()
