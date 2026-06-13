"""Tests del poller de Trend Vision One (Fase 3).

Destino en el repo: tests/test_tv1_poller.py

Convenciones del repo: respx para HTTP (cero llamadas reales), SQLite en
tmp_path, Settings construidos con _env_file=None para aislarse del .env
(leccion aprendida: el .env contamina los tests si no se desactiva).
"""

import json
from pathlib import Path

import httpx
import pytest
import respx

from src.config import Settings
from src.tools.visionone import VisionOneClient, VisionOneError
from src.tv1_poller import build_severity_filter, poll_once
from src.tv1_state import (
    get_tv1_cursor,
    init_tv1_tables,
    mark_tv1_processed,
    set_tv1_cursor,
)

FIXTURES = Path(__file__).parent / "fixtures"
BASE_URL = "https://api.xdr.trendmicro.com"
ALERTS_URL = f"{BASE_URL}/v3.0/workbench/alerts"


@pytest.fixture
def raw_alert() -> dict:
    with open(FIXTURES / "tv1_workbench_completa.json", encoding="utf-8") as fh:
        return json.load(fh)


@pytest.fixture
def settings(tmp_path) -> Settings:
    """Settings de test: DB temporal, triage 'habilitado', sin leer .env."""
    return Settings(
        _env_file=None,
        tv1_base_url=BASE_URL,
        tv1_api_token="test-token",
        state_db_path=str(tmp_path / "state.db"),
        enable_triage=True,
        enable_tv1_poller=True,
        tv1_initial_lookback_minutes=5,
        tv1_poll_overlap_seconds=120,
    )


@pytest.fixture
def client() -> VisionOneClient:
    return VisionOneClient(base_url=BASE_URL, token="test-token")


class FakePipeline:
    """Callback espía: registra las alertas que el poller mandó al pipeline."""

    def __init__(self, fail_on_alert_ids: set[str] | None = None):
        self.calls: list = []
        self._fail_on = fail_on_alert_ids or set()

    async def __call__(self, alert, settings) -> None:
        if alert.alert_id in self._fail_on:
            raise RuntimeError(f"pipeline explotó para {alert.alert_id}")
        self.calls.append(alert)


# ---------------------------------------------------------------------------
# build_severity_filter
# ---------------------------------------------------------------------------

class TestBuildSeverityFilter:
    def test_medium_incluye_hacia_arriba(self):
        f = build_severity_filter("medium")
        assert f == "severity eq 'medium' or severity eq 'high' or severity eq 'critical'"

    def test_critical_solo_critical(self):
        assert build_severity_filter("critical") == "severity eq 'critical'"

    @pytest.mark.parametrize("raw", ["", "  ", "banana"])
    def test_vacio_o_invalido_sin_filtro(self, raw):
        assert build_severity_filter(raw) is None

    def test_case_insensitive(self):
        assert build_severity_filter("HIGH") == "severity eq 'high' or severity eq 'critical'"


# ---------------------------------------------------------------------------
# tv1_state: cursor + dedup
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestTv1State:
    async def test_cursor_roundtrip(self, settings):
        await init_tv1_tables(settings.state_db_path)
        assert await get_tv1_cursor(settings.state_db_path) is None
        await set_tv1_cursor(settings.state_db_path, "2026-06-12T10:00:00+00:00")
        assert await get_tv1_cursor(settings.state_db_path) == "2026-06-12T10:00:00+00:00"

    async def test_mark_processed_dedup(self, settings):
        await init_tv1_tables(settings.state_db_path)
        assert await mark_tv1_processed(settings.state_db_path, "WB-1") is True
        assert await mark_tv1_processed(settings.state_db_path, "WB-1") is False  # repetido
        assert await mark_tv1_processed(settings.state_db_path, "WB-2") is True


# ---------------------------------------------------------------------------
# poll_once
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestPollOnce:
    @respx.mock
    async def test_alerta_nueva_dispara_pipeline(self, settings, client, raw_alert):
        await init_tv1_tables(settings.state_db_path)
        respx.get(ALERTS_URL).mock(
            return_value=httpx.Response(200, json={"items": [raw_alert]})
        )
        pipeline = FakePipeline()

        fetched, new = await poll_once(settings, client, pipeline)

        assert (fetched, new) == (1, 1)
        assert len(pipeline.calls) == 1
        assert pipeline.calls[0].source == "tv1_workbench"
        assert pipeline.calls[0].alert_id == raw_alert["id"]
        # El ciclo exitoso avanzó el cursor
        assert await get_tv1_cursor(settings.state_db_path) is not None
        await client.aclose()

    @respx.mock
    async def test_segunda_pasada_deduplica(self, settings, client, raw_alert):
        """El solape hace que la misma alerta vuelva a aparecer: pipeline corre 1 vez."""
        await init_tv1_tables(settings.state_db_path)
        respx.get(ALERTS_URL).mock(
            return_value=httpx.Response(200, json={"items": [raw_alert]})
        )
        pipeline = FakePipeline()

        await poll_once(settings, client, pipeline)
        fetched, new = await poll_once(settings, client, pipeline)

        assert fetched == 1
        assert new == 0  # ya estaba en tv1_processed_alerts
        assert len(pipeline.calls) == 1
        await client.aclose()

    @respx.mock
    async def test_error_api_no_avanza_cursor(self, settings, client):
        """API caída: poll_once propaga el error y el cursor queda intacto."""
        await init_tv1_tables(settings.state_db_path)
        await set_tv1_cursor(settings.state_db_path, "2026-06-12T10:00:00+00:00")
        respx.get(ALERTS_URL).mock(return_value=httpx.Response(500, text="boom"))

        with pytest.raises(VisionOneError):
            await poll_once(settings, client, FakePipeline())

        assert await get_tv1_cursor(settings.state_db_path) == "2026-06-12T10:00:00+00:00"
        await client.aclose()

    @respx.mock
    async def test_fallo_de_una_alerta_no_frena_las_demas(self, settings, client, raw_alert):
        """Si el pipeline explota con una alerta, las otras del lote se procesan igual."""
        await init_tv1_tables(settings.state_db_path)
        alert2 = dict(raw_alert, id="WB-99999-20260612-00002")
        respx.get(ALERTS_URL).mock(
            return_value=httpx.Response(200, json={"items": [raw_alert, alert2]})
        )
        pipeline = FakePipeline(fail_on_alert_ids={raw_alert["id"]})

        fetched, new = await poll_once(settings, client, pipeline)

        assert (fetched, new) == (2, 2)
        assert [a.alert_id for a in pipeline.calls] == ["WB-99999-20260612-00002"]
        # El ciclo igual cerró bien: cursor avanzado
        assert await get_tv1_cursor(settings.state_db_path) is not None
        await client.aclose()

    @respx.mock
    async def test_triage_deshabilitado_solo_loguea(self, settings, client, raw_alert):
        await init_tv1_tables(settings.state_db_path)
        settings.enable_triage = False
        respx.get(ALERTS_URL).mock(
            return_value=httpx.Response(200, json={"items": [raw_alert]})
        )
        pipeline = FakePipeline()

        fetched, new = await poll_once(settings, client, pipeline)

        assert (fetched, new) == (1, 1)
        assert pipeline.calls == []  # no se invocó el pipeline
        await client.aclose()

    @respx.mock
    async def test_filtro_de_severidad_viaja_en_header(self, settings, client):
        await init_tv1_tables(settings.state_db_path)
        settings.tv1_min_severity = "high"
        route = respx.get(ALERTS_URL).mock(
            return_value=httpx.Response(200, json={"items": []})
        )

        await poll_once(settings, client, FakePipeline())

        sent = route.calls.last.request
        assert sent.headers["TMV1-Filter"] == "severity eq 'high' or severity eq 'critical'"
        await client.aclose()

    @respx.mock
    async def test_segundo_ciclo_consulta_desde_cursor_con_solape(
        self, settings, client, raw_alert
    ):
        """El startDateTime del 2do ciclo = cursor - overlap (no el lookback inicial)."""
        await init_tv1_tables(settings.state_db_path)
        route = respx.get(ALERTS_URL).mock(
            return_value=httpx.Response(200, json={"items": []})
        )

        await poll_once(settings, client, FakePipeline())
        cursor_iso = await get_tv1_cursor(settings.state_db_path)
        await poll_once(settings, client, FakePipeline())

        from datetime import datetime, timedelta

        params = dict(httpx.QueryParams(route.calls.last.request.url.query))
        sent_start = datetime.strptime(params["startDateTime"], "%Y-%m-%dT%H:%M:%SZ")
        cursor_dt = datetime.fromisoformat(cursor_iso).replace(tzinfo=None)
        expected = cursor_dt - timedelta(seconds=settings.tv1_poll_overlap_seconds)
        # Tolerancia de 1s por el truncado a segundos del formato wire
        assert abs((sent_start - expected).total_seconds()) <= 1
        await client.aclose()
