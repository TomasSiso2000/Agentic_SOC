"""Tests del webhook de Trend Vision One (normalizer + endpoint).

Destino en el repo: tests/test_tv1_webhook.py
Fixture: tests/fixtures/tv1_webhook_eicar.json (payload real capturado).
"""

import json
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.models import NormalizedAlert
from src.normalize_tv1_webhook import normalize_tv1_webhook
from src.tv1_webhook_endpoint import build_tv1_webhook_router

FIXTURES = Path(__file__).parent / "fixtures"
TOKEN = "s3cr3t-token-de-prueba"


@pytest.fixture
def webhook_body() -> dict:
    with open(FIXTURES / "tv1_webhook_eicar.json", encoding="utf-8") as fh:
        return json.load(fh)


# ---------------------------------------------------------------------------
# Normalizer
# ---------------------------------------------------------------------------

class TestNormalizeWebhook:
    def test_produce_normalized_alert(self, webhook_body):
        alert = normalize_tv1_webhook(webhook_body)
        assert isinstance(alert, NormalizedAlert)
        assert alert.source == "tv1_webhook"
        assert alert.alert_id == "WB-67283-20260828-00000"
        assert alert.severity_source == "low"

    def test_doble_parseo_del_campo_data(self, webhook_body):
        """El 'data' es un string con JSON adentro: debe parsearse igual."""
        alert = normalize_tv1_webhook(webhook_body)
        assert alert.title == "Eicar Test File Detection"

    def test_host_y_red(self, webhook_body):
        alert = normalize_tv1_webhook(webhook_body)
        assert alert.device.hostname == "AgenticSoc"
        assert alert.device.internal_ip == "10.0.3.4"
        assert alert.network.src_ip_internal == "10.0.3.4"

    def test_archivo_fusionado(self, webhook_body):
        """Los 'Highlighted Objects' de un archivo -> una sola FileEvidence."""
        alert = normalize_tv1_webhook(webhook_body)
        assert len(alert.files) == 1
        f = alert.files[0]
        assert f.name == "eicar.com"           # defang revertido
        assert f.sha1 == "3395856ce81f2b7382dee72602f798b642f14140"
        assert f.verdict == "blocked"          # "File quarantined"
        assert f.path and "eicar.com" in f.path

    def test_defang_revertido(self, webhook_body):
        """El webhook manda eicar[.]com; lo devolvemos usable como eicar.com."""
        alert = normalize_tv1_webhook(webhook_body)
        assert "[.]" not in alert.files[0].name
        assert "[.]" not in (alert.files[0].path or "")

    def test_family_desde_detection_name(self, webhook_body):
        alert = normalize_tv1_webhook(webhook_body)
        assert alert.threat.family == "Eicar_test_file"

    def test_no_hay_sha256_solo_sha1(self, webhook_body):
        """Limitacion documentada del webhook: trae sha1, no sha256."""
        alert = normalize_tv1_webhook(webhook_body)
        assert alert.files[0].sha256 is None
        assert alert.files[0].sha1 is not None

    def test_level_sintetico(self, webhook_body):
        alert = normalize_tv1_webhook(webhook_body)
        assert alert.wazuh_rule.level == 4  # low
        assert alert.wazuh_rule.groups == ["tv1", "webhook"]

    def test_raw_preserva_body(self, webhook_body):
        alert = normalize_tv1_webhook(webhook_body)
        assert alert.raw["businessId"] == webhook_body["businessId"]

    def test_severidad_desconocida_cae_en_medium(self, webhook_body):
        inner = json.loads(webhook_body["data"])
        inner["Model severity"] = "ultra"
        webhook_body["data"] = json.dumps(inner)
        alert = normalize_tv1_webhook(webhook_body)
        assert alert.severity_source == "medium"


# ---------------------------------------------------------------------------
# Endpoint (con seguridad)
# ---------------------------------------------------------------------------

class FakeSettings:
    enable_triage = True


class FakePipeline:
    def __init__(self):
        self.calls = []

    async def __call__(self, alert, settings):
        self.calls.append(alert)


def make_client(pipeline, token=TOKEN, cidrs=None, settings=None):
    app = FastAPI()
    router = build_tv1_webhook_router(
        expected_token=token,
        process_alert_fn=pipeline,
        settings=settings or FakeSettings(),
        allowed_cidrs=cidrs,
    )
    app.include_router(router)
    return TestClient(app)


class TestWebhookEndpoint:
    def test_token_correcto_dispara_pipeline(self, webhook_body):
        pipeline = FakePipeline()
        client = make_client(pipeline)
        r = client.post(f"/webhook/tv1-alert/{TOKEN}", json=webhook_body)
        assert r.status_code == 202
        assert len(pipeline.calls) == 1
        assert pipeline.calls[0].alert_id == "WB-67283-20260828-00000"

    def test_token_incorrecto_rechazado(self, webhook_body):
        pipeline = FakePipeline()
        client = make_client(pipeline)
        r = client.post("/webhook/tv1-alert/token-falso", json=webhook_body)
        assert r.status_code == 403
        assert pipeline.calls == []  # NO se disparo el pipeline

    def test_sin_token_es_404(self, webhook_body):
        """Sin token en la URL, la ruta ni matchea."""
        pipeline = FakePipeline()
        client = make_client(pipeline)
        r = client.post("/webhook/tv1-alert/", json=webhook_body)
        assert r.status_code in (404, 405)
        assert pipeline.calls == []

    def test_triage_apagado_no_dispara(self, webhook_body):
        class Off:
            enable_triage = False
        pipeline = FakePipeline()
        client = make_client(pipeline, settings=Off())
        r = client.post(f"/webhook/tv1-alert/{TOKEN}", json=webhook_body)
        assert r.status_code == 202          # igual acepta
        assert pipeline.calls == []          # pero no analiza

    def test_body_no_json_es_400(self):
        pipeline = FakePipeline()
        client = make_client(pipeline)
        r = client.post(f"/webhook/tv1-alert/{TOKEN}",
                        content=b"esto no es json",
                        headers={"content-type": "application/json"})
        assert r.status_code == 400

    def test_ip_no_permitida_rechazada(self, webhook_body):
        """Con allowlist activa, una IP fuera de rango -> 403."""
        pipeline = FakePipeline()
        # El TestClient reporta como 'testclient'/127.0.0.1; restringimos a otro rango
        client = make_client(pipeline, cidrs=["203.0.113.0/24"])
        r = client.post(f"/webhook/tv1-alert/{TOKEN}", json=webhook_body)
        assert r.status_code == 403
        assert pipeline.calls == []

    def test_ip_permitida_via_forwarded_for(self, webhook_body):
        """Con X-Forwarded-For dentro del rango permitido, pasa."""
        pipeline = FakePipeline()
        client = make_client(pipeline, cidrs=["34.200.0.0/16"])
        r = client.post(
            f"/webhook/tv1-alert/{TOKEN}",
            json=webhook_body,
            headers={"x-forwarded-for": "34.200.91.79"},
        )
        assert r.status_code == 202
        assert len(pipeline.calls) == 1
