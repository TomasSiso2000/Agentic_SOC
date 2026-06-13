"""Tests de normalize_tv1 (Fase 2).

Destino en el repo: tests/test_normalize_tv1.py
Fixture: tests/fixtures/tv1_workbench_completa.json
"""

import json
from pathlib import Path

import pytest

from src.models import NormalizedAlert
from src.normalize_tv1 import _classify_host_ips, _parse_account, normalize_tv1

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def raw_alert() -> dict:
    with open(FIXTURES / "tv1_workbench_completa.json", encoding="utf-8") as fh:
        return json.load(fh)


# ---------------------------------------------------------------------------
# Normalizacion end-to-end contra el fixture real
# ---------------------------------------------------------------------------

class TestNormalizeTv1:
    def test_produce_normalized_alert_valido(self, raw_alert):
        alert = normalize_tv1(raw_alert)
        assert isinstance(alert, NormalizedAlert)
        assert alert.source == "tv1_workbench"
        assert alert.alert_id == "WB-62495-20260612-00000"
        assert alert.severity_source == "high"

    def test_filtra_cuenta_builtin_system(self, raw_alert):
        """NT AUTHORITY\\SYSTEM no debe ir al lookup LDAP del Enricher."""
        alert = normalize_tv1(raw_alert)
        assert alert.users_involved == []

    def test_device_del_impact_scope(self, raw_alert):
        alert = normalize_tv1(raw_alert)
        assert alert.device.hostname  # el host del fixture tiene nombre
        assert alert.device.internal_ip  # y una IPv4 privada (no la fe80::)
        assert alert.device.internal_ip == alert.network.src_ip_internal

    def test_files_desde_indicators_fullpath(self, raw_alert):
        """El fixture tiene 10 fullpath (con repetidos): deduplicados, con name."""
        alert = normalize_tv1(raw_alert)
        assert alert.files  # al menos uno
        assert all(f.path for f in alert.files)
        assert all(f.name for f in alert.files)
        paths = [f.path for f in alert.files]
        assert len(paths) == len(set(paths))  # sin duplicados

    def test_threat_apunta_a_tv1(self, raw_alert):
        alert = normalize_tv1(raw_alert)
        assert alert.threat.provider == "Trend Vision One"
        assert alert.threat.display_name == "Test"
        assert alert.threat.incident_id == "IC-62495-20260612-00000"
        assert alert.threat.alert_url and "workbench" in alert.threat.alert_url

    def test_rule_sintetica_consistente(self, raw_alert):
        """severity high -> level 10, coherente con _severity_from_level()."""
        alert = normalize_tv1(raw_alert)
        assert alert.wazuh_rule.level == 10
        assert "tv1" in alert.wazuh_rule.groups
        assert alert.wazuh_rule.description == "Test"

    def test_raw_preserva_payload_original(self, raw_alert):
        alert = normalize_tv1(raw_alert)
        assert alert.raw["id"] == raw_alert["id"]

    def test_severidad_desconocida_cae_en_medium(self, raw_alert):
        raw_alert["severity"] = "ultra-mega-critical"  # valor futuro de Trend
        alert = normalize_tv1(raw_alert)
        assert alert.severity_source == "medium"


# ---------------------------------------------------------------------------
# Unit tests del parseo de cuentas
# ---------------------------------------------------------------------------

class TestParseAccount:
    @pytest.mark.parametrize("raw,sam,domain", [
        ("EXAMPLE\\jperez", "jperez", "EXAMPLE"),
        ("jperez@example.local", "jperez", "example.local"),
        ("jperez", "jperez", None),
    ])
    def test_formatos_validos(self, raw, sam, domain):
        user = _parse_account(raw)
        assert user is not None
        assert user.sam == sam
        assert user.domain == domain
        assert user.role == "event_user"

    @pytest.mark.parametrize("raw", [
        "NT AUTHORITY\\SYSTEM",
        "nt authority\\system",            # case-insensitive
        "AUTORIDAD NT\\SYSTEM",            # Windows en espanol
        "NT AUTHORITY\\LOCAL SERVICE",
        "NT SERVICE\\TrustedInstaller",
        "BUILTIN\\Administrators",
        "EXAMPLE\\DESKTOP-ABC123$",        # cuenta de maquina
        "SYSTEM",                          # sin dominio
        "",                                # vacio
        "   ",                             # espacios
    ])
    def test_builtins_y_maquina_filtrados(self, raw):
        assert _parse_account(raw) is None

    def test_administrator_no_se_filtra(self):
        """'Administrator' es una cuenta real de AD: debe pasar el filtro
        (los guardrails PROTECTED_USERS del executor son otra capa)."""
        user = _parse_account("EXAMPLE\\Administrator")
        assert user is not None
        assert user.sam == "Administrator"


# ---------------------------------------------------------------------------
# Unit tests de clasificacion de IPs
# ---------------------------------------------------------------------------

class TestClassifyHostIps:
    def test_privada_y_publica(self):
        # OJO: no usar rangos de documentacion (192.0.2.x / 203.0.113.x) como
        # "publica": ipaddress los considera reservados, no globales.
        internal, external = _classify_host_ips(["10.1.2.3", "8.8.8.8"])
        assert internal == "10.1.2.3"
        assert external == "8.8.8.8"

    def test_ignora_link_local_y_basura(self):
        internal, external = _classify_host_ips(
            ["fe80::fab1:a517:58e6:cc16", "169.254.1.1", "no-es-ip", "192.168.1.5"]
        )
        assert internal == "192.168.1.5"
        assert external is None

    def test_lista_vacia(self):
        assert _classify_host_ips([]) == (None, None)
