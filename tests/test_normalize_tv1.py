"""Tests de normalize_tv1 (Fase 2).

Destino en el repo: tests/test_normalize_tv1.py
Fixture: tests/fixtures/tv1_workbench_completa.json
"""

import json
from pathlib import Path

import pytest

from src.models import NormalizedAlert
from src.normalize_tv1 import (
    _basename,
    _category_from_model,
    _classify_host_ips,
    _parse_account,
    normalize_tv1,
)

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def raw_alert() -> dict:
    with open(FIXTURES / "tv1_workbench_completa.json", encoding="utf-8") as fh:
        return json.load(fh)


@pytest.fixture
def raw_alert_hktl() -> dict:
    """Alerta real (lab): Hacking Tool Detection - Not Blocked (netcat).

    Trae los campos que la otra fixture no tiene: detection_name, file_sha256,
    filename explicito y actResult. Es la que ejercita el enriquecimiento.
    """
    with open(FIXTURES / "tv1_espana.json", encoding="utf-8") as fh:
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
        """El fixture tiene 10 fullpath distintos: deduplicados, con name."""
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
# Enriquecimiento (Fase 5): campos que el system prompt del Triage consume
# ---------------------------------------------------------------------------

class TestEnriquecimientoHktl:
    """Contra la alerta real de netcat: los datos que TV1 desparrama en varios
    indicators tienen que llegar al Triage fusionados y completos."""

    def test_un_solo_file_con_todo_junto(self, raw_alert_hktl):
        """REGRESION: antes salian 2 FileEvidence (path sin hash + hash huerfano)."""
        alert = normalize_tv1(raw_alert_hktl)
        assert len(alert.files) == 1
        f = alert.files[0]
        assert f.name == "nc.exe"
        assert f.sha256 == "b3b207dfab2f429cc352ba125be32a0cae69fe4bf8563ab7d0128bba8c57a71c"
        assert f.path and f.path.endswith("nc.exe")
        assert f.verdict == "not_blocked"

    def test_sha256_normalizado_a_minusculas(self, raw_alert_hktl):
        """TV1 lo manda en MAYUSCULAS; VirusTotal espera lowercase."""
        alert = normalize_tv1(raw_alert_hktl)
        assert alert.files[0].sha256 == alert.files[0].sha256.lower()

    def test_sha1_vacio_no_se_cuela(self, raw_alert_hktl):
        """El indicator file_sha1 viene con value='' -> None, no cadena vacia."""
        alert = normalize_tv1(raw_alert_hktl)
        assert alert.files[0].sha1 is None

    def test_name_del_indicator_explicito(self, raw_alert_hktl):
        """Preferimos el indicator 'filename' antes que derivar del path."""
        alert = normalize_tv1(raw_alert_hktl)
        assert alert.files[0].name == "nc.exe"

    def test_verdict_not_blocked_desde_act_result(self, raw_alert_hktl):
        """actResult='File passed' -> not_blocked (NO 'malicious': Trend no dijo eso)."""
        alert = normalize_tv1(raw_alert_hktl)
        assert alert.files[0].verdict == "not_blocked"

    def test_family_desde_detection_name(self, raw_alert_hktl):
        alert = normalize_tv1(raw_alert_hktl)
        assert alert.threat.family == "HKTL_NETCAT"

    def test_category_hacking_tool(self, raw_alert_hktl):
        """'Hacking Tool Detection' -> vocabulario que el prompt del Triage entiende."""
        alert = normalize_tv1(raw_alert_hktl)
        assert alert.category == "Hacking Tool"

    def test_incident_url_cuando_hay_incident_id(self, raw_alert_hktl):
        """El prompt mira incident_url para 'multiples evidencias en el incidente'."""
        alert = normalize_tv1(raw_alert_hktl)
        assert alert.threat.incident_id == "IC-14106-20260618-00002"
        assert alert.threat.incident_url is not None

    def test_sin_incident_id_no_hay_incident_url(self, raw_alert_hktl):
        raw_alert_hktl["incidentId"] = ""
        alert = normalize_tv1(raw_alert_hktl)
        assert alert.threat.incident_url is None


class TestCategoryMapping:
    @pytest.mark.parametrize("model,esperado", [
        ("Hacking Tool Detection - Not Blocked", "Hacking Tool"),
        ("Ransomware Behavior Detected", "Ransomware"),
        ("Mimikatz Credential Dumping", "Credential Access"),
        ("Suspicious PsExec Lateral Movement", "Lateral Movement"),
        ("Scheduled Task Persistence", "Persistence"),
        ("Trojan Detected on Endpoint", "Malware"),
        ("Possible Data Exfiltration", "Exfiltration"),
        ("C&C Callback Detected", "Command and Control"),
    ])
    def test_keywords_conocidas(self, raw_alert_hktl, model, esperado):
        raw_alert_hktl["model"] = model
        raw_alert_hktl["description"] = ""
        # Sin detection_name para aislar el mapeo por nombre de modelo
        raw_alert_hktl["indicators"] = [
            i for i in raw_alert_hktl["indicators"] if i["type"] != "detection_name"
        ]
        alert = normalize_tv1(raw_alert_hktl)
        assert alert.category == esperado

    def test_sin_coincidencia_cae_en_fallback(self, raw_alert_hktl):
        """Sin keyword conocida NO inventamos categoria: fallback neutro."""
        raw_alert_hktl["model"] = "Algo Totalmente Nuevo De Trend"
        raw_alert_hktl["description"] = ""
        raw_alert_hktl["indicators"] = [
            i for i in raw_alert_hktl["indicators"] if i["type"] != "detection_name"
        ]
        alert = normalize_tv1(raw_alert_hktl)
        assert alert.category == "tv1_preset"

    def test_detection_name_tambien_alimenta_la_category(self, raw_alert_hktl):
        """Si el modelo no dice nada, el detection_name (HKTL_) puede decidir."""
        raw_alert_hktl["model"] = "Generic Detection"
        raw_alert_hktl["description"] = ""
        alert = normalize_tv1(raw_alert_hktl)
        assert alert.category == "Hacking Tool"  # por HKTL_NETCAT


class TestMitreGroups:
    def test_sin_mitre_solo_tv1_y_provider(self, raw_alert_hktl):
        """Esta alerta (product event log) no trae tecnicas MITRE."""
        alert = normalize_tv1(raw_alert_hktl)
        assert alert.wazuh_rule.groups == ["tv1", "sae"]

    def test_con_mitre_las_agrega_como_groups(self, raw_alert_hktl):
        """Cuando TV1 trae mitreTechniqueIds, van a groups (dedup + ordenadas)."""
        raw_alert_hktl["matchedRules"][0]["matchedFilters"][0]["mitreTechniqueIds"] = [
            "T1059", "T1078", "T1059",
        ]
        alert = normalize_tv1(raw_alert_hktl)
        assert alert.wazuh_rule.groups == ["tv1", "sae", "T1059", "T1078"]


class TestBasename:
    @pytest.mark.parametrize("path,esperado", [
        ("C:\\dir\\nc.exe", "nc.exe"),
        ("/usr/bin/nc", "nc"),
        ("nc.exe", "nc.exe"),
        (None, None),
        ("", None),
    ])
    def test_basename(self, path, esperado):
        assert _basename(path) == esperado


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
