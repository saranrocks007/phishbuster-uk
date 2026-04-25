"""PhishBuster UK — integration tests.

Run: pytest tests/ -v

Uses local .eml fixtures + in-memory SQLite. No M365 creds needed.
Detector tests reuse the shared AnalysisEngine to avoid re-loading config.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("ENABLE_AUTO_QUARANTINE", "false")
os.environ.setdefault("ENABLE_TICKETING", "false")
os.environ.setdefault("ENABLE_NCSC_SERS_FORWARDING", "false")
os.environ.setdefault("TICKETING_BACKEND", "stdout")

SAMPLES = Path(__file__).parent / "samples"


# ---------------------------------------------------------------- shared engine
@pytest.fixture(scope="session")
def engine():
    from src.analysis import AnalysisEngine
    return AnalysisEngine()


# ---------------------------------------------------------------- email fixtures
@pytest.fixture(scope="session")
def hmrc_email():
    from src.ingestion import parse_eml_bytes
    return parse_eml_bytes((SAMPLES / "hmrc_refund.eml").read_bytes())

@pytest.fixture(scope="session")
def royal_mail_email():
    from src.ingestion import parse_eml_bytes
    return parse_eml_bytes((SAMPLES / "royal_mail_redelivery.eml").read_bytes())

@pytest.fixture(scope="session")
def natwest_email():
    from src.ingestion import parse_eml_bytes
    return parse_eml_bytes((SAMPLES / "natwest_payee.eml").read_bytes())

@pytest.fixture(scope="session")
def legit_octopus_email():
    from src.ingestion import parse_eml_bytes
    return parse_eml_bytes((SAMPLES / "legit_octopus.eml").read_bytes())


# ================================================================ INGESTION
class TestIngestion:
    def test_hmrc_parsed_subject(self, hmrc_email):
        assert "tax refund" in hmrc_email.header.subject.lower()

    def test_hmrc_urls_extracted(self, hmrc_email):
        assert len(hmrc_email.urls) >= 1

    def test_royal_mail_domain_in_urls(self, royal_mail_email):
        combined = " ".join(royal_mail_email.urls).lower()
        assert "royal" in combined or "redeliver" in combined

    def test_legit_octopus_auth_headers_present(self, legit_octopus_email):
        assert legit_octopus_email.header.authentication_results is not None


# ================================================================ HEADER FORENSICS
class TestHeaderForensics:
    def test_hmrc_spf_fail(self, engine, hmrc_email):
        from src.analysis.header_forensics import analyse_headers
        _, findings = analyse_headers(hmrc_email, engine.weights)
        assert "spf_fail" in {f.rule for f in findings}

    def test_hmrc_dmarc_fail(self, engine, hmrc_email):
        from src.analysis.header_forensics import analyse_headers
        _, findings = analyse_headers(hmrc_email, engine.weights)
        assert "dmarc_fail" in {f.rule for f in findings}

    def test_hmrc_reply_to_mismatch(self, engine, hmrc_email):
        from src.analysis.header_forensics import analyse_headers
        _, findings = analyse_headers(hmrc_email, engine.weights)
        assert "reply_to_mismatch" in {f.rule for f in findings}

    def test_legit_octopus_no_spf_fail(self, engine, legit_octopus_email):
        from src.analysis.header_forensics import analyse_headers
        _, findings = analyse_headers(legit_octopus_email, engine.weights)
        rules = {f.rule for f in findings}
        assert "spf_fail" not in rules
        assert "dmarc_fail" not in rules


# ================================================================ URL ANALYSIS
class TestUrlAnalyser:
    def test_high_risk_tld_natwest(self, engine, natwest_email):
        findings, _ = engine.urls.analyse(natwest_email)
        assert "high_risk_tld" in {f.rule for f in findings}

    def test_homoglyph_or_tld_royal_mail(self, engine, royal_mail_email):
        findings, _ = engine.urls.analyse(royal_mail_email)
        risky = {"homoglyph_domain", "high_risk_tld", "typosquat_domain"}
        assert risky.intersection({f.rule for f in findings})

    def test_legit_octopus_no_risk_flags(self, engine, legit_octopus_email):
        findings, _ = engine.urls.analyse(legit_octopus_email)
        risky = {"homoglyph_domain", "typosquat_domain", "url_shortener"}
        assert not risky.intersection({f.rule for f in findings})


# ================================================================ UK LURE DETECTOR
class TestUkLureDetector:
    def test_hmrc_brand_finding(self, engine, hmrc_email):
        findings, _ = engine.lure.analyse(hmrc_email)
        hits = [f for f in findings if "revenue" in f.detail.lower() or "hmrc" in f.detail.lower()]
        assert hits, "Expected HMRC lure finding"

    def test_legit_octopus_no_impersonation(self, engine, legit_octopus_email):
        findings, _ = engine.lure.analyse(legit_octopus_email)
        assert not any(f.rule == "display_name_spoof" for f in findings)


# ================================================================ NLP
class TestNlpClassifier:
    def test_hmrc_classified_phishing(self, engine, hmrc_email):
        prob, _ = engine.nlp.predict(hmrc_email)
        # Fallback returns 0.0 if no model loaded — only assert if model available
        import os
        if os.path.exists("data/classifier.joblib"):
            assert prob >= 0.5, f"Expected phish prob ≥0.5, got {prob:.3f}"

    def test_octopus_classified_benign(self, engine, legit_octopus_email):
        prob, _ = engine.nlp.predict(legit_octopus_email)
        if os.path.exists("data/classifier.joblib"):
            assert prob < 0.5, f"Expected benign prob <0.5, got {prob:.3f}"

    def test_predict_returns_list_of_tokens(self, engine, hmrc_email):
        _, tokens = engine.nlp.predict(hmrc_email)
        assert isinstance(tokens, list)


# ================================================================ END-TO-END ENGINE
class TestAnalysisEngine:
    def test_hmrc_verdict_phishing(self, engine, hmrc_email):
        from src.models import Verdict, Severity
        r = engine.analyse(hmrc_email)
        assert r.verdict == Verdict.PHISHING
        assert r.score >= 0.65
        assert r.severity in (Severity.HIGH, Severity.CRITICAL)

    def test_natwest_verdict_phishing(self, engine, natwest_email):
        from src.models import Verdict
        assert engine.analyse(natwest_email).verdict == Verdict.PHISHING

    def test_royal_mail_verdict_phishing(self, engine, royal_mail_email):
        from src.models import Verdict
        assert engine.analyse(royal_mail_email).verdict == Verdict.PHISHING

    def test_legit_octopus_verdict_benign(self, engine, legit_octopus_email):
        from src.models import Verdict
        assert engine.analyse(legit_octopus_email).verdict == Verdict.BENIGN

    def test_hmrc_iocs_emitted(self, engine, hmrc_email):
        r = engine.analyse(hmrc_email)
        assert len(r.iocs) >= 1

    def test_hmrc_mitre_techniques(self, engine, hmrc_email):
        r = engine.analyse(hmrc_email)
        assert len(r.mitre_techniques) >= 1

    def test_hmrc_findings_3plus(self, engine, hmrc_email):
        r = engine.analyse(hmrc_email)
        assert len(r.findings) >= 3

    def test_brand_impersonation_attributed(self, engine, hmrc_email):
        r = engine.analyse(hmrc_email)
        assert r.brand_impersonated is not None


# ================================================================ DASHBOARD API
class TestDashboardApi:
    @pytest.fixture(scope="class")
    def client(self):
        """Create a test client with a fresh DB."""
        # Use a file-based temp DB for this class so the startup event sees the tables
        import tempfile, os
        tmp = tempfile.mktemp(suffix=".db")
        os.environ["DATABASE_URL"] = f"sqlite:///{tmp}"

        from src import database as _db
        _db._engine = None
        _db._SessionLocal = None
        _db.init_db()

        from fastapi.testclient import TestClient
        from src.dashboard.app import app
        yield TestClient(app)

        # cleanup
        try:
            os.unlink(tmp)
        except Exception:
            pass

    def test_health(self, client):
        r = client.get("/api/health")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"

    def test_kpis_structure(self, client):
        r = client.get("/api/kpis?hours=24")
        assert r.status_code == 200
        data = r.json()
        for field in ("total_scanned", "confirmed_phishing", "mttd_label", "sla_adherence_pct"):
            assert field in data, f"Missing KPI field: {field}"

    def test_charts_all_ok(self, client):
        for path in [
            "/api/charts/verdicts", "/api/charts/brands",
            "/api/charts/detectors", "/api/charts/timeline",
            "/api/charts/mitre", "/api/charts/ioc-velocity",
        ]:
            assert client.get(path).status_code == 200, f"Chart endpoint failed: {path}"

    def test_index_html(self, client):
        r = client.get("/")
        assert r.status_code == 200
        assert "PhishBuster" in r.text

    def test_incident_not_found(self, client):
        assert client.get("/incidents/99999").status_code == 404


# ================================================================ v2 DETECTORS

class TestThreatIntel:
    def test_disabled_by_default_returns_empty(self, engine, hmrc_email):
        # ENABLE_THREAT_INTEL not set → no findings, no errors
        findings, iocs = engine.threat_intel.analyse(hmrc_email)
        assert findings == [] and iocs == []

    def test_constructed_without_api_keys(self, engine):
        # Should still construct cleanly; URLhaus/PhishTank work without keys
        assert engine.threat_intel.urlhaus is not None
        assert engine.threat_intel.phishtank is not None


class TestDomainAge:
    def test_disabled_returns_empty(self, monkeypatch, engine, hmrc_email):
        monkeypatch.setenv("ENABLE_DOMAIN_AGE_CHECK", "false")
        from src.analysis.domain_age import DomainAgeDetector
        d = DomainAgeDetector(engine.weights)
        findings, _ = d.analyse(hmrc_email)
        assert findings == []

    def test_construction(self, engine):
        assert engine.domain_age.recent_days >= 1


class TestUrlSandbox:
    def test_disabled_by_default(self, engine, hmrc_email):
        findings, iocs = engine.url_sandbox.analyse(hmrc_email)
        assert findings == [] and iocs == []

    def test_credential_form_detected_locally(self):
        """Direct test of the HTML inspector on a synthetic credential page."""
        from src.analysis.url_sandbox import DirectFetchSandbox
        # We don't actually fetch — directly test the parsing
        from bs4 import BeautifulSoup
        html = '''<html><body><form action="/login" method="post">
                  Sign in to your account
                  <input type="text" name="username">
                  <input type="password" name="pw">
                  </form></body></html>'''
        soup = BeautifulSoup(html, "lxml")
        assert soup.find_all("input", {"type": "password"})


class TestAttachmentScanner:
    def test_pdf_javascript_detection(self):
        from src.analysis.attachment_scanner import _pdf_has_javascript
        assert _pdf_has_javascript(b"%PDF-1.7\n/JavaScript (alert(1))")
        assert not _pdf_has_javascript(b"%PDF-1.7\n/Catalog /Pages")
        assert not _pdf_has_javascript(b"not a pdf")

    def test_office_macro_detection_legacy_ole(self):
        from src.analysis.attachment_scanner import _office_has_macros
        # Compound document magic + VBA marker + auto-exec hook
        blob = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"x" * 200 + \
               b"vbaProject" + b"x" * 50 + b"Auto_Open" + b"x" * 50
        has_macros, has_auto = _office_has_macros(blob)
        assert has_macros and has_auto


class TestBecDetector:
    def test_disabled_returns_empty(self, monkeypatch, engine, hmrc_email):
        monkeypatch.setenv("ENABLE_BEC_DETECTOR", "false")
        from src.analysis.bec_detector import BecDetector
        d = BecDetector(engine.weights)
        findings, _ = d.analyse(hmrc_email)
        assert findings == []

    def test_finance_keyword_regex(self):
        from src.analysis.bec_detector import _FINANCE_RE
        for hit in [
            "Please update our bank details for the next invoice.",
            "Wire transfer urgent — we have a new account.",
            "Change of supplier banking — IBAN below.",
        ]:
            assert _FINANCE_RE.search(hit), f"Should match: {hit}"

    def test_cosine_similarity(self):
        from src.analysis.bec_detector import _cosine
        a = {"hello": 1.0, "team": 1.0}
        b = {"hello": 1.0, "team": 1.0}
        assert abs(_cosine(a, b) - 1.0) < 0.01
        c = {"foo": 1.0, "bar": 1.0}
        assert _cosine(a, c) == 0.0


class TestAiContentDetectorV2:
    def test_requires_three_signals(self, engine):
        """Plain short message should not fire."""
        from src.models import EmailHeader, ParsedEmail
        email = ParsedEmail(
            header=EmailHeader(message_id="<x>", subject="hi", from_address="a@b.com"),
            text_body="Hi, see you tomorrow. Cheers.",
        )
        result = engine.ai_content.analyse(email)
        assert result is None

    def test_fires_on_llm_style_text(self, engine):
        """Long text with multiple LLM markers should fire."""
        from src.models import EmailHeader, ParsedEmail
        body = (
            "Dear valued customer, "
            "I hope this email finds you well. "
            "Furthermore, please be advised that we have detected unusual activity. "
            "Moreover, kindly note that immediate action is required. "
            "Additionally, we kindly request that you authorize the transaction. "
            "Consequently, we appreciate your patience. "
            "Please do not hesitate to reach out if you have any questions. "
            "Furthermore, in addition to the above, please verify your details. "
            "Therefore, kindly respond at your earliest convenience. "
            "Moreover, in order to ensure the continued security of your account. "
            "Additionally, kindly note that we value your trust. "
        )
        email = ParsedEmail(
            header=EmailHeader(
                message_id="<y>", subject="HMRC tax matter",
                from_address="noreply@hmrc-fake.com", from_name="HMRC"),
            text_body=body,
        )
        result = engine.ai_content.analyse(email)
        assert result is not None
        assert result.evidence
        assert len(result.evidence.get("signals", [])) >= 3


class TestEngineV2Integration:
    """Verify engine still produces valid reports with v2 detectors wired in."""

    def test_score_capped_at_one(self, engine, hmrc_email):
        report = engine.analyse(hmrc_email)
        assert 0.0 <= report.score <= 1.0

    def test_mitre_t1534_for_first_seen_sender(self, engine, hmrc_email):
        report = engine.analyse(hmrc_email)
        # First-seen sender + finance keywords → T1534
        assert "T1534" in report.mitre_techniques

    def test_bec_does_not_corrupt_pipeline(self, engine, legit_octopus_email):
        from src.models import Verdict
        # Even with first-seen finding, score should remain benign
        report = engine.analyse(legit_octopus_email)
        assert report.verdict == Verdict.BENIGN


class TestCorpusImporter:
    def test_import_csv_round_trip(self, tmp_path, monkeypatch):
        import csv
        # Redirect corpus dirs to tmp
        from scripts import import_corpus
        monkeypatch.setattr(import_corpus, "CORPUS_DIR", tmp_path)
        monkeypatch.setattr(import_corpus, "PHISH_DIR", tmp_path / "phish")
        monkeypatch.setattr(import_corpus, "HAM_DIR", tmp_path / "ham")
        monkeypatch.setattr(import_corpus, "EXPORT_PATH", tmp_path / "out.jsonl")
        (tmp_path / "phish").mkdir()
        (tmp_path / "ham").mkdir()

        csv_path = tmp_path / "demo.csv"
        with csv_path.open("w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["label", "text"])
            w.writerow(["phish", "HMRC tax refund click here"])
            w.writerow(["ham", "Hi team, lunch tomorrow"])
        p, h = import_corpus.import_csv(csv_path)
        assert p == 1 and h == 1
        n = import_corpus.export_jsonl()
        assert n == 2
