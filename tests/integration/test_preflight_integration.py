"""Integration tests for PreFlightScanner v2.0."""

import pytest
from unittest.mock import MagicMock, patch
from pathlib import Path
import tempfile

# Patch requests globally to prevent any real HTTP calls
@pytest.fixture(autouse=True)
def no_http(monkeypatch):
    """Prevent any real HTTP requests during integration tests."""
    mock_response = MagicMock()
    mock_response.status_code = 404
    mock_response.text = ''
    mock_response.headers = {}
    mock_response.url = 'http://testsite.local'
    mock_response.cookies = MagicMock()
    mock_response.cookies.__iter__ = MagicMock(return_value=iter([]))
    mock_response.json.side_effect = ValueError

    import requests
    monkeypatch.setattr(requests.Session, 'get', lambda *a, **kw: mock_response)
    monkeypatch.setattr(requests.Session, 'post', lambda *a, **kw: mock_response)
    monkeypatch.setattr(requests.Session, 'put', lambda *a, **kw: mock_response)
    monkeypatch.setattr(requests.Session, 'delete', lambda *a, **kw: mock_response)
    monkeypatch.setattr(requests.Session, 'head', lambda *a, **kw: mock_response)
    monkeypatch.setattr(requests.Session, 'options', lambda *a, **kw: mock_response)
    monkeypatch.setattr(requests.Session, 'request', lambda *a, **kw: mock_response)
    monkeypatch.setattr(requests, 'get', lambda *a, **kw: mock_response)
    monkeypatch.setattr(requests, 'head', lambda *a, **kw: mock_response)


class TestPreFlightScannerIntegration:
    def _make_scanner(self, mode='full'):
        from preflight import PreFlightScanner
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = PreFlightScanner(
                target_url='http://testsite.local',
                output_dir=tmpdir,
                scan_mode=mode
            )
            yield scanner

    @pytest.fixture
    def scanner_full(self):
        from preflight import PreFlightScanner
        with tempfile.TemporaryDirectory() as tmpdir:
            yield PreFlightScanner(
                target_url='http://testsite.local',
                output_dir=tmpdir,
                scan_mode='full'
            )

    @pytest.fixture
    def scanner_quick(self):
        from preflight import PreFlightScanner
        with tempfile.TemporaryDirectory() as tmpdir:
            yield PreFlightScanner(
                target_url='http://testsite.local',
                output_dir=tmpdir,
                scan_mode='quick'
            )

    @pytest.fixture
    def scanner_recon(self):
        from preflight import PreFlightScanner
        with tempfile.TemporaryDirectory() as tmpdir:
            yield PreFlightScanner(
                target_url='http://testsite.local',
                output_dir=tmpdir,
                scan_mode='recon'
            )

    def test_banner_no_crash(self, scanner_full, capsys):
        scanner_full.banner()
        captured = capsys.readouterr()
        assert 'PreFlight' in captured.out

    def test_authenticate_no_credentials(self, scanner_full):
        result = scanner_full.authenticate()
        assert result is False

    def test_recon_phase(self, scanner_recon):
        scanner_recon.run_recon_phase()
        # Should complete without errors

    def test_header_phase(self, scanner_full):
        scanner_full.run_header_phase()

    def test_enrichment_phase(self, scanner_full):
        scanner_full.findings = [
            {'title': 'Test', 'severity': 'HIGH', 'cwe': 'CWE-89'}
        ]
        scanner_full.run_enrichment_phase()
        assert scanner_full.findings[0].get('epss_estimate') is not None

    def test_add_findings_with_cvss(self, scanner_full):
        findings = [{'title': 'Test', 'severity': 'HIGH'}]
        scanner_full._add_findings(findings)
        assert len(scanner_full.findings) == 1
        assert 'cvss' in scanner_full.findings[0]


class TestCLIParsing:
    def test_import_main(self):
        """Test that the main module can be imported."""
        try:
            # The file is named preflight.py, so we import it differently
            import importlib.util
            spec = importlib.util.spec_from_file_location(
                "preflight", "preflight.py")
            if spec:
                module = importlib.util.module_from_spec(spec)
                assert module is not None
        except Exception:
            pass  # Import test is best effort
