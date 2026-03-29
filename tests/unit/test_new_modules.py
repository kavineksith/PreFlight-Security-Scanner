"""Unit tests for CORSTester, CSRFTester, SSRFTester, InjectionTester, and other new modules.
Uses mocked HTTP responses to test logic without network calls.
"""

import pytest
from unittest.mock import MagicMock, patch, PropertyMock
import json
from tests.conftest import make_mock_response, BASE_URL

# --- CORS Tester ---
from modules.cors_tester import CORSTester

class TestCORSTester:
    def setup_method(self):
        self.session = MagicMock()
        self.tester = CORSTester(self.session, BASE_URL)

    def test_wildcard_origin_detected(self):
        resp = make_mock_response(200, headers={'Access-Control-Allow-Origin': '*'})
        self.session.options.return_value = resp
        self.tester.test_wildcard_origin()
        assert any('Wildcard' in f['title'] for f in self.tester.findings)

    def test_null_origin_detected(self):
        resp = make_mock_response(200, headers={'Access-Control-Allow-Origin': 'null'})
        self.session.options.return_value = resp
        self.tester.test_null_origin()
        assert any('Null' in f['title'] for f in self.tester.findings)

    def test_reflected_origin_detected(self):
        resp = make_mock_response(200, headers={'Access-Control-Allow-Origin': 'https://evil.com'})
        self.session.options.return_value = resp
        self.tester.test_reflected_origin()
        assert any('Reflection' in f['title'] for f in self.tester.findings)

    def test_credentials_with_wildcard(self):
        resp = make_mock_response(200, headers={
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Credentials': 'true'
        })
        self.session.options.return_value = resp
        self.tester.test_credentials_with_wildcard()
        assert any('Credentials' in f['title'] for f in self.tester.findings)

    def test_no_cors_issues(self):
        resp = make_mock_response(200, headers={})
        self.session.options.return_value = resp
        self.tester.test_wildcard_origin()
        assert len(self.tester.findings) == 0

    def test_run_all_checks(self):
        resp = make_mock_response(200, headers={})
        self.session.options.return_value = resp
        self.session.post.return_value = resp
        results = self.tester.run_all_checks()
        assert isinstance(results, list)


# --- Header Analyzer ---
from modules.header_analyzer import HeaderAnalyzer

class TestHeaderAnalyzer:
    def setup_method(self):
        self.session = MagicMock()
        resp = make_mock_response(200, headers={})
        resp.headers = {}
        self.session.get.return_value = resp
        self.session.cookies = []

    def test_missing_security_headers(self):
        analyzer = HeaderAnalyzer(self.session, BASE_URL)
        findings = analyzer.run_all_checks()
        header_findings = [f for f in findings if 'Missing Security Header' in f['title']]
        assert len(header_findings) > 0  # Should find missing headers

    def test_server_fingerprint_detected(self):
        resp = make_mock_response(200, headers={'Server': 'Apache/2.4.51', 'X-Powered-By': 'PHP/8.1'})
        self.session.get.return_value = resp
        self.session.cookies = []
        analyzer = HeaderAnalyzer(self.session, BASE_URL)
        findings = analyzer.run_all_checks()
        fp_findings = [f for f in findings if 'Information Disclosure' in f['title']]
        assert len(fp_findings) > 0

    def test_csp_weakness_detected(self):
        resp = make_mock_response(200, headers={
            'Content-Security-Policy': "default-src * 'unsafe-inline' 'unsafe-eval'"
        })
        self.session.get.return_value = resp
        self.session.cookies = []
        analyzer = HeaderAnalyzer(self.session, BASE_URL)
        findings = analyzer.run_all_checks()
        csp_findings = [f for f in findings if 'CSP' in f['title'] or 'Content-Security' in f['title']]
        assert len(csp_findings) > 0


# --- HTTP Method Tester ---
from modules.http_method_tester import HTTPMethodTester

class TestHTTPMethodTester:
    def setup_method(self):
        self.session = MagicMock()
        self.tester = HTTPMethodTester(self.session, BASE_URL)

    def test_trace_method_detected(self):
        resp = make_mock_response(200)
        self.session.request.return_value = resp
        self.tester.test_dangerous_methods()
        trace_findings = [f for f in self.tester.findings if 'TRACE' in f['title']]
        assert len(trace_findings) > 0

    def test_methods_blocked(self):
        resp = make_mock_response(405)
        self.session.request.return_value = resp
        self.tester.test_dangerous_methods()
        assert len(self.tester.findings) == 0

    def test_no_https(self):
        tester = HTTPMethodTester(self.session, 'http://example.com')
        tester.test_protocol_downgrade()
        assert any('HTTPS' in f['title'] for f in tester.findings)


# --- Crypto Analyzer ---
from modules.crypto_analyzer import CryptoAnalyzer

class TestCryptoAnalyzer:
    def setup_method(self):
        self.session = MagicMock()
        self.session.cookies = []

    def test_entropy_calculation(self):
        analyzer = CryptoAnalyzer(self.session, BASE_URL)
        high = analyzer._calc_entropy('a1b2c3d4e5f6g7h8')
        low = analyzer._calc_entropy('aaaaaaaaaaaaaaaa')
        assert high > low

    def test_empty_entropy(self):
        analyzer = CryptoAnalyzer(self.session, BASE_URL)
        assert analyzer._calc_entropy('') == 0.0

    def test_run_all_checks(self):
        resp = make_mock_response(200, text='normal response')
        self.session.get.return_value = resp
        analyzer = CryptoAnalyzer(self.session, BASE_URL)
        results = analyzer.run_all_checks()
        assert isinstance(results, list)


# --- Privilege Escalation Tester ---
from modules.privilege_escalation_tester import PrivilegeEscalationTester

class TestPrivilegeEscalationTester:
    def setup_method(self):
        self.session = MagicMock()
        self.session.cookies = []

    def test_forced_browsing_detected(self):
        resp = make_mock_response(200, text='Admin Dashboard Content')
        resp.url = BASE_URL + '/admin'
        self.session.get.return_value = resp
        tester = PrivilegeEscalationTester(self.session, BASE_URL)
        tester.test_forced_browsing()
        assert any('Forced Browsing' in f['title'] for f in tester.findings)

    def test_forced_browsing_blocked(self):
        resp = make_mock_response(403, text='Forbidden')
        self.session.get.return_value = resp
        tester = PrivilegeEscalationTester(self.session, BASE_URL)
        tester.test_forced_browsing()
        assert len(tester.findings) == 0

    def test_run_all_checks(self):
        resp = make_mock_response(403, text='Forbidden')
        self.session.get.return_value = resp
        self.session.put.return_value = resp
        tester = PrivilegeEscalationTester(self.session, BASE_URL)
        results = tester.run_all_checks()
        assert isinstance(results, list)


# --- Rate Limiter Tester ---
from modules.rate_limiter_tester import RateLimiterTester

class TestRateLimiterTester:
    def setup_method(self):
        self.session = MagicMock()

    def test_captcha_missing(self):
        resp = make_mock_response(200, text='<form><input name="user"></form>')
        self.session.get.return_value = resp
        tester = RateLimiterTester(self.session, BASE_URL)
        tester.test_captcha_presence()
        assert any('CAPTCHA' in f['title'] for f in tester.findings)

    def test_captcha_present(self):
        resp = make_mock_response(200, text='<div class="g-recaptcha"></div>')
        self.session.get.return_value = resp
        tester = RateLimiterTester(self.session, BASE_URL)
        tester.test_captcha_presence()
        assert len(tester.findings) == 0


# --- Param Pollution Tester ---
from modules.param_pollution_tester import ParamPollutionTester

class TestParamPollutionTester:
    def setup_method(self):
        self.session = MagicMock()

    def test_type_juggling_detected(self):
        resp = make_mock_response(200, text='{"token": "abc123"}')
        self.session.post.return_value = resp
        tester = ParamPollutionTester(self.session, BASE_URL)
        tester.test_type_juggling()
        assert any('Type Juggling' in f['title'] for f in tester.findings)

    def test_type_juggling_blocked(self):
        resp = make_mock_response(401, text='Unauthorized')
        self.session.post.return_value = resp
        tester = ParamPollutionTester(self.session, BASE_URL)
        tester.test_type_juggling()
        assert len(tester.findings) == 0


# --- Auth Bypass Tester ---
from modules.auth_bypass_tester import AuthBypassTester

class TestAuthBypassTester:
    def setup_method(self):
        self.session = MagicMock()

    def test_verb_tampering_detected(self):
        def mock_request(method, url, **kwargs):
            if method == 'GET':
                return make_mock_response(403)
            return make_mock_response(200)
        self.session.request.side_effect = mock_request
        tester = AuthBypassTester(self.session, BASE_URL)
        tester.test_verb_tampering()
        assert any('Verb Tampering' in f['title'] for f in tester.findings)

    def test_path_bypass_blocked(self):
        resp = make_mock_response(403, text='Forbidden')
        self.session.get.return_value = resp
        tester = AuthBypassTester(self.session, BASE_URL)
        tester.test_path_bypass()
        assert len(tester.findings) == 0
