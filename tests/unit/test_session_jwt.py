"""Unit tests for SessionTester and JWTAnalyzer."""

import pytest
from unittest.mock import MagicMock, patch
import json
import base64
import time
from tests.conftest import make_mock_response, BASE_URL

from modules.session_tester import SessionTester
from modules.jwt_analyzer import JWTAnalyzer


class TestSessionTester:
    def setup_method(self):
        self.session = MagicMock()
        self.session.cookies = []

    def test_entropy_high(self):
        tester = SessionTester(self.session, BASE_URL)
        e = tester._calc_entropy('a1b2c3d4e5f6g7h8i9j0')
        assert e > 3.0

    def test_entropy_low(self):
        tester = SessionTester(self.session, BASE_URL)
        e = tester._calc_entropy('aaaaaa')
        assert e == 0.0

    def test_entropy_empty(self):
        tester = SessionTester(self.session, BASE_URL)
        assert tester._calc_entropy('') == 0.0

    def test_get_session_cookies(self):
        cookie = MagicMock()
        cookie.name = 'sessionid'
        cookie.value = 'abc123'
        self.session.cookies = [cookie]
        tester = SessionTester(self.session, BASE_URL)
        result = tester._get_session_cookies()
        assert len(result) == 1

    def test_no_session_cookies(self):
        cookie = MagicMock()
        cookie.name = 'theme'
        cookie.value = 'dark'
        self.session.cookies = [cookie]
        tester = SessionTester(self.session, BASE_URL)
        result = tester._get_session_cookies()
        assert len(result) == 0

    def test_secure_transport_insecure(self):
        cookie = MagicMock()
        cookie.name = 'sessionid'
        cookie.value = 'abc'
        cookie.secure = False
        self.session.cookies = [cookie]
        tester = SessionTester(self.session, BASE_URL)
        tester.test_secure_transport()
        assert any('Insecure' in f['title'] for f in tester.findings)

    def test_secure_transport_secure(self):
        cookie = MagicMock()
        cookie.name = 'sessionid'
        cookie.value = 'abc'
        cookie.secure = True
        self.session.cookies = [cookie]
        tester = SessionTester(self.session, BASE_URL)
        tester.test_secure_transport()
        assert len(tester.findings) == 0

    def test_run_all_checks(self):
        self.session.cookies = []
        self.session.get.return_value = make_mock_response(200)
        tester = SessionTester(self.session, BASE_URL)
        results = tester.run_all_checks()
        assert isinstance(results, list)


class TestJWTAnalyzer:
    def _make_jwt(self, header=None, payload=None):
        h = header or {'alg': 'HS256', 'typ': 'JWT'}
        p = payload or {'sub': '1', 'exp': int(time.time()) + 3600}
        h_b64 = base64.urlsafe_b64encode(json.dumps(h).encode()).rstrip(b'=').decode()
        p_b64 = base64.urlsafe_b64encode(json.dumps(p).encode()).rstrip(b'=').decode()
        return f"{h_b64}.{p_b64}.fakesignature"

    def test_is_jwt_valid(self):
        session = MagicMock()
        session.cookies = []
        session.headers = {}
        analyzer = JWTAnalyzer(session, BASE_URL)
        assert analyzer._is_jwt(self._make_jwt())

    def test_is_jwt_invalid(self):
        session = MagicMock()
        session.cookies = []
        session.headers = {}
        analyzer = JWTAnalyzer(session, BASE_URL)
        assert not analyzer._is_jwt('not.a.jwt.token.here')
        assert not analyzer._is_jwt('simple_string')

    def test_decode_jwt_parts(self):
        session = MagicMock()
        session.cookies = []
        session.headers = {}
        analyzer = JWTAnalyzer(session, BASE_URL)
        header, payload = analyzer._decode_jwt_parts(self._make_jwt())
        assert header['alg'] == 'HS256'
        assert payload['sub'] == '1'

    def test_symmetric_algorithm_warning(self):
        session = MagicMock()
        session.cookies = []
        session.headers = {}
        analyzer = JWTAnalyzer(session, BASE_URL)
        token = self._make_jwt()
        analyzer.test_algorithm_confusion(token)
        assert any('Symmetric' in f['title'] for f in analyzer.findings)

    def test_claims_missing_exp(self):
        session = MagicMock()
        session.cookies = []
        session.headers = {}
        analyzer = JWTAnalyzer(session, BASE_URL)
        token = self._make_jwt(payload={'sub': '1'})
        analyzer.test_claims_validation(token)
        assert any('Claims' in f['title'] for f in analyzer.findings)

    def test_claims_all_present(self):
        session = MagicMock()
        session.cookies = []
        session.headers = {}
        analyzer = JWTAnalyzer(session, BASE_URL)
        token = self._make_jwt(payload={
            'sub': '1', 'exp': int(time.time()) + 3600,
            'iss': 'test', 'aud': 'test', 'iat': int(time.time()),
            'nbf': int(time.time())
        })
        analyzer.test_claims_validation(token)
        assert len(analyzer.findings) == 0

    def test_kid_present_warning(self):
        session = MagicMock()
        session.cookies = []
        session.headers = {}
        analyzer = JWTAnalyzer(session, BASE_URL)
        token = self._make_jwt(header={'alg': 'HS256', 'kid': 'key-1'})
        analyzer.test_kid_injection(token)
        assert any('kid' in f['title'] for f in analyzer.findings)

    def test_jku_present_warning(self):
        session = MagicMock()
        session.cookies = []
        session.headers = {}
        analyzer = JWTAnalyzer(session, BASE_URL)
        token = self._make_jwt(header={'alg': 'RS256', 'jku': 'https://evil.com/jwks.json'})
        analyzer.test_jku_injection(token)
        assert any('JKU' in f['title'] for f in analyzer.findings)

    def test_no_tokens_found(self):
        session = MagicMock()
        session.cookies = []
        session.headers = {}
        analyzer = JWTAnalyzer(session, BASE_URL)
        results = analyzer.run_all_checks()
        assert results == []
