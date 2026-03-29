"""Unit tests for the 8 newest V2.0 Enterprise Modules:
WAFDetector, PathBypassTester, DirectoryBruteforcer, OASTTester,
WebCrawler, LFITester, GraphQLTester, LLMInjectionTester.
"""

import pytest
from unittest.mock import MagicMock, patch
from tests.conftest import make_mock_response, BASE_URL

# --- WAF Detector ---
from modules.waf_detector import WAFDetector

class TestWAFDetector:
    def setup_method(self):
        self.session = MagicMock()

    def test_cloudflare_detected(self):
        resp1 = make_mock_response(200, headers={'cf-ray': '12345'})
        resp2 = make_mock_response(403, headers={'cf-ray': '12345'})
        self.session.get.side_effect = [resp1, resp2]
        tester = WAFDetector(self.session, BASE_URL)
        tester.detect_waf()
        assert any('Cloudflare' in f['title'] for f in tester.findings)

    def test_generic_waf_detected(self):
        resp1 = make_mock_response(200)
        resp2 = make_mock_response(406)
        self.session.get.side_effect = [resp1, resp2]
        tester = WAFDetector(self.session, BASE_URL)
        tester.detect_waf()
        assert any('WAF' in f['title'] for f in tester.findings)

# --- Path Bypass Tester ---
from modules.path_bypass_tester import PathBypassTester

class TestPathBypassTester:
    def setup_method(self):
        self.session = MagicMock()

    def test_path_normalization_bypass(self):
        def mock_get(url, *args, **kwargs):
            if '/%2e/' in url:
                return make_mock_response(200, text='Admin Panel')
            return make_mock_response(403)
        self.session.get.side_effect = mock_get
        tester = PathBypassTester(self.session, BASE_URL)
        tester.test_path_normalization()
        assert any('Bypass' in f['title'] for f in tester.findings)

# --- Directory Bruteforcer ---
from modules.directory_bruteforcer import DirectoryBruteforcer

class TestDirectoryBruteforcer:
    def setup_method(self):
        self.session = MagicMock()

    def test_directory_found(self):
        def mock_get(url, *args, **kwargs):
            if 'admin' in url or '.env' in url:
                return make_mock_response(200, text='SECRET=123')
            return make_mock_response(404)
        self.session.get.side_effect = mock_get
        tester = DirectoryBruteforcer(self.session, BASE_URL)
        # Mock the payload list to avoid real downloads in unit tests
        tester.payloads = ['admin', '.env']
        tester.bruteforce()
        assert len(tester.findings) > 0

# --- LFI Tester ---
from modules.lfi_tester import LFITester

class TestLFITester:
    def setup_method(self):
        self.session = MagicMock()

    def test_lfi_query_param(self):
        def mock_get(url, *args, **kwargs):
            if 'etc/passwd' in url:
                return make_mock_response(200, text='root:x:0:0:root:/root:/bin/bash')
            return make_mock_response(200)
        self.session.get.side_effect = mock_get
        tester = LFITester(self.session, BASE_URL)
        tester.test_path_traversal()
        assert any('Local File Inclusion' in f['title'] for f in tester.findings)

# --- GraphQL Tester ---
from modules.graphql_tester import GraphQLTester

class TestGraphQLTester:
    def setup_method(self):
        self.session = MagicMock()

    def test_introspection_enabled(self):
        resp = make_mock_response(200, text='{"data": {"__schema": {"queryType": {"name": "Query"}}}}')
        self.session.post.return_value = resp
        self.session.get.return_value = make_mock_response(200, text='{"data": {"__typename": "Query"}}')
        
        tester = GraphQLTester(self.session, BASE_URL)
        endpoint = tester.discover_endpoint()
        tester.test_introspection(endpoint or f"{BASE_URL}/graphql")
        assert any('Introspection Enabled' in f['title'] for f in tester.findings)

# --- LLM Injection Tester ---
from modules.llm_injection_tester import LLMInjectionTester

class TestLLMInjectionTester:
    def setup_method(self):
        self.session = MagicMock()

    def test_direct_prompt_injection(self):
        resp_discover = make_mock_response(200, text='{"response": "Hello"}')
        resp_inject = make_mock_response(200, text='{"response": "VULNERABLE_LLM_INJECTION"}')
        
        # First call is discover (Hello), subsequent is injection
        self.session.post.side_effect = [resp_discover, resp_inject, resp_inject, resp_inject, resp_inject]
        
        tester = LLMInjectionTester(self.session, BASE_URL)
        tester.llm_endpoints = ['/api/chat'] # Limit for test speed
        endpoints = tester._discover_llm_endpoints()
        if endpoints:
            tester.test_direct_prompt_injection(endpoints[0])
            
        assert any('Direct Prompt Injection' in f['title'] for f in tester.findings)

# --- Web Crawler ---
from modules.web_crawler import WebCrawler

class TestWebCrawler:
    def setup_method(self):
        self.session = MagicMock()

    def test_crawler_finds_forms(self):
        html_content = '''
        <html><body>
            <a href="/about">About</a>
            <form action="/login" method="POST">
                <input type="text" name="user">
            </form>
        </body></html>
        '''
        resp = make_mock_response(200, text=html_content, headers={'Content-Type': 'text/html'})
        self.session.get.return_value = resp
        
        tester = WebCrawler(self.session, BASE_URL, max_depth=1)
        tester.run_all_checks()
        
        assert any('Attack Surface Mapped' in f['title'] for f in tester.findings)
