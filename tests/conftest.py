"""
Shared pytest fixtures for PreFlight Security Scanner test suite.
"""

import pytest
import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch
import requests


BASE_URL = 'http://testsite.local'
API_BASE = 'http://testsite.local/api'


@pytest.fixture
def base_url():
    return BASE_URL


@pytest.fixture
def api_base():
    return API_BASE


@pytest.fixture
def mock_session():
    """Create a mock requests.Session."""
    session = MagicMock(spec=requests.Session)
    session.cookies = MagicMock()
    session.cookies.__iter__ = MagicMock(return_value=iter([]))
    session.cookies.get_dict = MagicMock(return_value={})
    session.headers = {}
    session.verify = False
    return session


@pytest.fixture
def real_session():
    """Create a real requests.Session (for mocking with responses lib)."""
    session = requests.Session()
    session.verify = False
    return session


@pytest.fixture
def temp_output_dir():
    """Create a temporary directory for report output."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def sample_finding_critical():
    return {
        'title': 'SQL Injection Vulnerability',
        'description': 'SQL injection in search parameter',
        'severity': 'CRITICAL',
        'owasp': 'A03:2021',
        'cwe': 'CWE-89',
        'remediation': 'Use parameterized queries',
        'evidence': 'Payload triggered SQL error'
    }


@pytest.fixture
def sample_finding_high():
    return {
        'title': 'XSS Vulnerability',
        'description': 'Reflected XSS in search',
        'severity': 'HIGH',
        'owasp': 'A03:2021',
        'cwe': 'CWE-79',
        'remediation': 'Encode output',
        'evidence': 'Payload reflected'
    }


@pytest.fixture
def sample_finding_medium():
    return {
        'title': 'Missing CSP Header',
        'description': 'No Content-Security-Policy',
        'severity': 'MEDIUM',
        'owasp': 'A05:2021',
        'cwe': 'CWE-693',
        'remediation': 'Add CSP header',
        'evidence': 'CSP absent'
    }


@pytest.fixture
def sample_finding_low():
    return {
        'title': 'Server Version Disclosed',
        'description': 'Server header reveals version',
        'severity': 'LOW',
        'cwe': 'CWE-200',
        'remediation': 'Remove Server header',
        'evidence': 'Server: Apache/2.4.51'
    }


@pytest.fixture
def sample_findings(sample_finding_critical, sample_finding_high,
                    sample_finding_medium, sample_finding_low):
    return [sample_finding_critical, sample_finding_high,
            sample_finding_medium, sample_finding_low]


@pytest.fixture
def sample_report_data(sample_findings):
    return {
        'scanner_version': '2.0.0',
        'target': BASE_URL,
        'scan_time': '2026-03-29T12:00:00',
        'duration_seconds': 42.5,
        'scan_mode': 'full',
        'authenticated': False,
        'total_findings': len(sample_findings),
        'findings': sample_findings,
        'mitre_summary': {}
    }


def make_mock_response(status_code=200, text='', headers=None, json_data=None, url=''):
    """Factory for creating mock HTTP responses."""
    resp = MagicMock(spec=requests.Response)
    resp.status_code = status_code
    resp.text = text
    resp.url = url or BASE_URL
    resp.headers = headers or {}
    if json_data is not None:
        resp.json.return_value = json_data
        resp.text = json.dumps(json_data)
    else:
        resp.json.side_effect = ValueError("No JSON")
    return resp
