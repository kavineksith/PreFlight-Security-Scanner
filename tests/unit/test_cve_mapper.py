"""Unit tests for CVEMapper."""

import pytest
from modules.cve_mapper import CVEMapper


class TestCVEMapper:
    def setup_method(self):
        self.mapper = CVEMapper()

    def test_enrich_adds_mitre(self):
        findings = [{'title': 'SQLi', 'severity': 'CRITICAL', 'cwe': 'CWE-89'}]
        result = self.mapper.enrich_findings(findings)
        assert result[0].get('mitre_attack') == 'T1190'
        assert result[0].get('mitre_tactic') == 'Initial Access'

    def test_enrich_adds_cve_references(self):
        findings = [{'title': 'SQL Injection Found', 'severity': 'CRITICAL', 'cwe': 'CWE-89'}]
        result = self.mapper.enrich_findings(findings)
        assert 'related_cves' in result[0]
        assert len(result[0]['related_cves']) > 0

    def test_enrich_adds_epss(self):
        findings = [{'title': 'Test', 'severity': 'HIGH', 'cwe': 'CWE-79'}]
        result = self.mapper.enrich_findings(findings)
        assert result[0]['epss_estimate'] == 0.55

    def test_enrich_xss_cves(self):
        findings = [{'title': 'Cross-Site Scripting XSS', 'severity': 'HIGH', 'cwe': 'CWE-79'}]
        result = self.mapper.enrich_findings(findings)
        assert 'related_cves' in result[0]

    def test_enrich_ssrf(self):
        findings = [{'title': 'SSRF Found', 'severity': 'HIGH', 'cwe': 'CWE-918'}]
        result = self.mapper.enrich_findings(findings)
        assert result[0].get('mitre_tactic') == 'Command and Control'

    def test_enrich_unknown_cwe(self):
        findings = [{'title': 'Unknown', 'severity': 'LOW', 'cwe': 'CWE-99999'}]
        result = self.mapper.enrich_findings(findings)
        assert 'mitre_tactic' not in result[0]

    def test_enrich_empty_findings(self):
        result = self.mapper.enrich_findings([])
        assert result == []

    def test_generate_mitre_report(self):
        findings = [
            {'title': 'SQLi', 'severity': 'CRITICAL', 'mitre_tactic': 'Initial Access', 'mitre_attack': 'T1190'},
            {'title': 'Brute', 'severity': 'HIGH', 'mitre_tactic': 'Credential Access', 'mitre_attack': 'T1110'},
        ]
        report = self.mapper.generate_mitre_report(findings)
        assert 'Initial Access' in report
        assert 'Credential Access' in report

    def test_default_mitre_mapping_loaded(self):
        assert 'CWE-89' in self.mapper.mitre_mapping
        assert 'CWE-79' in self.mapper.mitre_mapping

    def test_default_cve_patterns_loaded(self):
        assert 'sql_injection' in self.mapper.cve_patterns
        assert 'xss' in self.mapper.cve_patterns

    def test_epss_critical(self):
        findings = [{'title': 'X', 'severity': 'CRITICAL'}]
        self.mapper.enrich_findings(findings)
        assert findings[0]['epss_estimate'] == 0.85

    def test_epss_info(self):
        findings = [{'title': 'X', 'severity': 'INFO'}]
        self.mapper.enrich_findings(findings)
        assert findings[0]['epss_estimate'] == 0.01

    def test_jwt_cve_mapping(self):
        findings = [{'title': 'JWT Weak Key', 'severity': 'HIGH', 'cwe': 'CWE-327'}]
        self.mapper.enrich_findings(findings)
        assert 'related_cves' in findings[0]

    def test_auth_bypass_cve_mapping(self):
        findings = [{'title': 'MFA Bypass Found', 'severity': 'CRITICAL'}]
        self.mapper.enrich_findings(findings)
        assert 'related_cves' in findings[0]

    def test_cors_cve_mapping(self):
        findings = [{'title': 'Test', 'severity': 'MEDIUM', 'category': 'cors'}]
        self.mapper.enrich_findings(findings)
        assert 'related_cves' in findings[0]
