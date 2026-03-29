"""Unit tests for CVSSCalculator."""

import pytest
from modules.cvss_scorer import CVSSCalculator


class TestCVSSCalculator:
    def setup_method(self):
        self.calc = CVSSCalculator()

    # --- calculate_auth_score ---

    def test_auth_score_critical(self):
        result = self.calc.calculate_auth_score({'severity': 'CRITICAL'})
        assert result['score'] == 9.8
        assert result['severity'] == 'CRITICAL'
        assert 'CVSS:3.1' in result['vector']

    def test_auth_score_high(self):
        result = self.calc.calculate_auth_score({'severity': 'HIGH'})
        assert result['score'] == 8.1

    def test_auth_score_medium(self):
        result = self.calc.calculate_auth_score({'severity': 'MEDIUM'})
        assert result['score'] == 6.5

    def test_auth_score_low(self):
        result = self.calc.calculate_auth_score({'severity': 'LOW'})
        assert result['score'] == 4.2

    def test_auth_score_default(self):
        result = self.calc.calculate_auth_score({})
        assert result['score'] == 6.5  # Default is MEDIUM

    # --- calculate_owasp_score ---

    def test_owasp_sql_injection(self):
        result = self.calc.calculate_owasp_score({'title': 'SQL Injection Detected', 'severity': 'CRITICAL'})
        assert result['score'] == 9.8

    def test_owasp_command_injection(self):
        result = self.calc.calculate_owasp_score({'title': 'Command Injection', 'severity': 'CRITICAL'})
        assert result['score'] == 9.8

    def test_owasp_xss(self):
        result = self.calc.calculate_owasp_score({'title': 'XSS Vulnerability', 'severity': 'HIGH'})
        assert result['score'] == 6.1

    def test_owasp_path_traversal(self):
        result = self.calc.calculate_owasp_score({'title': 'Path Traversal', 'severity': 'HIGH'})
        assert result['score'] == 7.5

    def test_owasp_ssrf(self):
        result = self.calc.calculate_owasp_score({'title': 'SSRF Vulnerability', 'severity': 'HIGH'})
        assert result['score'] == 7.5

    def test_owasp_default_critical(self):
        result = self.calc.calculate_owasp_score({'title': 'Unknown', 'severity': 'CRITICAL'})
        assert result['score'] == 9.8

    def test_owasp_default_medium(self):
        result = self.calc.calculate_owasp_score({'title': 'Something', 'severity': 'MEDIUM'})
        assert result['score'] == 5.5

    # --- calculate_api_score ---

    def test_api_bola(self):
        result = self.calc.calculate_api_score({'title': 'Broken Object Level Auth (BOLA)'})
        assert result['score'] == 8.1

    def test_api_function_level(self):
        result = self.calc.calculate_api_score({'title': 'Broken Function Level Auth'})
        assert result['score'] == 9.0

    def test_api_rate_limiting(self):
        result = self.calc.calculate_api_score({'title': 'Lack of Rate Limiting'})
        assert result['score'] == 5.3

    def test_api_default(self):
        result = self.calc.calculate_api_score({'title': 'Unknown API Issue'})
        assert result['score'] == 6.5

    # --- calculate_config_score ---

    def test_config_directory_listing(self):
        result = self.calc.calculate_config_score({'title': 'Directory Listing Enabled'})
        assert result['score'] == 5.3

    def test_config_debug(self):
        result = self.calc.calculate_config_score({'title': 'Debug Information Exposed'})
        assert result['score'] == 4.3

    def test_config_default(self):
        result = self.calc.calculate_config_score({'title': 'Miscellaneous Config'})
        assert result['score'] == 3.7

    # --- calculate_generic_score ---

    def test_generic_critical(self):
        result = self.calc.calculate_generic_score({'severity': 'CRITICAL'})
        assert result['score'] == 9.8

    def test_generic_high(self):
        result = self.calc.calculate_generic_score({'severity': 'HIGH'})
        assert result['score'] == 7.5

    def test_generic_medium(self):
        result = self.calc.calculate_generic_score({'severity': 'MEDIUM'})
        assert result['score'] == 5.3

    def test_generic_low(self):
        result = self.calc.calculate_generic_score({'severity': 'LOW'})
        assert result['score'] == 3.1

    def test_generic_info(self):
        result = self.calc.calculate_generic_score({'severity': 'INFO'})
        assert result['score'] == 0.0

    def test_generic_default(self):
        result = self.calc.calculate_generic_score({})
        assert result['score'] == 5.3  # Default MEDIUM

    def test_all_scores_have_vector(self):
        methods = [
            (self.calc.calculate_auth_score, {'severity': 'HIGH'}),
            (self.calc.calculate_owasp_score, {'title': 'Test', 'severity': 'HIGH'}),
            (self.calc.calculate_api_score, {'title': 'Test'}),
            (self.calc.calculate_config_score, {'title': 'Test'}),
            (self.calc.calculate_generic_score, {'severity': 'HIGH'}),
        ]
        for method, arg in methods:
            result = method(arg)
            assert 'score' in result
            assert 'vector' in result
            assert 'severity' in result
            assert result['vector'].startswith('CVSS:3.1')
