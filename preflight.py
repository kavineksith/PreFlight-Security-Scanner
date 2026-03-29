#!/usr/bin/env python3
"""
PreFlight Security Scanner v2.0 — Enterprise Edition
Advanced Pre-Production Security Validation Tool
For authorized testing only.
"""

import argparse
import sys
import json
import time
from datetime import datetime
from pathlib import Path
from colorama import init, Fore, Style
import requests
from urllib.parse import urlparse

# Core modules
from modules.auth_tester import AuthTester
from modules.owasp_scanner import OWASPScanner
from modules.api_tester import APITester
from modules.cvss_scorer import CVSSCalculator
from modules.reporter import ReportGenerator
from modules.utils import Utils

# v2.0 Advanced modules
from modules.dns_recon import DNSRecon
from modules.header_analyzer import HeaderAnalyzer
from modules.cors_tester import CORSTester
from modules.csrf_tester import CSRFTester
from modules.ssrf_tester import SSRFTester
from modules.injection_tester import InjectionTester
from modules.session_tester import SessionTester
from modules.jwt_analyzer import JWTAnalyzer
from modules.rate_limiter_tester import RateLimiterTester
from modules.auth_bypass_tester import AuthBypassTester
from modules.param_pollution_tester import ParamPollutionTester
from modules.cve_mapper import CVEMapper
from modules.server_fingerprinter import ServerFingerprinter
from modules.http_method_tester import HTTPMethodTester
from modules.crypto_analyzer import CryptoAnalyzer
from modules.privilege_escalation_tester import PrivilegeEscalationTester

init(autoreset=True)

VERSION = "2.0.0"


class PreFlightScanner:
    def __init__(self, target_url, login_url=None, username=None, password=None,
                 api_base=None, output_dir="./scan_reports", scan_mode="full",
                 severity_threshold="LOW", threads=1):
        self.target_url = target_url.rstrip('/')
        self.login_url = login_url
        self.username = username
        self.password = password
        self.api_base = api_base or f"{target_url}/api"
        self.output_dir = Path(output_dir)
        self.scan_mode = scan_mode
        self.severity_threshold = severity_threshold
        self.threads = threads
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({'User-Agent': f'PreFlight-Scanner/{VERSION}'})
        self.findings = []
        self.start_time = datetime.now()
        self.authenticated = False

        # Create output directory
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Initialize core modules
        self.auth_tester = AuthTester(self.session, self.target_url)
        self.owasp_scanner = OWASPScanner(self.session, self.target_url)
        self.api_tester = APITester(self.session, self.api_base)
        self.cvss_calculator = CVSSCalculator()
        self.reporter = ReportGenerator(self.output_dir)
        self.utils = Utils()

        # Initialize v2.0 advanced modules
        self.dns_recon = DNSRecon(self.target_url)
        self.header_analyzer = HeaderAnalyzer(self.session, self.target_url)
        self.cors_tester = CORSTester(self.session, self.target_url)
        self.csrf_tester = CSRFTester(self.session, self.target_url)
        self.ssrf_tester = SSRFTester(self.session, self.target_url)
        self.injection_tester = InjectionTester(self.session, self.target_url)
        self.session_tester = SessionTester(self.session, self.target_url)
        self.jwt_analyzer = JWTAnalyzer(self.session, self.target_url)
        self.rate_limiter_tester = RateLimiterTester(self.session, self.target_url)
        self.auth_bypass_tester = AuthBypassTester(self.session, self.target_url)
        self.param_pollution_tester = ParamPollutionTester(self.session, self.target_url)
        self.cve_mapper = CVEMapper()
        self.server_fingerprinter = ServerFingerprinter(self.session, self.target_url)
        self.http_method_tester = HTTPMethodTester(self.session, self.target_url)
        self.crypto_analyzer = CryptoAnalyzer(self.session, self.target_url)
        self.privilege_escalation_tester = PrivilegeEscalationTester(self.session, self.target_url)

    def banner(self):
        print(f"""
{Fore.CYAN}{'='*65}
{Fore.YELLOW}🔒 PreFlight Security Scanner v{VERSION} — Enterprise Edition
{Fore.WHITE}Advanced Pre-Production Security Validation Tool
{Fore.GREEN}✓ 22 Security Modules | MITRE ATT&CK | CVE/NVD Mapping
{Fore.RED}⚠️  FOR AUTHORIZED TESTING ONLY
{Fore.CYAN}{'='*65}
{Style.RESET_ALL}
        """)

    def authenticate(self):
        """Establish authenticated session if credentials provided."""
        if not self.login_url or not self.username or not self.password:
            print(f"{Fore.YELLOW}[!] No credentials — running unauthenticated scans{Style.RESET_ALL}")
            return False

        print(f"{Fore.CYAN}[*] Authenticating to {self.login_url}{Style.RESET_ALL}")
        try:
            login_data = {'username': self.username, 'password': self.password, 'email': self.username}
            response = self.session.post(self.login_url, data=login_data, timeout=10)
            if response.status_code == 200 and self.session.cookies:
                print(f"{Fore.GREEN}[✓] Authentication successful{Style.RESET_ALL}")
                self.authenticated = True
                return True

            login_json = {'username': self.username, 'password': self.password}
            response = self.session.post(self.login_url, json=login_json, timeout=10)
            if response.status_code == 200 and 'token' in response.text.lower():
                print(f"{Fore.GREEN}[✓] JWT/Token authentication successful{Style.RESET_ALL}")
                self.authenticated = True
                return True
        except Exception as e:
            print(f"{Fore.RED}[✗] Authentication error: {e}{Style.RESET_ALL}")

        print(f"{Fore.YELLOW}[!] Continuing without authentication{Style.RESET_ALL}")
        return False

    def _add_findings(self, findings, score_method='generic'):
        """Add findings with CVSS scoring."""
        for finding in findings:
            if 'cvss' not in finding:
                finding['cvss'] = self.cvss_calculator.calculate_generic_score(finding)
            self.findings.append(finding)

    # === SCAN PHASES ===

    def run_recon_phase(self):
        """Phase 1: Reconnaissance."""
        print(f"\n{Fore.CYAN}{'='*50}")
        print(f"[*] PHASE 1: RECONNAISSANCE & FINGERPRINTING")
        print(f"{'='*50}{Style.RESET_ALL}")
        self._add_findings(self.dns_recon.run_all_checks())
        self._add_findings(self.server_fingerprinter.run_all_checks())

    def run_header_phase(self):
        """Phase 2: Header & Transport Security."""
        print(f"\n{Fore.CYAN}{'='*50}")
        print(f"[*] PHASE 2: HEADER & TRANSPORT SECURITY")
        print(f"{'='*50}{Style.RESET_ALL}")
        self._add_findings(self.header_analyzer.run_all_checks())
        self._add_findings(self.cors_tester.run_all_checks())
        self._add_findings(self.http_method_tester.run_all_checks())

    def run_auth_phase(self):
        """Phase 3: Authentication & Authorization."""
        print(f"\n{Fore.CYAN}{'='*50}")
        print(f"[*] PHASE 3: AUTHENTICATION & AUTHORIZATION")
        print(f"{'='*50}{Style.RESET_ALL}")
        findings = self.auth_tester.run_all_tests(self.authenticated, self.username, self.password)
        for f in findings:
            f['cvss'] = self.cvss_calculator.calculate_auth_score(f)
            self.findings.append(f)
        self._add_findings(self.auth_bypass_tester.run_all_checks())
        self._add_findings(self.privilege_escalation_tester.run_all_checks(self.authenticated))

    def run_session_phase(self):
        """Phase 4: Session, Cookie & JWT Security."""
        print(f"\n{Fore.CYAN}{'='*50}")
        print(f"[*] PHASE 4: SESSION, COOKIE & JWT SECURITY")
        print(f"{'='*50}{Style.RESET_ALL}")
        self._add_findings(self.session_tester.run_all_checks(
            self.authenticated, self.username, self.password))
        self._add_findings(self.jwt_analyzer.run_all_checks())
        self._add_findings(self.csrf_tester.run_all_checks())
        self._add_findings(self.crypto_analyzer.run_all_checks())

    def run_injection_phase(self):
        """Phase 5: Injection Testing."""
        print(f"\n{Fore.CYAN}{'='*50}")
        print(f"[*] PHASE 5: INJECTION TESTING (SQL/XSS/CMD/SSTI)")
        print(f"{'='*50}{Style.RESET_ALL}")
        self._add_findings(self.injection_tester.run_all_checks())
        findings = self.owasp_scanner.run_all_checks(self.authenticated)
        for f in findings:
            f['cvss'] = self.cvss_calculator.calculate_owasp_score(f)
            self.findings.append(f)

    def run_api_phase(self):
        """Phase 6: API Security."""
        print(f"\n{Fore.CYAN}{'='*50}")
        print(f"[*] PHASE 6: API SECURITY (OWASP API TOP 10)")
        print(f"{'='*50}{Style.RESET_ALL}")
        findings = self.api_tester.run_all_tests(self.authenticated)
        for f in findings:
            f['cvss'] = self.cvss_calculator.calculate_api_score(f)
            self.findings.append(f)
        self._add_findings(self.ssrf_tester.run_all_checks())
        self._add_findings(self.param_pollution_tester.run_all_checks())
        self._add_findings(self.rate_limiter_tester.run_all_checks())

    def run_pre_prod_phase(self):
        """Phase 7: Pre-Production Hardening."""
        print(f"\n{Fore.CYAN}{'='*50}")
        print(f"[*] PHASE 7: PRE-PRODUCTION HARDENING")
        print(f"{'='*50}{Style.RESET_ALL}")
        findings = []
        findings.extend(self.utils.check_security_headers(self.target_url))
        findings.extend(self.utils.check_tls_security(self.target_url))
        findings.extend(self.utils.check_sensitive_files(self.target_url))
        findings.extend(self.utils.check_error_handling(self.target_url, self.session))
        for f in findings:
            f['cvss'] = self.cvss_calculator.calculate_config_score(f)
            self.findings.append(f)

    def run_enrichment_phase(self):
        """Phase 8: CVE/MITRE Enrichment."""
        print(f"\n{Fore.CYAN}{'='*50}")
        print(f"[*] PHASE 8: CVE/MITRE ATT&CK ENRICHMENT")
        print(f"{'='*50}{Style.RESET_ALL}")
        self.findings = self.cve_mapper.enrich_findings(self.findings)

    def generate_report(self):
        """Generate all report formats."""
        print(f"\n{Fore.CYAN}[*] Generating reports{Style.RESET_ALL}")

        # Filter by severity threshold
        sev_order = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'INFO': 0}
        threshold = sev_order.get(self.severity_threshold, 0)
        filtered = [f for f in self.findings if sev_order.get(f.get('severity', 'INFO'), 0) >= threshold]

        scan_duration = (datetime.now() - self.start_time).total_seconds()
        report_data = {
            'scanner_version': VERSION,
            'target': self.target_url,
            'scan_time': self.start_time.isoformat(),
            'duration_seconds': scan_duration,
            'scan_mode': self.scan_mode,
            'authenticated': self.authenticated,
            'total_findings': len(filtered),
            'findings': filtered,
            'mitre_summary': self.cve_mapper.generate_mitre_report(filtered)
        }
        self.reporter.generate_html(report_data)
        self.reporter.generate_json(report_data)
        self.reporter.generate_csv(filtered)
        self.reporter.generate_console_summary(report_data)
        return self.output_dir

    def run(self):
        """Main execution flow."""
        self.banner()

        if not self.utils.validate_url(self.target_url):
            print(f"{Fore.RED}[✗] Invalid URL: {self.target_url}{Style.RESET_ALL}")
            return False

        print(f"{Fore.WHITE}[+] Target:    {self.target_url}")
        print(f"[+] Mode:      {self.scan_mode}")
        print(f"[+] Output:    {self.output_dir}")

        self.authenticate()

        if self.scan_mode == 'recon':
            self.run_recon_phase()
        elif self.scan_mode == 'quick':
            self.run_header_phase()
            self.run_auth_phase()
            self.run_injection_phase()
        else:  # full
            self.run_recon_phase()
            self.run_header_phase()
            self.run_auth_phase()
            self.run_session_phase()
            self.run_injection_phase()
            self.run_api_phase()
            self.run_pre_prod_phase()

        self.run_enrichment_phase()
        report_dir = self.generate_report()

        print(f"\n{Fore.GREEN}{'='*65}")
        print(f"✓ Scan completed — {len(self.findings)} findings")
        print(f"✓ Reports saved to: {report_dir}")
        print(f"{'='*65}{Style.RESET_ALL}")

        critical_count = sum(1 for f in self.findings
                            if f.get('severity') == 'CRITICAL' or f.get('cvss', {}).get('score', 0) >= 9.0)
        if critical_count > 0:
            print(f"{Fore.RED}[!] {critical_count} CRITICAL findings — DO NOT RELEASE TO PRODUCTION{Style.RESET_ALL}")
            return False
        return True


def main():
    parser = argparse.ArgumentParser(
        description='PreFlight Security Scanner v2.0 — Enterprise Edition',
        epilog='Example: python preflight.py https://staging.app.com --mode full --login-url /login'
    )
    parser.add_argument('target', help='Target URL')
    parser.add_argument('--login-url', help='Login endpoint')
    parser.add_argument('--username', help='Username')
    parser.add_argument('--password', help='Password')
    parser.add_argument('--api-base', help='API base URL')
    parser.add_argument('--output-dir', default='./scan_reports', help='Report output dir')
    parser.add_argument('--mode', choices=['full', 'quick', 'recon'], default='full',
                        help='Scan mode: full, quick, or recon')
    parser.add_argument('--severity-threshold', choices=['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
                        default='LOW', help='Minimum severity to report')
    parser.add_argument('--threads', type=int, default=1, help='Number of threads')

    args = parser.parse_args()

    scanner = PreFlightScanner(
        target_url=args.target,
        login_url=args.login_url,
        username=args.username,
        password=args.password,
        api_base=args.api_base,
        output_dir=args.output_dir,
        scan_mode=args.mode,
        severity_threshold=args.severity_threshold,
        threads=args.threads
    )

    success = scanner.run()
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()