"""
Server Fingerprinting & Infrastructure Analysis
Web server ID, tech stack, WAF detection, port scan, SSL ciphers, cert validation.
"""

import ssl
import socket
import re
from urllib.parse import urlparse, urljoin
from colorama import Fore, Style


class ServerFingerprinter:
    def __init__(self, session, base_url):
        self.session = session
        self.base_url = base_url
        self.hostname = urlparse(base_url).hostname or ''
        self.findings = []

    def run_all_checks(self):
        print(f"{Fore.CYAN}[*] Server Fingerprinting & Infrastructure Analysis{Style.RESET_ALL}")
        self.identify_web_server()
        self.detect_tech_stack()
        self.detect_waf()
        self.scan_common_ports()
        self.analyze_ssl_tls()
        self.check_certificate()
        return self.findings

    def identify_web_server(self):
        print(f"{Fore.YELLOW}[*] Identifying web server...{Style.RESET_ALL}")
        try:
            r = self.session.get(self.base_url, timeout=10)
            server = r.headers.get('Server', '')
            if server:
                self.findings.append({
                    'title': f'Web Server Identified: {server}',
                    'description': f'Server header reveals: {server}',
                    'severity': 'LOW', 'category': 'fingerprint',
                    'owasp': 'A05:2021', 'cwe': 'CWE-200',
                    'remediation': 'Remove or obfuscate the Server header',
                    'evidence': f'Server: {server}'
                })
                # Check for known vulnerable versions
                vuln_patterns = [
                    (r'Apache/2\.[0-3]\.', 'OLD', 'Apache < 2.4 — update immediately'),
                    (r'nginx/1\.[0-9]\.', 'OLD', 'Nginx < 1.10 — update immediately'),
                    (r'IIS/[5-7]\.', 'OLD', 'IIS < 8 — update immediately'),
                ]
                for pattern, _, msg in vuln_patterns:
                    if re.search(pattern, server):
                        self.findings.append({
                            'title': 'Outdated Web Server Version',
                            'description': msg,
                            'severity': 'HIGH', 'category': 'fingerprint',
                            'cwe': 'CWE-1104',
                            'remediation': 'Update web server to latest stable version',
                            'evidence': f'Server: {server}'
                        })
                        break
        except Exception:
            pass

    def detect_tech_stack(self):
        print(f"{Fore.YELLOW}[*] Detecting technology stack...{Style.RESET_ALL}")
        try:
            r = self.session.get(self.base_url, timeout=10)
            detected = []
            # Headers
            tech_headers = {
                'X-Powered-By': None, 'X-AspNet-Version': 'ASP.NET',
                'X-AspNetMvc-Version': 'ASP.NET MVC', 'X-Generator': None,
                'X-Drupal-Cache': 'Drupal', 'X-Shopify-Stage': 'Shopify',
                'X-Pingback': 'WordPress',
            }
            for h, tech in tech_headers.items():
                val = r.headers.get(h)
                if val:
                    detected.append(tech or val)
            # Body patterns
            patterns = [
                (r'wp-content|wordpress', 'WordPress'),
                (r'drupal', 'Drupal'), (r'joomla', 'Joomla'),
                (r'react', 'React'), (r'angular', 'Angular'),
                (r'vue\.js|vuejs', 'Vue.js'), (r'next\.js|nextjs', 'Next.js'),
                (r'django', 'Django'), (r'laravel|csrf-token', 'Laravel'),
                (r'express|connect\.sid', 'Express.js'),
                (r'flask|werkzeug', 'Flask'), (r'rails|csrf-token', 'Ruby on Rails'),
                (r'spring|jsessionid', 'Spring/Java'),
            ]
            for pattern, tech in patterns:
                if re.search(pattern, r.text, re.IGNORECASE):
                    detected.append(tech)
            if detected:
                self.findings.append({
                    'title': 'Technology Stack Detected',
                    'description': f'Technologies identified: {", ".join(set(detected))}',
                    'severity': 'INFO', 'category': 'fingerprint',
                    'cwe': 'CWE-200',
                    'remediation': 'Remove technology identifiers from production responses',
                    'evidence': f'Detected: {", ".join(set(detected))}'
                })
        except Exception:
            pass

    def detect_waf(self):
        print(f"{Fore.YELLOW}[*] Detecting WAF...{Style.RESET_ALL}")
        waf_signatures = {
            'cloudflare': ['cf-ray', 'cf-cache-status', '__cfduid'],
            'aws_waf': ['x-amzn-requestid', 'x-amz-cf-id'],
            'akamai': ['x-akamai-transformed', 'akamai-grn'],
            'sucuri': ['x-sucuri-id', 'x-sucuri-cache'],
            'imperva': ['x-iinfo', 'x-cdn'],
            'f5_big_ip': ['x-cnection', 'bigipserver'],
            'modsecurity': ['mod_security', 'nyob'],
        }
        try:
            # Normal request
            r1 = self.session.get(self.base_url, timeout=10)
            # Malicious request
            r2 = self.session.get(f"{self.base_url}/?q=<script>alert(1)</script>", timeout=10)
            headers_str = str(r1.headers).lower() + str(r2.headers).lower()
            for waf, sigs in waf_signatures.items():
                if any(s in headers_str for s in sigs):
                    self.findings.append({
                        'title': f'WAF Detected: {waf.replace("_", " ").title()}',
                        'description': f'Web Application Firewall detected: {waf}',
                        'severity': 'INFO', 'category': 'fingerprint',
                        'remediation': 'WAF is a good defense — ensure rules are up to date',
                        'evidence': f'WAF signature matched: {waf}'
                    })
                    return
            if r2.status_code in (403, 406, 429, 503):
                self.findings.append({
                    'title': 'WAF Detected (Generic)',
                    'description': 'Request blocked — likely WAF in place',
                    'severity': 'INFO', 'category': 'fingerprint',
                    'evidence': f'Malicious request blocked with status {r2.status_code}'
                })
        except Exception:
            pass

    def scan_common_ports(self):
        print(f"{Fore.YELLOW}[*] Scanning common ports...{Style.RESET_ALL}")
        ports = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB',
            3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC',
            6379: 'Redis', 8080: 'HTTP-ALT', 8443: 'HTTPS-ALT',
            9200: 'Elasticsearch', 27017: 'MongoDB',
        }
        open_ports = []
        for port, service in ports.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((self.hostname, port))
                if result == 0:
                    open_ports.append({'port': port, 'service': service})
                sock.close()
            except Exception:
                pass
        dangerous = [p for p in open_ports if p['port'] in (21, 23, 445, 3389, 5900, 6379, 27017, 9200)]
        if dangerous:
            self.findings.append({
                'title': 'Dangerous Ports Open',
                'description': 'Sensitive services exposed: ' + ', '.join('{}/{}'.format(p['port'], p['service']) for p in dangerous),
                'severity': 'HIGH', 'category': 'fingerprint',
                'owasp': 'A05:2021', 'cwe': 'CWE-200',
                'remediation': 'Close unnecessary ports, restrict access via firewall',
                'evidence': 'Open: ' + ', '.join('{}/{}'.format(p['port'], p['service']) for p in dangerous)
            })
        if open_ports:
            self.findings.append({
                'title': 'Open Ports Discovered',
                'description': f'{len(open_ports)} open ports found on {self.hostname}',
                'severity': 'INFO', 'category': 'fingerprint',
                'evidence': 'Ports: ' + ', '.join('{}/{}'.format(p['port'], p['service']) for p in open_ports)
            })

    def analyze_ssl_tls(self):
        print(f"{Fore.YELLOW}[*] Analyzing SSL/TLS configuration...{Style.RESET_ALL}")
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((self.hostname, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                    version = ssock.version()
                    cipher = ssock.cipher()
                    if version and 'TLSv1.0' in version or 'TLSv1.1' in version or 'SSLv' in str(version):
                        self.findings.append({
                            'title': f'Deprecated TLS Version: {version}',
                            'description': f'Server supports {version} — deprecated and insecure',
                            'severity': 'HIGH', 'category': 'fingerprint',
                            'cwe': 'CWE-326',
                            'remediation': 'Disable TLS 1.0/1.1, use TLS 1.2+ only',
                            'evidence': f'TLS version: {version}'
                        })
                    if cipher:
                        cipher_name = cipher[0]
                        weak = ['RC4', 'DES', '3DES', 'NULL', 'EXPORT', 'MD5']
                        if any(w in cipher_name for w in weak):
                            self.findings.append({
                                'title': f'Weak Cipher Suite: {cipher_name}',
                                'description': 'Weak/deprecated cipher suite in use',
                                'severity': 'HIGH', 'category': 'fingerprint',
                                'cwe': 'CWE-327',
                                'remediation': 'Use only strong cipher suites (AES-GCM, ChaCha20)',
                                'evidence': f'Cipher: {cipher_name}'
                            })
        except Exception:
            pass

    def check_certificate(self):
        print(f"{Fore.YELLOW}[*] Checking SSL certificate...{Style.RESET_ALL}")
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((self.hostname, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                    cert = ssock.getpeercert()
                    if cert:
                        import datetime
                        expiry = ssl.cert_time_to_seconds(cert['notAfter'])
                        now = datetime.datetime.now().timestamp()
                        days_left = (expiry - now) / 86400
                        if days_left < 0:
                            self.findings.append({
                                'title': 'SSL Certificate Expired',
                                'description': f'Certificate expired {abs(int(days_left))} days ago',
                                'severity': 'CRITICAL', 'category': 'fingerprint',
                                'cwe': 'CWE-295',
                                'remediation': 'Renew SSL certificate immediately',
                                'evidence': f'Expired: {cert["notAfter"]}'
                            })
                        elif days_left < 30:
                            self.findings.append({
                                'title': 'SSL Certificate Expiring Soon',
                                'description': f'Certificate expires in {int(days_left)} days',
                                'severity': 'MEDIUM', 'category': 'fingerprint',
                                'remediation': 'Renew SSL certificate before expiry',
                                'evidence': f'Expires: {cert["notAfter"]}'
                            })
        except ssl.SSLCertVerificationError as e:
            self.findings.append({
                'title': 'SSL Certificate Validation Failed',
                'description': f'Certificate validation error: {str(e)[:100]}',
                'severity': 'HIGH', 'category': 'fingerprint',
                'cwe': 'CWE-295',
                'remediation': 'Fix certificate chain — use a trusted CA',
                'evidence': str(e)[:200]
            })
        except Exception:
            pass
