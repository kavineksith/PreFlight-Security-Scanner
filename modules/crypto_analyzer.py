"""
Cryptography & Password Security Analyzer
Hash algorithm detection, salt analysis, weak crypto, token entropy, sensitive data exposure.
"""

import re
import math
import hashlib
from collections import Counter
from urllib.parse import urljoin
from colorama import Fore, Style


class CryptoAnalyzer:
    def __init__(self, session, base_url):
        self.session = session
        self.base_url = base_url
        self.findings = []

    def run_all_checks(self):
        print(f"{Fore.CYAN}[*] Cryptography & Password Security Analysis{Style.RESET_ALL}")
        self.detect_hash_algorithms()
        self.check_password_storage_indicators()
        self.analyze_token_entropy()
        self.check_sensitive_data_exposure()
        self.check_crypto_headers()
        return self.findings

    def detect_hash_algorithms(self):
        """Detect hash algorithms in API responses."""
        print(f"{Fore.YELLOW}[*] Detecting hash algorithms in responses...{Style.RESET_ALL}")
        endpoints = ['/api/users', '/api/me', '/api/profile', '/api/user/1']
        hash_patterns = {
            r'^[a-f0-9]{32}$': ('MD5', 'CRITICAL', 'MD5 is cryptographically broken'),
            r'^[a-f0-9]{40}$': ('SHA-1', 'HIGH', 'SHA-1 is deprecated for security use'),
            r'^[a-f0-9]{64}$': ('SHA-256', 'MEDIUM', 'SHA-256 without salt is weak for passwords'),
            r'^\$2[aby]?\$\d{2}\$': ('bcrypt', 'INFO', 'bcrypt is acceptable'),
            r'^\$argon2': ('Argon2', 'INFO', 'Argon2 is recommended'),
            r'^\$scrypt\$': ('scrypt', 'INFO', 'scrypt is acceptable'),
            r'^\$5\$': ('SHA-256 crypt', 'MEDIUM', 'Consider bcrypt or Argon2'),
            r'^\$6\$': ('SHA-512 crypt', 'LOW', 'Acceptable but consider Argon2'),
            r'^\$1\$': ('MD5 crypt', 'HIGH', 'MD5 crypt is deprecated'),
        }
        for ep in endpoints:
            try:
                r = self.session.get(urljoin(self.base_url, ep), timeout=5)
                if r.status_code != 200:
                    continue
                text = r.text
                for pattern, (algo, severity, msg) in hash_patterns.items():
                    matches = re.findall(pattern, text, re.MULTILINE)
                    if matches and severity in ('CRITICAL', 'HIGH', 'MEDIUM'):
                        # Verify it's actually exposed
                        if any(k in text.lower() for k in ['password', 'hash', 'digest', 'passwd']):
                            self.findings.append({
                                'title': f'Password Hash Exposed ({algo})',
                                'description': f'{algo} hash found in API response at {ep} — {msg}',
                                'severity': severity, 'category': 'crypto',
                                'owasp': 'A02:2021', 'cwe': 'CWE-916',
                                'remediation': 'Never expose password hashes. Use bcrypt/Argon2 with per-user salt.',
                                'evidence': f'Found {algo} pattern at {ep}',
                                'mitre_attack': 'T1110.002'
                            })
                            return
            except Exception:
                continue

    def check_password_storage_indicators(self):
        """Check for indicators of weak password storage."""
        print(f"{Fore.YELLOW}[*] Checking password storage indicators...{Style.RESET_ALL}")
        # Test password reset — if password is returned in plaintext
        endpoints = ['/api/forgot-password', '/api/password/reset', '/forgot-password']
        for ep in endpoints:
            try:
                r = self.session.post(urljoin(self.base_url, ep),
                                      json={'email': 'test@test.com'}, timeout=5)
                if r.status_code == 200 and 'password' in r.text.lower():
                    if re.search(r'"password"\s*:\s*"[^"]{3,}"', r.text):
                        self.findings.append({
                            'title': 'Plaintext Password in Response',
                            'description': f'Password returned in plaintext at {ep}',
                            'severity': 'CRITICAL', 'category': 'crypto',
                            'owasp': 'A02:2021', 'cwe': 'CWE-256',
                            'remediation': 'Never store or return passwords in plaintext. Hash with bcrypt/Argon2.',
                            'evidence': f'Password field found in {ep} response',
                            'mitre_attack': 'T1552.001'
                        })
                        return
            except Exception:
                continue

    def analyze_token_entropy(self):
        """Analyze randomness of security tokens."""
        print(f"{Fore.YELLOW}[*] Analyzing token entropy...{Style.RESET_ALL}")
        # Collect CSRF tokens, session IDs, etc
        tokens = {}
        for cookie in self.session.cookies:
            tokens[f'cookie:{cookie.name}'] = cookie.value

        # Try fetching a page for CSRF tokens
        try:
            r = self.session.get(self.base_url, timeout=5)
            csrf_pattern = r'name=["\'](?:csrf|_token|csrfmiddlewaretoken)["\'].*?value=["\']([^"\']+)["\']'
            csrf_matches = re.findall(csrf_pattern, r.text, re.IGNORECASE)
            for i, token in enumerate(csrf_matches):
                tokens[f'csrf_token_{i}'] = token
        except Exception:
            pass

        for name, value in tokens.items():
            if len(value) < 8:
                continue
            entropy = self._calc_entropy(value)
            bits = entropy * len(value)
            if bits < 64:
                self.findings.append({
                    'title': f'Low Entropy Token: {name}',
                    'description': f'Token has only {bits:.0f} bits of entropy (minimum 128)',
                    'severity': 'HIGH', 'category': 'crypto',
                    'cwe': 'CWE-330',
                    'remediation': 'Use CSPRNG to generate tokens with at least 128 bits of entropy',
                    'evidence': f'{name}: {len(value)} chars, {entropy:.2f} bits/char, {bits:.0f} total bits'
                })

    def _calc_entropy(self, data):
        if not data:
            return 0.0
        c = Counter(data)
        l = len(data)
        return -sum((n/l) * math.log2(n/l) for n in c.values())

    def check_sensitive_data_exposure(self):
        """Check for sensitive data in API responses."""
        print(f"{Fore.YELLOW}[*] Checking sensitive data exposure...{Style.RESET_ALL}")
        endpoints = ['/api/me', '/api/users', '/api/profile', '/api/config', '/api/settings']
        sensitive_patterns = {
            r'[A-Za-z0-9]{20,40}': 'Possible API key/token',
            r'(?:password|passwd|pwd)\s*[=:]\s*["\'][^"\']+["\']': 'Password in response',
            r'(?:secret|private_key|api_key)\s*[=:]\s*["\'][^"\']+["\']': 'Secret key in response',
            r'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b': 'AWS Access Key',
            r'\b(?:sk-|pk_)[a-zA-Z0-9]{20,}\b': 'API Key (Stripe-like)',
        }
        for ep in endpoints:
            try:
                r = self.session.get(urljoin(self.base_url, ep), timeout=5)
                if r.status_code != 200:
                    continue
                for pattern, desc in sensitive_patterns.items():
                    if re.search(pattern, r.text, re.IGNORECASE):
                        if 'password' in pattern.lower() or 'secret' in pattern.lower():
                            self.findings.append({
                                'title': f'Sensitive Data Exposure: {desc}',
                                'description': f'{desc} found at {ep}',
                                'severity': 'HIGH', 'category': 'crypto',
                                'owasp': 'A02:2021', 'cwe': 'CWE-200',
                                'remediation': 'Remove sensitive data from API responses, use data filtering',
                                'evidence': f'Pattern "{desc}" matched at {ep}'
                            })
                            return
            except Exception:
                continue

    def check_crypto_headers(self):
        """Check for cryptographic security in headers."""
        print(f"{Fore.YELLOW}[*] Checking cryptographic headers...{Style.RESET_ALL}")
        try:
            r = self.session.get(self.base_url, timeout=5)
            # Check if using weak ETags (inode-based)
            etag = r.headers.get('ETag', '')
            if etag and '-' in etag and len(etag.split('-')) >= 3:
                self.findings.append({
                    'title': 'Weak ETag (Inode-Based)',
                    'description': 'ETag contains inode number — leaks file system information',
                    'severity': 'LOW', 'category': 'crypto',
                    'cwe': 'CWE-200',
                    'remediation': 'Configure ETags without inode (FileETag MTime Size)',
                    'evidence': f'ETag: {etag}'
                })
        except Exception:
            pass
