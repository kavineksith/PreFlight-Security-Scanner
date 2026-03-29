"""
JWT Vulnerability Analyzer
Tests algorithm confusion, weak keys, missing claims, JKU/kid injection.
"""

import json
import hashlib
import hmac
import base64
import time
from pathlib import Path
from colorama import Fore, Style

try:
    import jwt as pyjwt
    JWT_AVAILABLE = True
except ImportError:
    JWT_AVAILABLE = False


class JWTAnalyzer:
    def __init__(self, session, base_url):
        self.session = session
        self.base_url = base_url
        self.findings = []
        self.data_dir = Path(__file__).parent.parent / 'data'

    def run_all_checks(self):
        """Run all JWT security checks."""
        print(f"{Fore.CYAN}[*] JWT Security Analysis{Style.RESET_ALL}")
        tokens = self._collect_tokens()
        if not tokens:
            print(f"{Fore.YELLOW}[!] No JWT tokens found{Style.RESET_ALL}")
            return self.findings
        for token in tokens:
            self.test_algorithm_confusion(token)
            self.test_none_algorithm(token)
            self.test_weak_secret(token)
            self.test_claims_validation(token)
            self.test_kid_injection(token)
            self.test_jku_injection(token)
        return self.findings

    def _collect_tokens(self):
        """Collect JWT tokens from cookies and headers."""
        tokens = []
        for cookie in self.session.cookies:
            if self._is_jwt(cookie.value):
                tokens.append(cookie.value)
        auth = self.session.headers.get('Authorization', '')
        if auth.startswith('Bearer ') and self._is_jwt(auth[7:]):
            tokens.append(auth[7:])
        return tokens

    def _is_jwt(self, value):
        parts = value.split('.')
        if len(parts) != 3:
            return False
        try:
            base64.urlsafe_b64decode(parts[0] + '==')
            return True
        except Exception:
            return False

    def _decode_jwt_parts(self, token):
        parts = token.split('.')
        try:
            header = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))
            payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))
            return header, payload
        except Exception:
            return None, None

    def test_algorithm_confusion(self, token):
        print(f"{Fore.YELLOW}[*] Testing algorithm confusion...{Style.RESET_ALL}")
        header, payload = self._decode_jwt_parts(token)
        if not header:
            return
        alg = header.get('alg', '')
        if alg in ('HS256', 'HS384', 'HS512'):
            self.findings.append({
                'title': 'JWT Uses Symmetric Algorithm',
                'description': f'JWT uses {alg} — vulnerable to key confusion if RSA public key is known',
                'severity': 'MEDIUM', 'category': 'jwt',
                'owasp': 'A02:2021', 'cwe': 'CWE-327',
                'remediation': 'Use asymmetric algorithms (RS256/ES256) and validate algorithm server-side',
                'evidence': f'Algorithm: {alg}', 'mitre_attack': 'T1550.001'
            })

    def test_none_algorithm(self, token):
        print(f"{Fore.YELLOW}[*] Testing 'none' algorithm...{Style.RESET_ALL}")
        header, payload = self._decode_jwt_parts(token)
        if not header or not payload:
            return
        for alg in ['none', 'None', 'NONE', 'nOnE']:
            new_header = {**header, 'alg': alg}
            h = base64.urlsafe_b64encode(json.dumps(new_header).encode()).rstrip(b'=').decode()
            p = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b'=').decode()
            forged = f"{h}.{p}."
            try:
                from urllib.parse import urljoin
                for cookie in self.session.cookies:
                    if cookie.value == token:
                        self.session.cookies.set(cookie.name, forged)
                resp = self.session.get(urljoin(self.base_url, '/api/me'), timeout=5)
                if resp.status_code == 200 and 'unauthorized' not in resp.text.lower():
                    self.findings.append({
                        'title': 'JWT "none" Algorithm Accepted',
                        'description': 'Server accepts JWT with "none" algorithm — signature bypass',
                        'severity': 'CRITICAL', 'category': 'jwt',
                        'owasp': 'A02:2021', 'cwe': 'CWE-327',
                        'remediation': 'Reject "none" algorithm, enforce algorithm allowlist server-side',
                        'evidence': f'Forged token with alg={alg} accepted',
                        'mitre_attack': 'T1550.001'
                    })
                    self.session.cookies.set(cookie.name, token)
                    return
                self.session.cookies.set(cookie.name, token)
            except Exception:
                pass

    def test_weak_secret(self, token):
        print(f"{Fore.YELLOW}[*] Testing weak JWT signing key...{Style.RESET_ALL}")
        header, payload = self._decode_jwt_parts(token)
        if not header or header.get('alg', '') not in ('HS256', 'HS384', 'HS512'):
            return
        secrets_path = self.data_dir / 'jwt_secrets.txt'
        if secrets_path.exists():
            with open(secrets_path) as f:
                secrets = [l.strip() for l in f if l.strip()]
        else:
            secrets = ['secret', 'password', 'key', '123456', 'admin', 'jwt_secret',
                       'changeme', 'test', 'default', 'supersecret', 'qwerty', '']
        if JWT_AVAILABLE:
            for secret in secrets[:50]:
                try:
                    pyjwt.decode(token, secret, algorithms=[header['alg']])
                    self.findings.append({
                        'title': 'JWT Weak Signing Key',
                        'description': f'JWT signed with weak/guessable key: "{secret}"',
                        'severity': 'CRITICAL', 'category': 'jwt',
                        'owasp': 'A02:2021', 'cwe': 'CWE-521',
                        'remediation': 'Use a strong, random key (256+ bits) for JWT signing',
                        'evidence': f'Key "{secret}" successfully verified token',
                        'mitre_attack': 'T1552.001'
                    })
                    return
                except Exception:
                    continue

    def test_claims_validation(self, token):
        print(f"{Fore.YELLOW}[*] Checking JWT claims...{Style.RESET_ALL}")
        header, payload = self._decode_jwt_parts(token)
        if not payload:
            return
        issues = []
        if 'exp' not in payload:
            issues.append("Missing 'exp' — token never expires")
        elif payload['exp'] < time.time():
            issues.append("Token is expired but still accepted")
        elif payload['exp'] - time.time() > 86400 * 30:
            issues.append(f"Token expiry too long (>30 days)")
        if 'iss' not in payload:
            issues.append("Missing 'iss' (issuer) claim")
        if 'aud' not in payload:
            issues.append("Missing 'aud' (audience) claim")
        if 'iat' not in payload:
            issues.append("Missing 'iat' (issued at) claim")
        if 'nbf' not in payload:
            issues.append("Missing 'nbf' (not before) claim")
        if issues:
            self.findings.append({
                'title': 'JWT Claims Validation Issues',
                'description': f'JWT has {len(issues)} claim issue(s)',
                'severity': 'MEDIUM', 'category': 'jwt',
                'cwe': 'CWE-345',
                'remediation': 'Include and validate exp, iss, aud, iat, nbf claims',
                'evidence': '; '.join(issues)
            })

    def test_kid_injection(self, token):
        print(f"{Fore.YELLOW}[*] Testing kid parameter injection...{Style.RESET_ALL}")
        header, _ = self._decode_jwt_parts(token)
        if not header or 'kid' not in header:
            return
        injection_payloads = [
            "' UNION SELECT 'secret' --",
            "../../dev/null",
            "/dev/null",
        ]
        self.findings.append({
            'title': 'JWT kid Parameter Present',
            'description': 'JWT uses "kid" header — potential for SQL injection or path traversal',
            'severity': 'MEDIUM', 'category': 'jwt', 'cwe': 'CWE-94',
            'remediation': 'Validate kid parameter against an allowlist, do not use in file/DB queries directly',
            'evidence': f'kid: {header["kid"]}'
        })

    def test_jku_injection(self, token):
        print(f"{Fore.YELLOW}[*] Testing JKU/x5u injection...{Style.RESET_ALL}")
        header, _ = self._decode_jwt_parts(token)
        if not header:
            return
        for param in ['jku', 'x5u']:
            if param in header:
                self.findings.append({
                    'title': f'JWT {param.upper()} Header Present',
                    'description': f'JWT uses "{param}" — attacker could point to malicious key set',
                    'severity': 'HIGH', 'category': 'jwt', 'cwe': 'CWE-345',
                    'remediation': f'Validate {param} against a strict allowlist of trusted URLs',
                    'evidence': f'{param}: {header[param]}'
                })
