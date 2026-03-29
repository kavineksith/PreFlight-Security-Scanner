"""
CVE/NVD & MITRE ATT&CK Mapper
Maps findings to CVEs, CWEs, MITRE ATT&CK techniques, and EPSS scores.
"""

import json
import re
from pathlib import Path
from colorama import Fore, Style

try:
    import requests as req
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


class CVEMapper:
    def __init__(self):
        self.data_dir = Path(__file__).parent.parent / 'data'
        self.mitre_mapping = self._load_mitre_mapping()
        self.cve_patterns = self._load_cve_patterns()

    def _load_mitre_mapping(self):
        path = self.data_dir / 'mitre_attack_mapping.json'
        if path.exists():
            with open(path) as f:
                return json.load(f)
        return self._default_mitre_mapping()

    def _load_cve_patterns(self):
        path = self.data_dir / 'cve_patterns.json'
        if path.exists():
            with open(path) as f:
                return json.load(f)
        return self._default_cve_patterns()

    def _default_mitre_mapping(self):
        return {
            'CWE-89': {'techniques': ['T1190'], 'tactic': 'Initial Access', 'name': 'SQL Injection'},
            'CWE-79': {'techniques': ['T1189'], 'tactic': 'Initial Access', 'name': 'XSS'},
            'CWE-78': {'techniques': ['T1059'], 'tactic': 'Execution', 'name': 'OS Command Injection'},
            'CWE-22': {'techniques': ['T1083'], 'tactic': 'Discovery', 'name': 'Path Traversal'},
            'CWE-918': {'techniques': ['T1090'], 'tactic': 'Command and Control', 'name': 'SSRF'},
            'CWE-352': {'techniques': ['T1185'], 'tactic': 'Collection', 'name': 'CSRF'},
            'CWE-384': {'techniques': ['T1563'], 'tactic': 'Lateral Movement', 'name': 'Session Fixation'},
            'CWE-327': {'techniques': ['T1550.001'], 'tactic': 'Defense Evasion', 'name': 'Weak Crypto'},
            'CWE-307': {'techniques': ['T1110'], 'tactic': 'Credential Access', 'name': 'Brute Force'},
            'CWE-798': {'techniques': ['T1078'], 'tactic': 'Persistence', 'name': 'Hardcoded Credentials'},
            'CWE-639': {'techniques': ['T1548'], 'tactic': 'Privilege Escalation', 'name': 'IDOR'},
            'CWE-269': {'techniques': ['T1548'], 'tactic': 'Privilege Escalation', 'name': 'Privilege Escalation'},
            'CWE-200': {'techniques': ['T1592'], 'tactic': 'Reconnaissance', 'name': 'Information Disclosure'},
            'CWE-434': {'techniques': ['T1105'], 'tactic': 'Command and Control', 'name': 'Unrestricted Upload'},
            'CWE-942': {'techniques': ['T1189'], 'tactic': 'Initial Access', 'name': 'CORS Misconfig'},
            'CWE-521': {'techniques': ['T1110'], 'tactic': 'Credential Access', 'name': 'Weak Password'},
            'CWE-614': {'techniques': ['T1557'], 'tactic': 'Credential Access', 'name': 'Insecure Cookie'},
            'CWE-1004': {'techniques': ['T1539'], 'tactic': 'Credential Access', 'name': 'Cookie Theft'},
            'CWE-330': {'techniques': ['T1539'], 'tactic': 'Credential Access', 'name': 'Weak PRNG'},
            'CWE-943': {'techniques': ['T1190'], 'tactic': 'Initial Access', 'name': 'NoSQL Injection'},
            'CWE-90': {'techniques': ['T1190'], 'tactic': 'Initial Access', 'name': 'LDAP Injection'},
            'CWE-1336': {'techniques': ['T1190'], 'tactic': 'Initial Access', 'name': 'SSTI'},
            'CWE-113': {'techniques': ['T1190'], 'tactic': 'Initial Access', 'name': 'CRLF Injection'},
            'CWE-304': {'techniques': ['T1556.006'], 'tactic': 'Defense Evasion', 'name': 'MFA Bypass'},
            'CWE-915': {'techniques': ['T1098'], 'tactic': 'Persistence', 'name': 'Mass Assignment'},
            'CWE-601': {'techniques': ['T1528'], 'tactic': 'Credential Access', 'name': 'Open Redirect'},
        }

    def _default_cve_patterns(self):
        return {
            'sql_injection': ['CVE-2023-36844', 'CVE-2023-34362', 'CVE-2022-26134'],
            'xss': ['CVE-2023-29489', 'CVE-2023-24998', 'CVE-2022-22965'],
            'ssrf': ['CVE-2023-35078', 'CVE-2021-44228', 'CVE-2023-27997'],
            'rce': ['CVE-2023-44487', 'CVE-2023-4966', 'CVE-2023-22515'],
            'auth_bypass': ['CVE-2023-46747', 'CVE-2023-20198', 'CVE-2023-22518'],
            'path_traversal': ['CVE-2023-34039', 'CVE-2023-42793', 'CVE-2024-21887'],
            'jwt': ['CVE-2022-23529', 'CVE-2022-21449', 'CVE-2018-0114'],
            'cors': ['CVE-2023-2825', 'CVE-2022-0482'],
            'csrf': ['CVE-2023-37462', 'CVE-2022-36804'],
        }

    def enrich_findings(self, findings):
        """Enrich findings with CVE, CWE, and MITRE ATT&CK mappings."""
        print(f"{Fore.CYAN}[*] Enriching findings with CVE/MITRE mappings{Style.RESET_ALL}")
        for finding in findings:
            self._add_mitre_mapping(finding)
            self._add_cve_references(finding)
            self._calculate_epss(finding)
        return findings

    def _add_mitre_mapping(self, finding):
        """Map finding to MITRE ATT&CK techniques."""
        cwe = finding.get('cwe', '')
        if cwe and cwe in self.mitre_mapping:
            mapping = self.mitre_mapping[cwe]
            finding['mitre_attack'] = finding.get('mitre_attack', mapping['techniques'][0])
            finding['mitre_tactic'] = mapping['tactic']
            finding['mitre_name'] = mapping['name']

    def _add_cve_references(self, finding):
        """Map finding to known CVE patterns."""
        title = finding.get('title', '').lower()
        category = finding.get('category', '').lower()

        cve_type = None
        if 'sql' in title and 'injection' in title:
            cve_type = 'sql_injection'
        elif 'xss' in title or 'cross-site scripting' in title:
            cve_type = 'xss'
        elif 'ssrf' in title:
            cve_type = 'ssrf'
        elif 'command' in title and 'injection' in title:
            cve_type = 'rce'
        elif 'bypass' in title or 'mfa' in title:
            cve_type = 'auth_bypass'
        elif 'traversal' in title or 'path' in title:
            cve_type = 'path_traversal'
        elif 'jwt' in title:
            cve_type = 'jwt'
        elif 'cors' in title or 'cors' in category:
            cve_type = 'cors'
        elif 'csrf' in title or 'csrf' in category:
            cve_type = 'csrf'

        if cve_type and cve_type in self.cve_patterns:
            finding['related_cves'] = self.cve_patterns[cve_type]

    def _calculate_epss(self, finding):
        """Estimate EPSS-like exploit probability based on severity and type."""
        severity = finding.get('severity', 'MEDIUM')
        epss_map = {'CRITICAL': 0.85, 'HIGH': 0.55, 'MEDIUM': 0.25, 'LOW': 0.05, 'INFO': 0.01}
        finding['epss_estimate'] = epss_map.get(severity, 0.1)

    def lookup_cve_online(self, keyword):
        """Search NVD for CVEs matching a keyword (optional online lookup)."""
        if not REQUESTS_AVAILABLE:
            return []
        try:
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={keyword}&resultsPerPage=5"
            r = req.get(url, timeout=10)
            if r.status_code == 200:
                data = r.json()
                return [
                    {
                        'id': v['cve']['id'],
                        'description': v['cve']['descriptions'][0]['value'][:200] if v['cve']['descriptions'] else '',
                    }
                    for v in data.get('vulnerabilities', [])[:5]
                ]
        except Exception:
            pass
        return []

    def generate_mitre_report(self, findings):
        """Generate a MITRE ATT&CK mapping summary."""
        tactics = {}
        for f in findings:
            tactic = f.get('mitre_tactic', 'Unknown')
            technique = f.get('mitre_attack', 'N/A')
            if tactic not in tactics:
                tactics[tactic] = []
            tactics[tactic].append({
                'technique': technique,
                'finding': f.get('title', 'N/A'),
                'severity': f.get('severity', 'N/A')
            })
        return tactics
