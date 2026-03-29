"""
CVSS v3.1 Score Calculator
Maps findings to CVSS scores based on severity and impact
"""

import math

class CVSSCalculator:
    def __init__(self):
        self.cvss_scores = {}
    
    def calculate_auth_score(self, finding):
        """Calculate CVSS for authentication/authorization findings"""
        severity = finding.get('severity', 'MEDIUM')
        
        if severity == 'CRITICAL':
            vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
            score = 9.8
        elif severity == 'HIGH':
            vector = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"
            score = 8.1
        elif severity == 'MEDIUM':
            vector = "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:L/A:N"
            score = 6.5
        else:
            vector = "CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:N"
            score = 4.2
        
        return {
            'score': score,
            'vector': vector,
            'severity': severity
        }
    
    def calculate_owasp_score(self, finding):
        """Calculate CVSS for OWASP findings"""
        title = finding.get('title', '').lower()
        severity = finding.get('severity', 'MEDIUM')
        
        # SQL Injection, Command Injection
        if 'sql' in title or 'command' in title:
            return {
                'score': 9.8,
                'vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
                'severity': 'CRITICAL'
            }
        
        # XSS
        if 'xss' in title:
            return {
                'score': 6.1,
                'vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
                'severity': 'MEDIUM'
            }
        
        # Path traversal, SSRF
        if 'traversal' in title or 'ssrf' in title:
            return {
                'score': 7.5,
                'vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
                'severity': 'HIGH'
            }
        
        # Default mapping
        severity_map = {
            'CRITICAL': 9.8,
            'HIGH': 7.5,
            'MEDIUM': 5.5,
            'LOW': 3.5
        }
        
        score = severity_map.get(severity, 5.5)
        
        return {
            'score': score,
            'vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N',
            'severity': severity
        }
    
    def calculate_api_score(self, finding):
        """Calculate CVSS for API-specific findings"""
        title = finding.get('title', '').lower()
        
        if 'bola' in title or 'object level' in title:
            return {
                'score': 8.1,
                'vector': 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N',
                'severity': 'HIGH'
            }
        
        if 'function level' in title:
            return {
                'score': 9.0,
                'vector': 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H',
                'severity': 'CRITICAL'
            }
        
        if 'rate limiting' in title:
            return {
                'score': 5.3,
                'vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L',
                'severity': 'MEDIUM'
            }
        
        # Default API score
        return {
            'score': 6.5,
            'vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N',
            'severity': 'MEDIUM'
        }
    
    def calculate_config_score(self, finding):
        """Calculate CVSS for configuration findings"""
        title = finding.get('title', '').lower()
        
        if 'directory listing' in title:
            return {
                'score': 5.3,
                'vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
                'severity': 'MEDIUM'
            }
        
        if 'debug' in title or 'information exposure' in title:
            return {
                'score': 4.3,
                'vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
                'severity': 'MEDIUM'
            }
        
        return {
            'score': 3.7,
            'vector': 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N',
            'severity': 'LOW'
        }

    def calculate_generic_score(self, finding):
        """Calculate CVSS for any finding based on severity."""
        severity = finding.get('severity', 'MEDIUM')
        severity_map = {
            'CRITICAL': {'score': 9.8, 'vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'},
            'HIGH':     {'score': 7.5, 'vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N'},
            'MEDIUM':   {'score': 5.3, 'vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N'},
            'LOW':      {'score': 3.1, 'vector': 'CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N'},
            'INFO':     {'score': 0.0, 'vector': 'CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:N'},
        }
        entry = severity_map.get(severity, severity_map['MEDIUM'])
        return {'score': entry['score'], 'vector': entry['vector'], 'severity': severity}