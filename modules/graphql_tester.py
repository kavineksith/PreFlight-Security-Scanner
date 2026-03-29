"""
GraphQL Security Analyzer
Hunts for Introspection queries, Batched Query Denial of Service, 
and Field/Type enumeration vulnerabilities in GraphQL endpoints.
"""

import concurrent.futures
from urllib.parse import urljoin
from colorama import Fore, Style

class GraphQLTester:
    def __init__(self, session, base_url):
        self.session = session
        self.base_url = base_url
        self.findings = []
        
        # Common GraphQL endpoints
        self.graphql_endpoints = [
            '/graphql', '/v1/graphql', '/v2/graphql', '/api/graphql', 
            '/graphql/console', '/graphql.php', '/graph'
        ]

    def run_all_checks(self):
        """Run all GraphQL vulnerability checks."""
        print(f"{Fore.CYAN}[*] GraphQL API Auditing{Style.RESET_ALL}")
        
        active_endpoint = self.discover_endpoint()
        if active_endpoint:
            self.test_introspection(active_endpoint)
            self.test_query_batching(active_endpoint)
            self.test_field_suggestion(active_endpoint)
            
        return self.findings

    def discover_endpoint(self):
        """Find the active GraphQL endpoint."""
        print(f"{Fore.YELLOW}[*] Discovering GraphQL Endpoints...{Style.RESET_ALL}")
        
        active_endpoint = None
        
        # Simple query to test validity
        test_payload = {"query": "{ __typename }"}
        
        def check_endpoint(endpoint):
            url = urljoin(self.base_url, endpoint)
            try:
                # GET test
                g_resp = self.session.get(f"{url}?query={{__typename}}", timeout=3)
                if '__typename' in g_resp.text:
                    return url
                    
                # POST JSON test
                p_resp = self.session.post(url, json=test_payload, timeout=3)
                if '__typename' in p_resp.text or 'errors' in p_resp.text:
                    return url
            except Exception:
                pass
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            results = executor.map(check_endpoint, self.graphql_endpoints)
            for r in results:
                if r:
                    active_endpoint = r
                    break
                    
        return active_endpoint

    def test_introspection(self, endpoint):
        """Test if the GraphQL Introspection schema is enabled, exposing the entire database."""
        print(f"{Fore.YELLOW}[*] Testing GraphQL Introspection (Schema Leak)...{Style.RESET_ALL}")
        
        introspection_payload = {
            "query": "\n    query IntrospectionQuery {\n      __schema {\n        queryType { name }\n        mutationType { name }\n        subscriptionType { name }\n        types {\n          ...FullType\n        }\n        directives {\n          name\n          description\n          locations\n          args {\n            ...InputValue\n          }\n        }\n      }\n    }\n\n    fragment FullType on __Type {\n      kind\n      name\n      description\n      fields(includeDeprecated: true) {\n        name\n        description\n        args {\n          ...InputValue\n        }\n        type {\n          ...TypeRef\n        }\n        isDeprecated\n        deprecationReason\n      }\n      inputFields {\n        ...InputValue\n      }\n      interfaces {\n        ...TypeRef\n      }\n      enumValues(includeDeprecated: true) {\n        name\n        description\n        isDeprecated\n        deprecationReason\n      }\n      possibleTypes {\n        ...TypeRef\n      }\n    }\n\n    fragment InputValue on __InputValue {\n      name\n      description\n      type { ...TypeRef }\n      defaultValue\n    }\n\n    fragment TypeRef on __Type {\n      kind\n      name\n      ofType {\n        kind\n        name\n        ofType {\n          kind\n          name\n          ofType {\n            kind\n            name\n            ofType {\n              kind\n              name\n              ofType {\n                kind\n                name\n                ofType {\n                  kind\n                  name\n                  ofType {\n                    kind\n                    name\n                  }\n                }\n              }\n            }\n          }\n        }\n      }\n    }\n  "
        }
        
        try:
            resp = self.session.post(endpoint, json=introspection_payload, timeout=5)
            if '__schema' in resp.text and 'queryType' in resp.text:
                self.findings.append({
                    'title': 'GraphQL Introspection Enabled',
                    'description': f'Full GraphQL schema definition is exposed at {endpoint}',
                    'severity': 'HIGH',
                    'api_owasp': 'API3:2023',
                    'cwe': 'CWE-200',
                    'remediation': 'Disable GraphQL introspection in production environments. Attackers can use this to map every single API query, mutation, and data type available.',
                    'evidence': f'Introspection query returned full schema: {resp.text[:200]}...',
                    'mitre_attack': 'T1592'
                })
        except Exception:
            pass

    def test_query_batching(self, endpoint):
        """Test if the endpoint accepts massive batched arrays (used to bypass rate limits)."""
        print(f"{Fore.YELLOW}[*] Testing Batched Query Rate Limit Evasion...{Style.RESET_ALL}")
        
        # We send 10 batched queries in a single HTTP request
        batched_payload = [
            {"query": "{ __typename }"} for _ in range(10)
        ]
        
        try:
            resp = self.session.post(endpoint, json=batched_payload, timeout=5)
            # If the response is a JSON list with 10 elements, batching worked
            if resp.status_code == 200 and isinstance(resp.json(), list) and len(resp.json()) == 10:
                self.findings.append({
                    'title': 'GraphQL Query Batching Enabled (Rate Limit Bypass)',
                    'description': f'API accepts arrays of queries at {endpoint}, bypassing standard HTTP rate limits.',
                    'severity': 'MEDIUM',
                    'api_owasp': 'API4:2023',
                    'cwe': 'CWE-770',
                    'remediation': 'Disable query batching in the GraphQL engine, or implement complex cost-based rate limiting that analyzes the AST depth of queries.',
                    'evidence': f'Sent 10 GraphQL queries inside a single HTTP request array, received 10 successful responses.',
                    'mitre_attack': 'T1190'
                })
        except Exception:
            pass

    def test_field_suggestion(self, endpoint):
        """Test for Field Suggestion (e.g. 'Did you mean password?') leaking unmapped schema elements."""
        print(f"{Fore.YELLOW}[*] Testing GraphQL Error Field Suggestions...{Style.RESET_ALL}")
        
        test_payload = {
            "query": "{ systemUser { passwrd } }" # Intentional typo
        }
        try:
            resp = self.session.post(endpoint, json=test_payload, timeout=3)
            # Look for Apollo or standard GraphQL suggestion errors
            if 'Did you mean' in resp.text or 'Cannot query field' in resp.text:
                self.findings.append({
                    'title': 'GraphQL Field Hinting / Error Verbosity',
                    'description': f'GraphQL errors leak hidden field and object names via "Did you mean?" suggestions: {endpoint}',
                    'severity': 'LOW',
                    'api_owasp': 'API3:2023',
                    'cwe': 'CWE-203',
                    'remediation': 'Disable development-level verbose errors and field/typographical suggestions in production GraphQL instances.',
                    'evidence': f'Typo query triggered suggestion: {resp.text[:150]}',
                    'mitre_attack': 'T1592'
                })
        except Exception:
            pass
