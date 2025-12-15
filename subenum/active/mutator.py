
class Mutator:
    def __init__(self, domain):
        self.domain = domain
        self.words = [
            "dev", "staging", "test", "prod", "beta", "demo", "admin",
            "v1", "v2", "api", "vpn", "mail", "web", "internal",
            "corp", "private", "public", "cloud", "backup", "db",
            "stage", "qa", "uat", "sandbox", "secure", "login"
        ]

    def generate_permutations(self, subdomains):
        """
        Generates new subdomains based on input set.
        Returns a set of new logical variants.
        OPTIMIZED: Only permutes high-value targets to avoid millions of useless combinations.
        """
        new_subs = set()
        
        # OPTIMIZATION: Only permute the most interesting subdomains
        # Filter for high-value patterns (api, auth, admin, dev, etc.)
        high_value_keywords = [
            'api', 'auth', 'admin', 'vpn', 'login', 'sso', 'dev', 'stage', 
            'test', 'prod', 'beta', 'internal', 'secure', 'portal', 'dashboard',
            'jenkins', 'jira', 'gitlab', 'git', 'db', 'sql', 'backup'
        ]
        
        interesting_subs = []
        for sub in subdomains:
            if sub == self.domain:
                continue
            # Check if subdomain contains high-value keywords
            sub_lower = sub.lower()
            if any(keyword in sub_lower for keyword in high_value_keywords):
                interesting_subs.append(sub)
        
        # Limit to top 100 to prevent explosion
        interesting_subs = list(interesting_subs)[:100]
        
        for sub in interesting_subs:
            # Extract the prefix part (e.g., 'api' from 'api.target.com')
            prefix = sub.replace(f".{self.domain}", "")
            
            # 1. Append/Prepend variations (api-dev, dev-api)
            for word in self.words:
                new_subs.add(f"{prefix}-{word}.{self.domain}")
                new_subs.add(f"{word}-{prefix}.{self.domain}")
            
            # 2. Number iteration (api1, api2) - reduced range
            for i in range(1, 5):  # Reduced from 10 to 5
                new_subs.add(f"{prefix}{i}.{self.domain}")
                new_subs.add(f"{prefix}-{i}.{self.domain}")

        return new_subs
