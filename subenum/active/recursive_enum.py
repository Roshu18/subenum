import asyncio

class RecursiveEnumerator:
    """
    Performs recursive subdomain enumeration.
    Finds subdomains of discovered subdomains (e.g., dev.api.example.com).
    """
    
    def __init__(self, passive_sources, max_depth=2, verbose=False):
        self.passive_sources = passive_sources
        self.max_depth = max_depth
        self.verbose = verbose
        self.discovered = set()
    
    async def enumerate_recursive(self, initial_subdomains: set, base_domain: str) -> set:
        """
        Recursively enumerate subdomains up to max_depth levels.
        Returns all discovered subdomains.
        """
        all_found = set(initial_subdomains)
        
        # OPTIMIZATION: Filter to high-value targets only for recursive scanning
        high_value_targets = self._filter_high_value(initial_subdomains, base_domain)
        
        if self.verbose:
            print(f"  [Optimization] Filtered {len(initial_subdomains)} → {len(high_value_targets)} high-value targets for recursive scan")
        
        current_level = high_value_targets
        
        for depth in range(1, self.max_depth + 1):
            if not current_level:
                break
            
            if self.verbose:
                print(f"  [Recursive Level {depth}] Scanning {len(current_level)} subdomains...")
            
            next_level = set()
            
            # For each subdomain, try to find its subdomains
            scanned_count = 0
            for subdomain in current_level:
                # Skip if it's the base domain
                if subdomain == base_domain:
                    continue
                
                scanned_count += 1
                if self.verbose:
                    print(f"    [{scanned_count}/{len(current_level)}] Scanning: {subdomain}")
                
                # Run passive enumeration on this subdomain
                found = await self._enumerate_subdomain(subdomain)
                
                # Filter to only include subdomains that end with base_domain
                valid_found = {s for s in found if s.endswith(base_domain) and s != subdomain}
                
                # Add new discoveries
                new_discoveries = valid_found - all_found
                if new_discoveries:
                    next_level.update(new_discoveries)
                    all_found.update(new_discoveries)
                    
                    if self.verbose:
                        print(f"      ✓ Found {len(new_discoveries)} new subdomains under {subdomain}")
            
            current_level = next_level
            
            if self.verbose:
                print(f"  [Level {depth} Complete] Found {len(next_level)} new subdomains")
        
        return all_found
    
    def _filter_high_value(self, subdomains: set, base_domain: str) -> set:
        """
        Filter subdomains to only include high-value targets for recursive scanning.
        Skips: game servers, CDN nodes, auto-generated IDs, etc.
        """
        high_value = set()
        
        # Patterns to SKIP (low-value, auto-generated)
        skip_patterns = [
            r'^gs-',           # Game servers (gs-classic-xxx)
            r'^cdn-',          # CDN nodes
            r'^edge-',         # Edge nodes
            r'^node-',         # Generic nodes
            r'^server-',       # Generic servers
            r'^instance-',     # Cloud instances
            r'^[a-f0-9]{8,}',  # Long hex IDs
            r'-[a-z0-9]{10,}', # Random suffixes (e.g., -9cqrl1euxtiqgi2ppvq6r)
        ]
        
        # Patterns to KEEP (high-value)
        keep_patterns = [
            r'api',
            r'admin',
            r'dev',
            r'stage',
            r'staging',
            r'test',
            r'uat',
            r'prod',
            r'internal',
            r'vpn',
            r'portal',
            r'dashboard',
            r'console',
            r'panel',
            r'mail',
            r'smtp',
            r'auth',
            r'login',
            r'sso',
        ]
        
        import re
        
        for subdomain in subdomains:
            # Extract subdomain prefix (before base domain)
            prefix = subdomain.replace(f'.{base_domain}', '').lower()
            
            # Skip if matches skip patterns
            should_skip = any(re.search(pattern, prefix) for pattern in skip_patterns)
            if should_skip:
                continue
            
            # Keep if matches high-value patterns OR is short/simple
            is_high_value = any(re.search(pattern, prefix) for pattern in keep_patterns)
            is_simple = len(prefix) < 20 and prefix.count('.') <= 1  # Simple subdomains
            
            if is_high_value or is_simple:
                high_value.add(subdomain)
        
        return high_value
    
    async def _enumerate_subdomain(self, subdomain: str) -> set:
        """
        Run passive enumeration on a single subdomain.
        """
        if self.verbose:
            source_names = [s.__class__.__name__ for s in self.passive_sources]
            print(f"      Querying: {', '.join(source_names)}")
        
        tasks = [source.fetch(subdomain) for source in self.passive_sources]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        found = set()
        for i, res in enumerate(results):
            if isinstance(res, set):
                if res and self.verbose:
                    source_name = self.passive_sources[i].__class__.__name__
                    print(f"        ✓ {source_name}: {len(res)} results")
                found.update(res)
        
        return found
