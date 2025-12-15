import subprocess
import aiodns
from ..security import SecurityValidator

class AXFRChecker:
    """
    Attempts DNS Zone Transfer (AXFR) to discover all subdomains.
    Only works if DNS server is misconfigured to allow unauthorized transfers.
    """
    
    async def attempt_transfer(self, domain: str) -> set[str]:
        """
        Attempt AXFR on all nameservers for the domain.
        Returns set of discovered subdomains.
        """
        # SECURITY: Validate domain to prevent command injection
        if not SecurityValidator.is_valid_domain(domain):
            return set()
        
        subdomains = set()
        resolver = aiodns.DNSResolver()
        
        try:
            # Get nameservers for the domain
            ns_records = await resolver.query(domain, 'NS')
            nameservers = [ns.host for ns in ns_records]
            
            # Try AXFR on each nameserver
            for ns in nameservers:
                try:
                    # Resolve NS to IP
                    ns_ips = await resolver.query(ns, 'A')
                    
                    for ns_record in ns_ips:
                        ns_ip = ns_record.host
                        
                        # SECURITY: Validate NS IP before using in subprocess
                        if not ns_ip or '..' in ns_ip or ';' in ns_ip:
                            continue
                        
                        try:
                            # Use nslookup to attempt AXFR
                            # SECURITY: All inputs are validated above
                            result = subprocess.run(
                                ['nslookup', '-type=AXFR', domain, ns_ip],
                                capture_output=True,
                                text=True,
                                timeout=10
                            )
                            
                            if result.returncode == 0 and result.stdout:
                                # Parse output for subdomains
                                lines = result.stdout.split('\n')
                                for line in lines:
                                    parts = line.split()
                                    if len(parts) >= 1:
                                        potential_sub = parts[0].strip()
                                        # SECURITY: Validate discovered subdomain
                                        if potential_sub.endswith(domain) and SecurityValidator.is_valid_domain(potential_sub):
                                            subdomains.add(potential_sub.lower())
                        except (subprocess.TimeoutExpired, FileNotFoundError):
                            # nslookup not available or timeout
                            pass
                            
                except Exception:
                    continue
                    
        except Exception:
            # Domain doesn't have NS records or query failed
            pass
            
        return subdomains
