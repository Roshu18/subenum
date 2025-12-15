import aiodns
import asyncio
import logging
from ..data_classes import DomainResult

# Common CDN CNAME/PTR fingerprints
CDN_SIGNATURES = {
    'cloudflare': 'CDN: Cloudflare',
    'cloudfront': 'CDN: AWS CloudFront',
    'akamai': 'CDN: Akamai',
    'fastly': 'CDN: Fastly',
    'azureedge': 'CDN: Azure',
    'googleusercontent': 'Cloud: Google',
    'herokuapp': 'Cloud: Heroku',
    'vercel': 'CDN: Vercel',
    'netlify': 'CDN: Netlify',
    'incapsula': 'CDN: Imperva',
    'sucuri': 'CDN: Sucuri',
    'awsglobalaccelerator': 'CDN: AWS Global Accelerator'
}

class AsyncResolver:
    def __init__(self, nameservers=None):
        self.resolver = aiodns.DNSResolver(nameservers=nameservers)

    async def detect_provider(self, ip: str, cname: str = "") -> str:
        """
        Identify CDN or Cloud provider based on CNAME and Reverse DNS (PTR).
        """
        # 1. Check CNAME first (fastest)
        if cname:
            cname_lower = cname.lower()
            for sig, name in CDN_SIGNATURES.items():
                if sig in cname_lower:
                    return name

        # 2. Check PTR (Reverse DNS) if CNAME didn't match
        if ip and ip != "-":
            try:
                # Need to use 'PTR' query on the reverse IP address
                # But aiodns gethostbyaddr is easier if supported, 
                # or manually formatting the arpa address. 
                # aiodns wraps pycares. try standard gethostbyaddr wrapper?
                # Actually aiodns.gethostbyaddr works well.
                try:
                    res = await self.resolver.gethostbyaddr(ip)
                    ptr_name = res.name.lower()
                    for sig, name in CDN_SIGNATURES.items():
                        if sig in ptr_name:
                            return name
                    # If valid PTR but no CDN match, return the PTR domain (shortened)
                    # e.g. "x.y.compute.amazonaws.com" -> "Host: amazonaws.com"
                    parts = ptr_name.split('.')
                    if len(parts) > 2:
                        return f"Host: {parts[-2]}.{parts[-1]}"
                except Exception:
                    pass
            except Exception:
                pass

        return "-"

    async def resolve(self, domain: str) -> DomainResult:
        result = DomainResult(domain=domain)
        found_cname = ""
        
        try:
            # 1. Try CNAME first to catch the chain
            try:
                msg = await self.resolver.query(domain, 'CNAME')
                found_cname = msg.cname
                result.ip = "-" 
                result.rtype = 'CNAME'
                result.status = 'LIVE'
                
                # If we have a CNAME, we still usually want the A record IP 
                # to know where it actually goes.
                # Recursive resolve for the IP
                try:
                    ip_msg = await self.resolver.query(found_cname, 'A')
                    result.ip = ip_msg[0].host
                except:
                    pass # Keep IP as - if A fails

            except aiodns.error.DNSError:
                # No CNAME, try A
                 try:
                    msg = await self.resolver.query(domain, 'A')
                    result.ip = msg[0].host
                    result.rtype = 'A'
                    result.status = 'LIVE'
                 except aiodns.error.DNSError:
                    result.status = 'DEAD'

            if result.status == 'LIVE':
                result.cname = found_cname  # Store CNAME for takeover detection
                result.provider = await self.detect_provider(result.ip, found_cname)
        
        except Exception as e:
            # logging.debug(f"Resolution error for {domain}: {e}")
            result.status = 'DEAD'
        
        return result

    async def check_wildcard(self, domain: str) -> bool:
        import random
        import string
        rand_sub = ''.join(random.choices(string.ascii_lowercase, k=10))
        test_domain = f"{rand_sub}.{domain}"
        
        res = await self.resolve(test_domain)
        return res.status == 'LIVE'
