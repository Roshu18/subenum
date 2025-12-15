import aiohttp
import asyncio

class ThreatMinerFetcher:
    async def fetch(self, domain: str) -> set[str]:
        url = f"https://api.threatminer.org/v2/domain.php?q={domain}&rt=5"
        subdomains = set()
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=10) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        # Format: {'status_code': '200', 'results': [...]}
                        if data.get("status_code") == "200":
                            results = data.get("results", [])
                            for sub in results:
                                if sub.endswith(domain) and sub != domain:
                                    subdomains.add(sub)
        except Exception:
            pass
            
        return subdomains
