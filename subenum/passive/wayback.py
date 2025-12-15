import aiohttp
import asyncio
import json

class WaybackFetcher:
    async def fetch(self, domain: str) -> set[str]:
        # Wayback CDX API
        url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&collapse=urlkey"
        subdomains = set()
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
        
        try:
            async with aiohttp.ClientSession(headers=headers) as session:
                async with session.get(url, timeout=60, ssl=False) as resp:  # Increased timeout
                    if resp.status == 200:
                        data = await resp.json()
                        # Data is list of lists, header usually first
                        # ['urlkey', 'timestamp', 'original', 'mimetype', 'statuscode', 'digest', 'length']
                        for entry in data:
                            if len(entry) < 3:
                                continue
                            original_url = entry[2]
                            # Clean "http://sub.domain.com/path" -> "sub.domain.com"
                            if "://" in original_url:
                                part = original_url.split("://")[1]
                                host = part.split("/")[0]
                                if host.endswith(domain) and host != domain:
                                    subdomains.add(host)
        except Exception as e:
            # Return exception for debugging instead of silent fail
            return e
            
        return subdomains
