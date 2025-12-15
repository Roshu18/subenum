import asyncio
import logging
import sys

# Suppress warnings
logging.getLogger("asyncio").setLevel(logging.CRITICAL)

from subenum.resolve.resolver import AsyncResolver

async def test_resolution():
    print("--- Debugging AsyncResolver ---")
    resolver = AsyncResolver(nameservers=['8.8.8.8', '1.1.1.1'])
    
    test_domains = [
        "google.com",                       # Control: Should be LIVE
        "www.example.com",                  # Control: Should be LIVE
        "www.mmsdose.live",                 # Target: Should be LIVE
        "thisdoesnotexist.mmsdose.live",    # Target: Should be DEAD
        "admin.mmsdose.live",               # Target: Verify if hidden
        "mmsdose.live"                      # Target: Root
    ]
    
    for domain in test_domains:
        print(f"\nResolving: {domain}")
        try:
            res = await resolver.resolve(domain)
            print(f"  > Status: {res.status}")
            print(f"  > IP: {res.ip}")
            print(f"  > Type: {res.rtype}")
            print(f"  > Provider: {res.provider}")
        except Exception as e:
            print(f"  > ERROR: {e}")

if __name__ == "__main__":
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(test_resolution())
