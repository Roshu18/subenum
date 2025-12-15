import asyncio
import aiohttp
import os
from typing import List
from ..security import SecurityValidator

WORDLIST_URL = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-110000.txt"
SAFE_WORDLIST_FILE = "subenum/active/safe_wordlist.txt"
DEEP_WORDLIST_FILE = "subdomains_110000.txt"

class BruteForcer:
    def __init__(self, domain: str, deep_scan: bool = False, custom_path: str = None):
        self.domain = domain
        self.deep_scan = deep_scan
        
        if custom_path:
            # SECURITY: Validate custom wordlist path to prevent path traversal
            if not SecurityValidator.is_safe_path(custom_path):
                raise ValueError(f"Invalid wordlist path: {custom_path}")
            
            # Additional check: file must exist and be readable
            if not os.path.isfile(custom_path):
                raise ValueError(f"Wordlist file not found: {custom_path}")
            
            self.wordlist_path = custom_path
            self.custom = True
        elif self.deep_scan:
            self.wordlist_path = os.path.join(os.getcwd(), DEEP_WORDLIST_FILE)
            self.custom = False
        else:
            self.wordlist_path = os.path.join(os.getcwd(), SAFE_WORDLIST_FILE)
            self.custom = False

    async def ensure_wordlist(self):
        """ Checks if wordlist exists, downloads if deep scanning (and not custom). """
        if self.custom:
            if not os.path.exists(self.wordlist_path):
                raise FileNotFoundError(f"Custom wordlist not found: {self.wordlist_path}")
            return

        if self.deep_scan and not os.path.exists(self.wordlist_path):
            try:
                print(f"\n[cyan]Deep Scan enabled: Downloading top-5000 wordlist...[/cyan]")
                async with aiohttp.ClientSession() as session:
                    async with session.get(WORDLIST_URL) as resp:
                        if resp.status == 200:
                            content = await resp.text()
                            with open(self.wordlist_path, 'w', encoding='utf-8') as f:
                                f.write(content)
                            print("[green]Download complete.[/green]")
            except Exception as e:
                print(f"[!] Failed to download wordlist: {e}")

    async def generate_candidates(self) -> set[str]:
        await self.ensure_wordlist()
        candidates = set()
        
        if os.path.exists(self.wordlist_path):
            try:
                with open(self.wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        sub = line.strip()
                        if sub and not sub.startswith('#'):
                            candidates.add(f"{sub}.{self.domain}")
            except Exception:
                pass
        
        return candidates
