
import hashlib

class SmartFingerprinter:
    def __init__(self):
        self.seen_hashes = set()

    def get_hash(self, http_status: int, title: str, content_length: int, body_snippet: str = "") -> str:
        """
        Generates a unique hash for the response content.
        Uses Status + Title + Length (approx) + Body Sig.
        """
        # Round length to nearest 100 bytes to group "very similar" pages
        rounded_len = round(content_length / 100) * 100
        
        # Create a signature string
        # e.g. "200|Welcome to nginx|500|<div..."
        sig_str = f"{http_status}|{title}|{rounded_len}|{body_snippet[:100]}"
        
        return hashlib.sha256(sig_str.encode('utf-8', errors='ignore')).hexdigest()

    def is_duplicate(self, content_hash: str) -> bool:
        """Returns True if this content has been seen before."""
        if content_hash in self.seen_hashes:
            return True
        self.seen_hashes.add(content_hash)
        return False
