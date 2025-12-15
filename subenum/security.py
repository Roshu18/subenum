"""
Security utilities for input validation and sanitization.
Prevents command injection, path traversal, and other attacks.
"""

import re
import os
from typing import Optional

class SecurityValidator:
    """Validates user inputs to prevent security vulnerabilities."""
    
    # RFC 1035 compliant domain validation
    DOMAIN_PATTERN = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    SUBDOMAIN_PATTERN = r'^[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$'
    
    # Maximum lengths (RFC 1035)
    MAX_DOMAIN_LENGTH = 253
    MAX_LABEL_LENGTH = 63
    MAX_PATH_LENGTH = 4096
    
    @staticmethod
    def is_valid_domain(domain: str) -> bool:
        """
        Validates domain name according to RFC 1035.
        Prevents command injection in subprocess calls.
        
        Args:
            domain: Domain name to validate
            
        Returns:
            True if valid, False otherwise
        """
        if not domain or len(domain) > SecurityValidator.MAX_DOMAIN_LENGTH:
            return False
        
        # Check overall pattern
        if not re.match(SecurityValidator.DOMAIN_PATTERN, domain):
            return False
        
        # Check each label
        labels = domain.split('.')
        for label in labels:
            if len(label) > SecurityValidator.MAX_LABEL_LENGTH:
                return False
            if not re.match(SecurityValidator.SUBDOMAIN_PATTERN, label):
                return False
        
        return True
    
    @staticmethod
    def is_safe_path(path: str, base_dir: Optional[str] = None) -> bool:
        """
        Validates file path to prevent path traversal attacks.
        
        Args:
            path: File path to validate
            base_dir: Base directory (defaults to cwd)
            
        Returns:
            True if path is safe, False otherwise
        """
        if not path or len(path) > SecurityValidator.MAX_PATH_LENGTH:
            return False
        
        # Resolve to absolute paths
        abs_path = os.path.abspath(path)
        abs_base = os.path.abspath(base_dir or os.getcwd())
        
        # Check if path is within allowed directory
        # Also check for common path traversal patterns
        if not abs_path.startswith(abs_base):
            return False
        
        # Reject paths with suspicious patterns
        suspicious_patterns = ['..', '~', '$', '`', '|', ';', '&', '\n', '\r']
        for pattern in suspicious_patterns:
            if pattern in path:
                return False
        
        return True
    
    @staticmethod
    def sanitize_domain(domain: str) -> str:
        """
        Sanitizes domain input by removing dangerous characters.
        
        Args:
            domain: Raw domain input
            
        Returns:
            Sanitized domain string
        """
        # Remove protocol prefixes
        domain = domain.replace("https://", "").replace("http://", "")
        
        # Remove path and query components
        domain = domain.split("/")[0].split("?")[0].split("#")[0]
        
        # Remove whitespace
        domain = domain.strip()
        
        # Convert to lowercase
        domain = domain.lower()
        
        return domain
    
    @staticmethod
    def validate_targets(targets: list) -> list:
        """
        Validates a list of target domains/subdomains.
        Filters out invalid or malicious entries.
        
        Args:
            targets: List of target domains
            
        Returns:
            List of validated targets
        """
        validated = []
        for target in targets:
            sanitized = SecurityValidator.sanitize_domain(target)
            if SecurityValidator.is_valid_domain(sanitized):
                validated.append(sanitized)
        
        return validated
