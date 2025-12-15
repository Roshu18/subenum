
import re

class RiskScorer:
    def __init__(self):
        pass

    def calculate_score(self, subdomain: str, http_status: int, title: str, 
                        is_private: bool, takeover_risk: str) -> tuple[int, list[str]]:
        """
        Calculates risk score and returns risks/categories.
        Returns: (score, list_of_reasons)
        """
        score = 0
        reasons = []

        sub_lower = subdomain.lower()

        # --- NEGATIVE SCORING (Noise Reduction) ---
        if is_private:
            score -= 5
            reasons.append("Private IP")
        
        if http_status == 404:
            score -= 3
            reasons.append("404 Not Found")
        
        # --- POSITIVE SCORING (High Value) ---
        
        # 1. Takeover (Critical)
        if takeover_risk:
            score += 10
            reasons.append(f"TAKEOVER ({takeover_risk})")

        # 2. Public API (+5)
        api_patterns = [r"api\.", r"/api/", r"/v1/", r"/v2/", r"graphql"]
        if any(re.search(p, sub_lower) for p in api_patterns):
            score += 5
            reasons.append("API Endpoint")

        # 3. Auth / Sensitive (+4)
        auth_patterns = [r"auth", r"login", r"signin", r"sso", r"vpn", r"admin", r"dashboard", r"portal", r"jenkins", r"jira"]
        if any(re.search(p, sub_lower) for p in auth_patterns):
            score += 6
            reasons.append("Auth/Admin")
        
        # 4. Dev / Stage (+2) - Often lower security
        dev_patterns = [r"dev", r"stg", r"stage", r"test", r"uat", r"beta", r"internal"]
        if any(re.search(p, sub_lower) for p in dev_patterns):
            score += 3
            reasons.append("Dev/Pre-Prod environment")

        # 5. ID Parameters (Basic heuristic on URL/Title)
        # (This is harder without full crawling, but we check if title implies a specific resource)
        
        return score, reasons
