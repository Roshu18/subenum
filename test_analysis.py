
import asyncio
from subenum.analysis import TrafficFilter, TakeoverDetector, RiskScorer, SmartFingerprinter

def test_filter():
    tf = TrafficFilter()
    assert tf.is_private_ip("192.168.1.5") == True, "Failed 192.168.x"
    assert tf.is_private_ip("10.0.0.1") == True, "Failed 10.x"
    assert tf.is_private_ip("8.8.8.8") == False, "Refused Public IP"
    assert tf.is_private_ip("172.16.0.5") == True, "Failed 172.16.x"
    print("[+] Filter Test Passed")

def test_takeover():
    td = TakeoverDetector()
    # Test Match
    vuln = td.check("sub.s3.amazonaws.com", "The specified bucket does not exist")
    assert vuln == "AWS S3", f"Failed AWS detection: {vuln}"
    
    # Test Non-Match
    safe = td.check("google.com", "<html>")
    assert safe is None, "False positive on google.com"
    print("[+] Takeover Test Passed")

def test_risk():
    rs = RiskScorer()
    
    # API Test
    score, reasons = rs.calculate_score("api.target.com", 200, "API", False, None)
    assert score >= 5, f"API Score too low: {score}"
    assert "API Endpoint" in reasons

    # Auth Test
    score_auth, _ = rs.calculate_score("admin.target.com", 200, "Login", False, None)
    assert score_auth == 6, f"Auth Score incorrect: {score_auth}"

    # Dev Test
    score_dev, _ = rs.calculate_score("dev.target.com", 200, "Dev", False, None)
    assert score_dev == 3, f"Dev Score incorrect: {score_dev}"
    
    # Private IP Test
    score, reasons = rs.calculate_score("intranet.target.com", 200, "Intranet", True, None)
    assert score <= 0, f"Private IP score too high: {score}"
    assert "Private IP" in reasons
    
    print("[+] Risk Scoring Test Passed")

def test_dupe():
    sf = SmartFingerprinter()
    h1 = sf.get_hash(200, "Home", 500, "<body>Hello</body>")
    h2 = sf.get_hash(200, "Home", 505, "<body>Hello</body>") # slightly diff len
    assert h1 == h2, "Fuzzy hashing failed"
    
    assert sf.is_duplicate(h1) == False, "First see should not be duplicate"
    assert sf.is_duplicate(h2) == True, "Second see should be duplicate"
    print("[+] Deduplication Test Passed")

if __name__ == "__main__":
    test_filter()
    test_takeover()
    test_risk()
    test_dupe()
    print("\nALL SYSTEMS GREEN.")
