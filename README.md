# SubEnum - Advanced Subdomain Enumeration Tool

A powerful, feature-rich subdomain enumeration tool with vulnerability scanning, recursive discovery, and intelligent filtering.

## 🚀 Features

- **Passive Discovery**: CrtSh, RapidDNS, HackerTarget, AlienVault, Wayback Machine
- **Active Enumeration**: Brute force, mutations, JavaScript scraping
- **DNS Zone Transfer (AXFR)**: Exploits misconfigured DNS servers
- **Recursive Enumeration**: 2-level deep subdomain discovery with smart filtering
- **Port Scanning**: Checks common web ports (80, 443, 8080, 8443, 3000, 8000, 8888, 9000)
- **Nuclei Integration**: 11,911 CVE templates for vulnerability scanning
- **Multiple Output Formats**: JSON, CSV, TXT
- **Advanced Filtering**: Wildcard detection, deduplication, private IP filtering
- **Security Hardened**: Protection against command injection and path traversal

## 📦 Installation

### Requirements
- Python 3.8+
- Windows/Linux/macOS

### Setup
```powershell
# Clone or download the tool
cd subenum_cli

# Install dependencies
pip install -r requirements.txt

# Setup Nuclei (optional, for vulnerability scanning)
powershell -ExecutionPolicy Bypass -File setup_nuclei.ps1
```

## 🎯 Quick Start

### Basic Scan
```powershell
python main.py -d example.com
```

### Full Scan (All Features)
```powershell
python main.py -d example.com --recursive --ports --nuclei --axfr -o results.json
```

## 📖 Usage

### Command Line Options

```
Options:
  -d, --domain TEXT          Target domain (required)
  -c, --concurrency INTEGER  Concurrent workers (1-20, default: 10)
  --safe                     Quick scan with smaller wordlist
  -w, --wordlist PATH        Custom wordlist file
  -q, --quiet                Disable verbose output
  -o, --output PATH          Output file path
  -f, --format [json|csv|txt] Output format (default: json)
  --recursive                Enable recursive enumeration (2-level)
  --axfr                     Attempt DNS zone transfer
  --ports                    Scan common web ports
  --nuclei                   Run Nuclei vulnerability scanner
```

## 💡 Examples

### Bug Bounty Hunting
```powershell
# Comprehensive scan with all features
python main.py -d target.com --recursive --ports --nuclei -o findings.json

# Export to CSV for reporting
python main.py -d target.com --recursive -o report.csv -f csv
```

### Quick Reconnaissance
```powershell
# Fast scan with safe wordlist
python main.py -d example.com --safe --axfr -o quick.txt -f txt
```

### Custom Wordlist
```powershell
# Use your own wordlist
python main.py -d example.com -w /path/to/wordlist.txt --recursive
```

### High Concurrency
```powershell
# Maximum speed (20 workers)
python main.py -d example.com -c 20 --ports
```

## 🔍 Features Explained

### Recursive Enumeration (`--recursive`)
Discovers deep subdomains like `dev.api.example.com`:
- **Smart filtering**: Skips low-value targets (game servers, CDN nodes, random IDs)
- **Focuses on**: api, admin, dev, staging, vpn, portal, mail, auth
- **Performance**: Filters 793 → 50 high-value targets (15x faster)

### Port Scanning (`--ports`)
Checks for non-standard web services:
- Scans: 80, 443, 8080, 8443, 3000, 8000, 8888, 9000
- Async/fast scanning
- Boosts risk score for unusual ports

### Nuclei Scanning (`--nuclei`)
Automated vulnerability detection:
- **11,911 templates** included
- Checks for: CVEs, misconfigurations, exposed panels, default credentials
- Severity levels: CRITICAL, HIGH, MEDIUM, LOW

### DNS Zone Transfer (`--axfr`)
Attempts to exploit DNS misconfigurations:
- Tests all nameservers
- Can reveal all subdomains if server is misconfigured

## 📊 Output Formats

### JSON (Default)
```json
{
  "domain": "api.example.com",
  "ip": "1.2.3.4",
  "status": "LIVE",
  "http_status": 200,
  "title": "API Dashboard",
  "score": 8,
  "risk_reasons": ["API Endpoint", "Open ports: 8080"]
}
```

### CSV
```csv
Domain,IP,Status,HTTP Status,Title,Score,Risk Reasons
api.example.com,1.2.3.4,LIVE,200,API Dashboard,8,"API Endpoint, Open ports: 8080"
```

### TXT
```
api.example.com
admin.example.com
dev.example.com
```

## 🛡️ Security Features

- **Command Injection Protection**: All inputs validated (RFC 1035 compliant)
- **Path Traversal Prevention**: Wordlist paths validated
- **Private IP Filtering**: Prevents SSRF attacks
- **Wildcard Detection**: Multi-layer false positive filtering
- **Content Deduplication**: Smart fingerprinting

## ⚡ Performance

- **Concurrent scanning**: Up to 20 workers
- **HTTP rate limiting**: Prevents 429 errors
- **Smart filtering**: Skips low-value targets in recursive mode
- **Async operations**: Fast DNS resolution and HTTP probing

## 📁 Project Structure

```
subenum_cli/
├── bin/                    # Nuclei binary and templates
│   ├── nuclei.exe
│   └── nuclei-templates/
├── subenum/
│   ├── active/            # Active enumeration
│   │   ├── brute.py
│   │   ├── mutator.py
│   │   ├── scraper.py
│   │   ├── port_scanner.py
│   │   ├── nuclei_scanner.py
│   │   └── recursive_enum.py
│   ├── passive/           # Passive sources
│   │   ├── crtsh.py
│   │   ├── rapiddns.py
│   │   ├── axfr.py
│   │   └── ...
│   ├── resolve/           # DNS & HTTP
│   │   ├── resolver.py
│   │   └── prober.py
│   ├── analysis/          # Filtering & scoring
│   ├── output/            # Export modules
│   └── security.py        # Input validation
├── main.py                # CLI entry point
└── setup_nuclei.ps1       # Nuclei installer
```

## 🔧 Troubleshooting

### Nuclei Not Found
```powershell
# Run the setup script
powershell -ExecutionPolicy Bypass -File setup_nuclei.ps1
```

### Slow Recursive Scan
The tool automatically filters to high-value targets. If still slow:
```powershell
# Disable recursive mode
python main.py -d example.com --ports --nuclei
```

### Rate Limiting (429 Errors)
```powershell
# Reduce concurrency
python main.py -d example.com -c 5
```

## 📝 Tips

1. **Start with safe mode** (`--safe`) for quick reconnaissance
2. **Use recursive mode** (`--recursive`) for deep discovery
3. **Enable Nuclei** (`--nuclei`) for comprehensive security assessment
4. **Export to CSV** (`-f csv`) for easy reporting
5. **Combine flags** for maximum coverage

## 🎯 Comparison with Other Tools

| Feature | SubEnum | Subfinder | Amass | Assetfinder |
|---------|---------|-----------|-------|-------------|
| Passive Sources | ✅ | ✅ | ✅ | ✅ |
| Active Brute Force | ✅ | ❌ | ✅ | ❌ |
| Recursive Enumeration | ✅ | ❌ | ✅ | ❌ |
| Port Scanning | ✅ | ❌ | ❌ | ❌ |
| Nuclei Integration | ✅ | ❌ | ❌ | ❌ |
| Smart Filtering | ✅ | ✅ | ✅ | ❌ |
| Multiple Outputs | ✅ | ✅ | ✅ | ❌ |

## 📄 License

This tool is for educational and authorized security testing only.

## 🤝 Contributing

Contributions welcome! Please ensure all tests pass:
```powershell
python test_analysis.py
```

---

**Made with ❤️ for Bug Bounty Hunters and Security Researchers**
