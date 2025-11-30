# 🚀 DeepRecon Quick Start Guide

## Installation (5 minutes)

### 1. Prerequisites Check
```bash
python --version  # Should be 3.7+
pip --version
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

**Expected output:**
```
Successfully installed requests dnspython python-whois colorama beautifulsoup4 shodan
```

---

## First Run

### Basic Example
```bash
python deeprecon.py --target google.com
```

### What You'll See
- Beautiful banner with Team 313 IQ logo
- Real-time scan progress
- Color-coded results:
  - 🟢 Green = Success
  - 🔵 Blue = Information
  - 🟡 Yellow = Warnings
  - 🔴 Red = Critical/Errors

---

## Common Scenarios

### Scenario 1: Quick Domain Overview
```bash
python deeprecon.py --target example.com --dns --http
```
**Time:** ~10 seconds
**Output:** DNS records and web server info

### Scenario 2: Find Open Ports
```bash
python deeprecon.py --target example.com --ports
```
**Time:** ~30 seconds
**Output:** List of open ports and services

### Scenario 3: Check SSL Certificate
```bash
python deeprecon.py --target example.com --ssl
```
**Time:** ~5 seconds
**Output:** Certificate details and expiration date

### Scenario 4: Full Comprehensive Scan
```bash
python deeprecon.py --target example.com --save report.json
```
**Time:** ~2-3 minutes
**Output:** Complete JSON report with all data

### Scenario 5: Security Assessment
```bash
python deeprecon.py --target example.com --security --http
```
**Time:** ~20 seconds
**Output:** Security vulnerabilities and missing headers

---

## File Structure After Installation

```
DeepRecon/
├── deeprecon.py              ← Main program (run this!)
├── requirements.txt          ← Dependencies list
├── README.md                 ← Full documentation
├── QUICKSTART.md             ← This file
│
├── utils.py                  ← CLI formatting & utilities
├── dns_recon.py              ← DNS analysis
├── http_recon.py             ← Web server detection
├── ssl_recon.py              ← SSL certificate info
├── whois_recon.py            ← Domain registration data
├── port_scanner.py           ← Port scanning
└── security_checks.py        ← Vulnerability checks
```

---

## Command Syntax

### Format
```
python deeprecon.py --target <domain_or_ip> [options]
```

### Essential Options
| Option | Short | Purpose |
|--------|-------|---------|
| `--target TARGET` | `-t` | **Required** - Domain or IP to scan |
| `--dns` | | Run DNS reconnaissance |
| `--http` | | Run HTTP analysis |
| `--ports` | `-p` | Port scanning |
| `--ssl` | | SSL certificate analysis |
| `--whois` | | WHOIS domain info |
| `--security` | `-s` | Security vulnerability checks |
| `--save FILE` | `-o` | Save results to JSON |
| `--help` | `-h` | Show all options |
| `--version` | `-v` | Show version |

---

## Tips & Tricks

### 💡 Tip 1: Combine Multiple Modules
```bash
python deeprecon.py --target example.com --dns --http --ports --ssl
```

### 💡 Tip 2: Save for Later Analysis
```bash
python deeprecon.py --target example.com --save results_$(date +%Y%m%d).json
```

### 💡 Tip 3: Quick Security Check
```bash
python deeprecon.py --target example.com --security --http
```

### 💡 Tip 4: Background Scan (Linux/Mac)
```bash
nohup python deeprecon.py --target example.com --save results.json &
```

### 💡 Tip 5: Scan Multiple Domains
```bash
for domain in example.com test.org sample.net; do
  python deeprecon.py --target $domain --save ${domain}.json
done
```

---

## Expected Results Summary

### DNS Module
- IPv4 and IPv6 addresses
- Mail servers (MX records)
- Nameservers
- SPF/DKIM records (TXT)

### HTTP Module
- Server type (Apache, Nginx, IIS, etc.)
- WAF/CDN detection
- CMS identification
- Common sensitive files

### SSL Module
- Certificate validity
- Expiration date
- Issuer information
- SSL/TLS version

### Port Module
- List of open ports
- Associated services
- Total ports found

### Security Module
- CVE matches from banner
- Missing security headers
- Potential vulnerabilities

### WHOIS Module
- Domain owner
- Registration dates
- Nameserver list
- Domain status

---

## Troubleshooting

### ❌ "Module not found"
```bash
# Make sure you're in the DeepRecon directory
cd DeepRecon
python deeprecon.py --target example.com
```

### ❌ "SSL Certificate Error"
```bash
pip install --upgrade certifi
```

### ❌ "Connection timeout"
- Check internet connection
- Target might be down or blocking
- Try a different domain

### ❌ "Permission denied"
```bash
# Windows: Run Command Prompt as Administrator
# Linux/Mac: Add execute permission
chmod +x deeprecon.py
```

---

## Output Examples

### Successful DNS Lookup
```
>>> A Records (IPv4)
    [*] IPv4: 93.184.216.34

>>> MX Records (Mail Servers)
    [*] Priority 10: mail.example.com
```

### Server Detection
```
>>> Web Server Detection
    [*] Server: nginx/1.18.0
    [✓] Detected: Nginx
```

### Security Alert
```
>>> Security Headers Analysis
    [✓] X-Content-Type-Options is present
    [!] X-Frame-Options is MISSING
    [!] Strict-Transport-Security is MISSING
```

---

## Next Steps

1. **Read Full Documentation**: `README.md`
2. **Explore Modules**: Open individual `.py` files to understand structure
3. **Customize**: Add your own reconnaissance modules
4. **Integrate**: Use with other security tools
5. **Learn**: Study the code and expand functionality

---

## Legal Reminder

⚠️ **This tool is for AUTHORIZED testing only**

- Only test systems you own or have written permission to test
- Unauthorized access is ILLEGAL
- Violates Computer Fraud and Abuse Act (CFAA) and similar laws
- Always obtain proper authorization before use

---

## Quick Reference Card

```bash
# Show help
python deeprecon.py --help

# DNS only
python deeprecon.py -t example.com --dns

# Everything
python deeprecon.py -t example.com

# Save results
python deeprecon.py -t example.com -o scan.json

# Specific scans
python deeprecon.py -t example.com --http --ports

# Security focus
python deeprecon.py -t example.com --security
```

---

**Happy Reconnaissance! 🎯**

*Team 313 IQ*
