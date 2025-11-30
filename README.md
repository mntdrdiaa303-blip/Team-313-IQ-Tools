# 🔍 DeepRecon - Team 313 IQ

**Advanced OSINT and Security Reconnaissance Tool**

A comprehensive Python-based command-line tool for gathering intelligence about domains and IP addresses, with integrated vulnerability assessment capabilities.

---

## 📋 Features

### 1. **DNS Reconnaissance**
- A records (IPv4 addresses)
- AAAA records (IPv6 addresses)
- MX records (mail servers)
- TXT records (includes SPF, DKIM, DMARC)
- NS records (nameservers)
- CNAME records
- SOA records

### 2. **WHOIS Information**
- Domain ownership details
- Registrant information
- Registrar details
- Creation and expiration dates
- Domain status
- Nameserver listing

### 3. **HTTP Reconnaissance**
- HTTP headers analysis
- Web server type detection (Apache, Nginx, IIS, etc.)
- Page title extraction
- Common sensitive files discovery (robots.txt, wp-admin, etc.)
- Server information gathering

### 4. **WAF/CDN Detection**
- Cloudflare
- AWS CloudFront
- Akamai
- Imperva/Incapsula
- ModSecurity
- F5 BIG-IP
- Barracuda
- Fortinet

### 5. **CMS Detection**
- WordPress
- Drupal
- Joomla
- Magento
- OpenCart
- PrestaShop
- Wix
- Squarespace
- Shopify

### 6. **SSL/TLS Certificate Analysis**
- Certificate information
- Issuer details
- Validity dates and expiration warnings
- Subject Alternative Names (SANs)
- SSL/TLS version detection
- Cipher suite analysis

### 7. **Port Scanning**
- Fast scanning of common ports
- Service identification
- Multithreaded implementation
- Common ports: FTP, SSH, DNS, HTTP, HTTPS, MySQL, RDP, PostgreSQL, etc.

### 8. **Security Assessment**
- CVE banner matching
- Security headers analysis
- XSS vulnerability testing (basic)
- SQL Injection detection (basic)
- Local File Inclusion detection (basic)

---

## 🛠️ Installation

### Prerequisites
- Python 3.7 or higher
- pip package manager

### Setup

1. **Clone or extract the project**
```bash
cd DeepRecon
```

2. **Install dependencies**
```bash
pip install -r requirements.txt
```

For Windows users with SSL certificate issues:
```bash
pip install --upgrade certifi
```

3. **Make script executable (Linux/Mac)**
```bash
chmod +x deeprecon.py
```

---

## 📦 Dependencies

```
requests>=2.28.0          # HTTP requests
dnspython>=2.3.0          # DNS queries
python-whois>=0.8.0       # WHOIS lookups
colorama>=0.4.6           # Colored CLI output
beautifulsoup4>=4.11.0    # HTML parsing
shodan>=1.28.0            # Shodan API (optional)
```

---

## 🚀 Usage

### Basic Scan (All Modules)
```bash
python deeprecon.py --target example.com
```

### Specific Module Scanning
```bash
# DNS only
python deeprecon.py --target example.com --dns

# HTTP only
python deeprecon.py --target example.com --http

# Port scanning only
python deeprecon.py --target example.com --ports

# Security checks only
python deeprecon.py --target example.com --security

# SSL analysis only
python deeprecon.py --target example.com --ssl

# WHOIS information only
python deeprecon.py --target example.com --whois
```

### Combining Multiple Modules
```bash
python deeprecon.py --target example.com --dns --http --ports
```

### Scanning IP Addresses
```bash
python deeprecon.py --target 8.8.8.8
python deeprecon.py --target 8.8.8.8 --ports --ssl
```

### Save Results to JSON
```bash
python deeprecon.py --target example.com --save results.json
```

### View Help
```bash
python deeprecon.py --help
```

---

## 📊 Example Output

```
╔═══════════════════════════════════════════════════════╗
║                 🔍 DeepRecon 🔍                       ║
║              Team 313 IQ OSINT Tool                   ║
║  Advanced Reconnaissance & Security Assessment        ║
║           Educational Use Only - Use Responsibly      ║
╚═══════════════════════════════════════════════════════╝

[*] Target type detected: domain
[*] Starting comprehensive reconnaissance on: example.com
[*] Timestamp: 2025-11-29 10:30:45

============================================================
📋 DNS RECONNAISSANCE
============================================================

>>> A Records (IPv4)
    [*] IPv4: 93.184.216.34

>>> MX Records (Mail Servers)
    [*] Priority 10: mail.example.com

>>> TXT Records
    [*] TXT: "v=spf1 include:_spf.google.com ~all"

[✓] DNS reconnaissance completed
```

---

## 🔐 Security Considerations

### ⚠️ Important Legal Notice
This tool is provided **EXCLUSIVELY** for authorized security testing and educational purposes.

**Unauthorized testing is ILLEGAL** and violates laws including:
- Computer Fraud and Abuse Act (CFAA) - USA
- Computer Misuse Act - UK
- Similar laws in most countries

### Best Practices
1. **Always obtain written authorization** before testing any target
2. Use only on systems you own or have explicit permission to test
3. Respect privacy and confidentiality
4. Document all testing activities
5. Use within ethical and legal boundaries

---

## 📁 Project Structure

```
DeepRecon/
├── deeprecon.py          # Main CLI application
├── utils.py              # Utility functions and formatting
├── dns_recon.py          # DNS reconnaissance module
├── http_recon.py         # HTTP reconnaissance module
├── ssl_recon.py          # SSL/TLS analysis module
├── whois_recon.py        # WHOIS information module
├── port_scanner.py       # Port scanning module
├── security_checks.py    # Security vulnerability checks
├── requirements.txt      # Python dependencies
└── README.md             # This file
```

---

## 🔧 Configuration

### Customizing Port Scan
Edit `port_scanner.py` and modify the `COMMON_PORTS` list:

```python
COMMON_PORTS = [
    21,    # FTP
    22,    # SSH
    80,    # HTTP
    443,   # HTTPS
    # Add more ports as needed
]
```

### Adding CMS Signatures
Edit `http_recon.py` and add to the `CMS_SIGNATURES` dictionary:

```python
CMS_SIGNATURES = {
    'custom_cms': ['signature1', 'signature2'],
    # ... existing entries
}
```

---

## 📝 Advanced Features

### JSON Output Format
Results saved with `--save` include:
- Target information
- Scan timestamp
- Results from all modules
- Structured data for integration with other tools

### Modular Architecture
Each reconnaissance module is independent:
- Easy to extend with new modules
- Can be imported separately for custom scripts
- Well-documented API for each module

---

## 🐛 Troubleshooting

### "SSL: CERTIFICATE_VERIFY_FAILED"
```bash
pip install --upgrade certifi
# Or use: python -m certifi
```

### DNS Resolution Fails
- Check your internet connection
- Verify the target domain exists
- Try with a different DNS server

### Port Scan Timeout
- Increase timeout value in `port_scanner.py`
- Reduce the number of concurrent threads
- Check firewall rules

### WHOIS Lookup Fails
- Some registrars block WHOIS queries
- Try with different target domains
- Check internet connection

---

## 📚 Additional Resources

- [OWASP OSINT Guide](https://owasp.org/)
- [DNS Record Types](https://www.iana.org/assignments/dns-parameters/)
- [SSL/TLS Best Practices](https://tools.ietf.org/html/rfc8446)
- [CVE Database](https://nvd.nist.gov/)

---

## 🤝 Contributing

To contribute improvements:
1. Create a new module following the existing pattern
2. Add it to the main `deeprecon.py` orchestrator
3. Update documentation

---

## 📄 License

Educational Use Only - Use Responsibly

---

## 👥 Team 313 IQ

**DeepRecon** is maintained by Team 313 IQ for educational and authorized security testing purposes.

---

## ⚡ Version

**DeepRecon v1.0.0** - November 2025

---

## 📞 Support

For issues or questions:
1. Check the README section above
2. Review error messages carefully
3. Verify internet connectivity
4. Ensure correct target format

---

**Remember: Use this tool responsibly and ethically. Unauthorized testing is illegal.**
