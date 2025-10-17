# ac-lk-network-audit

A comprehensive subdomain enumeration and security audit toolkit for network reconnaissance and security assessment.

## 📋 Table of Contents
- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage Guide](#usage-guide)
- [Security Audit Workflow](#security-audit-workflow)
- [Output Files](#output-files)
- [Repository Feedback](#repository-feedback)

## 🔍 Overview

This repository provides a suite of Python tools for:
- **Subdomain enumeration** using passive (crt.sh) and active (DNS probing) techniques
- **Host auditing** to collect HTTP headers, server information, and technology fingerprints
- **Security checklist generation** with comprehensive DNS, WHOIS, and security assessment data

## 🛠️ Prerequisites

Before running the scripts, ensure you have:

- **Python 3.8+** (preferably in a virtual environment)
- **pip** package manager
- **dig** command-line tool (for DNS lookups)
- **whois** command-line tool (for domain registration info)

### Verify Prerequisites

```bash
python --version  # Should be 3.8 or higher
dig -v           # Should display ISC BIND version
whois --version  # Should display whois version
```

## 📦 Installation

1. **Clone the repository** (if not already done):
```bash
cd /path/to/ac-lk-network-audit
```

2. **Create a virtual environment** (recommended):
```bash
python -m venv venv
source venv/bin/activate  # On macOS/Linux
```

3. **Install Python dependencies**:
```bash
pip install -r requirements.txt
```

This installs:
- `requests` - For HTTP requests and API calls
- `pandas` - For data manipulation and CSV/Excel output
- `openpyxl` - For Excel file generation

## 🚀 Usage Guide

### Step 1: Subdomain Enumeration

Run the subdomain enumerator to discover and classify subdomains:

```bash
python subdomain_enumerator.py
```

**What it does:**
- Queries crt.sh (Certificate Transparency logs) for passive subdomain discovery
- Probes common subdomain names (www, mail, api, dev, etc.)
- Tests DNS resolution for discovered hosts
- Checks HTTP/HTTPS availability
- Classifies subdomains into categories

**Configuration:**
- Edit the `domain` variable in the `main()` function of `subdomain_enumerator.py` to change the target domain
- Default: `domain = "oeducat.org"`

**Output files:**
- `<domain>_all.txt` - All discovered subdomains
- `<domain>_active.txt` - Subdomains responding to HTTP/HTTPS
- `<domain>_created_not_active.txt` - Discovered but not active subdomains

**Alternative:** You can also use `subdomain_handler.py` (duplicate functionality).

### Step 2: Subdomain Auditing

Perform detailed auditing of active subdomains:

```bash
python subdomain_audit.py oeducat.org
```

Or specify the active file directly:

```bash
python subdomain_audit.py oeducat.org_active.txt
```

**What it does:**
- Reads active subdomains from `<domain>_active.txt`
- Resolves IP addresses (A/AAAA records)
- Probes HTTP/HTTPS endpoints
- Extracts server headers (Server, X-Powered-By)
- Captures page titles
- Detects common technologies (WordPress, Shopify, Cloudflare, etc.)

**Output files:**
- `<domain>_audit.csv` - Audit results in CSV format
- `<domain>_audit.xlsx` - Excel format (if openpyxl installed)

### Step 3: Security Checklist Generation

Build a comprehensive security assessment spreadsheet:

```bash
python build_security_checklist.py oeducat.org_audit.csv
```

**What it does:**
- Reads audit CSV from Step 2
- Performs DNS lookups (A, AAAA, CNAME, MX, TXT, NS, SOA, PTR, CAA records)
- Retrieves WHOIS information (registrar, creation/expiration dates)
- Identifies hosting provider and ASN
- Detects CDN/WAF services
- Prepares columns for manual security testing (TLS, headers, ports, etc.)

**Output files:**
- `<domain>_security_checklist.xlsx` - Comprehensive security checklist

## 🔐 Security Audit Workflow

Follow this order for a complete security audit:

```
┌─────────────────────────────────────────────────────────────────┐
│                    STEP 1: ENUMERATION                          │
│  python subdomain_enumerator.py                                 │
│  → Discovers all subdomains                                     │
│  → Classifies by activity status                                │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│                    STEP 2: AUDITING                             │
│  python subdomain_audit.py oeducat.org                          │
│  → Collects HTTP/HTTPS information                              │
│  → Identifies technologies and servers                          │
│  → Resolves IP addresses                                        │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│                    STEP 3: SECURITY CHECKLIST                   │
│  python build_security_checklist.py oeducat.org_audit.csv      │
│  → Performs comprehensive DNS analysis                          │
│  → Retrieves WHOIS and hosting info                             │
│  → Generates security assessment spreadsheet                    │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│                    STEP 4: MANUAL REVIEW                        │
│  Review the security checklist Excel file and:                  │
│  • Test SSL/TLS configuration (sslyze, testssl.sh)              │
│  • Scan for open ports (nmap)                                   │
│  • Check security headers (securityheaders.com)                 │
│  • Test for vulnerabilities (OWASP ZAP, Burp Suite)             │
│  • Verify WAF/CDN configuration                                 │
│  • Check for subdomain takeover risks                           │
└─────────────────────────────────────────────────────────────────┘
```

### Recommended Audit Order

1. **Reconnaissance Phase** (Step 1)
   - Discover all subdomains
   - Identify attack surface

2. **Information Gathering** (Step 2)
   - Collect technical details
   - Identify technologies and versions

3. **Assessment Preparation** (Step 3)
   - Build comprehensive asset inventory
   - Prepare structured checklist

4. **Security Testing** (Manual)
   - TLS/SSL analysis
   - Port scanning
   - Vulnerability assessment
   - Configuration review

## 📊 Output Files

| File | Description | Generated By |
|------|-------------|--------------|
| `<domain>_all.txt` | All discovered subdomains | subdomain_enumerator.py |
| `<domain>_active.txt` | HTTP/HTTPS active subdomains | subdomain_enumerator.py |
| `<domain>_created_not_active.txt` | Inactive subdomains | subdomain_enumerator.py |
| `<domain>_audit.csv` | Detailed audit data (CSV) | subdomain_audit.py |
| `<domain>_audit.xlsx` | Detailed audit data (Excel) | subdomain_audit.py |
| `<domain>_security_checklist.xlsx` | Comprehensive security checklist | build_security_checklist.py |

## 📝 Repository Feedback

### ✅ Strengths

1. **Well-structured workflow**: Clear progression from enumeration → audit → checklist
2. **Comprehensive documentation**: Good inline comments and docstrings in Python files
3. **Multiple output formats**: CSV and Excel for flexibility
4. **Concurrent execution**: Uses ThreadPoolExecutor for efficient parallel processing
5. **Error handling**: Graceful handling of timeouts and failures
6. **Technology detection**: Basic fingerprinting for common platforms
7. **Multi-source enumeration**: Combines passive (crt.sh) and active (DNS) techniques

### 🔧 Areas for Improvement

1. **Configuration Management**
   - Currently requires editing Python files to change the target domain
   - **Recommendation**: Use command-line arguments or configuration files
   ```python
   # Example improvement:
   import argparse
   parser = argparse.ArgumentParser()
   parser.add_argument('domain', help='Target domain to scan')
   args = parser.parse_args()
   ```

2. **Code Duplication**
   - `subdomain_enumerator.py` and `subdomain_handler.py` appear to be duplicates
   - **Recommendation**: Remove duplicate file or clarify purpose

3. **Rate Limiting**
   - No rate limiting for HTTP requests
   - **Recommendation**: Add delays or respect rate limits to avoid overwhelming targets

4. **TLS/SSL Analysis**
   - Security checklist has placeholders for SSL/TLS info
   - **Recommendation**: Integrate `sslyze` or `ssl` module for certificate analysis

5. **Logging**
   - Limited logging for debugging
   - **Recommendation**: Implement Python logging module with different verbosity levels

6. **Testing**
   - No unit tests present
   - **Recommendation**: Add tests for core functions

7. **Security Headers Check**
   - Placeholders exist but not implemented
   - **Recommendation**: Add checks for CSP, HSTS, X-Frame-Options, etc.

8. **Subdomain Takeover Detection**
   - Mentioned but not implemented
   - **Recommendation**: Add CNAME validation against known vulnerable services

### 🎯 Suggested Enhancements

1. Add JSON output format for easier integration with other tools
2. Implement retry logic with exponential backoff for API calls
3. Add progress bars (using `tqdm`) for long-running operations
4. Create a unified CLI with subcommands (using `click` or `argparse`)
5. Add Docker support for easy deployment
6. Implement database storage option (SQLite) for historical tracking
7. Add report generation with executive summary

### ⚠️ Security Considerations

- **Authorization Required**: Only scan domains you own or have explicit permission to test
- **Legal Compliance**: Port scanning and enumeration may be illegal without authorization
- **Rate Limits**: Be respectful of third-party services (crt.sh, DNS servers)
- **Data Privacy**: Handle collected data responsibly and securely

### 📈 Overall Assessment

**Score: 7.5/10**

This is a **solid, functional security audit toolkit** with clear documentation and practical utility. The code is well-organized with good separation of concerns. It's particularly useful for:
- Security professionals conducting authorized assessments
- System administrators managing large domain portfolios
- DevOps teams performing infrastructure audits

The main improvements needed are around configurability, completeness of security checks, and eliminating code duplication. With the suggested enhancements, this could easily become a production-ready enterprise tool.

## 📄 License & Ethics

**⚠️ IMPORTANT**: This tool is for authorized security testing only. Unauthorized scanning may violate:
- Computer Fraud and Abuse Act (CFAA)
- Computer Misuse Act
- Local cybersecurity laws

Always obtain written permission before scanning networks or systems you don't own.

## 🤝 Contributing

Contributions are welcome! Consider implementing any of the suggested improvements above.

---

**Last Updated**: October 2025

