# Subdomain Security Scanner & Auditor

**Universal Comprehensive Subdomain Security Assessment Toolkit**

A Python toolkit for subdomain enumeration and comprehensive security assessment of any domain, featuring automated 20-item security checklist, weighted scoring (0-100), and ranked Excel reports. Works with any TLD (.com, .org, .edu, .gov, .ac.lk, etc.).

---

## 📋 Table of Contents
- [Overview](#overview)
- [Features](#features)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Detailed Usage](#detailed-usage)
- [Security Checklist](#security-checklist)
- [Scoring Methodology](#scoring-methodology)
- [Output Files](#output-files)
- [Research Use Cases](#research-use-cases)
- [Troubleshooting](#troubleshooting)
- [Ethical Considerations](#ethical-considerations)
- [Contributing](#contributing)

---

## 🔍 Overview

This repository provides two Python scripts for comprehensive subdomain security assessment:

1. **`subdomain_handler.py`** - Subdomain enumeration using passive (crt.sh) and active (DNS) techniques
2. **`security_scanner.py`** - Universal 20-item security checklist scanner with weighted scoring

**Use Cases:**
- 🔒 Security auditing of any domain or subdomain set
- 🏢 Enterprise security posture assessment
- 🎓 Educational institution cybersecurity research
- 📊 Comparative security analysis across multiple domains
- 📈 Compliance benchmarking and scoring
- 🌐 Multi-domain security audits for any TLD

---

## ✨ Features

### Subdomain Enumeration
- ✅ Passive discovery via Certificate Transparency (crt.sh)
- ✅ Active DNS probing of common subdomains
- ✅ HTTP/HTTPS availability testing
- ✅ Classification (all/active/created-but-not-active)


### Security Assessment (106-Parameter Dynamic Checklist)
- ✅ **Comprehensive 106-parameter checklist** covering TLS, headers, authentication, input validation, access control, API, cloud, DNS, logging, compliance, and more
- ✅ **Context-aware scanning**: Each subdomain is classified (webapp, API, static, other) and only relevant checks are applied
- ✅ **Dynamic scoring**: Only applicable checks are scored for each subdomain, with clear pass/fail and context-aware total
- ✅ **Excel Export** with all relevant checks, subdomain type, and summary by type

### Ethical & Research-Friendly
- ✅ Rate-limiting (3s per request) to prevent DoS
- ✅ Passive scanning (no exploitation attempts)
- ✅ Graceful error handling
- ✅ Detailed progress reporting
- ✅ Statistical summary output

---

## 🛠️ Prerequisites

**System Requirements:**
- Python 3.8 or higher
- Internet connection (for scanning and crt.sh queries)

**Optional (for subdomain_handler.py):**
- `dig` command (DNS lookups) - usually pre-installed on macOS/Linux
- `whois` command (domain info) - usually pre-installed on macOS/Linux

**Verify Prerequisites:**
```bash
python3 --version  # Should show 3.8+
```

---

## 📦 Installation

### 1. Clone the Repository
```bash
git clone https://github.com/LalithK90/ac-lk-network-audit.git
cd ac-lk-network-audit
```

### 2. Create Virtual Environment (Recommended)
```bash
python3 -m venv venv
source venv/bin/activate  # On macOS/Linux
# venv\Scripts\activate  # On Windows
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

**Dependencies installed:**
- `requests` - HTTP requests
- `pandas` - Data manipulation & Excel
- `openpyxl` - Excel file generation
- `sslyze` - TLS/certificate analysis
- `dnspython` - DNS validation
- `beautifulsoup4` - HTML parsing
- `tqdm` - Progress bars

---

## 🚀 Quick Start

### 3-Step Workflow

```bash
# Step 1: Enumerate subdomains for your target domain (edit domain in script first)
python subdomain_handler.py
# Example output: example.com_active.txt

# Step 2: Run security scanner on discovered subdomains
python security_scanner.py --file example.com_active.txt
# Output: website_ranking.xlsx

# Step 3: Open website_ranking.xlsx and analyze results!
```

**Note:** The scanner works with `.txt` or `.xlsx` files containing subdomains from **any domain** (.com, .org, .edu, .gov, etc.)

---

## 📖 Detailed Usage

### Part 1: Subdomain Enumeration

**File:** `subdomain_handler.py`

**Configuration:**
Edit the script and set your target domain:
```python
def main():
    domain = "example.com"  # Change to your target domain
    # Examples: "example.com", "university.edu", "company.org", etc.
```

**Run:**
```bash
python subdomain_handler.py
```

**Output Files:**
- `<domain>_all.txt` - All discovered subdomains
- `<domain>_active.txt` - HTTP/HTTPS responsive subdomains ✅
- `<domain>_created_not_active.txt` - Discovered but inactive

**What it does:**
1. Queries crt.sh for SSL certificate history
2. Probes common subdomains (www, mail, api, dev, portal, etc.)
3. Tests DNS resolution for each subdomain
4. Checks HTTP/HTTPS availability
5. Classifies subdomains by status

---

### Part 2: Security Scanner

**File:** `security_scanner.py`

**Usage Options:**

```bash
# Option 1: Scan subdomains from TXT file
python security_scanner.py --file example.com_active.txt

# Option 2: Interactive mode (prompts for file selection)
python security_scanner.py

# Option 3: Custom output filename
python security_scanner.py --file domains.txt --output security_report.xlsx

# Option 4: Works with any domain list
python security_scanner.py --file company_subdomains.xlsx
```

**Supported Input Formats:**
- `.txt` files (one subdomain per line) - e.g., portal.example.com
- `.xlsx` files (must have 'Subdomain' column)

**What it does:**
1. Loads subdomains from input file
2. For each subdomain:
   - Tests 20 security controls (see checklist below)
   - Uses sslyze for TLS/certificate analysis
   - Uses dnspython for DNS checks
   - Checks HTTP headers and configuration
3. Computes weighted scores per category
4. Ranks subdomains by total score
5. Exports comprehensive Excel report

**Performance:**
- **Rate limit:** 3 seconds per subdomain (ethical)
- **100 subdomains:** ~5 minutes
- **1000 subdomains:** ~50 minutes

**Console Output Example:**
```
[1/32] portal.example.com
  Score: 87.50/100 | H:4/4 M:7/8 L:6/8

[2/32] www.example.com
  Score: 72.30/100 | H:3/4 M:6/8 L:5/8
```

---


## 🔐 Security Checklist

### www and non-www Checks

The scanner automatically tests both `www.example.com` and `example.com` for each subdomain, recording results for both if they resolve. This ensures you know if a domain is only secure (or only available) with or without the `www` prefix.

### 106-Parameter Security Assessment Table

Below is the **complete table** of all 106 security parameters, including IDs, priorities, descriptions, feasibility with this stack, reference/standard, and direct links to resources:

| # | Main Section | ID | Priority | Description | Feasible? | Reference/Standard | Link |
|---|--------------|-----|----------|-------------|-----------|-------------------|------|
| 1 | TLS & Certificate Security | TLS-1 | High | TLS 1.2+ enforced | ✅ (sslyze) | OWASP TLS Cheat Sheet | [Link](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html) |
| 2 | | CERT-1 | High | Valid cert chain | ✅ (sslyze) | RFC 5280 (X.509) | [Link](https://tools.ietf.org/html/rfc5280) |
| 3 | | FS-1 | Medium | Forward secrecy (ECDHE ciphers) | ✅ (sslyze) | OWASP TLS Cheat Sheet | [Link](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html) |
| 4 | | WC-1 | Medium | No weak ciphers (RC4/3DES) | ✅ (sslyze) | NIST SP 800-52r2 | [Link](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-52r2.pdf) |
| 5 | | TLS-2 | Medium | OCSP stapling enabled | ✅ (sslyze) | RFC 6960 (OCSP) | [Link](https://tools.ietf.org/html/rfc6960) |
| 6 | | CERT-2 | Medium | Certificate transparency compliance | ✅ (sslyze) | RFC 6962 | [Link](https://tools.ietf.org/html/rfc6962) |
| 7 | | HSTS-2 | High | HSTS preload directive enabled | ✅ (requests) | OWASP HSTS Cheat Sheet | [Link](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html) |
| 8 | HTTP Headers & Protocols | HTTPS-1 | High | HTTPS enforced (HTTP → HTTPS redirect) | ✅ (requests) | OWASP HTTPS Cheat Sheet | [Link](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html) |
| 9 | | HSTS-1 | High | HSTS max-age ≥31536000 + includeSubDomains | ✅ (requests) | RFC 6797 (HSTS) | [Link](https://tools.ietf.org/html/rfc6797) |
| 10 | | CSP-1 | Medium | CSP present (non-empty) | ✅ (requests) | OWASP CSP Cheat Sheet | [Link](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html) |
| 11 | | XFO-1 | Medium | X-Frame-Options: DENY/SAMEORIGIN | ✅ (requests) | OWASP Clickjacking Cheat Sheet | [Link](https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html) |
| 12 | | XCTO-1 | Medium | X-Content-Type-Options: nosniff | ✅ (requests) | OWASP Header Cheat Sheet | [Link](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html) |
| 13 | | XXP-1 | Medium | X-XSS-Protection: 1; mode=block | ✅ (requests) | OWASP XSS Cheat Sheet | [Link](https://cheatsheetseries.owasp.org/cheatsheets/XSS_Prevention_Cheat_Sheet.html) |
| 14 | | RP-1 | Medium | Referrer-Policy: strict-origin-when-cross-origin or stricter | ✅ (requests) | W3C Referrer Policy | [Link](https://w3c.github.io/webappsec-referrer-policy/) |
| 15 | | PP-1 | Medium | Permissions-Policy present (non-empty) | ✅ (requests) | W3C Permissions Policy | [Link](https://w3c.github.io/webappsec-permissions-policy/) |
| 16 | | HEADER-1 | Low | Clear-Site-Data header present | ✅ (requests) | W3C Clear-Site-Data | [Link](https://w3c.github.io/webappsec-clear-site-data/) |
| 17 | | HEADER-2 | Medium | Cross-Origin-Opener-Policy: same-origin | ✅ (requests) | W3C COOP | [Link](https://html.spec.whatwg.org/multipage/origin.html#cross-origin-opener-policy) |
| 18 | | HEADER-3 | Medium | Cross-Origin-Embedder-Policy: require-corp | ✅ (requests) | W3C COEP | [Link](https://html.spec.whatwg.org/multipage/origin.html#cross-origin-embedder-policy) |
| 19 | | CORS-1 | Medium | Restrictive CORS (Access-Control-Allow-Origin ≠ "*") | ✅ (requests) | OWASP CORS Cheat Sheet | [Link](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html) |
| 20 | | WAF-1 | Medium | WAF presence (e.g., X-WAF/Cloudflare headers) | ✅ (requests) | OWASP WAF Cheat Sheet | [Link](https://cheatsheetseries.owasp.org/cheatsheets/Web_Application_Firewall_Cheat_Sheet.html) |
| 21 | | REPORT-1 | Low | Report-To header for security reports | ✅ (requests) | W3C Reporting API | [Link](https://w3c.github.io/reporting/) |
| 22 | | HEADER-5 | Medium | Cross-Origin-Resource-Policy: same-site | ✅ (requests) | W3C CORP | [Link](https://fetch.spec.whatwg.org/#cross-origin-resource-policy-header) |
| 23 | | HEADER-6 | Low | Remove Server/X-Powered-By headers | ✅ (requests) | OWASP Header Cheat Sheet | [Link](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html) |
| 24 | Authentication & Session Management | COO-1 | Low | Cookies Secure/HttpOnly | ✅ (requests) | OWASP Session Management Cheat Sheet | [Link](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html) |
| 25 | | AUTH-1 | High | Session timeout ≤30 minutes | ⚠️ (requests + timing) | OWASP Session Management Cheat Sheet | [Link](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html) |
| 26 | | AUTH-2 | High | CSRF tokens on state-changing operations | ✅ (requests + bs4) | OWASP CSRF Cheat Sheet | [Link](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html) |
| 27 | | AUTH-3 | Medium | No autocomplete on password fields | ✅ (requests + bs4) | OWASP Authentication Cheat Sheet | [Link](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html) |
| 28 | | SESSION-1 | Medium | Session cookie regenerated on login | ⚠️ (requests + session) | OWASP Session Management Cheat Sheet | [Link](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html) |
| 29 | | SAMESITE-1 | Medium | Cookies with SameSite=Lax/Strict | ✅ (requests) | OWASP SameSite Cookie Cheat Sheet | [Link](https://cheatsheetseries.owasp.org/cheatsheets/SameSite_Cookie_Cheat_Sheet.html) |
| 30 | | AUTH-4 | High | Multi-Factor Authentication (MFA) for privileged accounts | ⚠️ (requests + auth flow) | OWASP MFA Cheat Sheet | [Link](https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html) |
| 31 | | AUTH-5 | High | Account lockout/exponential backoff on failed logins | ⚠️ (requests + auth flow) | OWASP Authentication Cheat Sheet | [Link](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html) |
| 32 | | AUTH-6 | Medium | No username enumeration in login errors | ✅ (requests) | OWASP Authentication Cheat Sheet | [Link](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html) |
| 33 | | AUTH-7 | Medium | Password policy: complexity, rotation, or passkey support | ⚠️ (policy review) | NIST SP 800-63B | [Link](https://pages.nist.gov/800-63-3/sp800-63b.html) |
| 34 | Input Validation & Sanitization | INPUT-1 | High | SQL injection protection | ⚠️ (basic payload testing) | OWASP SQL Injection Cheat Sheet | [Link](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html) |
| 35 | | INPUT-2 | High | XSS protection (reflects user input safely) | ⚠️ (basic XSS testing) | OWASP XSS Prevention Cheat Sheet | [Link](https://cheatsheetseries.owasp.org/cheatsheets/XSS_Prevention_Cheat_Sheet.html) |
| 36 | | INPUT-3 | Medium | File upload restrictions | ⚠️ (if upload forms detected) | OWASP File Upload Cheat Sheet | [Link](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html) |
| 37 | | INPUT-4 | Medium | Path traversal prevention | ⚠️ (basic path testing) | OWASP Path Traversal Cheat Sheet | [Link](https://cheatsheetseries.owasp.org/cheatsheets/Path_Traversal_Cheat_Sheet.html) |
| 38 | | INPUT-5 | High | OS/Command injection protection | ⚠️ (payload testing) | OWASP Command Injection Cheat Sheet | [Link](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html) |
| 39 | | INPUT-6 | High | LDAP/NoSQL/Template injection protection | ⚠️ (payload testing) | OWASP Injection Prevention Cheat Sheet | [Link](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html) |
| 40 | | INPUT-7 | High | SSRF protection | ⚠️ (URL parameter testing) | OWASP SSRF Cheat Sheet | [Link](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html) |
| 41 | | INPUT-8 | Medium | File upload malware scanning and execution prevention | ⚠️ (file handling) | OWASP File Upload Cheat Sheet | [Link](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html) |
| 42 | | INPUT-9 | Medium | Deserialization security | ⚠️ (code review) | OWASP Deserialization Cheat Sheet | [Link](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html) |
| 43 | Access Control & Authorization | AUTHZ-1 | High | Access control (vertical privilege escalation) | ⚠️ (if multiple roles) | OWASP Access Control Cheat Sheet | [Link](https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html) |
| 44 | | AUTHZ-2 | High | IDOR protection | ⚠️ (parameter manipulation) | OWASP IDOR Cheat Sheet | [Link](https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html) |
| 45 | | AUTHZ-3 | High | Least privilege and RBAC enforcement | ⚠️ (role testing) | OWASP Access Control Cheat Sheet | [Link](https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html) |
| 46 | | AUTHZ-4 | High | Authorization checks on every request | ⚠️ (API/endpoint testing) | OWASP Access Control Cheat Sheet | [Link](https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html) |
| 47 | | AUTHZ-5 | High | IDOR and privilege escalation testing | ⚠️ (parameter manipulation) | OWASP IDOR Cheat Sheet | [Link](https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html) |
| 48 | | AUTHZ-6 | Medium | Business logic flaw testing | ⚠️ (flow testing) | OWASP Business Logic Cheat Sheet | [Link](https://cheatsheetseries.owasp.org/cheatsheets/Business_Logic_Security_Cheat_Sheet.html) |
| 49 | Security Headers & Browser Policies | HEADER-7 | Medium | Strict CSP (no unsafe-inline/unsafe-eval, all resource types) | ✅ (requests) | OWASP CSP Cheat Sheet | [Link](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html) |
| 50 | Encryption & Data Protection | ENCRYPT-1 | High | Encryption at rest for sensitive data | ⚠️ (infrastructure review) | NIST SP 800-175B | [Link](https://csrc.nist.gov/publications/detail/sp/800-175b/final) |
| 51 | | ENCRYPT-2 | Medium | Secure key management (no hard-coded keys) | ⚠️ (code review) | OWASP Cryptographic Storage Cheat Sheet | [Link](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html) |
| 52 | Logging, Monitoring & Incident Response | LOG-1 | Low | Security logging presence | ⚠️ (check for log endpoints) | OWASP Logging Cheat Sheet | [Link](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html) |
| 53 | | LOG-2 | High | Comprehensive logging (auth, data access, admin actions) | ⚠️ (log review) | OWASP Logging Cheat Sheet | [Link](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html) |
| 54 | | LOG-3 | Medium | Intrusion detection and anomaly monitoring | ⚠️ (SIEM/IDS setup) | NIST SP 800-92 | [Link](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-92.pdf) |
| 55 | | LOG-4 | Medium | Error handling (no stack traces exposed, logs sanitized) | ✅ (requests) | OWASP Error Handling Cheat Sheet | [Link](https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html) |
| 56 | Cloud & Infrastructure Security | CLOUD-1 | High | Secure IAM roles and least privilege | ⚠️ (cloud review) | CIS AWS Foundations Benchmark | [Link](https://www.cisecurity.org/benchmark/amazon_web_services/) |
| 57 | | CLOUD-2 | Medium | Private subnets for databases, encrypted storage | ⚠️ (cloud review) | CIS Azure Foundations Benchmark | [Link](https://www.cisecurity.org/benchmark/microsoft_azure/) |
| 58 | | CLOUD-3 | Medium | Container/VM security (non-root, patched, scanned) | ⚠️ (infrastructure review) | OWASP Container Security Cheat Sheet | [Link](https://cheatsheetseries.owasp.org/cheatsheets/Container_Security_Cheat_Sheet.html) |
| 59 | Email & DNS Security | DNS-1 | Low | DNSSEC (DS records) | ✅ (dnspython) | RFC 4033 (DNSSEC) | [Link](https://tools.ietf.org/html/rfc4033) |
| 60 | | SPF-1 | Low | SPF TXT record | ✅ (dnspython) | RFC 7208 (SPF) | [Link](https://tools.ietf.org/html/rfc7208) |
| 61 | | DMARC-1 | Low | DMARC TXT record exists | ✅ (dnspython) | RFC 7489 (DMARC) | [Link](https://tools.ietf.org/html/rfc7489) |
| 62 | | DNS-2 | Low | CAA record present | ✅ (dnspython) | RFC 8659 (CAA) | [Link](https://tools.ietf.org/html/rfc8659) |
| 63 | | MX-1 | Low | MX record configuration | ✅ (dnspython) | RFC 1035 (DNS) | [Link](https://tools.ietf.org/html/rfc1035) |
| 64 | | DNS-3 | Medium | DKIM signing enabled | ✅ (dnspython) | RFC 6376 (DKIM) | [Link](https://tools.ietf.org/html/rfc6376) |
| 65 | | DNS-4 | Medium | DMARC policy set to p=quarantine/reject | ✅ (dnspython) | RFC 7489 (DMARC) | [Link](https://tools.ietf.org/html/rfc7489) |
| 66 | File & Directory Security | DIR-1 | Medium | No directory listing | ✅ (requests) | OWASP Directory Listing Prevention | [Link](https://cheatsheetseries.owasp.org/) |
| 67 | | ADMIN-1 | Medium | No exposed common admin paths | ✅ (requests) | OWASP Admin Interface Security | [Link](https://cheatsheetseries.owasp.org/) |
| 68 | | ROBOTS-1 | Low | /robots.txt does not expose sensitive paths | ✅ (requests) | OWASP Robots.txt Security | [Link](https://cheatsheetseries.owasp.org/) |
| 69 | | SEC-1 | Low | /.well-known/security.txt exists | ✅ (requests) | RFC 9116 (security.txt) | [Link](https://tools.ietf.org/html/rfc9116) |
| 70 | | BACKUP-1 | Medium | No backup files exposed (.bak, .old, .tmp) | ✅ (requests) | OWASP Backup File Exposure Prevention | [Link](https://cheatsheetseries.owasp.org/) |
| 71 | | GIT-1 | High | No .git directory exposed | ✅ (requests) | OWASP Git Exposure Prevention | [Link](https://cheatsheetseries.owasp.org/) |
| 72 | | CONFIG-1 | High | No config files exposed (.env, config.json) | ✅ (requests) | OWASP Config File Exposure Prevention | [Link](https://cheatsheetseries.owasp.org/) |
| 73 | Information Disclosure | SI-1 | Low | No server info leakage | ✅ (requests) | OWASP Information Leakage Prevention | [Link](https://cheatsheetseries.owasp.org/) |
| 74 | | TITLE-1 | Low | Page title not default | ✅ (requests + bs4) | OWASP Default Page Security | [Link](https://cheatsheetseries.owasp.org/) |
| 75 | | ETag-1 | Low | ETag not timestamp-based | ✅ (requests) | OWASP ETag Security | [Link](https://cheatsheetseries.owasp.org/) |
| 76 | | ERROR-1 | Medium | No stack traces in error pages | ✅ (requests) | OWASP Error Handling Cheat Sheet | [Link](https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html) |
| 77 | | HEADER-4 | Low | No version disclosure in headers | ✅ (requests) | OWASP Header Security | [Link](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html) |
| 78 | | ERROR-2 | Medium | Custom error pages (no verbose details) | ✅ (requests) | OWASP Error Handling Cheat Sheet | [Link](https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html) |
| 79 | Performance & Cache Security | Cache-1 | Low | Cache-Control: no-store on root | ✅ (requests) | OWASP Cache Control Cheat Sheet | [Link](https://cheatsheetseries.owasp.org/) |
| 80 | | CACHE-2 | Low | No cache on sensitive pages | ✅ (requests) | OWASP Cache Control Cheat Sheet | [Link](https://cheatsheetseries.owasp.org/) |
| 81 | Redirect & Navigation Security | REDIR-1 | Medium | No open redirect vulnerabilities | ⚠️ (requests) | OWASP Open Redirect Prevention | [Link](https://cheatsheetseries.owasp.org/) |
| 82 | | REDIR-2 | Medium | Relative URLs used (not absolute) | ✅ (requests + bs4) | OWASP URL Redirect Security | [Link](https://cheatsheetseries.owasp.org/) |
| 83 | Content & Resource Security | SR-1 | Low | SRI on external scripts | ⚠️ (bs4 + regex) | OWASP Subresource Integrity Cheat Sheet | [Link](https://cheatsheetseries.owasp.org/cheatsheets/Subresource_Integrity_Cheat_Sheet.html) |
| 84 | | SRI-2 | Low | External resources from trusted CDNs | ✅ (requests + bs4) | OWASP CDN Security | [Link](https://cheatsheetseries.owasp.org/) |
| 85 | | MIME-1 | Low | Correct Content-Type headers | ✅ (requests) | OWASP Content-Type Security | [Link](https://cheatsheetseries.owasp.org/) |
| 86 | | MIXED-1 | Medium | No mixed active content on HTTPS | ✅ (bs4) | OWASP Mixed Content Prevention | [Link](https://cheatsheetseries.owasp.org/) |
| 87 | | THIRD-1 | Low | Limited risky third-party scripts | ✅ (bs4) | OWASP Third-Party JavaScript Security | [Link](https://cheatsheetseries.owasp.org/) |
| 88 | API & Modern Web Features | API-1 | Medium | Rate limiting on endpoints | ⚠️ (requests + timing) | OWASP Rate Limiting Cheat Sheet | [Link](https://cheatsheetseries.owasp.org/) |
| 89 | | API-2 | Medium | JSON encoding safe (no XSS) | ✅ (requests) | OWASP JSON Security Cheat Sheet | [Link](https://cheatsheetseries.owasp.org/) |
| 90 | | HTTP2-1 | Low | HTTP/2 or HTTP/3 support | ✅ (requests) | RFC 9113 (HTTP/2) | [Link](https://tools.ietf.org/html/rfc9113) |
| 91 | Advanced Security Controls | AUTHZ-1 | High | Access control (vertical privilege escalation) | ⚠️ (if multiple roles) | OWASP Access Control Cheat Sheet | [Link](https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html) |
| 92 | | AUTHZ-2 | High | IDOR protection | ⚠️ (parameter manipulation) | OWASP IDOR Cheat Sheet | [Link](https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html) |
| 93 | | LOG-1 | Low | Security logging presence | ⚠️ (check for log endpoints) | OWASP Logging Cheat Sheet | [Link](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html) |
| 94 | Compliance & Standards | COMP-1 | Low | Privacy policy accessible | ✅ (requests) | GDPR Compliance Guide | [Link](https://gdpr-info.eu/) |
| 95 | | COMP-2 | Low | GDPR compliance indicators | ✅ (requests + bs4) | GDPR Compliance Guide | [Link](https://gdpr-info.eu/) |
| 96 | | COMP-3 | Low | Accessibility security (WCAG) | ⚠️ (basic checks) | WCAG 2.1 Guidelines | [Link](https://www.w3.org/TR/WCAG21/) |
| 97 | Subdomain Security | SUB-1 | High | No unmanaged or forgotten subdomains | ✅ (requests + dnspython) | OWASP Subdomain Takeover Prevention | [Link](https://cheatsheetseries.owasp.org/) |
| 98 | | SUB-2 | High | No subdomain takeover risks | ✅ (requests + dnspython) | OWASP Subdomain Takeover Prevention | [Link](https://cheatsheetseries.owasp.org/) |
| 99 | WAF & DDoS Protection | WAF-2 | Medium | WAF actively blocks malicious requests | ✅ (requests) | OWASP WAF Cheat Sheet | [Link](https://cheatsheetseries.owasp.org/cheatsheets/Web_Application_Firewall_Cheat_Sheet.html) |
| 100 | | DDoS-1 | Medium | DDoS protection (e.g., Cloudflare, AWS Shield) | ✅ (requests) | OWASP DDoS Cheat Sheet | [Link](https://cheatsheetseries.owasp.org/) |
| 101 | Server & Infrastructure Security | SERVER-1 | Medium | Server software is up-to-date | ✅ (requests) | CIS Benchmarks | [Link](https://www.cisecurity.org/cis-benchmarks/) |
| 102 | Third-Party & Supply Chain Security | THIRD-2 | Medium | Regularly audit third-party libraries for vulnerabilities | ✅ (requests) | OWASP Dependency Check | [Link](https://owasp.org/www-project-dependency-check/) |
| 103 | | THIRD-3 | Medium | Subresource Integrity (SRI) for all third-party scripts/styles | ✅ (requests + bs4) | OWASP SRI Cheat Sheet | [Link](https://cheatsheetseries.owasp.org/cheatsheets/Subresource_Integrity_Cheat_Sheet.html) |
| 104 | Compliance & Documentation | COMP-4 | Medium | Incident response plan documented and tested | ⚠️ (policy review) | NIST SP 800-61 | [Link](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf) |
| 105 | | COMP-5 | Medium | Software Bill of Materials (SBOM) maintained | ⚠️ (tooling) | NTIA SBOM Guide | [Link](https://www.ntia.doc.gov/files/ntia/publications/sbom_minimum_elements_report.pdf) |
| 106 | | COMP-6 | Low | Cookie consent banner is present and functional | ✅ (requests + bs4) | GDPR Cookie Consent Guide | [Link](https://gdpr-info.eu/) |

Each parameter is mapped to a global standard or research paper with direct links, so you know exactly what is being checked and why it matters.

### Marking/Scoring System

- Each check is scored as Pass (100) or Fail (0) for each subdomain (and for both www/non-www if both resolve).
- Only relevant checks for the detected subdomain type are included in the score.
- The Excel output includes all relevant columns, with clear pass/fail, and a summary by type.

---

## 📊 Scoring Methodology


### Dynamic, Context-Aware Scoring

- Each subdomain is classified (webapp, API, static, other) and only relevant controls are scored.
- Each control receives binary scoring: **Pass (100 points)** or **Fail (0 points)**
- The final score is the percentage of relevant controls passed for that subdomain.
- The Excel output includes a summary by type (average, median, min, max scores for each type).

**Score Interpretation:**
| Score Range | Security Level | Interpretation |
|-------------|----------------|----------------|
| **80-100** | 🟢 **Strong** | Excellent security posture, most controls implemented |
| **50-79** | 🟡 **Moderate** | Core protections present, improvements needed |
| **0-49** | 🔴 **Weak** | Critical vulnerabilities, immediate action required |

---

## 📁 Output Files


### Primary Output: `website_ranking.xlsx`

Excel file with **multiple sheets**:

#### Sheet 1: Security Results
Table of all scanned subdomains with:
- **Subdomain** - Domain name
- **Type** - Detected type (webapp, API, static, other)
- **Total_Score** - Security Compliance Score (0-100, context-aware)
- **Scan_Success** - Whether HTTPS connection succeeded
- **Relevant Controls** - Only columns for checks relevant to that subdomain type (e.g., TLS-1_Pass, CORS-1_Pass, etc.)

#### Sheet 2: Summary By Type
Summary table with average, median, min, max scores for each subdomain type.

#### Sheet 3: Checklist
Reference table of all 106 controls with:
- Control ID
- Priority level
- Description

### Other Files

| File | Description | Generated By |
|------|-------------|--------------|
| `<domain>_all.txt` | All discovered subdomains | subdomain_handler.py |
| `<domain>_active.txt` | HTTP/HTTPS active subdomains | subdomain_handler.py |
| `<domain>_created_not_active.txt` | Inactive subdomains | subdomain_handler.py |

---

## 🔬 Research Use Cases & Data Analysis

### 1. Comparative Domain Security Analysis
```python
import pandas as pd

df = pd.read_excel('website_ranking.xlsx', sheet_name='Security Ranking')

# Compare organizations or domains
for subdomain in df['Subdomain']:
    domain = subdomain.split('.')[-2] + '.' + subdomain.split('.')[-1]  # Extract root domain
    print(f"Domain: {domain} | Subdomain: {subdomain} | Score: {df[df['Subdomain']==subdomain]['Total_Score'].values[0]}")
```

### 2. Statistical Analysis
```python
# Descriptive statistics
print(df['Total_Score'].describe())
print(f"Median: {df['Total_Score'].median()}")

# Control adoption rates
controls = [col for col in df.columns if col.endswith('_Pass')]
for ctrl in controls:
    pass_rate = (df[ctrl] == 'Yes').sum() / len(df) * 100
    print(f"{ctrl}: {pass_rate:.1f}%")
```

### 3. Category Analysis
```python
# Category performance
category_cols = ['Encryption/TLS_Score', 'Secure Headers_Score', 
                 'Configuration Protections_Score', 
                 'Information Disclosure_Score', 'DNS/Email_Score']
df[category_cols].mean()
```

### 4. Vulnerability Patterns
```python
# Identify common failures
for ctrl in controls:
    failure_rate = (df[ctrl] == 'No').sum() / len(df) * 100
    if failure_rate > 50:
        print(f"Common vulnerability: {ctrl} ({failure_rate:.1f}% fail)")
```

### 5. .ac.lk Correlation Studies
```python
# Example: Score vs. Sri Lankan University Characteristics
import pandas as pd

# Merge with Sri Lankan university data (UGC data, student enrollment, etc.)
merged = pd.merge(df, srilanka_uni_data, left_on='Subdomain', right_on='domain')
merged[['Total_Score', 'student_count', 'it_budget', 'establishment_year']].corr()

# Analyze by university type
print("State Universities:", merged[merged['type']=='state']['Total_Score'].mean())
print("Private Universities:", merged[merged['type']=='private']['Total_Score'].mean())
```

---

## 🐛 Troubleshooting

### Common Issues

**Error: "File not found"**
```bash
# Solution: Verify file exists
ls -la *.txt *.xlsx

# Or use absolute path
python security_scanner.py --file /full/path/to/file.txt
```

**Error: "ModuleNotFoundError: No module named 'sslyze'"**
```bash
# Solution: Install dependencies
pip install -r requirements.txt

# Or install individually
pip install sslyze dnspython beautifulsoup4 tqdm
```

**Error: "Connection timeout"**
```
# Normal behavior for unreachable hosts
# These will score 0 and marked as Scan_Success=False
# The scanner continues with remaining subdomains
```

**Error: "SSL certificate verification failed"**
```
# Expected for invalid/self-signed certificates
# CERT-1 control will fail (as intended)
# Scanner handles this gracefully
```

**Slow scanning**
```bash
# Rate limiting is intentional (3s per subdomain)
# To scan faster (NOT RECOMMENDED without permission):
# Edit security_scanner.py and reduce time.sleep(3)

# WARNING: Aggressive scanning may:
# - Trigger security alerts
# - Be considered DoS attack
# - Violate computer misuse laws
```

**Memory issues (1000+ subdomains)**
```bash
# Solution: Process in batches
# Split your input file into smaller files:
split -l 500 large_domain_list.txt batch_

# Scan each batch:
for file in batch_*; do
    python security_scanner.py --file $file --output results_$file.xlsx
done
```

### Debug Mode

To see detailed error messages, edit `security_scanner.py`:
```python
# Comment out this line:
# warnings.filterwarnings('ignore')
```

---

## ⚠️ Ethical Considerations

### **IMPORTANT: Only Scan Authorized Domains**

**Legal Requirements:**
- ✅ Only scan domains you **own**
- ✅ Only scan domains you have **written permission** to test
- ❌ **Never** scan third-party domains without authorization

**Why This Matters:**
Unauthorized scanning may violate:
- **Computer Fraud and Abuse Act (CFAA)** - United States
- **Computer Misuse Act** - United Kingdom
- **Local cybersecurity and computer crimes acts** in your jurisdiction
- Privacy and data protection laws

**Penalties may include:**
- Criminal prosecution
- Civil lawsuits
- University disciplinary action
- Professional consequences

### Best Practices

1. **Authorization**
   - Obtain written permission before scanning
   - Document authorization (emails, letters)
   - Respect scope limitations

2. **Rate Limiting**
   - Keep 3-second delay (default)
   - Don't run multiple instances simultaneously
   - Avoid peak traffic hours

3. **Responsible Disclosure**
   - Report critical vulnerabilities privately
   - Give institutions time to remediate (90 days typical)
   - Follow coordinated disclosure practices

4. **Data Handling**
   - Secure storage of results
   - Comply with data protection laws
   - Anonymize data for public research

5. **Research Ethics**
   - Obtain IRB approval if required
   - Respect institutional review processes
   - Follow academic integrity guidelines

### For Academic/Research Use

If conducting security research:
1. Seek approval from relevant authorities or governing bodies
2. Contact local CERT organizations for guidance
3. Notify target organizations of research intent
4. Share results with scanned institutions
5. Follow established responsible disclosure guidelines

---

## 🤝 Contributing

Contributions welcome! To contribute:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/improvement`)
3. Make your changes
4. Test thoroughly
5. Commit (`git commit -am 'Add new feature'`)
6. Push (`git push origin feature/improvement`)
7. Create Pull Request

### Suggested Improvements

- [ ] Add JSON output format
- [ ] Implement retry logic with exponential backoff
- [ ] Add support for custom checklist items
- [ ] Create web dashboard for results visualization
- [ ] Add Docker support
- [ ] Implement concurrent scanning (with rate limiting)
- [ ] Add historical tracking database
- [ ] Generate PDF reports
- [ ] Add ML-based risk scoring

---

## 📚 References & Citations

### Methodology Based On:
- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
- [NIST SP 800-52 Rev. 2: TLS Guidelines](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-52r2.pdf)
- [OWASP Top 10 (2021)](https://owasp.org/www-project-top-ten/)
- [OWASP Application Security Verification Standard (ASVS)](https://owasp.org/www-project-application-security-verification-standard/)

### Tools Used:
- [SSLyze](https://github.com/nabla-c0d3/sslyze) - TLS/SSL scanner
- [dnspython](https://www.dnspython.org/) - DNS toolkit
- [BeautifulSoup](https://www.crummy.com/software/BeautifulSoup/) - HTML parser
- [crt.sh](https://crt.sh/) - Certificate Transparency search

### Citing This Tool in Research

If you use this tool in academic research, please cite:

```bibtex
@software{subdomain_security_scanner_2025,
  title = {Universal Subdomain Security Scanner: Comprehensive Security Assessment Toolkit},
  author = {LalithK90},
  year = {2025},
  url = {https://github.com/LalithK90/ac-lk-network-audit},
  note = {Automated 20-item security checklist with weighted scoring for any domain}
}
```

---

## 📄 License

**Use for authorized security testing and academic research only.**

This tool is provided for:
- Educational purposes
- Authorized security assessments
- Academic research with proper approvals

**You accept full responsibility** for how you use this tool. The authors assume no liability for misuse.

---

## 👤 Author

**LalithK90**
- GitHub: [@LalithK90](https://github.com/LalithK90)
- Repository: [ac-lk-network-audit](https://github.com/LalithK90/ac-lk-network-audit)

---

## 📧 Support

For questions or issues:
1. Check this README thoroughly
2. Review code comments in scripts
3. Check [Issues](https://github.com/LalithK90/ac-lk-network-audit/issues) page
4. Create new issue with detailed description

---

**Version:** 2.0  
**Last Updated:** October 21, 2025  
**Status:** Production-ready for authorized use

---

### Quick Commands Reference

```bash
# Installation
pip install -r requirements.txt

# Enumerate subdomains (edit domain in script first)
python subdomain_handler.py

# Run security scanner
python security_scanner.py --file example.com_active.txt

# Interactive mode (select from available files)
python security_scanner.py

# Custom output filename
python security_scanner.py --file domains.txt --output security_report.xlsx

# Works with any domain or TLD
python security_scanner.py --file company_subdomains.txt
```

---


**🌍 Universal:** This toolkit works with any domain or TLD (.com, .org, .edu, .gov, .ac.lk, etc.)  
**🔒 Ethics:** Only scan domains you own or have explicit permission to test  
**📊 Output:** Comprehensive Excel reports with dynamic, context-aware scoring and detailed checklist results

---

**Remember: With great scanning power comes great responsibility. Scan ethically!**
