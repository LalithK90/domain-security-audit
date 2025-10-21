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

### Security Assessment (20-Item Checklist)
- ✅ **TLS/Certificate Analysis** (sslyze) - TLS 1.2+, valid certs, cipher strength
- ✅ **Security Headers** (OWASP) - CSP, HSTS, X-Frame-Options, etc.
- ✅ **DNS Security** (dnspython) - DNSSEC, SPF records
- ✅ **Configuration** - SRI, secure cookies, cache control
- ✅ **Information Disclosure** - Server version leakage
- ✅ **Binary Pass/Fail** scoring with weighted categories
- ✅ **Security Compliance Score** (0-100) for ranking
- ✅ **Excel Export** with 3 sheets (results, checklist, methodology)

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

**Note:** The scanner works with `.txt` or `.xlsx` files containing subdomains from **any domain** (.com, .org, .edu, .gov, .ac.lk, etc.)

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

### 20-Item Security Assessment

The scanner evaluates each subdomain against 20 controls aligned with OWASP, NIST SP 800-52, and industry best practices.

### High Priority (4 controls) - Critical Security
| ID | Control | Description |
|----|---------|-------------|
| **TLS-1** | TLS 1.2+ Enforced | No TLS 1.0/1.1 allowed |
| **CERT-1** | Valid Certificate | Trusted CA, not expired, valid chain |
| **HTTPS-1** | HTTPS Enforced | HTTP redirects to HTTPS (301/302) |
| **HSTS-1** | HSTS Configured | max-age ≥31536000 + includeSubDomains |

### Medium Priority (8 controls) - Important Protections
| ID | Control | Description |
|----|---------|-------------|
| **CSP-1** | Content Security Policy | CSP header present |
| **XFO-1** | X-Frame-Options | DENY or SAMEORIGIN |
| **XCTO-1** | X-Content-Type-Options | nosniff |
| **XXP-1** | X-XSS-Protection | 1; mode=block |
| **RP-1** | Referrer-Policy | strict-origin-when-cross-origin or stricter |
| **PP-1** | Permissions-Policy | Present and configured |
| **FS-1** | Forward Secrecy | ECDHE/DHE cipher suites |
| **WC-1** | No Weak Ciphers | No RC4/3DES/NULL/EXPORT |

### Low Priority (8 controls) - Best Practices
| ID | Control | Description |
|----|---------|-------------|
| **SR-1** | Subresource Integrity | SRI on external scripts |
| **COO-1** | Secure Cookies | Secure + HttpOnly flags |
| **SI-1** | Server Info | No version disclosure |
| **DNS-1** | DNSSEC | DS records present |
| **SPF-1** | SPF Record | Email validation configured |
| **HPKP-1** | HPKP Absent | Deprecated, should be absent |
| **ETag-1** | ETag Security | Not timestamp-based |
| **Cache-1** | Cache Control | no-store on sensitive pages |

---

## 📊 Scoring Methodology

### Weighted Category Scoring

Each control receives binary scoring: **Pass (100 points)** or **Fail (0 points)**

Category scores are computed as: `(passes / total_controls) × weight`

| Category | Weight | Controls | Max Points |
|----------|--------|----------|------------|
| **Encryption/TLS** | 25% | TLS-1, CERT-1, HTTPS-1, HSTS-1, FS-1, WC-1 (6) | 25 |
| **Secure Headers** | 30% | CSP-1, XFO-1, XCTO-1, XXP-1, RP-1, PP-1 (6) | 30 |
| **Config Protections** | 20% | SR-1, COO-1, HPKP-1, ETag-1, Cache-1 (5) | 20 |
| **Info Disclosure** | 10% | SI-1 (1) | 10 |
| **DNS/Email** | 15% | DNS-1, SPF-1 (2) | 15 |
| **TOTAL** | **100%** | **20 controls** | **100** |

### Example Calculation

**Subdomain:** `portal.university.ac.lk`

```
Encryption/TLS:    5/6 pass → (5/6) × 25 = 20.83 points
Secure Headers:    4/6 pass → (4/6) × 30 = 20.00 points
Config Protections: 3/5 pass → (3/5) × 20 = 12.00 points
Info Disclosure:   1/1 pass → (1/1) × 10 = 10.00 points
DNS/Email:         1/2 pass → (1/2) × 15 =  7.50 points
────────────────────────────────────────────────────
Total Score: 70.33 / 100
```

### Score Interpretation

| Score Range | Security Level | Interpretation |
|-------------|----------------|----------------|
| **80-100** | 🟢 **Strong** | Excellent security posture, most controls implemented |
| **50-79** | 🟡 **Moderate** | Core protections present, improvements needed |
| **0-49** | 🔴 **Weak** | Critical vulnerabilities, immediate action required |

---

## 📁 Output Files

### Primary Output: `website_ranking.xlsx`

Excel file with **3 sheets**:

#### Sheet 1: Security Ranking
Ranked table of all scanned subdomains with:
- **Subdomain** - Domain name
- **Rank** - Position (1 = highest score)
- **Total_Score** - Security Compliance Score (0-100)
- **Scan_Success** - Whether HTTPS connection succeeded
- **High/Medium/Low_Priority_Passes** - Control pass counts (e.g., "3/4")
- **Individual Controls** - 20 columns (TLS-1_Pass, CERT-1_Pass, etc.) showing "Yes"/"No"
- **Category Scores** - 5 columns showing points per category

#### Sheet 2: Checklist
Reference table of all 20 controls with:
- Control ID
- Priority level
- Description

#### Sheet 3: Categories
Scoring methodology with:
- Category name
- Weight percentage
- Controls included
- Check count

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

**� Universal:** This toolkit works with any domain or TLD (.com, .org, .edu, .gov, .ac.lk, etc.)  
**🔒 Ethics:** Only scan domains you own or have explicit permission to test  
**📊 Output:** Comprehensive Excel reports with security scores and detailed checklist results

---

**Remember: With great scanning power comes great responsibility. Scan ethically!**
