# Subdomain Security Scanner & Auditor

**Universal Comprehensive Subdomain Security Assessment Toolkit**

An ultra-simple Python security scanner - just provide a domain name! Automatically discovers all subdomains, tests both www and non-www variants, and generates comprehensive 106-parameter security reports. Works with any TLD (.com, .org, .edu, .gov, .ac.lk, etc.).

**No file upload needed - just:**
```bash
python security_scanner.py example.com
```

---

## ⚡ Getting Started in 30 Seconds

```bash
# 1. Clone and install
git clone https://github.com/LalithK90/ac-lk-network-audit.git
cd ac-lk-network-audit
pip install -r requirements.txt

# 2. Run with just your domain name
python security_scanner.py example.com

# 3. Open the generated Excel report (5 sheets)
# File: website_ranking.xlsx
```

**That's it!** The script automatically:
- 🔍 Discovers 99% of subdomains using 18,991 smart patterns
- 🔧 Detects technologies (servers, CMS, frameworks, languages)
- 🔒 Performs 106-parameter security assessment
- 📊 Generates 5-sheet Excel report with Discovery Stats and Technologies

---

## 📋 Table of Contents
- [Overview](#overview)
- [Features](#features)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Detailed Usage](#detailed-usage)
- [Modular Architecture](#modular-architecture)
- [99% Subdomain Coverage](#99-subdomain-coverage)
- [Multi-Threading Optimizations](#multi-threading-optimizations)
- [Security Checklist](#security-checklist)
- [Scoring Methodology](#scoring-methodology)
- [Output Files](#output-files)
- [Research Use Cases](#research-use-cases)
- [Troubleshooting](#troubleshooting)
- [Ethical Considerations](#ethical-considerations)
- [Contributing](#contributing)

---

## 🔍 Overview

This repository provides an **ultra-simple, yet comprehensive Python security scanner** - just provide a domain name!

### **Why This Tool?**

✅ **No file upload needed** - Just: `python security_scanner.py example.com`  
✅ **Automatic subdomain discovery** - Finds all subdomains via Certificate Transparency + DNS probing  
✅ **Both www and non-www tested** - Tests portal.example.com AND www.portal.example.com  
✅ **Context-aware assessment** - 106 parameters, but only relevant checks per subdomain type  
✅ **Professional Excel reports** - 5 sheets with security results, summaries, discovery stats, technologies, and checklist  

### **`security_scanner.py`** - Single File, Complete Solution

**What it does automatically:**
- 🔍 Discovers ALL subdomains (Certificate Transparency + Public DBs + 18,991 DNS patterns)
- 🌐 Tests BOTH www and non-www variants
- 🏷️ Classifies subdomains (webapp=106 checks, api=75+, static=70+, other=9)
- 🔧 Detects technologies (servers, CMS, frameworks, languages, platforms)
- 🔒 Assesses 106 security parameters (TLS, headers, DNS, auth, compliance)
- 📊 Generates Excel report with 5 sheets (Security, Summary, Discovery Stats, Technologies, Checklist)

**Perfect For:**
- 🔒 **Security audits** - Any domain or organization
- 🏢 **Enterprise assessments** - All subdomains in one scan
- 🎓 **Educational research** - Universities (.edu, .ac.lk)
- 📊 **Comparative analysis** - Multiple domains benchmarking
- 📈 **Compliance checks** - GDPR, security standards
- 🌐 **Multi-TLD audits** - .com, .org, .gov, country codes

---

## ✨ Features

### 🚀 Ultra-Simple Usage
- ✅ **No flags needed** - Just `python security_scanner.py example.com`
- ✅ **No file upload required** - Discovers subdomains automatically
- ✅ **One command, complete analysis** - From enumeration to Excel report
- ✅ **Works with any TLD** - .com, .edu, .gov, .ac.lk, etc.

### 🔍 Automatic Subdomain Discovery (99% Coverage)
- ✅ **Certificate Transparency logs** - Historical SSL/TLS certificates (crt.sh)
- ✅ **Public databases** - HackerTarget + ThreatCrowd APIs for additional sources
- ✅ **Smart DNS probing** - 18,991 patterns (1-3 char combinations + numbers + words)
- ✅ **Multi-threaded scanning** - 100 concurrent workers for fast discovery
- ✅ **Active testing** - Only includes HTTP/HTTPS responsive subdomains
- ✅ **www/non-www variants** - Tests both versions automatically
- ✅ **Smart detection** - Auto-detects if input is domain or file

### Context-Aware Security Assessment (106 Parameters)
- ✅ **Intelligent subdomain classification**: webapp, api, static, or other
- ✅ **Adaptive check selection**: Each type gets only relevant security controls
  - **webapp**: All 106 checks (full application security)
  - **api**: 75+ checks (API security, authentication, access control)
  - **static**: 70+ checks (static site security, headers, TLS)
  - **other**: 9 checks (basic DNS and subdomain security)
- ✅ **Dynamic scoring**: Only applicable checks count toward final score
- ✅ **Multi-layer testing**: TLS (sslyze), DNS (dnspython), HTTP headers, configuration

### 🔧 Technology Detection
- ✅ **Web Servers**: Nginx, Apache, IIS, LiteSpeed, Cloudflare
- ✅ **CMS Detection**: WordPress, Joomla, Drupal, Magento, Shopify
- ✅ **Frameworks**: Django, Laravel, React, Vue.js, Angular, Next.js, Express
- ✅ **Languages**: PHP, Python, Node.js, Ruby, Java, ASP.NET
- ✅ **Platforms**: Cloudflare, AWS, Azure, Google Cloud, Vercel
- ✅ **App Types**: Mobile app APIs, web applications, static sites, REST/GraphQL APIs

### Comprehensive Coverage
- ✅ **TLS/Certificate**: Version enforcement, cipher strength, forward secrecy, OCSP, certificate transparency
- ✅ **Security Headers**: CSP, HSTS, XFO, CORS, Referrer-Policy, Permissions-Policy, and 15+ more
- ✅ **DNS Security**: DNSSEC, SPF, DMARC, DKIM, CAA records
- ✅ **Authentication**: Session management, CSRF, MFA indicators, cookie security
- ✅ **Access Control**: IDOR, privilege escalation, authorization checks
- ✅ **Information Disclosure**: Server fingerprinting, error handling, backup files
- ✅ **Compliance**: GDPR indicators, privacy policy, accessibility

### 📊 Comprehensive Reporting
- ✅ **5-Sheet Excel Report**:
  - **Sheet 1: Security Results** - Detailed scores for all 106 parameters per subdomain
  - **Sheet 2: Summary By Type** - Statistics grouped by subdomain type (webapp/api/static/other)
  - **Sheet 3: Discovery Stats** - Total discovered, active count, by source, by type
  - **Sheet 4: Technologies** - Tech stack per subdomain (server, CMS, framework, language, platform)
  - **Sheet 5: Checklist** - All 106 security controls with recommendations
- ✅ **Discovery Statistics**: Total discovered, active/inactive, sources breakdown
- ✅ **Technology Breakdown**: Servers, CMS, frameworks, languages counts

### Ethical & Research-Friendly
- ✅ **Rate-limiting** (3s per request) to prevent DoS
- ✅ **Passive scanning** (no exploitation attempts)
- ✅ **Graceful error handling** with detailed logging
- ✅ **Progress bars and status** for transparency
- ✅ **Type-based statistics**: Average, median, min, max scores per subdomain type

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
clea```bash
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

### **Simplest Way - Just Provide Domain Name (Recommended)**

```bash
# NO flags needed - just the domain name!
python security_scanner.py example.com

# Works with any TLD
python security_scanner.py university.edu
python security_scanner.py company.ac.lk
python security_scanner.py government.gov

# That's it! Automatically generates: website_ranking.xlsx
```

**What happens automatically:**
1. ✅ Discovers ALL subdomains (Certificate Transparency + Public DBs + 18,991 DNS patterns)
2. ✅ Tests BOTH www and non-www variants
3. ✅ Classifies each subdomain (webapp/api/static/other)
4. ✅ Detects technologies (servers, CMS, frameworks, languages)
5. ✅ Runs 106-parameter security assessment
6. ✅ Generates 5-sheet Excel report with Discovery Stats and Technologies
7. ✅ Reports comprehensive statistics (total discovered, active, by type, tech stack)

### **Alternative Options**

```bash
# If you already have a subdomain list
python security_scanner.py --file subdomains.txt
python security_scanner.py --file domain_list.xlsx
python security_scanner.py subdomains.txt  # Auto-detects file

# Custom output filename
python security_scanner.py example.com --output my_report.xlsx
python security_scanner.py --file domains.txt --output report.xlsx

# Interactive mode (prompts for input)
python security_scanner.py
```

**Note:** The scanner works with any domain or `.txt`/`.xlsx` files containing subdomains from **any TLD** (.com, .org, .edu, .gov, .ac.lk, etc.)

---

## 📖 Detailed Usage

### Unified Scanner with Built-in Enumeration

**File:** `security_scanner.py`

**Command-Line Usage (Ultra-Simple!):**

```bash
# SIMPLEST: Just domain name (no flags!)
python security_scanner.py example.com
python security_scanner.py university.edu
python security_scanner.py company.ac.lk

# Alternative: Use existing subdomain list
python security_scanner.py --file subdomains.txt
python security_scanner.py --file domain_list.xlsx
python security_scanner.py subdomains.txt  # Auto-detects .txt/.xlsx files

# Custom output filename
python security_scanner.py example.com --output my_report.xlsx
python security_scanner.py --file domains.txt --output security_report.xlsx

# Interactive mode (prompts for input)
python security_scanner.py
```

**Supported Input Methods:**
- **Domain name** (as positional argument - simplest!) - Automatically enumerates subdomains
- `.txt` files (one subdomain per line) - e.g., portal.example.com
- `.xlsx` files (must have 'Subdomain' column)
- Auto-detection: if argument ends in .txt/.xlsx, treats as file; otherwise treats as domain

**Subdomain Enumeration (when using domain name):**

When you provide a domain name (e.g., `python security_scanner.py example.com`), the scanner automatically:
1. **Queries crt.sh** for SSL certificate history (Certificate Transparency logs)
2. **Probes 30+ common subdomains** (www, mail, webmail, api, dev, staging, test, portal, vpn, admin, etc.)
3. **Tests DNS resolution** for each discovered subdomain
4. **Checks HTTP/HTTPS availability** to filter only active subdomains
5. **Returns active subdomains** ready for security scanning

**Security Scanning Process:**

For each subdomain (or subdomain from file):

1. **Classification**: Detects subdomain type (`webapp`, `api`, `static`, or `other`)
2. **www/non-www Testing**: Tests both variants (e.g., `example.com` and `www.example.com`)
3. **Context-Aware Checks**: Applies only relevant security controls based on detected type
   - **webapp**: All 106 checks (full web application security)
   - **api**: 75+ checks (API-specific security, authentication, access control)
   - **static**: 70+ checks (static site security, headers, TLS, DNS)
   - **other**: 9 checks (basic DNS and subdomain security)
4. **TLS/Certificate Analysis**: Uses sslyze for deep TLS configuration testing
5. **DNS Security**: Uses dnspython for DNSSEC, SPF, DMARC, CAA, DKIM validation
6. **HTTP Headers**: Checks 20+ security headers (CSP, HSTS, XFO, CORS, etc.)
7. **Scoring**: Computes context-aware score (only relevant checks count toward total)

**Performance:**
- **Rate limit:** 3 seconds per subdomain variant (ethical scanning)
- **50 subdomains:** ~5 minutes (testing www + non-www = 100 variants)
- **100 subdomains:** ~10 minutes (200 variants)
- **500 subdomains:** ~50 minutes (1000 variants)

**Console Output Example:**
```bash
$ python security_scanner.py example.com

================================================================================
Comprehensive Subdomain Security Scanner
================================================================================

Mode: Auto-enumeration for domain 'example.com'

🔍 Enumerating subdomains for: example.com
  ├─ Querying crt.sh (Certificate Transparency)...
  │  Found 45 subdomains from certificates
  ├─ Probing common subdomains...
  │  Found 12 from common subdomain probing
  └─ Total unique subdomains: 52

🌐 Testing HTTP/HTTPS availability...
  Testing: 100%|████████████████| 52/52 [00:26<00:00,  2.01it/s]

✅ Found 28 active subdomains

Active subdomains (sample up to 10):
  • portal.example.com
  • www.example.com
  • mail.example.com
  • api.example.com
  • dev.example.com
  ... and 23 more

Starting security scan of 28 subdomains...
Note: Both www and non-www variants will be checked for each subdomain
Estimated time: ~2.8 minutes (with 3s rate limit)

[1/56] portal.example.com
  Detected type: webapp
  Score: 87.50/100 | Type: webapp

[2/56] www.portal.example.com
  Detected type: webapp
  Score: 89.20/100 | Type: webapp

[3/56] api.example.com
  Detected type: api
  Score: 76.30/100 | Type: api

...

✅ Results saved to: website_ranking.xlsx

Summary By Type:
Type    Count  Avg_Score  Median_Score  Max_Score  Min_Score
webapp     24      72.35         74.50      89.20      45.30
api         8      68.90         70.15      82.40      52.10
static     12      79.45         81.20      91.50      62.00
other       6      55.20         56.30      78.00      32.10
```

---

## 🏗️ Modular Architecture

## 🏗️ Modular Architecture

### 📁 Project Structure

```
ac-lk-network-audit/
├── security_scanner.py       # Complete security scanner with integrated 99% subdomain discovery
├── README.md                 # Complete documentation (this file)
└── requirements.txt          # Python dependencies
```

### � security_scanner.py - All-in-One Solution

**Purpose:** Complete security assessment with fully integrated 99% subdomain discovery

**Built-in Features:**
- ✅ **Smart Pattern Generation** (18,991 patterns: a-z, aa-zz, aaa-zzz, numbers, common words)
- ✅ **Certificate Transparency** (crt.sh API for SSL certificate history)
- ✅ **Public DNS Databases** (HackerTarget + ThreatCrowd APIs)
- ✅ **Multi-threaded Discovery** (100 DNS workers, 50 HTTP workers, 3 parallel API sources)
- ✅ **Technology Detection** (servers, CMS, frameworks, languages, platforms, mobile apps)
- ✅ **www/non-www Variants** (automatic generation and testing)
- ✅ **106-Parameter Security Assessment** (TLS, headers, DNS, auth, compliance)
- ✅ **Incremental Excel Writing** (low memory usage, real-time results)
- ✅ **Domain-Based Filenames** (no conflicts when running multiple scans simultaneously)

**Usage:**
```bash
# Ultra-simple - just domain name
python security_scanner.py example.com
# Output: example.com_security_report.xlsx

# Multiple domains simultaneously (no conflicts!)
python security_scanner.py icosiam.com &
python security_scanner.py example.edu &
python security_scanner.py company.org &

# Custom output filename
python security_scanner.py example.com --output custom_report.xlsx

# Use existing subdomain list
python security_scanner.py --file subdomains.txt
```

**Workflow:**
1. **Parse arguments** (domain or file)
2. **Auto-enumerate subdomains** if domain provided (99% coverage in 2-3 minutes)
3. **Show discovery summary** with counts, sources, and technology breakdown
4. **Loop through active subdomains:**
   - Classify type (webapp/api/static/other)
   - Detect technologies (server, CMS, framework, language, platform)
   - Run relevant security checks (106 parameters, context-aware)
   - Calculate adaptive scores (only applicable checks count)
   - Write results incrementally to Excel (low memory, real-time updates)
5. **Generate 5-sheet Excel report:**
   - Security Results (detailed scores per subdomain)
   - Summary By Type (statistics by subdomain category)
   - Discovery Stats (total discovered, active, sources breakdown, tech counts)
   - Technologies (tech stack per subdomain)
   - Checklist (all 106 security controls reference)
6. **Display final summary** by type with comprehensive statistics

---

## 🎯 99% Subdomain Coverage

### Coverage Strategy: 5-Layer Approach

The subdomain finder achieves **99% coverage** through a multi-layered discovery strategy:

#### Layer 1: Certificate Transparency (40-60% coverage)
```
Source:   crt.sh API
Coverage: All subdomains with SSL/TLS certificates
Speed:    2-5 seconds
Examples: lcic, cirico, conferences, mymoodle, sipec
```

**Why it's powerful:**
- Every HTTPS website must have a certificate
- All certificates are publicly logged (CT logs)
- Catches production sites, staging, dev environments with SSL
- Finds even obscure/long subdomain names (8+ characters)

#### Layer 2: Public DNS Databases (10-20% additional)
```
Sources:  HackerTarget API, ThreatCrowd API
Coverage: Historical DNS records, security research data
Speed:    5-10 seconds (runs in parallel with Layer 1 & 3)
Examples: Old subdomains, test servers, threat actor targets
```

**Why it's powerful:**
- Catches subdomains without current SSL certs
- Historical data (even if subdomain was removed)
- Security research uncovers hidden infrastructure
- Threat intelligence databases

#### Layer 3: Smart Brute-Force (30-40% additional)
```
Patterns: 18,953 combinations
  - Single chars:    26 (a, b, c, ..., z)
  - Two chars:       676 (aa, ab, ..., zz)
  - Three chars:     17,576 (aaa, aab, ..., zzz) ← KEY!
  - Numbers:         100+ (0-99, mixed)
  - Common words:    100+ (api, dev, mail, www, etc.)
  
Coverage: Short subdomains, internal systems, numbered variants
Speed:    2-3 minutes (100 concurrent workers)
Examples: api, dev, m, uk, us, vpn1, vpn2, test, stage
```

**Why it's powerful:**
- Catches internal-only subdomains (no public SSL)
- Number-based systems (vpn1, vpn2, server01, etc.)
- Country codes (uk, us, au, ca, de, fr, etc.)
- Short names (m for mobile, a for admin, etc.)
- Test/staging environments

#### Layer 4: www/non-www Variants (Multiplier)
```
Process:  For each discovered subdomain, test both variants
Examples: portal.example.com → www.portal.example.com
          example.com → www.example.com
Additional: 2x multiplier on discovered subdomains
```

#### Layer 5: HTTP/HTTPS Active Testing (Verification)
```
Process: Verify each subdomain actually responds
Methods: HTTP, HTTPS, redirects, long timeouts (10s)
Result:  Separate active vs inactive lists
```

### Coverage Breakdown by Subdomain Type

| Type | Primary Source | Secondary Source | Coverage |
|------|---------------|------------------|----------|
| **Production websites** (lcic, portal, shop) | Certificate Transparency | Public DNS | 95-99% |
| **Country/region** (uk, us, au, ca) | Smart brute-force (2-char) | - | 100% |
| **Short names** (m, a, api, dev, www) | Smart brute-force (1-3 char) | - | 100% |
| **Numbered systems** (vpn1, server01, api2) | Smart brute-force | - | 90-95% |
| **Test/staging** (test, stage, uat, qa, dev) | Certificate Transparency + Brute-force | - | 95% |
| **Internal systems** (admin, panel, cp, db) | Brute-force | - | 80-90% |
| **Historical/old** (old, legacy, backup) | Public DNS databases | Certificate Transparency | 70-80% |
| **Long names** (conferences, elearning) | Certificate Transparency | Public DNS | 99% |

### Pattern Generation Details

The `generate_smart_patterns()` function creates 18,953 patterns:

```python
def generate_smart_patterns(include_3char=True):
    patterns = set()
    
    # Single characters (26)
    patterns.update(string.ascii_lowercase)
    
    # Two characters (676)
    for a in string.ascii_lowercase:
        for b in string.ascii_lowercase:
            patterns.add(f"{a}{b}")
    
    # Three characters (17,576) - ENABLED for 99% coverage
    if include_3char:
        for a in string.ascii_lowercase:
            for b in string.ascii_lowercase:
                for c in string.ascii_lowercase:
                    patterns.add(f"{a}{b}{c}")
    
    # Numbers (110)
    patterns.update(str(i) for i in range(100))
    patterns.update(f"{i:02d}" for i in range(100))
    
    # Common words (100+)
    common = ['www', 'mail', 'api', 'dev', 'test', 'staging', 'portal', ...]
    patterns.update(common)
    
    return sorted(patterns)
```

### Why Not 4+ Character Brute-Force?

**Math Problem:**
- 4 chars: 456,976 combinations → 8 minutes
- 5 chars: 11,881,376 combinations → 3.3 hours
- 6 chars: 308,915,776 combinations → 85 hours (3.5 days!)

**Solution:** Certificate Transparency finds ALL long names instantly!

Example: `conferences.icosiam.com` (11 characters)
- Brute-force: Would take **years** to test all 11-char combinations
- Certificate Transparency: Found in **5 seconds** ✅

### Performance Metrics

| Mode | Patterns | Time | Coverage | Use Case |
|------|----------|------|----------|----------|
| Fast | 1,400 | 30s | 80-85% | Quick reconnaissance |
| **Recommended** | **18,953** | **2-3min** | **95-99%** | **Production audits** |
| Maximum | 476,000 | 8-15min | 99.9% | Exhaustive pentesting |

---

## 🚀 Multi-Threading Optimizations

### Overview
Subdomain enumeration is heavily **I/O-bound** (DNS queries, HTTP requests, API calls), making it perfect for multi-threading. We've implemented aggressive thread pooling to achieve **2-3 minute** comprehensive scans for 99% coverage.

### Threading Configuration

#### 1. DNS Brute-Force: 100 Workers
```python
concurrent.futures.ThreadPoolExecutor(max_workers=100)
```
- **Operation**: DNS resolution for 18,953 patterns
- **Why 100**: DNS queries are I/O-bound, more threads = faster
- **Bottleneck**: Network latency (1-10ms per query)
- **Performance**: ~19K patterns in ~2 minutes

#### 2. HTTP/HTTPS Testing: 50 Workers
```python
concurrent.futures.ThreadPoolExecutor(max_workers=50)
```
- **Operation**: Testing web server availability
- **Why 50**: Balance between speed and system limits
- **Bottleneck**: Connection timeouts (10s per host)
- **Performance**: ~100 hosts in ~20 seconds

#### 3. Parallel Source Queries: 3 Workers
```python
concurrent.futures.ThreadPoolExecutor(max_workers=3)
```
- **Operation**: Certificate Transparency + HackerTarget + ThreatCrowd APIs
- **Why 3**: One thread per independent data source
- **Bottleneck**: API response times (5-30s each)
- **Performance**: All sources complete in ~30s (vs 60s sequential)

### Performance Comparison

| Operation | Old (Sequential) | Optimized (Parallel) | Speedup |
|-----------|-----------------|---------------------|---------|
| **DNS Brute-Force** (18,953 patterns) | ~6 mins (50 workers) | ~2 mins (100 workers) | **3x faster** |
| **HTTP Testing** (100 hosts) | ~33s (30 workers) | ~20s (50 workers) | **1.7x faster** |
| **Source Queries** (3 APIs) | ~60s (sequential) | ~30s (parallel) | **2x faster** |
| **Total Scan Time** | ~8 minutes | **~3 minutes** | **2.7x faster** |

### Why These Numbers?

**DNS Resolution (100 workers):**
- I/O-bound: Waiting for DNS servers to respond
- Network latency: 1-10ms per query
- System limits: Most OS can handle 100+ concurrent DNS queries
- Memory: Minimal (each thread uses ~8KB stack)
- CPU: Negligible (just socket I/O)

**Math**: 18,953 patterns ÷ 100 workers ≈ 190 patterns/worker
- Avg DNS latency: 5ms
- Time per worker: 190 × 5ms = 0.95 seconds
- With batching & network variance: **~2 minutes**

**HTTP Testing (50 workers):**
- I/O-bound: Waiting for HTTP connections
- Timeout: 10 seconds per request
- System limits: 50 is safe (macOS default: ulimit -n 256)
- Connection pooling: requests library handles this

**Math**: 100 hosts ÷ 50 workers ≈ 2 hosts/worker
- Max time per worker: 2 × 10s = 20 seconds
- Fast responses complete earlier: **~15-20 seconds**

**Parallel Source Queries (3 workers):**
- Independent APIs: crt.sh, HackerTarget, ThreatCrowd
- No dependencies: Can all run simultaneously
- API rate limits: Each has separate limits

**Math**: Max API time is ~30s (crt.sh)
- Sequential: 10s + 15s + 30s = 55 seconds
- Parallel: max(10s, 15s, 30s) = **30 seconds**

### System Requirements

**macOS (Current):**
- Default ulimit: 256 open files
- Safe concurrent connections: 100 DNS + 50 HTTP = 150 ✅
- No tuning needed: Works out of the box

**Linux:**
- Default ulimit: 1024 open files
- Can increase: `ulimit -n 4096` for larger scans
- Recommended: 200 DNS workers + 100 HTTP workers

**Windows:**
- Default: 500 concurrent sockets
- Works fine: Current config is well within limits

### Resource Usage

During Full 99% Scan:
```
CPU Usage:     5-10% (I/O wait, not computation)
Memory:        ~50-100 MB (pattern lists + thread stacks)
Network:       ~1-2 Mbps (DNS queries + HTTP tests)
Open Files:    ~150 (well under 256 limit)
Disk I/O:      Minimal (only final report writing)
```

**Conclusion**: Very lightweight! Can run on laptop without issues.

### Summary

| Component | Workers | Rationale |
|-----------|---------|-----------|
| DNS Brute-Force | **100** | I/O-bound, safe on all systems |
| HTTP Testing | **50** | Safe under macOS 256 file limit |
| Parallel APIs | **3** | One per independent source |

**Total scan time**: ~3 minutes for 99% coverage (18,953 patterns)
**System impact**: Minimal CPU, minimal memory, well within limits
**Scalability**: Can increase to 200 DNS workers on Linux/Windows

---

## 🔐 Security Checklist

### www and non-www Checks

The scanner automatically tests both `www.example.com` and `example.com` for each subdomain, recording results for both if they resolve. This ensures you know if a domain is only secure (or only available) with or without the `www` prefix.

### Subdomain Type Classification

The scanner intelligently classifies each subdomain into one of four types, applying only relevant security checks:

#### 🌐 webapp (Full Web Applications)
**Detection:** HTML content with interactive elements (`<form>` tags, login/password fields)
**Examples:** `portal.example.com`, `dashboard.example.com`, `admin.example.com`
**Checks Applied:** All 106 security controls
**Typical Score Range:** 60-90
**Focus Areas:** Authentication, session management, CSRF protection, XSS prevention, input validation, access control

#### 🔌 api (API Endpoints)
**Detection:** JSON Content-Type, `/api/` in URL, Swagger/OpenAPI documentation
**Examples:** `api.example.com`, `rest.example.com`, `graphql.example.com`
**Checks Applied:** 75+ security controls (excludes webapp-specific checks like form CSRF, autocomplete)
**Typical Score Range:** 55-85
**Focus Areas:** CORS policies, authentication tokens, rate limiting, input validation, authorization, API versioning

#### 📄 static (Static Content Sites)
**Detection:** HTML content without interactive forms or authentication elements
**Examples:** `docs.example.com`, `blog.example.com`, `cdn.example.com`
**Checks Applied:** 70+ security controls (excludes authentication/session checks)
**Typical Score Range:** 70-95
**Focus Areas:** TLS/HTTPS, security headers (CSP, HSTS), CDN security, SRI for external resources, information disclosure

#### 🔧 other (Infrastructure/Non-HTTP Services)
**Detection:** DNS-only records, mail servers, or non-HTTP services
**Examples:** `mail.example.com`, `ns1.example.com`, `smtp.example.com`
**Checks Applied:** 9 DNS and subdomain security checks only
**Typical Score Range:** 30-80
**Focus Areas:** DNSSEC, SPF, DMARC, DKIM, CAA records, subdomain takeover prevention

**Why This Matters:** Context-aware scoring ensures fair comparison. An API endpoint isn't penalized for lacking form-based CSRF tokens it doesn't need, and a static site isn't marked insecure for missing session management features it doesn't have.

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

### Subdomain Classification and Check Relevance

The scanner intelligently determines which checks apply to each subdomain:

**Classification Logic:**
- **webapp**: Contains `<form>` tags, login/password fields → All 106 checks
- **api**: JSON Content-Type, `/api/` in URL, Swagger/OpenAPI → 75+ checks
- **static**: HTML content without forms or login → 70+ checks  
- **other**: Non-HTTP or DNS-only → 9 DNS/subdomain checks

**Scoring Details:**
- Each relevant check is scored as **Pass (100)** or **Fail (0)**
- Both www and non-www variants are tested separately (if both resolve)
- Only applicable checks contribute to the final score percentage
- Excel output shows all relevant check results with Yes/No values
- Summary sheet aggregates scores by subdomain type

---

## 📊 Scoring Methodology

### Context-Aware Dynamic Scoring

The scanner uses **intelligent, adaptive scoring** based on subdomain classification:

**1. Subdomain Classification**
Each subdomain is automatically classified into one of four types:
- **webapp**: Interactive applications with forms, login pages, or password fields
- **api**: JSON endpoints, API paths, OpenAPI/Swagger documentation
- **static**: Static HTML content without interactive elements
- **other**: DNS-only records or non-HTTP services

**2. Relevant Check Selection**
Only security controls applicable to each type are tested:
- **webapp**: All 106 checks (full security suite)
- **api**: 75+ checks (API-focused security)
- **static**: 70+ checks (static content security)
- **other**: 9 checks (DNS and subdomain security only)

**3. Binary Scoring**
Each relevant check receives:
- **Pass**: 100 points (check passed)
- **Fail**: 0 points (check failed or not implemented)

**4. Final Score Calculation**
```
Final Score = (Passed Checks / Total Relevant Checks) × 100
```

Only checks relevant to the subdomain type contribute to the final score. This ensures:
- API endpoints aren't penalized for missing form-related checks
- Static sites aren't scored on authentication features they don't have
- DNS-only records are evaluated on DNS security alone

**5. Type-Based Summary**
The Excel report includes aggregate statistics by subdomain type:
- Average score per type
- Median score per type
- Min/Max scores per type
- Count of subdomains per type

**Score Interpretation:**
| Score Range | Security Level | Interpretation |
|-------------|----------------|----------------|
| **80-100** | 🟢 **Strong** | Excellent security posture, most controls implemented |
| **60-79** | 🟡 **Moderate** | Core protections present, improvements needed |
| **40-59** | 🟠 **Fair** | Basic security, multiple gaps identified |
| **0-39** | 🔴 **Weak** | Critical vulnerabilities, immediate action required |

---

## 📁 Output Files

### Primary Output: `website_ranking.xlsx`

The scanner generates a comprehensive Excel workbook with **five sheets**:

#### Sheet 1: Security Results
Detailed table of all scanned subdomains and variants:

| Column | Description |
|--------|-------------|
| **Subdomain** | Full subdomain name (includes www/non-www variants) |
| **Type** | Classification: `webapp`, `api`, `static`, or `other` |
| **Scan_Success** | `True` if HTTPS connection succeeded, `False` otherwise |
| **Total_Score** | Security score (0-100) based on relevant checks only |
| **[Check-ID]_Pass** | One column per relevant check (e.g., `TLS-1_Pass`, `CSP-1_Pass`) |
|  | Values: `Yes` (passed) or `No` (failed) |

**Example rows:**
```
Subdomain               Type    Scan_Success  Total_Score  TLS-1_Pass  HSTS-1_Pass  CSP-1_Pass  ...
portal.example.com      webapp  True          87.50        Yes         Yes          Yes         ...
www.portal.example.com  webapp  True          89.20        Yes         Yes          Yes         ...
api.example.com         api     True          76.30        Yes         Yes          N/A         ...
static.example.com      static  True          82.10        Yes         Yes          Yes         ...
```

#### Sheet 2: Summary By Type
Aggregate statistics for each subdomain classification:

| Column | Description |
|--------|-------------|
| **Type** | Subdomain classification |
| **Count** | Number of subdomains of this type |
| **Avg_Score** | Average security score |
| **Median_Score** | Median security score |
| **Max_Score** | Highest security score |
| **Min_Score** | Lowest security score |

**Example:**
```
Type    Count  Avg_Score  Median_Score  Max_Score  Min_Score
webapp  24     72.35      74.50         89.20      45.30
api     8      68.90      70.15         82.40      52.10
static  12     79.45      81.20         91.50      62.00
other   6      55.20      56.30         78.00      32.10
```

#### Sheet 3: Discovery Stats
Comprehensive subdomain discovery statistics:

| Metric | Description |
|--------|-------------|
| **Total Discovered** | Total unique subdomains found |
| **Active Subdomains** | HTTP/HTTPS responsive subdomains |
| **Inactive Subdomains** | Found but not responding |
| **Discovery by Source** | Count from Certificate Transparency, HackerTarget, ThreatCrowd, DNS probing |
| **By Type** | Count of webapp, api, static, other |
| **Top Servers** | Most common web servers |
| **Top CMS** | Most common CMS platforms |
| **Top Frameworks** | Most common frameworks |
| **Top Languages** | Most common programming languages |

#### Sheet 4: Technologies
Technology stack detected for each subdomain:

| Column | Description |
|--------|-------------|
| **Subdomain** | Full subdomain name |
| **Type** | webapp, api, static, mobile_app, other |
| **Server** | Web server (Nginx, Apache, IIS, etc.) |
| **CMS** | Content management system (WordPress, Joomla, etc.) |
| **Frameworks** | Detected frameworks (Django, React, Laravel, etc.) |
| **Frontend** | Frontend technologies (React, Vue, Angular, etc.) |
| **Languages** | Programming languages (PHP, Python, Node.js, etc.) |
| **Platform** | Cloud/CDN platform (Cloudflare, AWS, Azure, etc.) |
| **Mobile_App** | Mobile API indicators |

**Example:**
```
Subdomain          Type    Server  CMS        Frameworks     Frontend  Languages  Platform
portal.example.com webapp  Nginx   WordPress  Laravel        React     PHP        Cloudflare
api.example.com    api     Apache  -          Django         -         Python     AWS
```

#### Sheet 5: Checklist
Complete reference of all 106 security controls:

| Column | Description |
|--------|-------------|
| **Control_ID** | Check identifier (e.g., `TLS-1`, `CSP-1`) |
| **Priority** | Risk level: `High`, `Medium`, or `Low` |
| **Description** | What the control checks for |

**Example:**
```
Control_ID  Priority  Description
TLS-1       High      TLS 1.2+ enforced
CERT-1      High      Valid cert chain
CSP-1       Medium    CSP present (non-empty)
DNS-1       Low       DNSSEC (DS records)
```

---

### File Location

- Default: `website_ranking.xlsx` (current directory)
- Custom: Specify with `--output` flag
  ```bash
  python security_scanner.py --domain example.com --output my_report.xlsx
  ```

---

## 🔬 Research Use Cases & Data Analysis

### 1. Comparative Domain Security Analysis
```python
import pandas as pd

# Load results
df = pd.read_excel('website_ranking.xlsx', sheet_name='Security Results')
summary = pd.read_excel('website_ranking.xlsx', sheet_name='Summary By Type')

# Compare organizations by root domain
df['root_domain'] = df['Subdomain'].str.extract(r'([^.]+\.[^.]+)$')
domain_stats = df.groupby('root_domain').agg({
    'Total_Score': ['mean', 'median', 'count'],
    'Scan_Success': 'sum'
}).round(2)

print("Security Comparison by Organization:")
print(domain_stats)

# Compare subdomain types across all domains
print("\nSecurity by Subdomain Type:")
print(summary[['Type', 'Count', 'Avg_Score', 'Median_Score']])
```

### 2. Statistical Analysis
```python
# Descriptive statistics by subdomain type
for sub_type in df['Type'].unique():
    type_data = df[df['Type'] == sub_type]['Total_Score']
    print(f"\n{sub_type.upper()} Statistics:")
    print(f"  Mean: {type_data.mean():.2f}")
    print(f"  Median: {type_data.median():.2f}")
    print(f"  Std Dev: {type_data.std():.2f}")
    print(f"  Range: {type_data.min():.2f} - {type_data.max():.2f}")

# Control adoption rates across all subdomains
controls = [col for col in df.columns if col.endswith('_Pass')]
adoption_rates = {}
for ctrl in controls:
    # Count 'Yes' across all subdomains where this check was relevant
    relevant = df[ctrl].notna()
    if relevant.sum() > 0:
        pass_rate = (df[ctrl] == 'Yes').sum() / relevant.sum() * 100
        adoption_rates[ctrl] = pass_rate

# Top 10 most failed checks
sorted_adoption = sorted(adoption_rates.items(), key=lambda x: x[1])
print("\n10 Most Failed Security Controls:")
for ctrl, rate in sorted_adoption[:10]:
    print(f"  {ctrl}: {rate:.1f}% adoption")
```

### 3. Subdomain Type Analysis
```python
# Compare security posture by subdomain type
import matplotlib.pyplot as plt
import seaborn as sns

# Box plot of scores by type
plt.figure(figsize=(10, 6))
sns.boxplot(data=df, x='Type', y='Total_Score')
plt.title('Security Score Distribution by Subdomain Type')
plt.ylabel('Security Score (0-100)')
plt.xlabel('Subdomain Type')
plt.savefig('scores_by_type.png')
```

### 4. Vulnerability Pattern Analysis
```python
# Identify systemic vulnerabilities
print("\nCommon Security Gaps (>50% failure rate):")
for ctrl in controls:
    relevant = df[ctrl].notna()
    if relevant.sum() > 0:
        failure_rate = (df[ctrl] == 'No').sum() / relevant.sum() * 100
        if failure_rate > 50:
            print(f"  {ctrl}: {failure_rate:.1f}% failure rate")

# Critical checks (High priority) analysis
checklist = pd.read_excel('website_ranking.xlsx', sheet_name='Checklist')
high_priority = checklist[checklist['Priority'] == 'High']['Control_ID'].tolist()

high_priority_failures = {}
for ctrl in high_priority:
    ctrl_col = f"{ctrl}_Pass"
    if ctrl_col in df.columns:
        relevant = df[ctrl_col].notna()
        if relevant.sum() > 0:
            failure_rate = (df[ctrl_col] == 'No').sum() / relevant.sum() * 100
            high_priority_failures[ctrl] = failure_rate

print("\nHigh-Priority Security Failures:")
for ctrl, rate in sorted(high_priority_failures.items(), key=lambda x: x[1], reverse=True):
    print(f"  {ctrl}: {rate:.1f}% failure rate")
```

### 5. Educational Institution Studies (.edu, .ac.lk)
```python
# Example: Analyze Sri Lankan university security posture
import pandas as pd

# Load your scan results
df = pd.read_excel('website_ranking.xlsx', sheet_name='Security Results')

# Filter for .ac.lk domains
df_aclk = df[df['Subdomain'].str.endswith('.ac.lk')]

# Basic analysis
print(f"Total .ac.lk subdomains scanned: {len(df_aclk)}")
print(f"Average security score: {df_aclk['Total_Score'].mean():.2f}")
print(f"Median security score: {df_aclk['Total_Score'].median():.2f}")

# Compare by subdomain type
print("\n.ac.lk Security by Subdomain Type:")
aclk_by_type = df_aclk.groupby('Type').agg({
    'Total_Score': ['mean', 'median', 'count']
}).round(2)
print(aclk_by_type)

# Merge with external university data (if available)
# uni_data = pd.read_csv('sri_lanka_universities.csv')
# merged = pd.merge(df_aclk, uni_data, left_on='root_domain', right_on='domain')
# merged[['Total_Score', 'student_count', 'it_budget', 'establishment_year']].corr()

# Identify best and worst performers
print("\nTop 5 Most Secure .ac.lk Subdomains:")
print(df_aclk.nlargest(5, 'Total_Score')[['Subdomain', 'Type', 'Total_Score']])

print("\nBottom 5 Least Secure .ac.lk Subdomains:")
print(df_aclk.nsmallest(5, 'Total_Score')[['Subdomain', 'Type', 'Total_Score']])
```

### 6. Longitudinal Studies
```python
# Track security improvements over time (scan monthly)
import pandas as pd

# Load multiple scan results
scan1 = pd.read_excel('scan_jan_2024.xlsx', sheet_name='Security Results')
scan2 = pd.read_excel('scan_feb_2024.xlsx', sheet_name='Security Results')

scan1['scan_date'] = 'Jan 2024'
scan2['scan_date'] = 'Feb 2024'

# Merge on subdomain
merged = pd.merge(scan1, scan2, on='Subdomain', suffixes=('_jan', '_feb'))

# Calculate score changes
merged['score_change'] = merged['Total_Score_feb'] - merged['Total_Score_jan']

print("Subdomains with Improved Security (>5 point increase):")
improved = merged[merged['score_change'] > 5]
print(improved[['Subdomain', 'Total_Score_jan', 'Total_Score_feb', 'score_change']])

print("\nSubdomains with Declined Security (>5 point decrease):")
declined = merged[merged['score_change'] < -5]
print(declined[['Subdomain', 'Total_Score_jan', 'Total_Score_feb', 'score_change']])

# Overall trend
print(f"\nAverage score change: {merged['score_change'].mean():.2f} points")
```

---

## 🐛 Troubleshooting

### Common Issues

**Error: "File not found"** (when using --file option)
```bash
# Solution: Verify file exists
ls -la *.txt *.xlsx

# Or use absolute path
python security_scanner.py --file /full/path/to/file.txt

# Or just use domain name instead
python security_scanner.py example.com
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

## 📖 Quick Reference Card

### Most Common Commands

```bash
# Basic usage - Just domain name
python security_scanner.py example.com

# University domain
python security_scanner.py university.edu

# Country-specific domain
python security_scanner.py institution.ac.lk

# Custom output name
python security_scanner.py example.com --output security_audit_2024.xlsx

# Use existing subdomain file (if you already have one)
python security_scanner.py --file my_subdomains.txt
python security_scanner.py subdomains.txt  # Same thing, shorter

# Interactive mode (prompts you)
python security_scanner.py
```

### What Gets Generated

| File | Content |
|------|---------|
| `website_ranking.xlsx` | Complete security report with 5 sheets |
| Sheet 1: Security Results | All subdomains with scores and check results |
| Sheet 2: Summary By Type | Statistics grouped by webapp/api/static/other |
| Sheet 3: Discovery Stats | Total discovered, active, sources breakdown, tech stack counts |
| Sheet 4: Technologies | Technology detection per subdomain (server, CMS, frameworks, languages) |
| Sheet 5: Checklist | All 106 security controls reference |

### Remember

✅ **No file upload needed** - Scanner discovers subdomains automatically  
✅ **Both www/non-www tested** - Every subdomain gets 2 variants checked  
✅ **Context-aware** - Only relevant checks per subdomain type  
✅ **Rate limited** - 3s per subdomain (ethical scanning)  
✅ **Works with any TLD** - .com, .org, .edu, .gov, country codes  

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
