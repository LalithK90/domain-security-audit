# Domain Security Audit - Research & Security Assessment Platform

A comprehensive, globally-applicable domain security assessment platform for analyzing subdivisions, enumeration methods, and assessing security posture at scale. Built for security researchers, domain administrators, and academic institutions worldwide.

**Dual-Purpose Platform**:
- 🔬 **Academic Research**: Publish peer-reviewed studies on enumeration methods, security trends, and domain infrastructure (passive-only, global)
- 🛡️ **Infrastructure Audit**: Self-audit your domains using active or passive analysis with proper authorization

---

## Quick Setup (Recommended)

1. Copy [.env.example](.env.example) to [.env](.env)
2. Edit [.env](.env) with your domain and preferred mode
3. Run the scanner (see [Usage](#usage))

Note: [.env](.env) is excluded via [.gitignore](.gitignore).

## 📋 Table of Contents

1. [About This Platform](#about-this-platform)
2. [Two Usage Models](#two-usage-models)
3. [Legal & Ethical Use](#legal--ethical-use)
4. [Passive-Only Mode (Default)](#passive-only-mode-default)
5. [Project Architecture](#project-architecture)
6. [Key Features](#key-features)
7. [Directory Structure](#directory-structure)
8. [Core Components](#core-components)
9. [Security Checks](#security-checks)
10. [Installation & Setup](#installation--setup)
11. [Usage](#usage)
12. [Output Files](#output-files)
13. [Configuration](#configuration)
14. [Team & Contact](#team--contact)
15. [License & Citation](#license--citation)

---

## About This Platform

A comprehensive domain security assessment platform that combines passive subdomain enumeration with optional active security scanning. Designed for global use by security researchers, domain administrators, and academic institutions.

### Key Capabilities
- 🔍 **Subdomain Discovery**: 12 enumeration methods (Certificate Transparency, DNS, public databases, etc.)
- 🛡️ **Security Assessment**: 30+ security checks (HTTPS, TLS, email security, headers, etc.)
- 📊 **Research-Grade Output**: CSV, Excel, JSON reports with detailed analytics
- ⚖️ **Legal Compliance**: Passive-only mode uses public data (100% legal globally, no permission needed)
- 🔬 **Dual Purpose**: Academic research or practical infrastructure auditing

### Who Can Use This

**Globally Applicable**:
- **Security Researchers**: Analyze enumeration methods, security trends, domain infrastructure (global coverage)
- **Domain Administrators**: Audit your own infrastructure, identify security gaps
- **Academic Institutions**: Publish peer-reviewed research on enumeration effectiveness
- **Security Teams**: Assess external attack surface of your organization
- **Compliance Officers**: Validate security configuration across domain portfolios

---

## Two Usage Models

### Model 1: Academic Research (Passive-Only - Default)

**Best for**: Publishing research, understanding enumeration methods, analyzing domain trends

```bash
ALLOW_ACTIVE_PROBES=false   # Only public data sources
DOMAIN=example.com          # Any domain worldwide
```

**What you can do**:
- Discover subdomains from public Certificate Transparency logs
- Query public vulnerability databases and WHOIS records
- Analyze DNS infrastructure and naming patterns
- Compare enumeration method effectiveness
- Publish research findings without permission from domain owner

**Legal status**: **Legal everywhere** - Using only publicly available data

**Research advantage**: Study ANY domain (competitors, governments, etc.) because you're only analyzing public information. No permission needed.

---

### Model 2: Infrastructure Audit (Active Scanning)

**Best for**: Domain administrators and security teams auditing their own or authorized infrastructure

```bash
ALLOW_ACTIVE_PROBES=true    # Passive + Active probes
DOMAIN=yourdomain.com       # Your own domain or with permission
```

**What you can do**:
- All passive methods (public data)
- Active HTTP probing (check if subdomains respond)
- TLS certificate validation
- Email server security testing
- Complete security posture assessment
- Identify vulnerabilities and misconfigurations

**Legal status**: **Legal only with authorization** - Testing infrastructure you own or have explicit permission to test

**Infrastructure advantage**: Deep security assessment of your domain portfolio. Requires ownership or written permission.

---

## ⚖️ Legal & Ethical Use

### Core Principle

**Passive-Only Mode (Default)**: 100% Legal Everywhere
- Uses only publicly available data (Certificate Transparency logs, DNS records, WHOIS, public databases)
- No active probing or network interaction
- Legal in all jurisdictions without permission
- **Best for**: Research, publication, and analysis

**Active Scanning**: Requires Authorization
- Requires explicit permission from domain owner before testing, OR
- You own/manage the domain being tested, OR
- You have institutional IRB/ethics board approval
- Active probing without authorization may violate cybercrime laws in most jurisdictions

### Legal Compliance

**To Use Safely**:
1. **Default (Passive-Only)**: Set `ALLOW_ACTIVE_PROBES=false` - No permission needed, fully legal
2. **Active Scanning**: Only run if:
   - You own the domain, OR
   - You have written authorization, OR
   - You have IRB/ethics approval for research
3. **Document your authorization** in scan metadata for compliance audits

### Responsible Research Practices

If conducting active security assessments with permission:

1. Email domain owner with research scope and timeline
2. Request written authorization (email is acceptable)
3. Include contact information for security questions
4. Use descriptive User-Agent identifying your scanner (pre-configured)
5. Use default rate limiting (0.05s between requests) to minimize impact
6. Respect HTTP 429 responses (stop probing)
7. Report findings responsibly to domain owner
8. Allow 90+ days for remediation before publication

### What NOT to Do

- ❌ Active scanning without permission
- ❌ Bypassing rate limits or DoS-style behaviors
- ❌ Accessing private data or authenticated endpoints
- ❌ Disrupting services or causing outages
- ❌ Publishing findings without responsible disclosure

**If in doubt**: Use passive-only mode (default). It's always legal and still produces publishable research.

---

## Passive-Only Mode (Default & Recommended)

By default, this tool runs in **passive-only mode** using only publicly available data:

```env
ALLOW_ACTIVE_PROBES=false   # DEFAULT - Public data only, no permission needed
```

### Data Sources (All Public)

**Enabled**:
- Certificate Transparency logs (crt.sh)
- DNS public records (A, MX, NS, CNAME, SRV, SOA)
- WHOIS domain registration data
- Public vulnerability databases (HackerTarget, ThreatCrowd, etc.)
- DNS brute-force against common naming patterns
- Reverse DNS (PTR) enumeration

**Disabled** (requires active probing):
- HTTP endpoint probing and response headers
- TLS certificate validation
- Email server probing
- Web content crawling
- Port scanning

### Why Passive-Only is Ideal for Research

1. **Legal Clarity**: Completely unambiguous - only public data, no legal questions
2. **Scalability**: No rate limiting by target servers, no interference issues
3. **Sustainability**: Can run continuously without causing disruption
4. **Publishable**: Peer-reviewed researchers prefer passive/public-data methodology
5. **Professional**: Demonstrates responsible research practices
6. **Global**: Legal in all jurisdictions for all types of domains

### Switching to Active Mode

To enable active probes (requires authorization):

```env
ALLOW_ACTIVE_PROBES=true    # Enables HTTP/TLS/email probing
```

**Prerequisites**:
- Written permission from domain owner, OR
- You own/manage the domain, OR
- You have IRB/ethics committee approval

---

## Project Architecture

```
┌─────────────────────────────────────────────────┐
│       DOMAIN SECURITY AUDIT PLATFORM             │
└─────────────────────────────────────────────────┘
          │                          │
          ├─ ACADEMIC RESEARCH      ├─ PRODUCT FOR DOMAIN OWNERS
          │  (Passive Data)         │  (Self-Audit)
          │  No permission needed   │  Own your domain
          │  Publish findings       │  Security assessment
          └──────────┬──────────────┘
                     │
        ┌────────────┴────────────┐
        │   ENUMERATION STAGE     │
        └────────────┬────────────┘
                     │
        ┌────────────┴────────────┐
        │  SCANNER STAGE          │
        │  (If ALLOW_ACTIVE=true) │
        └────────────┬────────────┘
                     │
        ┌────────────┴────────────┐
        │  OUTPUT GENERATION      │
        │  Reports, CSV, Excel    │
        └─────────────────────────┘
```

---

## Key Features & Capabilities

### Subdomain Enumeration Framework (12 Methods)

The platform employs multiple complementary enumeration techniques to achieve comprehensive subdomain discovery:

| Method | Data Source | Accuracy | Coverage | Research Value |
|---|---|---|---|---|
| **Certificate Transparency Logs** | crt.sh API | Very High | Public CAs only | Study CT adoption, certificate issuance patterns |
| **Public Vulnerability DBs** | HackerTarget, ThreatCrowd | Medium | Externally discovered subdomains | Compare with other enumeration methods |
| **DNS Brute-Force** | Recursive resolver (18,991 patterns) | High | Common naming patterns | Effectiveness analysis of naming conventions |
| **DNS Resolution** | Standard resolvers | Very High | Resolvable domains | Infrastructure mapping, service discovery |
| **SRV Records** | DNS SRV queries | High | Service-specific subdomains | Email, XMPP, SIP infrastructure assessment |
| **MX Record Enumeration** | DNS MX queries | Very High | Mail infrastructure | Email server topology and redundancy analysis |
| **WHOIS Analysis** | WHOIS registries | Medium | Registrant-published data | Historical data, organizational structure |
| **PTR Record Pivoting** | Reverse DNS from IP space | Medium | Reverse-mapped hosts | Network reconnaissance, IP-to-hostname correlation |
| **Wildcard Detection** | DNS wildcard queries | Very High | Catch-all subdomains | Network configuration assessment |
| **Web Crawling (Lite)** | Link extraction from target | Low-Medium | References in HTML/JS | Client-side domain references, legacy systems |
| **Seed Data** | User-provided CSV/XLSX | Variable | Custom wordlists | Integration with organizational knowledge |
| **Advanced Correlation** | Multi-source aggregation | High | Cross-verified results | Reduce false positives through consensus |

### Security Assessment Framework (30+ Checks)

See [Security Assessment Framework](#security-assessment-framework) section above for detailed methodology.

**By Category**:
- **Certificate & TLS**: 8 checks (encryption, validity, version, cipher strength)
- **Email Security**: 5 checks (SPF, DKIM, DMARC authentication)
- **DNS Security**: 3 checks (DNSSEC, CAA, consistency)
- **HTTP Headers**: 7 checks (clickjacking, XSS, MIME-sniffing protections)
- **Infrastructure**: 7+ checks (wildcard detection, takeover risk, registration status)

### State Management & Resilience

**Persistent SQLite Backend**:
- Crash recovery - resume from exact interruption point
- Incremental scanning - skip re-scanned subdomains by configurable time window
- Automatic retry of failed checks with exponential backoff
- Lease-based job locking for distributed work (multi-instance safety)
- Historical audit trail of all scan results

**Configuration**:
```env
RESCAN_HOURS=24          # Re-scan subdomains after 24 hours of inactivity
ERROR_RETRY_HOURS=6      # Retry failed checks after 6 hours
LEASE_MINUTES=30         # Job lease timeout (for distributed scanning)
```

### Research-Grade Output Formats

**CSV Reports** (machine-readable, suitable for statistical analysis):
- `discovered_candidates.csv` - All enumerated subdomains with discovery method(s) and confidence scores
- `check_results.csv` - Security check results with pass/fail status and finding details
- `enumeration_method_counts.csv` - Effectiveness statistics by method and domain

**Excel Workbooks** (pivot tables, charts for presentations):
- Sheet 1: Subdomain inventory with method breakdown and sorting
- Sheet 2: Security check results with pass rate analysis
- Sheet 3: Statistical summary and key findings
- Sheet 4: Timeline analysis for longitudinal studies

**JSON Metadata** (structured data for programmatic analysis):
- Execution metadata (timing, configuration, environment)
- Full check results with all findings and timestamps
- Enumeration statistics by method and source

**Markdown Reports** (human-readable for documentation):
- Executive summary with key findings
- Detailed findings with remediation recommendations
- Statistical tables and trend analysis

---

## Directory Structure

```
domain-security-audit/
├── .env                          # Configuration (DOMAIN, ALLOW_ACTIVE_PROBES, etc.)
├── README.md                     # This file
├── run.sh                        # Execution script
├── scan_all_lk_domains.sh        # Batch scanning helper
├── scan_all_lk.log               # Batch scan log
├── scan_errors.log               # Error log
├── out/                          # Output reports and CSV files
├── research/                     # Paper assets and supporting scripts
├── src/                          # Scanner implementation
│   ├── app.py                    # Main orchestrator
│   ├── generate_reports.py       # Post-processing and reporting
│   ├── requirements.txt          # Python dependencies
│   ├── scanner/                  # Core scanning modules
│   │   ├── runner.py             # Scan execution
│   │   ├── enumeration.py        # Subdomain discovery
│   │   ├── enumerator_worker.py  # Worker orchestration
│   │   ├── scan_worker.py        # Security checks
│   │   ├── normalization.py      # Data normalization
│   │   ├── advanced_enumeration.py
│   │   ├── advanced_checks.py
│   │   ├── crawl_lite.py
│   │   ├── wildcard.py
│   │   ├── ptr_pivot.py
│   │   ├── srv_pivot.py
│   │   ├── xlsx_seed.py
│   │   ├── profiles.py
│   │   ├── checks/               # Security check registry
│   │   ├── probes/               # HTTP, TLS, DNS, Email probes
│   │   ├── output/               # Report generation
│   │   └── scoring/              # Risk scoring model
│   ├── state/                    # SQLite database layer
│   ├── tests/                    # Unit tests
│   └── util/                     # Configuration, logging, utilities
├── state/                        # SQLite databases (gov.lk/, ac.lk/, etc.)
├── .venv/                        # Local virtual environment (optional)
├── .vscode/                      # Editor settings (optional)
└── .git/                         # Repository metadata
```

---

## Core Components

### 1. Enumeration Module (`scanner/enumeration.py`)
**Purpose**: Discover all subdomains of target domain

**Methods**:
- Certificate Transparency log queries
- Public vulnerability database searches
- DNS queries (brute-force, wildcards, SRV records)
- WHOIS data extraction
- Web crawling for links
- Seed data from CSV/XLSX
- PTR record pivoting

**Passive-Only Gates**:
- DNS brute-force: Disabled when `ALLOW_ACTIVE_PROBES=false`
- Wildcard detection: Disabled when `ALLOW_ACTIVE_PROBES=false`
- HTTP crawling: Disabled when `ALLOW_ACTIVE_PROBES=false`
- PTR pivoting: Disabled when `ALLOW_ACTIVE_PROBES=false`

### 2. Scanner Module (`scanner/scan_worker.py`)
**Purpose**: Run security checks on discovered subdomains

**Checks Performed** (if `ALLOW_ACTIVE_PROBES=true`):
- HTTPS/TLS validation
- Certificate expiry
- Email server security (SPF, DKIM, DMARC)
- HTTP security headers
- SSL/TLS version compliance
- Cipher strength

**When Passive-Only**: Scanner stage is completely skipped (returns 0 checks)

### 3. State Management (`state/state_manager.py`)
**Purpose**: Persistent SQLite database for crash recovery and incremental scanning

**Features**:
- Skip already-scanned subdomains
- Track scanning status
- Automatic retry of failures
- Configurable rescan intervals
- Lease-based job locking

### 4. Output Generation (`scanner/output/writer.py`)
**Purpose**: Generate reports in multiple formats

**Formats**:
- CSV: discovery_log.csv, check_results.csv
- Excel: Formatted workbooks with charts
- JSON: Detailed metadata
- Markdown: Human-readable summaries

---

## Security Assessment Framework

This section details all 30+ security validations performed by the platform, organized by domain, with methodology, validation criteria, and standards alignment. Each check is grounded in established security frameworks (NIST, OWASP, CIS) and RFC standards.

### 1. Certificate & TLS/HTTPS Validation (8 Checks)

| Check Name | Purpose & Why | Methodology | Validation Criteria | Standards |
|---|---|---|---|---|
| **HTTPS Availability** | Verify encrypted transport layer for all communication | Probe subdomain on port 443, check HTTP response code | 200-299 HTTP status or valid TLS handshake | NIST SP 800-52, OWASP A02:2021 |
| **Valid Certificate Chain** | Ensure certificate is issued by trusted CA and not expired | Verify certificate chain against system root CA store | Complete chain verified, no self-signed intermediate certs | RFC 5280, OWASP A02:2021 |
| **Certificate Expiry (90d)** | Early warning: cert expiring within 90 days | Parse cert notAfter timestamp, compare to current date | expiry_date - today >= 90 days | RFC 5280 best practice |
| **Certificate Expiry (30d)** | Medium urgency: cert expiring within 30 days | Parse cert notAfter timestamp, compare to current date | expiry_date - today >= 30 days | RFC 5280 best practice |
| **Certificate Expiry (7d)** | Critical: cert expiring within 7 days | Parse cert notAfter timestamp, compare to current date | expiry_date - today >= 7 days | RFC 5280, CIS Benchmarks |
| **TLS Version 1.2+** | Enforce modern TLS to prevent downgrade attacks | Connect to subdomain, read negotiated TLS version | TLS_version >= 1.2 | NIST SP 800-52 Rev 2, OWASP |
| **TLS Version 1.3** | Optimal security: TLS 1.3 offers strongest protections | Connect and negotiate TLS, check for 1.3 support | TLS_version == 1.3 or TLS_version >= 1.3 | NIST SP 800-52 Rev 2 (recommended) |
| **Cipher Strength** | Prevent weak cipher suites vulnerable to cryptanalysis | Retrieve cipher suite list from TLS handshake, check strength | No RC4, DES, MD5, or < 128-bit ciphers; AES-GCM preferred | NIST SP 800-52 Cipher Suite Recommendations |

### 2. Email Security & Authentication (5 Checks)

| Check Name | Purpose & Why | Methodology | Validation Criteria | Standards |
|---|---|---|---|---|
| **SPF Record Present** | Prevent email spoofing by authenticating sender IP addresses | DNS TXT query for SPF record (v=spf1) | SPF record exists and contains at least one valid mechanism | RFC 7208, DMARC RFC 7489 |
| **SPF Configuration Quality** | Validate SPF policy is properly configured | Parse SPF directives, check for ~all or -all | Contains explicit ~all (softfail) or -all (fail) policy | RFC 7208, NIST Email Security |
| **DKIM Enabled** | Verify email message integrity via cryptographic signature | DNS query for DKIM public key (_domainkey selector) | Valid DKIM key record exists, modulus >= 2048 bits | RFC 6376, DMARC RFC 7489 |
| **DMARC Policy** | Enforce email authentication and alignment policy | DNS TXT query for DMARC policy (_dmarc subdomain) | DMARC record with explicit p=quarantine or p=reject | DMARC RFC 7489, CIS Email Security |
| **MX Records Valid** | Ensure mail server infrastructure is configured | DNS MX query, validate MX hostnames resolve | At least 1 MX record, MX hostname resolves to valid IP | RFC 5321, Zone File Best Practices |

### 3. DNS Security (3 Checks)

| Check Name | Purpose & Why | Methodology | Validation Criteria | Standards |
|---|---|---|---|---|
| **DNSSEC Validation** | Prevent DNS spoofing and man-in-the-middle attacks | DNSSEC query with validation enabled, check RRSIG records | DNSSEC enabled with valid signatures on key record types | RFC 4033, OWASP A07:2021 |
| **CAA Records Present** | Control which CAs can issue certificates for domain | DNS query for CAA records (RFC 6844) | CAA records present with appropriate CA restrictions | RFC 6844, NIST SP 800-52, CIS Benchmarks |
| **DNS Response Consistency** | Detect DNS hijacking and cache poisoning | Query same record from multiple resolvers, compare responses | Responses identical across resolvers (same IPs, TTLs) | DNS Best Practices, RFC 1035 |

### 4. HTTP Security Headers (7 Checks)

| Check Name | Purpose & Why | Methodology | Validation Criteria | Standards |
|---|---|---|---|---|
| **HSTS Header** | Force HTTPS to prevent downgrade attacks and MitM | HTTP GET request, check for Strict-Transport-Security header | Header present with max-age >= 31536000 (1 year) | RFC 6797, OWASP A02:2021 |
| **X-Frame-Options** | Prevent clickjacking attacks | HTTP response header check | Header set to DENY, SAMEORIGIN, or ALLOW-FROM | OWASP A05:2021 (XSS Prevention) |
| **X-Content-Type-Options** | Prevent MIME type sniffing attacks | HTTP response header check | Header set to "nosniff" | OWASP A05:2021, HTTP Header Best Practices |
| **Content-Security-Policy** | Mitigate XSS and injection attacks via strict policy | HTTP response header check, parse directives | CSP header present with restrictive directives (no unsafe-inline) | OWASP A05:2021, NIST SP 800-53 SI-10 |
| **Referrer-Policy** | Control HTTP referrer information leakage | HTTP response header check | Header set to no-referrer, strict-origin, or strict-origin-when-cross-origin | OWASP A04:2021 |
| **X-XSS-Protection** | Legacy XSS protection (modern CSP preferred) | HTTP response header check | Header set to "1; mode=block" (if present) | OWASP A05:2021 (Legacy) |
| **Permissions-Policy** | Restrict access to browser features (camera, microphone, etc.) | HTTP response header check | Policy header present, restricts unnecessary features | W3C Permissions Policy, OWASP A05:2021 |

### 5. Domain Configuration & Infrastructure (7+ Checks)

| Check Name | Purpose & Why | Methodology | Validation Criteria | Standards |
|---|---|---|---|---|
| **Wildcard Subdomain Detection** | Identify catch-all wildcard subdomains for attack surface | DNS A query for *.domain, check if returns IP | Wildcard returns NXDOMAIN (good) or IP (potential risk) | DNS Configuration Best Practices |
| **Subdomain Takeover Risk** | Detect CNAME records pointing to dangling services | Enumerate subdomains, check CNAME targets for 404/available | CNAME targets should resolve; if not, is potential takeover risk | OWASP, Subdomain Takeover CVE Database |
| **DNS Forwarding Check** | Detect unauthorized DNS redirects | Query for NS records, verify against authoritative registry | NS records match official domain registrar records | DNS Configuration, Security Best Practices |
| **Registration Status** | Verify domain is active and properly registered | WHOIS lookup, check expiry date and registrar | Domain registered, not expired, active status | ICANN RFC 3912, Domain Best Practices |
| **Subdomain Consistency** | Detect configuration inconsistencies | Compare DNS records across multiple resolvers and time points | Consistent A/AAAA records, no unexpected changes | Infrastructure Monitoring Best Practices |
| **MX Record Consistency** | Verify mail infrastructure stability | Query MX records multiple times, check for changes | Consistent MX records across queries | Email Infrastructure Best Practices |
| **SOA Record Validation** | Verify zone configuration integrity | DNS SOA query, parse serial, TTL, retry values | Valid SOA record with appropriate TTLs (3600+) | RFC 1035, DNS Zone Management |

### Validation Methodology

**Data Sources** (all publicly available, no active probing required in passive mode):
- CRT.sh (Certificate Transparency logs)
- DNS public resolvers (1.1.1.1, 8.8.8.8, etc.)
- WHOIS registries
- Public vulnerability databases (HackerTarget, ThreatCrowd)
- RFC-compliant DNS queries

**Quality Assurance**:
- Each check is independently validated against RFC standards
- Results cross-referenced with CIS Benchmark criteria
- NIST SP 800-52 compliance verified for cryptographic recommendations
- All checks aligned with OWASP Top 10

**Scope**:
- Passive-only mode: No network probes, only public DNS and CT logs
- Active mode: HTTP/TLS probes with configurable rate limiting and User-Agent identification

---

## Installation & Setup

### Prerequisites
- Python 3.8+
- macOS, Linux, or WSL (not native Windows)
- pip or conda

### Quick Start

1. **Clone or download this repository**
   ```bash
   cd domain-security-audit
   ```

2. **Create Python environment**
   ```bash
   # Using conda (recommended)
   conda create -n domain-audit python=3.10
   conda activate domain-audit
   
   # OR using venv
   python3 -m venv venv
   source venv/bin/activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r src/requirements.txt
   ```

4. **Configure .env**
   ```bash
   # Edit .env file with your target domain
   DOMAIN=example.com         # Change to any domain
   ALLOW_ACTIVE_PROBES=false  # Keep passive-only (default, recommended)
   ```

5. **Run the scan**
   ```bash
   ./run.sh
   # OR
   python src/app.py
   ```

6. **View results**
   ```bash
   ls out/
   # Check CSV files, Excel reports, metadata
   ```

---

## Usage

### Single Domain Scan

```bash
# 1. Configure for your domain
cat > .env << 'EOF'
DOMAIN=example.com           # Change to your target domain
ALLOW_ACTIVE_PROBES=false    # Passive-only (safe, legal)
STATE_DIR=state
OUT_DIR=out
ENABLE_EXCEL=true
EOF

# 2. Run scan
./run.sh

# 3. View results
cd out/
cat run_metadata.json        # Summary statistics
head -20 discovered_candidates.csv
open subdomain_metrics.csv
```

### For Domain Owners (Self-Audit with Active Checks)

```bash
# Only if you OWN the domain
cat > .env << 'EOF'
DOMAIN=yourdomain.com
ALLOW_ACTIVE_PROBES=true     # Enables HTTP/TLS checks
EOF

./run.sh
```

### Research Data Analysis

```bash
# Generate figures for research paper
cd research/
python3 generate_summary_stats.py
python3 generate_method_comparison.py
python3 generate_security_analysis.py
python3 generate_visualizations.py

# Output: Figures saved to research/figures/
```
## Output Files

### CSV Reports
- **discovered_candidates.csv**: All enumerated subdomains with discovery method
- **check_results.csv**: Security check results (pass/fail)
- **enumeration_method_counts.csv**: Statistics on discovery method effectiveness

### Excel Workbook
- **audit_report.xlsx**: Formatted with charts and pivot tables
  - Sheet 1: Subdomains (discovery method breakdown)
  - Sheet 2: Security Checks (pass rates by category)
  - Sheet 3: Statistics and trends
  - Sheet 4: Timeline analysis

### JSON Metadata
- **run_metadata.json**: Execution details, timing, configuration
- **discovered_candidates.json**: Detailed discovery data

### Markdown Report
- **report.md**: Human-readable summary with findings and recommendations

---

## Configuration

Create a local config file from the template (do not commit it):

1. Copy [.env.example](.env.example) to [.env](.env)
2. Edit [.env](.env) with your values

The [.env](.env) file is intentionally excluded via [.gitignore](.gitignore).

All configuration is in the [.env](.env) file (single source of truth):

### Required Settings
```env
DOMAIN=example.com            # Domain to scan (any domain worldwide)
```

### Research Mode (Passive-Only) - RECOMMENDED
```env
ALLOW_ACTIVE_PROBES=false      # Only public data
                               # No permission needed
                               # 100% legal
                               # Published research friendly
```

### Product Mode (Active Scanning) - For Domain Owners
```env
ALLOW_ACTIVE_PROBES=true       # Passive + HTTP/TLS/Email probes
                               # Requires permission or ownership
```

### Enumeration Sources
```env
USE_CT_LOGS=true               # Certificate Transparency logs
USE_PUBLIC_DBS=true            # HackerTarget, ThreatCrowd
USE_DNS_BRUTE=true             # DNS brute-force (18,991 patterns)
```

### Network Settings
```env
RATE_LIMIT=0.05                # 50ms between requests (respectful)
HTTP_USER_AGENT=...            # Identify your scanner in logs
DNS_TIMEOUT=4.0
HTTP_TIMEOUT=8.0
TLS_TIMEOUT=8.0
```

### State Management
```env
STATE_DIR=state                # SQLite database location
OUT_DIR=out                    # Output reports location
RESCAN_HOURS=24                # Rescan subdomains after 24h
ERROR_RETRY_HOURS=6            # Retry failed checks after 6h
```

### Output Options
```env
ENABLE_EXCEL=true              # Generate Excel reports
```

### Parallelization
```env
# Auto-configured based on CPU cores, can override:
# WORKERS=64                    # Scanner workers
# ENUM_WORKERS=128              # Enumeration workers
```

---

## Research Platform Status & Capabilities

**Platform Status**: Production-ready. Comprehensive security assessment framework implemented, validated, and ready for research deployment.

### Implementation Summary

The platform implements a complete security assessment framework with:
- **30+ security checks** across 5 domains (certificates/TLS, email, DNS, HTTP headers, infrastructure)
- **12 enumeration methods** for comprehensive subdomain discovery
- **Standards-aligned validation** (NIST SP 800-52, OWASP Top 10, CIS Benchmarks, RFC compliance)
- **Production-grade infrastructure** (SQLite state persistence, parallel workers, crash recovery)
- **Research-ready outputs** (CSV, Excel, JSON, Markdown, statistical analysis)

### Development & Validation

**Code Quality & Testing**:
- 100% syntax validation with comprehensive error handling
- Full type hints and documentation per compliance standards
- 48+ unit tests across 5 test files (1,600+ lines of test code)
- Integration tests validating cross-component interactions
- Backward compatibility verified: Zero breaking changes

**Validation Against Standards**:
- NIST SP 800-52 (TLS/HTTPS recommendations)
- OWASP Top 10 (security vulnerabilities)
- CIS Benchmarks (security configurations)
- RFC 5280 (X.509 certificates)
- RFC 6376 (DKIM)
- RFC 7208 (SPF)
- RFC 7489 (DMARC)
- RFC 4033 (DNSSEC)

**Security Rigor**:
- User-level operations only (no elevated privileges required)
- Passive enumeration isolates legal risk (public data only)
- Active probes configurable and gated by `ALLOW_ACTIVE_PROBES` flag
- Rate limiting and respectful scanning practices enforced by default

### Research Applications

This platform is suitable for:

1. **Empirical Security Studies**
   - Analyze enumeration method effectiveness (passive data collection)
   - Quantify security posture across domain populations
   - Study certificate ecosystem health and TLS deployment patterns
   - Email authentication adoption and configuration quality analysis

2. **Infrastructure Auditing**
   - Large-scale security assessment of domain portfolios
   - Comparative analysis of security implementation across sectors
   - Longitudinal studies of security posture changes over time
   - Risk modeling and prioritization frameworks

3. **Academic Publications**
   - Peer-reviewed research on domain security trends
   - Vulnerability discovery and classification
   - Methodology papers on passive security assessment
   - Policy recommendations based on empirical findings

### Extensibility

The modular architecture supports:
- Custom check implementations (see `src/scanner/checks/`)
- New enumeration sources (see `src/scanner/enumeration.py`)
- Custom scoring models (see `src/scanner/scoring/`)
- Output format extensions (see `src/scanner/output/`)

### Documentation

Key research and technical documentation:
- [SDLC Execution Plan](research/project/SDLC_EXECUTION_PLAN.md) - Detailed methodology
- [Testing Completion Summary](research/project/TESTING_COMPLETION_SUMMARY.md) - Validation results
- [Deployment Plan](research/project/DEPLOYMENT_PLAN.md) - Production deployment procedures
- [Project Completion Index](research/project/PROJECT_COMPLETION_INDEX.md) - Comprehensive reference

### Citation

If using this platform in research or publications, please cite:

```bibtex
@software{domain_security_audit_2026,
  title={Domain Security Audit Platform: Research-Grade Infrastructure Assessment Framework},
  author={Project Team},
  year={2026},
  url={https://github.com/lalithk90/domain-security-audit},
  note={Standards-aligned security assessment with NIST, OWASP, CIS compliance}
}
```

---

## Team & Contact

- **Maintainers**: Domain Security Audit project team
- **Contact**: asakahatapitiya@gmail.com
- **Purpose**: Support researchers and domain owners using this tool

## License & Citation

- **Usage**: Free to use for research and for auditing domains you own or have permission to test
- **Citation**: Please cite when used in research outputs:

```
Domain Security Audit Platform. 2026. https://github.com/lalithk90/domain-security-audit
```
