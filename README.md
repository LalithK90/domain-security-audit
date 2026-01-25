# Domain Security Audit - Research & Product Platform

A comprehensive domain security assessment platform combining academic research capabilities with practical security auditing tools. Analyze subdomain enumeration methods, assess security posture, and research domain infrastructure at scale.

**Dual-Purpose Platform**:
- 🔬 **Academic Research**: Publish peer-reviewed studies on enumeration methods, security trends, and domain infrastructure
- 🛡️ **Product for Domain Owners**: Self-audit your own domains using passive analysis without any permission requirements

---

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

A comprehensive domain security assessment platform that combines passive subdomain enumeration with optional active security scanning. This tool serves both security researchers and domain administrators.

### Key Capabilities
- 🔍 **Subdomain Discovery**: 12 enumeration methods (Certificate Transparency, DNS, public databases, etc.)
- 🛡️ **Security Assessment**: 30+ security checks (HTTPS, TLS, email security, headers, etc.)
- 📊 **Research-Grade Output**: CSV, Excel, JSON reports with detailed analytics
- ⚖️ **Legal Compliance**: Passive-only mode uses public data (100% legal, no permission needed)
- 🔬 **Dual Purpose**: Academic research or practical domain auditing

### Who Can Use This
- **Security Researchers**: Analyze subdomain enumeration methods, security trends, domain infrastructure
- **Domain Administrators**: Self-audit your infrastructure, identify security gaps
- **Academic Institutions**: Publish peer-reviewed research on enumeration effectiveness
- **Security Teams**: Assess your organization's external attack surface

---

## Two Usage Models

### Model 1: Academic Research (Passive-Only - Default)

**Best for**: Publishing research, understanding enumeration methods, analyzing domain trends

```bash
ALLOW_ACTIVE_PROBES=false   # Only public data sources
DOMAIN=gov.lk               # Any domain
```

**What you can do**:
- Discover subdomains from public Certificate Transparency logs
- Query public vulnerability databases (HackerTarget, ThreatCrowd)
- Analyze WHOIS and public DNS records
- Compare enumeration method effectiveness
- Publish research findings

**Legal status**: **100% Legal** - Using only publicly available data

**Research advantage**: You can study ANY domain without permission (including competitors, government domains, etc.) because you're only using public data.

---

### Model 2: Product for Domain Owners (Active Scanning)

**Best for**: Domain administrators auditing their own infrastructure

```bash
ALLOW_ACTIVE_PROBES=true    # Passive + Active probes
DOMAIN=yourdomain.com       # Your own domain
```

**What domain owners can do**:
- All passive methods (public data)
- Active HTTP probing (check if subdomains respond)
- TLS certificate validation
- Email server probing
- Complete security posture assessment

**Legal status**: **Fully Legal** - Testing your own infrastructure

**Product advantage**: Domain owners can use the tool themselves without needing a researcher. No permission required (they own it).

---

## ⚖️ Legal & Ethical Use

### Permitted Uses

#### 1. **Passive-Only Research (Default Mode)**
- Analyze ANY domain using only public data sources
- No permission needed - you're using publicly available information
- Certificate Transparency logs, public vulnerability databases, WHOIS, DNS
- **Legal Status**: **Fully Legal in ALL jurisdictions**

#### 2. **Active Scanning on Your Own Domains**
- Audit infrastructure you own or manage
- Full HTTP/TLS/email probing enabled
- **Legal Status**: **Fully Legal**

#### 3. **Active Scanning with Written Permission**
- Explicit authorization from domain owner
- Include authorization documentation
- Follow agreed scope and timeline
- **Legal Status**: **Fully Legal** (if permission obtained)

#### 4. **Academic Research with IRB Approval**
- Institutional Review Board approval
- Ethics committee clearance
- Proper documentation and procedures
- **Legal Status**: **Fully Legal** (if approved)

### ⚠️ Legal Risks - Without Permission

Unauthorized active security scanning may violate:

- **Computer Crimes Act 2007** (Sri Lanka) - Key law for this project
  - Unauthorized access to computer systems
  - Criminal penalties: Imprisonment 1-5 years, fines LKR 500,000-5,000,000+
  - Enhanced penalties for government systems (.gov.lk)

- **Computer Fraud and Abuse Act (CFAA)** - US federal law
- **Computer Misuse Act 1990** - UK and similar legislation
- **Local cyber crime laws** - Jurisdiction-specific statutes

**BUT**: All of these only apply to **active probing without permission**. **Passive analysis of public data is legal everywhere.**

### 🛡️ Solution: Use Passive-Only Mode

To avoid all legal risk while conducting research:

```bash
# .env - This is the default
ALLOW_ACTIVE_PROBES=false   # Only public data
```

**This means**:
- Research ANY domain
- No permission needed
- No legal risk
- Publish findings freely
- ⚠️ Limited to passive methods (but still publishable)

### Best Practices for Responsible Research

#### If Doing Passive-Only Research (Recommended)
1. Document that you used only public data sources
2. Be transparent about methods in publication
3. Include data source citations
4. No permission needed

#### If Doing Active Scanning (With Permission)
1. Email domain owner with research plan
2. Obtain written approval
3. Document permission in scan metadata
4. Follow agreed scope and timeline
5. Use descriptive User-Agent header (configured by default)
6. Include contact information for questions
7. Use default rate limiting (0.05s between requests)
8. Respect HTTP 429 (Too Many Requests) responses
9. Report security issues found to domain owner
10. Provide adequate time for remediation (90+ days)

---

## Passive-Only Mode (Default)

By default, this tool runs in **passive-only mode** for maximum legal safety:

```env
ALLOW_ACTIVE_PROBES=false   # DEFAULT - Only public data
```

### What This Means

#### Enabled (Public Data Only)
- Certificate Transparency log analysis (crt.sh)
- Public vulnerability database queries (HackerTarget, ThreatCrowd)
- WHOIS lookups
- DNS resolution
- Public DNS records (SRV, CNAME, etc.)

#### Disabled (Requires Active Probes)
- HTTP endpoint probing
- TLS certificate validation
- Email server probing  
- Web content crawling
- Port scanning

### Why Passive-Only is Ideal for Research

1. **Legal Clarity**: No ambiguity - you're analyzing public data
2. **Scalability**: No rate limiting issues, no servers getting upset
3. **Sustainability**: Can run continuously without causing problems
4. **Publishable**: Academic papers love passive/public-data studies
5. **Professional**: Shows responsible research practices

### Switching to Active Mode

To enable active probes (requires either permission or your own domains):

```env
ALLOW_ACTIVE_PROBES=true    # Enables HTTP/TLS/email probing
```

**Prerequisites**:
- Written permission from domain owner, OR
- You own/manage the domain, OR
- You have IRB approval for the research

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

## Key Features

### Subdomain Enumeration (12 Methods)
- **Certificate Transparency**: crt.sh integration
- **Public Databases**: HackerTarget, ThreatCrowd
- **DNS Resolution**: MX, NS, CNAME lookup
- **Wildcard Detection**: Subdomain wildcard analysis
- **PTR Pivoting**: Reverse DNS enumeration
- **DNS Brute-Force**: 18,991 pattern dictionary
- **Web Crawling**: Link extraction
- **SRV Records**: Service discovery
- **Seed Data**: CSV/XLSX seed lists
- **WHOIS Analysis**: Domain registration data
- **Mail Server Enumeration**: Email infrastructure
- **Advanced Enumeration**: Multi-source correlation

### Security Checks (30+ Methods)
- HTTPS/TLS validation
- Certificate expiry
- Email server security (SPF, DKIM, DMARC)
- DNS security (DNSSEC)
- HTTP security headers
- SSL/TLS version compliance
- Cipher strength analysis
- And 20+ more security validations

### Persistent State Management
- SQLite database for crash recovery
- Incremental scanning with rescan policies
- Skip already-scanned subdomains
- Automatic retry of failed checks
- Historical data preservation

### Production-Ready Output
- CSV reports (discovery, checks, findings)
- Excel workbooks with formatting
- Detailed JSON metadata
- Markdown summaries
- Time-series analysis

---

## Directory Structure

```
domain-security-audit/
├── src/
│   ├── app.py                    # Main orchestrator
│   ├── requirements.txt          # Python dependencies
│   ├── scanner/                  # Core scanning modules
│   │   ├── runner.py            # Scan execution
│   │   ├── enumeration.py       # Subdomain discovery
│   │   ├── enumerator_worker.py # Worker orchestration
│   │   ├── scan_worker.py       # Security checks
│   │   ├── normalization.py     # Data normalization
│   │   ├── advanced_enumeration.py
│   │   ├── advanced_checks.py
│   │   ├── crawl_lite.py
│   │   ├── wildcard.py
│   │   ├── ptr_pivot.py
│   │   ├── srv_pivot.py
│   │   ├── xlsx_seed.py
│   │   ├── profiles.py
│   │   ├── checks/              # Security check registry
│   │   ├── probes/              # HTTP, TLS, DNS, Email probes
│   │   ├── output/              # Report generation
│   │   └── scoring/             # Risk scoring model
│   ├── state/                    # SQLite database layer
│   └── util/                     # Configuration, logging, utilities
├── state/                        # SQLite databases (gov.lk/, ac.lk/, etc.)
├── out/                          # Output reports and CSV files
├── .env                          # Configuration (DOMAIN, ALLOW_ACTIVE_PROBES, etc.)
├── README.md                     # This file
├── permission_request_email.txt  # Email template for requesting permission
├── run.sh                        # Execution script
├── generate_reports.py           # Post-processing and reporting
└── generate_paper_tables.py      # Research paper table generation
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

## Security Checks

The platform evaluates 30+ security properties:

### Certificate & TLS
- HTTPS availability
- Valid certificate chain
- Certificate expiry (90, 30, 7 day warnings)
- TLS version (1.2+, 1.3)
- Cipher strength (no weak ciphers)
- OCSP stapling

### Email Security
- SPF records present
- DKIM configuration
- DMARC policy
- Mail server TLS support
- MX record configuration

### DNS Security
- DNSSEC validation
- CAA records (certificate authority authorization)
- DNS response consistency

### HTTP Security
- HSTS header
- X-Frame-Options
- X-Content-Type-Options
- Content-Security-Policy
- Referrer-Policy
- Security headers compliance

### Domain Configuration
- Wildcard subdomains
- DNS forwarding
- Subdomain consistency
- Registration status

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
   # Edit .env file
   DOMAIN=gov.lk              # Change to your domain
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

All configuration is in the `.env` file (single source of truth):

### Required Settings
```env
DOMAIN=gov.lk                  # Domain to scan
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

## Team & Contact

- **Maintainers**: Domain Security Audit project team
- **Contact**: Add your contact email here (e.g., security@yourdomain.com)
 - **Contact**: asakahatapitiya@gmail.com
- **Purpose**: Support researchers and domain owners using this tool

## License & Citation

- **Usage**: Free to use for research and for auditing domains you own or have permission to test
- **Citation**: Please cite when used in research outputs:

```
Domain Security Audit Platform. 2026. https://github.com/lalithk90/domain-security-audit
```
