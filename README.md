# LK Public Domain Security Audit - Project Documentation

## 🔍 Overview

This is an academic research project for comprehensive security auditing of public domains (specifically targeting the `.lk` domain namespace). The system performs large-scale subdomain enumeration, security scanning, and compliance checking with persistent state management and crash recovery capabilities.

**Domain**: `ac.lk` (Academic institutions in Sri Lanka)  
**Purpose**: Research and security assessment of public domain infrastructure  
**Architecture**: Parallel producer-consumer model with SQLite-based persistence

---

## 📋 Table of Contents

1. [Project Architecture](#project-architecture)
2. [Key Features](#key-features)
3. [Directory Structure](#directory-structure)
4. [Core Components](#core-components)
5. [Security Checks](#security-checks)
6. [Data Flow](#data-flow)
7. [Installation & Setup](#installation--setup)
8. [Usage](#usage)
9. [Output Files](#output-files)
10. [Configuration](#configuration)
11. [Technical Details](#technical-details)
12. [Research Applications](#research-applications)

---

## 🏗️ Project Architecture

### High-Level Design

```
┌─────────────────────────────────────────────────────────────┐
│                    PARALLEL EXECUTION                        │
├──────────────────────────┬──────────────────────────────────┤
│   ENUMERATOR WORKER      │      SCANNER WORKER              │
│   (Producer)             │      (Consumer)                  │
│                          │                                  │
│  • CT Logs (crt.sh)      │  • Claims targets from DB       │
│  • DNS Brute Force       │  • Runs probes (DNS/HTTP/TLS)   │
│  • SRV/PTR Records       │  • Evaluates checks             │
│  • HTTP Crawling         │  • Computes scores              │
│  • Pattern Generation    │  • Writes results               │
│                          │                                  │
│  ↓ Writes Candidates     │  ↑ Reads Eligible Targets       │
└──────────────┬───────────┴─────────────┬────────────────────┘
               │                         │
               └────→ SQLite DB ←────────┘
                   (state.db)
                   
         • WAL Mode (concurrent access)
         • Atomic queue operations
         • Crash-safe & resumable
```

### Key Architectural Principles

1. **Persistent State**: All progress stored in SQLite - survives crashes
2. **Parallel Execution**: Enumeration and scanning run simultaneously
3. **No Re-scanning**: Respects configurable rescan intervals (default: 24h)
4. **Memory Efficient**: Streams through DB, not RAM-resident lists
5. **Rate Limiting**: Configurable concurrency and delays
6. **Caching**: TTL-based caching for DNS, HTTP, TLS results

---

## ✨ Key Features

### Subdomain Discovery (12 Methods)

1. **Certificate Transparency Logs** - crt.sh API queries
2. **Public DNS Databases** - HackerTarget, ThreatCrowd
3. **Smart Pattern Generation** - 18,953 patterns (a-z, aa-zz, aaa-zzz + common words)
4. **DNS SRV Records** - 34 common services (_http, _ldap, _kerberos, etc.)
5. **PTR Reverse DNS** - Reverse lookups from known IPs
6. **HTTP Response Crawling** - HTML, JavaScript, CSP headers
7. **XLSX Seed Files** - Import from previous scans
8. **DNS Brute Force** - Concurrent verification (500 workers)
9. **HTTP/HTTPS Probing** - Active testing (200 workers)
10. **Wildcard DNS Filtering** - Eliminates false positives
11. **FQDN Normalization** - Deduplication and validation
12. **Advanced Enumeration** - Recursive depth-first discovery

### Security Probes (4 Types)

- **DNS Probe**: A/AAAA records, CNAME, MX, TXT records
- **HTTP Probe**: Reachability, headers, redirects, status codes
- **TLS Probe**: Certificate validation, protocol versions, cipher suites
- **Email Probe**: SPF, DMARC, DKIM, MTA-STS, TLS-RPT

### Security Checks (30+ Controls)

Organized into 7 categories:
- TLS/Certificate Security (4 checks)
- HTTP Security Headers (6 checks)
- Cookie Security (3 checks)
- Email Authentication (10+ checks)
- HTTP-to-HTTPS Redirection (1 check)
- Subdomain Takeover Detection (2 checks)
- Security Disclosure (2 checks)

---

## 📁 Directory Structure

```
lk-public-domain-security-audit/
│
├── src/                          # Main source code
│   ├── app.py                    # Main application entry point
│   ├── generate_reports.py       # Report generation with 13 publication tables
│   ├── requirements.txt          # Python dependencies
│   │
│   ├── scanner/                  # Scanning engine
│   │   ├── runner.py             # Scan orchestrator
│   │   ├── enumeration.py        # Subdomain discovery
│   │   ├── enumerator_worker.py  # Producer worker
│   │   ├── scan_worker.py        # Consumer worker
│   │   ├── advanced_enumeration.py # Recursive discovery
│   │   ├── crawl_lite.py         # HTTP crawling for subdomains
│   │   ├── normalization.py      # FQDN validation
│   │   ├── profiles.py           # Domain profiling
│   │   ├── ptr_pivot.py          # PTR record discovery
│   │   ├── srv_pivot.py          # SRV record discovery
│   │   ├── wildcard.py           # Wildcard detection
│   │   ├── xlsx_seed.py          # Excel seed file loader
│   │   │
│   │   ├── probes/               # Security probes
│   │   │   ├── dns_probe.py      # DNS resolution
│   │   │   ├── http_probe.py     # HTTP/HTTPS testing
│   │   │   ├── tls_probe.py      # TLS/certificate checks
│   │   │   └── email_probe.py    # Email security (SPF/DMARC)
│   │   │
│   │   ├── checks/               # Security check evaluators
│   │   │   ├── registry.py       # Check catalog
│   │   │   ├── evaluator.py      # Check evaluation logic
│   │   │   └── advanced_checks.py # Complex checks
│   │   │
│   │   ├── scoring/              # Risk scoring
│   │   │   └── model.py          # Scoring algorithms
│   │   │
│   │   └── output/               # Output generation
│   │       └── writer.py         # CSV/Excel/JSON export
│   │
│   ├── state/                    # State management
│   │   └── state_manager.py      # SQLite-based persistence
│   │
│   ├── util/                     # Utilities
│   │   ├── cache.py              # TTL-based caching
│   │   ├── concurrency.py        # Rate limiting
│   │   ├── config.py             # Configuration management
│   │   ├── env.py                # Environment variables
│   │   ├── io.py                 # File I/O helpers
│   │   ├── log.py                # Logging setup
│   │   ├── time.py               # Time utilities
│   │   └── types.py              # Type definitions
│   │
│   └── tests/                    # Unit tests
│       └── test_security_scanner.py
│
├── state/                        # Persistent state storage
│   └── ac.lk/                    # Per-domain state
│       └── state.db              # SQLite database
│
├── out/                          # Output directory
│   └── ac.lk/                    # Per-domain outputs
│       └── YYYY-MM-DD/           # Date-based runs
│           └── YYYYMMDD_HHMMSS/  # Timestamped results
│
├── run.sh                        # Main execution script (does everything!)
├── .env                          # Environment configuration
└── README.md                     # This file
```

---

## 🔧 Core Components

### 1. State Manager (`state/state_manager.py`)

**Purpose**: Persistent state management using SQLite

**Key Features**:
- WAL mode for concurrent reads + single writer
- Atomic queue operations (no race conditions)
- Tables: `meta`, `candidates`, `scan_queue`, `scan_runs`, `scan_results`
- Crash recovery via lease timeouts
- Configurable rescan intervals

**Database Schema**:
```sql
-- Configuration and metadata
CREATE TABLE meta (
    key TEXT PRIMARY KEY,
    value TEXT
);

-- All discovered subdomains
CREATE TABLE candidates (
    fqdn TEXT PRIMARY KEY,
    discovered_at TEXT,
    discovery_method TEXT
);

-- Scan queue with status tracking
CREATE TABLE scan_queue (
    fqdn TEXT PRIMARY KEY,
    status TEXT,  -- 'pending', 'scanning', 'completed', 'error'
    last_scan_at TEXT,
    lease_expires_at TEXT,
    retry_count INTEGER
);

-- Audit log of scan runs
CREATE TABLE scan_runs (
    run_id TEXT PRIMARY KEY,
    started_at TEXT,
    finished_at TEXT,
    config TEXT
);

-- Results per (fqdn, run_id)
CREATE TABLE scan_results (
    fqdn TEXT,
    run_id TEXT,
    check_id TEXT,
    status TEXT,
    reason_code TEXT,
    PRIMARY KEY (fqdn, run_id, check_id)
);
```

### 2. Enumerator Worker (`scanner/enumerator_worker.py`)

**Purpose**: Producer - discovers subdomains and writes to DB

**Discovery Methods**:
1. Certificate Transparency logs
2. DNS brute force (18,953 patterns)
3. SRV record pivoting (34 services)
4. PTR record pivoting
5. HTTP crawling (HTML/JS/CSP)
6. XLSX seed loading

**Output**: Writes candidates to `state.db`

### 3. Scanner Worker (`scanner/scan_worker.py`)

**Purpose**: Consumer - scans targets and writes results

**Workflow**:
1. Claims eligible targets from DB (atomic lease)
2. Runs 4 probes (DNS, HTTP, TLS, Email)
3. Evaluates 30+ security checks
4. Computes risk scores
5. Writes results to DB
6. Marks target as completed

**Concurrency**: Configurable batch size and rate limiting

### 4. Probes System (`scanner/probes/`)

#### DNS Probe
- Resolves A/AAAA records
- Checks CNAME, MX, TXT records
- Caches results (4s timeout)

#### HTTP Probe
- Tests HTTP/HTTPS reachability
- Collects security headers
- Follows redirects (max 3)
- 8s timeout, connection pooling

#### TLS Probe
- Validates certificates
- Checks protocol versions (TLS 1.2+)
- Extracts cipher suites
- Validates hostname matching

#### Email Probe
- Parses SPF records
- Parses DMARC policies
- Checks MTA-STS
- Checks TLS-RPT

### 5. Check Evaluator (`scanner/checks/evaluator.py`)

**Purpose**: Evaluates security controls based on probe results

**Check Results**:
- **Pass**: Control is implemented correctly
- **Fail**: Control is missing or misconfigured
- **Not Tested**: Insufficient data to evaluate
- **Not Applicable**: Control doesn't apply to this target
- **Error**: Evaluation failed due to error

**Example Checks**:
```python
# TLS availability check
if tls_probe.success and tls_probe.data.get('protocol_version') in ['TLSv1.2', 'TLSv1.3']:
    return CheckResult(status=CheckStatus.PASS)
else:
    return CheckResult(status=CheckStatus.FAIL, reason_code=ReasonCode.TLS_NOT_AVAILABLE)

# HSTS header check
if 'Strict-Transport-Security' in http_headers:
    return CheckResult(status=CheckStatus.PASS)
else:
    return CheckResult(status=CheckStatus.FAIL, reason_code=ReasonCode.HSTS_MISSING)
```

### 6. Scoring Model (`scanner/scoring/model.py`)

**Purpose**: Computes risk scores with confidence metrics

**Scoring Rules**:
- Only Pass/Fail count toward score
- Not Tested = insufficient evidence (excluded)
- Error = tracked separately
- Not Applicable = excluded from scoring

**Metrics**:
- **Pass Rate**: `(passed / tested) × 100`
- **Attempt Rate**: `(tested / total) × 100`
- **Error Rate**: `(errors / total) × 100`

**Risk Levels**:
- **Low**: Pass rate ≥ 90%
- **Medium**: 70% ≤ Pass rate < 90%
- **High**: 50% ≤ Pass rate < 70%
- **Critical**: Pass rate < 50%
- **Unknown**: < 3 tested checks

### 7. Output Writer (`scanner/output/writer.py`)

**Purpose**: Exports results to multiple formats

**Output Files**:
- `observations_long.csv` - All check results (long format)
- `subdomain_metrics.csv` - Per-subdomain scores
- `discovered_candidates.csv` - All discovered FQDNs
- `errors.csv` - Scan errors and failures
- `control_metrics.csv` - Aggregate statistics per check
- `enumeration_method_counts.csv` - Discovery method effectiveness
- `run_metadata.json` - Run configuration and metadata
- `domain_summary.json` - High-level summary

---

## 🔒 Security Checks

### TLS/Certificate Security (4 checks)

| Check ID | Name | Description |
|----------|------|-------------|
| `TLS_AVAILABLE` | TLS Service Available | HTTPS endpoint reachable |
| `TLS_MIN_VERSION` | Minimum TLS Version | TLS 1.2 or higher |
| `CERT_VALID_DATES` | Certificate Valid Dates | Certificate not expired |
| `CERT_HOSTNAME_MATCH` | Certificate Hostname Match | Certificate CN/SAN matches FQDN |

### HTTP Security Headers (6 checks)

| Check ID | Name | Description |
|----------|------|-------------|
| `HSTS_PRESENT` | HSTS Header Present | Strict-Transport-Security header |
| `CSP_PRESENT` | CSP Header Present | Content-Security-Policy header |
| `X_FRAME_OPTIONS` | X-Frame-Options | Clickjacking protection |
| `X_CONTENT_TYPE_OPTIONS` | X-Content-Type-Options | MIME sniffing protection |
| `REFERRER_POLICY` | Referrer-Policy | Referrer leakage control |
| `PERMISSIONS_POLICY` | Permissions-Policy | Feature policy restrictions |

### Cookie Security (3 checks)

| Check ID | Name | Description |
|----------|------|-------------|
| `COOKIE_SECURE` | Secure Cookie Flag | Cookies have Secure flag |
| `COOKIE_HTTPONLY` | HttpOnly Cookie Flag | Cookies have HttpOnly flag |
| `COOKIE_SAMESITE` | SameSite Cookie Attribute | CSRF protection via SameSite |

### Email Authentication (10+ checks)

| Check ID | Name | Description |
|----------|------|-------------|
| `SPF_PRESENT` | SPF Record Present | SPF record exists |
| `SPF_POLICY` | SPF Policy Valid | SPF policy is valid |
| `SPF_SINGLE_RECORD` | Single SPF Record | Only one SPF record |
| `SPF_LOOKUP_LIMIT_OK` | SPF Lookup Limit | < 10 DNS lookups |
| `SPF_TERMINAL_POLICY` | SPF Terminal Policy | -all or ~all |
| `DMARC_PRESENT` | DMARC Record Present | DMARC record exists |
| `DMARC_POLICY` | DMARC Policy Valid | DMARC policy is valid |
| `DMARC_POLICY_STRONG` | DMARC Policy Strong | p=quarantine or p=reject |
| `MTA_STS_PRESENT` | MTA-STS Present | MTA-STS policy exists |
| `MTA_STS_MODE_ENFORCE` | MTA-STS Enforce Mode | mode=enforce |
| `TLS_RPT_PRESENT` | TLS-RPT Present | TLS reporting configured |

### Subdomain Takeover (2 checks)

| Check ID | Name | Description |
|----------|------|-------------|
| `TAKEOVER_DANGLING_CNAME` | Dangling CNAME | CNAME points to unresolved host |
| `TAKEOVER_UNCLAIMED_SIGNATURE` | Unclaimed Service Signature | Service-specific takeover signatures |

### Security Disclosure (2 checks)

| Check ID | Name | Description |
|----------|------|-------------|
| `SECURITY_TXT_PRESENT` | security.txt Present | security.txt file exists |
| `SECURITY_TXT_CONTACT_VALID` | security.txt Contact Valid | Valid contact in security.txt |

### Redirect Security (1 check)

| Check ID | Name | Description |
|----------|------|-------------|
| `HTTP_TO_HTTPS_REDIRECT` | HTTP to HTTPS Redirect | HTTP redirects to HTTPS |

---

## 🔄 Data Flow

```
1. INITIALIZATION
   ├── Load .env configuration
   ├── Initialize StateManager (SQLite)
   ├── Create scan run record
   └── Reset enumeration_done flag

2. PARALLEL EXECUTION
   ├── ENUMERATOR WORKER (Producer)
   │   ├── Certificate Transparency logs
   │   ├── DNS brute force (18,953 patterns)
   │   ├── SRV record pivoting
   │   ├── PTR record pivoting
   │   ├── HTTP crawling
   │   ├── XLSX seed loading
   │   └── Write candidates → state.db
   │
   └── SCANNER WORKER (Consumer)
       ├── Claim eligible targets ← state.db
       ├── Run probes (DNS/HTTP/TLS/Email)
       ├── Evaluate security checks
       ├── Compute risk scores
       ├── Write results → state.db
       └── Mark completed → state.db

3. EXPORT RESULTS
   ├── Read all results from state.db
   ├── Generate CSV files
   ├── Generate JSON summary
   └── Write to out/ac.lk/YYYY-MM-DD/YYYYMMDD_HHMMSS/

4. REPORT GENERATION
   ├── generate_reports.py → HTML/Excel reports
   └── generate_paper_tables.py → Academic tables
```

---

## 🚀 Installation & Setup

### Prerequisites

- Python 3.8 or higher
- Virtual environment (venv or conda)
- Unix-like system (macOS, Linux) or WSL on Windows

### Step 1: Clone Repository

```bash
git clone https://github.com/LalithK90/lk-public-domain-security-audit.git
cd lk-public-domain-security-audit
```

### Step 2: Create Environment File

Create a `.env` file in the project root:

```bash
# Required
DOMAIN=ac.lk

# Optional (with defaults)
OUT_DIR=out
STATE_DIR=state
ENABLE_EXCEL=false
MAX_WORKERS=200
RATE_LIMIT_DELAY=0.05
RESCAN_HOURS=24
ERROR_RETRY_HOURS=6
CACHE_TTL_HOURS=24
LOG_LEVEL=INFO
```

### Step 3: Run Setup Script

The `run.sh` script handles everything:

```bash
chmod +x run.sh
./run.sh
```

This will:
1. Check for Python 3
2. Create virtual environment (`.venv/`)
3. Install dependencies from `src/requirements.txt`
4. Run the scanner

### Manual Setup (Alternative)

```bash
# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -r src/requirements.txt

# Run scanner
python src/app.py
```

---

## 📖 Usage

### Basic Scan

```bash
# Use run.sh (recommended) - does everything automatically!
./run.sh

# This will:
# 1. Setup Python environment
# 2. Run security scan (src/app.py)
# 3. Generate comprehensive reports (src/generate_reports.py)
# All reports saved to: out/{domain}/{date}/{run_id}/report.md
```

### Resume Interrupted Scan

The scanner automatically resumes from where it left off:

```bash
# Just run again - it will skip completed targets and regenerate reports
./run.sh
```

### Force Rescan All Targets

```bash
# Set force rescan in .env
echo "FORCE_RESCAN=true" >> .env
./run.sh
```

### Scan Different Domain

```bash
# Edit .env
echo "DOMAIN=gov.lk" > .env

# Run scanner
./run.sh
```

---

## 📊 Output Files

All results are written to: `out/<domain>/YYYY-MM-DD/YYYYMMDD_HHMMSS/`

### Report File

#### `report.md` (NEW - Comprehensive Report with 13 Tables)

Auto-generated after every scan with complete analysis including:

**Run Report Section**:
- Run metadata (date, duration, configuration)
- Aggregation metrics (DNS vs TLS)
- Error breakdown
- Risk level distribution
- Top problematic checks
- Enumeration method counts

**Publication Tables Section** (13 Professional Tables):

1. **Table 1**: Run & dataset overview
2. **Table 2**: DNS discovery vs TLS evidence aggregation
3. **Table 3**: Observation outcome distribution
4. **Table 4**: Error reason breakdown
5. **Table 5**: Risk-level distribution
6. **Table 6**: Top failing checks (worst performers)
7. **Table 7**: Enumeration method contribution
8. **Table 8**: Protocol breakdown by category
9. **Table 9**: Subdomain pass rate distribution
10. **Table 10**: Check categories summary
11. **Table 11**: Top passing checks (best performers)
12. **Table 12**: Target scan status overview
13. **Table 13**: Attempt rate distribution analysis

**Methodology Notes**: Disclaimers about TLS and DNS interpretations

**Usage**: Ready for academic papers, presentations, compliance reports

### Core Output Files

#### 1. `observations_long.csv`
Long-format data with one row per (target, check) combination.

**Columns**:
- `target` - FQDN being checked
- `check_id` - Security check identifier
- `check_name` - Human-readable check name
- `category` - Check category
- `status` - Pass/Fail/Not Tested/Not Applicable/Error
- `reason_code` - Specific reason for status
- `timestamp` - When check was performed

**Use Case**: Detailed analysis, filtering by check or target

#### 2. `subdomain_metrics.csv`
Per-subdomain aggregated metrics.

**Columns**:
- `target` - FQDN
- `total_checks` - All checks attempted
- `tested_checks` - Checks with Pass/Fail result
- `passed_checks` - Successful checks
- `failed_checks` - Failed checks
- `not_tested_checks` - Insufficient data
- `not_applicable_checks` - Control doesn't apply
- `error_checks` - Evaluation errors
- `pass_rate` - Percentage passed (0-100)
- `attempt_rate` - Percentage tested (0-100)
- `error_rate` - Percentage errors (0-100)
- `risk_level` - Low/Medium/High/Critical/Unknown

**Use Case**: Ranking subdomains by security posture

#### 3. `discovered_candidates.csv`
All discovered subdomains with discovery metadata.

**Columns**:
- `fqdn` - Fully qualified domain name
- `discovered_at` - Timestamp of discovery
- `discovery_method` - How it was found (ct_logs, dns_brute, srv_pivot, etc.)

**Use Case**: Subdomain enumeration effectiveness analysis

#### 4. `errors.csv`
All scan errors and failures.

**Columns**:
- `target` - FQDN where error occurred
- `check_id` - Check that failed
- `error_type` - Error category
- `reason_code` - Specific error reason
- `error_message` - Detailed error message
- `timestamp` - When error occurred

**Use Case**: Debugging, reliability analysis

#### 5. `control_metrics.csv`
Aggregate statistics per security check.

**Columns**:
- `check_id` - Security check identifier
- `check_name` - Human-readable name
- `category` - Check category
- `total_evaluated` - Targets where check ran
- `passed` - Targets that passed
- `failed` - Targets that failed
- `not_applicable` - Targets where check didn't apply
- `errors` - Evaluation errors
- `pass_rate` - Aggregate pass rate (%)

**Use Case**: Overall domain security posture, compliance reporting

#### 6. `enumeration_method_counts.csv`
Effectiveness of discovery methods.

**Columns**:
- `discovery_method` - Enumeration technique
- `count` - Subdomains discovered
- `percentage` - % of total discoveries

**Use Case**: Optimizing enumeration strategy

#### 7. `run_metadata.json`
Complete run configuration and metadata.

**Structure**:
```json
{
  "run_id": "20260121_143022",
  "domain": "ac.lk",
  "started_at": "2026-01-21T14:30:22Z",
  "finished_at": "2026-01-21T16:45:18Z",
  "duration_seconds": 8096,
  "config": {
    "max_workers": 200,
    "rate_limit_delay": 0.05,
    "rescan_hours": 24,
    "cache_ttl_hours": 24
  },
  "stats": {
    "total_candidates": 1547,
    "scanned_targets": 1423,
    "total_checks": 42690,
    "passed_checks": 18234,
    "failed_checks": 12456
  }
}
```

#### 8. `domain_summary.json`
High-level domain security summary.

**Structure**:
```json
{
  "domain": "ac.lk",
  "total_subdomains": 1423,
  "overall_pass_rate": 59.4,
  "overall_attempt_rate": 87.2,
  "risk_distribution": {
    "Low": 234,
    "Medium": 512,
    "High": 445,
    "Critical": 232
  },
  "top_failures": [
    {"check_id": "HSTS_PRESENT", "fail_rate": 78.2},
    {"check_id": "CSP_PRESENT", "fail_rate": 84.5}
  ]
}
```

---

## ⚙️ Configuration

### Environment Variables (`.env`)

#### Required

```bash
# Target domain
DOMAIN=ac.lk
```

#### Optional (with defaults)

```bash
# Output directory
OUT_DIR=out                    # Default: out

# State directory
STATE_DIR=state                # Default: state

# Excel output (requires pandas/openpyxl)
ENABLE_EXCEL=false             # Default: false

# Concurrency settings
MAX_WORKERS=200                # Default: 200 (DNS/HTTP concurrency)
RATE_LIMIT_DELAY=0.05          # Default: 0.05s (delay between requests)

# Rescan policies
RESCAN_HOURS=24                # Default: 24 (hours before rescanning)
ERROR_RETRY_HOURS=6            # Default: 6 (hours before retrying errors)
LEASE_MINUTES=30               # Default: 30 (lease timeout for crash recovery)

# Caching
CACHE_TTL_HOURS=24             # Default: 24 (cache expiration)

# Logging
LOG_LEVEL=INFO                 # Default: INFO (DEBUG/INFO/WARNING/ERROR)

# Force rescan
FORCE_RESCAN=false             # Default: false (clear cache and rescan all)
```

### Performance Tuning

**For Small Domains (< 100 subdomains)**:
```bash
MAX_WORKERS=50
RATE_LIMIT_DELAY=0.1
```

**For Large Domains (> 1000 subdomains)**:
```bash
MAX_WORKERS=500
RATE_LIMIT_DELAY=0.01
RESCAN_HOURS=168  # 7 days
```

**For Rate-Limited APIs**:
```bash
MAX_WORKERS=10
RATE_LIMIT_DELAY=1.0
```

**Memory Constrained**:
```bash
MAX_WORKERS=50
SCANNER_BATCH_SIZE=10  # Smaller batches
```

---

## 🔬 Technical Details

### Subdomain Enumeration Statistics

**Pattern Generation**:
- Single chars: 26 (a-z)
- Two chars: 676 (aa-zz)
- Three chars: 17,576 (aaa-zzz)
- Numbers: 110 (0-99, 00-99)
- Letter+number: 520 (a0-z9, 0a-9z)
- Common words: 100+
- **Total: 18,953 patterns**

**SRV Services Checked** (34 total):
```
_http, _https, _ftp, _ssh, _telnet, _smtp, _pop3, _imap, _ldap, _ldaps,
_kerberos, _kpasswd, _xmpp-client, _xmpp-server, _sip, _sips, _caldav,
_carddav, _git, _svn, _mysql, _postgresql, _mongodb, _redis, _elasticsearch,
_kafka, _zookeeper, _consul, _etcd, _vault, _nomad, _prometheus, _grafana,
_kubernetes-api
```

### Performance Characteristics

**Typical Scan Times**:
- 100 subdomains: ~5-10 minutes
- 500 subdomains: ~20-30 minutes
- 1000 subdomains: ~40-60 minutes
- 5000 subdomains: ~3-5 hours

**Bottlenecks**:
1. DNS resolution (parallel: 500 workers)
2. HTTP/HTTPS probing (parallel: 200 workers)
3. TLS handshakes (sequential per target)
4. API rate limits (crt.sh, HackerTarget)

**Optimizations**:
- Aggressive caching (24h TTL)
- Connection pooling (aiohttp)
- WAL mode SQLite (concurrent reads)
- Batch processing (claim N targets at once)
- Early termination (skip rescans within interval)

### Database Performance

**SQLite Configuration**:
```sql
PRAGMA journal_mode=WAL;        -- Concurrent reads
PRAGMA synchronous=NORMAL;      -- Faster writes
PRAGMA temp_store=MEMORY;       -- In-memory temp tables
PRAGMA busy_timeout=10000;      -- 10s lock timeout
```

**Indexing**:
- `candidates(fqdn)` - PRIMARY KEY
- `scan_queue(fqdn)` - PRIMARY KEY
- `scan_queue(status, last_scan_at)` - Eligibility queries
- `scan_results(fqdn, run_id, check_id)` - PRIMARY KEY

### Security & Privacy

**User Agent**:
```
LK-Domain-Security-Research/1.0 (Academic Study; mailto:security-research@example.edu)
```

**Rate Limiting**:
- Default: 0.05s delay between requests
- Respects HTTP 429 (Too Many Requests)
- Exponential backoff on errors

**Data Collection**:
- Only collects publicly available data
- No authentication bypass attempts
- No exploitation of vulnerabilities
- Read-only operations only

---

## 📚 Research Applications

### Academic Use Cases

1. **Domain Security Posture Assessment**
   - Measure security control adoption rates
   - Identify common misconfigurations
   - Track improvements over time

2. **Enumeration Method Effectiveness**
   - Compare discovery techniques
   - Measure coverage overlap
   - Optimize for specific TLDs

3. **Risk Scoring Validation**
   - Validate scoring models
   - Correlate with known incidents
   - Benchmark against industry standards

4. **Compliance Monitoring**
   - Track regulatory compliance
   - Measure policy effectiveness
   - Identify outliers

### Paper Generation

**Report generation happens automatically** after each scan run:

```bash
# Reports are auto-generated by run.sh
./run.sh

# Output: out/{domain}/YYYY-MM-DD/YYYYMMDD_HHMMSS/report.md
# Contains all 13 publication tables (markdown format) + methodology notes
# Ready for academic papers, presentations, and compliance reports
```

**Manual report generation** (if needed):

```bash
# Generate reports for all runs of a domain
python src/generate_reports.py --domain ac.lk

# Generate report for specific run
python src/generate_reports.py --domain ac.lk --run-dir out/ac.lk/2026-01-25/20260125_065145
```

All reports are in **Markdown format** for easy integration into papers, presentations, and compliance documentation.

---

## 🧪 Testing

### Unit Tests

Located in `src/tests/test_security_scanner.py`

**Run tests**:
```bash
# Activate venv
source .venv/bin/activate

# Run pytest
pytest src/tests/ -v

# With coverage
pytest src/tests/ --cov=src --cov-report=html
```

**Test Coverage**:
- Status label validation
- Applicability rules
- Not Applicable vs Not Tested logic
- Coverage summary consistency
- Check result derivation

### Integration Testing

**Test against known domain**:
```bash
# Set test domain in .env
echo "DOMAIN=example.com" > .env
echo "MAX_WORKERS=10" >> .env

# Run scanner
./run.sh

# Verify outputs
ls -lh out/example.com/*/
```

---

## 🐛 Troubleshooting

### Common Issues

#### 1. "No targets found - aborting scan"

**Cause**: DNS resolution failures or no subdomains discovered

**Solutions**:
```bash
# Check DNS connectivity
nslookup ac.lk

# Enable debug logging
echo "LOG_LEVEL=DEBUG" >> .env
./run.sh

# Try with known subdomain
echo "SEED_SUBDOMAINS=www,mail,api" >> .env
```

#### 2. "Database is locked"

**Cause**: Multiple scanner instances running

**Solutions**:
```bash
# Kill existing processes
pkill -f "python.*app.py"

# Check for stale locks
ls -lh state/ac.lk/state.db*

# If needed, clear state
rm -rf state/ac.lk/state.db*
```

#### 3. "SSL certificate verification failed"

**Cause**: Self-signed or expired certificates

**Solutions**:
- This is expected behavior - scanner reports these as failures
- Check `errors.csv` for details
- Consider adding `IGNORE_SSL_ERRORS=true` for testing (not recommended)

#### 4. "Rate limit exceeded"

**Cause**: Too aggressive concurrency

**Solutions**:
```bash
# Reduce workers
echo "MAX_WORKERS=50" >> .env
echo "RATE_LIMIT_DELAY=0.5" >> .env
./run.sh
```

#### 5. Memory issues

**Cause**: Large domain with aggressive concurrency

**Solutions**:
```bash
# Reduce batch sizes
echo "SCANNER_BATCH_SIZE=50" >> .env
echo "MAX_WORKERS=100" >> .env
```

---

## 📄 Dependencies

### Core Dependencies

```
aiohttp>=3.9.0           # Async HTTP client
python-dotenv>=1.0.0     # Environment variables
python-dateutil>=2.8.0   # Date parsing
dnspython>=2.3.0         # DNS resolution
```

### Optional Dependencies

```
openpyxl>=3.1.0          # Excel output
pandas>=2.0.0            # Data analysis
tabulate>=0.9.0          # Table formatting
pytest>=7.0.0            # Testing
pytest-cov>=4.0.0        # Coverage
```

### Installation

```bash
# Core only
pip install -r src/requirements.txt

# With optional
pip install -r src/requirements.txt openpyxl pandas tabulate

# Development
pip install -r src/requirements.txt pytest pytest-cov
```

---

## 📝 License & Citation

### License

This is an academic research project. Please contact the authors for usage permissions.

### Citation

If you use this tool in your research, please cite:

```bibtex
@misc{lk-domain-security-audit,
  title={Large-Scale Security Assessment of .LK Public Domains},
  author={[KRAL Kahatapitiya, ]},
  year={2026},
  publisher={GitHub},
  howpublished={\url{https://github.com/lalithk90/lk-public-domain-security-audit}}
}
```

---

## 🤝 Contributing

This is an academic research project. Contributions are welcome via:

1. Bug reports
2. Feature requests
3. Documentation improvements
4. New security checks
5. Performance optimizations

Please open an issue first to discuss major changes.

---

## 📞 Contact

For questions, issues, or collaboration:

- **Project**: LK Public Domain Security Audit
- **Purpose**: Academic research on domain security
- **Email**: askahatapitiya@gmail.com
- **GitHub**: [Project Repository](https://github.com/LalithK90/lk-public-domain-security-audit)

---

## 📅 Version History

### v1.0 (Current)
- Initial release
- 30+ security checks across 7 categories
- 12 subdomain discovery methods
- SQLite-based persistent state
- Parallel producer-consumer architecture
- Comprehensive CSV/JSON output
- Academic paper table generation

---

## 🙏 Acknowledgments

- Certificate Transparency logs (crt.sh)
- HackerTarget API
- ThreatCrowd API
- Python community (aiohttp, dnspython, etc.)
- SQLite project
- Academic research community

---

**End of Documentation**
