# Security Scanner - Complete Scoring Guide

## 📊 Table of Contents
1. [Overview](#overview)
2. [How Scoring Works](#how-scoring-works)
3. [Category Weights](#category-weights)
4. [Context-Aware Scoring](#context-aware-scoring)
5. [Risk Rating System](#risk-rating-system)
6. [Implementation Details](#implementation-details)
7. [Excel Report Structure](#excel-report-structure)
8. [Usage Guide](#usage-guide)

---

## Overview

The security scanner evaluates **106 security parameters** across **20 categories** and calculates a **final score out of 100 points** using a weighted scoring system with context-aware adjustments.

### Key Features:
- ✅ **Comprehensive Coverage**: All 106 parameters included in scoring (100% coverage)
- ✅ **Context-Aware Weights**: Different priorities for webapp/api/static/other types
- ✅ **Risk Rating**: Automatic Critical/High/Medium/Low classification
- ✅ **Type-Specific Rankings**: Separate sheets for each subdomain type

---

## How Scoring Works

### Step 1: Security Checks Execution

The scanner runs **106 security checks** on each subdomain:

```
Example Subdomain: portal.example.com
├── TLS & Certificates (7 checks)
│   ├── TLS-1: TLS 1.2+ enforced ✅ Pass
│   ├── CERT-1: Valid cert chain ✅ Pass
│   ├── TLS-2: OCSP stapling ❌ Fail
│   └── ... (4 more checks)
├── HTTP Security Headers (15 checks)
│   ├── HTTPS-1: HTTPS enforced ✅ Pass
│   ├── HSTS-1: HSTS configured ❌ Fail
│   └── ... (13 more checks)
├── Authentication & Sessions (10 checks)
│   ├── AUTH-1: Session timeout ✅ Pass
│   └── ... (9 more checks)
└── ... (17 more categories)
```

### Step 2: Subdomain Type Classification

Each subdomain is automatically classified based on detected characteristics:

| Type | Detection Logic | Example |
|------|-----------------|---------|
| **webapp** | Has forms, login pages, dashboards | portal.example.com, admin.example.com |
| **api** | JSON content, /api/ paths, Swagger docs | api.example.com, rest.example.com |
| **static** | CDN, static assets, no dynamic content | cdn.example.com, assets.example.com |
| **other** | Email servers, DNS, load balancers | mail.example.com, ns1.example.com |

### Step 3: Category Scoring with Context-Aware Weights

For each of the **20 security categories**, the score is calculated as:

```
Category Score = (Checks Passed / Total Checks in Category) × Category Weight
```

**The category weight varies based on subdomain type!**

#### Example: Authentication & Sessions Category

**For a WebApp** (portal.example.com):
```python
Checks in Category: 10
Checks Passed: 7
Pass Rate: 7/10 = 70%
Category Weight: 15% (High priority for webapps)
Category Score: 0.70 × 15 = 10.5 points
```

**For Static Content** (cdn.example.com):
```python
Checks in Category: 10
Checks Passed: 1
Pass Rate: 1/10 = 10%
Category Weight: 2% (Low priority for static)
Category Score: 0.10 × 2 = 0.2 points
```

**Same failed checks, different impact based on subdomain type!**

### Step 4: Total Score Calculation

Sum all 20 category scores:

```python
Total Score = Sum of all Category Scores (0-100)

Example WebApp Score:
  TLS & Certificates:        8.5 / 10   (85% × 10 weight)
  HTTP Security Headers:    10.2 / 12   (85% × 12 weight)
  Authentication & Sessions: 10.5 / 15   (70% × 15 weight)
  Input Validation:          9.6 / 12   (80% × 12 weight)
  ... (16 more categories)
  ─────────────────────────────────────
  Total Score:              72.4 / 100
```

### Step 5: Risk Rating Assignment

Based on the total score and subdomain type:

```python
if subdomain_type in ['webapp', 'api']:
    if score >= 80: risk = 'Low'
    elif score >= 60: risk = 'Medium'
    elif score >= 40: risk = 'High'
    else: risk = 'Critical'
elif subdomain_type == 'static':
    if score >= 70: risk = 'Low'
    elif score >= 50: risk = 'Medium'
    elif score >= 30: risk = 'High'
    else: risk = 'Critical'
else:  # other
    if score >= 60: risk = 'Low'
    elif score >= 40: risk = 'Medium'
    elif score >= 20: risk = 'High'
    else: risk = 'Critical'
```

---

## Category Weights

### All 20 Categories and Their Checks

| **Category** | **Checks** | **Check IDs** |
|--------------|------------|---------------|
| **TLS & Certificates** | 7 | TLS-1, CERT-1, TLS-2, CERT-2, FS-1, WC-1, HSTS-2 |
| **HTTP Security Headers** | 15 | HTTPS-1, HSTS-1, CSP-1, XFO-1, XCTO-1, XXP-1, RP-1, PP-1, HEADER-1, HEADER-2, HEADER-3, HEADER-5, HEADER-6, HEADER-7, CORS-1 |
| **Authentication & Sessions** | 10 | AUTH-1, AUTH-2, AUTH-3, AUTH-4, AUTH-5, AUTH-6, AUTH-7, SESSION-1, COO-1, SAMESITE-1 |
| **Input Validation** | 9 | INPUT-1, INPUT-2, INPUT-3, INPUT-4, INPUT-5, INPUT-6, INPUT-7, INPUT-8, INPUT-9 |
| **Access Control** | 6 | AUTHZ-1, AUTHZ-2, AUTHZ-3, AUTHZ-4, AUTHZ-5, AUTHZ-6 |
| **Encryption & Data** | 2 | ENCRYPT-1, ENCRYPT-2 |
| **Logging & Monitoring** | 4 | LOG-1, LOG-2, LOG-3, LOG-4 |
| **Cloud & Infrastructure** | 4 | CLOUD-1, CLOUD-2, CLOUD-3, SERVER-1 |
| **DNS & Email Security** | 7 | DNS-1, SPF-1, DMARC-1, DNS-2, MX-1, DNS-3, DNS-4 |
| **File & Directory Security** | 7 | DIR-1, ADMIN-1, ROBOTS-1, SEC-1, BACKUP-1, GIT-1, CONFIG-1 |
| **Information Disclosure** | 6 | SI-1, TITLE-1, ETag-1, ERROR-1, HEADER-4, ERROR-2 |
| **Performance & Caching** | 2 | Cache-1, CACHE-2 |
| **Redirect Security** | 2 | REDIR-1, REDIR-2 |
| **Content Security** | 5 | SR-1, SRI-2, MIME-1, MIXED-1, THIRD-1 |
| **API Security** | 3 | API-1, API-2, HTTP2-1 |
| **Advanced Controls** | 2 | WAF-1, REPORT-1 |
| **Compliance & Standards** | 6 | COMP-1, COMP-2, COMP-3, COMP-4, COMP-5, COMP-6 |
| **Subdomain Security** | 2 | SUB-1, SUB-2 |
| **WAF & DDoS Protection** | 2 | WAF-2, DDoS-1 |
| **Third-Party Security** | 2 | THIRD-2, THIRD-3 |
| **TOTAL** | **106** | Complete coverage |

---

## Context-Aware Scoring

### Why Context Matters

Not all security checks are equally important for all subdomain types. Example:

**Authentication Security:**
- **Critical for webapps** (users login, sessions, passwords)
- **Critical for APIs** (token authentication, OAuth)
- **Less critical for static sites** (no user login)
- **Not applicable for email servers** (different auth mechanism)

### Weight Distribution by Subdomain Type

#### 🌐 WebApp Weights (Interactive Applications)

| Category | Weight | Why? |
|----------|--------|------|
| Authentication & Sessions | **15%** | 🔴 Users login, session management critical |
| Input Validation | **12%** | 🔴 SQL injection, XSS protection |
| HTTP Security Headers | **12%** | 🔴 Browser-level protection |
| TLS & Certificates | **10%** | 🟡 Foundation for secure communication |
| Access Control | **8%** | 🟡 Authorization, privilege management |
| File & Directory Security | **6%** | 🟡 Prevent information leakage |
| DNS & Email Security | **5%** | 🟢 Domain-level protection |
| Information Disclosure | **5%** | 🟢 Metadata protection |
| Logging & Monitoring | **5%** | 🟢 Audit trails |
| Content Security | **4%** | 🟢 Resource integrity |
| Encryption & Data | **4%** | 🟢 Data protection |
| Compliance & Standards | **4%** | 🟢 Legal/regulatory |
| Cloud & Infrastructure | **3%** | 🟢 Deployment security |
| Redirect Security | **3%** | 🟢 Phishing prevention |
| API Security | **2%** | ⚪ Less relevant |
| Advanced Controls | **2%** | ⚪ Additional protections |
| WAF & DDoS Protection | **2%** | ⚪ Infrastructure defense |
| Third-Party Security | **2%** | ⚪ Supply chain |
| Performance & Caching | **1%** | ⚪ Efficiency |
| Subdomain Security | **1%** | ⚪ Takeover prevention |
| **TOTAL** | **100%** | |

#### 🔌 API Weights (Programmatic Access)

| Category | Weight | Why? |
|----------|--------|------|
| TLS & Certificates | **15%** | 🔴 Foundation for secure APIs |
| Authentication & Sessions | **15%** | 🔴 Token security, OAuth |
| Input Validation | **12%** | 🔴 Injection prevention |
| Access Control | **10%** | 🔴 Authorization critical |
| HTTP Security Headers | **10%** | 🟡 API-specific headers |
| Logging & Monitoring | **8%** | 🟡 Audit trails essential |
| API Security | **8%** | 🟡 Rate limiting, versioning |
| Cloud & Infrastructure | **5%** | 🟢 Modern deployments |
| Encryption & Data | **5%** | 🟢 Data protection |
| File & Directory Security | **4%** | 🟢 Config file exposure |
| DNS & Email Security | **3%** | 🟢 Domain protection |
| Information Disclosure | **3%** | 🟢 Error handling |
| Advanced Controls | **3%** | 🟢 CORS, security features |
| WAF & DDoS Protection | **3%** | 🟢 Infrastructure defense |
| Third-Party Security | **3%** | 🟢 Dependencies |
| Compliance & Standards | **3%** | 🟢 Legal requirements |
| Content Security | **2%** | ⚪ Less relevant for APIs |
| Performance & Caching | **1%** | ⚪ Efficiency |
| Redirect Security | **1%** | ⚪ Minimal redirects |
| Subdomain Security | **1%** | ⚪ Takeover prevention |
| **TOTAL** | **100%** | |

#### 📄 Static Content Weights (CDN, Assets)

| Category | Weight | Why? |
|----------|--------|------|
| HTTP Security Headers | **18%** | 🔴 Browser protection crucial |
| TLS & Certificates | **15%** | 🔴 Encrypted delivery |
| Content Security | **10%** | 🔴 Resource integrity |
| DNS & Email Security | **8%** | 🟡 Domain configuration |
| File & Directory Security | **8%** | 🟡 Directory listing |
| Information Disclosure | **7%** | 🟡 Metadata leakage |
| Performance & Caching | **5%** | 🟡 Important for static |
| Cloud & Infrastructure | **5%** | 🟢 CDN configuration |
| Compliance & Standards | **4%** | 🟢 Privacy policies |
| Third-Party Security | **4%** | 🟢 CDN dependencies |
| Encryption & Data | **3%** | 🟢 Data protection |
| Logging & Monitoring | **3%** | 🟢 Access logs |
| Advanced Controls | **2%** | ⚪ Additional security |
| Authentication & Sessions | **2%** | ⚪ Not applicable |
| WAF & DDoS Protection | **2%** | ⚪ Infrastructure |
| Redirect Security | **2%** | ⚪ Minimal redirects |
| Access Control | **2%** | ⚪ Not applicable |
| Input Validation | **2%** | ⚪ No input processing |
| API Security | **1%** | ⚪ Not applicable |
| Subdomain Security | **1%** | ⚪ Takeover prevention |
| **TOTAL** | **100%** | |

#### 🔧 Other Types (Email, DNS, etc.)

| Category | Weight | Why? |
|----------|--------|------|
| TLS & Certificates | **20%** | 🔴 Foundation |
| DNS & Email Security | **15%** | 🔴 Core functionality |
| HTTP Security Headers | **15%** | 🟡 When applicable |
| Subdomain Security | **5%** | 🟡 Takeover risks |
| All others | **3-5%** | 🟢 Balanced approach |
| **TOTAL** | **100%** | |

---

## Risk Rating System

### Risk Thresholds by Type

Risk ratings are **context-aware** - the same score gets different risk ratings based on subdomain type:

#### WebApp & API (Strict Thresholds)

```
Score ≥ 80  → ✅ Low Risk       (Good security posture)
Score 60-79 → ⚠️  Medium Risk    (Needs improvement)
Score 40-59 → 🔴 High Risk      (Significant vulnerabilities)
Score < 40  → 💀 Critical Risk  (Immediate action required)
```

**Why strict?** WebApps and APIs handle user data, authentication, and have high attack surface.

#### Static Content (Moderate Thresholds)

```
Score ≥ 70  → ✅ Low Risk       (Acceptable security)
Score 50-69 → ⚠️  Medium Risk    (Some improvements needed)
Score 30-49 → 🔴 High Risk      (Security gaps present)
Score < 30  → 💀 Critical Risk  (Major issues)
```

**Why moderate?** Static sites have no user input processing, limited attack surface.

#### Other Types (Relaxed Thresholds)

```
Score ≥ 60  → ✅ Low Risk       (Adequate security)
Score 40-59 → ⚠️  Medium Risk    (Room for improvement)
Score 20-39 → 🔴 High Risk      (Security concerns)
Score < 20  → 💀 Critical Risk  (Serious issues)
```

**Why relaxed?** Email servers, DNS have different security models.

### Real-World Example

**Scenario:** Both subdomains score 65/100

```
portal.example.com (webapp) - Score: 65
  → Risk Rating: Medium Risk ⚠️
  → Reason: WebApp handles user login, needs better security
  → Action: Improve authentication and input validation

cdn.example.com (static) - Score: 65
  → Risk Rating: Low Risk ✅
  → Reason: Static content, no user interaction
  → Action: Maintain current security level
```

---

## Implementation Details

### Code Location: `security_scanner.py`

#### 1. Category Definitions (Lines 827-888)

```python
CATEGORIES = {
    'TLS & Certificates': {
        'weight': 12,  # Default weight
        'checks': ['TLS-1', 'CERT-1', 'TLS-2', 'CERT-2', 'FS-1', 'WC-1', 'HSTS-2']
    },
    'HTTP Security Headers': {
        'weight': 15,
        'checks': ['HTTPS-1', 'HSTS-1', 'CSP-1', ... (15 checks)]
    },
    # ... 18 more categories
}
```

#### 2. Context-Aware Weights (Lines 889-988)

```python
CONTEXT_WEIGHTS = {
    'webapp': {
        'TLS & Certificates': 10,
        'HTTP Security Headers': 12,
        'Authentication & Sessions': 15,  # Higher for webapps!
        # ... all 20 categories
    },
    'api': {
        'TLS & Certificates': 15,
        'Authentication & Sessions': 15,
        'API Security': 8,  # Much higher for APIs!
        # ... all 20 categories
    },
    'static': { ... },
    'other': { ... }
}
```

#### 3. Score Computation Function (Lines 1401-1434)

```python
def compute_scores(all_checks, subdomain_type='other'):
    """
    Compute category and total scores with context-aware weights.
    
    Args:
        all_checks: Dict of check results {check_id: True/False}
        subdomain_type: 'webapp', 'api', 'static', or 'other'
    
    Returns:
        scores: Dict of category scores
        total_score: Total score (0-100)
        risk_rating: 'Critical', 'High', 'Medium', or 'Low'
    """
    scores = {}
    total_score = 0
    
    # Get context-aware weights for this type
    weights = CONTEXT_WEIGHTS.get(subdomain_type, {})
    
    for cat, info in CATEGORIES.items():
        # Get checks for this category
        cat_checks = [all_checks.get(check, False) for check in info['checks']]
        
        if len(cat_checks) > 0:
            # Calculate pass rate
            pass_rate = sum(cat_checks) / len(cat_checks)
            
            # Use context-aware weight or default
            weight = weights.get(cat, info['weight'])
            
            # Calculate category score
            cat_score = pass_rate * weight
        else:
            cat_score = 0
        
        scores[cat] = round(cat_score, 2)
        total_score += cat_score
    
    # Calculate risk rating
    risk_rating = calculate_risk_rating(total_score, subdomain_type)
    
    return scores, round(total_score, 2), risk_rating
```

#### 4. Risk Rating Function (Lines 1437-1473)

```python
def calculate_risk_rating(score, subdomain_type):
    """Calculate risk rating based on score and type."""
    
    if subdomain_type in ['webapp', 'api']:
        # Strict thresholds
        if score >= 80: return 'Low'
        elif score >= 60: return 'Medium'
        elif score >= 40: return 'High'
        else: return 'Critical'
    
    elif subdomain_type == 'static':
        # Moderate thresholds
        if score >= 70: return 'Low'
        elif score >= 50: return 'Medium'
        elif score >= 30: return 'High'
        else: return 'Critical'
    
    else:  # other
        # Relaxed thresholds
        if score >= 60: return 'Low'
        elif score >= 40: return 'Medium'
        elif score >= 20: return 'High'
        else: return 'Critical'
```

---

## Excel Report Structure

### Complete Report Sheets (11 Total)

#### Core Data Sheets:
1. **Security Results** - All subdomains with complete scores
2. **Active Subdomains** - Subdomains with active web services
3. **Inactive Subdomains** - Subdomains with DNS only (no web service)
4. **Summary By Type** - Statistics grouped by subdomain type

#### NEW: Type-Specific Ranking Sheets:
5. **WEBAPP RANKING** - Web applications sorted by score (best to worst)
6. **API RANKING** - APIs sorted by score
7. **STATIC RANKING** - Static content sorted by score
8. **OTHER RANKING** - Other services sorted by score

#### Analysis Sheets:
9. **Discovery Stats** - Subdomain discovery metrics and technology detection
10. **Technologies** - Detected technology stack per subdomain
11. **Checklist** - Reference of all 106 security parameters

### Columns in Ranking Sheets:

```
Rank | Subdomain | Type | Total_Score | Risk_Rating | Scan_Success | [106 check columns]
-----|-----------|------|-------------|-------------|--------------|---------------------
1    | portal... | webapp | 87.42      | Low         | True         | TLS-1_Pass: Yes...
2    | app...    | webapp | 82.15      | Low         | True         | TLS-1_Pass: Yes...
3    | admin...  | webapp | 67.89      | Medium      | True         | TLS-1_Pass: No...
...
```

---

## Usage Guide

### Running a Scan

```bash
# Basic scan
python security_scanner.py example.com

# Output: example.com_security_report.xlsx
```

### Understanding Your Report

#### 1. Open the Excel File

```bash
open example.com_security_report.xlsx
```

#### 2. Check Summary By Type Sheet

This shows overall statistics:

```
Type    | Count | Avg_Score | Median_Score | Max_Score | Min_Score
--------|-------|-----------|--------------|-----------|----------
webapp  | 15    | 72.5      | 74.2         | 91.3      | 34.1
api     | 8     | 81.2      | 82.5         | 95.7      | 45.3
static  | 25    | 68.9      | 70.1         | 88.4      | 52.6
other   | 7     | 55.3      | 56.8         | 72.1      | 38.9
```

**Insights:**
- APIs have highest average score (81.2) - Good!
- WebApps have one very low score (34.1) - Investigate!
- Static content is consistent - Good baseline

#### 3. Review Type-Specific Rankings

**Go to WEBAPP RANKING sheet:**

```
Rank | Subdomain           | Score | Risk    | Key Issues
-----|---------------------|-------|---------|---------------------------
1    | portal.example.com  | 91.3  | Low     | Excellent security ✅
2    | app.example.com     | 87.5  | Low     | Very good ✅
...
14   | test.example.com    | 45.2  | High    | Missing: AUTH-1, INPUT-1 🔴
15   | legacy.example.com  | 34.1  | Critical| Major gaps! 💀
```

**Prioritize:**
1. Fix `legacy.example.com` (Critical Risk)
2. Improve `test.example.com` (High Risk)
3. Review Medium Risk items
4. Maintain Low Risk items

#### 4. Understand Individual Scores

**Click on `legacy.example.com` row:**

```
Category Breakdown:
  TLS & Certificates: 4.2 / 10 (42% pass rate × 10 weight)
  HTTP Security Headers: 3.6 / 12 (30% pass rate × 12 weight)
  Authentication: 3.0 / 15 (20% pass rate × 15 weight) ← Major issue!
  Input Validation: 2.4 / 12 (20% pass rate × 12 weight) ← Major issue!
  ...

Failed Checks:
  AUTH-1: No session timeout ❌
  AUTH-2: No CSRF protection ❌
  INPUT-1: SQL injection risk ❌
  INPUT-2: XSS vulnerability ❌
```

**Action Plan:**
1. Implement session timeout (AUTH-1)
2. Add CSRF tokens (AUTH-2)
3. Add SQL injection protection (INPUT-1)
4. Implement XSS filters (INPUT-2)

#### 5. Compare with Best Performers

**Compare `legacy.example.com` (34.1) with `portal.example.com` (91.3):**

```
What portal.example.com does right:
  ✅ Strong authentication (AUTH-1 to AUTH-7 all pass)
  ✅ Input validation (INPUT-1 to INPUT-9 all pass)
  ✅ Proper headers (CSP, HSTS, XFO, etc.)
  ✅ TLS 1.3 with forward secrecy

Replicate these practices on legacy.example.com!
```

### Interpreting Scores

| Score Range | Webapp/API Risk | Static Risk | Action Required |
|-------------|----------------|-------------|-----------------|
| 90-100 | ✅ Low | ✅ Low | Excellent - Maintain |
| 80-89 | ✅ Low | ✅ Low | Very Good - Minor improvements |
| 70-79 | ⚠️ Medium | ✅ Low | Good - Some gaps to address |
| 60-69 | ⚠️ Medium | ⚠️ Medium | Fair - Improvement needed |
| 50-59 | 🔴 High | ⚠️ Medium | Poor - Significant gaps |
| 40-49 | 🔴 High | 🔴 High | Bad - Major vulnerabilities |
| 30-39 | 💀 Critical | 🔴 High | Critical - Immediate action |
| 0-29 | 💀 Critical | 💀 Critical | Severe - Emergency |

### Quick Wins for Score Improvement

**High Impact, Low Effort:**
1. **Enable HTTPS redirect** (HTTPS-1) → +10-15 points
2. **Add HSTS header** (HSTS-1) → +8-12 points
3. **Configure CSP** (CSP-1) → +5-10 points
4. **Set secure cookie flags** (COO-1) → +3-5 points
5. **Remove server header** (SI-1) → +2-3 points

**Medium Impact, Medium Effort:**
1. **Implement CSRF protection** (AUTH-2) → +8-12 points
2. **Add input validation** (INPUT-1 to INPUT-9) → +15-20 points
3. **Configure session timeout** (AUTH-1) → +5-8 points
4. **Enable TLS 1.3** (TLS-1) → +10-15 points

**High Impact, High Effort:**
1. **Implement MFA** (AUTH-4) → +10-15 points
2. **Add comprehensive logging** (LOG-1 to LOG-4) → +8-12 points
3. **Implement rate limiting** (API-1) → +5-10 points
4. **Add WAF** (WAF-1, WAF-2) → +5-8 points

---

## Frequently Asked Questions

### Q1: Why does my static site have a lower score than my webapp?

**A:** Different types have different requirements. A static site scoring 65 might be rated "Low Risk" while a webapp at 65 is "Medium Risk". Check the Risk Rating column, not just the score.

### Q2: Can I customize the weights?

**A:** Yes! Edit `CONTEXT_WEIGHTS` in `security_scanner.py` (lines 889-988). Adjust weights to match your organization's priorities.

### Q3: Which score should I focus on improving first?

**A:** Focus on:
1. Critical Risk items (regardless of type)
2. High Risk webapps and APIs
3. Categories with 0% pass rate
4. High-priority checks (marked "High" in Checklist sheet)

### Q4: What's a "good" score?

**A:** 
- **WebApp/API:** 80+ is good, 90+ is excellent
- **Static:** 70+ is good, 85+ is excellent
- **Other:** 60+ is good, 75+ is excellent

### Q5: How do I see which specific checks failed?

**A:** In the Security Results sheet, scroll right to see columns like `TLS-1_Pass`, `AUTH-1_Pass`, etc. "No" means failed.

### Q6: Can I track improvement over time?

**A:** Yes! Run scans periodically and compare:
```bash
python security_scanner.py example.com --output 2025-01-01_report.xlsx
python security_scanner.py example.com --output 2025-04-01_report.xlsx
# Compare scores in both files
```

---

## Summary

### Key Takeaways:

1. **106 parameters scored** across 20 categories = Complete security assessment
2. **Context-aware weights** = Different priorities for webapp/api/static/other
3. **Risk ratings** = Automatic prioritization (Critical/High/Medium/Low)
4. **Type-specific rankings** = Easy comparison within same category
5. **Actionable insights** = Clear remediation path

### The Formula in One Sentence:

**Score = Sum of [(Checks Passed / Total Checks in Category) × Context-Aware Weight for Type] across all 20 categories**

### Getting Started:

```bash
# 1. Run scan
python security_scanner.py yourdomain.com

# 2. Open Excel report
open yourdomain.com_security_report.xlsx

# 3. Check WEBAPP RANKING (or API/STATIC/OTHER)
# 4. Focus on Critical/High Risk items
# 5. Review failed checks
# 6. Implement fixes
# 7. Re-scan to verify improvements
```

---

## References

- **Security Scanner Code:** `security_scanner.py`
- **Dashboard:** `dashboard.html`
- **Main Documentation:** `README.md`
- **This Guide:** `SCORING_GUIDE.md`

**Last Updated:** October 21, 2025
