#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

try:
    import pandas as pd
except ImportError:
    print("Error: pandas is required. Install with: pip install pandas tabulate", file=sys.stderr)
    sys.exit(1)


def load_env_file(env_path: Path = Path(".env")) -> Dict[str, str]:
    """Load environment variables from .env file."""
    env_vars = {}
    if not env_path.exists():
        return env_vars
    
    with env_path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            # Skip comments and empty lines
            if not line or line.startswith("#"):
                continue
            # Parse KEY=VALUE
            if "=" in line:
                key, value = line.split("=", 1)
                env_vars[key.strip()] = value.strip()
    
    return env_vars


REQUIRED_FILES = [
    "observations_long.csv",
    "subdomain_metrics.csv",
    "discovered_candidates.csv",
    "errors.csv",
    "control_metrics.csv",
    "enumeration_method_counts.csv",
    "run_metadata.json",
]

# Paper tables file mappings
PAPER_FILES = {
    "obs": "observations_long.csv",
    "sub": "subdomain_metrics.csv",
    "disc": "discovered_candidates.csv",
    "err": "errors.csv",
    "ctrl": "control_metrics.csv",
    "enum": "enumeration_method_counts.csv",
    "meta": "run_metadata.json",
}


def safe_read_csv(path: Path) -> pd.DataFrame:
    # Keep empty strings as empty, avoid pandas guessing too hard
    return pd.read_csv(path, keep_default_na=True)


def read_csv(path: Path) -> pd.DataFrame:
    """Alias for safe_read_csv for paper tables compatibility."""
    return pd.read_csv(path, keep_default_na=True)


def md_table(rows: List[List[str]], headers: List[str]) -> str:
    """Minimal markdown table generator (for reports)."""
    out = []
    out.append("| " + " | ".join(headers) + " |")
    out.append("| " + " | ".join(["---"] * len(headers)) + " |")
    for r in rows:
        out.append("| " + " | ".join("" if v is None else str(v) for v in r) + " |")
    return "\n".join(out)


def md_df_table(df: pd.DataFrame) -> str:
    """Convert DataFrame to markdown table (for paper tables).
    
    Requires tabulate package: pip install tabulate
    """
    try:
        # clean up NaNs for markdown readability
        out = df.copy()
        out = out.fillna("NA")
        return out.to_markdown(index=False)
    except AttributeError:
        print("Warning: pandas.DataFrame.to_markdown() requires tabulate package.", file=sys.stderr)
        print("Install with: pip install tabulate", file=sys.stderr)
        # Fallback to simple format
        return str(out)


def pick_col(df: pd.DataFrame, candidates: list[str]) -> str | None:
    """Pick the first column that exists from a list of candidates."""
    for c in candidates:
        if c in df.columns:
            return c
    return None


def find_run_dirs(root: Path, domain: Optional[str] = None) -> List[Path]:
    """
    Find all run directories. If domain is specified, only find runs for that domain.
    
    Expected pattern:
      root/YYYY-MM-DD/YYYYMMDD_HHMMSS/  (if no domain specified)
      root/{domain}/YYYY-MM-DD/YYYYMMDD_HHMMSS/  (if domain specified)
    """
    run_dirs: List[Path] = []
    
    if domain:
        # Domain-specific search: out/{domain}/YYYY-MM-DD/YYYYMMDD_HHMMSS/
        search_root = root / domain
        if not search_root.exists():
            return run_dirs
    else:
        search_root = root
    
    for p in search_root.rglob("*"):
        if not p.is_dir():
            continue
        if all((p / f).exists() for f in REQUIRED_FILES):
            run_dirs.append(p)
    
    # deterministic order
    run_dirs.sort()
    return run_dirs


def load_metadata(path: Path) -> Dict:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def compute_tls_enabled(observations: pd.DataFrame) -> int:
    # TLS-enabled targets are those with TLS_AVAILABLE == Pass
    needed_cols = {"target", "check_id", "status"}
    missing = needed_cols - set(observations.columns)
    if missing:
        raise ValueError(f"observations_long.csv missing columns: {sorted(missing)}")

    tls = observations[
        (observations["check_id"] == "TLS_AVAILABLE") & (observations["status"] == "Pass")
    ]
    return int(tls["target"].nunique())


def summarize_errors(errors: pd.DataFrame) -> Tuple[int, pd.DataFrame]:
    total = int(len(errors))
    if total == 0 or "reason_code" not in errors.columns:
        return total, pd.DataFrame(columns=["reason_code", "count"])
    by_reason = (
        errors["reason_code"]
        .fillna("NA")
        .value_counts(dropna=False)
        .rename_axis("reason_code")
        .reset_index(name="count")
    )
    return total, by_reason


def summarize_risk(sub_metrics: pd.DataFrame) -> pd.DataFrame:
    # expected columns: risk_level, pass_rate, attempt_rate
    for col in ["risk_level", "pass_rate", "attempt_rate"]:
        if col not in sub_metrics.columns:
            # degrade gracefully
            sub_metrics[col] = pd.NA

    g = sub_metrics.groupby("risk_level", dropna=False)
    out = pd.DataFrame(
        {
            "count": g.size(),
            "pass_rate_min": g["pass_rate"].min(),
            "pass_rate_median": g["pass_rate"].median(),
            "pass_rate_max": g["pass_rate"].max(),
            "attempt_rate_min": g["attempt_rate"].min(),
            "attempt_rate_median": g["attempt_rate"].median(),
            "attempt_rate_max": g["attempt_rate"].max(),
        }
    ).reset_index()

    # make NA label stable for markdown
    out["risk_level"] = out["risk_level"].fillna("NA")
    # deterministic ordering: highest count first
    out = out.sort_values(["count", "risk_level"], ascending=[False, True])
    return out


def top_problem_checks(control: pd.DataFrame, n: int = 10) -> pd.DataFrame:
    # Prefer checks with errors, then failed, then low pass_rate
    for col in ["errors", "failed", "pass_rate", "check_id", "check_name", "category"]:
        if col not in control.columns:
            control[col] = pd.NA

    tmp = control.copy()
    # numeric coercion for sorting
    for c in ["errors", "failed", "pass_rate"]:
        tmp[c] = pd.to_numeric(tmp[c], errors="coerce").fillna(0)

    tmp = tmp.sort_values(
        ["errors", "failed", "pass_rate"],
        ascending=[False, False, True],
    ).head(n)

    return tmp[["check_id", "check_name", "category", "failed", "errors", "pass_rate"]]


def parse_cache_evidence(cache_dir: Path) -> Dict[str, int]:
    """
    Optional: estimate evidence counts from cache filenames.
    This is NOT authoritative; it's evidence-based.
    """
    if not cache_dir.exists():
        return {"http_evidence": 0, "tls_evidence": 0}

    http_targets = set()
    tls_targets = set()

    for f in cache_dir.glob("http_*.json"):
        # examples:
        # http_http_example.com.json  OR  http_https_example.com.json
        name = f.name
        # strip prefix and suffix carefully
        # http_http_ + domain + .json
        parts = name.split("_", 2)
        if len(parts) == 3:
            domain = parts[2].removesuffix(".json")
            http_targets.add(domain)

    for f in cache_dir.glob("tls_*_443.json"):
        # tls_domain_443.json
        name = f.name
        if name.startswith("tls_") and name.endswith("_443.json"):
            domain = name[len("tls_") : -len("_443.json")]
            tls_targets.add(domain)

    return {
        "http_evidence": len(http_targets),
        "tls_evidence": len(tls_targets),
        "http_only_evidence": len(http_targets - tls_targets),
    }


def methodology_notes() -> str:
    return (
        "## Methodology notes (for the paper)\n\n"
        "### Why missing TLS ≠ insecure\n"
        "- **TLS absence is not automatically a vulnerability.** Many subdomains are intentionally HTTP-only because they serve non-sensitive public content, run legacy services, or are internal endpoints exposed through DNS.\n"
        "- Security assessment must separate **service intent** (what the endpoint is for) from **transport properties** (whether it uses HTTPS). Without knowing the data sensitivity, labeling non-TLS as \"insecure\" is an overclaim.\n"
        "- Measurement artifacts matter: a domain may support TLS but fail TLS checks due to transient network issues, SNI quirks, rate limiting, or non-standard ports. Therefore, TLS findings must be presented as **observations**, not absolute truths.\n\n"
        "### Why DNS ≠ service availability\n"
        "- DNS only proves a name can resolve (or exists via records). It does **not** prove that a web service is running, reachable, or responding.\n"
        "- Many DNS names point to:\n"
        "  - parked infrastructure,\n"
        "  - private/internal IP ranges,\n"
        "  - services on non-HTTP ports,\n"
        "  - endpoints restricted by firewall/geo/IP allow-lists.\n"
        "- Therefore, DNS-discovered subdomains should be treated as **candidates**. Availability and security posture require protocol-level probing (HTTP/TLS) and must be reported separately.\n"
    )


def build_report(run_dir: Path, out_dir: Path, use_cache: bool) -> Path:
    obs = safe_read_csv(run_dir / "observations_long.csv")
    subm = safe_read_csv(run_dir / "subdomain_metrics.csv")
    disc = safe_read_csv(run_dir / "discovered_candidates.csv")
    errs = safe_read_csv(run_dir / "errors.csv")
    ctrl = safe_read_csv(run_dir / "control_metrics.csv")
    enum = safe_read_csv(run_dir / "enumeration_method_counts.csv")
    meta = load_metadata(run_dir / "run_metadata.json")

    dns_discovered = int(len(disc))
    tls_enabled = compute_tls_enabled(obs)
    no_tls_evidence = max(0, dns_discovered - tls_enabled)
    total_observations = int(len(obs))
    total_errors, errors_by_reason = summarize_errors(errs)

    risk = summarize_risk(subm)
    top_checks = top_problem_checks(ctrl, n=10)

    # Metadata table (small, stable keys)
    meta_keys = [
        "run_id",
        "started_at",
        "finished_at",
        "duration_seconds",
        "root_domain",
        "targets_total",
        "notes",
        "version",
    ]
    meta_rows = []
    for k in meta_keys:
        if k in meta:
            meta_rows.append([k, str(meta.get(k))])

    report_lines: List[str] = []
    report_lines.append(f"# Run Report: {run_dir.parent.name}/{run_dir.name}\n")

    report_lines.append("## Run metadata\n")
    report_lines.append(md_table(meta_rows if meta_rows else [["(metadata)", "not available"]], ["Key", "Value"]))
    report_lines.append("\n")

    report_lines.append("## Aggregation (DNS / TLS)\n")
    agg_rows = [
        ["DNS-discovered candidates", dns_discovered],
        ["TLS-enabled (TLS_AVAILABLE Pass)", tls_enabled],
        ["DNS-discovered but no TLS evidence", no_tls_evidence],
        ["Total observations", total_observations],
        ["Total errors", total_errors],
    ]
    report_lines.append(md_table([[str(a), str(b)] for a, b in agg_rows], ["Metric", "Value"]))
    report_lines.append("\n")

    if use_cache:
        cache_dir = run_dir.parents[1] / "cache"  # out/ac.lk/cache
        cache_stats = parse_cache_evidence(cache_dir)
        report_lines.append("## Optional cache-based evidence (non-authoritative)\n")
        report_lines.append(
            md_table(
                [[k, str(v)] for k, v in cache_stats.items()],
                ["Cache evidence metric", "Value"],
            )
        )
        report_lines.append(
            "\n**Warning:** Cache-derived counts are evidence-based (what was probed/cached), "
            "not ground-truth availability.\n"
        )

    report_lines.append("## Error reasons\n")
    if errors_by_reason.empty:
        report_lines.append("_No error breakdown available._\n")
    else:
        rows = errors_by_reason.head(20).values.tolist()
        report_lines.append(md_table([[str(a), str(b)] for a, b in rows], ["reason_code", "count"]))
        report_lines.append("\n")

    report_lines.append("## Risk level distribution (subdomain_metrics)\n")
    if risk.empty:
        report_lines.append("_No risk metrics available._\n")
    else:
        rows = risk.values.tolist()
        report_lines.append(
            md_table(
                [[str(x) for x in r] for r in rows],
                list(risk.columns),
            )
        )
        report_lines.append("\n")

    report_lines.append("## Top problematic checks (control_metrics)\n")
    if top_checks.empty:
        report_lines.append("_No control metrics available._\n")
    else:
        rows = top_checks.values.tolist()
        report_lines.append(
            md_table(
                [[str(x) for x in r] for r in rows],
                list(top_checks.columns),
            )
        )
        report_lines.append("\n")

    report_lines.append("## Enumeration method counts\n")
    if enum.empty:
        report_lines.append("_No enumeration data available._\n")
    else:
        # enforce expected columns
        for c in ["discovery_method", "subdomain_count"]:
            if c not in enum.columns:
                enum[c] = pd.NA
        enum2 = enum[["discovery_method", "subdomain_count"]].copy()
        enum2 = enum2.sort_values("subdomain_count", ascending=False)
        report_lines.append(
            md_table(
                [[str(a), str(b)] for a, b in enum2.values.tolist()],
                ["discovery_method", "subdomain_count"],
            )
        )
        report_lines.append("\n")

    # ========================================================================
    # ADD PUBLICATION TABLES (paper tables section)
    # ========================================================================
    report_lines.append("---\n")
    report_lines.append("# Publication Tables\n\n")
    
    try:
        # Generate all 13 tables
        tables = {}
        tables["t1"] = table_1_run_overview(run_dir, meta, disc, obs, enum)
        tables["t2"] = table_2_dns_tls_aggregation(disc, obs)
        tables["t3"] = table_3_outcome_distribution(obs)
        tables["t4"] = table_4_error_reasons(errs)
        tables["t5"] = table_5_risk_distribution(subm)
        tables["t6"] = table_6_top_failing_checks(ctrl, n=10)
        tables["t7"] = table_7_enum_methods(enum)
        tables["t8"] = table_8_protocol_by_category(ctrl)
        tables["t9"] = table_9_subdomain_pass_rate_distribution(subm)
        tables["t10"] = table_10_check_categories_summary(ctrl)
        tables["t11"] = table_11_top_passing_checks(ctrl, n=10)
        tables["t12"] = table_12_target_status_overview(disc)
        tables["t13"] = table_13_attempt_rate_analysis(subm)
        
        captions = {
            "t1": "Table 1. Run & dataset overview.",
            "t2": "Table 2. DNS discovery vs TLS evidence aggregation (avoid overclaiming).",
            "t3": "Table 3. Observation outcome distribution.",
            "t4": "Table 4. Error reason breakdown (measurement artifacts).",
            "t5": "Table 5. Risk-level distribution (descriptive indicators, not confirmed vulnerabilities).",
            "t6": "Table 6. Top failing checks (transparency).",
            "t7": "Table 7. Enumeration method contribution.",
            "t8": "Table 8. Protocol breakdown by category.",
            "t9": "Table 9. Subdomain pass rate distribution.",
            "t10": "Table 10. Check categories summary.",
            "t11": "Table 11. Top passing checks (best performers).",
            "t12": "Table 12. Target scan status overview.",
            "t13": "Table 13. Attempt rate distribution analysis.",
        }
        
        for key in ["t1", "t2", "t3", "t4", "t5", "t6", "t7", "t8", "t9", "t10", "t11", "t12", "t13"]:
            report_lines.append(f"## {captions[key]}\n")
            report_lines.append(md_df_table(tables[key]))
            report_lines.append("\n")
    except Exception as e:
        report_lines.append(f"_Error generating publication tables: {e}_\n\n")

    report_lines.append(methodology_notes())

    out_dir.mkdir(parents=True, exist_ok=True)
    # Use a simpler filename when writing to the run directory itself
    if out_dir == run_dir:
        md_path = out_dir / "report.md"
    else:
        md_path = out_dir / f"{run_dir.parent.name}__{run_dir.name}.md"
    
    md_path.write_text("\n".join(report_lines).strip() + "\n", encoding="utf-8")
    return md_path


# ============================================================================
# PAPER TABLES FUNCTIONS (from generate_paper_tables.py)
# ============================================================================

def table_1_run_overview(run_dir: Path, meta: dict, disc: pd.DataFrame, obs: pd.DataFrame, enum: pd.DataFrame) -> pd.DataFrame:
    """Table 1: Run and dataset overview."""
    date_folder = run_dir.parent.name
    run_id = run_dir.name

    # Try to use meta keys if present; otherwise fallback
    root_domain = meta.get("root_domain", "ac.lk")
    duration = meta.get("duration_seconds", meta.get("duration", "NA"))
    started = meta.get("started_at", meta.get("start_time", "NA"))
    finished = meta.get("finished_at", meta.get("end_time", "NA"))

    methods_col = pick_col(enum, ["discovery_method", "method", "source"])
    methods_used = int(enum[methods_col].nunique()) if (
        methods_col and len(enum)) else 0

    df = pd.DataFrame(
        [{
            "Run date": date_folder,
            "Run ID": run_id,
            "Root domain": root_domain,
            "Started at": started,
            "Finished at": finished,
            "Duration (s)": duration,
            "DNS-discovered candidates": int(len(disc)),
            "Total observations": int(len(obs)),
            "Enumeration methods used": methods_used,
        }]
    )
    return df


def table_2_dns_tls_aggregation(disc: pd.DataFrame, obs: pd.DataFrame) -> pd.DataFrame:
    """Table 2: DNS discovery vs TLS evidence aggregation."""
    # REQUIRED: columns target, check_id, status in observations_long
    required = {"target", "check_id", "status"}
    missing = required - set(obs.columns)
    if missing:
        raise ValueError(
            f"observations_long.csv missing columns: {sorted(missing)}")

    dns_discovered = int(len(disc))
    tls_enabled = int(
        obs[(obs["check_id"] == "TLS_AVAILABLE") & (
            obs["status"] == "Pass")]["target"].nunique()
    )
    no_tls_evidence = max(0, dns_discovered - tls_enabled)

    df = pd.DataFrame(
        [
            {"Category": "DNS-discovered candidates", "Count": dns_discovered},
            {"Category": "TLS-enabled endpoints (TLS_AVAILABLE = Pass)",
             "Count": tls_enabled},
            {"Category": "DNS-discovered with no TLS evidence",
                "Count": no_tls_evidence},
            {"Category": "Total protocol observations",
                "Count": int(len(obs))},
        ]
    )
    return df


def table_3_outcome_distribution(obs: pd.DataFrame) -> pd.DataFrame:
    """Table 3: Observation outcome distribution."""
    # outcome/status column might differ; prefer "status"
    status_col = pick_col(obs, ["status", "outcome", "result"])
    if not status_col:
        raise ValueError(
            "observations_long.csv: can't find status/outcome/result column")

    counts = obs[status_col].fillna(
        "NA").value_counts(dropna=False).reset_index()
    counts.columns = ["Outcome", "Count"]
    total = counts["Count"].sum()
    counts["Percentage"] = (counts["Count"] / total *
                            100).round(2).astype(str) + "%"

    # put common outcomes first if present
    preferred = ["Pass", "Fail", "Error", "Timeout"]
    counts["__order"] = counts["Outcome"].apply(
        lambda x: preferred.index(x) if x in preferred else 999)
    counts = counts.sort_values(["__order", "Count"], ascending=[
                                True, False]).drop(columns="__order")

    return counts


def table_4_error_reasons(err: pd.DataFrame) -> pd.DataFrame:
    """Table 4: Error reason breakdown (measurement artifacts)."""
    if len(err) == 0:
        return pd.DataFrame([{"Error reason": "No errors recorded", "Count": 0}])

    reason_col = pick_col(
        err, ["reason_code", "reason", "error_type", "category"])
    if not reason_col:
        # fallback: single bucket
        return pd.DataFrame([{"Error reason": "Uncategorized", "Count": int(len(err))}])

    df = (
        err[reason_col]
        .fillna("NA")
        .value_counts(dropna=False)
        .rename_axis("Error reason")
        .reset_index(name="Count")
        .sort_values("Count", ascending=False)
    )
    return df


def table_5_risk_distribution(sub: pd.DataFrame) -> pd.DataFrame:
    """Table 5: Risk-level distribution (descriptive indicators)."""
    risk_col = pick_col(sub, ["risk_level", "risk", "tier"])
    pass_rate_col = pick_col(sub, ["pass_rate", "passRate"])
    attempt_rate_col = pick_col(sub, ["attempt_rate", "attemptRate"])

    if not risk_col:
        raise ValueError(
            "subdomain_metrics.csv: can't find risk_level/risk/tier column")

    tmp = sub.copy()
    tmp[risk_col] = tmp[risk_col].fillna("NA")

    # numeric coercion
    if pass_rate_col:
        tmp[pass_rate_col] = pd.to_numeric(tmp[pass_rate_col], errors="coerce")
    if attempt_rate_col:
        tmp[attempt_rate_col] = pd.to_numeric(
            tmp[attempt_rate_col], errors="coerce")

    g = tmp.groupby(risk_col, dropna=False)

    df = pd.DataFrame({
        "Risk level": g.size().index,
        "Subdomains": g.size().values,
        "Median pass rate": (g[pass_rate_col].median().values if pass_rate_col else ["NA"] * g.size().shape[0]),
        "Median attempt rate": (g[attempt_rate_col].median().values if attempt_rate_col else ["NA"] * g.size().shape[0]),
    })

    # sort: High -> Medium -> Low if present
    order = {"High": 0, "Medium": 1, "Low": 2, "NA": 3}
    df["__order"] = df["Risk level"].map(order).fillna(99)
    df = df.sort_values(["__order", "Subdomains"], ascending=[
                        True, False]).drop(columns="__order")

    return df


def table_6_top_failing_checks(ctrl: pd.DataFrame, n: int = 10) -> pd.DataFrame:
    """Table 6: Top failing checks (transparency)."""
    # flexible column mapping
    check_id = pick_col(ctrl, ["check_id", "id"])
    check_name = pick_col(ctrl, ["check_name", "name"])
    category = pick_col(ctrl, ["category", "group"])
    failed = pick_col(ctrl, ["failed", "fail_count"])
    errors = pick_col(ctrl, ["errors", "error_count"])
    pass_rate = pick_col(ctrl, ["pass_rate", "passRate"])

    if not check_id:
        raise ValueError("control_metrics.csv: can't find check_id column")

    tmp = ctrl.copy()

    for c in [failed, errors, pass_rate]:
        if c:
            tmp[c] = pd.to_numeric(tmp[c], errors="coerce").fillna(0)

    # sort by errors desc, failed desc, pass_rate asc
    sort_cols = [c for c in [errors, failed, pass_rate] if c]
    sort_asc = []
    for c in sort_cols:
        if c == pass_rate:
            sort_asc.append(True)
        else:
            sort_asc.append(False)

    tmp = tmp.sort_values(sort_cols, ascending=sort_asc).head(n)

    cols = [c for c in [check_id, check_name,
                        category, failed, errors, pass_rate] if c]
    out = tmp[cols].copy()

    # rename for paper readability
    rename = {}
    if check_id:
        rename[check_id] = "Check ID"
    if check_name:
        rename[check_name] = "Check name"
    if category:
        rename[category] = "Category"
    if failed:
        rename[failed] = "Failed"
    if errors:
        rename[errors] = "Errors"
    if pass_rate:
        rename[pass_rate] = "Pass rate"
    out = out.rename(columns=rename)

    return out


def table_7_enum_methods(enum: pd.DataFrame) -> pd.DataFrame:
    """Table 7: Enumeration method contribution."""
    method_col = pick_col(enum, ["discovery_method", "method", "source"])
    count_col = pick_col(enum, ["subdomain_count", "count", "n"])

    if not method_col or not count_col:
        raise ValueError(
            "enumeration_method_counts.csv missing method/count columns")

    tmp = enum[[method_col, count_col]].copy()
    tmp[count_col] = pd.to_numeric(
        tmp[count_col], errors="coerce").fillna(0).astype(int)
    tmp = tmp.sort_values(count_col, ascending=False)

    tmp = tmp.rename(
        columns={method_col: "Enumeration method", count_col: "Subdomains found"})
    return tmp


def table_8_protocol_by_category(ctrl: pd.DataFrame) -> pd.DataFrame:
    """Table 8: Protocol breakdown by category."""
    category_col = pick_col(ctrl, ["category", "group", "type"])
    if not category_col:
        raise ValueError("control_metrics.csv: can't find category column")
    
    tmp = ctrl.copy()
    for c in ["tested_checks", "total_targets", "passed", "failed", "errors", "pass_rate"]:
        if c in tmp.columns:
            tmp[c] = pd.to_numeric(tmp[c], errors="coerce").fillna(0)
    
    # Group by category
    grouped = tmp.groupby(category_col, dropna=False).agg({
        "total_targets": "sum",
        "passed": "sum",
        "failed": "sum",
        "errors": "sum",
        "pass_rate": "mean",
    }).reset_index()
    
    grouped = grouped.rename(columns={
        category_col: "Category",
        "total_targets": "Total tests",
        "passed": "Passed",
        "failed": "Failed",
        "errors": "Errors",
        "pass_rate": "Avg pass rate (%)"
    })
    
    # Round percentages
    grouped["Avg pass rate (%)"] = grouped["Avg pass rate (%)"].round(2)
    grouped = grouped.sort_values("Avg pass rate (%)", ascending=True)
    
    return grouped


def table_9_subdomain_pass_rate_distribution(sub: pd.DataFrame) -> pd.DataFrame:
    """Table 9: Subdomain pass rate distribution (histogram)."""
    pass_rate_col = pick_col(sub, ["pass_rate", "passRate"])
    if not pass_rate_col:
        raise ValueError("subdomain_metrics.csv: can't find pass_rate column")
    
    tmp = sub.copy()
    tmp[pass_rate_col] = pd.to_numeric(tmp[pass_rate_col], errors="coerce").fillna(0)
    
    # Create manual bins
    bins_ranges = [(0, 10), (10, 20), (20, 30), (30, 40), (40, 50), 
                   (60, 70), (70, 80), (80, 90), (90, 101)]
    
    counts = []
    for low, high in bins_ranges:
        count = len(tmp[(tmp[pass_rate_col] >= low) & (tmp[pass_rate_col] < high)])
        counts.append({"Pass rate range": f"{low}-{high-1}%", "Subdomain count": count})
    
    return pd.DataFrame(counts)


def table_10_check_categories_summary(ctrl: pd.DataFrame) -> pd.DataFrame:
    """Table 10: Check categories summary."""
    category_col = pick_col(ctrl, ["category", "group", "type"])
    if not category_col:
        raise ValueError("control_metrics.csv: can't find category column")
    
    tmp = ctrl.copy()
    tmp["count"] = 1
    for c in ["total_targets", "passed", "failed", "errors", "pass_rate"]:
        if c in tmp.columns:
            tmp[c] = pd.to_numeric(tmp[c], errors="coerce").fillna(0)
    
    grouped = tmp.groupby(category_col, dropna=False).agg({
        "count": "size",
        "total_targets": "sum",
        "passed": "sum",
        "failed": "sum",
        "errors": "sum",
        "pass_rate": "mean",
    }).reset_index()
    
    grouped = grouped.rename(columns={
        category_col: "Category",
        "count": "Check count",
        "total_targets": "Total tests",
        "passed": "Passed",
        "failed": "Failed",
        "errors": "Errors",
        "pass_rate": "Avg pass rate (%)"
    })
    
    grouped["Avg pass rate (%)"] = grouped["Avg pass rate (%)"].round(2)
    grouped = grouped.sort_values("Avg pass rate (%)", ascending=True)
    
    return grouped


def table_11_top_passing_checks(ctrl: pd.DataFrame, n: int = 10) -> pd.DataFrame:
    """Table 11: Top passing checks (best performers)."""
    check_id = pick_col(ctrl, ["check_id", "id"])
    check_name = pick_col(ctrl, ["check_name", "name"])
    category = pick_col(ctrl, ["category", "group"])
    pass_rate = pick_col(ctrl, ["pass_rate", "passRate"])
    tested = pick_col(ctrl, ["tested_checks", "tested", "total_targets"])
    
    if not check_id:
        raise ValueError("control_metrics.csv: can't find check_id column")
    
    tmp = ctrl.copy()
    if pass_rate:
        tmp[pass_rate] = pd.to_numeric(tmp[pass_rate], errors="coerce").fillna(0)
    if tested:
        tmp[tested] = pd.to_numeric(tmp[tested], errors="coerce").fillna(0)
    
    # Sort by pass_rate descending (highest first)
    if pass_rate:
        tmp = tmp.sort_values(pass_rate, ascending=False).head(n)
    
    cols = [c for c in [check_id, check_name, category, tested, pass_rate] if c]
    out = tmp[cols].copy()
    
    # Rename for paper readability
    rename = {}
    if check_id:
        rename[check_id] = "Check ID"
    if check_name:
        rename[check_name] = "Check name"
    if category:
        rename[category] = "Category"
    if tested:
        rename[tested] = "Tests"
    if pass_rate:
        rename[pass_rate] = "Pass rate (%)"
    out = out.rename(columns=rename)
    
    return out


def table_12_target_status_overview(disc: pd.DataFrame) -> pd.DataFrame:
    """Table 12: Target scan status overview."""
    status_col = pick_col(disc, ["scan_status", "status", "state"])
    if not status_col:
        raise ValueError("discovered_candidates.csv: can't find scan_status column")
    
    tmp = disc.copy()
    tmp[status_col] = tmp[status_col].fillna("Unknown")
    
    status_dist = tmp[status_col].value_counts().reset_index()
    status_dist.columns = ["Scan status", "Target count"]
    status_dist = status_dist.sort_values("Target count", ascending=False)
    
    return status_dist


def table_13_attempt_rate_analysis(sub: pd.DataFrame) -> pd.DataFrame:
    """Table 13: Attempt rate distribution analysis."""
    attempt_rate_col = pick_col(sub, ["attempt_rate", "attemptRate"])
    if not attempt_rate_col:
        raise ValueError("subdomain_metrics.csv: can't find attempt_rate column")
    
    tmp = sub.copy()
    tmp[attempt_rate_col] = pd.to_numeric(tmp[attempt_rate_col], errors="coerce").fillna(0)
    
    # Create manual bins
    bins_ranges = [(0, 10), (10, 20), (20, 30), (30, 40), (40, 50), 
                   (60, 70), (70, 80), (80, 90), (90, 101)]
    
    counts = []
    for low, high in bins_ranges:
        count = len(tmp[(tmp[attempt_rate_col] >= low) & (tmp[attempt_rate_col] < high)])
        counts.append({"Attempt rate range": f"{low}-{high-1}%", "Subdomain count": count})
    
    return pd.DataFrame(counts)


def build_markdown(run_dir: Path, tables: dict[str, pd.DataFrame], out_path: Path) -> None:
    """Build complete markdown document with all tables and methodology notes."""
    lines = []
    lines.append(
        f"# Paper Tables – Run {run_dir.parent.name}/{run_dir.name}\n")

    captions = {
        "t1": "Table 1. Run & dataset overview.",
        "t2": "Table 2. DNS discovery vs TLS evidence aggregation (avoid overclaiming).",
        "t3": "Table 3. Observation outcome distribution.",
        "t4": "Table 4. Error reason breakdown (measurement artifacts).",
        "t5": "Table 5. Risk-level distribution (descriptive indicators, not confirmed vulnerabilities).",
        "t6": "Table 6. Top failing checks (transparency).",
        "t7": "Table 7. Enumeration method contribution.",
    }

    for key in ["t1", "t2", "t3", "t4", "t5", "t6", "t7"]:
        lines.append(f"## {captions[key]}\n")
        lines.append(md_df_table(tables[key]))
        lines.append("\n")

    # Add tight methodology note block you can paste into Methods
    lines.append("## Methodology text (paste into paper)\n")
    lines.append(
        "- **Missing TLS ≠ insecure:** TLS absence is reported as *lack of TLS evidence* and is not automatically interpreted as a security weakness. Many endpoints are intentionally HTTP-only or non-sensitive; additionally, transient network effects can prevent successful TLS probing. Therefore, TLS results are treated as observational measurements, not ground truth.\n"
        "- **DNS ≠ service availability:** DNS resolution only indicates naming/record existence. It does not confirm a reachable service, an HTTP endpoint, or externally accessible infrastructure (e.g., firewalled, internal, non-HTTP services). Hence, DNS-discovered candidates are separated from protocol-level evidence in the results.\n"
    )

    out_path.write_text("\n".join(lines).strip() + "\n", encoding="utf-8")


def paper_tables_main() -> int:
    """Generate publication-ready tables from a single scan run."""
    ap = argparse.ArgumentParser(
        description="Generate publication-ready tables from a single scan run.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate tables for a specific run
  python generate_reports.py --paper-tables --run-dir out/gov.lk/2026-01-25/20260125_065145
  
  # Specify output file and show top 15 checks
  python generate_reports.py --paper-tables --run-dir out/gov.lk/2026-01-25/20260125_065145 \\
      --out-md my_paper_tables.md --top-n 15

Requirements:
  pip install pandas tabulate
        """
    )
    ap.add_argument("--run-dir", required=True,
                    help="Path to one run folder (YYYYMMDD_HHMMSS).")
    ap.add_argument("--out-md", default=None,
                    help="Output markdown file path (default: <run_dir>/paper_tables.md).")
    ap.add_argument("--top-n", type=int, default=10,
                    help="Top N checks for Table 6 (default: 10).")
    args = ap.parse_args()

    run_dir = Path(args.run_dir).expanduser().resolve()
    if not run_dir.exists():
        print(f"Error: Run dir not found: {run_dir}", file=sys.stderr)
        return 1

    # validate required files
    missing_files = []
    for k, fn in PAPER_FILES.items():
        p = run_dir / fn
        if not p.exists():
            missing_files.append(str(p))

    if missing_files:
        print("Error: Missing required files:", file=sys.stderr)
        for f in missing_files:
            print(f"  - {f}", file=sys.stderr)
        return 1

    # Load data
    try:
        obs = read_csv(run_dir / PAPER_FILES["obs"])
        sub = read_csv(run_dir / PAPER_FILES["sub"])
        disc = read_csv(run_dir / PAPER_FILES["disc"])
        err = read_csv(run_dir / PAPER_FILES["err"])
        ctrl = read_csv(run_dir / PAPER_FILES["ctrl"])
        enum = read_csv(run_dir / PAPER_FILES["enum"])
        meta = json.loads(
            (run_dir / PAPER_FILES["meta"]).read_text(encoding="utf-8"))
    except Exception as e:
        print(f"Error loading data files: {e}", file=sys.stderr)
        return 1

    # Generate tables
    try:
        tables = {}
        tables["t1"] = table_1_run_overview(run_dir, meta, disc, obs, enum)
        tables["t2"] = table_2_dns_tls_aggregation(disc, obs)
        tables["t3"] = table_3_outcome_distribution(obs)
        tables["t4"] = table_4_error_reasons(err)
        tables["t5"] = table_5_risk_distribution(sub)
        tables["t6"] = table_6_top_failing_checks(ctrl, n=args.top_n)
        tables["t7"] = table_7_enum_methods(enum)
    except Exception as e:
        print(f"Error generating tables: {e}", file=sys.stderr)
        return 1

    # Write output
    out_md = Path(args.out_md).expanduser().resolve(
    ) if args.out_md else (run_dir / "paper_tables.md")
    try:
        build_markdown(run_dir, tables, out_md)
        print(f"✓ Wrote paper tables: {out_md}")
        print(f"\nGenerated 7 tables from run: {run_dir.name}")
        return 0
    except Exception as e:
        print(f"Error writing output: {e}", file=sys.stderr)
        return 1


def main() -> int:
    """Main entry point - dispatches between batch reports and single-run paper tables."""
    ap = argparse.ArgumentParser(
        description="Generate Markdown reports and paper tables from security scan runs.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
MODES:
  Automatic batch report (default, reads domain from .env):
    python generate_reports.py
  
  Batch report for specific domain:
    python generate_reports.py --domain gov.lk [--root out]
  
  Single-run paper tables:
    python generate_reports.py --paper-tables --run-dir out/gov.lk/2026-01-25/20260125_065145 [--out-md file.md] [--top-n 10]
        """
    )
    
    # Mode selection
    ap.add_argument("--paper-tables", action="store_true",
                    help="Generate publication-ready tables for a single run (requires --run-dir).")
    
    # Batch report arguments
    ap.add_argument("--root", type=str, default="out",
                    help="Root folder containing domain/date/run folders (batch mode, default: out).")
    ap.add_argument("--domain", type=str, default=None,
                    help="Domain to scan for (batch mode). If not specified, reads from .env DOMAIN variable.")
    ap.add_argument("--use-cache", action="store_true",
                    help="Compute optional evidence metrics from cache (batch mode).")
    
    # Paper tables arguments
    ap.add_argument("--run-dir", type=str, default=None,
                    help="Path to one run folder for paper tables (paper-tables mode).")
    ap.add_argument("--out-md", type=str, default=None,
                    help="Output markdown file path (paper-tables mode).")
    ap.add_argument("--top-n", type=int, default=10,
                    help="Top N checks for Table 6 (paper-tables mode, default: 10).")
    
    args = ap.parse_args()
    
    # Dispatch based on mode
    if args.paper_tables:
        if not args.run_dir:
            print("Error: --run-dir is required with --paper-tables", file=sys.stderr)
            return 1
        
        # Reconstruct args for paper_tables_main
        sys.argv = ["generate_reports.py", "--run-dir", args.run_dir]
        if args.out_md:
            sys.argv.extend(["--out-md", args.out_md])
        if args.top_n != 10:
            sys.argv.extend(["--top-n", str(args.top_n)])
        
        return paper_tables_main()
    else:
        # Batch mode (reports for domain runs)
        root = Path(args.root).expanduser().resolve()
        
        # Determine domain
        domain = args.domain
        if not domain:
            # Try to read from .env
            env_vars = load_env_file(Path(".env"))
            domain = env_vars.get("DOMAIN")
            if domain:
                print(f"📖 Domain from .env: {domain}")
            else:
                print("Error: Domain not specified and .env DOMAIN variable not found", file=sys.stderr)
                return 1
        else:
            print(f"📖 Domain specified: {domain}")
        
        # Find all run directories for this domain
        run_dirs = find_run_dirs(root, domain=domain)
        if not run_dirs:
            print(f"No run folders found under: {root}/{domain}")
            return 2

        print(f"Found {len(run_dirs)} run(s) for domain: {domain}\n")
        
        written = 0
        for run_dir in run_dirs:
            try:
                # Generate report in the run directory itself
                md_path = build_report(run_dir, run_dir, use_cache=args.use_cache)
                print(f"✓ {run_dir.parent.name}/{run_dir.name}: {md_path.name}")
                written += 1
            except Exception as e:
                print(f"✗ {run_dir.parent.name}/{run_dir.name}: {type(e).__name__}: {e}", file=sys.stderr)

        print(f"\n✓ Reports written: {written}/{len(run_dirs)}")
        return 0 if written == len(run_dirs) else 1


if __name__ == "__main__":
    raise SystemExit(main())
