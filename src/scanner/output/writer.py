"""CSV and optional Excel output writer.

Primary output is CSV files (tidy, analysis-ready).
Excel is optional and generated from CSVs if enabled.
"""

import logging
from pathlib import Path
from typing import List, Dict, Any
from datetime import datetime
import json

from util.types import CheckResult, ProbeResult
from util.io import write_csv, write_json, ensure_dir
from util.time import timestamp_str, date_str
from scanner.scoring.model import SubdomainScore

logger = logging.getLogger(__name__)


class OutputWriter:
    """Writes scan results to disk in CSV and optional Excel format.
    
    Output structure:
      out/<domain>/<date>/<timestamp>/
        observations_long.csv      # Tidy format: one row per check result
        subdomain_metrics.csv      # One row per subdomain with scores
        control_metrics.csv        # Aggregated stats per control
        errors.csv                 # All errors encountered
        run_metadata.json          # Scan metadata
        summary.xlsx               # Optional Excel workbook
    """
    
    def __init__(self, domain: str, out_dir: str = "out", enable_excel: bool = False, run_dir: Path = None):
        """Initialize writer with output directory.
        
        Args:
            domain: Target domain name
            out_dir: Base output directory (default: 'out')
            enable_excel: Whether to generate Excel summary (default: False)
            run_dir: Explicit run directory to use (overrides auto-creation)
        """
        self.domain = domain
        self.enable_excel = enable_excel
        
        if run_dir:
            # Use explicit run directory from caller (app.py)
            self.run_dir = Path(run_dir)
            ensure_dir(self.run_dir)
        else:
            # Create timestamped output directory (legacy behavior)
            base_dir = Path(out_dir) / domain / date_str()
            self.run_dir = base_dir / timestamp_str()
            ensure_dir(self.run_dir)
        
        logger.info(f"Output directory: {self.run_dir}")
    
    def write_all(self,
                  check_results: List[CheckResult],
                  subdomain_scores: List[SubdomainScore],
                  domain_summary: Dict[str, Any],
                  run_metadata: Dict[str, Any]) -> None:
        """Write all output files.
        
        Args:
            check_results: All check results from the scan
            subdomain_scores: Scores for each subdomain
            domain_summary: Domain-level aggregated stats
            run_metadata: Scan configuration and timing info
        """
        logger.info("Writing output files...")
        
        # 1. Observations (long format) - one row per check result
        self._write_observations(check_results)
        
        # 2. Subdomain metrics - one row per subdomain
        self._write_subdomain_metrics(subdomain_scores)
        
        # 3. Control metrics - aggregated by control type
        self._write_control_metrics(check_results)
        
        # 4. Errors - separate file for easy debugging
        self._write_errors(check_results)
        
        # 5. Run metadata
        self._write_metadata(run_metadata, domain_summary)
        
        # 6. Optional Excel summary
        if self.enable_excel:
            self._write_excel(check_results, subdomain_scores, domain_summary)
        
        logger.info(f"Output written to {self.run_dir}")
    
    def _write_observations(self, results: List[CheckResult]) -> None:
        """Write observations in long/tidy format."""
        rows = []
        for result in results:
            row = {
                'target': result.target,
                'check_id': result.check_id,
                'status': result.status.value,
                'reason_code': result.reason_code.value,
                'message': result.message,
                'duration_ms': round(result.duration_ms, 2),
                'timestamp': result.timestamp.isoformat() if result.timestamp else '',
                'evidence': json.dumps(result.evidence) if result.evidence else ''
            }
            rows.append(row)
        
        output_file = self.run_dir / "observations_long.csv"
        write_csv(output_file, rows)
        logger.info(f"Wrote {len(rows)} observations to {output_file.name}")
    
    def _write_subdomain_metrics(self, scores: List[SubdomainScore]) -> None:
        """Write per-subdomain metrics."""
        rows = []
        for score in scores:
            row = {
                'target': score.target,
                'total_checks': score.total_checks,
                'tested_checks': score.tested_checks,
                'passed_checks': score.passed_checks,
                'failed_checks': score.failed_checks,
                'not_tested_checks': score.not_tested_checks,
                'not_applicable_checks': score.not_applicable_checks,
                'error_checks': score.error_checks,
                'pass_rate': round(score.pass_rate, 2),
                'attempt_rate': round(score.attempt_rate, 2),
                'error_rate': round(score.error_rate, 2),
                'risk_level': score.risk_level
            }
            rows.append(row)
        
        # Sort by pass_rate descending
        rows.sort(key=lambda x: x['pass_rate'], reverse=True)
        
        output_file = self.run_dir / "subdomain_metrics.csv"
        write_csv(output_file, rows)
        logger.info(f"Wrote {len(rows)} subdomain metrics to {output_file.name}")
    
    def _write_control_metrics(self, results: List[CheckResult]) -> None:
        """Write aggregated metrics by control/check type."""
        from scanner.checks.registry import get_check_by_id
        
        # Group by check_id
        by_check = {}
        for result in results:
            if result.check_id not in by_check:
                by_check[result.check_id] = []
            by_check[result.check_id].append(result)
        
        rows = []
        for check_id, check_results in by_check.items():
            try:
                check_def = get_check_by_id(check_id)
            except:
                continue
            
            total = len(check_results)
            passed = sum(1 for r in check_results if r.status.value == "Pass")
            failed = sum(1 for r in check_results if r.status.value == "Fail")
            not_tested = sum(1 for r in check_results if r.status.value == "Not Tested")
            errors = sum(1 for r in check_results if r.status.value == "Error")
            
            tested = passed + failed
            pass_rate = (passed / tested * 100) if tested > 0 else 0.0
            
            row = {
                'check_id': check_id,
                'check_name': check_def.name,
                'category': check_def.category.value,
                'total_targets': total,
                'passed': passed,
                'failed': failed,
                'not_tested': not_tested,
                'errors': errors,
                'tested': tested,
                'pass_rate': round(pass_rate, 2)
            }
            rows.append(row)
        
        # Sort by pass_rate ascending (show worst first)
        rows.sort(key=lambda x: x['pass_rate'])
        
        output_file = self.run_dir / "control_metrics.csv"
        write_csv(output_file, rows)
        logger.info(f"Wrote {len(rows)} control metrics to {output_file.name}")
    
    def _write_errors(self, results: List[CheckResult]) -> None:
        """Write error results to separate file for debugging."""
        error_rows = []
        for result in results:
            if result.status.value in ("Error", "Not Tested"):
                row = {
                    'target': result.target,
                    'check_id': result.check_id,
                    'status': result.status.value,
                    'reason_code': result.reason_code.value,
                    'message': result.message,
                    'evidence': json.dumps(result.evidence) if result.evidence else ''
                }
                error_rows.append(row)
        
        if error_rows:
            output_file = self.run_dir / "errors.csv"
            write_csv(output_file, error_rows)
            logger.info(f"Wrote {len(error_rows)} errors to {output_file.name}")
        else:
            logger.info("No errors to write")
    
    def _write_metadata(self, run_metadata: Dict[str, Any], domain_summary: Dict[str, Any]) -> None:
        """Write run metadata and domain summary to JSON.
        
        Unified schema containing:
        - run_id, domain, timestamps, duration
        - scanned_count, total_candidates, error_count
        - config settings
        - domain_summary (pass_rate, total_checks_run)
        """
        # Merge run_metadata and domain_summary into single unified format
        metadata = {
            # Contains: run_id, domain, started_at, finished_at, duration_seconds, config, etc.
            **run_metadata,
            'total_subdomains': domain_summary.get('total_subdomains', 0),
            'scanned_subdomains': domain_summary.get('scanned_subdomains', 0),
            'total_checks_run': domain_summary.get('total_checks_run', 0),
            'overall_pass_rate': round(domain_summary.get('overall_pass_rate', 0.0), 2)
        }
        
        output_file = self.run_dir / "run_metadata.json"
        write_json(output_file, metadata)
        logger.info(f"Wrote metadata to {output_file.name}")
    
    def _write_excel(self, 
                     results: List[CheckResult],
                     scores: List[SubdomainScore],
                     domain_summary: Dict[str, Any]) -> None:
        """Write Excel summary workbook (optional).
        
        Only called if enable_excel=True.
        Creates workbook from CSV data using openpyxl.
        """
        try:
            import pandas as pd
            from openpyxl import Workbook
            from openpyxl.styles import Font, PatternFill, Alignment
        except ImportError:
            logger.warning("pandas or openpyxl not available - skipping Excel output")
            return
        
        try:
            output_file = self.run_dir / "summary.xlsx"
            
            with pd.ExcelWriter(output_file, engine='openpyxl') as writer:
                # Read CSVs and write to Excel sheets
                obs_df = pd.read_csv(self.run_dir / "observations_long.csv")
                obs_df.to_excel(writer, sheet_name='Observations', index=False)
                
                sub_df = pd.read_csv(self.run_dir / "subdomain_metrics.csv")
                sub_df.to_excel(writer, sheet_name='Subdomain Metrics', index=False)
                
                ctrl_df = pd.read_csv(self.run_dir / "control_metrics.csv")
                ctrl_df.to_excel(writer, sheet_name='Control Metrics', index=False)
                
                # Summary sheet
                summary_data = {
                    'Metric': list(domain_summary.keys()),
                    'Value': list(domain_summary.values())
                }
                summary_df = pd.DataFrame(summary_data)
                summary_df.to_excel(writer, sheet_name='Domain Summary', index=False)
            
            logger.info(f"Wrote Excel summary to {output_file.name}")
        
        except Exception as e:
            logger.error(f"Failed to write Excel output: {e}")
    
    def get_output_dir(self) -> Path:
        """Return the output directory path."""
        return self.run_dir
