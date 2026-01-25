"""Main application entrypoint with persistent state management.

WHY THIS EXISTS:
- Coordinates parallel enumeration (producer) and scanning (consumer)
- Uses SQLite for persistent state (resumable after crashes)
- Avoids rescanning targets until RESCAN_HOURS elapsed
- Reduces memory usage (no huge lists in RAM)

ARCHITECTURE:
1. Initialize StateManager (SQLite)
2. Spawn enumerator worker (discovers subdomains → writes to DB)
3. Spawn scanner worker (claims eligible targets → scans → marks complete)
4. Both run in parallel (scanner processes discoveries as they arrive)
5. Export results to CSV when complete
"""

import asyncio
import sys
import logging
from pathlib import Path
from datetime import datetime, timezone

# Add src directory to path
src_dir = Path(__file__).parent
if str(src_dir) not in sys.path:
    sys.path.insert(0, str(src_dir))

from util.config import Config
from util.log import setup_logging
from util.time import timestamp_str
from util.types import CheckResult, CheckStatus, ReasonCode
from state.state_manager import StateManager
from scanner.enumerator_worker import run_enumerator
from scanner.scan_worker import run_scanner_worker
from scanner.output.writer import OutputWriter
from scanner.scoring.model import SubdomainScore

logger = logging.getLogger(__name__)


async def main_async(config: Config):
    """Main async execution coordinator.
    
    WHY async: Both enumeration and scanning are I/O-bound (DNS, HTTP, TLS).
    Running them in parallel maximizes throughput.
    
    Returns:
        dict with execution results
    """
    start_time = datetime.now(timezone.utc).replace(tzinfo=None)
    run_id = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    
    logger.info("="*60)
    logger.info("Security Scanner with Persistent State Management")
    logger.info("="*60)
    logger.info(f"Domain: {config.domain}")
    logger.info(f"Run ID: {run_id}")
    logger.info(f"State DB: {config.state_dir / config.domain / 'state.db'}")
    logger.info(f"Rescan policy: {config.rescan_hours}h")
    logger.info("="*60)
    
    # Initialize state manager
    state_mgr = StateManager(
        domain=config.domain,
        state_dir=config.state_dir,
        rescan_hours=config.rescan_hours,
        error_retry_hours=config.error_retry_hours,
        lease_minutes=config.lease_minutes
    )
    
    # Create scan run record
    state_mgr.create_run(run_id, config.to_dict())
    
    # Reset enumeration_done flag for fresh run
    state_mgr.set_meta('enumeration_done', 'false')

    # Show initial stats
    stats = state_mgr.get_stats()
    logger.info(f"Initial state:")
    logger.info(f"  Total candidates: {stats['total_candidates']}")
    logger.info(f"  Eligible for scan: {stats['eligible_now']}")
    logger.info(f"  Ever scanned: {stats['ever_scanned']}")
    logger.info("")
    
    # === PARALLEL EXECUTION ===
    # Strategy: Run enumeration and scanning in parallel
    # Scanner continuously polls for new targets while enumerator discovers
    
    logger.info("Starting PARALLEL execution:")
    logger.info("  - Enumerator: Discovering subdomains (CT logs, DNS, SRV, PTR, crawl-lite)")
    if config.allow_active_probes:
        logger.info(
            "  - Scanner: Polling DB for new targets and scanning as they arrive")
    else:
        logger.info(
            "  - Passive-only mode: Scanner is disabled (no active probes)")
    logger.info("")
    
    if config.allow_active_probes:
        # Create scanner task (runs continuously, polls DB)
        scanner_task = asyncio.create_task(
            run_scanner_worker(
                config.domain,
                state_mgr,
                config,
                run_id,
                continuous=True  # Poll mode: scan as targets arrive
            )
        )
    else:
        scanner_task = None
    
    # Create enumerator task
    enumerator_task = asyncio.create_task(
        run_enumerator(config.domain, config.state_dir, config, state_mgr)
    )
    
    # Wait for enumeration to complete
    logger.info("Waiting for enumeration to complete...")
    enum_count, method_counts = await enumerator_task
    logger.info("")
    logger.info(f"Enumeration complete: {enum_count} subdomains discovered")
    
    # Show stats after enumeration
    stats = state_mgr.get_stats()
    logger.info(f"Post-enumeration state:")
    logger.info(f"  Total candidates: {stats['total_candidates']}")
    logger.info(f"  Eligible for scan: {stats['eligible_now']}")
    logger.info("")
    
    if config.allow_active_probes and scanner_task:
        # Wait for scanner to finish processing all eligible targets
        logger.info("Waiting for scanner to complete remaining targets...")
        scanner_worker = await scanner_task
        scanned_count = scanner_worker.scanned_count
        error_count = scanner_worker.error_count

        # Update run statistics
        stats = state_mgr.get_stats()
        state_mgr.update_run(
            run_id,
            enumerated=stats['total_candidates'],
            scanned=scanned_count,
            errors=error_count
        )
    else:
        # Passive-only: no scanning performed
        scanner_worker = None
        scanned_count = 0
        error_count = 0
        state_mgr.update_run(
            run_id,
            enumerated=stats['total_candidates'],
            scanned=scanned_count,
            errors=error_count
        )
        state_mgr.set_meta('enumeration_done', 'true')
    state_mgr.finish_run(run_id)
    
    # === EXPORT RESULTS ===
    logger.info("")
    logger.info("Exporting results...")
    
    # Create output directory
    output_dir = config.out_dir / config.domain / datetime.now(timezone.utc).strftime("%Y-%m-%d") / run_id
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Export candidates list
    candidates_csv = output_dir / "discovered_candidates.csv"
    state_mgr.export_candidates_csv(candidates_csv)
    logger.info(f"Exported candidates to {candidates_csv}")
    
    # Export method counts
    if method_counts:
        method_counts_csv = output_dir / "enumeration_method_counts.csv"
        with open(method_counts_csv, 'w', newline='') as f:
            import csv
            writer = csv.writer(f)
            writer.writerow(['discovery_method', 'subdomain_count'])
            for method, count in sorted(method_counts.items()):
                writer.writerow([method, count])
        logger.info(f"Exported enumeration methods to {method_counts_csv}")
    
    # Export aggregated scan results (subdomain-level scores)
    # Generate CSVs even if scanned_count=0 (will have headers only)
    subdomain_results_csv = output_dir / "subdomain_metrics.csv"
    state_mgr.export_scan_results_csv(subdomain_results_csv, run_id)
    logger.info(f"Exported subdomain metrics to {subdomain_results_csv}")

    # Extract detailed check results from findings_summary JSON
    check_observations = state_mgr.get_all_check_results(run_id)
    subdomain_scores = state_mgr.get_all_scores(run_id)

    if check_observations:
        # Convert observations to CheckResult objects for OutputWriter
        check_results = []
        for obs in check_observations:
                try:
                    check_results.append(CheckResult(
                        check_id=obs.get('check_id', ''),
                        target=obs.get('target', ''),
                        status=CheckStatus(obs.get('status', 'Error')),
                        reason_code=ReasonCode(obs.get('reason_code', 'unknown_error')),
                        evidence=obs.get('evidence', {}),
                        duration_ms=obs.get('duration_ms', 0.0),
                        timestamp=None,  # Parse if needed
                        message=obs.get('message', '')
                    ))
                except (ValueError, KeyError) as e:
                    logger.warning(f"Skipping malformed observation: {e}")

        # Convert score dicts to SubdomainScore objects
        score_objects = []
        for score_dict in subdomain_scores:
            try:
                score_objects.append(SubdomainScore(
                    target=score_dict['target'],
                    total_checks=score_dict['total_checks'],
                    tested_checks=score_dict['tested_checks'],
                    passed_checks=score_dict['passed_checks'],
                    failed_checks=score_dict['failed_checks'],
                    not_tested_checks=score_dict['not_tested_checks'],
                    not_applicable_checks=score_dict['not_applicable_checks'],
                    error_checks=score_dict['error_checks']
                ))
            except (ValueError, KeyError) as e:
                logger.warning(f"Skipping malformed score: {e}")

        # Use OutputWriter to generate research-ready CSVs
        writer = OutputWriter(config.domain, str(
            config.out_dir), enable_excel=False, run_dir=output_dir)

        # Compute domain-level summary stats
        domain_summary = {
            'total_subdomains': stats['total_candidates'],
            'scanned_subdomains': scanned_count,
            'total_checks_run': len(check_results),
            'overall_pass_rate': (sum(1 for r in check_results if r.status == CheckStatus.PASS) /
                                  len([r for r in check_results if r.status in (CheckStatus.PASS, CheckStatus.FAIL)]) * 100)
            if len([r for r in check_results if r.status in (CheckStatus.PASS, CheckStatus.FAIL)]) > 0 else 0.0
        }

        # Generate all research CSVs (observations, metrics, control_metrics, errors)
        writer.write_all(
            check_results=check_results,
            subdomain_scores=score_objects,
            domain_summary=domain_summary,
            run_metadata={
                'run_id': run_id,
                'domain': config.domain,
                'started_at': start_time.isoformat(),
                'finished_at': datetime.utcnow().isoformat(),
                'duration_seconds': (datetime.utcnow() - start_time).total_seconds(),
                'scanned_count': scanned_count,
                'total_candidates': stats['total_candidates'],
                'error_count': error_count,
                'rescan_hours': config.rescan_hours,
                'config': config.to_dict()
            }
        )
        logger.info(f"Generated research CSVs in {writer.get_output_dir()}")
    else:
        # No scan results yet, but create empty CSVs with headers
        writer = OutputWriter(config.domain, str(
            config.out_dir), enable_excel=False, run_dir=output_dir)
        writer.write_all(
            check_results=[],
            subdomain_scores=[],
            domain_summary={
                'total_subdomains': stats['total_candidates'],
                'scanned_subdomains': 0,
                'total_checks_run': 0,
                'overall_pass_rate': 0.0
            },
            run_metadata={
                'run_id': run_id,
                'domain': config.domain,
                'started_at': start_time.isoformat(),
                'finished_at': datetime.utcnow().isoformat(),
                'duration_seconds': (datetime.utcnow() - start_time).total_seconds(),
                'scanned_count': scanned_count,
                'total_candidates': stats['total_candidates'],
                'error_count': error_count,
                'rescan_hours': config.rescan_hours,
                'config': config.to_dict()
            }
        )
        logger.info(
            f"Generated empty research CSVs (headers only) in {writer.get_output_dir()}")
    
    # Write run metadata JSON
    end_time = datetime.utcnow()
    duration = (end_time - start_time).total_seconds()
    
    # Final summary
    logger.info("="*60)
    logger.info("Scan Complete!")
    logger.info(f"  Duration: {duration:.1f}s")
    logger.info(f"  Total candidates: {stats['total_candidates']}")
    logger.info(f"  Scanned: {scanned_count}")
    logger.info(f"  Errors: {error_count}")
    logger.info(f"  Output: {output_dir}")
    logger.info("="*60)
    
    return {
        'success': True,
        'run_id': run_id,
        'duration_seconds': duration,
        'total_candidates': stats['total_candidates'],
        'scanned_count': scanned_count,
        'error_count': error_count,
        'output_dir': str(output_dir)
    }


def main():
    """Main entry point."""
    try:
        # Load configuration
        config = Config()
        
        # Set up logging
        log_dir = config.out_dir / config.domain / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        log_file = log_dir / f"scan_{timestamp_str()}.log"
        setup_logging(log_file=log_file, level=logging.INFO)
        
        # Run async main
        result = asyncio.run(main_async(config))
        
        # Print summary
        if result['success']:
            print(f"\n✓ Scan complete for {config.domain}")
            print(f"  Total candidates: {result['total_candidates']}")
            print(f"  Scanned: {result['scanned_count']}")
            print(f"  Output: {result['output_dir']}")
            print(f"  Duration: {result['duration_seconds']:.1f}s")
            print(f"\nState persisted to: {config.state_dir / config.domain / 'state.db'}")
            print(f"Next rescan eligible after: {config.rescan_hours}h")
            return 0
        else:
            print(f"\n✗ Scan failed")
            return 1
    
    except ValueError as e:
        print(f"\n✗ Configuration error: {e}")
        print("\nCreate .env file with: DOMAIN=your-domain.com")
        return 1
    
    except KeyboardInterrupt:
        print("\n\n✗ Scan interrupted by user")
        return 130
    
    except Exception as e:
        logging.error(f"Unexpected error: {e}", exc_info=True)
        print(f"\n✗ Unexpected error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())

