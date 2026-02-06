"""SQLite-based persistent state manager for domain scanning.

WHY THIS EXISTS:
- Avoid re-scanning subdomains every run (respect RESCAN_HOURS)
- Reduce memory usage (don't keep 10K+ domains in RAM)
- Enable parallel enumeration + scanning (producer/consumer model)
- Crash-safe and resumable (all state in SQLite, not RAM)
- Atomic queue operations (no race conditions)

ARCHITECTURE:
- Single SQLite DB per domain (state/<domain>/state.db)
- WAL mode for concurrent reads + single writer
- Tables: meta, candidates, scan_queue, scan_runs, scan_results
- Enumerator writes discovered subdomains
- Scanner claims jobs atomically and marks completion
"""

import sqlite3
import json
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime, timedelta
from contextlib import contextmanager

logger = logging.getLogger(__name__)


class StateManager:
    """Persistent state manager using SQLite.
    
    Handles all disk I/O for subdomain discovery, scan queue, and results.
    Thread-safe with proper locking and WAL mode.
    """
    
    SCHEMA_VERSION = "1.0"
    
    def __init__(self, domain: str, state_dir: Path, rescan_hours: int = 24, 
                 error_retry_hours: int = 6, lease_minutes: int = 30):
        """Initialize state manager.
        
        Args:
            domain: Base domain (e.g., 'ac.lk')
            state_dir: Base state directory (e.g., 'state/')
            rescan_hours: Hours before rescanning a completed subdomain
            error_retry_hours: Hours before retrying a failed scan
            lease_minutes: Lease timeout for 'scanning' status (crash recovery)
        """
        self.domain = domain
        self.state_dir = state_dir / domain
        self.state_dir.mkdir(parents=True, exist_ok=True)
        
        self.db_path = self.state_dir / "state.db"
        self.rescan_hours = rescan_hours
        self.error_retry_hours = error_retry_hours
        self.lease_minutes = lease_minutes
        
        # Initialize database
        self._init_db()
        
        logger.info(f"State manager initialized: {self.db_path}")
        logger.info(f"  Rescan policy: {rescan_hours}h, Error retry: {error_retry_hours}h, Lease: {lease_minutes}m")
    
    @contextmanager
    def _get_conn(self, timeout: int = 10):
        """Get a database connection with proper configuration.
        
        WHY context manager: Ensures connections are always closed.
        WHY WAL mode: Allows concurrent readers while writer is active.
        WHY busy_timeout: Handles brief lock contention gracefully.
        """
        conn = sqlite3.connect(str(self.db_path), timeout=timeout)
        conn.row_factory = sqlite3.Row
        
        # Configure for concurrency and performance
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA temp_store=MEMORY")
        conn.execute(f"PRAGMA busy_timeout={timeout * 1000}")
        
        try:
            yield conn
        finally:
            conn.close()
    
    def _init_db(self):
        """Initialize database schema if not exists.
        
        WHY this schema:
        - meta: Configuration and domain metadata
        - candidates: All discovered subdomains (persistent discovery log)
        - scan_queue: Durable queue with status tracking
        - scan_runs: Audit log of scan executions
        - scan_results: Summary metrics per (fqdn, run_id)
        """
        with self._get_conn() as conn:
            # Meta table (config/metadata)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
            """)
            
            # Candidates table (persistent discovery log)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS candidates (
                    fqdn TEXT PRIMARY KEY,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    sources TEXT NOT NULL,
                    confidence TEXT NOT NULL,
                    dns_state TEXT,
                    notes TEXT
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_candidates_last_seen ON candidates(last_seen)")
            
            # Scan queue (durable job queue with time-based eligibility)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scan_queue (
                    fqdn TEXT PRIMARY KEY,
                    status TEXT NOT NULL DEFAULT 'never',
                    last_scan_time TEXT,
                    next_scan_time TEXT,
                    last_error TEXT,
                    attempts INTEGER DEFAULT 0,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY (fqdn) REFERENCES candidates(fqdn)
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_queue_status ON scan_queue(status, next_scan_time)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_queue_next_scan ON scan_queue(next_scan_time)")
            
            # Scan runs (audit trail)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scan_runs (
                    run_id TEXT PRIMARY KEY,
                    started_at TEXT NOT NULL,
                    finished_at TEXT,
                    config_json TEXT,
                    enumerated_count INTEGER DEFAULT 0,
                    scanned_count INTEGER DEFAULT 0,
                    errors_count INTEGER DEFAULT 0
                )
            """)
            
            # Scan results (summary per fqdn per run)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scan_results (
                    fqdn TEXT NOT NULL,
                    run_id TEXT NOT NULL,
                    scan_time TEXT NOT NULL,
                    overall_score REAL,
                    risk_bucket TEXT,
                    tested_count INTEGER DEFAULT 0,
                    pass_count INTEGER DEFAULT 0,
                    fail_count INTEGER DEFAULT 0,
                    not_tested_count INTEGER DEFAULT 0,
                    not_applicable_count INTEGER DEFAULT 0,
                    error_count INTEGER DEFAULT 0,
                    findings_summary TEXT,
                    PRIMARY KEY (fqdn, run_id)
                )
            """)
            
            conn.commit()
            
            # Initialize meta if empty
            cursor = conn.execute("SELECT COUNT(*) as cnt FROM meta")
            if cursor.fetchone()['cnt'] == 0:
                now = datetime.utcnow().isoformat()
                conn.executemany("INSERT INTO meta (key, value) VALUES (?, ?)", [
                    ('domain', self.domain),
                    ('created_at', now),
                    ('rescan_hours', str(self.rescan_hours)),
                    ('error_retry_hours', str(self.error_retry_hours)),
                    ('schema_version', self.SCHEMA_VERSION),
                ])
                conn.commit()
                logger.info(f"Initialized new state database for {self.domain}")
    
    def upsert_candidate(self, fqdn: str, sources: List[str], confidence: str = "Medium", 
                        dns_state: Optional[str] = None, notes: Optional[str] = None):
        """Add or update a discovered subdomain candidate.
        
        WHY upsert: Enumerator may rediscover same subdomain from multiple sources.
        WHY sources list: Track provenance (CT logs, brute-force, DNS, etc.)
        
        This also adds the candidate to scan_queue if not present.
        """
        now = datetime.utcnow().isoformat()
        
        with self._get_conn() as conn:
            # Check if exists
            cursor = conn.execute("SELECT fqdn, sources FROM candidates WHERE fqdn = ?", (fqdn,))
            row = cursor.fetchone()
            
            if row:
                # Merge sources (union)
                existing_sources = set(json.loads(row['sources']))
                merged_sources = list(existing_sources.union(set(sources)))
                
                conn.execute("""
                    UPDATE candidates 
                    SET last_seen = ?, sources = ?, confidence = ?, dns_state = ?, notes = ?
                    WHERE fqdn = ?
                """, (now, json.dumps(merged_sources), confidence, dns_state, notes, fqdn))
            else:
                # New candidate
                conn.execute("""
                    INSERT INTO candidates (fqdn, first_seen, last_seen, sources, confidence, dns_state, notes)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (fqdn, now, now, json.dumps(sources), confidence, dns_state, notes))
            
            # Add to scan queue if not exists
            cursor = conn.execute("SELECT fqdn FROM scan_queue WHERE fqdn = ?", (fqdn,))
            if not cursor.fetchone():
                conn.execute("""
                    INSERT INTO scan_queue (fqdn, status, next_scan_time, updated_at)
                    VALUES (?, 'never', ?, ?)
                """, (fqdn, now, now))
            
            conn.commit()
    
    def claim_scan_jobs(self, batch_size: int = 50) -> List[str]:
        """Atomically claim eligible scan jobs.
        
        WHY atomic: Prevents multiple workers from claiming same job.
        WHY eligibility check: Only claim if never scanned OR rescan time elapsed.
        WHY lease recovery: Reclaim jobs stuck in 'scanning' status > lease timeout.
        
        Returns: List of FQDNs to scan
        """
        now = datetime.utcnow()
        now_iso = now.isoformat()
        lease_cutoff = (now - timedelta(minutes=self.lease_minutes)).isoformat()
        
        with self._get_conn() as conn:
            # BEGIN IMMEDIATE ensures exclusive write access
            conn.execute("BEGIN IMMEDIATE")
            
            try:
                # Find eligible jobs:
                # 1. status='never' => never scanned
                # 2. status='scanned' AND next_scan_time <= now => rescan due
                # 3. status='error' AND next_scan_time <= now => retry due
                # 4. status='queued' AND next_scan_time <= now => ready
                # 5. status='scanning' AND updated_at < lease_cutoff => lease expired (crash recovery)
                # EXCLUDE: status='failed_permanent' => stop retrying
                
                cursor = conn.execute("""
                    SELECT fqdn FROM scan_queue
                    WHERE (
                        (status = 'never')
                        OR (status IN ('queued', 'scanned', 'error') AND next_scan_time <= ?)
                        OR (status = 'scanning' AND updated_at < ?)
                    )
                    AND status != 'failed_permanent'
                    ORDER BY 
                        CASE status
                            WHEN 'never' THEN 1
                            WHEN 'queued' THEN 2
                            WHEN 'error' THEN 3
                            WHEN 'scanned' THEN 4
                            WHEN 'scanning' THEN 5
                        END,
                        next_scan_time ASC NULLS FIRST,
                        updated_at ASC
                    LIMIT ?
                """, (now_iso, lease_cutoff, batch_size))
                
                claimed = [row['fqdn'] for row in cursor.fetchall()]
                
                if claimed:
                    # Mark as scanning
                    placeholders = ','.join('?' * len(claimed))
                    conn.execute(f"""
                        UPDATE scan_queue
                        SET status = 'scanning', updated_at = ?
                        WHERE fqdn IN ({placeholders})
                    """, [now_iso] + claimed)
                
                conn.commit()
                
                if claimed:
                    logger.debug(f"Claimed {len(claimed)} scan jobs")
                
                return claimed
                
            except Exception as e:
                conn.rollback()
                logger.error(f"Failed to claim scan jobs: {e}")
                return []
    
    def mark_scan_complete(self, fqdn: str, success: bool = True, error_msg: Optional[str] = None,
                          scan_summary: Optional[Dict[str, Any]] = None):
        """Mark a scan job as complete.
        
        WHY next_scan_time: Automatically schedule rescan based on policy.
        WHY attempts: Track retry count for error cases.
        """
        now = datetime.utcnow()
        now_iso = now.isoformat()
        
        with self._get_conn() as conn:
            if success:
                # Calculate next scan time based on rescan policy
                next_scan = now + timedelta(hours=self.rescan_hours)
                
                conn.execute("""
                    UPDATE scan_queue
                    SET status = 'scanned',
                        last_scan_time = ?,
                        next_scan_time = ?,
                        last_error = NULL,
                        updated_at = ?
                    WHERE fqdn = ?
                """, (now_iso, next_scan.isoformat(), now_iso, fqdn))
            else:
                # Calculate retry time based on error policy
                next_retry = now + timedelta(hours=self.error_retry_hours)
                
                conn.execute("""
                    UPDATE scan_queue
                    SET status = 'error',
                        last_scan_time = ?,
                        next_scan_time = ?,
                        last_error = ?,
                        attempts = attempts + 1,
                        updated_at = ?
                    WHERE fqdn = ?
                """, (now_iso, next_retry.isoformat(), error_msg, now_iso, fqdn))
            
            conn.commit()
    
    def save_scan_result(self, fqdn: str, run_id: str, check_results: List[Dict[str, Any]],
                        overall_score: Optional[float] = None):
        """Save scan results summary.
        
        WHY summary only: Full check details go to CSV exports.
        WHY indexed by (fqdn, run_id): Historical scan comparison.
        """
        now_iso = datetime.utcnow().isoformat()
        
        # Compute counts
        status_counts = {
            'tested': 0,
            'pass': 0,
            'fail': 0,
            'not_tested': 0,
            'not_applicable': 0,
            'error': 0
        }
        
        for result in check_results:
            status = result.get('status', '').lower()
            if 'pass' in status:
                status_counts['pass'] += 1
                status_counts['tested'] += 1
            elif 'fail' in status:
                status_counts['fail'] += 1
                status_counts['tested'] += 1
            elif 'not tested' in status:
                status_counts['not_tested'] += 1
            elif 'not applicable' in status:
                status_counts['not_applicable'] += 1
            elif 'error' in status:
                status_counts['error'] += 1
        
        # Determine risk bucket
        if status_counts['tested'] == 0:
            risk_bucket = "Unknown"
        else:
            pass_rate = status_counts['pass'] / status_counts['tested']
            if pass_rate >= 0.8:
                risk_bucket = "Low"
            elif pass_rate >= 0.5:
                risk_bucket = "Medium"
            else:
                risk_bucket = "High"
        
        # Top findings summary (comma-separated check IDs of failures)
        failed_checks = []
        for result in check_results:
            if result.get('status', '').lower() == 'fail':
                failed_checks.append(result.get('check_id', 'Unknown'))
        findings_text = ', '.join(failed_checks[:5])  # Top 5 failures for quick view
        
        # Store full check results as JSON for detailed analysis
        findings_json = json.dumps(check_results)
        
        with self._get_conn() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO scan_results 
                (fqdn, run_id, scan_time, overall_score, risk_bucket,
                 tested_count, pass_count, fail_count, not_tested_count, 
                 not_applicable_count, error_count, findings_summary)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (fqdn, run_id, now_iso, overall_score, risk_bucket,
                  status_counts['tested'], status_counts['pass'], status_counts['fail'],
                  status_counts['not_tested'], status_counts['not_applicable'],
                  status_counts['error'], findings_json))  # Store JSON, not comma string
            conn.commit()
    
    def get_stats(self) -> Dict[str, Any]:
        """Get current state statistics.
        
        WHY: Monitoring and progress tracking.
        """
        with self._get_conn() as conn:
            stats = {}
            
            # Total candidates
            cursor = conn.execute("SELECT COUNT(*) as cnt FROM candidates")
            stats['total_candidates'] = cursor.fetchone()['cnt']
            
            # Queue status breakdown
            cursor = conn.execute("""
                SELECT status, COUNT(*) as cnt
                FROM scan_queue
                GROUP BY status
            """)
            stats['queue_by_status'] = {row['status']: row['cnt'] for row in cursor.fetchall()}
            
            # Recent scans
            cursor = conn.execute("""
                SELECT COUNT(*) as cnt
                FROM scan_queue
                WHERE last_scan_time IS NOT NULL
            """)
            stats['ever_scanned'] = cursor.fetchone()['cnt']
            
            # Eligible for scan now
            now = datetime.utcnow().isoformat()
            cursor = conn.execute("""
                SELECT COUNT(*) as cnt
                FROM scan_queue
                WHERE (status = 'never')
                   OR (status IN ('queued', 'scanned', 'error') AND next_scan_time <= ?)
            """, (now,))
            stats['eligible_now'] = cursor.fetchone()['cnt']
            
            return stats
    
    def create_run(self, run_id: str, config: Dict[str, Any]) -> None:
        """Create a new scan run record."""
        now_iso = datetime.utcnow().isoformat()
        
        with self._get_conn() as conn:
            conn.execute("""
                INSERT INTO scan_runs (run_id, started_at, config_json)
                VALUES (?, ?, ?)
            """, (run_id, now_iso, json.dumps(config)))
            conn.commit()
    
    def update_run(self, run_id: str, enumerated: int = 0, scanned: int = 0, errors: int = 0):
        """Update scan run statistics."""
        with self._get_conn() as conn:
            conn.execute("""
                UPDATE scan_runs
                SET enumerated_count = ?, scanned_count = ?, errors_count = ?
                WHERE run_id = ?
            """, (enumerated, scanned, errors, run_id))
            conn.commit()
    
    def finish_run(self, run_id: str):
        """Mark scan run as finished."""
        now_iso = datetime.utcnow().isoformat()
        
        with self._get_conn() as conn:
            conn.execute("""
                UPDATE scan_runs
                SET finished_at = ?
                WHERE run_id = ?
            """, (now_iso, run_id))
            conn.commit()
    
    def export_candidates_csv(self, output_path: Path):
        """Export candidates to CSV for human analysis."""
        import csv
        
        with self._get_conn() as conn:
            cursor = conn.execute("""
                SELECT c.fqdn, c.first_seen, c.last_seen, c.sources, c.confidence,
                       q.status, q.last_scan_time, q.next_scan_time, q.attempts
                FROM candidates c
                LEFT JOIN scan_queue q ON c.fqdn = q.fqdn
                ORDER BY c.last_seen DESC
            """)
            
            rows = cursor.fetchall()
            
            with open(output_path, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=[
                    'fqdn', 'first_seen', 'last_seen', 'sources', 'confidence',
                    'scan_status', 'last_scan_time', 'next_scan_time', 'attempts'
                ])
                writer.writeheader()
                
                for row in rows:
                    writer.writerow({
                        'fqdn': row['fqdn'],
                        'first_seen': row['first_seen'],
                        'last_seen': row['last_seen'],
                        'sources': row['sources'],
                        'confidence': row['confidence'],
                        'scan_status': row['status'] or 'never',
                        'last_scan_time': row['last_scan_time'] or '',
                        'next_scan_time': row['next_scan_time'] or '',
                        'attempts': row['attempts'] or 0
                    })
        
        logger.info(f"Exported {len(rows)} candidates to {output_path}")
    
    def export_scan_results_csv(self, output_path: Path, run_id: str = None):
        """Export aggregated scan results to CSV for analysis.
        
        Args:
            output_path: Path to write CSV file
            run_id: Optional run ID to filter results (default: all results)
        """
        import csv
        
        with self._get_conn() as conn:
            if run_id:
                cursor = conn.execute("""
                    SELECT fqdn, run_id, scan_time, overall_score, risk_bucket,
                           tested_count, pass_count, fail_count, 
                           not_tested_count, not_applicable_count, error_count
                    FROM scan_results
                    WHERE run_id = ?
                    ORDER BY fqdn
                """, (run_id,))
            else:
                cursor = conn.execute("""
                    SELECT fqdn, run_id, scan_time, overall_score, risk_bucket,
                           tested_count, pass_count, fail_count,
                           not_tested_count, not_applicable_count, error_count
                    FROM scan_results
                    ORDER BY fqdn
                """)
            
            rows = cursor.fetchall()
            
            if not rows:
                logger.warning(f"No scan results to export for run_id={run_id}")
                return
            
            with open(output_path, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=[
                    'fqdn', 'run_id', 'scan_time', 'overall_score', 'risk_bucket',
                    'tested_count', 'pass_count', 'fail_count',
                    'not_tested_count', 'not_applicable_count', 'error_count'
                ])
                writer.writeheader()
                
                for row in rows:
                    writer.writerow({
                        'fqdn': row['fqdn'],
                        'run_id': row['run_id'],
                        'scan_time': row['scan_time'],
                        'overall_score': round(row['overall_score'], 2) if row['overall_score'] else 0.0,
                        'risk_bucket': row['risk_bucket'],
                        'tested_count': row['tested_count'],
                        'pass_count': row['pass_count'],
                        'fail_count': row['fail_count'],
                        'not_tested_count': row['not_tested_count'],
                        'not_applicable_count': row['not_applicable_count'],
                        'error_count': row['error_count']
                    })
        
        logger.info(f"Exported {len(rows)} scan results to {output_path}")
    
    def get_all_check_results(self, run_id: str = None) -> List[Dict[str, Any]]:
        """Extract individual check results from findings_summary JSON.
        
        Args:
            run_id: Optional run ID to filter results
            
        Returns:
            List of check result dicts (observations)
        """
        all_observations = []
        
        with self._get_conn() as conn:
            if run_id:
                cursor = conn.execute("""
                    SELECT fqdn, findings_summary
                    FROM scan_results
                    WHERE run_id = ? AND findings_summary IS NOT NULL
                """, (run_id,))
            else:
                cursor = conn.execute("""
                    SELECT fqdn, findings_summary
                    FROM scan_results
                    WHERE findings_summary IS NOT NULL
                """)
            
            for row in cursor.fetchall():
                if row['findings_summary']:
                    try:
                        findings = json.loads(row['findings_summary'])
                        if isinstance(findings, list):
                            all_observations.extend(findings)
                    except json.JSONDecodeError:
                        logger.warning(f"Failed to parse findings for {row['fqdn']}")
        
        return all_observations
    
    def get_all_scores(self, run_id: str = None) -> List[Dict[str, Any]]:
        """Get all subdomain scores.
        
        Args:
            run_id: Optional run ID to filter results
            
        Returns:
            List of score dicts for SubdomainScore conversion
        """
        scores = []
        
        with self._get_conn() as conn:
            if run_id:
                cursor = conn.execute("""
                    SELECT fqdn, overall_score, risk_bucket,
                           tested_count, pass_count, fail_count,
                           not_tested_count, not_applicable_count, error_count
                    FROM scan_results
                    WHERE run_id = ?
                """, (run_id,))
            else:
                cursor = conn.execute("""
                    SELECT fqdn, overall_score, risk_bucket,
                           tested_count, pass_count, fail_count,
                           not_tested_count, not_applicable_count, error_count
                    FROM scan_results
                """)
            
            for row in cursor.fetchall():
                scores.append({
                    'target': row['fqdn'],
                    'overall_score': row['overall_score'] or 0.0,
                    'risk_level': row['risk_bucket'] or 'Unknown',
                    'total_checks': (row['tested_count'] + row['not_tested_count'] + 
                                   row['not_applicable_count'] + row['error_count']),
                    'tested_checks': row['tested_count'],
                    'passed_checks': row['pass_count'],
                    'failed_checks': row['fail_count'],
                    'not_tested_checks': row['not_tested_count'],
                    'not_applicable_checks': row['not_applicable_count'],
                    'error_checks': row['error_count'],
                    'pass_rate': row['overall_score'] or 0.0,
                    'attempt_rate': (row['tested_count'] / (row['tested_count'] + row['not_tested_count'] + 
                                    row['not_applicable_count'] + row['error_count']) * 100) if (row['tested_count'] + row['not_tested_count'] + 
                                    row['not_applicable_count'] + row['error_count']) > 0 else 0.0,
                    'error_rate': (row['error_count'] / (row['tested_count'] + row['not_tested_count'] + 
                                  row['not_applicable_count'] + row['error_count']) * 100) if (row['tested_count'] + row['not_tested_count'] + 
                                  row['not_applicable_count'] + row['error_count']) > 0 else 0.0
                })
        
        return scores
    
    def get_all_candidates(self) -> List[str]:
        """Get all candidate FQDNs (for initial seeding).
        
        WHY: Scanner can start immediately with existing discoveries.
        """
        with self._get_conn() as conn:
            cursor = conn.execute("SELECT fqdn FROM candidates ORDER BY last_seen DESC")
            return [row['fqdn'] for row in cursor.fetchall()]

    def set_meta(self, key: str, value: str):
        """Set a metadata key-value pair.
        
        WHY: Store coordination flags like enumeration_done.
        """
        with self._get_conn() as conn:
            conn.execute("""
                INSERT INTO meta (key, value) VALUES (?, ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
            """, (key, value))
            conn.commit()

    def get_meta(self, key: str, default: Optional[str] = None) -> Optional[str]:
        """Get a metadata value by key.
        
        Args:
            key: Metadata key
            default: Default value if key not found
        
        Returns:
            Value or default
        """
        with self._get_conn() as conn:
            cursor = conn.execute(
                "SELECT value FROM meta WHERE key = ?", (key,))
            row = cursor.fetchone()
            return row['value'] if row else default    
    def get_scan_attempts(self, fqdn: str) -> int:
        """Get the number of scan attempts for a subdomain.
        
        WHY: Used to implement max retry limits (e.g., fail permanently after 3 attempts).
        
        Args:
            fqdn: Fully qualified domain name
        
        Returns:
            Number of scan attempts (0 if never scanned)
        """
        with self._get_conn() as conn:
            cursor = conn.execute("""
                SELECT attempts FROM scan_queue WHERE fqdn = ?
            """, (fqdn,))
            row = cursor.fetchone()
            return row['attempts'] if row else 0
    
    def mark_scan_failed_permanent(self, fqdn: str, error_msg: str):
        """Mark a scan as permanently failed (stop retrying).
        
        WHY: Prevents infinite retry loops for unfixable errors (e.g., DNS doesn't exist).
        After max attempts exceeded, we mark as 'failed_permanent' so it won't be
        retried even if next_scan_time arrives.
        
        Args:
            fqdn: Fully qualified domain name
            error_msg: Error message describing why scan failed
        """
        now = datetime.utcnow()
        now_iso = now.isoformat()
        
        with self._get_conn() as conn:
            conn.execute("""
                UPDATE scan_queue
                SET status = 'failed_permanent',
                    last_scan_time = ?,
                    next_scan_time = NULL,
                    last_error = ?,
                    attempts = attempts + 1,
                    updated_at = ?
                WHERE fqdn = ?
            """, (now_iso, f"PERMANENT FAILURE: {error_msg}", now_iso, fqdn))
            conn.commit()
        
        logger.warning(f"🚫 {fqdn}: Marked as permanently failed - {error_msg}")