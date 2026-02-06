"""
Historical Tracking
===================
Tracks scan results over time for trend analysis and remediation progress
"""

import sqlite3
import json
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from pathlib import Path


class HistoricalTracker:
    """Track and analyze historical scan data"""
    
    def __init__(self, db_path: str = 'state/audit_history.db'):
        """Initialize historical tracker with database"""
        self.db_path = db_path
        self._init_database()
    
    def _init_database(self):
        """Initialize SQLite database schema"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT NOT NULL,
                    scan_date TIMESTAMP NOT NULL,
                    scan_id TEXT UNIQUE,
                    subdomain_count INTEGER,
                    vulnerable_count INTEGER,
                    critical_count INTEGER,
                    scan_results TEXT,  -- JSON
                    UNIQUE(domain, scan_date)
                )
            ''')
            
            conn.execute('''
                CREATE TABLE IF NOT EXISTS subdomain_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER,
                    domain TEXT NOT NULL,
                    subdomain TEXT NOT NULL,
                    first_seen TIMESTAMP,
                    last_seen TIMESTAMP,
                    status TEXT,  -- 'active', 'resolved', 'vulnerable'
                    FOREIGN KEY(scan_id) REFERENCES scans(id)
                )
            ''')
            
            conn.execute('''
                CREATE TABLE IF NOT EXISTS vulnerability_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER,
                    domain TEXT NOT NULL,
                    vulnerability_type TEXT,
                    risk_level TEXT,
                    subdomain TEXT,
                    first_detected TIMESTAMP,
                    last_detected TIMESTAMP,
                    status TEXT,  -- 'open', 'resolved', 'acknowledged'
                    FOREIGN KEY(scan_id) REFERENCES scans(id)
                )
            ''')
            
            conn.execute('''
                CREATE TABLE IF NOT EXISTS remediation_tracking (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    vulnerability_id INTEGER,
                    action TEXT,
                    action_date TIMESTAMP,
                    effectiveness TEXT,  -- 'resolved', 'partial', 'ineffective'
                    notes TEXT,
                    FOREIGN KEY(vulnerability_id) REFERENCES vulnerability_history(id)
                )
            ''')
            
            conn.commit()
    
    def record_scan(self, domain: str, scan_id: str, scan_results: Dict) -> int:
        """
        Record a complete scan result
        
        Returns:
            Scan ID in database
        """
        subdomains = scan_results.get('enumeration', {}).get('subdomains', [])
        vulnerabilities = scan_results.get('vulnerabilities', {})
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO scans (domain, scan_date, scan_id, subdomain_count, 
                                  vulnerable_count, critical_count, scan_results)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                domain,
                datetime.now(),
                scan_id,
                len(subdomains),
                vulnerabilities.get('total', 0),
                vulnerabilities.get('critical', 0),
                json.dumps(scan_results)
            ))
            
            scan_db_id = cursor.lastrowid
            conn.commit()
        
        return scan_db_id
    
    def track_subdomains(self, scan_id: int, domain: str, subdomains: List[str]) -> None:
        """Track subdomain discoveries and changes"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            for subdomain in subdomains:
                # Check if subdomain was seen before
                cursor.execute('''
                    SELECT id, last_seen FROM subdomain_history
                    WHERE domain = ? AND subdomain = ?
                    ORDER BY last_seen DESC LIMIT 1
                ''', (domain, subdomain))
                
                result = cursor.fetchone()
                
                if result:
                    # Update last_seen
                    cursor.execute('''
                        UPDATE subdomain_history
                        SET last_seen = ?
                        WHERE id = ?
                    ''', (datetime.now(), result[0]))
                else:
                    # New subdomain
                    cursor.execute('''
                        INSERT INTO subdomain_history 
                        (scan_id, domain, subdomain, first_seen, last_seen, status)
                        VALUES (?, ?, ?, ?, ?, 'active')
                    ''', (scan_id, domain, subdomain, datetime.now(), datetime.now()))
            
            conn.commit()
    
    def track_vulnerability(self, scan_id: int, domain: str, vuln_type: str, 
                           risk_level: str, subdomain: Optional[str] = None) -> int:
        """
        Track a discovered vulnerability
        
        Returns:
            Vulnerability ID
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Check if similar vulnerability exists
            cursor.execute('''
                SELECT id FROM vulnerability_history
                WHERE domain = ? AND vulnerability_type = ? AND subdomain = ?
                AND status != 'resolved'
                ORDER BY last_detected DESC LIMIT 1
            ''', (domain, vuln_type, subdomain))
            
            existing = cursor.fetchone()
            
            if existing:
                # Update last_detected
                cursor.execute('''
                    UPDATE vulnerability_history
                    SET last_detected = ?
                    WHERE id = ?
                ''', (datetime.now(), existing[0]))
                vuln_id = existing[0]
            else:
                # New vulnerability
                cursor.execute('''
                    INSERT INTO vulnerability_history
                    (scan_id, domain, vulnerability_type, risk_level, subdomain, 
                     first_detected, last_detected, status)
                    VALUES (?, ?, ?, ?, ?, ?, ?, 'open')
                ''', (scan_id, domain, vuln_type, risk_level, subdomain, 
                      datetime.now(), datetime.now()))
                vuln_id = cursor.lastrowid
            
            conn.commit()
        
        return vuln_id
    
    def get_trend_analysis(self, domain: str, days: int = 30) -> Dict:
        """
        Analyze trends over specified time period
        
        Returns:
            {
                'subdomain_growth': float,  # percentage change
                'vulnerability_trend': str,  # 'improving', 'stable', 'degrading'
                'critical_vulnerabilities': int,
                'new_subdomains': int,
                'remediated_vulnerabilities': int,
                'first_scan': datetime,
                'latest_scan': datetime,
                'scan_count': int
            }
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Get time period bounds
            cursor.execute('''
                SELECT MIN(scan_date), MAX(scan_date), COUNT(*) FROM scans
                WHERE domain = ? AND scan_date >= datetime('now', ? || ' days')
            ''', (domain, f'-{days}'))
            
            first_date, latest_date, scan_count = cursor.fetchone()
            
            if not first_date:
                return {'error': 'No scan data found'}
            
            # Get initial vs latest subdomain count
            cursor.execute('''
                SELECT subdomain_count FROM scans
                WHERE domain = ? ORDER BY scan_date ASC LIMIT 1
            ''', (domain,))
            initial_count = cursor.fetchone()[0] if cursor.fetchone() else 0
            
            cursor.execute('''
                SELECT subdomain_count FROM scans
                WHERE domain = ? ORDER BY scan_date DESC LIMIT 1
            ''', (domain,))
            latest_count = cursor.fetchone()[0] if cursor.fetchone() else 0
            
            # Calculate growth
            subdomain_growth = 0
            if initial_count > 0:
                subdomain_growth = ((latest_count - initial_count) / initial_count) * 100
            
            # Vulnerability trend
            cursor.execute('''
                SELECT vulnerable_count FROM scans
                WHERE domain = ? ORDER BY scan_date DESC LIMIT 2
            ''', (domain,))
            recent = cursor.fetchall()
            
            if len(recent) >= 2:
                if recent[0][0] < recent[1][0]:
                    trend = 'improving'
                elif recent[0][0] > recent[1][0]:
                    trend = 'degrading'
                else:
                    trend = 'stable'
            else:
                trend = 'unknown'
            
            # Count critical vulnerabilities
            cursor.execute('''
                SELECT COUNT(*) FROM scans
                WHERE domain = ? AND critical_count > 0
            ''', (domain,))
            critical_count = cursor.fetchone()[0]
            
            return {
                'subdomain_growth': round(subdomain_growth, 2),
                'vulnerability_trend': trend,
                'critical_vulnerabilities': critical_count,
                'scan_count': scan_count,
                'initial_subdomains': initial_count,
                'latest_subdomains': latest_count,
                'first_scan': first_date,
                'latest_scan': latest_date
            }
    
    def get_new_discoveries(self, domain: str, since_days: int = 7) -> List[str]:
        """Get subdomains discovered in last N days"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT subdomain FROM subdomain_history
                WHERE domain = ? AND first_seen >= datetime('now', ? || ' days')
            ''', (domain, f'-{since_days}'))
            
            return [row[0] for row in cursor.fetchall()]
    
    def get_remediation_status(self, domain: str) -> Dict[str, int]:
        """Get remediation status summary"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT status, COUNT(*) FROM vulnerability_history
                WHERE domain = ? GROUP BY status
            ''', (domain,))
            
            results = dict(cursor.fetchall())
            
            return {
                'open': results.get('open', 0),
                'resolved': results.get('resolved', 0),
                'acknowledged': results.get('acknowledged', 0)
            }
