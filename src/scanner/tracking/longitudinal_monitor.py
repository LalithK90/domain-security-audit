"""
Longitudinal Monitor
====================
Monitors domain security changes over time with scheduled scanning
"""

import asyncio
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Callable
import logging


class LongitudinalMonitor:
    """
    Longitudinal domain security monitoring with scheduled scanning
    """
    
    def __init__(self, callback: Optional[Callable] = None):
        """
        Initialize longitudinal monitor
        
        Args:
            callback: Async function to call on scheduled scan
        """
        self.scheduler = BackgroundScheduler()
        self.callback = callback
        self.monitored_domains: Dict[str, Dict] = {}
        self.scan_history: Dict[str, List[Dict]] = {}
        self.logger = logging.getLogger('LongitudinalMonitor')
    
    def add_domain(self, domain: str, schedule: str = 'weekly') -> None:
        """
        Add domain to monitoring schedule
        
        Args:
            domain: Domain to monitor
            schedule: 'daily', 'weekly', 'monthly'
        """
        self.monitored_domains[domain] = {
            'schedule': schedule,
            'added_date': datetime.now(),
            'last_scan': None,
            'next_scan': self._calculate_next_scan(schedule),
            'enabled': True
        }
        
        self.scan_history[domain] = []
        
        self._schedule_scan(domain, schedule)
    
    def remove_domain(self, domain: str) -> None:
        """Remove domain from monitoring"""
        if domain in self.monitored_domains:
            del self.monitored_domains[domain]
            self.logger.info(f"Domain {domain} removed from monitoring")
    
    def start(self) -> None:
        """Start the scheduler"""
        if not self.scheduler.running:
            self.scheduler.start()
            self.logger.info("Longitudinal monitor started")
    
    def stop(self) -> None:
        """Stop the scheduler"""
        if self.scheduler.running:
            self.scheduler.shutdown()
            self.logger.info("Longitudinal monitor stopped")
    
    def record_scan_result(self, domain: str, scan_result: Dict) -> None:
        """
        Record scan result for longitudinal analysis
        
        Args:
            domain: Domain scanned
            scan_result: Complete scan result dictionary
        """
        if domain not in self.scan_history:
            self.scan_history[domain] = []
        
        self.scan_history[domain].append({
            'timestamp': datetime.now(),
            'subdomain_count': len(scan_result.get('enumeration', {}).get('subdomains', [])),
            'vulnerability_count': scan_result.get('vulnerabilities', {}).get('total', 0),
            'critical_count': scan_result.get('vulnerabilities', {}).get('critical', 0),
            'full_result': scan_result
        })
        
        # Update last scan time
        if domain in self.monitored_domains:
            self.monitored_domains[domain]['last_scan'] = datetime.now()
    
    def get_trend(self, domain: str, days: int = 30) -> Dict:
        """
        Get security trend for domain
        
        Returns:
            {
                'domain': str,
                'period_days': int,
                'scan_count': int,
                'subdomain_trend': 'increasing' | 'decreasing' | 'stable',
                'vulnerability_trend': 'improving' | 'degrading' | 'stable',
                'critical_incidents': int,
                'first_scan_date': datetime,
                'latest_scan_date': datetime,
                'average_vulnerabilities': float
            }
        """
        if domain not in self.scan_history or not self.scan_history[domain]:
            return {'error': 'No scan data'}
        
        # Filter scans within time period
        cutoff_date = datetime.now() - timedelta(days=days)
        recent_scans = [
            s for s in self.scan_history[domain]
            if s['timestamp'] >= cutoff_date
        ]
        
        if not recent_scans:
            return {'error': f'No scans in last {days} days'}
        
        # Calculate trends
        first_scan = recent_scans[0]
        latest_scan = recent_scans[-1]
        
        subdomain_change = latest_scan['subdomain_count'] - first_scan['subdomain_count']
        subdomain_trend = 'stable'
        if subdomain_change > 0:
            subdomain_trend = 'increasing'
        elif subdomain_change < 0:
            subdomain_trend = 'decreasing'
        
        vuln_change = latest_scan['vulnerability_count'] - first_scan['vulnerability_count']
        vuln_trend = 'stable'
        if vuln_change < 0:
            vuln_trend = 'improving'
        elif vuln_change > 0:
            vuln_trend = 'degrading'
        
        avg_vulns = sum(s['vulnerability_count'] for s in recent_scans) / len(recent_scans)
        critical_incidents = sum(1 for s in recent_scans if s['critical_count'] > 0)
        
        return {
            'domain': domain,
            'period_days': days,
            'scan_count': len(recent_scans),
            'subdomain_trend': subdomain_trend,
            'subdomain_change': subdomain_change,
            'vulnerability_trend': vuln_trend,
            'vulnerability_change': vuln_change,
            'critical_incidents': critical_incidents,
            'average_vulnerabilities': round(avg_vulns, 2),
            'first_scan_date': first_scan['timestamp'],
            'latest_scan_date': latest_scan['timestamp'],
            'initial_vulnerabilities': first_scan['vulnerability_count'],
            'latest_vulnerabilities': latest_scan['vulnerability_count']
        }
    
    def get_monitoring_status(self) -> Dict:
        """Get current monitoring status"""
        return {
            'total_domains': len(self.monitored_domains),
            'enabled_domains': sum(
                1 for d in self.monitored_domains.values() if d['enabled']
            ),
            'scheduler_running': self.scheduler.running,
            'domains': {
                domain: {
                    'schedule': info['schedule'],
                    'enabled': info['enabled'],
                    'last_scan': info['last_scan'].isoformat() if info['last_scan'] else None,
                    'next_scan': info['next_scan'].isoformat() if info['next_scan'] else None,
                    'scan_count': len(self.scan_history.get(domain, []))
                }
                for domain, info in self.monitored_domains.items()
            }
        }
    
    def enable_domain(self, domain: str) -> None:
        """Enable monitoring for domain"""
        if domain in self.monitored_domains:
            self.monitored_domains[domain]['enabled'] = True
    
    def disable_domain(self, domain: str) -> None:
        """Disable monitoring for domain"""
        if domain in self.monitored_domains:
            self.monitored_domains[domain]['enabled'] = False
    
    def _schedule_scan(self, domain: str, schedule: str) -> None:
        """Schedule periodic scan for domain"""
        if schedule == 'daily':
            trigger = CronTrigger(hour=2, minute=0)  # 2 AM daily
        elif schedule == 'weekly':
            trigger = CronTrigger(day_of_week=0, hour=3, minute=0)  # Sunday 3 AM
        elif schedule == 'monthly':
            trigger = CronTrigger(day=1, hour=4, minute=0)  # 1st of month, 4 AM
        else:
            return
        
        job_id = f"scan_{domain}"
        
        try:
            self.scheduler.add_job(
                self._execute_scan,
                trigger,
                args=[domain],
                id=job_id,
                replace_existing=True
            )
            self.logger.info(f"Scheduled {schedule} scan for {domain}")
        except Exception as e:
            self.logger.error(f"Failed to schedule scan for {domain}: {e}")
    
    async def _execute_scan(self, domain: str) -> None:
        """Execute scan for domain"""
        if not self.monitored_domains[domain]['enabled']:
            return
        
        self.logger.info(f"Starting scheduled scan for {domain}")
        
        try:
            if self.callback:
                await self.callback(domain)
            self.logger.info(f"Completed scan for {domain}")
        except Exception as e:
            self.logger.error(f"Scan failed for {domain}: {e}")
    
    def _calculate_next_scan(self, schedule: str) -> datetime:
        """Calculate next scan time"""
        now = datetime.now()
        
        if schedule == 'daily':
            return now + timedelta(days=1)
        elif schedule == 'weekly':
            return now + timedelta(days=7)
        elif schedule == 'monthly':
            return now + timedelta(days=30)
        
        return now
    
    def get_compliance_status(self, domain: str) -> Dict:
        """
        Get compliance posture over monitoring period
        
        Returns:
            {
                'domain': str,
                'last_30_days': {
                    'critical_found': int,
                    'critical_resolved': int,
                    'critical_outstanding': int,
                    'security_score_trend': str
                },
                'audit_trail': [
                    {
                        'date': datetime,
                        'vulnerability': str,
                        'status': 'discovered' | 'resolved'
                    },
                    ...
                ]
            }
        """
        if domain not in self.scan_history:
            return {'error': 'No data'}
        
        cutoff_date = datetime.now() - timedelta(days=30)
        recent_scans = [
            s for s in self.scan_history[domain]
            if s['timestamp'] >= cutoff_date
        ]
        
        critical_found = sum(s['critical_count'] for s in recent_scans)
        
        return {
            'domain': domain,
            'monitoring_period': '30 days',
            'total_scans': len(recent_scans),
            'critical_found': critical_found,
            'latest_critical': max(
                (s['critical_count'] for s in recent_scans), default=0
            ),
            'average_critical': round(
                critical_found / max(1, len(recent_scans)), 2
            )
        }
