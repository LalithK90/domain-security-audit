"""
Chart Generator
===============
Generates visualization charts from scan results using matplotlib
"""

import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import seaborn as sns
from typing import Dict, List, Optional, Tuple
from datetime import datetime
import io


class ChartGenerator:
    """Generate charts for scan results visualization"""
    
    def __init__(self, style: str = 'seaborn-v0_8-darkgrid'):
        """Initialize chart generator with specific style"""
        try:
            plt.style.use(style)
        except:
            plt.style.use('default')
        
        sns.set_palette("husl")
        self.dpi = 150
        self.figsize = (10, 6)
    
    def generate_security_score_chart(self, scan_results: Dict) -> Tuple[str, bytes]:
        """
        Generate security score breakdown chart
        
        Returns:
            (chart_filename, chart_bytes)
        """
        fig, ax = plt.subplots(figsize=self.figsize, dpi=self.dpi)
        
        security_data = scan_results.get('security_checks', {})
        categories = ['TLS/SSL', 'HTTP Headers', 'Cookies', 'Email', 'Takeover']
        
        passed = [
            security_data.get('tls_passed', 0),
            security_data.get('headers_passed', 0),
            security_data.get('cookies_passed', 0),
            security_data.get('email_passed', 0),
            security_data.get('takeover_passed', 0),
        ]
        
        failed = [
            security_data.get('tls_failed', 0),
            security_data.get('headers_failed', 0),
            security_data.get('cookies_failed', 0),
            security_data.get('email_failed', 0),
            security_data.get('takeover_failed', 0),
        ]
        
        x = range(len(categories))
        width = 0.35
        
        ax.bar([i - width/2 for i in x], passed, width, label='Passed', color='#27ae60')
        ax.bar([i + width/2 for i in x], failed, width, label='Failed', color='#e74c3c')
        
        ax.set_xlabel('Security Category', fontsize=12, fontweight='bold')
        ax.set_ylabel('Number of Checks', fontsize=12, fontweight='bold')
        ax.set_title('Security Assessment Results', fontsize=14, fontweight='bold')
        ax.set_xticks(x)
        ax.set_xticklabels(categories, rotation=45, ha='right')
        ax.legend()
        ax.grid(True, alpha=0.3)
        
        plt.tight_layout()
        
        # Save to bytes
        buffer = io.BytesIO()
        plt.savefig(buffer, format='png', dpi=self.dpi)
        buffer.seek(0)
        chart_bytes = buffer.getvalue()
        plt.close()
        
        return 'security_score.png', chart_bytes
    
    def generate_subdomain_growth_chart(self, historical_data: List[Dict]) -> Tuple[str, bytes]:
        """
        Generate subdomain count growth chart over time
        
        Args:
            historical_data: List of scan results with timestamps
        
        Returns:
            (chart_filename, chart_bytes)
        """
        fig, ax = plt.subplots(figsize=self.figsize, dpi=self.dpi)
        
        dates = [d.get('date', '') for d in historical_data]
        subdomain_counts = [len(d.get('subdomains', [])) for d in historical_data]
        
        ax.plot(dates, subdomain_counts, marker='o', linewidth=2, markersize=8, color='#3498db')
        ax.fill_between(range(len(dates)), subdomain_counts, alpha=0.3, color='#3498db')
        
        ax.set_xlabel('Date', fontsize=12, fontweight='bold')
        ax.set_ylabel('Number of Subdomains', fontsize=12, fontweight='bold')
        ax.set_title('Subdomain Growth Over Time', fontsize=14, fontweight='bold')
        ax.grid(True, alpha=0.3)
        plt.xticks(rotation=45, ha='right')
        
        plt.tight_layout()
        
        buffer = io.BytesIO()
        plt.savefig(buffer, format='png', dpi=self.dpi)
        buffer.seek(0)
        chart_bytes = buffer.getvalue()
        plt.close()
        
        return 'subdomain_growth.png', chart_bytes
    
    def generate_vulnerability_pie_chart(self, scan_results: Dict) -> Tuple[str, bytes]:
        """
        Generate vulnerability distribution pie chart
        
        Returns:
            (chart_filename, chart_bytes)
        """
        fig, ax = plt.subplots(figsize=(8, 8), dpi=self.dpi)
        
        vulnerabilities = scan_results.get('vulnerabilities', {})
        critical = vulnerabilities.get('critical', 0)
        high = vulnerabilities.get('high', 0)
        medium = vulnerabilities.get('medium', 0)
        low = vulnerabilities.get('low', 0)
        
        sizes = [critical, high, medium, low]
        labels = [
            f'Critical ({critical})',
            f'High ({high})',
            f'Medium ({medium})',
            f'Low ({low})'
        ]
        colors = ['#e74c3c', '#f39c12', '#f1c40f', '#3498db']
        explode = (0.1, 0.05, 0, 0) if critical > 0 else (0, 0.05, 0, 0)
        
        ax.pie(sizes, explode=explode, labels=labels, colors=colors, autopct='%1.1f%%',
               shadow=True, startangle=90)
        ax.set_title('Vulnerability Distribution', fontsize=14, fontweight='bold')
        
        plt.tight_layout()
        
        buffer = io.BytesIO()
        plt.savefig(buffer, format='png', dpi=self.dpi)
        buffer.seek(0)
        chart_bytes = buffer.getvalue()
        plt.close()
        
        return 'vulnerabilities_pie.png', chart_bytes
    
    def generate_email_security_chart(self, email_data: Dict) -> Tuple[str, bytes]:
        """
        Generate email security configuration chart
        
        Returns:
            (chart_filename, chart_bytes)
        """
        fig, ax = plt.subplots(figsize=(10, 6), dpi=self.dpi)
        
        technologies = ['SPF', 'DMARC', 'DKIM']
        
        spf_score = 0
        if email_data.get('spf', {}).get('has_spf'):
            spf_score = 50 + (email_data.get('spf', {}).get('passes', 0) / max(1, email_data.get('spf', {}).get('total_checks', 1))) * 50
        
        dmarc_score = 0
        if email_data.get('dmarc', {}).get('has_dmarc'):
            dmarc_score = 50 + (email_data.get('dmarc', {}).get('passes', 0) / max(1, email_data.get('dmarc', {}).get('total_checks', 1))) * 50
        
        dkim_count = sum(1 for v in email_data.get('dkim', {}).values() if v)
        dkim_score = min(100, dkim_count * 25)
        
        scores = [spf_score, dmarc_score, dkim_score]
        
        # Color coding based on score
        colors_list = []
        for score in scores:
            if score >= 80:
                colors_list.append('#27ae60')  # Green
            elif score >= 50:
                colors_list.append('#f39c12')  # Orange
            else:
                colors_list.append('#e74c3c')  # Red
        
        bars = ax.bar(technologies, scores, color=colors_list, alpha=0.7, edgecolor='black', linewidth=1.5)
        
        # Add value labels on bars
        for bar, score in zip(bars, scores):
            height = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2., height,
                   f'{score:.0f}%',
                   ha='center', va='bottom', fontweight='bold')
        
        ax.set_ylabel('Security Score', fontsize=12, fontweight='bold')
        ax.set_title('Email Security Configuration Score', fontsize=14, fontweight='bold')
        ax.set_ylim(0, 120)
        ax.axhline(y=80, color='green', linestyle='--', alpha=0.5, label='Good (80%)')
        ax.axhline(y=50, color='orange', linestyle='--', alpha=0.5, label='Fair (50%)')
        ax.legend()
        ax.grid(True, alpha=0.3, axis='y')
        
        plt.tight_layout()
        
        buffer = io.BytesIO()
        plt.savefig(buffer, format='png', dpi=self.dpi)
        buffer.seek(0)
        chart_bytes = buffer.getvalue()
        plt.close()
        
        return 'email_security.png', chart_bytes
    
    def generate_enumeration_sources_chart(self, enum_data: Dict) -> Tuple[str, bytes]:
        """
        Generate enumeration method contribution chart
        
        Returns:
            (chart_filename, chart_bytes)
        """
        fig, ax = plt.subplots(figsize=self.figsize, dpi=self.dpi)
        
        methods = enum_data.get('methods', {})
        method_names = list(methods.keys())
        method_counts = list(methods.values())
        
        if not method_names:
            ax.text(0.5, 0.5, 'No enumeration data', ha='center', va='center')
            plt.close()
            return 'enumeration_sources.png', b''
        
        # Sort by count descending
        sorted_data = sorted(zip(method_names, method_counts), key=lambda x: x[1], reverse=True)
        method_names, method_counts = zip(*sorted_data)
        
        bars = ax.barh(method_names, method_counts, color=sns.color_palette("husl", len(method_names)))
        
        # Add value labels
        for i, (bar, count) in enumerate(zip(bars, method_counts)):
            ax.text(count, i, f' {int(count)}', va='center', fontweight='bold')
        
        ax.set_xlabel('Subdomains Found', fontsize=12, fontweight='bold')
        ax.set_title('Enumeration Method Contribution', fontsize=14, fontweight='bold')
        ax.grid(True, alpha=0.3, axis='x')
        
        plt.tight_layout()
        
        buffer = io.BytesIO()
        plt.savefig(buffer, format='png', dpi=self.dpi)
        buffer.seek(0)
        chart_bytes = buffer.getvalue()
        plt.close()
        
        return 'enumeration_sources.png', chart_bytes
    
    def generate_all_charts(self, scan_results: Dict) -> Dict[str, bytes]:
        """
        Generate all charts in one call
        
        Returns:
            {
                'filename': bytes_data,
                ...
            }
        """
        charts = {}
        
        try:
            filename, data = self.generate_security_score_chart(scan_results)
            charts[filename] = data
        except Exception:
            pass
        
        try:
            filename, data = self.generate_vulnerability_pie_chart(scan_results)
            charts[filename] = data
        except Exception:
            pass
        
        try:
            filename, data = self.generate_email_security_chart(scan_results.get('email_security', {}))
            charts[filename] = data
        except Exception:
            pass
        
        try:
            filename, data = self.generate_enumeration_sources_chart(scan_results.get('enumeration', {}))
            charts[filename] = data
        except Exception:
            pass
        
        return charts
