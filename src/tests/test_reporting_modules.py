"""
Unit Tests for Reporting Modules (PDF and Chart Generators)
"""

import pytest
import tempfile
import os
from io import BytesIO
from src.scanner.reporting.pdf_generator import PDFReportGenerator
from src.scanner.reporting.chart_generator import ChartGenerator


class TestPDFReportGenerator:
    """Test suite for PDFReportGenerator class"""
    
    @pytest.fixture
    def generator(self):
        """Fixture for PDF generator"""
        return PDFReportGenerator()
    
    @pytest.fixture
    def sample_scan_results(self):
        """Fixture for sample scan results"""
        return {
            'domain': 'example.com',
            'scan_date': '2024-02-04 10:00:00',
            'scan_id': 'scan_001',
            'enumeration': {
                'subdomains': ['www.example.com', 'mail.example.com'],
                'methods_used': ['DNS', 'HTTP']
            },
            'security_checks': {
                'passed': 20,
                'failed': 9,
                'tls_passed': 4,
                'tls_failed': 0,
                'headers_passed': 6,
                'headers_failed': 0,
                'cookies_passed': 3,
                'cookies_failed': 0,
                'email_passed': 5,
                'email_failed': 5,
                'takeover_passed': 2,
                'takeover_failed': 4
            },
            'email_security': {
                'spf': {'has_spf': True},
                'dmarc': {'has_dmarc': False, 'policy': None},
                'dkim': {}
            },
            'takeover': {
                'critical': 0,
                'high': 2
            },
            'recommendations': [
                'Deploy DMARC policy',
                'Enable HSTS header'
            ]
        }
    
    def test_generator_initialization(self, generator):
        """Test PDF generator initialization"""
        assert generator.filename is not None
        assert generator.styles is not None
    
    def test_pdf_report_generation(self, generator, sample_scan_results):
        """Test PDF report generation"""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_file = os.path.join(tmpdir, 'test_report.pdf')
            result = generator.generate_report(sample_scan_results, output_file)
            
            assert os.path.exists(result)
            assert result.endswith('.pdf')
    
    def test_enumeration_section_building(self, generator, sample_scan_results):
        """Test enumeration section building"""
        elements = generator._build_enumeration_section(sample_scan_results['enumeration'])
        
        assert len(elements) > 0
    
    def test_security_section_building(self, generator, sample_scan_results):
        """Test security section building"""
        elements = generator._build_security_section(sample_scan_results['security_checks'])
        
        assert len(elements) > 0
    
    def test_email_section_building(self, generator, sample_scan_results):
        """Test email security section building"""
        elements = generator._build_email_section(sample_scan_results['email_security'])
        
        assert len(elements) > 0
    
    def test_takeover_section_building(self, generator, sample_scan_results):
        """Test takeover vulnerabilities section"""
        elements = generator._build_takeover_section(sample_scan_results['takeover'])
        
        assert len(elements) > 0


class TestChartGenerator:
    """Test suite for ChartGenerator class"""
    
    @pytest.fixture
    def generator(self):
        """Fixture for chart generator"""
        return ChartGenerator()
    
    @pytest.fixture
    def sample_scan_data(self):
        """Fixture for sample scan data"""
        return {
            'security_checks': {
                'tls_passed': 4,
                'tls_failed': 0,
                'headers_passed': 6,
                'headers_failed': 0,
                'cookies_passed': 3,
                'cookies_failed': 0,
                'email_passed': 5,
                'email_failed': 5,
                'takeover_passed': 2,
                'takeover_failed': 4
            },
            'vulnerabilities': {
                'critical': 2,
                'high': 5,
                'medium': 10,
                'low': 15
            },
            'email_security': {
                'spf': {'has_spf': True, 'passes': 3, 'total_checks': 5},
                'dmarc': {'has_dmarc': False, 'passes': 0, 'total_checks': 5},
                'dkim': {'default': True, 'selector1': False}
            },
            'enumeration': {
                'methods': {
                    'CT Logs': 45,
                    'HackerTarget': 32,
                    'ThreatCrowd': 28,
                    'DNS Brute': 12
                }
            }
        }
    
    def test_chart_generator_initialization(self, generator):
        """Test chart generator initialization"""
        assert generator.dpi > 0
        assert generator.figsize is not None
    
    def test_security_score_chart_generation(self, generator, sample_scan_data):
        """Test security score chart generation"""
        filename, data = generator.generate_security_score_chart(sample_scan_data)
        
        assert filename == 'security_score.png'
        assert isinstance(data, bytes)
        assert len(data) > 0
    
    def test_vulnerability_pie_chart_generation(self, generator, sample_scan_data):
        """Test vulnerability pie chart generation"""
        filename, data = generator.generate_vulnerability_pie_chart(sample_scan_data)
        
        assert filename == 'vulnerabilities_pie.png'
        assert isinstance(data, bytes)
        assert len(data) > 0
    
    def test_email_security_chart_generation(self, generator, sample_scan_data):
        """Test email security chart generation"""
        filename, data = generator.generate_email_security_chart(sample_scan_data['email_security'])
        
        assert filename == 'email_security.png'
        assert isinstance(data, bytes)
        assert len(data) > 0
    
    def test_enumeration_sources_chart_generation(self, generator, sample_scan_data):
        """Test enumeration sources chart generation"""
        filename, data = generator.generate_enumeration_sources_chart(sample_scan_data['enumeration'])
        
        assert filename == 'enumeration_sources.png'
        assert isinstance(data, bytes)
        assert len(data) > 0
    
    def test_all_charts_generation(self, generator, sample_scan_data):
        """Test generation of all charts at once"""
        charts = generator.generate_all_charts(sample_scan_data)
        
        assert isinstance(charts, dict)
        assert len(charts) > 0
        
        for filename, data in charts.items():
            assert isinstance(filename, str)
            assert isinstance(data, bytes)
            assert len(data) > 0
