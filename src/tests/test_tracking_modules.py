"""
Unit Tests for Tracking Modules (Historical, Longitudinal, Risk, Recommendation)
"""

import pytest
import tempfile
import os
from datetime import datetime, timedelta
from src.scanner.tracking.historical_tracker import HistoricalTracker
from src.scanner.tracking.risk_calculator import RiskCalculator, RiskLevel
from src.scanner.tracking.recommendation_engine import RecommendationEngine, Priority


class TestHistoricalTracker:
    """Test suite for HistoricalTracker class"""
    
    @pytest.fixture
    def tracker(self):
        """Fixture for historical tracker"""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, 'test.db')
            yield HistoricalTracker(db_path=db_path)
    
    @pytest.fixture
    def sample_scan_result(self):
        """Fixture for sample scan result"""
        return {
            'enumeration': {
                'subdomains': ['www.example.com', 'mail.example.com', 'api.example.com']
            },
            'vulnerabilities': {
                'total': 5,
                'critical': 1
            }
        }
    
    def test_tracker_initialization(self, tracker):
        """Test tracker initialization and database setup"""
        assert tracker is not None
        assert os.path.exists(tracker.db_path)
    
    def test_record_scan(self, tracker, sample_scan_result):
        """Test recording a scan result"""
        scan_id = tracker.record_scan('example.com', 'scan_001', sample_scan_result)
        
        assert isinstance(scan_id, int)
        assert scan_id > 0
    
    def test_track_subdomains(self, tracker, sample_scan_result):
        """Test subdomain tracking"""
        scan_id = tracker.record_scan('example.com', 'scan_001', sample_scan_result)
        subdomains = ['www.example.com', 'mail.example.com']
        
        tracker.track_subdomains(scan_id, 'example.com', subdomains)
        # Should not raise exception
        assert True
    
    def test_track_vulnerability(self, tracker):
        """Test vulnerability tracking"""
        vuln_id = tracker.track_vulnerability(1, 'example.com', 'spf_missing', 'medium')
        
        assert isinstance(vuln_id, int)
        assert vuln_id > 0
    
    def test_get_remediation_status(self, tracker):
        """Test remediation status retrieval"""
        status = tracker.get_remediation_status('example.com')
        
        assert 'open' in status
        assert 'resolved' in status
        assert 'acknowledged' in status


class TestRiskCalculator:
    """Test suite for RiskCalculator class"""
    
    @pytest.fixture
    def calculator(self):
        """Fixture for risk calculator"""
        return RiskCalculator()
    
    @pytest.fixture
    def sample_scan(self):
        """Fixture for sample scan results"""
        return {
            'tls_checks': {
                'has_expired_certs': False,
                'weak_ciphers': False,
                'has_hsts': True,
                'tls_version': 'TLS 1.3'
            },
            'email_security': {
                'spf': {'has_spf': True, 'has_hardfail': True},
                'dmarc': {'has_dmarc': True, 'policy_enforced': True},
                'dkim': {'default': True, 'selector1': True}
            },
            'http_headers': {
                'X-Frame-Options': True,
                'X-Content-Type-Options': True,
                'Content-Security-Policy': True
            },
            'enumeration': {
                'subdomains': ['www.example.com', 'api.example.com']
            },
            'takeover': {
                'critical': 0,
                'high': 0
            },
            'vulnerabilities': {
                'critical': 0,
                'high': 0,
                'medium': 2,
                'low': 5
            }
        }
    
    def test_calculator_initialization(self, calculator):
        """Test risk calculator initialization"""
        assert calculator is not None
        assert calculator.total_weight > 0
    
    def test_ssl_score_calculation(self, calculator):
        """Test SSL/TLS score calculation"""
        tls_data = {
            'has_expired_certs': False,
            'weak_ciphers': False,
            'has_hsts': True
        }
        score = calculator._calculate_ssl_score(tls_data)
        
        assert 0 <= score <= 100
    
    def test_email_score_calculation(self, calculator):
        """Test email security score calculation"""
        email_data = {
            'spf': {'has_spf': True},
            'dmarc': {'has_dmarc': True},
            'dkim': {'default': True}
        }
        score = calculator._calculate_email_score(email_data)
        
        assert 0 <= score <= 100
    
    def test_overall_risk_calculation(self, calculator, sample_scan):
        """Test overall domain risk calculation"""
        result = calculator.calculate_domain_risk(sample_scan)
        
        assert 'overall_score' in result
        assert 'risk_level' in result
        assert 'factors' in result
        assert 0 <= result['overall_score'] <= 100
        assert result['risk_level'] in [level.name for level in RiskLevel]
    
    def test_subdomain_risk_calculation(self, calculator):
        """Test individual subdomain risk calculation"""
        subdomain_data = {
            'expired_cert': False,
            'weak_cipher': False,
            'dangling_cname': False,
            'open_redirect': False
        }
        result = calculator.calculate_subdomain_risk('www.example.com', subdomain_data)
        
        assert 'subdomain' in result
        assert 'risk_score' in result
        assert 'risk_level' in result
        assert 0 <= result['risk_score'] <= 100
    
    def test_risk_level_determination(self, calculator):
        """Test risk level determination from score"""
        assert calculator._get_risk_level(90) == RiskLevel.CRITICAL
        assert calculator._get_risk_level(70) == RiskLevel.HIGH
        assert calculator._get_risk_level(50) == RiskLevel.MEDIUM
        assert calculator._get_risk_level(25) == RiskLevel.LOW
        assert calculator._get_risk_level(5) == RiskLevel.INFO


class TestRecommendationEngine:
    """Test suite for RecommendationEngine class"""
    
    @pytest.fixture
    def engine(self):
        """Fixture for recommendation engine"""
        return RecommendationEngine()
    
    @pytest.fixture
    def sample_scan(self):
        """Fixture for sample scan with issues"""
        return {
            'email_security': {
                'spf': {'has_spf': False},
                'dmarc': {'has_dmarc': False},
                'dkim': {}
            },
            'http_headers': {
                'hsts': False,
                'csp': False,
                'x_frame_options': False,
                'x_content_type_options': False
            },
            'tls_checks': {
                'expired_certs': True,
                'weak_ciphers': True
            },
            'takeover': {
                'critical': 1,
                'critical_subdomains': ['api.example.com']
            }
        }
    
    def test_engine_initialization(self, engine):
        """Test recommendation engine initialization"""
        assert engine is not None
        assert len(engine.recommendations) > 0
    
    def test_recommendation_generation(self, engine, sample_scan):
        """Test recommendation generation from scan results"""
        recommendations = engine.generate_recommendations(sample_scan)
        
        assert isinstance(recommendations, list)
        assert len(recommendations) > 0
    
    def test_recommendation_priority_ordering(self, engine, sample_scan):
        """Test recommendations are ordered by priority"""
        recommendations = engine.generate_recommendations(sample_scan)
        
        # Check that each recommendation has lower priority value than next
        for i in range(len(recommendations) - 1):
            assert recommendations[i].priority.value <= recommendations[i + 1].priority.value
    
    def test_priority_matrix_generation(self, engine, sample_scan):
        """Test priority matrix generation"""
        recommendations = engine.generate_recommendations(sample_scan)
        matrix = engine.get_priority_matrix(recommendations)
        
        assert 'quick_wins' in matrix
        assert 'short_term' in matrix
        assert 'long_term' in matrix
        assert 'low_priority' in matrix
    
    def test_recommendation_formatting(self, engine, sample_scan):
        """Test recommendation report formatting"""
        recommendations = engine.generate_recommendations(sample_scan)
        report = engine.format_recommendations_report(recommendations)
        
        assert isinstance(report, str)
        assert len(report) > 0
        assert 'REMEDIATION' in report
