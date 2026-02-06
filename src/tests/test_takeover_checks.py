"""
Unit Tests for Subdomain Takeover Detection Module
"""

import pytest
import dns.resolver
import dns.exception
from unittest.mock import Mock, patch
from src.scanner.checks.takeover_checks import SubdomainTakeoverChecker, TakeoverProvider


class TestSubdomainTakeoverChecker:
    """Test suite for SubdomainTakeoverChecker class"""
    
    @pytest.fixture
    def checker(self):
        """Fixture for takeover checker instance"""
        return SubdomainTakeoverChecker()
    
    def test_vulnerable_cname_detection(self, checker):
        """Test detection of vulnerable CNAME targets"""
        is_vulnerable = checker._is_vulnerable_cname('app.herokuapp.com')
        assert is_vulnerable is True
    
    def test_safe_cname_detection(self, checker):
        """Test detection of safe CNAME targets"""
        is_vulnerable = checker._is_vulnerable_cname('app.example.com')
        assert is_vulnerable is False
    
    def test_service_provider_identification(self, checker):
        """Test service provider identification from CNAME"""
        provider = checker._get_service_provider('myblog.github.io')
        assert provider == TakeoverProvider.GITHUB
    
    def test_heroku_provider_identification(self, checker):
        """Test Heroku service identification"""
        provider = checker._get_service_provider('app.herokuapp.com')
        assert provider == TakeoverProvider.HEROKU
    
    @patch('dns.resolver.Resolver.resolve')
    def test_dangling_cname_detection(self, mock_resolve, checker):
        """Test dangling CNAME detection"""
        # First call returns CNAME, second call (for A record) fails
        cname_rdata = Mock()
        cname_rdata.target = Mock()
        cname_rdata.target.__str__ = Mock(return_value='app.herokuapp.com.')
        
        mock_resolve.side_effect = [
            [cname_rdata],  # CNAME query succeeds
            dns.exception.DNSException()  # A record query fails
        ]
        
        is_dangling, cname, is_vulnerable = checker.check_dangling_cname('app.example.com')
        
        assert is_dangling is True
    
    @patch('dns.resolver.Resolver.resolve')
    def test_active_cname_detection(self, mock_resolve, checker):
        """Test active (non-dangling) CNAME detection"""
        cname_rdata = Mock()
        cname_rdata.target = Mock()
        cname_rdata.target.__str__ = Mock(return_value='app.herokuapp.com.')
        
        a_rdata = Mock()
        a_rdata.address = '1.2.3.4'
        
        mock_resolve.side_effect = [
            [cname_rdata],  # CNAME query succeeds
            [a_rdata]       # A record query succeeds
        ]
        
        is_dangling, cname, is_vulnerable = checker.check_dangling_cname('app.example.com')
        
        assert is_dangling is False
    
    def test_takeover_vulnerability_check(self, checker):
        """Test comprehensive takeover vulnerability check"""
        result = checker.check_takeover_vulnerability('test.example.com')
        
        assert 'subdomain' in result
        assert 'vulnerable' in result
        assert 'cname' in result
        assert 'is_dangling' in result
        assert 'risk_level' in result
        assert result['risk_level'] in ['critical', 'high', 'medium', 'low', 'none']
    
    def test_subdomain_batch_check(self, checker):
        """Test batch subdomain checking"""
        subdomains = ['test1.example.com', 'test2.example.com', 'test3.example.com']
        results = checker.check_subdomain_batch(subdomains)
        
        assert len(results) == 3
        for subdomain in subdomains:
            assert subdomain in results
            assert 'vulnerable' in results[subdomain]
    
    def test_takeover_pattern_detection(self, checker):
        """Test pattern detection across multiple subdomains"""
        subdomains = ['blog.example.com', 'api.example.com', 'cdn.example.com']
        result = checker.detect_takeover_patterns(subdomains)
        
        assert 'total_subdomains' in result
        assert result['total_subdomains'] == 3
        assert 'vulnerable_count' in result
        assert 'dangling_count' in result
        assert 'by_provider' in result
        assert isinstance(result['recommendations'], list)
