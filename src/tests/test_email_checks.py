"""
Unit Tests for Email Security Checks Module
"""

import pytest
import dns.resolver
import dns.exception
from unittest.mock import Mock, patch, MagicMock
from src.scanner.checks.email_checks import EmailSecurityChecker, SPFRecord, DMARCRecord


class TestEmailSecurityChecker:
    """Test suite for EmailSecurityChecker class"""
    
    @pytest.fixture
    def checker(self):
        """Fixture for email checker instance"""
        return EmailSecurityChecker()
    
    def test_spf_record_parsing(self, checker):
        """Test SPF record parsing"""
        spf = checker._parse_spf('v=spf1 ip4:192.168.1.1 include:sendgrid.net -all')
        
        assert spf.has_all is True
        assert spf.all_mechanism == '-all'
        assert len(spf.mechanisms) > 0
        assert 'include:sendgrid.net' in spf.mechanisms
    
    def test_dmarc_record_parsing(self, checker):
        """Test DMARC record parsing"""
        dmarc = checker._parse_dmarc('v=DMARC1; p=reject; rua=mailto:dmarc@example.com')
        
        assert dmarc.p == 'reject'
        assert dmarc.rua is not None
    
    @patch('dns.resolver.Resolver.resolve')
    def test_spf_exists(self, mock_resolve, checker):
        """Test SPF existence check"""
        mock_rdata = Mock()
        mock_rdata.__str__ = Mock(return_value='"v=spf1 ip4:192.168.1.1 -all"')
        mock_resolve.return_value = [mock_rdata]
        
        exists, record, error = checker.check_spf_exists('example.com')
        
        assert exists is True
        assert record is not None
        assert error == ""
    
    @patch('dns.resolver.Resolver.resolve')
    def test_spf_not_exists(self, mock_resolve, checker):
        """Test SPF non-existence check"""
        mock_resolve.side_effect = dns.exception.DNSException()
        
        exists, record, error = checker.check_spf_exists('example.com')
        
        assert exists is False
        assert record is None
        assert error != ""
    
    def test_spf_quality_assessment(self, checker):
        """Test SPF quality evaluation"""
        result = checker.check_spf_quality('nonexistent-domain-12345.com')
        
        assert result['has_spf'] is False
        assert result['passes'] == 0
    
    @patch('dns.resolver.Resolver.resolve')
    def test_dmarc_exists(self, mock_resolve, checker):
        """Test DMARC existence check"""
        mock_rdata = Mock()
        mock_rdata.__str__ = Mock(return_value='"v=DMARC1; p=reject; rua=mailto:admin@example.com"')
        mock_resolve.return_value = [mock_rdata]
        
        exists, record, error = checker.check_dmarc_exists('example.com')
        
        assert exists is True
        assert record is not None
    
    @patch('dns.resolver.Resolver.resolve')
    def test_dmarc_not_exists(self, mock_resolve, checker):
        """Test DMARC non-existence check"""
        mock_resolve.side_effect = dns.exception.DNSException()
        
        exists, record, error = checker.check_dmarc_exists('example.com')
        
        assert exists is False
        assert error != ""
    
    def test_email_security_overall(self, checker):
        """Test comprehensive email security assessment"""
        result = checker.check_email_security_overall('example.com')
        
        assert 'domain' in result
        assert 'spf' in result
        assert 'dmarc' in result
        assert 'dkim' in result
        assert 'overall_score' in result
        assert 0 <= result['overall_score'] <= 100
        assert isinstance(result['vulnerabilities'], list)
