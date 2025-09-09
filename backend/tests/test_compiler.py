import pytest
from models import ASTNode, ASTCommand
from compiler import SPLCompiler, generate_explanation

class TestSPLCompiler:
    def setup_method(self):
        self.compiler = SPLCompiler()
    
    def test_compile_search_command(self):
        """Test compilation of basic search command"""
        ast = ASTNode(
            command=ASTCommand.SEARCH,
            args={"query": "error"}
        )
        context = {"index": "main", "lookback_days": 7}
        
        spl = self.compiler.compile(ast, context)
        
        assert "search" in spl
        assert "index=main" in spl
        assert "error" in spl
        assert "earliest=-7d" in spl
    
    def test_compile_stats_command(self):
        """Test compilation of stats command"""
        ast = ASTNode(
            command=ASTCommand.STATS,
            args={
                "aggregation": "count",
                "by_fields": ["host"]
            }
        )
        context = {}
        
        spl = self.compiler.compile(ast, context)
        
        assert "stats count by host" in spl
    
    def test_compile_timechart_command(self):
        """Test compilation of timechart command"""
        ast = ASTNode(
            command=ASTCommand.TIMECHART,
            args={
                "span": "1h",
                "aggregation": "count"
            }
        )
        context = {}
        
        spl = self.compiler.compile(ast, context)
        
        assert "timechart span=1h count" in spl
    
    def test_compile_table_command(self):
        """Test compilation of table command"""
        ast = ASTNode(
            command=ASTCommand.TABLE,
            args={
                "fields": ["_time", "host", "message"]
            }
        )
        context = {}
        
        spl = self.compiler.compile(ast, context)
        
        assert "table _time, host, message" in spl
    
    def test_compile_eval_command(self):
        """Test compilation of eval command"""
        ast = ASTNode(
            command=ASTCommand.EVAL,
            args={
                "field": "severity",
                "expression": "if(status>500, 'high', 'low')"
            }
        )
        context = {}
        
        spl = self.compiler.compile(ast, context)
        
        assert "eval severity=if(status>500, 'high', 'low')" in spl
    
    def test_compile_where_command(self):
        """Test compilation of where command"""
        ast = ASTNode(
            command=ASTCommand.WHERE,
            args={
                "condition": "status>400"
            }
        )
        context = {}
        
        spl = self.compiler.compile(ast, context)
        
        assert "where status>400" in spl
    
    def test_compile_with_context(self):
        """Test compilation with various context parameters"""
        ast = ASTNode(
            command=ASTCommand.SEARCH,
            args={"query": "error"}
        )
        
        # Test with index context
        context = {"index": "security", "lookback_days": 1}
        spl = self.compiler.compile(ast, context)
        assert "index=security" in spl
        assert "earliest=-1d" in spl
        
        # Test with sourcetype context
        context = {"sourcetype": "access_combined", "lookback_days": 30}
        spl = self.compiler.compile(ast, context)
        assert "sourcetype=access_combined" in spl
        assert "earliest=-30d" in spl
    
    def test_compile_optimization(self):
        """Test SPL optimization features"""
        ast = ASTNode(
            command=ASTCommand.SEARCH,
            args={"query": "*"}
        )
        context = {"index": "main"}
        
        spl = self.compiler.compile(ast, context)
        
        # Should add time bounds for optimization
        assert "earliest=" in spl
        # Should specify index for optimization
        assert "index=main" in spl
    
    def test_compile_safety_features(self):
        """Test safety features in compilation"""
        # Test that dangerous patterns are not compiled
        ast = ASTNode(
            command=ASTCommand.SEARCH,
            args={"query": "| rest /services"}
        )
        context = {}
        
        with pytest.raises(ValueError, match="Dangerous command"):
            self.compiler.compile(ast, context)
    
    def test_generate_explanation(self):
        """Test explanation generation"""
        ast = ASTNode(
            command=ASTCommand.SEARCH,
            args={"query": "error"}
        )
        query = "Show me all errors from the last week"
        
        explanation = generate_explanation(ast, query)
        
        assert isinstance(explanation, str)
        assert len(explanation) > 0
        assert "search" in explanation.lower()
        assert "error" in explanation.lower()
    
    def test_golden_compilation_cases(self):
        """Golden test cases for SPL compilation"""
        golden_cases = [
            # Basic search
            {
                "ast": ASTNode(command=ASTCommand.SEARCH, args={"query": "error"}),
                "context": {"index": "main", "lookback_days": 7},
                "expected_parts": ["search", "index=main", "error", "earliest=-7d"]
            },
            
            # Stats aggregation
            {
                "ast": ASTNode(command=ASTCommand.STATS, args={
                    "aggregation": "count",
                    "by_fields": ["host", "status"]
                }),
                "context": {},
                "expected_parts": ["stats", "count", "by", "host", "status"]
            },
            
            # Timechart with span
            {
                "ast": ASTNode(command=ASTCommand.TIMECHART, args={
                    "span": "5m",
                    "aggregation": "avg(response_time)"
                }),
                "context": {},
                "expected_parts": ["timechart", "span=5m", "avg(response_time)"]
            },
            
            # Table with multiple fields
            {
                "ast": ASTNode(command=ASTCommand.TABLE, args={
                    "fields": ["_time", "src_ip", "dest_ip", "bytes"]
                }),
                "context": {},
                "expected_parts": ["table", "_time", "src_ip", "dest_ip", "bytes"]
            },
            
            # Complex eval expression
            {
                "ast": ASTNode(command=ASTCommand.EVAL, args={
                    "field": "risk_score",
                    "expression": "case(bytes>1000000, 'high', bytes>100000, 'medium', 1=1, 'low')"
                }),
                "context": {},
                "expected_parts": ["eval", "risk_score=", "case", "bytes>1000000"]
            }
        ]
        
        for case in golden_cases:
            spl = self.compiler.compile(case["ast"], case["context"])
            for expected_part in case["expected_parts"]:
                assert expected_part in spl, f"Expected '{expected_part}' in SPL: {spl}"
    
    def test_compiler_error_handling(self):
        """Test compiler error handling"""
        # Test with invalid AST command (Pydantic will raise ValidationError)
        from pydantic_core import ValidationError
        with pytest.raises(ValidationError):
            invalid_ast = ASTNode(command="INVALID", args={})
        
        # Test with missing required args - stats without aggregation should still work
        # but may produce a default 'count' aggregation
        incomplete_ast = ASTNode(command=ASTCommand.STATS, args={})
        result = self.compiler.compile(incomplete_ast, {})
        assert "stats count" in result  # Should default to count aggregation
    
    def test_context_aware_compilation(self):
        """Test context-aware compilation features"""
        ast = ASTNode(
            command=ASTCommand.SEARCH,
            args={"query": "authentication failure"}
        )
        
        # Security context should add security-specific optimizations
        security_context = {
            "index": "security",
            "sourcetype": "windows_security",
            "lookback_days": 1
        }
        
        spl = self.compiler.compile(ast, security_context)
        
        assert "index=security" in spl
        assert "sourcetype=windows_security" in spl
        assert "earliest=-1d" in spl
        assert "authentication failure" in spl
    
    def test_performance_optimizations(self):
        """Test performance optimization features"""
        ast = ASTNode(
            command=ASTCommand.SEARCH,
            args={"query": "*"}
        )
        context = {"index": "main", "lookback_days": 7}
        
        spl = self.compiler.compile(ast, context)
        
        # Should add time bounds for performance
        assert "earliest=-7d" in spl
        # Should specify index to avoid searching all indexes
        assert "index=main" in spl
        # Should add latest time bound
        assert "latest=now" in spl