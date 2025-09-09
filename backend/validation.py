import re
from typing import List, Set
from models import ValidationResult, ASTNode, ASTCommand

class SPLValidator:
    """Validator for SPL queries with comprehensive guardrails"""
    
    # Blocked commands that are never allowed
    BLOCKED_COMMANDS: Set[str] = {
        'rest', 'script', 'outputcsv', 'sendemail', 'run', 'exec',
        'inputcsv', 'inputlookup', 'dbinspect', 'dbtable', 'dbquery'
    }
    
    # Commands that require special validation
    RESTRICTED_COMMANDS: Set[str] = {
        'search', 'eval', 'rex', 'where', 'lookup'
    }
    
    # Dangerous patterns to block
    DANGEROUS_PATTERNS: List[re.Pattern] = [
        re.compile(r'(?i)(?:https?|ftp)://'),  # External URLs
        re.compile(r'(?i)(?:exec|system|subprocess)'),  # System commands
        re.compile(r'(?i)(?:curl|wget|ping|nslookup)'),  # Network tools
        re.compile(r'(?i)(?:drop|delete|update|insert)'),  # Database operations
        re.compile(r'(?i)(?:file://|/etc/|/tmp/)'),  # File system access
        re.compile(r'(?i)(?:\$\{.*?\})'),  # Variable expansion
    ]
    
    @classmethod
    def validate_ast(cls, ast: ASTNode) -> ValidationResult:
        """Validate AST for safety and compliance"""
        result = ValidationResult(is_valid=True)
        
        # Check blocked commands
        if ast.command.value in cls.BLOCKED_COMMANDS:
            result.is_valid = False
            result.errors.append(f"Blocked command: {ast.command.value}")
        
        # Validate children recursively
        if ast.children:
            for child in ast.children:
                child_result = cls.validate_ast(child)
                if not child_result.is_valid:
                    result.is_valid = False
                    result.errors.extend(child_result.errors)
                result.warnings.extend(child_result.warnings)
        
        # Validate command-specific rules
        cls._validate_command_specific(ast, result)
        
        return result
    
    @classmethod
    def validate_spl(cls, spl: str) -> ValidationResult:
        """Validate raw SPL for safety"""
        result = ValidationResult(is_valid=True)
        
        # Check for blocked commands (both with and without pipe)
        for blocked_cmd in cls.BLOCKED_COMMANDS:
            if re.search(rf'\b{blocked_cmd}\b', spl, re.IGNORECASE):
                result.is_valid = False
                result.errors.append(f"Blocked command detected: {blocked_cmd}")
        
        # Check for dangerous patterns
        for pattern in cls.DANGEROUS_PATTERNS:
            if pattern.search(spl):
                result.is_valid = False
                result.errors.append(f"Dangerous pattern detected: {pattern.pattern}")
        
        # Validate time bounds
        cls._validate_time_bounds(spl, result)
        
        # Validate command-specific SPL rules
        cls._validate_spl_commands(spl, result)
        
        # Validate time bounds (ensure earliest is present and reasonable)
        if not cls._has_time_filter(spl):
            result.warnings.append("No explicit time filter found - consider adding one")
        
        return result
    
    @classmethod
    def _validate_command_specific(cls, ast: ASTNode, result: ValidationResult):
        """Validate command-specific rules"""
        if ast.command == ASTCommand.EVAL:
            cls._validate_eval(ast, result)
        elif ast.command == ASTCommand.SEARCH:
            cls._validate_search(ast, result)
        elif ast.command == ASTCommand.LOOKUP:
            cls._validate_lookup(ast, result)
    
    @classmethod
    def _validate_eval(cls, ast: ASTNode, result: ValidationResult):
        """Validate eval command for safety"""
        if 'expression' in ast.args:
            expr = ast.args['expression']
            for pattern in cls.DANGEROUS_PATTERNS:
                if pattern.search(expr):
                    result.is_valid = False
                    result.errors.append(f"Dangerous expression in eval: {expr}")
    
    @classmethod
    def _validate_search(cls, ast: ASTNode, result: ValidationResult):
        """Validate search command"""
        if 'query' in ast.args:
            query = ast.args['query']
            
            # Check for blocked commands
            for blocked_cmd in cls.BLOCKED_COMMANDS:
                if re.search(rf'\b{blocked_cmd}\b', query, re.IGNORECASE):
                    result.is_valid = False
                    result.errors.append(f"Dangerous command detected: {blocked_cmd}")
            
            # Check for dangerous patterns
            for pattern in cls.DANGEROUS_PATTERNS:
                if pattern.search(query):
                    result.is_valid = False
                    result.errors.append(f"Dangerous pattern in search: {query}")
    
    @classmethod
    def _validate_lookup(cls, ast: ASTNode, result: ValidationResult):
        """Validate lookup command"""
        if 'lookup_table' in ast.args:
            table = ast.args['lookup_table']
            # Prevent lookup to potentially sensitive tables
            sensitive_tables = {'passwords', 'secrets', 'credentials', 'tokens'}
            if any(sensitive in table.lower() for sensitive in sensitive_tables):
                result.warnings.append(f"Lookup to potentially sensitive table: {table}")
    
    @classmethod
    def _has_time_filter(cls, spl: str) -> bool:
        """Check if SPL has a time filter"""
        time_patterns = [
            r'earliest=',
            r'latest=',
            r'timeformat=',
            r'date_',
            r'relative_time',
        ]
        
        for pattern in time_patterns:
            if re.search(pattern, spl, re.IGNORECASE):
                return True
        return False
    
    @classmethod
    def _validate_time_bounds(cls, spl: str, result: ValidationResult):
        """Validate time bounds in SPL"""
        earliest_match = re.search(r'earliest=-?(\d+)([dhms])', spl)
        if earliest_match:
            value, unit = earliest_match.groups()
            value = int(value)
            
            # Convert to days for comparison
            if unit == 'h':
                days = value / 24
            elif unit == 'm':
                days = value / (24 * 60)
            elif unit == 's':
                days = value / (24 * 60 * 60)
            else:  # days
                days = value
            
            # Check if time range is too large
            if days > 365:  # More than 1 year
                result.is_valid = False
                result.errors.append(f"Time range too large: {value}{unit} (max 365 days)")
    
    @classmethod
    def _validate_spl_commands(cls, spl: str, result: ValidationResult):
        """Validate SPL command-specific rules"""
        # Check stats command has aggregation
        if re.search(r'\|\s*stats\s+(?!count|sum|avg|max|min|dc|values|list)', spl, re.IGNORECASE):
            # Stats without proper aggregation function
            if not re.search(r'\|\s*stats\s+\w+\s*\(', spl, re.IGNORECASE) and not re.search(r'\|\s*stats\s+(?:count|sum|avg|max|min|dc|values|list)\b', spl, re.IGNORECASE):
                result.is_valid = False
                result.errors.append("Stats command requires aggregation function (count, sum, avg, etc.)")
    
    @classmethod
    def enforce_time_bounds(cls, spl: str, max_lookback_days: int = 30) -> str:
        """Enforce time bounds on SPL query"""
        # Add earliest time if not present
        if 'earliest=' not in spl:
            # Remove 'search ' prefix if present, then add it back with time bounds
            if spl.startswith('search '):
                spl_without_search = spl[7:]  # Remove 'search ' (7 characters)
            else:
                spl_without_search = spl
            spl = f"search earliest=-{max_lookback_days}d {spl_without_search}"
        
        # Validate existing time bounds
        earliest_match = re.search(r'earliest=-?(\d+)([dhms])', spl)
        if earliest_match:
            value, unit = earliest_match.groups()
            value = int(value)
            
            # Convert to days for comparison
            if unit == 'h':
                days = value / 24
            elif unit == 'm':
                days = value / (24 * 60)
            elif unit == 's':
                days = value / (24 * 60 * 60)
            else:  # days
                days = value
            
            if days > max_lookback_days:
                spl = re.sub(r'earliest=-?\d+[dhms]', f'earliest=-{max_lookback_days}d', spl)
        
        return spl

# Global validator instance
validator = SPLValidator()