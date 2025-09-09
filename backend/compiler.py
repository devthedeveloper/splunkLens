from typing import Dict, Any, List
from models import ASTNode, ASTCommand
from validation import validator

class SPLCompiler:
    """Compiler that converts AST to safe, optimized SPL"""
    
    def __init__(self):
        self.command_handlers = {
            ASTCommand.SEARCH: self._compile_search,
            ASTCommand.STATS: self._compile_stats,
            ASTCommand.TIMECHART: self._compile_timechart,
            ASTCommand.TABLE: self._compile_table,
            ASTCommand.EVAL: self._compile_eval,
            ASTCommand.WHERE: self._compile_where,
            ASTCommand.LOOKUP: self._compile_lookup,
            ASTCommand.TSTATS: self._compile_tstats,
            ASTCommand.DATAMODEL: self._compile_datamodel,
        }
    
    def compile(self, ast: ASTNode, query_context: Dict[str, Any] = None) -> str:
        """Compile AST to SPL with context-aware optimizations"""
        if query_context is None:
            query_context = {}
        
        # Validate AST first
        validation_result = validator.validate_ast(ast)
        if not validation_result.is_valid:
            raise ValueError(f"Invalid AST: {', '.join(validation_result.errors)}")
        
        # Compile the AST
        spl_parts = []
        self._compile_node(ast, spl_parts, query_context)
        
        # Join SPL parts
        spl = " | ".join(spl_parts)
        
        # Enforce time bounds and add latest=now for performance
        max_lookback = query_context.get('lookback_days', 30)
        spl = validator.enforce_time_bounds(spl, max_lookback)
        
        # Add latest=now if not already present
        if 'latest=' not in spl:
            if ' | ' in spl:
                # Insert latest=now before the first pipe
                parts = spl.split(' | ', 1)
                spl = f"{parts[0]} latest=now | {parts[1]}"
            else:
                # No pipes, just append latest=now
                spl = spl + ' latest=now'
        
        # Final validation
        final_validation = validator.validate_spl(spl)
        if not final_validation.is_valid:
            raise ValueError(f"Generated invalid SPL: {', '.join(final_validation.errors)}")
        
        return spl
    
    def _compile_node(self, node: ASTNode, parts: List[str], context: Dict[str, Any]):
        """Compile a single AST node"""
        handler = self.command_handlers.get(node.command)
        if handler:
            part = handler(node.args, context)
            if part:
                parts.append(part)
        
        # Compile children
        if node.children:
            for child in node.children:
                self._compile_node(child, parts, context)
    
    def _compile_search(self, args: Dict[str, Any], context: Dict[str, Any]) -> str:
        """Compile search command"""
        search_parts = []
        
        # Add index/sourcetype from context if available
        if context.get('index'):
            search_parts.append(f"index={context['index']}")
        if context.get('sourcetype'):
            search_parts.append(f"sourcetype={context['sourcetype']}")
        
        # Add search query
        if args.get('query'):
            search_parts.append(args['query'])
        
        return f"search {' '.join(search_parts)}".strip() if search_parts else None
    
    def _compile_stats(self, args: Dict[str, Any], context: Dict[str, Any]) -> str:
        """Compile stats command"""
        stats_parts = []
        
        # Handle aggregation function
        if args.get('aggregation'):
            stats_parts.append(args['aggregation'])
        elif args.get('functions'):
            stats_parts.append(args['functions'])
        else:
            # Default aggregation if none specified
            stats_parts.append('count')
        
        # Handle by fields
        if args.get('by_fields'):
            by_fields = args['by_fields']
            if isinstance(by_fields, list):
                stats_parts.append(f"by {', '.join(by_fields)}")
            else:
                stats_parts.append(f"by {by_fields}")
        
        return f"stats {' '.join(stats_parts)}".strip()
    
    def _compile_timechart(self, args: Dict[str, Any], context: Dict[str, Any]) -> str:
        """Compile timechart command"""
        timechart_parts = []
        
        if args.get('span'):
            timechart_parts.append(f"span={args['span']}")
        
        if args.get('aggregation'):
            timechart_parts.append(args['aggregation'])
        elif args.get('function'):
            timechart_parts.append(args['function'])
        else:
            timechart_parts.append('count')
        
        return f"timechart {' '.join(timechart_parts)}".strip()
    
    def _compile_table(self, args: Dict[str, Any], context: Dict[str, Any]) -> str:
        """Compile table command"""
        if args.get('fields'):
            fields = args['fields']
            if isinstance(fields, list):
                return f"table {', '.join(fields)}"
            else:
                return f"table {fields}"
        return "table _time, host, message"  # Default fields
    
    def _compile_eval(self, args: Dict[str, Any], context: Dict[str, Any]) -> str:
        """Compile eval command"""
        if args.get('field') and args.get('expression'):
            return f"eval {args['field']}={args['expression']}"
        elif args.get('expression'):
            return f"eval {args['expression']}"
        return None
    
    def _compile_where(self, args: Dict[str, Any], context: Dict[str, Any]) -> str:
        """Compile where command"""
        if args.get('condition'):
            return f"where {args['condition']}"
        return None
    
    def _compile_lookup(self, args: Dict[str, Any], context: Dict[str, Any]) -> str:
        """Compile lookup command"""
        lookup_parts = []
        
        if args.get('lookup_table'):
            lookup_parts.append(args['lookup_table'])
        
        if args.get('input_field'):
            lookup_parts.append(f"{args['input_field']} AS {args.get('output_field', 'output')}")
        
        return f"lookup {' '.join(lookup_parts)}".strip()
    
    def _compile_tstats(self, args: Dict[str, Any], context: Dict[str, Any]) -> str:
        """Compile tstats command (optimized statistics)"""
        tstats_parts = []
        
        if args.get('functions'):
            tstats_parts.append(args['functions'])
        
        if args.get('from_datamodel'):
            tstats_parts.append(f"from datamodel={args['from_datamodel']}")
        
        if args.get('where'):
            tstats_parts.append(f"where {args['where']}")
        
        return f"tstats {' '.join(tstats_parts)}".strip()
    
    def _compile_datamodel(self, args: Dict[str, Any], context: Dict[str, Any]) -> str:
        """Compile datamodel command"""
        datamodel_parts = []
        
        if args.get('datamodel'):
            datamodel_parts.append(f"datamodel={args['datamodel']}")
        
        if args.get('action'):
            datamodel_parts.append(args['action'])
        
        return f"datamodel {' '.join(datamodel_parts)}".strip()

# Global compiler instance
compiler = SPLCompiler()

def generate_explanation(ast: ASTNode, query: str) -> str:
    """Generate human-readable explanation of the generated SPL"""
    explanations = []
    
    if ast.command == ASTCommand.SEARCH:
        explanations.append(f"Search for: {query}")
        if ast.args.get('query'):
            explanations.append(f"Filter criteria: {ast.args['query']}")
    
    if ast.children:
        for child in ast.children:
            if child.command == ASTCommand.STATS:
                explanations.append("Generate statistics")
                if child.args.get('functions'):
                    explanations.append(f"Calculate: {child.args['functions']}")
            elif child.command == ASTCommand.TIMECHART:
                explanations.append("Create time-based chart")
            elif child.command == ASTCommand.TABLE:
                explanations.append("Display results in table format")
    
    return ". ".join(explanations) + "." if explanations else "Generated SPL query based on your natural language input."