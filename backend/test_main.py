#!/usr/bin/env python3
"""
Test version of main.py with mocked OpenAI for integration testing
"""

from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from typing import Optional, List, Dict, Any
import os
import logging
import re
import requests
import json
import time
from dotenv import load_dotenv
from logging_config import setup_logging, structured_logger
from error_handling import (
    setup_error_handlers, ValidationException, SecurityException,
    SplunkAPIException, OpenAIException, handle_openai_error, handle_splunk_error
)

# Import local modules
from models import NLQuery, SPLResponse, SplunkRunRequest, SchemaContext, ErrorResponse, ASTNode, ASTCommand
from validation import validator
from compiler import compiler, generate_explanation

# Load environment variables
load_dotenv()

app = FastAPI(title="splunkLens API (Test Mode)", version="1.0.0")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure enhanced logging
logger = setup_logging()

# Mock OpenAI configuration
logger.info("Running in TEST MODE with mocked OpenAI")

# Schema context (would normally come from Splunk KV Store)
DEFAULT_SCHEMA_CONTEXT = SchemaContext(
    indexes=["main", "web", "security", "audit"],
    sourcetypes=["access_combined", "cisco_asa", "windows_security"],
    common_fields=["src_ip", "dest_ip", "user", "status", "bytes"],
    macros=["search_web_traffic", "search_security_events"],
    datamodels=["web", "internal_audit", "performance"]
)

# Setup enhanced error handling
setup_error_handlers(app)

@app.get("/")
async def root():
    return {"message": "splunkLens API is running (Test Mode)"}

@app.post("/generate-spl", response_model=SPLResponse, responses={400: {"model": ErrorResponse}, 500: {"model": ErrorResponse}})
async def generate_spl(query: NLQuery):
    """Convert natural language to SPL via AST (Test Mode)"""
    import time
    start_time = time.time()
    
    try:
        logger.info(f"Generating SPL for query: {query.query}")
        
        # Generate AST from NL using MOCK OpenAI
        ast = generate_ast_from_nl_mock(query)
        
        # Compile AST to SPL with context
        query_context = {
            "index": query.index,
            "sourcetype": query.sourcetype,
            "lookback_days": query.lookback_days
        }
        spl = compiler.compile(ast, query_context)
        
        # Generate explanation
        explanation = generate_explanation(ast, query.query)
        
        # Estimate cost and results
        estimated_cost = estimate_query_cost(spl)
        estimated_results = estimate_result_size(spl)
        
        duration_ms = (time.time() - start_time) * 1000
        
        # Log successful SPL generation
        structured_logger.log_spl_generation(
            query=query.query,
            spl=spl,
            success=True,
            duration_ms=duration_ms
        )
        
        logger.info(f"Generated SPL: {spl}")
        
        return SPLResponse(
            spl=spl,
            explanation=explanation,
            estimated_cost=estimated_cost,
            estimated_results=estimated_results
        )
        
    except ValueError as e:
        duration_ms = (time.time() - start_time) * 1000
        structured_logger.log_spl_generation(
            query=query.query,
            spl=None,
            success=False,
            duration_ms=duration_ms,
            error=str(e)
        )
        raise ValidationException(str(e), error_code="SPL_VALIDATION_ERROR")
    except Exception as e:
        duration_ms = (time.time() - start_time) * 1000
        structured_logger.log_spl_generation(
            query=query.query,
            spl=None,
            success=False,
            duration_ms=duration_ms,
            error=str(e)
        )
        raise HTTPException(status_code=500, detail=str(e))

def generate_ast_from_nl_mock(query: NLQuery) -> ASTNode:
    """Mock OpenAI to convert natural language to AST"""
    
    # Simple rule-based mock for testing
    query_lower = query.query.lower()
    
    if "count" in query_lower and "by" in query_lower:
        # Count by field query
        if "user" in query_lower:
            return ASTNode(
                command=ASTCommand.STATS,
                args={"aggregation": "count", "by_fields": ["user"]}
            )
        elif "ip" in query_lower:
            return ASTNode(
                command=ASTCommand.STATS,
                args={"aggregation": "count", "by_fields": ["src_ip"]}
            )
        else:
            return ASTNode(
                command=ASTCommand.STATS,
                args={"aggregation": "count", "by_fields": ["host"]}
            )
    
    elif "top" in query_lower:
        # Top N query
        if "ip" in query_lower:
            return ASTNode(
                command=ASTCommand.STATS,
                args={"aggregation": "sum(bytes)", "by_fields": ["src_ip"]}
            )
        else:
            return ASTNode(
                command=ASTCommand.STATS,
                args={"aggregation": "count", "by_fields": ["host"]}
            )
    
    elif "time" in query_lower and ("over" in query_lower or "chart" in query_lower):
        # Time chart query
        if "response" in query_lower:
            return ASTNode(
                command=ASTCommand.TIMECHART,
                args={"span": "1h", "aggregation": "avg(response_time)"}
            )
        else:
            return ASTNode(
                command=ASTCommand.TIMECHART,
                args={"span": "1h", "aggregation": "count"}
            )
    
    elif "table" in query_lower or "show" in query_lower:
        # Table query
        return ASTNode(
            command=ASTCommand.TABLE,
            args={"fields": ["_time", "host", "message"]}
        )
    
    else:
        # Default search query
        search_terms = []
        if "error" in query_lower:
            search_terms.append("error")
        if "fail" in query_lower:
            search_terms.append("failed")
        if "auth" in query_lower:
            search_terms.append("authentication")
        
        search_query = " OR ".join(search_terms) if search_terms else "*"
        
        return ASTNode(
            command=ASTCommand.SEARCH,
            args={"query": search_query}
        )

def estimate_query_cost(spl: str) -> float:
    """Estimate query cost based on complexity"""
    # Simple heuristic based on command count and complexity
    command_count = spl.count('|') + 1
    complexity_score = 0
    
    if 'stats' in spl:
        complexity_score += 2
    if 'timechart' in spl:
        complexity_score += 3
    if 'eval' in spl:
        complexity_score += 1
    if 'where' in spl:
        complexity_score += 1
    if 'lookup' in spl:
        complexity_score += 2
    
    return round(0.1 * command_count + 0.05 * complexity_score, 2)

def estimate_result_size(spl: str) -> int:
    """Estimate result size based on query patterns"""
    # Simple heuristic - in production this would use Splunk's estimate
    base_estimate = 1000
    
    if 'count' in spl and 'by' in spl:
        # Grouping queries typically return fewer results
        return 100
    elif 'head' in spl or 'limit' in spl:
        # Explicit limits
        match = re.search(r'head\s+(\d+)', spl) or re.search(r'limit\s+(\d+)', spl)
        if match:
            return int(match.group(1))
    elif 'table' in spl:
        # Table commands often return more structured data
        return 500
    
    return base_estimate

@app.post("/run-splunk")
async def run_splunk_query(request: SplunkRunRequest):
    """Run SPL query in Splunk using provided token (Test Mode)"""
    import time
    start_time = time.time()
    job_id = None
    
    try:
        # Validate SPL before sending to Splunk
        validation_result = validator.validate_spl(request.spl)
        
        # Log validation result
        structured_logger.log_validation(
            content=request.spl,
            content_type="SPL",
            is_valid=validation_result.is_valid,
            errors=validation_result.errors,
            warnings=validation_result.warnings
        )
        
        if not validation_result.is_valid:
            # Log security event for dangerous SPL
            structured_logger.log_security_event(
                event_type="dangerous_spl_blocked",
                details={
                    "spl": request.spl[:200],
                    "errors": validation_result.errors
                },
                severity="high"
            )
            raise ValidationException(
                f"SPL validation failed: {', '.join(validation_result.errors)}",
                error_code="SPL_VALIDATION_FAILED",
                details={"errors": validation_result.errors, "warnings": validation_result.warnings}
            )
        
        # Check authentication
        if not request.splunk_token:
            raise ValidationException(
                "No authentication provided. Please provide splunk_token or configure SPLUNK_USERNAME/SPLUNK_PASSWORD",
                error_code="SPLUNK_AUTH_MISSING"
            )
        
        # Mock successful Splunk execution
        job_id = "mock_job_12345"
        duration_ms = (time.time() - start_time) * 1000
        
        # Mock results
        mock_results = [
            {"_time": "2024-01-01T00:00:00", "count": "100", "host": "server1"},
            {"_time": "2024-01-01T01:00:00", "count": "150", "host": "server2"},
            {"_time": "2024-01-01T02:00:00", "count": "75", "host": "server3"}
        ]
        
        # Log successful Splunk query
        structured_logger.log_splunk_query(
            spl=request.spl,
            job_id=job_id,
            success=True,
            duration_ms=duration_ms,
            result_count=len(mock_results)
        )
        
        logger.info(f"Mock Splunk search completed successfully. Job ID: {job_id}, Results: {len(mock_results)} rows")
        
        return {
            "job_id": job_id,
            "results_link": f"https://localhost:8000/mock/search?q={request.spl[:50]}",
            "preview_rows": mock_results,
            "total_results": len(mock_results),
            "status": "completed"
        }
        
    except (ValidationException, SplunkAPIException) as e:
        # Re-raise our custom exceptions
        duration_ms = (time.time() - start_time) * 1000
        structured_logger.log_splunk_query(
            spl=request.spl,
            job_id=job_id,
            success=False,
            duration_ms=duration_ms,
            error=str(e)
        )
        raise
    except Exception as e:
        duration_ms = (time.time() - start_time) * 1000
        structured_logger.log_splunk_query(
            spl=request.spl,
            job_id=job_id,
            success=False,
            duration_ms=duration_ms,
            error=str(e)
        )
        logger.error(f"Unexpected error running Splunk query: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to run Splunk query: {e}"
        )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)  # Different port for testing