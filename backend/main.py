from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from typing import Optional, List, Dict, Any
import openai
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
from models import NLQuery, SPLResponse, SplunkRunRequest, SchemaContext, ErrorResponse
from validation import validator
from compiler import compiler, generate_explanation

# Load environment variables
load_dotenv()

app = FastAPI(title="splunkLens API", version="1.0.0")

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

# OpenAI configuration
openai.api_key = os.getenv("OPENAI_API_KEY")
if not openai.api_key:
    logger.warning("OPENAI_API_KEY not found in environment variables")

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
    return {"message": "splunkLens API is running"}

@app.post("/generate-spl", response_model=SPLResponse, responses={400: {"model": ErrorResponse}, 500: {"model": ErrorResponse}})
async def generate_spl(query: NLQuery):
    """Convert natural language to SPL via AST"""
    import time
    start_time = time.time()
    
    try:
        logger.info(f"Generating SPL for query: {query.query}")
        
        # Generate AST from NL using OpenAI
        ast = generate_ast_from_nl(query)
        
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
        if "openai" in str(type(e)).lower():
            raise handle_openai_error(e)
        raise HTTPException(status_code=500, detail=str(e))

def generate_ast_from_nl(query: NLQuery):
    """Use OpenAI to convert natural language to AST"""
    if not openai.api_key:
        raise HTTPException(status_code=500, detail="OpenAI API key not configured")
    
    prompt = f"""
Convert the following natural language query to a structured SPL AST.
Only use allowed SPL commands: search, stats, timechart, table, eval, where, lookup, tstats, datamodel.
Never use dangerous commands: rest, script, outputcsv, sendemail, or any external network calls.

Schema context:
Indexes: {DEFAULT_SCHEMA_CONTEXT.indexes}
Sourcetypes: {DEFAULT_SCHEMA_CONTEXT.sourcetypes}
Common fields: {DEFAULT_SCHEMA_CONTEXT.common_fields}
Macros: {DEFAULT_SCHEMA_CONTEXT.macros}
Datamodels: {DEFAULT_SCHEMA_CONTEXT.datamodels}

Query: {query.query}
Lookback: {query.lookback_days} days
Index: {query.index or 'default'}
Sourcetype: {query.sourcetype or 'any'}

Return only valid JSON AST structure with command and args.
"""
    
    try:
        from openai import OpenAI
        client = OpenAI(api_key=openai.api_key)
        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "You are a SPL query expert. Convert natural language to structured AST. Return only JSON."},
                {"role": "user", "content": prompt}
            ],
            max_tokens=500,
            temperature=0.1
        )
        
        # Parse and validate AST
        ast_data = response.choices[0].message.content.strip()
        # In production, this would parse the JSON and validate against ASTNode
        # For MVP, return a simple search AST
        from models import ASTNode, ASTCommand
        return ASTNode(command=ASTCommand.SEARCH, args={"query": query.query})
        
    except Exception as e:
        if "openai" in str(type(e)).lower():
            logger.error(f"OpenAI API error: {e}")
            raise HTTPException(status_code=500, detail=f"OpenAI API error: {e}")
        else:
            logger.error(f"Unexpected error in AST generation: {e}")
            raise HTTPException(status_code=500, detail=f"AST generation failed: {e}")

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
    """Run SPL query in Splunk using provided token"""
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
        
        # Get Splunk configuration from environment
        splunk_host = os.getenv("SPLUNK_HOST", "localhost:8089")
        splunk_username = os.getenv("SPLUNK_USERNAME")
        splunk_password = os.getenv("SPLUNK_PASSWORD")
        
        # Use provided token or fall back to username/password auth
        if request.splunk_token:
            headers = {
                "Authorization": f"Bearer {request.splunk_token}",
                "Content-Type": "application/x-www-form-urlencoded"
            }
            auth = None
        elif splunk_username and splunk_password:
            headers = {"Content-Type": "application/x-www-form-urlencoded"}
            auth = (splunk_username, splunk_password)
        else:
            raise ValidationException(
                "No authentication provided. Please provide splunk_token or configure SPLUNK_USERNAME/SPLUNK_PASSWORD",
                error_code="SPLUNK_AUTH_MISSING"
            )
        
        # Submit search job to Splunk
        search_url = f"https://{splunk_host}/services/search/jobs"
        search_data = {
            "search": request.spl,
            "output_mode": "json",
            "earliest_time": request.earliest_time or "-24h",
            "latest_time": request.latest_time or "now",
            "max_count": request.max_results or 1000
        }
        
        logger.info(f"Submitting search to Splunk: {request.spl}")
        
        # Submit the search job
        response = requests.post(
            search_url,
            data=search_data,
            headers=headers,
            auth=auth,
            verify=False,  # In production, use proper SSL verification
            timeout=30
        )
        
        if response.status_code != 201:
            logger.error(f"Splunk search submission failed: {response.status_code} - {response.text}")
            raise handle_splunk_error(
                Exception(f"Search submission failed: {response.text}"),
                status_code=response.status_code
            )
        
        # Parse job ID from response
        job_data = response.json()
        job_id = job_data.get("sid")
        
        if not job_id:
            raise SplunkAPIException(
                "Failed to get job ID from Splunk response",
                error_code="SPLUNK_JOB_ID_MISSING",
                details={"response": job_data}
            )
        
        # Wait for job completion (with timeout)
        job_status_url = f"https://{splunk_host}/services/search/jobs/{job_id}"
        max_wait_time = 60  # seconds
        start_time = time.time()
        
        while time.time() - start_time < max_wait_time:
            status_response = requests.get(
                job_status_url,
                headers=headers,
                auth=auth,
                verify=False,
                timeout=10
            )
            
            if status_response.status_code == 200:
                status_data = status_response.json()
                dispatch_state = status_data.get("entry", [{}])[0].get("content", {}).get("dispatchState")
                
                if dispatch_state == "DONE":
                    break
                elif dispatch_state == "FAILED":
                    raise SplunkAPIException(
                        "Splunk search job failed",
                        error_code="SPLUNK_JOB_FAILED",
                        details={"job_id": job_id}
                    )
            
            time.sleep(2)  # Wait 2 seconds before checking again
        
        # Get search results
        results_url = f"https://{splunk_host}/services/search/jobs/{job_id}/results"
        results_response = requests.get(
            results_url,
            headers=headers,
            auth=auth,
            params={"output_mode": "json", "count": request.max_results or 100},
            verify=False,
            timeout=30
        )
        
        if results_response.status_code != 200:
            logger.error(f"Failed to get search results: {results_response.status_code}")
            raise handle_splunk_error(
                Exception(f"Failed to retrieve results: {results_response.text}"),
                status_code=results_response.status_code
            )
        
        results_data = results_response.json()
        results = results_data.get("results", [])
        
        # Generate results link
        encoded_spl = requests.utils.quote(request.spl)
        results_link = f"https://{splunk_host.replace(':8089', ':8000')}/en-US/app/search/search?q={encoded_spl}"
        
        duration_ms = (time.time() - start_time) * 1000
        
        # Log successful Splunk query
        structured_logger.log_splunk_query(
            spl=request.spl,
            job_id=job_id,
            success=True,
            duration_ms=duration_ms,
            result_count=len(results)
        )
        
        logger.info(f"Splunk search completed successfully. Job ID: {job_id}, Results: {len(results)} rows")
        
        return {
            "job_id": job_id,
            "results_link": results_link,
            "preview_rows": results[:10],  # Return first 10 rows as preview
            "total_results": len(results),
            "status": "completed"
        }
        
    except (ValidationException, SplunkAPIException):
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
    except requests.exceptions.RequestException as e:
        duration_ms = (time.time() - start_time) * 1000
        structured_logger.log_splunk_query(
            spl=request.spl,
            job_id=job_id,
            success=False,
            duration_ms=duration_ms,
            error=str(e)
        )
        raise SplunkAPIException(
            f"Network error connecting to Splunk: {e}",
            error_code="SPLUNK_NETWORK_ERROR",
            details={"original_error": str(e)}
        )
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
    uvicorn.run(app, host="0.0.0.0", port=8000)