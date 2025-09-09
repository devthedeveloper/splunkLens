from typing import Optional, Dict, Any
from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse
import traceback
import uuid
from datetime import datetime
from logging_config import get_logger

logger = get_logger('splunklens.errors')

class SplunkLensException(Exception):
    """Base exception for SplunkLens application"""
    
    def __init__(self, message: str, error_code: str = None, details: Dict[str, Any] = None):
        self.message = message
        self.error_code = error_code or self.__class__.__name__
        self.details = details or {}
        self.error_id = str(uuid.uuid4())
        self.timestamp = datetime.utcnow().isoformat()
        super().__init__(self.message)

class ValidationException(SplunkLensException):
    """Exception for validation errors"""
    pass

class CompilationException(SplunkLensException):
    """Exception for SPL compilation errors"""
    pass

class SplunkAPIException(SplunkLensException):
    """Exception for Splunk API errors"""
    pass

class OpenAIException(SplunkLensException):
    """Exception for OpenAI API errors"""
    pass

class SecurityException(SplunkLensException):
    """Exception for security-related errors"""
    pass

class RateLimitException(SplunkLensException):
    """Exception for rate limiting errors"""
    pass

class ErrorTracker:
    """Track and analyze application errors"""
    
    def __init__(self):
        self.error_counts = {}
        self.recent_errors = []
        self.max_recent_errors = 100
    
    def track_error(self, error: Exception, context: Dict[str, Any] = None):
        """Track an error occurrence"""
        error_type = type(error).__name__
        
        # Count error types
        self.error_counts[error_type] = self.error_counts.get(error_type, 0) + 1
        
        # Store recent error details
        error_details = {
            'error_type': error_type,
            'message': str(error),
            'timestamp': datetime.utcnow().isoformat(),
            'context': context or {},
            'traceback': traceback.format_exc() if hasattr(error, '__traceback__') else None
        }
        
        if isinstance(error, SplunkLensException):
            error_details.update({
                'error_id': error.error_id,
                'error_code': error.error_code,
                'details': error.details
            })
        
        self.recent_errors.append(error_details)
        
        # Keep only recent errors
        if len(self.recent_errors) > self.max_recent_errors:
            self.recent_errors = self.recent_errors[-self.max_recent_errors:]
        
        # Log the error
        logger.error(
            f"Error tracked: {error_type} - {str(error)}",
            extra={
                'error_details': error_details,
                'error_counts': self.error_counts
            }
        )
    
    def get_error_stats(self) -> Dict[str, Any]:
        """Get error statistics"""
        return {
            'error_counts': self.error_counts,
            'total_errors': sum(self.error_counts.values()),
            'recent_error_count': len(self.recent_errors),
            'most_common_errors': sorted(
                self.error_counts.items(),
                key=lambda x: x[1],
                reverse=True
            )[:5]
        }
    
    def get_recent_errors(self, limit: int = 10) -> list:
        """Get recent errors"""
        return self.recent_errors[-limit:]

# Global error tracker
error_tracker = ErrorTracker()

def create_error_response(
    error: Exception,
    status_code: int = 500,
    include_details: bool = False
) -> JSONResponse:
    """Create standardized error response"""
    
    # Track the error
    error_tracker.track_error(error)
    
    # Base response
    response_data = {
        'error': True,
        'message': str(error),
        'timestamp': datetime.utcnow().isoformat()
    }
    
    # Add SplunkLens exception details
    if isinstance(error, SplunkLensException):
        response_data.update({
            'error_code': error.error_code,
            'error_id': error.error_id
        })
        
        if include_details:
            response_data['details'] = error.details
    
    # Add traceback in development mode
    if include_details and hasattr(error, '__traceback__'):
        response_data['traceback'] = traceback.format_exc()
    
    return JSONResponse(
        status_code=status_code,
        content=response_data
    )

async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Global exception handler for unhandled exceptions"""
    
    # Log the unhandled exception
    logger.error(
        f"Unhandled exception: {type(exc).__name__} - {str(exc)}",
        extra={
            'request_url': str(request.url),
            'request_method': request.method,
            'traceback': traceback.format_exc()
        }
    )
    
    # Create error response
    return create_error_response(
        exc,
        status_code=500,
        include_details=False  # Don't expose internal details in production
    )

async def validation_exception_handler(request: Request, exc: ValidationException) -> JSONResponse:
    """Handler for validation exceptions"""
    return create_error_response(exc, status_code=400)

async def security_exception_handler(request: Request, exc: SecurityException) -> JSONResponse:
    """Handler for security exceptions"""
    # Log security events with high priority
    logger.warning(
        f"Security exception: {str(exc)}",
        extra={
            'request_url': str(request.url),
            'request_method': request.method,
            'client_ip': request.client.host if request.client else 'unknown',
            'security_event': True
        }
    )
    
    return create_error_response(exc, status_code=403)

async def rate_limit_exception_handler(request: Request, exc: RateLimitException) -> JSONResponse:
    """Handler for rate limit exceptions"""
    return create_error_response(exc, status_code=429)

async def splunk_api_exception_handler(request: Request, exc: SplunkAPIException) -> JSONResponse:
    """Handler for Splunk API exceptions"""
    return create_error_response(exc, status_code=503)

async def openai_exception_handler(request: Request, exc: OpenAIException) -> JSONResponse:
    """Handler for OpenAI API exceptions"""
    return create_error_response(exc, status_code=502)

def setup_error_handlers(app):
    """Setup error handlers for FastAPI app"""
    
    # Add exception handlers
    app.add_exception_handler(ValidationException, validation_exception_handler)
    app.add_exception_handler(SecurityException, security_exception_handler)
    app.add_exception_handler(RateLimitException, rate_limit_exception_handler)
    app.add_exception_handler(SplunkAPIException, splunk_api_exception_handler)
    app.add_exception_handler(OpenAIException, openai_exception_handler)
    app.add_exception_handler(Exception, global_exception_handler)
    
    logger.info("Error handlers configured")

def handle_openai_error(error: Exception) -> OpenAIException:
    """Convert OpenAI errors to application exceptions"""
    error_message = str(error)
    
    if "rate limit" in error_message.lower():
        return RateLimitException(
            "OpenAI API rate limit exceeded",
            error_code="OPENAI_RATE_LIMIT",
            details={"original_error": error_message}
        )
    elif "authentication" in error_message.lower():
        return OpenAIException(
            "OpenAI API authentication failed",
            error_code="OPENAI_AUTH_ERROR",
            details={"original_error": error_message}
        )
    else:
        return OpenAIException(
            f"OpenAI API error: {error_message}",
            error_code="OPENAI_API_ERROR",
            details={"original_error": error_message}
        )

def handle_splunk_error(error: Exception, status_code: int = None) -> SplunkAPIException:
    """Convert Splunk errors to application exceptions"""
    error_message = str(error)
    
    if status_code == 401:
        return SplunkAPIException(
            "Splunk authentication failed",
            error_code="SPLUNK_AUTH_ERROR",
            details={"status_code": status_code, "original_error": error_message}
        )
    elif status_code == 403:
        return SplunkAPIException(
            "Splunk access denied",
            error_code="SPLUNK_ACCESS_DENIED",
            details={"status_code": status_code, "original_error": error_message}
        )
    elif status_code and status_code >= 500:
        return SplunkAPIException(
            "Splunk server error",
            error_code="SPLUNK_SERVER_ERROR",
            details={"status_code": status_code, "original_error": error_message}
        )
    else:
        return SplunkAPIException(
            f"Splunk API error: {error_message}",
            error_code="SPLUNK_API_ERROR",
            details={"status_code": status_code, "original_error": error_message}
        )