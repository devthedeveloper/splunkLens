import logging
import logging.config
import os
from datetime import datetime

# Logging configuration
LOGGING_CONFIG = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'standard': {
            'format': '%(asctime)s [%(levelname)s] %(name)s: %(message)s',
            'datefmt': '%Y-%m-%d %H:%M:%S'
        },
        'detailed': {
            'format': '%(asctime)s [%(levelname)s] %(name)s:%(lineno)d: %(message)s (%(funcName)s)',
            'datefmt': '%Y-%m-%d %H:%M:%S'
        },
        'json': {
            'format': '{"timestamp": "%(asctime)s", "level": "%(levelname)s", "logger": "%(name)s", "message": "%(message)s", "module": "%(module)s", "function": "%(funcName)s", "line": %(lineno)d}',
            'datefmt': '%Y-%m-%dT%H:%M:%S'
        }
    },
    'handlers': {
        'console': {
            'level': 'INFO',
            'class': 'logging.StreamHandler',
            'formatter': 'standard',
            'stream': 'ext://sys.stdout'
        },
        'file': {
            'level': 'DEBUG',
            'class': 'logging.handlers.RotatingFileHandler',
            'formatter': 'detailed',
            'filename': 'logs/splunklens.log',
            'maxBytes': 10485760,  # 10MB
            'backupCount': 5
        },
        'error_file': {
            'level': 'ERROR',
            'class': 'logging.handlers.RotatingFileHandler',
            'formatter': 'json',
            'filename': 'logs/errors.log',
            'maxBytes': 10485760,  # 10MB
            'backupCount': 3
        }
    },
    'loggers': {
        'splunklens': {
            'level': 'DEBUG',
            'handlers': ['console', 'file', 'error_file'],
            'propagate': False
        },
        'uvicorn': {
            'level': 'INFO',
            'handlers': ['console', 'file'],
            'propagate': False
        },
        'fastapi': {
            'level': 'INFO',
            'handlers': ['console', 'file'],
            'propagate': False
        }
    },
    'root': {
        'level': 'INFO',
        'handlers': ['console']
    }
}

def setup_logging():
    """Setup logging configuration"""
    # Create logs directory if it doesn't exist
    os.makedirs('logs', exist_ok=True)
    
    # Configure logging
    logging.config.dictConfig(LOGGING_CONFIG)
    
    # Get logger for the application
    logger = logging.getLogger('splunklens')
    logger.info("Logging configuration initialized")
    
    return logger

def get_logger(name: str = 'splunklens') -> logging.Logger:
    """Get a logger instance"""
    return logging.getLogger(name)

class StructuredLogger:
    """Structured logger for better log analysis"""
    
    def __init__(self, name: str = 'splunklens'):
        self.logger = logging.getLogger(name)
    
    def log_request(self, method: str, path: str, status_code: int, duration_ms: float, user_id: str = None):
        """Log HTTP request"""
        self.logger.info(
            f"HTTP {method} {path} - {status_code} - {duration_ms:.2f}ms",
            extra={
                'event_type': 'http_request',
                'method': method,
                'path': path,
                'status_code': status_code,
                'duration_ms': duration_ms,
                'user_id': user_id
            }
        )
    
    def log_spl_generation(self, query: str, spl: str, success: bool, duration_ms: float, error: str = None):
        """Log SPL generation event"""
        level = logging.INFO if success else logging.ERROR
        message = f"SPL generation {'succeeded' if success else 'failed'} - {duration_ms:.2f}ms"
        
        self.logger.log(
            level,
            message,
            extra={
                'event_type': 'spl_generation',
                'query': query[:100] + '...' if len(query) > 100 else query,
                'spl': spl[:200] + '...' if spl and len(spl) > 200 else spl,
                'success': success,
                'duration_ms': duration_ms,
                'error': error
            }
        )
    
    def log_splunk_query(self, spl: str, job_id: str, success: bool, duration_ms: float, result_count: int = None, error: str = None):
        """Log Splunk query execution"""
        level = logging.INFO if success else logging.ERROR
        message = f"Splunk query {'succeeded' if success else 'failed'} - {duration_ms:.2f}ms"
        
        self.logger.log(
            level,
            message,
            extra={
                'event_type': 'splunk_query',
                'spl': spl[:200] + '...' if len(spl) > 200 else spl,
                'job_id': job_id,
                'success': success,
                'duration_ms': duration_ms,
                'result_count': result_count,
                'error': error
            }
        )
    
    def log_validation(self, content: str, content_type: str, is_valid: bool, errors: list = None, warnings: list = None):
        """Log validation event"""
        level = logging.WARNING if not is_valid else logging.DEBUG
        message = f"{content_type} validation {'passed' if is_valid else 'failed'}"
        
        self.logger.log(
            level,
            message,
            extra={
                'event_type': 'validation',
                'content_type': content_type,
                'content': content[:100] + '...' if len(content) > 100 else content,
                'is_valid': is_valid,
                'errors': errors,
                'warnings': warnings
            }
        )
    
    def log_security_event(self, event_type: str, details: dict, severity: str = 'medium'):
        """Log security-related events"""
        level = logging.WARNING if severity in ['medium', 'high'] else logging.INFO
        message = f"Security event: {event_type}"
        
        self.logger.log(
            level,
            message,
            extra={
                'event_type': 'security',
                'security_event_type': event_type,
                'severity': severity,
                'details': details
            }
        )

# Global structured logger instance
structured_logger = StructuredLogger()