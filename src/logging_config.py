"""
ETNA Logging Configuration
Structured logging with security considerations.
"""

import logging
import logging.handlers
import os
import json
from datetime import datetime
from typing import Dict, Any

class SecureFormatter(logging.Formatter):
    """Custom formatter that sanitizes log messages."""
    
    def format(self, record):
        # Sanitize the message
        if hasattr(record, 'getMessage'):
            msg = record.getMessage()
            # Remove potential sensitive data patterns
            import re
            
            # Remove potential passwords, keys, tokens
            msg = re.sub(r'(password|key|token|secret|auth)[=:]\s*\S+', r'\1=***REDACTED***', msg, flags=re.IGNORECASE)
            
            # Remove potential IP addresses in some contexts
            msg = re.sub(r'api[_-]?key[=:]\s*\S+', 'api_key=***REDACTED***', msg, flags=re.IGNORECASE)
            
            record.msg = msg
        
        return super().format(record)

class StructuredFormatter(SecureFormatter):
    """JSON structured logging formatter."""
    
    def format(self, record):
        log_data = {
            'timestamp': datetime.utcnow().isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno
        }
        
        # Add extra fields if present
        if hasattr(record, 'user_id'):
            log_data['user_id'] = record.user_id
        if hasattr(record, 'request_id'):
            log_data['request_id'] = record.request_id
        if hasattr(record, 'security_event'):
            log_data['security_event'] = record.security_event
        
        return json.dumps(log_data)

def setup_logging(log_level: str = "INFO", log_dir: str = "logs/") -> None:
    """
    Setup secure logging configuration.
    
    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_dir: Directory for log files
    """
    # Create logs directory
    os.makedirs(log_dir, exist_ok=True)
    
    # Set log level
    numeric_level = getattr(logging, log_level.upper(), logging.INFO)
    
    # Root logger configuration
    root_logger = logging.getLogger()
    root_logger.setLevel(numeric_level)
    
    # Clear any existing handlers
    root_logger.handlers.clear()
    
    # Console handler with structured format
    console_handler = logging.StreamHandler()
    console_handler.setLevel(numeric_level)
    console_formatter = SecureFormatter(
        fmt='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    console_handler.setFormatter(console_formatter)
    root_logger.addHandler(console_handler)
    
    # File handler with rotation
    file_handler = logging.handlers.RotatingFileHandler(
        filename=os.path.join(log_dir, 'etna.log'),
        maxBytes=10 * 1024 * 1024,  # 10MB
        backupCount=5,
        encoding='utf-8'
    )
    file_handler.setLevel(numeric_level)
    file_formatter = StructuredFormatter()
    file_handler.setFormatter(file_formatter)
    root_logger.addHandler(file_handler)
    
    # Security events log (separate file)
    security_handler = logging.handlers.RotatingFileHandler(
        filename=os.path.join(log_dir, 'security.log'),
        maxBytes=10 * 1024 * 1024,  # 10MB
        backupCount=10,
        encoding='utf-8'
    )
    security_handler.setLevel(logging.WARNING)
    security_handler.setFormatter(StructuredFormatter())
    
    # Create security logger
    security_logger = logging.getLogger('etna.security')
    security_logger.addHandler(security_handler)
    security_logger.setLevel(logging.WARNING)
    
    # Set third-party loggers to WARNING to reduce noise
    logging.getLogger('requests').setLevel(logging.WARNING)
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    logging.getLogger('matplotlib').setLevel(logging.WARNING)
    
    logging.info("Logging configuration initialized")

def get_security_logger():
    """Get the security events logger."""
    return logging.getLogger('etna.security')

# Security event logging helpers
def log_security_event(event_type: str, details: Dict[str, Any], level: str = "WARNING"):
    """Log a security event with structured data."""
    security_logger = get_security_logger()
    
    log_data = {
        'security_event': True,
        'event_type': event_type,
        'details': details,
        'timestamp': datetime.utcnow().isoformat()
    }
    
    level_method = getattr(security_logger, level.lower(), security_logger.warning)
    level_method(f"Security Event: {event_type}", extra=log_data)