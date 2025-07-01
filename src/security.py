"""
ETNA Security Module
Input validation, sanitization, and security controls.
"""

import re
import os
import hashlib
import logging
from pathlib import Path
from typing import Optional, Dict, Any
import pandas as pd
from functools import wraps

logger = logging.getLogger(__name__)

class SecurityError(Exception):
    """Custom security exception"""
    pass

class SecurityValidator:
    """Centralized security validation and sanitization"""
    
    # Security limits
    MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB
    MAX_ROWS_PER_FILE = 1_000_000      # 1M rows max
    MAX_STRING_LENGTH = 10_000         # 10K chars max
    ALLOWED_EXTENSIONS = {'.csv', '.json', '.jsonl', '.log', '.txt'}
    
    # Testing mode flag
    TESTING_MODE = False
    
    # Dangerous patterns to block
    DANGEROUS_PATTERNS = [
        r'<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>',  # Script tags
        r'javascript:',                                        # JavaScript URLs
        r'data:(?!image/)',                                   # Data URLs (except images)
        r'vbscript:',                                         # VBScript
        r'on\w+\s*=',                                        # Event handlers
        r'expression\s*\(',                                   # CSS expressions
        r'import\s+os|import\s+subprocess|import\s+sys',     # Python imports
        r'eval\s*\(|exec\s*\(',                             # Python eval/exec
        r'__import__|getattr|setattr|delattr',               # Python introspection
    ]
    
    @classmethod
    def set_testing_mode(cls, enabled: bool = True):
        """Enable/disable testing mode for more flexible validation."""
        cls.TESTING_MODE = enabled
        if enabled:
            logger.info("Security testing mode enabled - some restrictions relaxed")
        else:
            logger.info("Security testing mode disabled - full restrictions active")
    
    @classmethod
    def validate_file_path(cls, file_path: str, base_dir: Optional[str] = None) -> bool:
        """
        Validate file path to prevent directory traversal attacks.
        
        Args:
            file_path: Path to validate
            base_dir: Base directory to restrict to (optional)
            
        Returns:
            bool: True if path is safe
            
        Raises:
            SecurityError: If path is dangerous
        """
        try:
            # Normalize the path
            path = Path(file_path).resolve()
            
            # Check if file exists
            if not path.exists():
                raise SecurityError(f"File does not exist: {file_path}")
            
            # Check if it's actually a file
            if not path.is_file():
                raise SecurityError(f"Path is not a file: {file_path}")
            
            # Check file extension
            if path.suffix.lower() not in cls.ALLOWED_EXTENSIONS:
                raise SecurityError(f"File type not allowed: {path.suffix}")
            
            # Check file size
            file_size = path.stat().st_size
            if file_size > cls.MAX_FILE_SIZE:
                raise SecurityError(f"File too large: {file_size} bytes (max: {cls.MAX_FILE_SIZE})")
            
            # Directory traversal protection
            if base_dir:
                base_path = Path(base_dir).resolve()
                try:
                    path.relative_to(base_path)
                except ValueError:
                    raise SecurityError(f"Path outside allowed directory: {file_path}")
            elif not cls.TESTING_MODE:
                # Only enforce project directory restriction in production mode
                try:
                    path.relative_to(Path.cwd().resolve())
                except ValueError:
                    # In production, files must be within project directory
                    raise SecurityError(f"Path outside project directory: {file_path}")
            
            logger.info(f"File validation passed: {file_path}")
            return True
            
        except Exception as e:
            if isinstance(e, SecurityError):
                raise
            logger.error(f"File validation error: {e}")
            raise SecurityError(f"File validation failed: {str(e)}")
    
    @classmethod
    def sanitize_string(cls, data: str, max_length: Optional[int] = None) -> str:
        """
        Sanitize string input to prevent injection attacks.
        
        Args:
            data: String to sanitize
            max_length: Maximum allowed length
            
        Returns:
            str: Sanitized string
        """
        if not isinstance(data, str):
            data = str(data)
        
        # Apply length limit
        max_len = max_length or cls.MAX_STRING_LENGTH
        if len(data) > max_len:
            logger.warning(f"String truncated from {len(data)} to {max_len} characters")
            data = data[:max_len]
        
        # Check for dangerous patterns
        for pattern in cls.DANGEROUS_PATTERNS:
            if re.search(pattern, data, re.IGNORECASE):
                logger.warning(f"Dangerous pattern detected and removed: {pattern}")
                data = re.sub(pattern, '[REMOVED]', data, flags=re.IGNORECASE)
        
        # Remove control characters but keep newlines and tabs
        data = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', data)
        
        # Escape HTML/XML special characters
        data = data.replace('&', '&amp;')
        data = data.replace('<', '&lt;')
        data = data.replace('>', '&gt;')
        data = data.replace('"', '&quot;')
        data = data.replace("'", '&#x27;')
        
        return data
    
    @classmethod
    def validate_dataframe_size(cls, df: pd.DataFrame) -> bool:
        """
        Validate DataFrame size to prevent memory exhaustion.
        
        Args:
            df: DataFrame to validate
            
        Returns:
            bool: True if size is acceptable
            
        Raises:
            SecurityError: If DataFrame is too large
        """
        if len(df) > cls.MAX_ROWS_PER_FILE:
            raise SecurityError(f"DataFrame too large: {len(df)} rows (max: {cls.MAX_ROWS_PER_FILE})")
        
        # Estimate memory usage (rough calculation)
        memory_usage = df.memory_usage(deep=True).sum()
        max_memory = 500 * 1024 * 1024  # 500MB
        
        if memory_usage > max_memory:
            raise SecurityError(f"DataFrame memory usage too high: {memory_usage} bytes")
        
        return True
    
    @classmethod
    def generate_file_hash(cls, file_path: str) -> str:
        """Generate SHA-256 hash of file for integrity checking."""
        hash_sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()

def require_valid_file(base_dir: Optional[str] = None):
    """Decorator to validate file paths before processing."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Assume first argument or 'log_path'/'file_path' kwarg contains the file path
            file_path = None
            if args:
                file_path = args[0] if isinstance(args[0], str) else getattr(args[0], 'log_path', None)
            if not file_path:
                file_path = kwargs.get('log_path') or kwargs.get('file_path')
            
            if file_path:
                SecurityValidator.validate_file_path(file_path, base_dir)
            
            return func(*args, **kwargs)
        return wrapper
    return decorator

def sanitize_inputs(fields: list):
    """Decorator to sanitize specific DataFrame fields."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            result = func(*args, **kwargs)
            
            if isinstance(result, pd.DataFrame):
                for field in fields:
                    if field in result.columns:
                        result[field] = result[field].apply(
                            lambda x: SecurityValidator.sanitize_string(str(x)) if pd.notna(x) else x
                        )
            
            return result
        return wrapper
    return decorator

# Rate limiting (simple implementation)
class RateLimiter:
    """Simple rate limiter for API endpoints."""
    
    def __init__(self, max_requests: int = 100, time_window: int = 3600):
        self.max_requests = max_requests
        self.time_window = time_window
        self.requests = {}  # {ip: [timestamps]}
    
    def is_allowed(self, identifier: str) -> bool:
        """Check if request is allowed under rate limit."""
        import time
        
        current_time = time.time()
        
        if identifier not in self.requests:
            self.requests[identifier] = []
        
        # Remove old requests outside time window
        self.requests[identifier] = [
            req_time for req_time in self.requests[identifier]
            if current_time - req_time < self.time_window
        ]
        
        # Check if under limit
        if len(self.requests[identifier]) >= self.max_requests:
            return False
        
        # Add current request
        self.requests[identifier].append(current_time)
        return True