import re
from pathlib import Path
import logging

logger = logging.getLogger(__name__)

def validate_log_file(file_path: str) -> bool:
    """Validate log file before processing."""
    try:
        path = Path(file_path)
        
        if not path.exists() or not path.is_file():
            return False
        
        # 100MB size limit
        if path.stat().st_size > 100 * 1024 * 1024:
            logger.warning(f"File too large: {path.stat().st_size} bytes")
            return False
        
        allowed_extensions = {'.csv', '.json', '.jsonl', '.log'}
        if path.suffix.lower() not in allowed_extensions:
            return False
        
        return True
        
    except Exception as e:
        logger.error(f"Error validating file {file_path}: {e}")
        return False

def sanitize_log_entry(entry: str) -> str:
    """Sanitize log entries to prevent injection attacks."""
    sanitized = re.sub(r'[<>"\']', '', entry)
    return sanitized[:1000]  # Limit length