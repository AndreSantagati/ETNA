"""
Security Tests for ETNA Platform - Windows Compatible
"""

import pytest
import tempfile
import os
import shutil
import time
import uuid
from pathlib import Path
from src.security import SecurityValidator, SecurityError
from src.log_parser import LogParserFactory

class TestSecurityValidator:
    
    def test_file_path_validation(self):
        """Test file path validation against directory traversal."""
        # Use a unique directory name to avoid conflicts
        test_dir = f"test_temp_{uuid.uuid4().hex[:8]}"
        os.makedirs(test_dir, exist_ok=True)
        
        # Create a test file within project directory
        test_file = os.path.join(test_dir, "test.csv")
        with open(test_file, 'w') as f:
            f.write("test,data\n1,2\n")
        
        try:
            # Valid path should pass (no base_dir restriction)
            assert SecurityValidator.validate_file_path(test_file, base_dir=test_dir)
            
            # Invalid paths should fail
            with pytest.raises(SecurityError):
                SecurityValidator.validate_file_path("../../../etc/passwd")
            
            with pytest.raises(SecurityError):
                SecurityValidator.validate_file_path("/etc/passwd")
            
            # Test with non-existent file
            with pytest.raises(SecurityError):
                SecurityValidator.validate_file_path("nonexistent.csv")
                
        finally:
            # Windows-safe cleanup
            self._safe_cleanup(test_dir)
    
    def test_string_sanitization(self):
        """Test string sanitization."""
        # Test script tag removal
        malicious = "<script>alert('xss')</script>Hello"
        clean = SecurityValidator.sanitize_string(malicious)
        assert "<script>" not in clean
        assert "Hello" in clean
        
        # Test length limiting
        long_string = "A" * 20000
        clean = SecurityValidator.sanitize_string(long_string, max_length=1000)
        assert len(clean) <= 1000
        
        # Test HTML escaping
        html_input = '<img src="x" onerror="alert(1)">'
        clean = SecurityValidator.sanitize_string(html_input)
        assert "<img" not in clean
        assert "&lt;" in clean  # Should be escaped
    
    def test_large_file_rejection(self):
        """Test large file rejection."""
        # Use a unique directory name
        test_dir = f"test_temp_{uuid.uuid4().hex[:8]}"
        os.makedirs(test_dir, exist_ok=True)
        
        try:
            # Create a file that's too large
            large_file = os.path.join(test_dir, "large.csv")
            
            # Write a file that exceeds our test limit
            with open(large_file, 'w') as f:
                # Write data to make it larger than our limit
                for i in range(1000):
                    f.write("A" * 1000 + "\n")
            
            # Temporarily reduce the max file size for testing
            original_max_size = SecurityValidator.MAX_FILE_SIZE
            SecurityValidator.MAX_FILE_SIZE = 100  # 100 bytes for testing
            
            try:
                with pytest.raises(SecurityError):
                    SecurityValidator.validate_file_path(large_file, base_dir=test_dir)
            finally:
                # Restore original size
                SecurityValidator.MAX_FILE_SIZE = original_max_size
                
        finally:
            # Windows-safe cleanup
            self._safe_cleanup(test_dir)

    def test_dataframe_size_validation(self):
        """Test DataFrame size validation."""
        import pandas as pd
        
        # Test normal sized DataFrame
        small_df = pd.DataFrame({'col1': [1, 2, 3], 'col2': ['a', 'b', 'c']})
        assert SecurityValidator.validate_dataframe_size(small_df)
        
        # Test oversized DataFrame - use a smaller number for testing
        # Create a DataFrame that exceeds row limit
        test_limit = 1000  # Smaller test limit
        original_limit = SecurityValidator.MAX_ROWS_PER_FILE
        SecurityValidator.MAX_ROWS_PER_FILE = test_limit
        
        try:
            large_data = {'col1': list(range(test_limit + 1))}
            large_df = pd.DataFrame(large_data)
            
            with pytest.raises(SecurityError):
                SecurityValidator.validate_dataframe_size(large_df)
        finally:
            SecurityValidator.MAX_ROWS_PER_FILE = original_limit

    def _safe_cleanup(self, directory):
        """Windows-safe directory cleanup."""
        if not os.path.exists(directory):
            return
            
        max_attempts = 5
        for attempt in range(max_attempts):
            try:
                # Close any open file handles
                import gc
                gc.collect()
                
                # Wait a bit for Windows to release file handles
                time.sleep(0.1)
                
                # Try to remove all files first
                for root, dirs, files in os.walk(directory, topdown=False):
                    for file in files:
                        file_path = os.path.join(root, file)
                        try:
                            os.chmod(file_path, 0o777)  # Ensure writable
                            os.unlink(file_path)
                        except (OSError, PermissionError):
                            pass
                    
                    for dir in dirs:
                        dir_path = os.path.join(root, dir)
                        try:
                            os.chmod(dir_path, 0o777)
                            os.rmdir(dir_path)
                        except (OSError, PermissionError):
                            pass
                
                # Remove the main directory
                os.chmod(directory, 0o777)
                os.rmdir(directory)
                break
                
            except (OSError, PermissionError) as e:
                if attempt == max_attempts - 1:
                    # Last attempt failed, log warning but don't fail test
                    import warnings
                    warnings.warn(f"Could not clean up test directory {directory}: {e}")
                else:
                    time.sleep(0.2)  # Wait longer before retry

def test_log_parser_security():
    """Test log parser security features."""
    # Create test directory structure
    test_logs_dir = "data/logs/test"
    os.makedirs(test_logs_dir, exist_ok=True)
    
    # Create malicious CSV in the correct directory
    test_file = os.path.join(test_logs_dir, f"malicious_test_{uuid.uuid4().hex[:8]}.csv")
    with open(test_file, 'w') as f:
        f.write("TimeCreated,ProcessName,EventData\n")
        f.write("2024-01-01,<script>alert('xss')</script>,Normal data\n")
    
    try:
        # This should work since file is in data/logs subdirectory
        parser = LogParserFactory.get_parser(test_file)
        df = parser.parse()
        
        # Check that malicious content was sanitized
        assert "<script>" not in str(df['process_name'].iloc[0])
        assert "alert" not in str(df['process_name'].iloc[0])
        
    finally:
        # Cleanup
        if os.path.exists(test_file):
            try:
                os.unlink(test_file)
            except (OSError, PermissionError):
                pass

def test_security_validator_file_extensions():
    """Test file extension validation."""
    test_dir = f"test_temp_{uuid.uuid4().hex[:8]}"
    os.makedirs(test_dir, exist_ok=True)
    
    try:
        # Test allowed extensions
        for ext in ['.csv', '.json', '.log']:
            test_file = os.path.join(test_dir, f"test{ext}")
            with open(test_file, 'w') as f:
                f.write("test content")
            
            # Should pass
            assert SecurityValidator.validate_file_path(test_file, base_dir=test_dir)
            
            # Clean up individual file
            try:
                os.unlink(test_file)
            except (OSError, PermissionError):
                pass
        
        # Test forbidden extension
        bad_file = os.path.join(test_dir, "test.exe")
        with open(bad_file, 'w') as f:
            f.write("test content")
        
        with pytest.raises(SecurityError):
            SecurityValidator.validate_file_path(bad_file, base_dir=test_dir)
            
    finally:
        # Windows-safe cleanup
        TestSecurityValidator()._safe_cleanup(test_dir)

if __name__ == "__main__":
    pytest.main([__file__, "-v"])