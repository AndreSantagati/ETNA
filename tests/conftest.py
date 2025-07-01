"""
Pytest configuration for ETNA security tests
"""

import pytest
import os
import shutil
from src.security import SecurityValidator

@pytest.fixture(scope="session", autouse=True)
def setup_test_environment():
    """Setup testing environment before any tests run."""
    # Enable testing mode for security validator
    SecurityValidator.set_testing_mode(True)
    
    # Create necessary test directories
    test_dirs = ["data/logs/test", "test_temp", "logs"]
    for test_dir in test_dirs:
        os.makedirs(test_dir, exist_ok=True)
    
    yield
    
    # Cleanup after tests
    SecurityValidator.set_testing_mode(False)
    
    # Clean up test directories
    cleanup_dirs = ["test_temp", "data/logs/test"]
    for cleanup_dir in cleanup_dirs:
        if os.path.exists(cleanup_dir):
            shutil.rmtree(cleanup_dir, ignore_errors=True)

@pytest.fixture
def temp_test_file():
    """Create a temporary test file in the correct location."""
    test_dir = "test_temp"
    os.makedirs(test_dir, exist_ok=True)
    
    test_file = os.path.join(test_dir, "temp_test.csv")
    with open(test_file, 'w') as f:
        f.write("TimeCreated,ProcessName,EventData\n")
        f.write("2024-01-01,test.exe,Normal data\n")
    
    yield test_file
    
    # Cleanup
    if os.path.exists(test_file):
        os.unlink(test_file)