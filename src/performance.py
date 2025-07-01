"""
Performance optimizations for ETNA platform.
"""

import functools
import time
import psutil
import logging
from typing import Callable, Any
import pandas as pd

logger = logging.getLogger(__name__)

def monitor_performance(func: Callable) -> Callable:
    """Decorator to monitor function performance."""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        start_time = time.time()
        start_memory = psutil.Process().memory_info().rss / 1024 / 1024  # MB
        
        try:
            result = func(*args, **kwargs)
            
            end_time = time.time()
            end_memory = psutil.Process().memory_info().rss / 1024 / 1024  # MB
            
            execution_time = end_time - start_time
            memory_used = end_memory - start_memory
            
            logger.info(f"Performance: {func.__name__} - Time: {execution_time:.2f}s, Memory: {memory_used:.2f}MB")
            
            # Warn if performance is poor
            if execution_time > 30:
                logger.warning(f"Slow execution detected: {func.__name__} took {execution_time:.2f}s")
            
            if memory_used > 500:  # 500MB
                logger.warning(f"High memory usage: {func.__name__} used {memory_used:.2f}MB")
            
            return result
            
        except Exception as e:
            logger.error(f"Error in {func.__name__}: {e}")
            raise
    
    return wrapper

class DataFrameOptimizer:
    """Optimize DataFrame operations for better performance."""
    
    @staticmethod
    def optimize_dtypes(df: pd.DataFrame) -> pd.DataFrame:
        """Optimize DataFrame data types to reduce memory usage."""
        optimized_df = df.copy()
        
        for col in optimized_df.columns:
            col_type = optimized_df[col].dtype
            
            if col_type == 'object':
                # Try to convert to category if it has few unique values
                unique_ratio = len(optimized_df[col].unique()) / len(optimized_df[col])
                if unique_ratio < 0.5:  # Less than 50% unique values
                    optimized_df[col] = optimized_df[col].astype('category')
            
            elif 'int' in str(col_type):
                # Downcast integers
                optimized_df[col] = pd.to_numeric(optimized_df[col], downcast='integer')
            
            elif 'float' in str(col_type):
                # Downcast floats
                optimized_df[col] = pd.to_numeric(optimized_df[col], downcast='float')
        
        return optimized_df
    
    @staticmethod
    def memory_usage_report(df: pd.DataFrame) -> dict:
        """Generate memory usage report for DataFrame."""
        memory_usage = df.memory_usage(deep=True)
        total_memory = memory_usage.sum() / 1024 / 1024  # MB
        
        return {
            'total_memory_mb': total_memory,
            'shape': df.shape,
            'columns': len(df.columns),
            'memory_per_column': {col: usage / 1024 / 1024 for col, usage in memory_usage.items()}
        }