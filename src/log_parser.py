# src/log_parser.py

import pandas as pd
import os
from abc import ABC, abstractmethod
from typing import Dict, Any, Union, Iterator
import time 
from functools import wraps
import json
import logging

# Import our new security module
from .security import SecurityValidator, SecurityError, require_valid_file, sanitize_inputs

logger = logging.getLogger(__name__)

# Define a standard schema for normalized logs
NORMALIZED_LOG_SCHEMA = {
    'timestamp': 'datetime64[ns]',
    'hostname': str,
    'username': str,
    'process_name': str,
    'event_id': int,
    'message': str,
    'source_ip': str,
    'destination_ip': str,
    'action': str,
}

class BaseLogParser(ABC):
    """Abstract base class for log parsers with security validation."""
    
    def __init__(self, log_path: str):
        # Validate file path first
        try:
            SecurityValidator.validate_file_path(log_path, base_dir="data/logs")
            logger.info(f"File validation passed for: {log_path}")
        except SecurityError as e:
            logger.error(f"Security validation failed: {e}")
            raise
        
        self.log_path = log_path
        self.normalized_df = pd.DataFrame(columns=NORMALIZED_LOG_SCHEMA.keys())
        self.file_hash = SecurityValidator.generate_file_hash(log_path)
        logger.info(f"File hash: {self.file_hash}")

    @abstractmethod
    def parse(self) -> pd.DataFrame:
        """Abstract method to parse the log file and return a normalized DataFrame."""
        pass

    def _normalize_columns(self, df: pd.DataFrame, column_map: Dict[str, str]) -> pd.DataFrame:
        """
        Applies column renaming and ensures all schema columns are present.
        Now with security validation.
        """
        # Validate DataFrame size first
        try:
            SecurityValidator.validate_dataframe_size(df)
        except SecurityError as e:
            logger.error(f"DataFrame validation failed: {e}")
            raise
        
        df = df.rename(columns=column_map)

        # Ensure all columns from the NORMALIZED_LOG_SCHEMA are present
        for col, dtype in NORMALIZED_LOG_SCHEMA.items():
            if col not in df.columns:
                df[col] = None  # Add missing columns with None
            try:
                # Attempt to convert to the target dtype, handling errors
                if df[col].dtype != dtype:
                    if dtype == 'datetime64[ns]':
                        df[col] = pd.to_datetime(df[col], errors='coerce')
                    elif isinstance(dtype, type) and dtype != str:
                        df[col] = df[col].astype(dtype, errors='ignore')
            except Exception as e:
                logger.warning(f"Could not convert column '{col}' to {dtype}. Error: {e}")
                df[col] = None

        # Sanitize string columns
        string_columns = ['hostname', 'username', 'process_name', 'message', 'source_ip', 'destination_ip', 'action']
        for col in string_columns:
            if col in df.columns:
                df[col] = df[col].apply(
                    lambda x: SecurityValidator.sanitize_string(str(x)) if pd.notna(x) else x
                )

        return df[list(NORMALIZED_LOG_SCHEMA.keys())]

    def parse_chunked(self, chunk_size: int = 10000) -> Iterator[pd.DataFrame]:
        """
        Parse file in chunks to handle large files safely.
        
        Args:
            chunk_size: Number of rows per chunk
            
        Yields:
            pd.DataFrame: Normalized chunks
        """
        try:
            if self.log_path.endswith('.csv'):
                for chunk in pd.read_csv(self.log_path, chunksize=chunk_size):
                    # Apply same normalization to each chunk
                    column_map = self._get_column_map()
                    normalized_chunk = self._normalize_columns(chunk, column_map)
                    yield normalized_chunk
            else:
                # For non-CSV files, fall back to regular parsing
                yield self.parse()
                
        except Exception as e:
            logger.error(f"Error during chunked parsing: {e}")
            raise SecurityError(f"Failed to parse file safely: {str(e)}")

    @abstractmethod
    def _get_column_map(self) -> Dict[str, str]:
        """Get the column mapping for this parser type."""
        pass


class CsvLogParser(BaseLogParser):
    """Parser for CSV log files with security enhancements."""
    
    @sanitize_inputs(['message', 'hostname', 'username', 'process_name'])
    def parse(self) -> pd.DataFrame:
        """Parse a CSV log file and normalize columns according to our schema."""
        try:
            # Use chunked reading for large files
            chunk_size = 50000  # Process 50k rows at a time
            file_size = os.path.getsize(self.log_path)
            
            if file_size > 10 * 1024 * 1024:  # 10MB
                logger.info(f"Large file detected ({file_size} bytes), using chunked processing")
                chunks = []
                for chunk in self.parse_chunked(chunk_size):
                    chunks.append(chunk)
                
                if chunks:
                    df = pd.concat(chunks, ignore_index=True)
                else:
                    df = pd.DataFrame(columns=NORMALIZED_LOG_SCHEMA.keys())
            else:
                # Small file, read normally but with safety limits
                df = pd.read_csv(
                    self.log_path,
                    nrows=SecurityValidator.MAX_ROWS_PER_FILE,  # Limit rows
                    encoding='utf-8',
                    on_bad_lines='skip'  # Skip malformed lines
                )
            
            column_map = self._get_column_map()
            self.normalized_df = self._normalize_columns(df, column_map)
            
            logger.info(f"Successfully parsed and normalized {len(self.normalized_df)} records from {self.log_path}")
            return self.normalized_df

        except SecurityError:
            raise  # Re-raise security errors
        except Exception as e:
            logger.error(f"Error parsing CSV file {self.log_path}: {e}")
            # Return empty DataFrame instead of crashing
            return pd.DataFrame(columns=NORMALIZED_LOG_SCHEMA.keys())

    def _get_column_map(self) -> Dict[str, str]:
        """Get CSV-specific column mapping."""
        return {
            'TimeCreated': 'timestamp',
            'UserName': 'username',
            'ProcessName': 'process_name',
            'EventID': 'event_id',
            'ComputerName': 'hostname',
            'SourceIpAddress': 'source_ip',
            'DestinationIpAddress': 'destination_ip',
            'EventData': 'message',
            'Action': 'action',
        }


class JsonLogParser(BaseLogParser):
    """Parser for JSON log files with security enhancements."""
    
    @sanitize_inputs(['message', 'hostname', 'username', 'process_name'])
    def parse(self) -> pd.DataFrame:
        """Parse JSON log files with security validation."""
        try:
            file_size = os.path.getsize(self.log_path)
            
            # Limit file size for JSON parsing
            if file_size > 50 * 1024 * 1024:  # 50MB limit for JSON
                raise SecurityError(f"JSON file too large: {file_size} bytes")
            
            with open(self.log_path, 'r', encoding='utf-8') as f:
                if self.log_path.endswith('.jsonl'):
                    logs = []
                    line_count = 0
                    for line in f:
                        if line_count >= SecurityValidator.MAX_ROWS_PER_FILE:
                            logger.warning(f"Reached max rows limit, stopping at {line_count}")
                            break
                        try:
                            logs.append(json.loads(line.strip()))
                            line_count += 1
                        except json.JSONDecodeError:
                            logger.warning(f"Skipping malformed JSON line: {line_count}")
                            continue
                else:
                    data = json.load(f)
                    if not isinstance(data, list):
                        logs = [data]
                    else:
                        logs = data[:SecurityValidator.MAX_ROWS_PER_FILE]  # Limit rows
            
            if not logs:
                logger.warning("No valid JSON records found")
                return pd.DataFrame(columns=NORMALIZED_LOG_SCHEMA.keys())
            
            df = pd.DataFrame(logs)
            column_map = self._get_column_map()
            
            return self._normalize_columns(df, column_map)
            
        except SecurityError:
            raise
        except Exception as e:
            logger.error(f"Error parsing JSON file {self.log_path}: {e}")
            return pd.DataFrame(columns=NORMALIZED_LOG_SCHEMA.keys())

    def _get_column_map(self) -> Dict[str, str]:
        """Get JSON-specific column mapping."""
        return {
            '@timestamp': 'timestamp',
            'host': 'hostname',
            'user': 'username',
            'process': 'process_name',
            'event_id': 'event_id',
            'message': 'message',
            'src_ip': 'source_ip',
            'dst_ip': 'destination_ip'
        }


# Updated Factory with security validation
class LogParserFactory:
    @staticmethod
    @require_valid_file(base_dir="data/logs")
    def get_parser(log_path: str) -> BaseLogParser:
        file_extension = os.path.splitext(log_path)[1].lower()
        
        if file_extension == '.csv':
            return CsvLogParser(log_path)
        elif file_extension in ['.json', '.jsonl']:
            return JsonLogParser(log_path)
        else:
            raise SecurityError(f"Unsupported log file type: {file_extension}")