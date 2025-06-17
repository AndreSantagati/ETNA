# src/log_parser.py

import pandas as pd
import os
from abc import ABC, abstractmethod
from typing import Dict, Any, Union

# Define a standard schema for normalized logs
# This helps ensure consistency across different log sources
NORMALIZED_LOG_SCHEMA = {
    'timestamp': 'datetime64[ns]',
    'hostname': str,
    'username': str,
    'process_name': str,
    'event_id': int,
    'message': str,
    'source_ip': str,
    'destination_ip': str,
    'action': str, # e.g., 'created', 'deleted', 'executed', 'failed'
    # Add more fields as needed for specific log types
}

class BaseLogParser(ABC):
    """Abstract base class for log parsers."""
    def __init__(self, log_path: str):
        if not os.path.exists(log_path):
            raise FileNotFoundError(f"Log file not found: {log_path}")
        self.log_path = log_path
        self.normalized_df = pd.DataFrame(columns=NORMALIZED_LOG_SCHEMA.keys())

    @abstractmethod
    def parse(self) -> pd.DataFrame:
        """
        Abstract method to parse the log file and return a normalized DataFrame.
        Each specific parser must implement this.
        """
        pass

    def _normalize_columns(self, df: pd.DataFrame, column_map: Dict[str, str]) -> pd.DataFrame:
        """
        Applies column renaming and ensures all schema columns are present.
        """
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
                print(f"Warning: Could not convert column '{col}' to {dtype}. Error: {e}")
                df[col] = None # Set to None if conversion fails

        return df[list(NORMALIZED_LOG_SCHEMA.keys())] # Return only schema-defined columns


class CsvLogParser(BaseLogParser):
    """Parser for CSV log files."""
    def parse(self) -> pd.DataFrame:
        """
        Parse a CSV log file and normalize columns according to our schema.
        """
        try:
            df = pd.read_csv(self.log_path)
            
            # Define specific column mappings for your CSV log file
            # You will need to adapt this based on the actual column names in your CSV
            column_map = {
                'TimeCreated': 'timestamp',
                'UserName': 'username',
                'ProcessName': 'process_name',
                'EventID': 'event_id',
                # Example: If your CSV has a 'ComputerName' column, map it to 'hostname'
                'ComputerName': 'hostname',
                # Example: If your CSV has a 'SourceIpAddress' column, map it
                'SourceIpAddress': 'source_ip',
                'DestinationIpAddress': 'destination_ip',
                'EventData': 'message', # Generic message field
            }
            
            self.normalized_df = self._normalize_columns(df, column_map)
            print(f"Successfully parsed and normalized {len(self.normalized_df)} records from {self.log_path}")
            return self.normalized_df

        except Exception as e:
            print(f"Error parsing CSV file {self.log_path}: {e}")
            return pd.DataFrame(columns=NORMALIZED_LOG_SCHEMA.keys())


# --- Log Parser Factory (for easily getting the right parser) ---
class LogParserFactory:
    """Factory to get the appropriate log parser based on file extension."""
    @staticmethod
    def get_parser(log_path: str) -> BaseLogParser:
        file_extension = os.path.splitext(log_path)[1].lower()
        if file_extension == '.csv':
            return CsvLogParser(log_path)
        # Add more parser types here as you implement them
        # elif file_extension == '.json':
        #     return JsonLogParser(log_path)
        # elif file_extension == '.evtx':
        #     return EvtxLogParser(log_path)
        else:
            raise ValueError(f"Unsupported log file type: {file_extension}")

# --- Example Usage (for testing this module) ---
if __name__ == "__main__":
    # Ensure a sample log file exists for testing
    sample_csv_path = "data/logs/sample_log.csv"
    if not os.path.exists("data/logs"):
        os.makedirs("data/logs")
    if not os.path.exists(sample_csv_path):
        with open(sample_csv_path, "w") as f:
            f.write("TimeCreated,ComputerName,UserName,ProcessName,EventID,SourceIpAddress,DestinationIpAddress,EventData\n")
            f.write("2024-06-17 10:00:00,HOST-01,user1,powershell.exe,4104,192.168.1.10,8.8.8.8,Process started\n")
            f.write("2024-06-17 10:05:00,HOST-02,admin,cmd.exe,4688,10.0.0.5,192.168.1.1,Account logon\n")
            f.write("2024-06-17 10:10:00,HOST-01,user1,calc.exe,4688,,,User opened calculator\n")
            f.write("2024-06-17 10:15:00,HOST-03,guest,explorer.exe,4624,172.16.0.1,172.16.0.10,Successful logon\n")
        print(f"Generated a sample CSV log file at {sample_csv_path}")

    try:
        print("\n--- Testing CsvLogParser ---")
        csv_parser = CsvLogParser(sample_csv_path)
        parsed_df_csv = csv_parser.parse()
        print(parsed_df_csv.head())
        print(f"DataFrame columns: {parsed_df_csv.columns.tolist()}")
        print(f"DataFrame dtypes:\n{parsed_df_csv.dtypes}")

        print("\n--- Testing LogParserFactory with CSV ---")
        factory_parser = LogParserFactory.get_parser(sample_csv_path)
        parsed_df_factory = factory_parser.parse()
        print(parsed_df_factory.head())

        # Example of unsupported file type (will raise ValueError)
        # print("\n--- Testing Unsupported File Type ---")
        # LogParserFactory.get_parser("data/logs/unsupported.txt")

    except Exception as e:
        print(f"An error occurred during testing: {e}")