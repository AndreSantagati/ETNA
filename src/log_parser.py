# src/log_parser.py

import pandas as pd
from typing import List, Dict

class LogParser:
    def __init__(self, log_path: str):
        self.log_path = log_path

    def parse_csv(self) -> pd.DataFrame:
        """
        Parse a CSV log file and normalize columns.
        """
        df = pd.read_csv(self.log_path)
        # Example normalization: rename columns to standard names
        column_map = {
            'TimeCreated': 'timestamp',
            'UserName': 'user',
            'ProcessName': 'process',
            'EventID': 'event_id',
            # Add more mappings as needed
        }
        df = df.rename(columns=column_map)
        # Ensure required columns exist
        required_cols = ['timestamp', 'user', 'process', 'event_id']
        for col in required_cols:
            if col not in df.columns:
                df[col] = None  # Fill missing columns with None
        return df[required_cols]

    # You can add more methods for other formats (e.g., JSON, EVTX) later

if __name__ == "__main__":
    parser = LogParser("data/logs/sample_log.csv")
    df_logs = parser.parse_csv()
    print(df_logs.head())