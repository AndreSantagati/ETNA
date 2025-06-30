import sqlite3
import json
from typing import List, Dict
from contextlib import contextmanager

class IOCDatabase:
    def __init__(self, db_path: str = "data/iocs.db"):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS iocs (
                    id INTEGER PRIMARY KEY,
                    value TEXT NOT NULL,
                    type TEXT NOT NULL,
                    source TEXT NOT NULL,
                    confidence TEXT,
                    timestamp TEXT,
                    tags TEXT,
                    description TEXT
                )
            ''')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_value ON iocs(value)')
    
    def bulk_insert_iocs(self, iocs: List[Dict]):
        with sqlite3.connect(self.db_path) as conn:
            conn.executemany('''
                INSERT OR REPLACE INTO iocs 
                (value, type, source, confidence, timestamp, tags, description)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', [(ioc['value'], ioc['type'], ioc['source'], 
                   ioc.get('confidence', 'medium'), ioc['timestamp'],
                   json.dumps(ioc.get('tags', [])), ioc.get('description', ''))
                  for ioc in iocs])
    
    def check_ioc(self, value: str) -> List[Dict]:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute('SELECT * FROM iocs WHERE value = ?', (value,))
            return [dict(zip([col[0] for col in cursor.description], row)) 
                    for row in cursor.fetchall()]