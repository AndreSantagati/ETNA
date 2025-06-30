"""
CTI Configuration Management
Centralized configuration for threat intelligence feeds and sources.
"""

import json
import os
from typing import Dict, List, Any
from dataclasses import dataclass

@dataclass
class IOCFeedConfig:
    name: str
    url: str
    feed_type: str  # 'ip', 'domain', 'hash', 'mixed'
    update_interval: int  # hours
    enabled: bool = True
    headers: Dict[str, str] = None

@dataclass
class CTIConfig:
    mitre_update_interval: int = 24  # hours
    ioc_feeds: List[IOCFeedConfig] = None
    cache_directory: str = "data/cti/"
    max_cache_age: int = 24  # hours

class CTIConfigManager:
    def __init__(self, config_path: str = "config/cti_config.json"):
        self.config_path = config_path
        self.config = self._load_config()
    
    def _load_config(self) -> CTIConfig:
        """Load configuration from JSON file or create default."""
        if os.path.exists(self.config_path):
            with open(self.config_path, 'r') as f:
                config_data = json.load(f)
                return self._dict_to_config(config_data)
        else:
            return self._create_default_config()
    
    def _create_default_config(self) -> CTIConfig:
        """Create default configuration with common IOC feeds."""
        default_feeds = [
            IOCFeedConfig(
                name="feodotracker_ips",
                url="https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
                feed_type="ip",
                update_interval=6
            ),
            IOCFeedConfig(
                name="malware_domains",
                url="https://urlhaus.abuse.ch/downloads/text/",
                feed_type="domain", 
                update_interval=12
            ),
            IOCFeedConfig(
                name="threatfox_iocs",
                url="https://threatfox.abuse.ch/export/json/recent/",
                feed_type="mixed",
                update_interval=4
            )
        ]
        
        config = CTIConfig(
            mitre_update_interval=24,
            ioc_feeds=default_feeds,
            cache_directory="data/cti/",
            max_cache_age=24
        )
        
        # Save default config
        self._save_config(config)
        return config
    
    def _dict_to_config(self, config_dict: Dict) -> CTIConfig:
        """Convert dictionary to CTIConfig object."""
        feeds = []
        for feed_data in config_dict.get('ioc_feeds', []):
            feeds.append(IOCFeedConfig(**feed_data))
        
        return CTIConfig(
            mitre_update_interval=config_dict.get('mitre_update_interval', 24),
            ioc_feeds=feeds,
            cache_directory=config_dict.get('cache_directory', 'data/cti/'),
            max_cache_age=config_dict.get('max_cache_age', 24)
        )
    
    def _save_config(self, config: CTIConfig):
        """Save configuration to JSON file."""
        os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
        
        config_dict = {
            'mitre_update_interval': config.mitre_update_interval,
            'cache_directory': config.cache_directory,
            'max_cache_age': config.max_cache_age,
            'ioc_feeds': [
                {
                    'name': feed.name,
                    'url': feed.url,
                    'feed_type': feed.feed_type,
                    'update_interval': feed.update_interval,
                    'enabled': feed.enabled,
                    'headers': feed.headers
                }
                for feed in config.ioc_feeds
            ]
        }
        
        with open(self.config_path, 'w') as f:
            json.dump(config_dict, f, indent=2)