"""
ETNA CTI Integration
Cyber Threat Intelligence feeds integration for ETNA platform.
"""

import requests
import json
import os
import pandas as pd
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from src.cti_config import CTIConfigManager, IOCFeedConfig
import time
from functools import wraps
from .security import SecurityValidator, SecurityError, RateLimiter
import ssl
import certifi

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def retry_with_backoff(max_retries=3, backoff_factor=1):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            for attempt in range(max_retries):
                try:
                    return func(*args, **kwargs)
                except requests.exceptions.RequestException as e:
                    if attempt == max_retries - 1:
                        raise
                    wait_time = backoff_factor * (2 ** attempt)
                    logger.warning(f"Request failed, retrying in {wait_time}s: {e}")
                    time.sleep(wait_time)
            return None
        return wrapper
    return decorator

class EnhancedCTIManager:
    def __init__(self, config_path: str = "config/cti_config.json"):
        self.config_manager = CTIConfigManager(config_path)
        self.config = self.config_manager.config
        self.cti_data_path = self.config.cache_directory
        os.makedirs(self.cti_data_path, exist_ok=True)
        
        # Security enhancements
        self.rate_limiter = RateLimiter(max_requests=100, time_window=3600)
        self.session = self._create_secure_session()
        
        # MITRE ATT&CK configuration
        self.mitre_attack_enterprise_url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
        self.mitre_data: Optional[Dict[str, Any]] = None
        self.techniques_df: Optional[pd.DataFrame] = None
        self.ioc_cache: Dict[str, Dict] = {}

    def _create_secure_session(self) -> requests.Session:
        """Create a secure requests session with proper SSL verification."""
        session = requests.Session()
        
        # Use system CA certificates
        session.verify = certifi.where()
        
        # Set secure headers
        session.headers.update({
            'User-Agent': 'ETNA-ThreatHunting-Platform/1.0',
            'Accept': 'application/json, text/plain, */*',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        })
        
        # Configure SSL context
        session.mount('https://', requests.adapters.HTTPAdapter(
            max_retries=3,
            pool_connections=10,
            pool_maxsize=10
        ))
        
        return session

    def initialize_cti_feeds(self) -> Dict[str, Any]:
        """
        Initialize all CTI feeds and return status summary.
        Production-ready method for real-world deployment.
        """
        logger.info("Initializing CTI feeds...")
        
        status_summary = {
            'mitre_attack': {'status': 'pending', 'techniques_count': 0, 'last_updated': None},
            'ioc_feeds': {},
            'total_iocs': 0,
            'errors': []
        }
        
        # Initialize MITRE ATT&CK data
        try:
            if self._should_update_mitre():
                logger.info("Updating MITRE ATT&CK data...")
                self.fetch_mitre_attack_data(force_download=True)
            else:
                logger.info("Loading cached MITRE ATT&CK data...")
                self.get_techniques_dataframe()
            
            status_summary['mitre_attack'] = {
                'status': 'success',
                'techniques_count': len(self.techniques_df) if self.techniques_df is not None else 0,
                'last_updated': self._get_file_age('enterprise-attack.json')
            }
        except Exception as e:
            logger.error(f"Failed to initialize MITRE ATT&CK: {e}")
            status_summary['mitre_attack']['status'] = 'failed'
            status_summary['errors'].append(f"MITRE ATT&CK: {str(e)}")
        
        # Initialize IOC feeds
        total_iocs = 0
        for feed_config in self.config.ioc_feeds:
            if not feed_config.enabled:
                continue
                
            try:
                if self._should_update_feed(feed_config):
                    logger.info(f"Updating IOC feed: {feed_config.name}")
                    iocs = self.fetch_ioc_feed_enhanced(feed_config)
                else:
                    logger.info(f"Loading cached IOC feed: {feed_config.name}")
                    iocs = self._load_cached_iocs(feed_config.name)
                
                status_summary['ioc_feeds'][feed_config.name] = {
                    'status': 'success',
                    'ioc_count': len(iocs),
                    'feed_type': feed_config.feed_type,
                    'last_updated': self._get_file_age(f"{feed_config.name}.json")
                }
                total_iocs += len(iocs)
                
            except Exception as e:
                logger.error(f"Failed to initialize feed {feed_config.name}: {e}")
                status_summary['ioc_feeds'][feed_config.name] = {
                    'status': 'failed',
                    'error': str(e)
                }
                status_summary['errors'].append(f"{feed_config.name}: {str(e)}")
        
        status_summary['total_iocs'] = total_iocs
        logger.info(f"CTI initialization complete. {total_iocs} IOCs loaded from {len(status_summary['ioc_feeds'])} feeds.")
        
        return status_summary
    
    @retry_with_backoff(max_retries=3)
    def fetch_ioc_feed_enhanced(self, feed_config: IOCFeedConfig) -> List[Dict[str, Any]]:
        """Enhanced IOC feed fetching with security controls."""
        
        # Rate limiting check
        if not self.rate_limiter.is_allowed(feed_config.url):
            raise SecurityError(f"Rate limit exceeded for {feed_config.name}")
        
        logger.info(f"Fetching IOC feed: {feed_config.name} from {feed_config.url}")
        
        # Validate URL
        if not self._validate_url(feed_config.url):
            raise SecurityError(f"Invalid or unsafe URL: {feed_config.url}")
        
        headers = feed_config.headers or {}
        headers.setdefault('User-Agent', 'ETNA-ThreatHunting-Platform/1.0')
        
        try:
            response = self.session.get(
                feed_config.url, 
                headers=headers, 
                timeout=30,
                stream=True  # Stream large responses
            )
            response.raise_for_status()
            
            # Check response size
            content_length = response.headers.get('content-length')
            if content_length and int(content_length) > 50 * 1024 * 1024:  # 50MB
                raise SecurityError(f"Response too large: {content_length} bytes")
            
            # Read response with size limit
            content = b''
            for chunk in response.iter_content(chunk_size=8192):
                content += chunk
                if len(content) > 50 * 1024 * 1024:  # 50MB limit
                    raise SecurityError("Response exceeded size limit")
            
            # Parse based on content type
            if 'application/json' in response.headers.get('content-type', ''):
                iocs = self._parse_json_feed(json.loads(content.decode('utf-8')), feed_config)
            else:
                iocs = self._parse_text_feed(content.decode('utf-8'), feed_config)
            
            # Validate and sanitize IOCs
            iocs = self._validate_iocs(iocs)
            
            # Cache the results
            self._cache_iocs(feed_config.name, iocs)
            
            logger.info(f"Successfully fetched {len(iocs)} IOCs from {feed_config.name}")
            return iocs
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Network error fetching {feed_config.name}: {e}")
            raise
        except Exception as e:
            logger.error(f"Error parsing {feed_config.name}: {e}")
            raise

    def _validate_url(self, url: str) -> bool:
        """Validate URL for security."""
        import urllib.parse
        
        parsed = urllib.parse.urlparse(url)
        
        # Must be HTTPS
        if parsed.scheme != 'https':
            logger.warning(f"Non-HTTPS URL rejected: {url}")
            return False
        
        # Check for suspicious domains
        suspicious_domains = ['localhost', '127.0.0.1', '0.0.0.0', '10.', '192.168.', '172.16.']
        if any(suspicious in parsed.netloc for suspicious in suspicious_domains):
            logger.warning(f"Suspicious domain rejected: {parsed.netloc}")
            return False
        
        return True

    def _validate_iocs(self, iocs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Validate and sanitize IOC data."""
        validated_iocs = []
        
        for ioc in iocs:
            try:
                # Sanitize all string fields
                sanitized_ioc = {}
                for key, value in ioc.items():
                    if isinstance(value, str):
                        sanitized_ioc[key] = SecurityValidator.sanitize_string(value, max_length=1000)
                    else:
                        sanitized_ioc[key] = value
                
                # Validate required fields
                if 'value' in sanitized_ioc and sanitized_ioc['value']:
                    validated_iocs.append(sanitized_ioc)
                    
            except Exception as e:
                logger.warning(f"Skipping invalid IOC: {e}")
                continue
        
        logger.info(f"Validated {len(validated_iocs)} out of {len(iocs)} IOCs")
        return validated_iocs

    def _parse_json_feed(self, data: Any, feed_config: IOCFeedConfig) -> List[Dict[str, Any]]:
        """Parse JSON-based IOC feeds."""
        iocs = []
        
        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    ioc = self._extract_ioc_from_dict(item, feed_config.feed_type)
                    if ioc:
                        iocs.append(ioc)
        elif isinstance(data, dict):
            # Handle different JSON structures
            if 'data' in data:
                return self._parse_json_feed(data['data'], feed_config)
            elif 'iocs' in data:
                return self._parse_json_feed(data['iocs'], feed_config)
        
        return iocs

    def _parse_text_feed(self, text: str, feed_config: IOCFeedConfig) -> List[Dict[str, Any]]:
        """Parse text-based IOC feeds."""
        iocs = []
        
        for line in text.splitlines():
            line = line.strip()
            
            # Skip comments and empty lines
            if not line or line.startswith('#') or line.startswith('//'):
                continue
            
            # Basic IOC extraction
            ioc_value = line.split()[0]  # Take first column for simple feeds
            
            if self._is_valid_ioc(ioc_value, feed_config.feed_type):
                iocs.append({
                    'value': ioc_value,
                    'type': feed_config.feed_type,
                    'source': feed_config.name,
                    'timestamp': datetime.now().isoformat(),
                    'confidence': 'medium'  # Default confidence
                })
        
        return iocs

    def _extract_ioc_from_dict(self, item: Dict, feed_type: str) -> Optional[Dict[str, Any]]:
        """Extract IOC information from dictionary item."""
        # Common field mappings
        value_fields = ['value', 'indicator', 'ioc', 'ip', 'domain', 'hash', 'url']
        type_fields = ['type', 'ioc_type', 'indicator_type']
        
        ioc_value = None
        ioc_type = feed_type
        
        # Try to find the IOC value
        for field in value_fields:
            if field in item:
                ioc_value = item[field]
                break
        
        # Try to find the IOC type
        for field in type_fields:
            if field in item:
                ioc_type = item[field]
                break
        
        if ioc_value and self._is_valid_ioc(ioc_value, ioc_type):
            return {
                'value': ioc_value,
                'type': ioc_type,
                'source': item.get('source', 'unknown'),
                'timestamp': item.get('timestamp', datetime.now().isoformat()),
                'confidence': item.get('confidence', 'medium'),
                'tags': item.get('tags', []),
                'description': item.get('description', '')
            }
        
        return None

    def _is_valid_ioc(self, value: str, ioc_type: str) -> bool:
        """Validate IOC value based on type."""
        import re
        
        if not value or len(value) < 3:
            return False
        
        # Enhanced validation for IP addresses
        if ioc_type == 'ip':
            try:
                parts = value.split('.')
                if len(parts) != 4:
                    return False
                for part in parts:
                    if not part.isdigit() or int(part) > 255 or int(part) < 0:
                        return False
                return True
            except (ValueError, AttributeError):
                return False
        
        # Basic validation patterns for other types
        patterns = {
            'domain': r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$',
            'url': r'^https?://',
            'md5': r'^[a-fA-F0-9]{32}$',
            'sha1': r'^[a-fA-F0-9]{40}$',
            'sha256': r'^[a-fA-F0-9]{64}$'
        }
        
        if ioc_type in patterns:
            return bool(re.match(patterns[ioc_type], value))
    
        return True  # Allow unknown types

    def _cache_iocs(self, feed_name: str, iocs: List[Dict[str, Any]]):
        """Cache IOCs to local storage."""
        cache_path = os.path.join(self.cti_data_path, f"{feed_name}.json")
        cache_data = {
            'timestamp': datetime.now().isoformat(),
            'count': len(iocs),
            'iocs': iocs
        }
        
        with open(cache_path, 'w') as f:
            json.dump(cache_data, f, indent=2)

    def _load_cached_iocs(self, feed_name: str) -> List[Dict[str, Any]]:
        """Load IOCs from cache."""
        cache_path = os.path.join(self.cti_data_path, f"{feed_name}.json")
        
        if os.path.exists(cache_path):
            with open(cache_path, 'r') as f:
                cache_data = json.load(f)
                return cache_data.get('iocs', [])
        
        return []

    def _should_update_mitre(self) -> bool:
        """Check if MITRE data needs updating."""
        return self._should_update_file('enterprise-attack.json', self.config.mitre_update_interval)

    def _should_update_feed(self, feed_config: IOCFeedConfig) -> bool:
        """Check if IOC feed needs updating."""
        return self._should_update_file(f"{feed_config.name}.json", feed_config.update_interval)

    def _should_update_file(self, filename: str, max_age_hours: int) -> bool:
        """Check if file needs updating based on age."""
        file_path = os.path.join(self.cti_data_path, filename)
        
        if not os.path.exists(file_path):
            return True
        
        file_age = datetime.now() - datetime.fromtimestamp(os.path.getmtime(file_path))
        return file_age > timedelta(hours=max_age_hours)

    def _get_file_age(self, filename: str) -> Optional[str]:
        """Get file last modified time."""
        file_path = os.path.join(self.cti_data_path, filename)
        
        if os.path.exists(file_path):
            return datetime.fromtimestamp(os.path.getmtime(file_path)).isoformat()
        
        return None

    def get_all_iocs(self, ioc_type: str = None) -> List[Dict[str, Any]]:
        """
        Get all cached IOCs, optionally filtered by type.
        Production method for IOC lookups.
        """
        all_iocs = []
        
        for feed_config in self.config.ioc_feeds:
            if not feed_config.enabled:
                continue
            
            cached_iocs = self._load_cached_iocs(feed_config.name)
            
            if ioc_type:
                cached_iocs = [ioc for ioc in cached_iocs if ioc.get('type') == ioc_type]
            
            all_iocs.extend(cached_iocs)
        
        return all_iocs

    def check_ioc(self, value: str) -> List[Dict[str, Any]]:
        """
        Check if a value matches any known IOCs.
        Returns list of matching IOC records.
        """
        matches = []
        all_iocs = self.get_all_iocs()
        
        for ioc in all_iocs:
            if ioc.get('value', '').lower() == value.lower():
                matches.append(ioc)
        
        return matches
    
    @retry_with_backoff(max_retries=3)
    def fetch_mitre_attack_data(self, force_download: bool = False) -> Dict[str, Any]:
        """Fetch MITRE ATT&CK Enterprise data."""
        mitre_path = os.path.join(self.cti_data_path, 'enterprise-attack.json')
        
        if not force_download and os.path.exists(mitre_path):
            try:
                with open(mitre_path, 'r') as f:
                    self.mitre_data = json.load(f)
                    logger.info(f"Loaded cached MITRE data with {len(self.mitre_data.get('objects', []))} objects")
                    return self.mitre_data
            except Exception as e:
                logger.warning(f"Failed to load cached MITRE data: {e}")
        
        try:
            logger.info("Downloading MITRE ATT&CK data...")
            response = self.session.get(self.mitre_attack_enterprise_url, timeout=60)
            response.raise_for_status()
            
            self.mitre_data = response.json()
            logger.info(f"Downloaded MITRE data with {len(self.mitre_data.get('objects', []))} objects")
            
            # Cache the data
            with open(mitre_path, 'w') as f:
                json.dump(self.mitre_data, f, indent=2)
                
        except requests.exceptions.RequestException as e:
            logger.error(f"Network error fetching MITRE data: {e}")
            # Create minimal fallback data
            self.mitre_data = {"objects": []}
        except Exception as e:
            logger.error(f"Failed to fetch MITRE data: {e}")
            self.mitre_data = {"objects": []}
            
        return self.mitre_data

    def get_techniques_dataframe(self) -> pd.DataFrame:
        """Convert MITRE data to DataFrame."""
        if not self.mitre_data:
            logger.info("No MITRE data available, fetching...")
            try:
                self.fetch_mitre_attack_data()
            except Exception as e:
                logger.error(f"Failed to fetch MITRE data: {e}")
                self.techniques_df = pd.DataFrame(columns=['technique_id', 'name', 'description', 'url'])
                return self.techniques_df
        
        techniques = []
        
        # Handle case where mitre_data is None or empty
        if not self.mitre_data or 'objects' not in self.mitre_data:
            logger.warning("MITRE data is empty or invalid")
            self.techniques_df = pd.DataFrame(columns=['technique_id', 'name', 'description', 'url'])
            return self.techniques_df
        
        for obj in self.mitre_data.get('objects', []):
            if obj.get('type') == 'attack-pattern':
                external_refs = obj.get('external_references', [])
                technique_id = ''
                
                # Find the MITRE technique ID
                for ref in external_refs:
                    if ref.get('source_name') == 'mitre-attack':
                        technique_id = ref.get('external_id', '')
                        break
                
                if technique_id:  # Only add if we have a valid technique ID
                    techniques.append({
                        'technique_id': technique_id,
                        'name': obj.get('name', ''),
                        'description': obj.get('description', ''),
                        'url': f"https://attack.mitre.org/techniques/{technique_id}"
                    })
        
        self.techniques_df = pd.DataFrame(techniques)
        
        if self.techniques_df.empty:
            logger.warning("No MITRE techniques found in data")
            self.techniques_df = pd.DataFrame(columns=['technique_id', 'name', 'description', 'url'])
        
        logger.info(f"Loaded {len(self.techniques_df)} MITRE techniques")
        return self.techniques_df

    def get_technique_by_id(self, technique_id: str) -> Optional[Dict[str, Any]]:
        """Get technique details by ID."""
        if self.techniques_df is None or self.techniques_df.empty:
            logger.warning("Techniques DataFrame is empty, attempting to reload...")
            self.get_techniques_dataframe()
        
        # Check if DataFrame still empty or missing column
        if self.techniques_df is None or self.techniques_df.empty:
            logger.error("No MITRE techniques available")
            return None
            
        if 'technique_id' not in self.techniques_df.columns:
            logger.error("technique_id column not found in DataFrame")
            return None
        
        technique = self.techniques_df[self.techniques_df['technique_id'] == technique_id]
        if not technique.empty:
            return technique.iloc[0].to_dict()
        return None


# Production-ready usage functions
def initialize_threat_intelligence(config_path: str = "config/cti_config.json") -> Tuple[EnhancedCTIManager, Dict[str, Any]]:
    """
    Initialize complete threat intelligence system.
    Returns CTI manager and status summary.
    """
    cti_manager = EnhancedCTIManager(config_path)
    status = cti_manager.initialize_cti_feeds()
    return cti_manager, status

def check_indicators(cti_manager: EnhancedCTIManager, indicators: List[str]) -> Dict[str, List[Dict]]:
    """
    Check multiple indicators against all IOC feeds.
    Returns dictionary mapping indicators to their matches.
    """
    results = {}
    
    for indicator in indicators:
        matches = cti_manager.check_ioc(indicator)
        if matches:
            results[indicator] = matches
    
    return results

def get_technique_info(cti_manager: EnhancedCTIManager, technique_ids: List[str]) -> Dict[str, Dict]:
    """
    Get information for multiple MITRE ATT&CK techniques.
    """
    results = {}
    
    for technique_id in technique_ids:
        technique_info = cti_manager.get_technique_by_id(technique_id)
        if technique_info:
            results[technique_id] = technique_info
    
    return results

# Usage for real-world scenarios
if __name__ == "__main__":
    # Production-ready initialization
    logger.info("Initializing Threat Intelligence System...")
    
    cti_manager, status = initialize_threat_intelligence()
    
    # Print status summary
    print(f"MITRE ATT&CK: {status['mitre_attack']['status']} - {status['mitre_attack']['techniques_count']} techniques")
    print(f"IOC Feeds: {len(status['ioc_feeds'])} feeds, {status['total_iocs']} total IOCs")
    
    if status['errors']:
        print(f"Errors encountered: {len(status['errors'])}")
        for error in status['errors']:
            print(f"  - {error}")
    
    # Example: Check suspicious indicators
    suspicious_indicators = ['192.168.1.100', 'malware.example.com', 'suspicious-hash-here']
    ioc_matches = check_indicators(cti_manager, suspicious_indicators)
    
    if ioc_matches:
        print(f"\nThreat indicators found:")
        for indicator, matches in ioc_matches.items():
            print(f"  {indicator}: {len(matches)} matches")
    
    # Example: Get technique information
    techniques_to_check = ['T1059.001', 'T1003', 'T1049']
    technique_info = get_technique_info(cti_manager, techniques_to_check)
    
    print(f"\nMITRE ATT&CK Techniques:")
    for tech_id, info in technique_info.items():
        print(f"  {tech_id}: {info['name']}")