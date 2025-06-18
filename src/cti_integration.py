# src/cti_integration.py

import requests
import json
import os
import pandas as pd
from typing import Dict, List, Any, Optional

class CTIManager:
    def __init__(self, cti_data_path: str = 'data/cti/'):
        self.cti_data_path = cti_data_path
        os.makedirs(self.cti_data_path, exist_ok=True)
        self.mitre_attack_enterprise_url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
        self.mitre_data: Optional[Dict[str, Any]] = None
        self.techniques_df: Optional[pd.DataFrame] = None # DataFrame for easy technique lookup

    def fetch_mitre_attack_data(self, force_download: bool = False) -> Dict[str, Any]:
        """
        Fetches the MITRE ATT&CK Enterprise JSON data.
        Downloads if not found locally or if force_download is True.
        """
        local_path = os.path.join(self.cti_data_path, "enterprise-attack.json")

        if not force_download and os.path.exists(local_path):
            print(f"Loading MITRE ATT&CK data from local file: {local_path}")
            try:
                with open(local_path, 'r', encoding='utf-8') as f:
                    self.mitre_data = json.load(f)
            except json.JSONDecodeError as e:
                print(f"ERROR: Local MITRE ATT&CK JSON file is corrupted or invalid: {e}")
                print("Attempting to re-download.")
                return self.fetch_mitre_attack_data(force_download=True) # Force download if local is bad
        else:
            print(f"Downloading MITRE ATT&CK data from {self.mitre_attack_enterprise_url}...")
            try:
                response = requests.get(self.mitre_attack_enterprise_url)
                response.raise_for_status() # Raise an exception for HTTP errors
                self.mitre_data = response.json()
                with open(local_path, 'w', encoding='utf-8') as f:
                    json.dump(self.mitre_data, f, indent=4)
                print(f"Successfully downloaded and saved MITRE ATT&CK data to {local_path}")
            except requests.exceptions.RequestException as e:
                print(f"Error downloading MITRE ATT&CK data: {e}")
                self.mitre_data = {} # Set to empty dict on failure
        
        return self.mitre_data

    def _parse_mitre_techniques(self) -> pd.DataFrame:
        """
        Parses the loaded MITRE ATT&CK data to extract techniques,
        including their IDs, names, descriptions, tactics, and mitigations.
        Includes extensive debugging.
        """
        if not self.mitre_data:
            print("ERROR: MITRE ATT&CK data not loaded or is empty. Cannot parse techniques.")
            return pd.DataFrame(columns=['id', 'name', 'tactics', 'description', 'url']) # Return empty with columns

        techniques_list = []
        total_objects_count = len(self.mitre_data.get('objects', []))
        print(f"DEBUG: Total objects found in MITRE data: {total_objects_count}")

        parsed_technique_count = 0
        object_types_found = {} # Keep track of object types found for debugging

        for obj in self.mitre_data.get('objects', []):
            obj_type = obj.get('type')
            object_types_found[obj_type] = object_types_found.get(obj_type, 0) + 1

            if obj_type == 'attack-pattern': # CORRECTED: looking for 'attack-pattern'
                parsed_technique_count += 1
                
                external_id = None
                for ref in obj.get('external_references', []):
                    if ref.get('source_name') == 'mitre-attack':
                        external_id = str(ref.get('external_id', '')) # Ensure ID is string
                        break
                
                technique_name = str(obj.get('name', 'Unknown Technique')) # Ensure name is string
                description = str(obj.get('description', 'No description provided.')) # Ensure description is string
                
                raw_tactics_names = []
                for phase in obj.get('kill_chain_phases', []):
                    if phase.get('kill_chain_name') == 'mitre-attack':
                        shortname = phase.get('x_mitre_shortname')
                        if isinstance(shortname, str): # Ensure it's a string
                            raw_tactics_names.append(shortname)
                
                final_tactics_value = ", ".join(raw_tactics_names) # Will be empty string if no tactics

                techniques_list.append({
                    'id': external_id,
                    'name': technique_name,
                    'description': description,
                    'tactics': final_tactics_value,
                    'url': f"https://attack.mitre.org/techniques/{external_id.replace('.', '/')}" if external_id and external_id.startswith('T') else None,
                })
        
        print(f"DEBUG: Found {parsed_technique_count} 'attack-pattern' objects during parsing.")
        print(f"DEBUG: Types of objects found in MITRE data: {object_types_found}")

        if not techniques_list:
            print("WARNING: techniques_list is empty after parsing. This indicates no 'attack-pattern' objects were found or processed successfully.")
            self.techniques_df = pd.DataFrame(columns=['id', 'name', 'tactics', 'description', 'url'])
        else:
            self.techniques_df = pd.DataFrame(techniques_list)
        
        print(f"Parsed {len(self.techniques_df)} MITRE ATT&CK techniques into DataFrame.")
        return self.techniques_df

    def get_techniques_dataframe(self) -> pd.DataFrame:
        """
        Returns the parsed MITRE ATT&CK techniques as a DataFrame.
        Fetches and parses if not already loaded.
        """
        if self.techniques_df is None or self.techniques_df.empty:
            self.fetch_mitre_attack_data() # This will now try to load local, or download if bad/missing
            self._parse_mitre_techniques()
        return self.techniques_df

    def get_technique_by_id(self, technique_id: str) -> Optional[Dict[str, Any]]:
        """
        Looks up a MITRE ATT&CK technique by its ID (e.g., 'T1003').
        """
        if self.techniques_df is None or self.techniques_df.empty:
            self.get_techniques_dataframe() # Ensure data is loaded
        
        # Use .str.contains for partial matches, or .str.fullmatch for exact matches
        if self.techniques_df is not None:
            # Ensure the 'id' column is treated as string for .str.contains
            result = self.techniques_df[self.techniques_df['id'].astype(str).str.contains(technique_id, na=False, case=False)]
            if not result.empty:
                return result.iloc[0].to_dict()
        return None

    # --- Future: IOC Feed Integration ---
    def fetch_ioc_feed(self, url: str, name: str, force_download: bool = False) -> List[str]:
        """
        Fetches a simple text-based IOC feed (e.g., list of IPs or domains).
        """
        local_path = os.path.join(self.cti_data_path, f"{name}.txt")
        iocs = []

        if not force_download and os.path.exists(local_path):
            print(f"Loading IOCs from local file: {local_path}")
            with open(local_path, 'r', encoding='utf-8') as f:
                iocs = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        else:
            print(f"Downloading IOCs from {url}...")
            try:
                response = requests.get(url)
                response.raise_for_status()
                iocs = [line.strip() for line in response.text.splitlines() if line.strip() and not line.startswith('#')]
                with open(local_path, 'w', encoding='utf-8') as f:
                    for ioc in iocs:
                        f.write(ioc + '\n')
                print(f"Successfully downloaded and saved {len(iocs)} IOCs to {local_path}")
            except requests.exceptions.RequestException as e:
                print(f"Error downloading IOCs from {url}: {e}")
        return iocs


# --- Example Usage (for testing this module) ---
if __name__ == "__main__":
    cti_manager = CTIManager()

    print("\n--- Fetching and Parsing MITRE ATT&CK Data ---")
    # Using get_techniques_dataframe will handle the download/load and parsing
    mitre_techniques_df = cti_manager.get_techniques_dataframe()
    
    if not mitre_techniques_df.empty:
        print("\nFirst 5 MITRE ATT&CK Techniques:")
        # Removed the explicit list indexing for print, just use .head() on the df
        print(mitre_techniques_df[['id', 'name', 'tactics']].head()) 
        print(f"Total techniques parsed: {len(mitre_techniques_df)}")
    else:
        print("\nNo MITRE ATT&CK techniques parsed. DataFrame is empty.")


    print(f"\nExample lookup for T1003 (OS Credential Dumping):")
    cred_dumping_tech = cti_manager.get_technique_by_id('T1003')
    if cred_dumping_tech:
        print(f"ID: {cred_dumping_tech['id']}, Name: {cred_dumping_tech['name']}, URL: {cred_dumping_tech['url']}")
    else:
        print("T1003 not found.")

    print("\n--- Fetching a Sample IOC Feed (Malware IPs) ---")
    malware_ip_feed_url = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
    malware_ips = cti_manager.fetch_ioc_feed(malware_ip_feed_url, "feodotracker_ips")
    if malware_ips:
        print(f"Downloaded {len(malware_ips)} malware IPs. First 5: {malware_ips[:5]}")
    else:
        print("Failed to download malware IPs.")