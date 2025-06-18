# src/hunting_engine.py

import pandas as pd
import os
import re # We'll need regex for matching Sigma rule patterns

from src.log_parser import LogParserFactory, NORMALIZED_LOG_SCHEMA
from src.cti_integration import CTIManager
from src.ttp_mapping import SigmaRuleLoader # Import our SigmaRuleLoader
from typing import Dict, List, Any

class ThreatHuntingEngine:
    def __init__(self, cti_manager: CTIManager, sigma_rule_loader: SigmaRuleLoader):
        self.cti_manager = cti_manager
        self.sigma_rule_loader = sigma_rule_loader # Store the Sigma rule loader
        
        self.mitre_techniques_df = self.cti_manager.get_techniques_dataframe()
        self.sigma_rules = self.sigma_rule_loader.get_loaded_rules() # Load Sigma rules here

        if self.mitre_techniques_df.empty:
            print("WARNING: MITRE ATT&CK techniques DataFrame is empty. Hunting rules may not find matches.")
        else:
            print(f"Hunting Engine initialized with {len(self.mitre_techniques_df)} MITRE ATT&CK techniques.")
        
        if not self.sigma_rules:
            print("WARNING: No Sigma rules loaded. Hunting engine will not perform rule-based detections.")
        else:
            print(f"Hunting Engine loaded {len(self.sigma_rules)} Sigma rules.")


    def _evaluate_sigma_condition(self, log_entry: pd.Series, detection_logic: Dict[str, Any]) -> bool:
        """
        Evaluates a simplified Sigma detection logic against a single log entry.
        NOTE: This is a highly simplified interpreter for demonstration.
              A full PySigma backend would be more robust.
        """
        # Simplistic handling of 'selection' and 'condition' (AND/OR logic)
        # Assumes 'condition: selection' or 'condition: selection1 and selection2' etc.
        # This implementation will handle basic 'selection' dictionaries with string/list matching.

        if 'selection' in detection_logic:
            selection_dict = detection_logic['selection']
            match_found = True # Assume AND logic between selection fields initially

            for field, patterns in selection_dict.items():
                if field not in log_entry.index or pd.isna(log_entry[field]):
                    match_found = False # Field not present in log or is NaN/None
                    break

                log_value = str(log_entry[field]).lower() # Convert log value to string for matching

                if isinstance(patterns, str): # Single string pattern
                    # Check if the pattern is in the log value
                    if patterns.startswith('*') and patterns.endswith('*'):
                        # Wildcard match (e.g., *powershell*)
                        if patterns[1:-1].lower() not in log_value:
                            match_found = False
                            break
                    elif patterns.endswith('*'):
                        # Starts with match (e.g., powershell*)
                        if not log_value.startswith(patterns[:-1].lower()):
                            match_found = False
                            break
                    elif patterns.startswith('*'):
                        # Ends with match (e.g., *powershell)
                        if not log_value.endswith(patterns[1:].lower()):
                            match_found = False
                            break
                    else: # Exact match or contains
                        if patterns.lower() not in log_value: # Simplified to 'contains' for non-exact
                            match_found = False
                            break
                elif isinstance(patterns, list): # List of patterns (OR logic within list)
                    list_match_found = False
                    for pattern in patterns:
                        if isinstance(pattern, str):
                            if pattern.startswith('*') and pattern.endswith('*'):
                                if pattern[1:-1].lower() in log_value:
                                    list_match_found = True
                                    break
                            elif pattern.endswith('*'):
                                if log_value.startswith(pattern[:-1].lower()):
                                    list_match_found = True
                                    break
                            elif pattern.startswith('*'):
                                if log_value.endswith(pattern[1:].lower()):
                                    list_match_found = True
                                    break
                            else:
                                if pattern.lower() in log_value: # Simplified to 'contains'
                                    list_match_found = True
                                    break
                    if not list_match_found:
                        match_found = False
                        break
                # Add more complex Sigma features like regex, not, all, etc. here if needed
                # For this MVP, we're simplifying.
            return match_found
        
        # If no explicit selection logic, consider it not matched for now
        return False

    def _apply_hunting_rules(self, logs_df: pd.DataFrame) -> pd.DataFrame:
        """
        Applies loaded Sigma rules to the logs DataFrame.
        """
        hunting_findings = []

        # Ensure all columns needed by Sigma rules are strings or handled
        for col in ['process_name', 'event_id', 'message', 'source_ip', 'destination_ip', 'hostname', 'username']:
            if col not in logs_df.columns:
                logs_df[col] = None # Add missing columns
            logs_df[col] = logs_df[col].astype(str).fillna('') # Convert to string, fill NaN with empty string

        if not self.sigma_rules:
            print("No Sigma rules available to apply.")
            return pd.DataFrame()

        print(f"Applying {len(self.sigma_rules)} Sigma rules to logs...")

        for _, log_entry in logs_df.iterrows():
            for sigma_rule in self.sigma_rules:
                rule_id = sigma_rule['id']
                rule_title = sigma_rule['title']
                rule_detection_logic = sigma_rule['detection']
                rule_tags = sigma_rule.get('tags', []) # Get tags for MITRE mapping
                rule_level = sigma_rule.get('level', 'informational')
                
                # Try to map Sigma rule tags to MITRE ATT&CK techniques
                mitre_tech_id = None
                for tag in rule_tags:
                    if tag.startswith('attack.t'): # Example: 'attack.t1059.001'
                        # Clean the tag to get just the technique ID (e.g., 'T1059.001')
                        parts = tag.split('.')
                        if len(parts) >= 2 and parts[1].startswith('t'):
                            mitre_tech_id = parts[1].upper().replace('T', 'T') # Ensure consistent T-id format
                            break
                
                # Attempt to evaluate the rule logic against the log entry
                # This is a very simplified interpreter. A real one would use PySigma's backend.
                if self._evaluate_sigma_condition(log_entry, rule_detection_logic):
                    # Found a match!
                    finding = log_entry.to_dict()
                    finding.update({
                        'hunting_rule_id': rule_id,
                        'hunting_rule_title': rule_title,
                        'mitre_technique_id': mitre_tech_id,
                        'mitre_technique_name': None, # Will fill this from CTI later
                        'mitre_technique_url': None, # Will fill this from CTI later
                        'risk_score': 0, # Default, can be set based on Sigma rule level
                        'rule_level': rule_level
                    })

                    # Enrich with MITRE ATT&CK details if a technique ID was found
                    if mitre_tech_id:
                        tech_details = self.cti_manager.get_technique_by_id(mitre_tech_id)
                        if tech_details:
                            finding['mitre_technique_name'] = tech_details['name']
                            finding['mitre_technique_url'] = tech_details['url']
                            # Simple risk scoring based on Sigma level
                            if rule_level == 'critical': finding['risk_score'] = 100
                            elif rule_level == 'high': finding['risk_score'] = 90
                            elif rule_level == 'medium': finding['risk_score'] = 70
                            elif rule_level == 'low': finding['risk_score'] = 40
                            else: finding['risk_score'] = 20 # informational, experimental etc.

                    hunting_findings.append(finding)
        
        # Convert findings list to DataFrame
        findings_df = pd.DataFrame(hunting_findings)
        
        # Define the desired output columns for findings
        output_cols_order = [
            'timestamp', 'hostname', 'username', 'process_name',
            'hunting_rule_id', 'hunting_rule_title', 'rule_level',
            'mitre_technique_id', 'mitre_technique_name', 
            'risk_score', 'mitre_technique_url',
            'event_id', 'message', 'source_ip', 'destination_ip', 'action'
        ]
        
        # Ensure all expected output columns are present and in order
        for col in output_cols_order:
            if col not in findings_df.columns:
                findings_df[col] = None # Add missing columns with None
        
        # Filter and reorder DataFrame columns
        findings_df = findings_df[output_cols_order]
        
        # Remove duplicate findings if the same log entry triggers multiple rules or same rule multiple times for simplicity
        findings_df.drop_duplicates(inplace=True) 

        return findings_df

    def hunt(self, log_path: str) -> pd.DataFrame:
        """
        Executes the threat hunt against a given log file.
        """
        print(f"\n--- Starting Threat Hunt for logs from: {log_path} ---")
        try:
            parser = LogParserFactory.get_parser(log_path)
            normalized_logs_df = parser.parse()
        except FileNotFoundError:
            print(f"Error: Log file not found at {log_path}. Please check the path.")
            return pd.DataFrame(columns=NORMALIZED_LOG_SCHEMA.keys()) # Return empty df
        except ValueError as e:
            print(f"Error parsing log file: {e}")
            return pd.DataFrame(columns=NORMALIZED_LOG_SCHEMA.keys()) # Return empty df

        if normalized_logs_df.empty:
            print("No logs to hunt in (DataFrame is empty after parsing). Exiting hunt.")
            return pd.DataFrame(columns=NORMALIZED_LOG_SCHEMA.keys()) # Return empty df

        print(f"Hunting across {len(normalized_logs_df)} normalized log entries...")
        
        findings_df = self._apply_hunting_rules(normalized_logs_df)
        
        print(f"Hunt complete. Found {len(findings_df)} potential findings.")
        return findings_df

