# src/hunting_engine.py

import pandas as pd
import os
import re

from src.log_parser import LogParserFactory, NORMALIZED_LOG_SCHEMA
from src.cti_integration import CTIManager
from src.ttp_mapping import SigmaRuleLoader # IMPORT SigmaRuleLoader again
from typing import Dict, List, Any

class ThreatHuntingEngine:
    def __init__(self, cti_manager: CTIManager, sigma_rule_loader: SigmaRuleLoader): # Pass SigmaRuleLoader
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
        This handles 'selection' and basic 'condition' logic (AND/OR of selections).
        It expects detection_logic to be the dictionary from rule.detection.parsed_detection.
        """
        selections = {}
        for sel_name, sel_conditions in detection_logic.items():
            if sel_name == 'condition': # Skip the 'condition' string itself for now
                continue

            selection_match = True # Assume AND logic within a selection
            if isinstance(sel_conditions, dict):
                for field_key, patterns in sel_conditions.items():
                    # Handle specific Sigma syntax: e.g., 'Image|contains'
                    field_name = field_key.split('|')[0]
                    operator = field_key.split('|')[1] if '|' in field_key else 'equals' # Default to equals
                    
                    if field_name not in log_entry.index or pd.isna(log_entry[field_name]):
                        selection_match = False # Field not present in log or is NaN/None
                        break

                    log_value = str(log_entry[field_name]).lower()

                    if isinstance(patterns, str):
                        patterns = [patterns] # Normalize to list for consistent iteration

                    if isinstance(patterns, list): # OR logic within patterns list
                        pattern_match_found = False
                        for pattern in patterns:
                            pat_lower = str(pattern).lower()
                            if operator == 'contains' or operator == 'endswith' or operator == 'startswith' or operator == 'equals':
                                # Basic contains, starts/ends with, for 'Image|contains' etc.
                                if '*' in pat_lower: # Handle wildcards in pattern
                                    pat_regex = pat_lower.replace('*', '.*')
                                    if re.search(pat_regex, log_value):
                                        pattern_match_found = True
                                        break
                                elif operator == 'contains' and pat_lower in log_value:
                                    pattern_match_found = True
                                    break
                                elif operator == 'startswith' and log_value.startswith(pat_lower):
                                    pattern_match_found = True
                                    break
                                elif operator == 'endswith' and log_value.endswith(pat_lower):
                                    pattern_match_found = True
                                    break
                                elif operator == 'equals' and log_value == pat_lower: # For exact equals
                                    pattern_match_found = True
                                    break
                            # Add more operators as needed (e.g., 'all', 're', 'lt', 'gt')
                        if not pattern_match_found:
                            selection_match = False
                            break
                    else: # Invalid pattern format in Sigma rule
                        selection_match = False
                        break
                selections[sel_name] = selection_match # Store result of this selection
            else: # If sel_conditions is not a dict (e.g., 'condition' string itself)
                selections[sel_name] = False # Treat as non-match for this simplified parser

        # Evaluate the main condition (e.g., "selection", "selection_wmic and selection_keywords")
        main_condition_str = detection_logic.get('condition', '').lower()
        if not main_condition_str:
            return False # No condition, no match

        # Simplified condition evaluation: replace selection names with their boolean results
        # This is a very basic eval, vulnerable to complex logic/injection if not careful
        # For simple 'selection' or 'sel1 and sel2' it's fine.
        try:
            # Replace selection names like 'selection' with their boolean result from 'selections' dict
            evaluated_condition = main_condition_str
            for sel_name, sel_val in selections.items():
                evaluated_condition = evaluated_condition.replace(sel_name, str(sel_val))

            # Use eval for simple boolean logic (e.g., "True and False")
            return eval(evaluated_condition)
        except Exception as e:
            print(f"WARNING: Could not evaluate Sigma rule condition '{main_condition_str}': {e}. Skipping rule.")
            return False


    def _apply_hunting_rules(self, logs_df: pd.DataFrame) -> pd.DataFrame:
        """
        Applies loaded Sigma rules to the logs DataFrame.
        """
        hunting_findings = []

        # Ensure all columns needed by Sigma rules are strings and filled
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
                rule_tags = sigma_rule.get('tags', [])
                rule_level = sigma_rule.get('level', 'informational')
                
                mitre_tech_id = None
                for tag in rule_tags:
                    if tag.startswith('attack.t'):
                        parts = tag.split('.')
                        if len(parts) >= 2 and parts[1].startswith('t'):
                            mitre_tech_id = parts[1].upper()
                            break
                
                if self._evaluate_sigma_condition(log_entry, rule_detection_logic):
                    # Found a match!
                    finding = log_entry.to_dict()
                    finding.update({
                        'hunting_rule_id': rule_id,
                        'hunting_rule_title': rule_title,
                        'mitre_technique_id': mitre_tech_id,
                        'mitre_technique_name': None,
                        'mitre_technique_url': None,
                        'risk_score': 0,
                        'rule_level': rule_level
                    })

                    # Enrich with MITRE ATT&CK details
                    if mitre_tech_id:
                        tech_details = self.cti_manager.get_technique_by_id(mitre_tech_id)
                        if tech_details:
                            finding['mitre_technique_name'] = tech_details['name']
                            finding['mitre_technique_url'] = tech_details['url']
                            # Simple risk scoring based on Sigma level (can be refined)
                            if rule_level == 'critical': finding['risk_score'] = 100
                            elif rule_level == 'high': finding['risk_score'] = 90
                            elif rule_level == 'medium': finding['risk_score'] = 70
                            elif rule_level == 'low': finding['risk_score'] = 40
                            else: finding['risk_score'] = 20

                    hunting_findings.append(finding)
        
        findings_df = pd.DataFrame(hunting_findings)
        
        output_cols_order = [
            'timestamp', 'hostname', 'username', 'process_name',
            'hunting_rule_id', 'hunting_rule_title', 'rule_level',
            'mitre_technique_id', 'mitre_technique_name', 
            'risk_score', 'mitre_technique_url',
            'event_id', 'message', 'source_ip', 'destination_ip', 'action'
        ]
        
        for col in output_cols_order:
            if col not in findings_df.columns:
                findings_df[col] = None
        
        findings_df = findings_df[output_cols_order]
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
            return pd.DataFrame(columns=list(NORMALIZED_LOG_SCHEMA.keys()))
        except ValueError as e:
            print(f"Error parsing log file: {e}")
            return pd.DataFrame(columns=list(NORMALIZED_LOG_SCHEMA.keys()))

        if normalized_logs_df.empty:
            print("No logs to hunt in (DataFrame is empty after parsing). Exiting hunt.")
            return pd.DataFrame(columns=list(NORMALIZED_LOG_SCHEMA.keys()))

        print(f"Hunting across {len(normalized_logs_df)} normalized log entries...")
        
        findings_df = self._apply_hunting_rules(normalized_logs_df)
        
        print(f"Hunt complete. Found {len(findings_df)} potential findings.")
        return findings_df