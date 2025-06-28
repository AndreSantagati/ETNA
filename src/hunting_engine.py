# src/hunting_engine.py

import pandas as pd
import os
import re

from src.log_parser import LogParserFactory, NORMALIZED_LOG_SCHEMA
from src.cti_integration import CTIManager
from src.ttp_mapping import SigmaRuleLoader
from typing import Dict, List, Any
from sigma.rule import SigmaRuleTag 
# No longer explicitly importing SigmaString etc. here, as ttp_mapping should have converted them to strings


class ThreatHuntingEngine:
    def __init__(self, cti_manager: CTIManager, sigma_rule_loader: SigmaRuleLoader):
        self.cti_manager = cti_manager
        self.sigma_rule_loader = sigma_rule_loader
        
        self.mitre_techniques_df = self.cti_manager.get_techniques_dataframe()
        self.sigma_rules = self.sigma_rule_loader.get_loaded_rules()

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
        """
        selections = {}
        
        main_condition_str = detection_logic.get('condition', 'False').lower() 

        print(f"\nDEBUG_EVAL: Evaluating log_entry (Process: {log_entry['process_name']}, Message: '{log_entry['message']}')")
        print(f"DEBUG_EVAL: Rule Detection Logic Keys: {list(detection_logic.keys())}")

        for sel_name, sel_conditions_map in detection_logic.items():
            if sel_name == 'condition': 
                continue

            print(f"DEBUG_EVAL:   Processing Selection: '{sel_name}'")
            print(f"DEBUG_EVAL:   Selection content: {sel_conditions_map}")
            
            selection_match_overall = True 
            
            if isinstance(sel_conditions_map, dict):
                for field_key_operator, patterns in sel_conditions_map.items():
                    parts = field_key_operator.split('|', 1)
                    field_name_raw = parts[0]
                    operator_raw = parts[1] if len(parts) > 1 else 'equals'

                    # Map common Sigma fields to our normalized log fields
                    log_field_name = field_name_raw
                    if field_name_raw.lower() == 'image':
                        log_field_name = 'process_name'
                    elif field_name_raw.lower() == 'commandline':
                        log_field_name = 'message'

                    print(f"DEBUG_EVAL:     Field: '{field_name_raw}' (mapped to '{log_field_name}') | Operator: '{operator_raw}'")
                    print(f"DEBUG_EVAL:     Raw patterns: {patterns}")
                    print(f"DEBUG_EVAL:     Pattern types: {[type(p) for p in patterns] if isinstance(patterns, list) else type(patterns)}")

                    if log_field_name not in log_entry.index or pd.isna(log_entry[log_field_name]):
                        print(f"DEBUG_EVAL:       Field '{log_field_name}' not in log entry or is NaN. Selection FAILED.")
                        selection_match_overall = False 
                        break

                    log_value = str(log_entry[log_field_name]).lower()
                    print(f"DEBUG_EVAL:       Log Value for '{log_field_name}': '{log_value}'")

                    if not isinstance(patterns, list): 
                        patterns = [patterns] 

                    pattern_match_found_for_field = False
                    for pattern_str_val in patterns:
                        pat_lower = str(pattern_str_val).lower()
                        
                        print(f"DEBUG_EVAL:         Trying pattern: '{pat_lower}' with operator '{operator_raw}'")
                        
                        # Apply operator logic
                        if operator_raw == 'contains':
                            if '*' in pat_lower:
                                try:
                                    pat_regex = re.escape(pat_lower).replace(r'\*', '.*')
                                    if re.search(pat_regex, log_value):
                                        pattern_match_found_for_field = True
                                        print(f"DEBUG_EVAL:         ✓ MATCH found with regex pattern!")
                                        break
                                except re.error as regex_err:
                                    print(f"WARNING: Invalid regex pattern '{pat_lower}': {regex_err}")
                            elif pat_lower in log_value:
                                pattern_match_found_for_field = True
                                print(f"DEBUG_EVAL:         ✓ MATCH found with contains!")
                                break
                        
                        elif operator_raw == 'startswith':
                            if log_value.startswith(pat_lower): 
                                pattern_match_found_for_field = True
                                print(f"DEBUG_EVAL:         ✓ MATCH found with startswith!")
                                break

                        elif operator_raw == 'endswith':
                            if log_value.endswith(pat_lower): 
                                pattern_match_found_for_field = True
                                print(f"DEBUG_EVAL:         ✓ MATCH found with endswith!")
                                break

                        elif operator_raw == 'equals':
                            if log_value == pat_lower: 
                                pattern_match_found_for_field = True
                                print(f"DEBUG_EVAL:         ✓ MATCH found with equals!")
                                break

                    if not pattern_match_found_for_field:
                        print(f"DEBUG_EVAL:       Pattern match FAILED for field '{log_field_name}'.")
                        selection_match_overall = False
                        break
                    else:
                        print(f"DEBUG_EVAL:       Pattern match SUCCESS for field '{log_field_name}'.")

            else:
                print(f"DEBUG_EVAL:   Selection '{sel_name}' has invalid conditions map. Selection FAILED.")
                selection_match_overall = False 

            selections[sel_name] = selection_match_overall 
            print(f"DEBUG_EVAL:   Result for Selection '{sel_name}': {selection_match_overall}")

        # Evaluate the main condition string
        print(f"DEBUG_EVAL: All Selections Results: {selections}")
        print(f"DEBUG_EVAL: Main Condition String: '{main_condition_str}'")
        
        try:
            evaluated_condition = main_condition_str
            for sel_name, sel_val in selections.items():
                evaluated_condition = re.sub(r'\b' + re.escape(sel_name) + r'\b', str(sel_val), evaluated_condition)

            print(f"DEBUG_EVAL: Evaluated Condition String: '{evaluated_condition}'")
            final_result = eval(evaluated_condition)
            print(f"DEBUG_EVAL: FINAL RULE EVALUATION RESULT: {final_result}\n")
            return final_result
        except Exception as e:
            print(f"WARNING: Could not evaluate Sigma rule condition expression '{main_condition_str}': {e}")
            return False

    def _apply_hunting_rules(self, logs_df: pd.DataFrame) -> pd.DataFrame:
        """
        Applies loaded Sigma rules to the logs DataFrame.
        """
        hunting_findings = []

        # Ensure all columns potentially needed by Sigma rules are strings and filled
        # Map Sigma 'Image' to 'process_name' and 'CommandLine' to 'message' based on our sample logs
        for col in ['process_name', 'event_id', 'message', 'source_ip', 'destination_ip', 'hostname', 'username']:
            if col not in logs_df.columns:
                logs_df[col] = None
            logs_df[col] = logs_df[col].astype(str).fillna('')

        if not self.sigma_rules:
            print("No Sigma rules available to apply.")
            return pd.DataFrame()

        print(f"Applying {len(self.sigma_rules)} Sigma rules to logs...")

        for _, log_entry in logs_df.iterrows():
            for sigma_rule in self.sigma_rules:
                rule_id = sigma_rule['id']
                rule_title = sigma_rule['title']
                rule_detection_logic = sigma_rule['detection'] # This is now the correctly reconstructed dict from ttp_mapping
                rule_tags = sigma_rule.get('tags', []) # This is now a list of SigmaRuleTag objects
                rule_level = sigma_rule.get('level', 'informational')
                
                mitre_tech_id = None
                # CORRECTED: Access tag.name attribute for SigmaRuleTag objects
                for tag_obj in rule_tags: # Iterate through SigmaRuleTag objects
                    if isinstance(tag_obj, SigmaRuleTag) and hasattr(tag_obj, 'name'):
                        tag_name_str = str(tag_obj.name) # Get the string name from the object
                        if tag_name_str.startswith('attack.t'):
                            parts = tag_name_str.split('.')
                            if len(parts) >= 2 and parts[1].startswith('t'):
                                mitre_tech_id = parts[1].upper() # T1059.001 -> T1059.001
                                break
                    # Else, if it's not a SigmaRuleTag or has no name, skip it
                
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