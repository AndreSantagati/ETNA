# src/ttp_mapping.py

import os
import yaml
from typing import List, Dict, Any, Optional

from sigma.collection import SigmaCollection
from sigma.rule import SigmaRule, SigmaLogSource, SigmaDetections, SigmaDetection, SigmaDetectionItem 
from sigma.exceptions import SigmaCollectionError
# Import SpecialChars for explicit handling of raw tuples from detection_item.value
from sigma.types import SigmaString, SigmaNumber, SigmaBool, SigmaRegularExpression, SpecialChars 

class SigmaRuleLoader:
    def __init__(self, rules_path: str = 'data/sigma_rules/'):
        self.rules_path = rules_path
        os.makedirs(self.rules_path, exist_ok=True)
        self.sigma_collection: Optional[SigmaCollection] = None
        self.loaded_rules: List[Dict[str, Any]] = []

    def _get_rule_files(self) -> List[str]:
        rule_files = []
        for root, _, files in os.walk(self.rules_path):
            for file in files:
                if file.lower().endswith(('.yml', '.yaml')):
                    rule_files.append(os.path.join(root, file))
        return rule_files

    def load_sigma_rules(self, force_reload: bool = False) -> List[Dict[str, Any]]:
        if self.sigma_collection and not force_reload:
            print("Sigma rules already loaded. Use force_reload=True to reload.")
            return self.loaded_rules

        rule_files = self._get_rule_files()
        if not rule_files:
            print(f"No Sigma rule files found in: {self.rules_path}. Please add .yml/.yaml files.")
            self.loaded_rules = []
            return self.loaded_rules

        print(f"Loading {len(rule_files)} Sigma rules from {self.rules_path}...")
        
        individual_sigma_rule_objects: List[SigmaRule] = []
        for rule_file in rule_files:
            try:
                with open(rule_file, 'r', encoding='utf-8') as f:
                    rule_content_str = f.read()
                    rule = SigmaRule.from_yaml(rule_content_str)
                    individual_sigma_rule_objects.append(rule)
            except Exception as e:
                print(f"WARNING: Failed to load Sigma rule from {rule_file}: {e}")
        
        if not individual_sigma_rule_objects:
            print("No valid individual Sigma rules were loaded after attempting to parse files.")
            self.loaded_rules = []
            return self.loaded_rules

        try:
            self.sigma_collection = SigmaCollection(individual_sigma_rule_objects)
            
            self.loaded_rules = []
            for rule in self.sigma_collection.rules:
                transformed_detection_logic = {}
                if isinstance(rule.detection, SigmaDetections) and rule.detection.detections:
                    for sel_name, sel_obj in rule.detection.detections.items():
                        selection_conditions_for_field = {}
                        
                        if isinstance(sel_obj, SigmaDetection) and sel_obj.detection_items:
                            for detection_item in sel_obj.detection_items:
                                if isinstance(detection_item, SigmaDetectionItem):
                                    field_key = detection_item.field # e.g., 'Image'
                                    operator = detection_item.operator # e.g., 'contains', 'endswith', or None
                                    value = detection_item.value # This can be list of SigmaString/tuple/etc.

                                    # --- NEW: Reconstruct Pattern String and Operator ---
                                    
                                    # Determine the operator to use in the combined key
                                    # If detection_item.operator is None, it defaults to 'equals' in Sigma context
                                    # However, our sample rules explicitly use 'Image|contains' so operator should be a string.
                                    # If operator is still None/empty for rules like 'Image|contains', it means PySigma's parsing of that is implicit.
                                    # Let's map implicitly to 'contains' for keywords if operator is missing and it's a string value.
                                    effective_operator = operator if operator else 'equals'
                                    if not effective_operator and isinstance(value, (str, list)): # Fallback for contains if operator is absent for literal strings
                                        effective_operator = 'contains' 

                                    # Reconstruct the "field|operator" key for hunting_engine
                                    combined_field_key = f"{field_key}|{effective_operator}" # Always include operator

                                    # Extract raw string value from various PySigma value types
                                    processed_values = []
                                    values_to_process = value if isinstance(value, list) else [value]

                                    for val_obj in values_to_process:
                                        if isinstance(val_obj, SigmaString):
                                            # SigmaString objects contain the actual string with wildcards
                                            pattern_str = str(val_obj)
                                            processed_values.append(pattern_str)
                                        elif isinstance(val_obj, SigmaRegularExpression):
                                            processed_values.append(str(val_obj))
                                        elif isinstance(val_obj, tuple):
                                            # Handle tuples like (<SpecialChars.WILDCARD_MULTI: 1>, 'netstat.exe')
                                            reconstructed_val = ""
                                            for part in val_obj:
                                                if hasattr(part, 'name') and 'WILDCARD' in str(part.name):
                                                    reconstructed_val += "*"
                                                elif isinstance(part, str):
                                                    reconstructed_val += part
                                                elif str(part) == "1":  # Skip numeric wildcard indicators
                                                    pass
                                            processed_values.append(reconstructed_val)
                                        elif hasattr(val_obj, '__iter__') and not isinstance(val_obj, str):
                                            # Handle other iterable objects
                                            for sub_val in val_obj:
                                                if isinstance(sub_val, str):
                                                    processed_values.append(sub_val)
                                        else:
                                            # For any other type, convert to string and try to extract useful parts
                                            str_val = str(val_obj)
                                            # Try to extract strings from representations like "('netstat.exe',)"
                                            import re
                                            matches = re.findall(r"'([^']+)'", str_val)
                                            if matches:
                                                for match in matches:
                                                    processed_values.append(match)
                                            else:
                                                processed_values.append(str_val)

                                    selection_conditions_for_field[combined_field_key] = processed_values
                            transformed_detection_logic[sel_name] = selection_conditions_for_field
                    
                    if rule.detection.condition:
                        transformed_detection_logic['condition'] = " ".join(rule.detection.condition)
                else:
                    print(f"WARNING: rule.detection is not a SigmaDetections object or has no detections for rule '{rule.id}'. Type: {type(rule.detection)}")
                
                # --- Correctly extract logsource (using .dict() or attributes) ---
                logsource_dict = {}
                if isinstance(rule.logsource, SigmaLogSource):
                    try:
                        logsource_dict = rule.logsource.dict() # Attempt .dict() first
                    except AttributeError:
                        logsource_dict = {
                            'category': rule.logsource.category,
                            'product': rule.logsource.product,
                            'service': rule.logsource.service,
                            'definition': getattr(rule.logsource, 'definition', None)
                        }
                        logsource_dict = {k: v for k, v in logsource_dict.items() if v is not None}
                else:
                    print(f"WARNING: rule.logsource is not a SigmaLogSource object for rule '{rule.id}'. Type: {type(rule.logsource)}")


                self.loaded_rules.append({
                    'id': rule.id,
                    'title': rule.title,
                    'description': rule.description,
                    'level': rule.level,
                    'tags': rule.tags, 
                    'detection': transformed_detection_logic,  
                    'logsource': logsource_dict,              
                })
            print(f"Successfully loaded and parsed {len(self.loaded_rules)} Sigma rules.")
        except SigmaCollectionError as e:
            print(f"ERROR: Failed to create SigmaCollection from loaded rules: {e}")
            self.loaded_rules = []
        except Exception as e:
            print(f"An unexpected error occurred while creating SigmaCollection: {e}. Check rule YAMLs.")
            self.loaded_rules = []
            
        return self.loaded_rules

    def get_loaded_rules(self) -> List[Dict[str, Any]]:
        if not self.loaded_rules:
            self.load_sigma_rules()
        return self.loaded_rules

# --- Example Usage (remains the same) ---
if __name__ == "__main__":
    # ... (code to generate sample rules, unchanged) ...
    pass