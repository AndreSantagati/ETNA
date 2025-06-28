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
                                    field_key = detection_item.field  # e.g., 'Image'
                                        
                                    # Get the operator from the original detection item
                                    # The operator is embedded in the field name in Sigma YAML
                                    # We need to extract it from the original rule field specification
                                    original_operator = None
                                    for original_field in sel_obj.detection_items:
                                        if hasattr(original_field, 'field') and original_field.field == field_key:
                                            # Check if this detection item has modifiers
                                            if hasattr(original_field, 'modifiers') and original_field.modifiers:
                                                # The modifier contains the operator (contains, endswith, etc.)
                                                original_operator = original_field.modifiers[0] if original_field.modifiers else None
                                            break
                                        
                                    # If no operator found, try to get it from field_key if it contains pipe
                                    if not original_operator and '|' in field_key:
                                        parts = field_key.split('|')
                                        field_key = parts[0]  # Remove operator from field name
                                        original_operator = parts[1] if len(parts) > 1 else 'equals'
                                    elif not original_operator:
                                        original_operator = 'equals'  # Default
                                        
                                    value = detection_item.value  # This can be list of SigmaString/tuple/etc.

                                    # Create the combined field|operator key
                                    combined_field_key = f"{field_key}|{original_operator}"

                                    # Process the values correctly
                                    processed_values = []
                                    values_to_process = value if isinstance(value, list) else [value]
                                        
                                    for val_obj in values_to_process:
                                        if isinstance(val_obj, SigmaString):
                                            # For SigmaString, get the plain string without adding wildcards
                                            # The operator will handle the matching logic
                                            plain_string = str(val_obj).strip('*')  # Remove any existing wildcards
                                            processed_values.append(plain_string)
                                        elif isinstance(val_obj, tuple):
                                            # Handle tuples like (<SpecialChars.WILDCARD_MULTI: 1>, 'netstat.exe')
                                            reconstructed_val = ""
                                            for part in val_obj:
                                                if isinstance(part, str):
                                                    reconstructed_val += part
                                                # Skip wildcard indicators - the operator will handle matching
                                            if reconstructed_val:
                                                processed_values.append(reconstructed_val)
                                        else:
                                            # For any other type, convert to string and clean up
                                            str_val = str(val_obj)
                                            # Try to extract the actual string value
                                            import re
                                            matches = re.findall(r"'([^']+)'", str_val)
                                            if matches:
                                                processed_values.extend(matches)
                                            else:
                                                # Clean up the string and remove quotes/wildcards
                                                clean_val = str_val.strip("'\"*")
                                                if clean_val and clean_val not in ['1', 'True', 'False']:
                                                    processed_values.append(clean_val)

                                    if processed_values:  # Only add if we have valid values
                                        selection_conditions_for_field[combined_field_key] = processed_values
                            
                        if selection_conditions_for_field:  # Only add non-empty selections
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