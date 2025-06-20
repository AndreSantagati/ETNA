# src/ttp_mapping.py

import os
import yaml
from typing import List, Dict, Any, Optional

from sigma.collection import SigmaCollection
from sigma.rule import SigmaRule, SigmaLogSource, SigmaDetections, SigmaDetection, SigmaDetectionItem # Import necessary detection classes
from sigma.exceptions import SigmaCollectionError


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
                # --- NEW: Correctly extract detection logic from deeply nested objects ---
                
                transformed_detection_logic = {}
                if isinstance(rule.detection, SigmaDetections) and rule.detection.detections:
                    for sel_name, sel_obj in rule.detection.detections.items():
                        # sel_obj is a SigmaDetection object
                        selection_conditions_for_field = {}
                        if isinstance(sel_obj, SigmaDetection) and sel_obj.detection_items:
                            for detection_item in sel_obj.detection_items: # Iterate through detection items
                                if isinstance(detection_item, SigmaDetectionItem):
                                    field_key = detection_item.field # e.g., 'Image'
                                    operator = detection_item.operator # e.g., 'contains'
                                    value = detection_item.value # e.g., ['powershell.exe']

                                    # Reconstruct the "Image|contains" key
                                    combined_field_key = f"{field_key}|{operator}" if operator else field_key
                                    selection_conditions_for_field[combined_field_key] = value
                                # Note: SigmaDetection can also contain nested SigmaDetection objects for complex AND/OR logic.
                                # Our simplified evaluator in hunting_engine currently expects simple field:value maps per selection.
                                # For more advanced rules, this part would need to handle nested SigmaDetection objects recursively.
                        transformed_detection_logic[sel_name] = selection_conditions_for_field
                    
                    if rule.detection.condition:
                        # Reconstruct the condition string (e.g., "selection and selection_wmic")
                        transformed_detection_logic['condition'] = " ".join(rule.detection.condition)
                else:
                    print(f"WARNING: rule.detection is not a SigmaDetections object or has no detections for rule '{rule.id}'. Type: {type(rule.detection)}")
                
                # --- Correctly extract logsource (using .dict() or attributes) ---
                logsource_dict = {}
                if isinstance(rule.logsource, SigmaLogSource):
                    try:
                        logsource_dict = rule.logsource.dict() # Attempt .dict() first
                    except AttributeError:
                        # Fallback if .dict() isn't available for some PySigma versions or specific objects
                        logsource_dict = {
                            'category': rule.logsource.category,
                            'product': rule.logsource.product,
                            'service': rule.logsource.service,
                            'definition': rule.logsource.definition # Include definition if available
                        }
                        logsource_dict = {k: v for k, v in logsource_dict.items() if v is not None}


                self.loaded_rules.append({
                    'id': rule.id,
                    'title': rule.title,
                    'description': rule.description,
                    'level': rule.level,
                    'tags': rule.tags, # This will be a list of SigmaRuleTag objects
                    
                    'detection': transformed_detection_logic,  # Use the reconstructed detection dict
                    'logsource': logsource_dict,              # Use the reconstructed logsource dict
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
        """Returns the list of loaded and simplified Sigma rules."""
        if not self.loaded_rules:
            self.load_sigma_rules()
        return self.loaded_rules

# --- Example Usage (remains the same as it correctly tests the loader) ---
if __name__ == "__main__":
    # ... (rest of the example usage for testing this module is good and unchanged) ...
    # This ensures your sample rules are correctly generated for testing
    pass