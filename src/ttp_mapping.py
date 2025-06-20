# src/ttp_mapping.py

import os
import yaml
from typing import List, Dict, Any, Optional

from sigma.collection import SigmaCollection
from sigma.rule import SigmaRule  # NEW: Import SigmaRule for individual rule parsing
from sigma.exceptions import SigmaCollectionError


class SigmaRuleLoader:  # Renamed back to SigmaRuleLoader for PySigma version
    def __init__(self, rules_path: str = 'data/sigma_rules/'): # Changed back to sigma_rules
        self.rules_path = rules_path
        os.makedirs(self.rules_path, exist_ok=True)
        self.sigma_collection: Optional[SigmaCollection] = None
        self.loaded_rules: List[Dict[str, Any]] = []

    def _get_rule_files(self) -> List[str]:
        """
        Walks through the rules directory and collects all YAML rule files.
        """
        rule_files = []
        for root, _, files in os.walk(self.rules_path):
            for file in files:
                if file.lower().endswith(('.yml', '.yaml')):
                    rule_files.append(os.path.join(root, file))
        return rule_files

    def load_sigma_rules(self, force_reload: bool = False) -> List[Dict[str, Any]]:
        """
        Loads Sigma rules from the configured rules_path using PySigma.
        Converts them into a simplified dictionary format for hunting.
        """
        if self.sigma_collection and not force_reload:
            print("Sigma rules already loaded. Use force_reload=True to reload.")
            return self.loaded_rules

        rule_files = self._get_rule_files()
        if not rule_files:
            print(f"No Sigma rule files found in: {self.rules_path}. Please add .yml/.yaml files.")
            self.loaded_rules = []
            return self.loaded_rules

        print(f"Loading {len(rule_files)} Sigma rules from {self.rules_path}...")
        
        individual_sigma_rule_objects: List[SigmaRule] = [] # List to hold parsed SigmaRule objects
        for rule_file in rule_files:
            try:
                with open(rule_file, 'r', encoding='utf-8') as f:
                    rule_content_str = f.read()
                    rule = SigmaRule.from_yaml(rule_content_str) # Load individual SigmaRule from YAML content
                    individual_sigma_rule_objects.append(rule)
            except Exception as e:
                print(f"WARNING: Failed to load Sigma rule from {rule_file}: {e}")
        
        if not individual_sigma_rule_objects:
            print("No valid individual Sigma rules were loaded after attempting to parse files.")
            self.loaded_rules = []
            return self.loaded_rules

        try:
            # Create SigmaCollection from the list of individual SigmaRule objects
            self.sigma_collection = SigmaCollection(individual_sigma_rule_objects)
            
            self.loaded_rules = []
            for rule in self.sigma_collection.rules: # Iterate through rules in the collection
                # Extract relevant information from each parsed Sigma rule
                self.loaded_rules.append({
                    'id': rule.id,
                    'title': rule.title,
                    'description': rule.description,
                    'detection': rule.detection.parsed_detection, # Use .parsed_detection to get the dict representation
                    'level': rule.level,
                    'tags': rule.tags,
                    'logsource': rule.logsource.to_dict() if rule.logsource else None,
                    # 'parsed_rule': rule # Can keep reference to the full parsed rule object if needed
                })
            print(f"Successfully loaded and parsed {len(self.loaded_rules)} Sigma rules.")
        except SigmaCollectionError as e:
            print(f"ERROR: Failed to create SigmaCollection from loaded rules: {e}")
            self.loaded_rules = []
        except Exception as e:
            print(f"An unexpected error occurred while creating SigmaCollection: {e}")
            self.loaded_rules = []
            
        return self.loaded_rules

    def get_loaded_rules(self) -> List[Dict[str, Any]]:
        """Returns the list of loaded and simplified Sigma rules."""
        if not self.loaded_rules:
            self.load_sigma_rules()
        return self.loaded_rules

# --- Example Usage (for testing this module) ---
if __name__ == "__main__":
    # Create a dummy Sigma rule directory and file for testing
    dummy_rules_dir = "data/sigma_rules"
    os.makedirs(dummy_rules_dir, exist_ok=True)
    dummy_rule_path = os.path.join(dummy_rules_dir, "proc_creation_powershell_keywords.yml")
    
    # A simple Sigma rule for PowerShell process creation (corresponds to T1059.001)
    # This rule is simplified, real Sigma rules are more complex and target specific event IDs
    dummy_sigma_rule_content = """
title: PowerShell Process Creation Keywords
id: d76a74b1-e2c8-4a92-b437-02b4d96a74b1
status: experimental
description: Detects suspicious PowerShell process creation using keywords.
author: Your Name @YourHandle
date: 2024/06/18
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|contains:
            - 'powershell.exe'
            - 'pwsh.exe'
    condition: selection
tags:
    - attack.execution
    - attack.t1059.001
level: medium
"""
    # Another sample rule for WMIC/Credential Access
    dummy_wmic_rule_path = os.path.join(dummy_rules_dir, "wmic_credential_access.yml")
    dummy_wmic_rule_content = """
title: WMIC usage for Credential Access
id: d1c9b2f3-e4d5-4c67-a89b-01c2d3e4f5a6
status: experimental
description: Detects suspicious WMIC usage potentially related to credential access or system information.
author: Your Name @YourHandle
date: 2024/06/18
logsource:
    category: process_creation
    product: windows
detection:
    selection_wmic:
        Image|endswith:
            - 'wmic.exe'
    selection_keywords:
        CommandLine|contains:
            - 'shadowcopy'
            - 'lsass.exe'
            - 'hash'
    condition: selection_wmic and selection_keywords
tags:
    - attack.collection
    - attack.t1003
    - attack.t1047
level: high
"""


    if not os.path.exists(dummy_rule_path):
        with open(dummy_rule_path, "w") as f:
            f.write(dummy_sigma_rule_content)
        print(f"Generated a sample Sigma PowerShell rule at {dummy_rule_path}")
    if not os.path.exists(dummy_wmic_rule_path):
        with open(dummy_wmic_rule_path, "w") as f:
            f.write(dummy_wmic_rule_content)
        print(f"Generated a sample Sigma WMIC rule at {dummy_wmic_rule_path}")
    
    loader = SigmaRuleLoader(rules_path=dummy_rules_dir)
    loaded_rules = loader.load_sigma_rules(force_reload=True)

    if loaded_rules:
        print(f"\nLoaded Sigma Rules ({len(loaded_rules)} total):")
        for i, rule in enumerate(loaded_rules):
            print(f"  --- Rule {i+1} ---")
            print(f"  ID: {rule['id']}")
            print(f"  Title: {rule['title']}")
            print(f"  Level: {rule['level']}")
            print(f"  Tags: {rule['tags']}")
            print(f"  Logsource: {rule['logsource']}")
            print(f"  Detection Logic (as dict): {rule['detection']}") # Show the parsed dict
    else:
        print("\nNo Sigma rules were loaded.")