import os
import yaml
from typing import List, Dict, Any, Optional

from sigma.collection import SigmaCollection
from sigma.rule import SigmaRule
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
                self.loaded_rules.append({
                    'id': rule.id,
                    'title': rule.title,
                    'description': rule.description,
                    'level': rule.level,
                    'tags': rule.tags,
                    
                    # NEW: Accessing detection and logsource directly from rule.data
                    'detection': rule.data.get('detection'), 
                    'logsource': rule.data.get('logsource'),
                    
                    # 'parsed_rule': rule # Keep reference to the full parsed rule object if needed
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
        if not self.loaded_rules:
            self.load_sigma_rules()
        return self.loaded_rules

# --- Example Usage (for testing this module) ---
if __name__ == "__main__":
    dummy_rules_dir = "data/sigma_rules"
    os.makedirs(dummy_rules_dir, exist_ok=True)
    dummy_rule_path = os.path.join(dummy_rules_dir, "proc_creation_powershell_keywords.yml")
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
            print(f"  Detection Logic (as dict): {rule['detection']}")
    else:
        print("\nNo Sigma rules were loaded.")