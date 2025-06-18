# src/ttp_mapping.py

import os
import yaml
from typing import List, Dict, Any, Optional
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaCollectionError

class SigmaRuleLoader:
    def __init__(self, rules_path: str = 'data/sigma_rules/'):
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
        try:
            # PySigma can load directly from a list of file paths
            self.sigma_collection = SigmaCollection.from_files(rule_files)
            
            self.loaded_rules = []
            for rule in self.sigma_collection.rules:
                # Extract relevant information from each parsed Sigma rule
                self.loaded_rules.append({
                    'id': rule.id,
                    'title': rule.title,
                    'description': rule.description,
                    'detection': rule.detection, # This is the parsed detection logic
                    'level': rule.level,
                    'tags': rule.tags, # MITRE ATT&CK tags should be here
                    'logsource': rule.logsource.to_dict() if rule.logsource else None,
                    'parsed_rule': rule # Keep reference to the full parsed rule object if needed
                })
            print(f"Successfully loaded and parsed {len(self.loaded_rules)} Sigma rules.")
        except SigmaCollectionError as e:
            print(f"ERROR: Failed to load Sigma rules from {self.rules_path}: {e}")
            self.loaded_rules = []
        except Exception as e:
            print(f"An unexpected error occurred while loading Sigma rules: {e}")
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
    if not os.path.exists(dummy_rule_path):
        with open(dummy_rule_path, "w") as f:
            f.write(dummy_sigma_rule_content)
        print(f"Generated a sample Sigma rule at {dummy_rule_path}")
    
    loader = SigmaRuleLoader(rules_path=dummy_rules_dir)
    loaded_rules = loader.load_sigma_rules(force_reload=True)

    if loaded_rules:
        print("\nLoaded Sigma Rules (first 1):")
        for rule in loaded_rules[:1]:
            print(f"  ID: {rule['id']}")
            print(f"  Title: {rule['title']}")
            print(f"  Level: {rule['level']}")
            print(f"  Tags: {rule['tags']}")
            print(f"  Logsource: {rule['logsource']}")
            # print(f"  Detection Logic (PySigma object): {rule['detection']}") # For deeper inspection
    else:
        print("\nNo Sigma rules were loaded.")