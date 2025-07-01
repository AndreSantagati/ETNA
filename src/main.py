# src/main.py
"""
ETNA - Enhanced Threat Network Analysis
Sicilian-inspired automated threat hunting platform.
"""

from src.hunting_engine import ThreatHuntingEngine
from src.cti_integration import EnhancedCTIManager
from src.log_parser import NORMALIZED_LOG_SCHEMA
from src.ttp_mapping import SigmaRuleLoader # IMPORT THE SigmaRuleLoader AGAIN
from src.reporting import ThreatHuntingReporter
import os
import pandas as pd

if __name__ == "__main__":
    # --- Configuration ---
    sample_log_file = "data/logs/sample_log.csv"
    sigma_rules_dir = "data/sigma_rules/" # Use the sigma rules directory
    output_dir = "output/"

    # --- Ensure sample log file exists (for testing) ---
    if not os.path.exists(sample_log_file):
        with open(sample_log_file, "w") as f:
            f.write("TimeCreated,ComputerName,UserName,ProcessName,EventID,SourceIpAddress,DestinationIpAddress,EventData,Action\n")  # Added Action
            f.write("2024-06-17 10:00:00,HOST-01,user1,powershell.exe,4104,192.168.1.10,8.8.8.8,Process started,executed\n")
            f.write("2024-06-17 10:05:00,HOST-02,admin,cmd.exe,4688,10.0.0.5,192.168.1.1,Account logon,logon\n")
            f.write("2024-06-17 10:10:00,HOST-01,user1,calc.exe,4688,,,User opened calculator,executed\n")
            f.write("2024-06-17 10:15:00,HOST-03,guest,explorer.exe,4624,172.16.0.1,172.16.0.10,Successful logon,logon\n")
            f.write("2024-06-17 10:20:00,HOST-01,user1,netstat.exe,4688,,,netstat -an,executed\n")
            f.write("2024-06-17 10:25:00,HOST-04,admin,wmic.exe,4688,,,wmic process list shadowcopy,executed\n")
            f.write("2024-06-17 10:30:00,HOST-02,attacker,powershell.exe,4688,192.168.1.50,1.2.3.4,powershell.exe -enc base64content,executed\n")
            f.write("2024-06-17 10:35:00,HOST-05,user2,pwsh.exe,4688,,,pwsh -Command Get-Process,executed\n")
        print(f"Generated enhanced sample CSV log file at {sample_log_file}")

    # --- Ensure Sigma rules exist (for testing) ---
    os.makedirs(sigma_rules_dir, exist_ok=True)
    
    # PowerShell Rule (same as before)
    powershell_rule_path = os.path.join(sigma_rules_dir, "proc_creation_powershell_keywords.yml")
    powershell_rule_content = """
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
    if not os.path.exists(powershell_rule_path):
        with open(powershell_rule_path, "w") as f:
            f.write(powershell_rule_content)
        print(f"Generated a sample Sigma PowerShell rule at {powershell_rule_path}")
    
    # WMIC Rule (same as before)
    wmic_rule_path = os.path.join(sigma_rules_dir, "wmic_credential_access.yml")
    wmic_rule_content = """
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
    if not os.path.exists(wmic_rule_path):
        with open(wmic_rule_path, "w") as f:
            f.write(wmic_rule_content)
        print(f"Generated a sample Sigma WMIC rule at {wmic_rule_path}")

    # Netstat Rule (from previous discussions, added for better testing)
    netstat_rule_path = os.path.join(sigma_rules_dir, "netstat_discovery.yml")
    netstat_rule_content = """
title: Network Connections Discovery via Netstat
id: e2b3c4d5-f6a7-8b9c-0d1e-2f3a4b5c6d7e
status: experimental
description: Detects usage of netstat for network connection enumeration.
author: Your Name @YourHandle
date: 2024/06/18
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - 'netstat.exe'
    condition: selection
tags:
    - attack.discovery
    - attack.t1049
level: low
"""
    if not os.path.exists(netstat_rule_path):
        with open(netstat_rule_path, "w") as f:
            f.write(netstat_rule_content)
        print(f"Generated a sample Sigma Netstat rule at {netstat_rule_path}")

    # --- Initialize Components ---
    cti_manager = EnhancedCTIManager()
    sigma_rule_loader = SigmaRuleLoader(rules_path=sigma_rules_dir) # Instantiate SigmaRuleLoader
    
    # Initialize the Threat Hunting Engine with both managers
    hunting_engine = ThreatHuntingEngine(cti_manager, sigma_rule_loader)

    # --- Run the Hunt ---
    findings = hunting_engine.hunt(sample_log_file)

    if not findings.empty:
        print("\n--- Threat Hunt Findings ---")
        print(findings.to_string()) 
        
        os.makedirs(output_dir, exist_ok=True)
        findings.to_csv(os.path.join(output_dir, "threat_hunt_findings.csv"), index=False)
        print(f"\nFindings saved to {os.path.join(output_dir, 'threat_hunt_findings.csv')}")
    else:
        print("\nNo threat hunt findings detected for the provided logs.")
    
    # --- Reporting ---
    if not findings.empty or True:  # Generate reports even if no findings for demo
        print("\n" + "="*60)
        print("GENERATING COMPREHENSIVE THREAT HUNTING REPORTS")
        print("="*60)
        
        reporter = ThreatHuntingReporter(output_dir=output_dir)
        summary = reporter.generate_complete_report_suite(findings)
        
        print("\nEXECUTIVE SUMMARY:")
        print(f"   • Total Findings: {summary.get('total_findings', 0)}")
        print(f"   • Risk Assessment: {summary.get('risk_assessment', 'N/A')}")
        print(f"   • Affected Hosts: {summary.get('affected_infrastructure', {}).get('hosts', 0)}")
        print(f"   • MITRE Techniques: {summary.get('unique_techniques', 0)}")
    else:
        print("\nNo threat hunt findings detected for the provided logs.")