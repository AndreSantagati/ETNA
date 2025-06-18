# src/hunting_engine.py

import pandas as pd
import os
from src.log_parser import LogParserFactory, NORMALIZED_LOG_SCHEMA
from src.cti_integration import CTIManager
from typing import Dict, List, Any

class ThreatHuntingEngine:
    def __init__(self, cti_manager: CTIManager):
        self.cti_manager = cti_manager
        # Ensure CTI data is loaded and techniques DataFrame is available
        self.mitre_techniques_df = self.cti_manager.get_techniques_dataframe()
        if self.mitre_techniques_df.empty:
            print("WARNING: MITRE ATT&CK techniques DataFrame is empty. Hunting rules may not find matches.")
        else:
            print(f"Hunting Engine initialized with {len(self.mitre_techniques_df)} MITRE ATT&CK techniques.")

    def _apply_hunting_rules(self, logs_df: pd.DataFrame) -> pd.DataFrame:
        """
        Applies a set of simple hunting rules to the logs DataFrame
        to identify potential ATT&CK techniques.
        """
        hunting_findings = []

        # Ensure process_name column is present and string type for reliable searching
        if 'process_name' not in logs_df.columns:
            logs_df['process_name'] = "" # Add empty column if missing for consistency
        logs_df['process_name'] = logs_df['process_name'].astype(str)

        # Ensure event_id column is present and string type for reliable searching
        if 'event_id' not in logs_df.columns:
            logs_df['event_id'] = None # Add empty column if missing for consistency
        logs_df['event_id'] = logs_df['event_id'].astype(str) # Convert to string for consistent searching

        # --- Rule for T1059.001 - Command and Scripting Interpreter: PowerShell ---
        # Description: Adversaries may abuse PowerShell for execution.
        powershell_tech = self.cti_manager.get_technique_by_id('T1059.001') 
        if powershell_tech:
            # Look for logs where 'process_name' contains 'powershell.exe' or 'pwsh.exe'
            # Also looking for specific Event IDs if relevant (e.g., 4104 for script block logging)
            susp_powershell_filter = (
                logs_df['process_name'].str.contains('powershell|pwsh', case=False, na=False)
            )
            # You could add: & (logs_df['event_id'] == '4104') for specific event ID correlation

            susp_powershell = logs_df[susp_powershell_filter]
            for _, row in susp_powershell.iterrows():
                finding = row.to_dict()
                finding.update({
                    'hunting_rule': 'Suspicious PowerShell Execution',
                    'mitre_technique_id': powershell_tech['id'],
                    'mitre_technique_name': powershell_tech['name'],
                    'mitre_technique_url': powershell_tech['url'],
                    'risk_score': 70 # Example score
                })
                hunting_findings.append(finding)
        else:
            print("WARNING: T1059.001 not found in MITRE data for PowerShell rule.")


        # --- Rule for T1003 - OS Credential Dumping ---
        # Description: Adversaries may attempt to dump credentials from memory.
        cred_dump_tech = self.cti_manager.get_technique_by_id('T1003')
        if cred_dump_tech:
            # Look for 'lsass.exe' process access or specific credential dumping tools (e.g., mimikatz, procdump)
            # For simplicity in sample logs, let's look for 'wmic.exe' or specific EventIDs (e.g., 4688 for process creation, then check command line)
            susp_cred_dump_filter = (
                logs_df['process_name'].str.contains('wmic.exe', case=False, na=False) |
                logs_df['message'].str.contains('lsass.exe', case=False, na=False) # Example for message content
            )
            susp_cred_dump = logs_df[susp_cred_dump_filter]
            for _, row in susp_cred_dump.iterrows():
                finding = row.to_dict()
                finding.update({
                    'hunting_rule': 'Potential Credential Dumping Attempt',
                    'mitre_technique_id': cred_dump_tech['id'],
                    'mitre_technique_name': cred_dump_tech['name'],
                    'mitre_technique_url': cred_dump_tech['url'],
                    'risk_score': 90 # Higher score
                })
                hunting_findings.append(finding)
        else:
            print("WARNING: T1003 not found in MITRE data for Credential Dumping rule.")
            
        # --- Rule for T1049 - System Network Connections Discovery ---
        # Description: Adversaries may look for connections to local and remote systems.
        # Example: looking for `netstat` usage
        net_conn_tech = self.cti_manager.get_technique_by_id('T1049')
        if net_conn_tech:
            susp_netstat = logs_df[
                logs_df['process_name'].str.contains('netstat.exe', case=False, na=False)
            ]
            for _, row in susp_netstat.iterrows():
                finding = row.to_dict()
                finding.update({
                    'hunting_rule': 'Network Connections Discovery via Netstat',
                    'mitre_technique_id': net_conn_tech['id'],
                    'mitre_technique_name': net_conn_tech['name'],
                    'mitre_technique_url': net_conn_tech['url'],
                    'risk_score': 50 # Lower score, often legitimate
                })
                hunting_findings.append(finding)
        else:
            print("WARNING: T1049 not found in MITRE data for Netstat rule.")


        # Convert findings list to DataFrame
        findings_df = pd.DataFrame(hunting_findings)
        
        # Ensure all columns from the NORMALIZED_LOG_SCHEMA plus hunting-specific columns are present
        # This prevents issues if a finding doesn't naturally have all log_schema fields or vice-versa
        all_expected_cols = list(NORMALIZED_LOG_SCHEMA.keys()) + [
            'hunting_rule', 'mitre_technique_id', 'mitre_technique_name', 
            'mitre_technique_url', 'risk_score'
        ]
        
        for col in all_expected_cols:
            if col not in findings_df.columns:
                findings_df[col] = None # Add missing columns with None

        # Reorder columns for a consistent output format
        # Prioritize key finding details at the beginning
        output_cols_order = [
            'timestamp', 'hostname', 'username', 'process_name', 
            'hunting_rule', 'mitre_technique_id', 'mitre_technique_name', 
            'risk_score', 'mitre_technique_url',
            'event_id', 'message', 'source_ip', 'destination_ip', 'action'
        ]
        
        # Ensure only columns in output_cols_order are present and in that order
        findings_df = findings_df[output_cols_order]
        
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

# --- Example Usage (for testing this module) ---
if __name__ == "__main__":
    # Initialize CTI Manager (this will load/download MITRE data)
    cti_manager = CTIManager()

    # Initialize the Threat Hunting Engine
    hunting_engine = ThreatHuntingEngine(cti_manager)

    # Path to your sample log file
    sample_log_file = "data/logs/sample_log.csv"

    # Ensure the sample log exists (updated to include more diverse processes for hunting)
    if not os.path.exists("data/logs"):
        os.makedirs("data/logs")
    if not os.path.exists(sample_log_file):
        with open(sample_log_file, "w") as f:
            f.write("TimeCreated,ComputerName,UserName,ProcessName,EventID,SourceIpAddress,DestinationIpAddress,EventData\n")
            f.write("2024-06-17 10:00:00,HOST-01,user1,powershell.exe,4104,192.168.1.10,8.8.8.8,Process started\n")
            f.write("2024-06-17 10:05:00,HOST-02,admin,cmd.exe,4688,10.0.0.5,192.168.1.1,Account logon\n")
            f.write("2024-06-17 10:10:00,HOST-01,user1,calc.exe,4688,,,User opened calculator\n")
            f.write("2024-06-17 10:15:00,HOST-03,guest,explorer.exe,4624,172.16.0.1,172.16.0.10,Successful logon\n")
            f.write("2024-06-17 10:20:00,HOST-01,user1,wmic.exe,4688,,,WMIC call to query process list\n") # This should trigger T1003/T1047
            f.write("2024-06-17 10:25:00,HOST-04,sysadmin,netstat.exe,4688,,,Network connection status\n") # This should trigger T1049
            f.write("2024-06-17 10:30:00,HOST-02,attacker,cmd.exe,4688,192.168.1.50,1.2.3.4,Suspicious network connection attempt\n")
            f.write("2024-06-17 10:35:00,HOST-01,svc_account,services.exe,7036,,,Service started\n")
        print(f"Generated a sample CSV log file at {sample_log_file}")

    # Run the hunt
    findings = hunting_engine.hunt(sample_log_file)

    if not findings.empty:
        print("\n--- Threat Hunt Findings ---")
        # Use to_string() for full DataFrame output, or .head() for truncated
        # You might need to adjust terminal width to see all columns
        print(findings.to_string()) 
        
        # You could also save to CSV:
        # output_dir = "output/"
        # os.makedirs(output_dir, exist_ok=True)
        # findings.to_csv(os.path.join(output_dir, "threat_hunt_findings.csv"), index=False)
        # print(f"\nFindings saved to {os.path.join(output_dir, 'threat_hunt_findings.csv')}")
    else:
        print("\nNo threat hunt findings detected for the provided logs.")