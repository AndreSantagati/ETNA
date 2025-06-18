from src import hunting_engine


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