import csv
import os
import sys
from datetime import datetime, timedelta

# Add parent directory to path to import src modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def create_advanced_test_logs():
    """Generate realistic enterprise log scenarios"""
    
    # Get the project root directory (parent of tests/)
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    test_logs_dir = os.path.join(project_root, "test_logs")
    
    # Scenario 1: Suspected APT Activity
    apt_logs = [
        ["2024-12-30 09:15:00", "DC-01", "admin", "powershell.exe", "4688", "10.0.1.50", "185.220.101.42", "powershell -ExecutionPolicy Bypass -WindowStyle Hidden", "executed"],
        ["2024-12-30 09:16:30", "DC-01", "admin", "wmic.exe", "4688", "", "", "wmic process call create calc.exe", "executed"],
        ["2024-12-30 09:17:00", "WS-FINANCE-01", "jdoe", "netstat.exe", "4688", "", "", "netstat -an", "executed"],
        ["2024-12-30 09:18:00", "DC-01", "admin", "rundll32.exe", "4688", "", "", "rundll32.exe shell32.dll,ShellExec_RunDLL", "executed"],
        ["2024-12-30 09:19:00", "WS-FINANCE-01", "jdoe", "powershell.exe", "4688", "", "", "powershell -enc SGVsbG8gV29ybGQ=", "executed"],
        ["2024-12-30 09:20:00", "DC-01", "admin", "wmic.exe", "4688", "", "", "wmic process list shadowcopy", "executed"],
    ]
    
    # Scenario 2: Normal Business Activity  
    normal_logs = [
        ["2024-12-30 08:30:00", "WS-HR-05", "alice", "excel.exe", "4688", "", "", "Excel startup", "executed"],
        ["2024-12-30 08:31:00", "WS-IT-02", "bob", "chrome.exe", "4688", "", "", "Chrome browser", "executed"],
        ["2024-12-30 08:32:00", "SRV-FILE-01", "system", "backup.exe", "4688", "", "", "Daily backup routine", "executed"],
        ["2024-12-30 08:33:00", "WS-MARKETING-03", "carol", "outlook.exe", "4688", "", "", "Outlook startup", "executed"],
    ]
    
    # Scenario 3: Mixed Activity (combines both)
    mixed_logs = apt_logs + normal_logs
    
    scenarios = {
        "apt_simulation.csv": apt_logs,
        "normal_activity.csv": normal_logs,
        "mixed_environment.csv": mixed_logs
    }
    
    # Create test_logs directory
    os.makedirs(test_logs_dir, exist_ok=True)
    
    for filename, logs in scenarios.items():
        full_path = os.path.join(test_logs_dir, filename)
        with open(full_path, 'w', newline='') as f:
            writer = csv.writer(f)
            # Write header
            writer.writerow(["TimeCreated", "ComputerName", "UserName", "ProcessName", 
                           "EventID", "SourceIpAddress", "DestinationIpAddress", "EventData", "Action"])
            # Write data
            writer.writerows(logs)
        print(f"✅ Created: {full_path}")

def main():
    print("🎯 GENERATING TEST SCENARIOS")
    print("=" * 40)
    create_advanced_test_logs()
    print("\n📁 Test files created in 'test_logs/' directory")
    print("🚀 Ready for testing!")

if __name__ == "__main__":
    main()