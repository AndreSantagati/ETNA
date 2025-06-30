#!/usr/bin/env python3
"""
SOC Analyst Daily Threat Hunting Workflow
Simulates how a security analyst would use the platform
"""

import os
import sys
import subprocess
from datetime import datetime
import shutil

# Add parent directory to path to import src modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def get_project_root():
    """Get the project root directory"""
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def run_threat_hunt(log_file, description):
    """Run threat hunt and measure performance"""
    print(f"\n🔍 {description}")
    print(f"📁 Analyzing: {log_file}")
    print("-" * 50)
    
    project_root = get_project_root()
    full_log_path = os.path.join(project_root, log_file)
    
    if not os.path.exists(full_log_path):
        print(f"❌ Log file not found: {full_log_path}")
        return False
    
    start_time = datetime.now()
    
    # Create unique output directory for this test
    output_dir = os.path.join(project_root, "output", f"test_{datetime.now().strftime('%H%M%S')}")
    os.makedirs(output_dir, exist_ok=True)
    
    # Temporarily modify main.py to use different log file
    backup_sample_log(project_root)
    replace_log_file_in_main(project_root, full_log_path)
    
    try:
        # Change to project root directory before running
        original_cwd = os.getcwd()
        os.chdir(project_root)
        
        # Run the threat hunting platform
        result = subprocess.run([
            sys.executable, "-m", "src.main"
        ], capture_output=True, text=True, timeout=120)
        
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        if result.returncode == 0:
            print(f"✅ Hunt completed in {duration:.2f} seconds")
            
            # Move results to unique directory
            output_path = os.path.join(project_root, "output")
            if os.path.exists(output_path):
                for file in os.listdir(output_path):
                    if file.endswith(('.csv', '.json', '.html', '.png', '.cef')) and not file.startswith('test_'):
                        src_file = os.path.join(output_path, file)
                        dst_file = os.path.join(output_dir, file)
                        if os.path.exists(src_file):
                            shutil.copy(src_file, dst_file)
            
            print(f"📊 Results saved to: {output_dir}")
            
            # Show key metrics
            show_hunt_summary(output_dir)
            
        else:
            print(f"❌ Hunt failed: {result.stderr}")
            
    except subprocess.TimeoutExpired:
        print("⏰ Hunt timed out after 2 minutes")
        
    finally:
        os.chdir(original_cwd)
        restore_sample_log(project_root)
    
    return result.returncode == 0 if 'result' in locals() else False

def backup_sample_log(project_root):
    """Backup original sample log"""
    sample_log = os.path.join(project_root, "data", "logs", "sample_log.csv")
    backup_log = os.path.join(project_root, "data", "logs", "sample_log_backup.csv")
    
    if os.path.exists(sample_log):
        shutil.copy(sample_log, backup_log)

def restore_sample_log(project_root):
    """Restore original sample log"""
    sample_log = os.path.join(project_root, "data", "logs", "sample_log.csv")
    backup_log = os.path.join(project_root, "data", "logs", "sample_log_backup.csv")
    
    if os.path.exists(backup_log):
        shutil.copy(backup_log, sample_log)
        os.remove(backup_log)

def replace_log_file_in_main(project_root, new_log_file):
    """Temporarily replace the log file in main.py"""
    sample_log = os.path.join(project_root, "data", "logs", "sample_log.csv")
    shutil.copy(new_log_file, sample_log)

def show_hunt_summary(output_dir):
    """Display summary of hunt results"""
    try:
        import json
        import pandas as pd
        
        # Check executive summary
        summary_file = os.path.join(output_dir, "executive_summary.json")
        if os.path.exists(summary_file):
            with open(summary_file, 'r') as f:
                summary = json.load(f)
                print(f"   🎯 Findings: {summary.get('total_findings', 0)}")
                print(f"   ⚠️  Risk Level: {summary.get('risk_assessment', 'Unknown')}")
                print(f"   🖥️  Affected Hosts: {summary.get('affected_infrastructure', {}).get('hosts', 0)}")
        
        # Check detailed findings
        findings_file = os.path.join(output_dir, "threat_hunt_findings.csv")
        if os.path.exists(findings_file):
            findings = pd.read_csv(findings_file)
            if not findings.empty:
                print(f"   📋 Top Techniques:")
                for technique in findings['mitre_technique_name'].value_counts().head(3).items():
                    print(f"      • {technique[0]}: {technique[1]} occurrences")
        
    except Exception as e:
        print(f"   ⚠️ Could not parse results: {e}")

def main():
    print("🎯 SOC ANALYST DAILY THREAT HUNTING WORKFLOW")
    print("=" * 60)
    
    # Test scenarios (relative to project root)
    scenarios = [
        ("test_logs/normal_activity.csv", "🏢 Normal Business Activity Analysis"),
        ("test_logs/apt_simulation.csv", "🚨 Suspected APT Activity Investigation"), 
        ("test_logs/mixed_environment.csv", "🔍 Comprehensive Environment Scan"),
    ]
    
    results = []
    
    for log_file, description in scenarios:
        success = run_threat_hunt(log_file, description)
        results.append((description, success))
    
    # Summary
    print("\n" + "=" * 60)
    print("📊 WORKFLOW TEST SUMMARY")
    print("=" * 60)
    
    for description, success in results:
        status = "✅ PASSED" if success else "❌ FAILED"
        print(f"{status} - {description}")
    
    passed = sum(1 for _, success in results if success)
    print(f"\n🎯 Overall: {passed}/{len(results)} scenarios passed")

if __name__ == "__main__":
    main()