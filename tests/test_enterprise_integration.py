"""
Enterprise Integration Testing
Tests SIEM integration, performance, and report quality
"""

import os
import json
import time
import sys

# Add parent directory to path to import src modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def get_project_root():
    """Get the project root directory"""
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def test_siem_integration():
    """Test SIEM export functionality"""
    print("🔌 TESTING SIEM INTEGRATION")
    print("-" * 40)
    
    project_root = get_project_root()
    output_dir = os.path.join(project_root, "output")
    
    # Check if all SIEM formats are generated
    expected_files = [
        ("siem_integration.json", "Splunk/Elasticsearch Format"),
        ("siem_integration.cef", "ArcSight/QRadar Format"), 
        ("extracted_iocs.json", "IOC Intelligence Feed"),
        ("threat_hunt_findings.csv", "Raw Findings Export")
    ]
    
    all_present = True
    
    for filename, description in expected_files:
        file_path = os.path.join(output_dir, filename)
        if os.path.exists(file_path):
            size = os.path.getsize(file_path)
            print(f"{description}")
            print(f"   {file_path} ({size:,} bytes)")
            
            # Validate file content
            if filename.endswith('.json'):
                try:
                    with open(file_path, 'r') as f:
                        data = json.load(f)
                        if isinstance(data, list):
                            print(f"   Contains {len(data)} records")
                        elif isinstance(data, dict):
                            print(f"   Contains {len(data)} fields")
                except json.JSONDecodeError:
                    print(f"   Invalid JSON format")
                    
        else:
            print(f"MISSING: {description}")
            print(f"   Expected: {file_path}")
            all_present = False
    
    # Use assert instead of return
    assert all_present, "Some SIEM integration files are missing"

def test_performance_metrics():
    """Test platform performance"""
    print("\n⚡ TESTING PERFORMANCE")
    print("-" * 30)
    
    project_root = get_project_root()
    
    # Run a performance test
    start_time = time.time()
    
    try:
        import subprocess
        
        # Change to project root directory before running
        original_cwd = os.getcwd()
        os.chdir(project_root)
        
        result = subprocess.run([
            sys.executable, "-m", "src.main"
        ], capture_output=True, text=True, timeout=300)  # 5 minute timeout
        
        os.chdir(original_cwd)
        
        end_time = time.time()
        execution_time = end_time - start_time
        
        if result.returncode == 0:
            print(f"Platform executed successfully")
            print(f"Execution time: {execution_time:.2f} seconds")
            
            if execution_time < 30:
                print("EXCELLENT: Very fast execution")
            elif execution_time < 60:
                print("GOOD: Acceptable execution time")
            elif execution_time < 120:
                print("MODERATE: Consider optimization")
            else:
                print("SLOW: Performance optimization needed")
            
            # Use assert instead of return
            assert result.returncode == 0, "Platform execution failed"
        else:
            print(f"Platform execution failed")
            print(f"Error: {result.stderr}")
            assert False, f"Platform execution failed: {result.stderr}"
            
    except subprocess.TimeoutExpired:
        print("Platform timed out after 5 minutes")
        assert False, "Platform timed out"
    except Exception as e:
        print(f"Performance test failed: {e}")
        assert False, f"Performance test failed: {e}"

def test_report_quality():
    """Validate report generation and content quality"""
    print("\nTESTING REPORT QUALITY")
    print("-" * 40)
    
    project_root = get_project_root()
    output_dir = os.path.join(project_root, "output")
    
    quality_checks = []
    
    # Check HTML report
    html_file = os.path.join(output_dir, "threat_hunting_report.html")
    if os.path.exists(html_file):
        with open(html_file, 'r', encoding='utf-8') as f:
            content = f.read()
            
        checks = [
            ("MITRE ATT&CK references", "MITRE ATT&CK" in content),
            ("Risk assessment data", "Risk Score" in content),
            ("Executive summary", "Executive Summary" in content),
            ("Detailed findings", "Detailed Findings" in content),
            ("Visual dashboard reference", "threat_landscape.png" in content),
        ]
        
        print("🔍 HTML Report Quality:")
        for check_name, passed in checks:
            status = "V" if passed else "X"
            print(f"   {status} {check_name}")
            quality_checks.append(passed)
    else:
        print("HTML report not found")
        quality_checks.extend([False] * 5)
    
    # Check executive summary
    summary_file = os.path.join(output_dir, "executive_summary.json")
    if os.path.exists(summary_file):
        try:
            with open(summary_file, 'r') as f:
                summary = json.load(f)
            
            required_fields = [
                'total_findings', 'risk_assessment', 'affected_infrastructure',
                'attack_patterns', 'recommendations'
            ]
            
            print("\n📋 Executive Summary Quality:")
            for field in required_fields:
                present = field in summary
                status = "V" if present else "X"
                print(f"   {status} {field}")
                quality_checks.append(present)
                
        except json.JSONDecodeError:
            print("Executive summary has invalid JSON")
            quality_checks.extend([False] * 5)
    else:
        print("Executive summary not found")
        quality_checks.extend([False] * 5)
    
    # Check visualization
    viz_file = os.path.join(output_dir, "threat_landscape.png")
    if os.path.exists(viz_file):
        size = os.path.getsize(viz_file)
        print(f"\nVisualization: Generated ({size:,} bytes)")
        quality_checks.append(True)
    else:
        print("\nVisualization: Not generated")
        quality_checks.append(False)
    
    # Use assert instead of return
    quality_score = sum(quality_checks)
    total_checks = len(quality_checks)
    
    print(f"\nQuality Score: {quality_score}/{total_checks}")
    
    # Assert that at least 80% of quality checks pass
    assert quality_score >= (total_checks * 0.8), f"Quality score too low: {quality_score}/{total_checks}"

def main():
    print("ENTERPRISE INTEGRATION TESTING SUITE")
    print("=" * 60)
    
    # Run all tests
    test_results = []
    
    # Test 1: SIEM Integration
    try:
        test_siem_integration()
        test_results.append(("SIEM Integration", True))
    except Exception as e:
        print(f"SIEM Integration failed: {e}")
        test_results.append(("SIEM Integration", False))
    
    # Test 2: Performance
    try:
        test_performance_metrics()
        test_results.append(("Performance", True))
    except Exception as e:
        print(f"Performance test failed: {e}")
        test_results.append(("Performance", False))
    
    # Test 3: Report Quality
    try:
        test_report_quality()
        test_results.append(("Report Quality", True))
    except Exception as e:
        print(f"Report quality test failed: {e}")
        test_results.append(("Report Quality", False))
    
    # Final Summary
    print("\n" + "=" * 60)
    print("ENTERPRISE TESTING SUMMARY")
    print("=" * 60)
    
    for test_name, passed in test_results:
        status = "PASSED" if passed else "FAILED"
        print(f"{status} - {test_name}")
    
    passed_tests = sum(1 for _, passed in test_results if passed)
    print(f"\nOverall Score: {passed_tests}/{len(test_results)} tests passed")
    
    if passed_tests == len(test_results):
        print("READY FOR ENTERPRISE DEPLOYMENT!")
    else:
        print("Some issues need attention before enterprise deployment")

if __name__ == "__main__":
    main()