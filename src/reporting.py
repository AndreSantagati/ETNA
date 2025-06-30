"""
Automated Threat Hunting Platform - Reporting Module
Generates comprehensive threat hunting reports for security analysts and blue teams.
"""

import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import json
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from collections import Counter
import numpy as np

class ThreatHuntingReporter:
    """
    Advanced reporting engine for threat hunting findings.
    Generates executive summaries, technical analysis, and actionable intelligence.
    """
    
    def __init__(self, output_dir: str = "output/"):
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Set professional styling for visualizations
        plt.style.use('seaborn-v0_8' if 'seaborn-v0_8' in plt.style.available else 'default')
        sns.set_palette("husl")
        
    def generate_executive_summary(self, findings_df: pd.DataFrame) -> Dict:
        """
        Generate executive-level summary for management and security leadership.
        """
        if findings_df.empty:
            return {
                "status": "No threats detected",
                "total_findings": 0,
                "risk_assessment": "LOW",
                "recommendation": "Continue routine monitoring"
            }
        
        # Calculate risk metrics
        risk_scores = findings_df['risk_score'].astype(float)
        high_risk_count = len(findings_df[risk_scores >= 80])
        medium_risk_count = len(findings_df[(risk_scores >= 50) & (risk_scores < 80)])
        low_risk_count = len(findings_df[risk_scores < 50])
        
        # Determine overall risk assessment
        if high_risk_count > 0:
            overall_risk = "HIGH"
        elif medium_risk_count > 3:
            overall_risk = "MEDIUM"
        else:
            overall_risk = "LOW"
        
        # Generate recommendations
        recommendations = self._generate_recommendations(findings_df)
        
        summary = {
            "generated_at": datetime.now().isoformat(),
            "total_findings": len(findings_df),
            "unique_techniques": findings_df['mitre_technique_id'].nunique(),
            "risk_assessment": overall_risk,
            "risk_distribution": {
                "high": high_risk_count,
                "medium": medium_risk_count,
                "low": low_risk_count
            },
            "affected_infrastructure": {
                "hosts": findings_df['hostname'].nunique(),
                "users": findings_df['username'].nunique(),
                "total_events": len(findings_df)
            },
            "attack_patterns": {
                "top_techniques": findings_df['mitre_technique_name'].value_counts().head(5).to_dict(),
                "attack_stages": self._analyze_attack_stages(findings_df)
            },
            "timeline": {
                "earliest_detection": str(findings_df['timestamp'].min()),
                "latest_detection": str(findings_df['timestamp'].max()),
                "duration": str(pd.to_datetime(findings_df['timestamp'].max()) - pd.to_datetime(findings_df['timestamp'].min()))
            },
            "recommendations": recommendations
        }
        
        return summary
    
    def _generate_recommendations(self, findings_df: pd.DataFrame) -> List[str]:
        """Generate actionable recommendations based on findings."""
        recommendations = []
        
        # Check for PowerShell activity
        if any('powershell' in str(name).lower() for name in findings_df['mitre_technique_name']):
            recommendations.append("Implement PowerShell logging and monitoring (Event ID 4104)")
            recommendations.append("Consider PowerShell Constrained Language Mode for non-admin users")
        
        # Check for credential access
        if any('credential' in str(name).lower() for name in findings_df['mitre_technique_name']):
            recommendations.append("Review privileged account security and implement credential guard")
            recommendations.append("Audit recent password changes and suspicious logon activity")
        
        # Check for discovery techniques
        if any('discovery' in str(name).lower() for name in findings_df['mitre_technique_name']):
            recommendations.append("Monitor network scanning and reconnaissance activities")
            recommendations.append("Implement network segmentation to limit lateral movement")
        
        # High-risk findings
        high_risk = findings_df[findings_df['risk_score'].astype(float) >= 80]
        if not high_risk.empty:
            recommendations.append(f"Immediate investigation required for {len(high_risk)} high-risk findings")
            recommendations.append("Consider isolating affected systems pending investigation")
        
        # Default recommendations
        if not recommendations:
            recommendations.extend([
                "Continue routine threat hunting activities",
                "Review and update detection rules based on current findings",
                "Validate findings through additional log analysis"
            ])
        
        return recommendations
    
    def _analyze_attack_stages(self, findings_df: pd.DataFrame) -> Dict:
        """Map findings to MITRE ATT&CK tactics/attack stages."""
        # Simplified mapping - in production, you'd have a comprehensive mapping
        tactic_mapping = {
            'T1059': 'Execution',
            'T1003': 'Credential Access',
            'T1049': 'Discovery',
            'T1047': 'Execution',
            'T1083': 'Discovery',
            'T1082': 'Discovery'
        }
        
        attack_stages = {}
        for _, finding in findings_df.iterrows():
            technique_id = str(finding['mitre_technique_id']).split('.')[0]  # Get base technique
            tactic = tactic_mapping.get(technique_id, 'Unknown')
            attack_stages[tactic] = attack_stages.get(tactic, 0) + 1
        
        return attack_stages
    
    def create_threat_landscape_visualization(self, findings_df: pd.DataFrame):
        """Create comprehensive threat landscape visualization."""
        if findings_df.empty:
            return
        
        fig, axes = plt.subplots(2, 2, figsize=(15, 12))
        fig.suptitle('Threat Hunting Analysis Dashboard', fontsize=16, fontweight='bold')
        
        # 1. Risk Level Distribution
        ax1 = axes[0, 0]
        risk_counts = findings_df['rule_level'].value_counts()
        colors = {'critical': '#d32f2f', 'high': '#f57c00', 'medium': '#fbc02d', 'low': '#388e3c'}
        bar_colors = [colors.get(level, '#757575') for level in risk_counts.index]
        
        bars = ax1.bar(risk_counts.index, risk_counts.values, color=bar_colors)
        ax1.set_title('Findings by Risk Level', fontweight='bold')
        ax1.set_xlabel('Risk Level')
        ax1.set_ylabel('Number of Findings')
        
        # Add value labels on bars
        for bar in bars:
            height = bar.get_height()
            ax1.text(bar.get_x() + bar.get_width()/2., height,
                    f'{int(height)}', ha='center', va='bottom')
        
        # 2. MITRE ATT&CK Techniques
        ax2 = axes[0, 1]
        technique_counts = findings_df['mitre_technique_name'].value_counts().head(8)
        if not technique_counts.empty:
            wedges, texts, autotexts = ax2.pie(technique_counts.values, 
                                              labels=technique_counts.index,
                                              autopct='%1.1f%%',
                                              startangle=90)
            ax2.set_title('Top MITRE ATT&CK Techniques', fontweight='bold')
            plt.setp(autotexts, size=8, weight="bold")
        
        # 3. Timeline Analysis
        ax3 = axes[1, 0]
        findings_df['timestamp'] = pd.to_datetime(findings_df['timestamp'])
        findings_df['hour'] = findings_df['timestamp'].dt.hour
        hourly_counts = findings_df['hour'].value_counts().sort_index()
        
        ax3.plot(hourly_counts.index, hourly_counts.values, marker='o', linewidth=2)
        ax3.set_title('Activity Timeline (24-hour)', fontweight='bold')
        ax3.set_xlabel('Hour of Day')
        ax3.set_ylabel('Number of Detections')
        ax3.grid(True, alpha=0.3)
        
        # 4. Host Impact Analysis
        ax4 = axes[1, 1]
        host_risk = findings_df.groupby('hostname')['risk_score'].agg(['count', 'mean']).sort_values('count', ascending=True)
        
        if not host_risk.empty:
            bars = ax4.barh(range(len(host_risk)), host_risk['count'], 
                           color=plt.cm.RdYlGn_r(host_risk['mean']/100))
            ax4.set_yticks(range(len(host_risk)))
            ax4.set_yticklabels(host_risk.index)
            ax4.set_title('Affected Hosts (colored by avg risk)', fontweight='bold')
            ax4.set_xlabel('Number of Detections')
        
        plt.tight_layout()
        viz_path = os.path.join(self.output_dir, 'threat_landscape.png')
        plt.savefig(viz_path, dpi=300, bbox_inches='tight')
        plt.close()
        print(f"Threat landscape visualization saved to {viz_path}")
    
    def generate_technical_report(self, findings_df: pd.DataFrame, summary: Dict):
        """Generate detailed technical report for security analysts."""
        html_content = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Threat Hunting Analysis Report</title>
            <style>
                body {{ 
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
                    margin: 0; padding: 20px; background-color: #f5f5f5; 
                }}
                .container {{ max-width: 1200px; margin: 0 auto; background-color: white; 
                            padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
                .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                          color: white; padding: 30px; margin: -30px -30px 30px -30px; border-radius: 8px 8px 0 0; }}
                .risk-high {{ background-color: #ffebee; border-left: 4px solid #f44336; padding: 10px; }}
                .risk-medium {{ background-color: #fff8e1; border-left: 4px solid #ff9800; padding: 10px; }}
                .risk-low {{ background-color: #e8f5e8; border-left: 4px solid #4caf50; padding: 10px; }}
                .finding-card {{ background-color: #fafafa; border: 1px solid #ddd; border-radius: 5px; 
                               padding: 15px; margin: 10px 0; }}
                .mitre-tag {{ background-color: #e3f2fd; color: #1976d2; padding: 2px 8px; 
                            border-radius: 12px; font-size: 12px; font-weight: bold; }}
                .timestamp {{ color: #666; font-size: 14px; }}
                table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
                th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
                th {{ background-color: #f2f2f2; font-weight: bold; }}
                .executive-summary {{ background-color: #e8f5e8; padding: 20px; border-radius: 5px; margin: 20px 0; }}
                .recommendations {{ background-color: #fff3e0; padding: 20px; border-radius: 5px; margin: 20px 0; }}
                .stat-box {{ display: inline-block; background-color: #f8f9fa; padding: 15px; 
                           margin: 5px; border-radius: 5px; text-align: center; min-width: 120px; }}
                .stat-number {{ font-size: 24px; font-weight: bold; color: #2c3e50; }}
                .stat-label {{ font-size: 12px; color: #7f8c8d; text-transform: uppercase; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>Automated Threat Hunting Report</h1>
                    <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
                    <p>Analysis Period: {summary.get('timeline', {}).get('earliest_detection', 'N/A')} to {summary.get('timeline', {}).get('latest_detection', 'N/A')}</p>
                </div>
                
                <div class="executive-summary">
                    <h2>Executive Summary</h2>
                    <div>
                        <div class="stat-box">
                            <div class="stat-number">{summary.get('total_findings', 0)}</div>
                            <div class="stat-label">Total Findings</div>
                        </div>
                        <div class="stat-box">
                            <div class="stat-number">{summary.get('unique_techniques', 0)}</div>
                            <div class="stat-label">MITRE Techniques</div>
                        </div>
                        <div class="stat-box">
                            <div class="stat-number">{summary.get('affected_infrastructure', {}).get('hosts', 0)}</div>
                            <div class="stat-label">Affected Hosts</div>
                        </div>
                        <div class="stat-box">
                            <div class="stat-number">{summary.get('risk_assessment', 'LOW')}</div>
                            <div class="stat-label">Risk Level</div>
                        </div>
                    </div>
                    
                    <h3>Risk Distribution</h3>
                    <p>High Risk: {summary.get('risk_distribution', {}).get('high', 0)} | 
                       Medium Risk: {summary.get('risk_distribution', {}).get('medium', 0)} | 
                       Low Risk: {summary.get('risk_distribution', {}).get('low', 0)}</p>
                </div>
        """
        
        # Add recommendations section
        recommendations = summary.get('recommendations', [])
        if recommendations:
            html_content += """
                <div class="recommendations">
                    <h2>Recommendations</h2>
                    <ul>
            """
            for rec in recommendations:
                html_content += f"<li>{rec}</li>"
            html_content += "</ul></div>"
        
        # Add detailed findings
        if not findings_df.empty:
            html_content += "<h2>Detailed Findings</h2>"
            
            for _, finding in findings_df.iterrows():
                risk_class = "risk-low"
                if finding['risk_score'] >= 80:
                    risk_class = "risk-high"
                elif finding['risk_score'] >= 50:
                    risk_class = "risk-medium"
                
                html_content += f"""
                <div class="finding-card {risk_class}">
                    <h3>{finding['hunting_rule_title']}</h3>
                    <p class="timestamp">{finding['timestamp']} |  {finding['hostname']} |  {finding['username']}</p>
                    <p><strong>Process:</strong> {finding['process_name']}</p>
                    <p><strong>Message:</strong> {finding['message']}</p>
                    <p><strong>Risk Score:</strong> {finding['risk_score']}/100</p>
                    <p><span class="mitre-tag">{finding['mitre_technique_id']}</span> {finding['mitre_technique_name']}</p>
                    <p><a href="{finding['mitre_technique_url']}" target="_blank">🔗 MITRE ATT&CK Reference</a></p>
                </div>
                """
        
        html_content += """
                <div style="margin-top: 40px;">
                    <h2>Threat Landscape Analysis</h2>
                    <img src="threat_landscape.png" alt="Threat Analysis Dashboard" style="max-width: 100%; border: 1px solid #ddd; border-radius: 5px;">
                </div>
                
                <footer style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; color: #666; text-align: center;">
                    <p>Generated by Automated Threat Hunting Platform | For Security Operations Use Only</p>
                </footer>
            </div>
        </body>
        </html>
        """
        
        report_path = os.path.join(self.output_dir, 'threat_hunting_report.html')
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        print(f"Technical report saved to {report_path}")
    
    def export_for_siem_integration(self, findings_df: pd.DataFrame):
        """Export findings in various SIEM-compatible formats."""
        if findings_df.empty:
            print("WARNING: No findings to export")
            return
        
        # JSON export for Splunk/Elasticsearch
        json_export = []
        for _, finding in findings_df.iterrows():
            json_record = {
                "timestamp": finding['timestamp'],
                "source": "threat_hunting_platform",
                "event_type": "threat_detection",
                "severity": finding['rule_level'],
                "risk_score": finding['risk_score'],
                "hostname": finding['hostname'],
                "username": finding['username'],
                "process_name": finding['process_name'],
                "rule_id": finding['hunting_rule_id'],
                "rule_title": finding['hunting_rule_title'],
                "mitre_technique": {
                    "id": finding['mitre_technique_id'],
                    "name": finding['mitre_technique_name'],
                    "url": finding['mitre_technique_url']
                },
                "raw_message": finding['message'],
                "source_ip": finding.get('source_ip', ''),
                "destination_ip": finding.get('destination_ip', ''),
                "action": finding.get('action', '')
            }
            json_export.append(json_record)
        
        # Save JSON
        json_path = os.path.join(self.output_dir, 'siem_integration.json')
        with open(json_path, 'w') as f:
            json.dump(json_export, f, indent=2, default=str)
        print(f"SIEM JSON export saved to {json_path}")
        
        # CEF format for ArcSight/QRadar
        cef_path = os.path.join(self.output_dir, 'siem_integration.cef')
        with open(cef_path, 'w') as f:
            for _, finding in findings_df.iterrows():
                # CEF format: CEF:Version|Device Vendor|Device Product|Device Version|Device Event Class ID|Name|Severity|[Extension]
                cef_line = (
                    f"CEF:0|ThreatHunter|AutomatedHuntingPlatform|1.0|"
                    f"{finding['hunting_rule_id']}|{finding['hunting_rule_title']}|"
                    f"{finding['risk_score']}|"
                    f"src={finding.get('source_ip', 'unknown')} "
                    f"dst={finding.get('destination_ip', 'unknown')} "
                    f"suser={finding['username']} "
                    f"dhost={finding['hostname']} "
                    f"cs1={finding['mitre_technique_id']} "
                    f"cs1Label=MITRE_Technique "
                    f"cs2={finding['process_name']} "
                    f"cs2Label=Process_Name "
                    f"msg={finding['message']}\n"
                )
                f.write(cef_line)
        print(f"CEF format export saved to {cef_path}")
    
    def generate_ioc_extraction(self, findings_df: pd.DataFrame):
        """Extract and analyze Indicators of Compromise (IOCs)."""
        if findings_df.empty:
            return
        
        iocs = {
            "ip_addresses": [],
            "processes": [],
            "users": [],
            "hosts": [],
            "techniques": []
        }
        
        # Extract unique IOCs
        iocs["ip_addresses"] = list(set(findings_df['source_ip'].dropna().tolist() + 
                                      findings_df['destination_ip'].dropna().tolist()))
        iocs["processes"] = findings_df['process_name'].dropna().unique().tolist()
        iocs["users"] = findings_df['username'].dropna().unique().tolist()
        iocs["hosts"] = findings_df['hostname'].dropna().unique().tolist()
        iocs["techniques"] = findings_df['mitre_technique_id'].dropna().unique().tolist()
        
        # Remove empty values
        for key in iocs:
            iocs[key] = [item for item in iocs[key] if item and str(item).lower() not in ['nan', 'none', '']]
        
        # Save IOC extraction
        ioc_path = os.path.join(self.output_dir, 'extracted_iocs.json')
        with open(ioc_path, 'w') as f:
            json.dump(iocs, f, indent=2, default=str)
        print(f"IOC extraction saved to {ioc_path}")
        
        return iocs
    
    def generate_complete_report_suite(self, findings_df: pd.DataFrame):
        """Generate the complete report suite for threat hunting analysis."""
        print("Generating comprehensive threat hunting reports...")
        
        # Generate executive summary
        summary = self.generate_executive_summary(findings_df)
        
        # Save executive summary as JSON
        summary_path = os.path.join(self.output_dir, 'executive_summary.json')
        with open(summary_path, 'w') as f:
            json.dump(summary, f, indent=2, default=str)
        print(f"Executive summary saved to {summary_path}")
        
        # Generate visualizations
        self.create_threat_landscape_visualization(findings_df)
        
        # Generate technical report
        self.generate_technical_report(findings_df, summary)
        
        # Export for SIEM integration
        self.export_for_siem_integration(findings_df)
        
        # Extract IOCs
        self.generate_ioc_extraction(findings_df)
        
        print(f"\nComplete report suite generated in: {self.output_dir}")
        print("Generated files:")
        print("   • executive_summary.json - Management overview")
        print("   • threat_hunting_report.html - Technical analysis")
        print("   • threat_landscape.png - Visual dashboard")
        print("   • siem_integration.json - SIEM import format")
        print("   • siem_integration.cef - CEF format for security tools")
        print("   • extracted_iocs.json - Indicators of Compromise")
        
        return summary

# Example usage for testing
if __name__ == "__main__":
    # Test the reporting module
    sample_data = pd.DataFrame({
        'timestamp': ['2024-06-17 10:00:00', '2024-06-17 10:30:00', '2024-06-17 11:00:00'],
        'hostname': ['HOST-01', 'HOST-02', 'HOST-01'],
        'username': ['user1', 'admin', 'attacker'],
        'process_name': ['powershell.exe', 'wmic.exe', 'netstat.exe'],
        'rule_level': ['medium', 'high', 'low'],
        'mitre_technique_id': ['T1059.001', 'T1003', 'T1049'],
        'mitre_technique_name': ['PowerShell', 'OS Credential Dumping', 'Network Discovery'],
        'risk_score': [70, 90, 40],
        'hunting_rule_title': ['PowerShell Detection', 'WMIC Abuse', 'Network Reconnaissance'],
        'hunting_rule_id': ['rule_001', 'rule_002', 'rule_003'],
        'message': ['powershell execution', 'credential access attempt', 'network scanning'],
        'mitre_technique_url': ['https://attack.mitre.org/techniques/T1059/001', 
                               'https://attack.mitre.org/techniques/T1003',
                               'https://attack.mitre.org/techniques/T1049'],
        'source_ip': ['192.168.1.10', '10.0.0.5', '172.16.0.1'],
        'destination_ip': ['8.8.8.8', '192.168.1.1', '172.16.0.10'],
        'action': ['executed', 'executed', 'executed']
    })
    
    reporter = ThreatHuntingReporter()
    reporter.generate_complete_report_suite(sample_data)