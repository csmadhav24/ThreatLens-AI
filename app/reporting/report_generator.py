# app/reporting/soc_report_generator.py
"""
Professional SOC Investigation Report Generator
Creates executive-ready incident reports with full SOC dashboard styling
"""

import pandas as pd
import json
from datetime import datetime
from typing import Dict, Any, List, Optional
from collections import Counter
import hashlib


class SOCReportGenerator:
    """
    Enterprise SOC Investigation Report Generator
    Produces comprehensive reports for SOC analysts, IR teams, and management
    """
    
    def __init__(self, company_name: str = "Security Operations Center"):
        self.company_name = company_name
        self.report_id = f"SOC-IR-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
    
    def generate_full_report(self, findings: Dict, df: pd.DataFrame = None, 
                              attack_chains: List = None, intelligence: Dict = None) -> str:
        """
        Generate complete professional SOC report as HTML
        """
        
        # Extract data from findings
        risk_score = findings.get('risk_score', 0)
        total_events = findings.get('total_events', len(df) if df is not None else 0)
        
        # Get counts
        critical_count = findings.get('summary', {}).get('critical_count', 0)
        high_count = findings.get('summary', {}).get('high_count', 0)
        medium_count = findings.get('summary', {}).get('medium_count', 0)
        low_count = findings.get('summary', {}).get('low_count', 0)
        
        # Determine severity
        if risk_score >= 70:
            severity_level = "CRITICAL"
            severity_color = "#dc3545"
            severity_badge = "CRITICAL"
        elif risk_score >= 40:
            severity_level = "HIGH"
            severity_color = "#fd7e14"
            severity_badge = "HIGH"
        elif risk_score >= 20:
            severity_level = "MEDIUM"
            severity_color = "#ffc107"
            severity_badge = "MEDIUM"
        else:
            severity_level = "LOW"
            severity_color = "#28a745"
            severity_badge = "LOW"
        
        # Affected assets
        affected_users = []
        affected_hosts = []
        affected_ips = []
        
        if intelligence:
            affected_users = intelligence.get('affected_assets', {}).get('users', [])
            affected_hosts = intelligence.get('affected_assets', {}).get('hosts', [])
            affected_ips = intelligence.get('affected_assets', {}).get('ip_addresses', [])
        
        # Failed logins count
        failed_logins = findings.get('failed_logins', [])
        
        # Suspicious events
        suspicious_ps = findings.get('suspicious_powershell', [])
        lateral_movement = findings.get('lateral_movement', [])
        privilege_esc = findings.get('privilege_escalation', [])
        
        # IOCs
        iocs = {
            'ips': [],
            'domains': [],
            'users': affected_users,
            'hosts': affected_hosts,
            'commands': []
        }
        
        for login in failed_logins[:10]:
            if login.get('source_ip'):
                iocs['ips'].append(login['source_ip'])
        
        for ps in suspicious_ps[:5]:
            if ps.get('command'):
                iocs['commands'].append(ps['command'][:100])
        
        # Calculate confidence
        confidence = 20
        if suspicious_ps:
            confidence += 30
        if lateral_movement:
            confidence += 25
        if privilege_esc:
            confidence += 20
        if failed_logins and len(failed_logins) > 10:
            confidence += 15
        
        confidence = min(confidence, 95)
        
        # Generate the HTML report
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SOC Investigation Report | {self.report_id}</title>
    <style>
        /* ============================================
           ENTERPRISE SOC REPORT STYLING
        ============================================ */
        
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', 'Roboto', 'SF Pro Text', -apple-system, BlinkMacSystemFont, sans-serif;
            background: linear-gradient(135deg, #0a0a1a 0%, #0f0f23 100%);
            color: #e8e8e8;
            line-height: 1.6;
            padding: 20px;
        }}
        
        /* Main Container */
        .report-container {{
            max-width: 1400px;
            margin: 0 auto;
            background: #0d1117;
            border-radius: 16px;
            overflow: hidden;
            box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
            border: 1px solid #1f2a3a;
        }}
        
        /* Header Section */
        .report-header {{
            background: linear-gradient(135deg, #0a1628 0%, #0d1b2a 100%);
            padding: 2rem;
            border-bottom: 3px solid #00d4ff;
            position: relative;
        }}
        
        .header-title {{
            font-size: 2rem;
            font-weight: 700;
            background: linear-gradient(135deg, #00d4ff, #7b2ff7);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            margin-bottom: 0.5rem;
        }}
        
        .header-subtitle {{
            color: #8b9dc3;
            font-size: 0.9rem;
        }}
        
        .header-meta {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-top: 1.5rem;
            flex-wrap: wrap;
            gap: 1rem;
        }}
        
        .meta-item {{
            background: rgba(0, 212, 255, 0.1);
            padding: 0.5rem 1rem;
            border-radius: 8px;
            border-left: 3px solid #00d4ff;
        }}
        
        .meta-label {{
            font-size: 0.7rem;
            text-transform: uppercase;
            color: #8b9dc3;
            letter-spacing: 1px;
        }}
        
        .meta-value {{
            font-size: 1rem;
            font-weight: 600;
            color: #fff;
        }}
        
        /* Risk Banner */
        .risk-banner {{
            background: linear-gradient(135deg, rgba(220, 53, 69, 0.15), rgba(220, 53, 69, 0.05));
            border: 1px solid rgba(220, 53, 69, 0.3);
            border-radius: 12px;
            padding: 1.5rem;
            margin-bottom: 2rem;
            position: relative;
            overflow: hidden;
        }}
        
        .risk-banner::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 4px;
            height: 100%;
            background: {severity_color};
        }}
        
        .risk-score {{
            font-size: 3rem;
            font-weight: 800;
            color: {severity_color};
        }}
        
        .risk-level {{
            display: inline-block;
            background: {severity_color};
            color: white;
            padding: 0.25rem 1rem;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: 600;
            margin-left: 1rem;
        }}
        
        /* Stats Grid */
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }}
        
        .stat-card {{
            background: #161b22;
            border-radius: 12px;
            padding: 1.25rem;
            border: 1px solid #21262d;
            transition: transform 0.2s, border-color 0.2s;
        }}
        
        .stat-card:hover {{
            border-color: #00d4ff;
            transform: translateY(-2px);
        }}
        
        .stat-value {{
            font-size: 2rem;
            font-weight: 700;
            color: #00d4ff;
        }}
        
        .stat-label {{
            font-size: 0.75rem;
            text-transform: uppercase;
            color: #8b9dc3;
            letter-spacing: 1px;
            margin-top: 0.5rem;
        }}
        
        /* Section Styling */
        .section {{
            background: #0d1117;
            border-radius: 12px;
            margin-bottom: 2rem;
            border: 1px solid #21262d;
            overflow: hidden;
        }}
        
        .section-header {{
            background: linear-gradient(135deg, #161b22, #0d1117);
            padding: 1rem 1.5rem;
            border-bottom: 1px solid #21262d;
            cursor: pointer;
            transition: background 0.2s;
        }}
        
        .section-header:hover {{
            background: #1a1f2a;
        }}
        
        .section-title {{
            font-size: 1.25rem;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }}
        
        .section-icon {{
            font-size: 1.5rem;
        }}
        
        .section-content {{
            padding: 1.5rem;
        }}
        
        /* Tables */
        .data-table {{
            width: 100%;
            border-collapse: collapse;
        }}
        
        .data-table th {{
            background: #1a1f2a;
            padding: 0.75rem;
            text-align: left;
            font-weight: 600;
            color: #00d4ff;
            border-bottom: 1px solid #2a2f3a;
        }}
        
        .data-table td {{
            padding: 0.75rem;
            border-bottom: 1px solid #1a1f2a;
            color: #c9d1d9;
        }}
        
        .data-table tr:hover {{
            background: #1a1f2a;
        }}
        
        /* Badges */
        .badge {{
            display: inline-block;
            padding: 0.2rem 0.6rem;
            border-radius: 20px;
            font-size: 0.7rem;
            font-weight: 600;
        }}
        
        .badge-critical {{ background: #dc3545; color: white; }}
        .badge-high {{ background: #fd7e14; color: white; }}
        .badge-medium {{ background: #ffc107; color: black; }}
        .badge-low {{ background: #28a745; color: white; }}
        .badge-info {{ background: #17a2b8; color: white; }}
        
        /* Metrics Grid */
        .metrics-3col {{
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 1rem;
            margin-bottom: 1.5rem;
        }}
        
        .metric-item {{
            background: #161b22;
            padding: 1rem;
            border-radius: 8px;
            text-align: center;
        }}
        
        .metric-value {{
            font-size: 1.5rem;
            font-weight: 700;
            color: #00d4ff;
        }}
        
        .metric-label {{
            font-size: 0.7rem;
            color: #8b9dc3;
        }}
        
        /* Attack Chain */
        .attack-chain {{
            display: flex;
            flex-wrap: wrap;
            gap: 0.5rem;
            margin: 1rem 0;
        }}
        
        .chain-phase {{
            flex: 1;
            min-width: 120px;
            background: #1a1f2a;
            padding: 0.75rem;
            border-radius: 8px;
            text-align: center;
            border-top: 3px solid #00d4ff;
        }}
        
        .phase-number {{
            font-size: 0.7rem;
            color: #8b9dc3;
        }}
        
        .phase-name {{
            font-weight: 600;
            margin-top: 0.25rem;
        }}
        
        /* Confidence Meter */
        .confidence-meter {{
            background: #1a1f2a;
            border-radius: 8px;
            padding: 0.25rem;
            margin: 0.5rem 0;
        }}
        
        .confidence-fill {{
            background: linear-gradient(90deg, #00d4ff, #7b2ff7);
            height: 8px;
            border-radius: 4px;
            width: {confidence}%;
        }}
        
        /* IOCs Grid */
        .iocs-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 1rem;
        }}
        
        .ioc-category {{
            background: #1a1f2a;
            border-radius: 8px;
            padding: 0.75rem;
        }}
        
        .ioc-title {{
            font-weight: 600;
            color: #00d4ff;
            margin-bottom: 0.5rem;
            border-bottom: 1px solid #2a2f3a;
            padding-bottom: 0.25rem;
        }}
        
        .ioc-list {{
            list-style: none;
        }}
        
        .ioc-list li {{
            font-family: monospace;
            font-size: 0.75rem;
            padding: 0.25rem 0;
            color: #c9d1d9;
        }}
        
        /* Footer */
        .report-footer {{
            background: #0a0a1a;
            padding: 1.5rem;
            text-align: center;
            border-top: 1px solid #1f2a3a;
            font-size: 0.7rem;
            color: #6e7681;
        }}
        
        /* Responsive */
        @media (max-width: 768px) {{
            .stats-grid {{
                grid-template-columns: repeat(2, 1fr);
            }}
            .metrics-3col {{
                grid-template-columns: 1fr;
            }}
            .attack-chain {{
                flex-direction: column;
            }}
        }}
    </style>
</head>
<body>
    <div class="report-container">
        
        <!-- HEADER -->
        <div class="report-header">
            <div class="header-title">🛡️ SOC Investigation Report</div>
            <div class="header-subtitle">Enterprise Security Operations Center | {self.company_name}</div>
            
            <div class="header-meta">
                <div class="meta-item">
                    <div class="meta-label">REPORT ID</div>
                    <div class="meta-value">{self.report_id}</div>
                </div>
                <div class="meta-item">
                    <div class="meta-label">INVESTIGATION DATE</div>
                    <div class="meta-value">{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
                </div>
                <div class="meta-item">
                    <div class="meta-label">ANALYST</div>
                    <div class="meta-value">AI SOC Analyst Agent</div>
                </div>
                <div class="meta-item">
                    <div class="meta-label">CLASSIFICATION</div>
                    <div class="meta-value">CONFIDENTIAL - SOC INTERNAL</div>
                </div>
            </div>
        </div>
        
        <div class="section-content">
            
            <!-- 1. EXECUTIVE SUMMARY -->
            <div class="risk-banner">
                <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap;">
                    <div>
                        <span class="risk-score">{risk_score}/100</span>
                        <span class="risk-level">{severity_badge} RISK</span>
                    </div>
                    <div class="stat-card" style="background: rgba(0,0,0,0.3); min-width: 150px;">
                        <div class="stat-value">{confidence}%</div>
                        <div class="stat-label">Investigation Confidence</div>
                    </div>
                </div>
                
                <div style="margin-top: 1.5rem;">
                    <h3 style="color: #00d4ff; margin-bottom: 0.5rem;">📋 Executive Summary</h3>
                    <p style="line-height: 1.6;">
                        This investigation has identified <strong>{critical_count + high_count}</strong> high-severity security events 
                        requiring immediate attention. The analysis reveals potential {self._get_incident_type(suspicious_ps, lateral_movement, privilege_esc)} 
                        with <strong>{
                            len(iocs['ips'])
                        } suspicious IPs</strong> and <strong>{len(affected_users)} affected user accounts</strong>.
                        {self._get_incident_description(suspicious_ps, lateral_movement, privilege_esc, failed_logins)}
                    </p>
                </div>
            </div>
            
            <!-- STATS GRID -->
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-value">{total_events}</div>
                    <div class="stat-label">Total Events</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" style="color: #dc3545;">{critical_count}</div>
                    <div class="stat-label">Critical Events</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" style="color: #fd7e14;">{high_count}</div>
                    <div class="stat-label">High Severity</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{len(affected_users)}</div>
                    <div class="stat-label">Affected Users</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{len(affected_hosts)}</div>
                    <div class="stat-label">Affected Hosts</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{len(iocs['ips'])}</div>
                    <div class="stat-label">Suspicious IPs</div>
                </div>
            </div>
            
            <!-- 2. INCIDENT OVERVIEW -->
            <div class="section">
                <div class="section-header">
                    <div class="section-title">
                        <span class="section-icon">📋</span> Incident Overview
                    </div>
                </div>
                <div class="section-content">
                    <div class="metrics-3col">
                        <div class="metric-item">
                            <div class="metric-value">{self._get_incident_category(severity_level)}</div>
                            <div class="metric-label">Incident Category</div>
                        </div>
                        <div class="metric-item">
                            <div class="metric-value">{len(df) if df is not None else 0}</div>
                            <div class="metric-label">Events Analyzed</div>
                        </div>
                        <div class="metric-item">
                            <div class="metric-value">{len(failed_logins)}</div>
                            <div class="metric-label">Authentication Failures</div>
                        </div>
                    </div>
                    <div class="metrics-3col">
                        <div class="metric-item">
                            <div class="metric-value">{len(suspicious_ps)}</div>
                            <div class="metric-label">Suspicious PowerShell</div>
                        </div>
                        <div class="metric-item">
                            <div class="metric-value">{len(lateral_movement)}</div>
                            <div class="metric-label">Lateral Movement Events</div>
                        </div>
                        <div class="metric-item">
                            <div class="metric-value">{len(privilege_esc)}</div>
                            <div class="metric-label">Privilege Escalation</div>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- 3. RISK ASSESSMENT -->
            <div class="section">
                <div class="section-header">
                    <div class="section-title">
                        <span class="section-icon">⚠️</span> Risk Assessment
                    </div>
                </div>
                <div class="section-content">
                    <div class="metrics-3col">
                        <div class="metric-item">
                            <div class="metric-value">{self._get_likelihood(risk_score)}</div>
                            <div class="metric-label">Threat Likelihood</div>
                        </div>
                        <div class="metric-item">
                            <div class="metric-value">{self._get_impact(risk_score)}</div>
                            <div class="metric-label">Business Impact</div>
                        </div>
                        <div class="metric-item">
                            <div class="metric-value">{self._get_sophistication(risk_score)}</div>
                            <div class="metric-label">Attack Sophistication</div>
                        </div>
                    </div>
                    
                    <h4 style="margin: 1rem 0 0.5rem 0; color: #00d4ff;">Risk Factors</h4>
                    <div class="stats-grid" style="margin-bottom: 0;">
                        <div class="stat-card"><span class="badge {'badge-critical' if suspicious_ps else 'badge-low'}">{
                            '✓' if suspicious_ps else '✗'
                        }</span> Malware Activity</div>
                        <div class="stat-card"><span class="badge {'badge-critical' if privilege_esc else 'badge-low'}">{
                            '✓' if privilege_esc else '✗'
                        }</span> Privilege Escalation</div>
                        <div class="stat-card"><span class="badge {'badge-critical' if lateral_movement else 'badge-low'}">{
                            '✓' if lateral_movement else '✗'
                        }</span> Lateral Movement</div>
                        <div class="stat-card"><span class="badge {'badge-critical' if len(failed_logins) > 50 else 'badge-low'}">{
                            '✓' if len(failed_logins) > 50 else '✗'
                        }</span> Credential Theft</div>
                        <div class="stat-card"><span class="badge {'badge-critical' if any(a.get('pattern') == 'ransomware_indicators' for a in findings.get('anomalies', [])) else 'badge-low'}">{
                            '✓' if any(a.get('pattern') == 'ransomware_indicators' for a in findings.get('anomalies', [])) else '✗'
                        }</span> Ransomware Indicators</div>
                    </div>
                </div>
            </div>
            
            <!-- 4. ATTACK NARRATIVE -->
            <div class="section">
                <div class="section-header">
                    <div class="section-title">
                        <span class="section-icon">📖</span> Attack Narrative
                    </div>
                </div>
                <div class="section-content">
                    <div class="attack-chain">
                        <div class="chain-phase"><div class="phase-number">1</div><div class="phase-name">Initial Access</div></div>
                        <div class="chain-phase"><div class="phase-number">2</div><div class="phase-name">Execution</div></div>
                        <div class="chain-phase"><div class="phase-number">3</div><div class="phase-name">Persistence</div></div>
                        <div class="chain-phase"><div class="phase-number">4</div><div class="phase-name">Priv Escalation</div></div>
                        <div class="chain-phase"><div class="phase-number">5</div><div class="phase-name">Lateral Movement</div></div>
                        <div class="chain-phase"><div class="phase-number">6</div><div class="phase-name">Collection</div></div>
                        <div class="chain-phase"><div class="phase-number">7</div><div class="phase-name">Exfiltration</div></div>
                        <div class="chain-phase"><div class="phase-number">8</div><div class="phase-name">Impact</div></div>
                    </div>
                    
                    <p style="margin-top: 1rem; line-height: 1.8;">
                        {self._generate_attack_narrative(suspicious_ps, lateral_movement, privilege_esc, failed_logins)}
                    </p>
                </div>
            </div>
            
            <!-- 5. INDICATORS OF COMPROMISE -->
            <div class="section">
                <div class="section-header">
                    <div class="section-title">
                        <span class="section-icon">🕵️</span> Indicators of Compromise (IOCs)
                    </div>
                </div>
                <div class="section-content">
                    <div class="iocs-grid">
                        <div class="ioc-category">
                            <div class="ioc-title">🌐 IP Addresses</div>
                            <ul class="ioc-list">
                                {self._render_ioc_list(iocs['ips'])}
                            </ul>
                        </div>
                        <div class="ioc-category">
                            <div class="ioc-title">👤 User Accounts</div>
                            <ul class="ioc-list">
                                {self._render_ioc_list(affected_users)}
                            </ul>
                        </div>
                        <div class="ioc-category">
                            <div class="ioc-title">🖥️ Hostnames</div>
                            <ul class="ioc-list">
                                {self._render_ioc_list(affected_hosts)}
                            </ul>
                        </div>
                    </div>
                    <div class="iocs-grid" style="margin-top: 1rem;">
                        <div class="ioc-category">
                            <div class="ioc-title">💻 Suspicious Commands</div>
                            <ul class="ioc-list">
                                {self._render_ioc_list(iocs['commands'])}
                            </ul>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- 6. REMEDIATION PLAN -->
            <div class="section">
                <div class="section-header">
                    <div class="section-title">
                        <span class="section-icon">🛡️</span> Remediation Plan
                    </div>
                </div>
                <div class="section-content">
                    <h4 style="color: #00d4ff; margin-bottom: 0.5rem;">🚨 Immediate Actions (0-24 Hours)</h4>
                    <ul style="margin-bottom: 1.5rem; margin-left: 1.5rem;">
                        {self._render_remediation_immediate(suspicious_ps, lateral_movement, privilege_esc, iocs['ips'])}
                    </ul>
                    
                    <h4 style="color: #00d4ff; margin-bottom: 0.5rem;">🛠️ Short-Term Actions (1-7 Days)</h4>
                    <ul style="margin-bottom: 1.5rem; margin-left: 1.5rem;">
                        <li>Run full antivirus/EDR scan on all affected systems</li>
                        <li>Review and audit all privilege assignments from the last 7 days</li>
                        <li>Implement JIT (Just-In-Time) access for privileged accounts</li>
                        <li>Enable enhanced logging on critical systems and services</li>
                    </ul>
                    
                    <h4 style="color: #00d4ff; margin-bottom: 0.5rem;">🔒 Long-Term Improvements (30+ Days)</h4>
                    <ul style="margin-left: 1.5rem;">
                        <li>Deploy Multi-Factor Authentication (MFA) for all administrative accounts</li>
                        <li>Implement Privileged Access Management (PAM) solution</li>
                        <li>Establish 24/7 security monitoring and incident response capability</li>
                        <li>Conduct regular security awareness training for all employees</li>
                        <li>Maintain offline, immutable backups of critical data</li>
                    </ul>
                </div>
            </div>
            
            <!-- 7. CONFIDENCE & FINAL VERDICT -->
            <div class="section">
                <div class="section-header">
                    <div class="section-title">
                        <span class="section-icon">✅</span> Confidence Assessment & Final Verdict
                    </div>
                </div>
                <div class="section-content">
                    <div class="confidence-meter">
                        <div class="confidence-fill"></div>
                    </div>
                    <div class="metrics-3col">
                        <div class="metric-item">
                            <div class="metric-value">{confidence}%</div>
                            <div class="metric-label">Overall Confidence</div>
                        </div>
                        <div class="metric-item">
                            <div class="metric-value">{min(85, confidence + 10)}%</div>
                            <div class="metric-label">Evidence Quality</div>
                        </div>
                        <div class="metric-item">
                            <div class="metric-value">{min(70, confidence)}%</div>
                            <div class="metric-label">Correlation Confidence</div>
                        </div>
                    </div>
                    
                    <h4 style="color: #00d4ff; margin: 1rem 0 0.5rem 0;">🎯 Final Verdict</h4>
                    <div class="risk-banner" style="margin-top: 0;">
                        <p style="font-size: 1rem; line-height: 1.6;">
                            <strong>Incident Classification:</strong> {self._get_incident_category(severity_level)}<br>
                            <strong>Recommended Priority:</strong> {self._get_priority(risk_score)}<br>
                            <strong>Investigation Conclusion:</strong> {self._get_conclusion(risk_score, suspicious_ps, lateral_movement)}
                        </p>
                    </div>
                </div>
            </div>
            
        </div>
        
        <!-- FOOTER -->
        <div class="report-footer">
            <p>🛡️ SOC Investigation Report | Generated by AI SOC Analyst Agent | 100% Local Processing</p>
            <p>This report is confidential and intended for authorized security personnel only.</p>
            <p style="margin-top: 0.5rem;">Report ID: {self.report_id} | Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
        
    </div>
</body>
</html>"""
        
        return html
    
    def _render_ioc_list(self, items: List) -> str:
        """Render IOC list as HTML"""
        if not items:
            return '<li style="color: #6e7681;">None detected</li>'
        return ''.join([f'<li>🔴 {str(item)[:50]}</li>' for item in items[:15]])
    
    def _render_remediation_immediate(self, suspicious_ps, lateral_movement, privilege_esc, ips) -> str:
        """Render immediate remediation steps"""
        steps = []
        if suspicious_ps:
            steps.append("<li>Isolate affected endpoints from the network immediately</li>")
            steps.append("<li>Kill all suspicious PowerShell processes</li>")
        if lateral_movement:
            steps.append("<li>Block identified suspicious source IPs at the perimeter firewall</li>")
        if privilege_esc:
            steps.append("<li>Force password reset for all privileged accounts</li>")
            steps.append("<li>Revoke unauthorized admin role assignments</li>")
        if ips:
            steps.append("<li>Block all identified malicious IP addresses</li>")
        
        if not steps:
            steps.append("<li>Review all findings for false positives</li>")
            steps.append("<li>Verify log sources and time synchronization</li>")
        
        return '\n'.join(steps[:5])
    
    def _get_incident_type(self, suspicious_ps, lateral_movement, privilege_esc) -> str:
        """Get incident type description"""
        if suspicious_ps:
            return "malicious PowerShell execution"
        if lateral_movement:
            return "lateral movement activity"
        if privilege_esc:
            return "privilege escalation attempts"
        return "suspicious security events"
    
    def _get_incident_category(self, severity: str) -> str:
        """Get incident category"""
        if severity == "CRITICAL":
            return "Active Compromise / Ransomware"
        elif severity == "HIGH":
            return "Potential Data Breach"
        elif severity == "MEDIUM":
            return "Suspicious Activity"
        else:
            return "Informational"
    
    def _get_likelihood(self, score: int) -> str:
        """Get likelihood based on score"""
        if score >= 70:
            return "VERY LIKELY"
        elif score >= 40:
            return "LIKELY"
        elif score >= 20:
            return "POSSIBLE"
        return "UNLIKELY"
    
    def _get_impact(self, score: int) -> str:
        """Get impact based on score"""
        if score >= 70:
            return "CRITICAL"
        elif score >= 40:
            return "HIGH"
        elif score >= 20:
            return "MEDIUM"
        return "LOW"
    
    def _get_sophistication(self, score: int) -> str:
        """Get attack sophistication"""
        if score >= 70:
            return "Advanced"
        elif score >= 40:
            return "Intermediate"
        return "Basic"
    
    def _get_priority(self, score: int) -> str:
        """Get response priority"""
        if score >= 70:
            return "CRITICAL - IMMEDIATE RESPONSE"
        elif score >= 40:
            return "HIGH - RESPOND WITHIN 4 HOURS"
        elif score >= 20:
            return "MEDIUM - RESPOND WITHIN 24 HOURS"
        return "LOW - ROUTINE MONITORING"
    
    def _get_conclusion(self, score: int, suspicious_ps, lateral_movement) -> str:
        """Get investigation conclusion"""
        if score >= 70:
            return "Active compromise confirmed. Immediate containment required."
        elif score >= 40:
            return "Strong evidence of suspicious activity. Urgent investigation recommended."
        elif suspicious_ps or lateral_movement:
            return "Anomalous behavior detected. Further investigation warranted."
        return "No immediate threats identified. Continue standard monitoring."
    
    def _get_incident_description(self, suspicious_ps, lateral_movement, privilege_esc, failed_logins) -> str:
        """Get detailed incident description"""
        if suspicious_ps:
            return f"<strong>Impact:</strong> Active compromise indicators with potential for data loss and system takeover. <strong>Priority:</strong> Immediate incident response required."
        elif lateral_movement:
            return f"<strong>Impact:</strong> Attacker appears to be moving laterally across the environment. <strong>Priority:</strong> Block identified IPs and isolate affected hosts."
        elif privilege_esc:
            return f"<strong>Impact:</strong> Unauthorized elevation of privileges detected. <strong>Priority:</strong> Reset privileged credentials immediately."
        elif len(failed_logins) > 20:
            return f"<strong>Impact:</strong> Credential brute force attempt detected. <strong>Priority:</strong> Enable MFA and block offending IPs."
        else:
            return f"<strong>Impact:</strong> Anomalous patterns detected requiring investigation. <strong>Priority:</strong> Review findings within 24 hours."
    
    def _generate_attack_narrative(self, suspicious_ps, lateral_movement, privilege_esc, failed_logins) -> str:
        """Generate attack narrative"""
        narrative = []
        
        if failed_logins and len(failed_logins) > 10:
            narrative.append("1. <strong>Initial Access:</strong> Multiple authentication failures detected, suggesting credential brute force or password spraying attempts against user accounts.")
        
        if privilege_esc:
            narrative.append("2. <strong>Privilege Escalation:</strong> Unauthorized administrative role assignments observed following authentication anomalies, indicating potential successful compromise.")
        
        if lateral_movement:
            narrative.append("3. <strong>Lateral Movement:</strong> Remote execution attempts detected across the environment, suggesting attacker is moving laterally between systems.")
        
        if suspicious_ps:
            narrative.append("4. <strong>Execution:</strong> Suspicious PowerShell commands detected, including encoded and obfuscated scripts commonly associated with malware deployment.")
        
        narrative.append("5. <strong>Impact:</strong> Critical systems and sensitive data potentially compromised. Immediate containment and eradication required.")
        
        return ' '.join(narrative)


def generate_full_soc_report(findings: Dict, df: pd.DataFrame = None) -> str:
    """Generate complete SOC report from findings"""
    generator = SOCReportGenerator()
    return generator.generate_full_report(findings, df)