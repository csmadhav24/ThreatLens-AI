# app/remediation/playbooks.py
"""
Remediation Playbooks Module - Incident response procedures
Features: MITRE ATT&CK mapping, specific commands, severity-based playbooks
"""

import json
from datetime import datetime
from typing import Dict, List, Any, Optional
from enum import Enum

# Import config
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))
from config import RISK_LEVELS


class PlaybookSeverity(Enum):
    """Playbook severity levels"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class RemediationPlaybooks:
    """
    Central repository of remediation playbooks for SOC investigations
    """
    
    # Master playbook database
    PLAYBOOKS = {
        # ============================================
        # AUTHENTICATION & ACCESS CONTROL
        # ============================================
        "brute_force_attack": {
            "id": "SOC-IR-001",
            "title": "Brute Force / Password Spraying Attack",
            "severity": PlaybookSeverity.HIGH,
            "mitre_tactic": "TA0006 - Credential Access",
            "mitre_technique": "T1110 - Brute Force",
            "detection_method": "Multiple failed logins (Event ID 4625) from same IP",
            "containment_steps": [
                {
                    "step": 1,
                    "action": "Identify attacking IP addresses",
                    "command": "Get-EventLog -LogName Security -InstanceId 4625 | Group-Object -Property ReplacementStrings | Select-Object -First 20 | Format-Table",
                    "platform": "windows",
                    "estimated_time": "2 minutes"
                },
                {
                    "step": 2,
                    "action": "Block attacking IPs at network perimeter",
                    "command": "New-NetFirewallRule -DisplayName 'SOC_Block_BruteForce' -Direction Inbound -RemoteAddress <ATTACKER_IP> -Action Block",
                    "platform": "windows",
                    "alternative": "Contact network team to block at firewall level",
                    "estimated_time": "5 minutes"
                },
                {
                    "step": 3,
                    "action": "Check for successful logins from attacker IP",
                    "command": "Get-EventLog -LogName Security -InstanceId 4624 | Where-Object {$_.ReplacementStrings[5] -eq '<ATTACKER_IP>'} | Select-Object -First 10",
                    "platform": "windows",
                    "estimated_time": "3 minutes"
                },
                {
                    "step": 4,
                    "action": "Reset passwords for compromised accounts",
                    "command": "net user <USERNAME> /domain /reset-password",
                    "platform": "windows",
                    "estimated_time": "5 minutes per account"
                },
                {
                    "step": 5,
                    "action": "Enable account lockout policy",
                    "command": "net accounts /lockoutthreshold:5 /lockoutduration:30 /lockoutwindow:30",
                    "platform": "windows",
                    "estimated_time": "5 minutes"
                },
                {
                    "step": 6,
                    "action": "Enable MFA for affected accounts",
                    "command": "Connect to Azure AD / Identity Provider console",
                    "platform": "cloud",
                    "estimated_time": "15 minutes"
                }
            ],
            "eradication_steps": [
                "Review all accounts for unauthorized access",
                "Analyze source IP geolocation and reputation",
                "Check for malware on compromised endpoints"
            ],
            "recovery_steps": [
                "Verify no persistent access established",
                "Monitor for follow-up attacks",
                "Document incident timeline"
            ],
            "verification": "Monitor failed login count for next 30 minutes - should drop to normal levels",
            "post_incident_actions": [
                "Update firewall rules permanently",
                "Implement geo-blocking if applicable",
                "Conduct password policy review"
            ]
        },
        
        "suspicious_powershell": {
            "id": "SOC-IR-002",
            "title": "Suspicious PowerShell Execution - Potential Malware",
            "severity": PlaybookSeverity.CRITICAL,
            "mitre_tactic": "TA0002 - Execution",
            "mitre_technique": "T1059.001 - PowerShell",
            "detection_method": "PowerShell with encoded commands, download cradle, or obfuscation",
            "containment_steps": [
                {
                    "step": 1,
                    "action": "Isolate affected endpoint immediately",
                    "command": "New-NetFirewallRule -DisplayName 'Isolate_Host' -Direction Outbound -Action Block -RemoteAddress Any",
                    "platform": "windows",
                    "estimated_time": "2 minutes"
                },
                {
                    "step": 2,
                    "action": "Capture full PowerShell command line arguments",
                    "command": "Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; ID=4104} | Where-Object {$_.Message -like '*<SUSPICIOUS_COMMAND>*'} | Select-Object -First 50 | Format-List",
                    "platform": "windows",
                    "estimated_time": "5 minutes"
                },
                {
                    "step": 3,
                    "action": "Decode base64 PowerShell commands",
                    "command": "[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('<BASE64_STRING>'))",
                    "platform": "windows",
                    "estimated_time": "3 minutes"
                },
                {
                    "step": 4,
                    "action": "Check for network connections from PowerShell",
                    "command": "Get-NetTCPConnection | Where-Object {$_.OwningProcess -eq (Get-Process -Name powershell).Id}",
                    "platform": "windows",
                    "estimated_time": "3 minutes"
                },
                {
                    "step": 5,
                    "action": "Scan for malware using EDR/AV",
                    "command": "Start-MpScan -ScanType QuickScan",
                    "platform": "windows",
                    "estimated_time": "10 minutes"
                },
                {
                    "step": 6,
                    "action": "Collect forensic artifacts",
                    "command": "Get-Process | Export-Csv -Path C:\\temp\\processes.csv; Get-Service | Export-Csv -Path C:\\temp\\services.csv",
                    "platform": "windows",
                    "estimated_time": "10 minutes"
                }
            ],
            "eradication_steps": [
                "Kill suspicious PowerShell processes",
                "Remove any downloaded files",
                "Delete scheduled tasks created by PowerShell",
                "Clear PowerShell history"
            ],
            "recovery_steps": [
                "Restore from clean backup if system compromised",
                "Reinstall endpoint if heavily infected",
                "Apply Windows updates"
            ],
            "verification": "No new PowerShell processes with suspicious arguments",
            "post_incident_actions": [
                "Enable PowerShell logging (ScriptBlock, Module, Transcription)",
                "Configure AppLocker or WDAC",
                "Restrict PowerShell to constrained language mode"
            ]
        },
        
        "privilege_escalation": {
            "id": "SOC-IR-003",
            "title": "Privilege Escalation Detected",
            "severity": PlaybookSeverity.CRITICAL,
            "mitre_tactic": "TA0004 - Privilege Escalation",
            "mitre_technique": "T1068 - Exploitation for Privilege Escalation",
            "detection_method": "Special privileges assigned (Event ID 4672) or sensitive privilege use",
            "containment_steps": [
                {
                    "step": 1,
                    "action": "Identify escalated account and affected systems",
                    "command": "Get-EventLog -LogName Security -InstanceId 4672 | Select-Object -First 20 TimeGenerated, User, Message",
                    "platform": "windows",
                    "estimated_time": "3 minutes"
                },
                {
                    "step": 2,
                    "action": "Force logout of suspicious user sessions",
                    "command": "logoff <SESSION_ID>; or: Get-Process -IncludeUserName | Where-Object UserName -like '*<USER>*' | Stop-Process -Force",
                    "platform": "windows",
                    "estimated_time": "3 minutes"
                },
                {
                    "step": 3,
                    "action": "Disable compromised accounts",
                    "command": "Disable-ADAccount -Identity <USERNAME>",
                    "platform": "windows",
                    "estimated_time": "2 minutes"
                },
                {
                    "step": 4,
                    "action": "Check for new admin account creation",
                    "command": "Get-LocalGroupMember -Group 'Administrators' | Where-Object {$_.Name -notlike '*Administrator*'}",
                    "platform": "windows",
                    "estimated_time": "3 minutes"
                },
                {
                    "step": 5,
                    "action": "Review scheduled tasks for persistence",
                    "command": "Get-ScheduledTask | Where-Object {$_.State -ne 'Disabled'} | Get-ScheduledTaskInfo",
                    "platform": "windows",
                    "estimated_time": "5 minutes"
                },
                {
                    "step": 6,
                    "action": "Check for unauthorized service creation",
                    "command": "Get-WmiObject -Class Win32_Service | Where-Object {$_.StartMode -eq 'Auto' -and $_.PathName -like '*temp*'}",
                    "platform": "windows",
                    "estimated_time": "5 minutes"
                }
            ],
            "eradication_steps": [
                "Remove malicious users from privileged groups",
                "Delete unauthorized scheduled tasks",
                "Remove malicious services",
                "Apply security patches for known escalation vectors"
            ],
            "recovery_steps": [
                "Reset all passwords for affected accounts",
                "Enable LAPS for local admin password management",
                "Review and audit all privilege assignments"
            ],
            "verification": "Run: whoami /priv on affected hosts - should show expected privileges only",
            "post_incident_actions": [
                "Implement Privileged Access Workstations (PAWs)",
                "Enable Just-In-Time (JIT) access",
                "Deploy PAM solution"
            ]
        },
        
        "lateral_movement": {
            "id": "SOC-IR-004",
            "title": "Lateral Movement Detected",
            "severity": PlaybookSeverity.CRITICAL,
            "mitre_tactic": "TA0008 - Lateral Movement",
            "mitre_technique": "T1021 - Remote Services",
            "detection_method": "PsExec, WMIC, WinRM, or other remote execution tools",
            "containment_steps": [
                {
                    "step": 1,
                    "action": "Identify source and destination hosts",
                    "command": "Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4688} | Where-Object {$_.Message -like '*psexec*' -or $_.Message -like '*wmic*'}",
                    "platform": "windows",
                    "estimated_time": "5 minutes"
                },
                {
                    "step": 2,
                    "action": "Isolate affected source host",
                    "command": "New-NetFirewallRule -DisplayName 'Containment' -Direction Outbound -Action Block -RemoteAddress Any",
                    "platform": "windows",
                    "estimated_time": "3 minutes"
                },
                {
                    "step": 3,
                    "action": "Block PsExec and WMIC across environment",
                    "command": "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\System' -Name 'EnablePSExec' -Value 0; Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name 'EnableWMIC' -Value 0",
                    "platform": "windows",
                    "estimated_time": "5 minutes"
                },
                {
                    "step": 4,
                    "action": "Check for credential dumping tools",
                    "command": "Get-Process | Where-Object {$_.ProcessName -match 'mimikatz|procdump|lsass'}",
                    "platform": "windows",
                    "estimated_time": "3 minutes"
                },
                {
                    "step": 5,
                    "action": "Force password reset for potentially compromised accounts",
                    "command": "Get-ADUser -Filter * | Where-Object {$_.LastLogonDate -gt (Get-Date).AddDays(-7)} | Set-ADAccountPassword -Reset",
                    "platform": "windows",
                    "estimated_time": "15 minutes"
                }
            ],
            "eradication_steps": [
                "Remove remote management tools if not needed",
                "Clean up any created services or scheduled tasks",
                "Disable unused administrative shares (C$, ADMIN$)"
            ],
            "recovery_steps": [
                "Rebuild compromised hosts from clean images",
                "Rotate all Kerberos tickets (KRBTGT)",
                "Reset machine account passwords"
            ],
            "verification": "Monitor for unexpected network connections and remote executions for next 24 hours",
            "post_incident_actions": [
                "Implement network segmentation",
                "Deploy EDR with lateral movement detection",
                "Restrict administrative access using JIT"
            ]
        },
        
        "data_exfiltration": {
            "id": "SOC-IR-005",
            "title": "Potential Data Exfiltration",
            "severity": PlaybookSeverity.CRITICAL,
            "mitre_tactic": "TA0010 - Exfiltration",
            "mitre_technique": "T1048 - Exfiltration Over Alternative Protocol",
            "detection_method": "Large outbound data transfers, unusual destinations",
            "containment_steps": [
                {
                    "step": 1,
                    "action": "Identify destination IPs and data volume",
                    "command": "Get-NetTCPConnection | Group-Object RemoteAddress | Select-Object Name, Count | Sort-Object Count -Descending",
                    "platform": "windows",
                    "estimated_time": "5 minutes"
                },
                {
                    "step": 2,
                    "action": "Block outbound traffic to suspicious destinations",
                    "command": "New-NetFirewallRule -DisplayName 'Block_Exfil' -Direction Outbound -RemoteAddress <SUSPICIOUS_IP> -Action Block",
                    "platform": "windows",
                    "estimated_time": "3 minutes"
                },
                {
                    "step": 3,
                    "action": "Identify what data was accessed/exfiltrated",
                    "command": "Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4663} | Where-Object {$_.Message -like '*Read*' -or $_.Message -like '*Copy*'} | Select-Object -First 100",
                    "platform": "windows",
                    "estimated_time": "10 minutes"
                },
                {
                    "step": 4,
                    "action": "Check for compressed/archived data",
                    "command": "Get-ChildItem -Path C:\\ -Recurse -Include *.zip,*.7z,*.rar -ErrorAction SilentlyContinue | Where-Object {$_.LastWriteTime -gt (Get-Date).AddHours(-24)}",
                    "platform": "windows",
                    "estimated_time": "10 minutes"
                },
                {
                    "step": 5,
                    "action": "Preserve firewall and proxy logs for investigation",
                    "command": "wevtutil epl Microsoft-Windows-WindowsFirewall-Firewall%4Operational.evtx C:\\temp\\firewall_logs.evtx",
                    "platform": "windows",
                    "estimated_time": "5 minutes"
                }
            ],
            "eradication_steps": [
                "Isolate affected data sources",
                "Revoke compromised credentials",
                "Rotate database credentials if applicable"
            ],
            "recovery_steps": [
                "Assess data breach impact",
                "Notify legal and compliance teams",
                "Prepare breach notification if PII involved"
            ],
            "verification": "Network traffic baseline restored to normal levels",
            "post_incident_actions": [
                "Implement DLP solution",
                "Enable data classification and labeling",
                "Review and enhance network monitoring"
            ]
        },
        
        "malware_infection": {
            "id": "SOC-IR-006",
            "title": "Malware / Ransomware Infection",
            "severity": PlaybookSeverity.CRITICAL,
            "mitre_tactic": "TA0040 - Impact",
            "mitre_technique": "T1486 - Data Encrypted for Impact",
            "detection_method": "Unusual file extensions, ransom notes, high CPU usage",
            "containment_steps": [
                {
                    "step": 1,
                    "action": "IMMEDIATE ISOLATION - Disable network interface",
                    "command": "Get-NetAdapter | Disable-NetAdapter -Confirm:$false",
                    "platform": "windows",
                    "estimated_time": "1 minute",
                    "critical": True
                },
                {
                    "step": 2,
                    "action": "Disable network shares",
                    "command": "Stop-Service LanmanServer -Force; Set-Service LanmanServer -StartupType Disabled",
                    "platform": "windows",
                    "estimated_time": "2 minutes"
                },
                {
                    "step": 3,
                    "action": "Kill suspicious processes",
                    "command": "Get-Process | Where-Object {$_.CPU -gt 50 -or $_.ProcessName -like '*ransom*'} | Stop-Process -Force",
                    "platform": "windows",
                    "estimated_time": "3 minutes"
                },
                {
                    "step": 4,
                    "action": "Disable all scheduled tasks",
                    "command": "Get-ScheduledTask | Disable-ScheduledTask",
                    "platform": "windows",
                    "estimated_time": "3 minutes"
                },
                {
                    "step": 5,
                    "action": "Initiate incident response team",
                    "command": "Contact SOC and CIRT immediately",
                    "platform": "process",
                    "estimated_time": "1 minute"
                }
            ],
            "eradication_steps": [
                "Take affected host offline completely",
                "Format and reinstall operating system",
                "Restore from clean backups",
                "Scan all connected network drives"
            ],
            "recovery_steps": [
                "Restore data from offline backups",
                "Apply all security patches",
                "Enhance endpoint protection"
            ],
            "verification": "System clean after full scan; no encryption activity detected",
            "post_incident_actions": [
                "Review backup strategy (offline, immutable)",
                "Implement application whitelisting",
                "Deploy endpoint detection and response (EDR)"
            ]
        },
        
        # ============================================
        # NETWORK THREATS
        # ============================================
        "port_scan": {
            "id": "SOC-IR-007",
            "title": "Port Scan / Network Reconnaissance",
            "severity": PlaybookSeverity.MEDIUM,
            "mitre_tactic": "TA0043 - Reconnaissance",
            "mitre_technique": "T1046 - Network Service Scanning",
            "detection_method": "Multiple connection attempts to different ports",
            "containment_steps": [
                {
                    "step": 1,
                    "action": "Identify scanning source IP",
                    "command": "Get-NetTCPConnection | Group-Object RemoteAddress | Where-Object {$_.Count -gt 100} | Select-Object Name, Count",
                    "platform": "windows",
                    "estimated_time": "3 minutes"
                },
                {
                    "step": 2,
                    "action": "Block scanning IP",
                    "command": "New-NetFirewallRule -DisplayName 'Block_PortScan' -Direction Inbound -RemoteAddress <SCANNER_IP> -Action Block",
                    "platform": "windows",
                    "estimated_time": "2 minutes"
                },
                {
                    "step": 3,
                    "action": "Check if scanner successfully accessed any service",
                    "command": "Get-NetTCPConnection | Where-Object {$_.RemoteAddress -eq '<SCANNER_IP>' -and $_.State -eq 'Established'}",
                    "platform": "windows",
                    "estimated_time": "3 minutes"
                },
                {
                    "step": 4,
                    "action": "Review vulnerable services on targeted ports",
                    "command": "Get-Service | Where-Object {$_.Status -eq 'Running'} | Select-Object Name, DisplayName",
                    "platform": "windows",
                    "estimated_time": "5 minutes"
                }
            ],
            "eradication_steps": [
                "Close unnecessary open ports",
                "Implement port knocking or allowlisting",
                "Apply patches to vulnerable services"
            ],
            "recovery_steps": [
                "Monitor for follow-up attacks",
                "Adjust IDS/IPS rules"
            ],
            "verification": "No further scan traffic from blocked IP",
            "post_incident_actions": [
                "Implement network segmentation",
                "Deploy honeypots for early detection"
            ]
        },
        
        # ============================================
        # GENERIC / CUSTOM
        # ============================================
        "generic_compromise": {
            "id": "SOC-IR-008",
            "title": "Security Incident - General Compromise",
            "severity": PlaybookSeverity.HIGH,
            "mitre_tactic": "Unknown",
            "mitre_technique": "Unknown",
            "detection_method": "SOC investigation findings",
            "containment_steps": [
                {
                    "step": 1,
                    "action": "Document all findings and indicators",
                    "command": "Export investigation results to CSV/JSON for evidence",
                    "platform": "process",
                    "estimated_time": "10 minutes"
                },
                {
                    "step": 2,
                    "action": "Isolate affected systems",
                    "command": "Network isolation or host blocking",
                    "platform": "network",
                    "estimated_time": "5 minutes"
                },
                {
                    "step": 3,
                    "action": "Preserve forensic artifacts",
                    "command": "Capture memory, logs, and disk images",
                    "platform": "forensics",
                    "estimated_time": "30 minutes"
                },
                {
                    "step": 4,
                    "action": "Reset compromised credentials",
                    "command": "Force password reset for affected accounts",
                    "platform": "identity",
                    "estimated_time": "10 minutes"
                }
            ],
            "eradication_steps": [
                "Remove malware/tools from system",
                "Apply security patches",
                "Close attack vectors"
            ],
            "recovery_steps": [
                "Restore from clean backup",
                "Monitor for re-infection",
                "Update incident documentation"
            ],
            "verification": "All indicators of compromise eliminated",
            "post_incident_actions": [
                "Conduct post-mortem analysis",
                "Update security controls",
                "Enhance monitoring rules"
            ]
        }
    }
    
    @classmethod
    def get_playbook(cls, finding_type: str) -> Optional[Dict]:
        """
        Retrieve a playbook by finding type
        
        Args:
            finding_type: Type of finding (e.g., 'brute_force_attack', 'suspicious_powershell')
            
        Returns:
            Playbook dictionary or None
        """
        return cls.PLAYBOOKS.get(finding_type)
    
    @classmethod
    def get_playbook_by_severity(cls, severity: PlaybookSeverity) -> List[Dict]:
        """
        Get all playbooks of a specific severity
        
        Args:
            severity: PlaybookSeverity enum value
            
        Returns:
            List of playbooks
        """
        return [
            playbook for playbook in cls.PLAYBOOKS.values()
            if playbook['severity'] == severity
        ]
    
    @classmethod
    def get_playbook_by_mitre_technique(cls, technique_id: str) -> Optional[Dict]:
        """
        Find playbook by MITRE ATT&CK technique ID
        
        Args:
            technique_id: MITRE technique ID (e.g., 'T1110')
            
        Returns:
            Playbook or None
        """
        for playbook in cls.PLAYBOOKS.values():
            if technique_id in playbook.get('mitre_technique', ''):
                return playbook
        return None
    
    @classmethod
    def get_all_playbooks(cls) -> Dict[str, Dict]:
        """Get all playbooks"""
        return cls.PLAYBOOKS
    
    @classmethod
    def get_playbook_summary(cls, finding_type: str) -> Dict[str, Any]:
        """
        Get a summary of the playbook (without full commands)
        
        Args:
            finding_type: Type of finding
            
        Returns:
            Summary dictionary
        """
        playbook = cls.get_playbook(finding_type)
        if not playbook:
            return {'error': f'No playbook found for {finding_type}'}
        
        return {
            'id': playbook['id'],
            'title': playbook['title'],
            'severity': playbook['severity'].value,
            'mitre_tactic': playbook['mitre_tactic'],
            'mitre_technique': playbook['mitre_technique'],
            'total_containment_steps': len(playbook.get('containment_steps', [])),
            'estimated_response_time': cls._calculate_response_time(playbook)
        }
    
    @classmethod
    def _calculate_response_time(cls, playbook: Dict) -> str:
        """Calculate estimated total response time"""
        total_minutes = 0
        for step in playbook.get('containment_steps', []):
            time_str = step.get('estimated_time', '5 minutes')
            # Extract number from string like "5 minutes"
            import re
            numbers = re.findall(r'\d+', time_str)
            if numbers:
                total_minutes += int(numbers[0])
        
        if total_minutes < 60:
            return f"{total_minutes} minutes"
        else:
            return f"{total_minutes // 60} hours {total_minutes % 60} minutes"
    
    @classmethod
    def generate_response_plan(cls, findings: List[Dict]) -> Dict[str, Any]:
        """
        Generate a complete response plan based on multiple findings
        
        Args:
            findings: List of finding dictionaries from ThreatDetector
            
        Returns:
            Complete response plan
        """
        response_plan = {
            'timestamp': datetime.now().isoformat(),
            'total_findings': len(findings),
            'priority_order': [],
            'playbooks': [],
            'critical_actions': [],
            'estimated_total_time': ''
        }
        
        # Sort findings by severity
        severity_order = {
            'CRITICAL': 0,
            'HIGH': 1,
            'MEDIUM': 2,
            'LOW': 3,
            'INFO': 4
        }
        
        sorted_findings = sorted(
            findings,
            key=lambda x: severity_order.get(x.get('severity', 'LOW'), 5)
        )
        
        # Map findings to playbooks
        for finding in sorted_findings:
            finding_type = cls._map_finding_to_playbook(finding)
            playbook = cls.get_playbook(finding_type)
            
            if playbook:
                response_plan['priority_order'].append({
                    'finding': finding.get('type', 'unknown'),
                    'severity': finding.get('severity', 'MEDIUM'),
                    'playbook_id': playbook['id'],
                    'playbook_title': playbook['title']
                })
                
                # Extract critical actions (first step of critical playbooks)
                if playbook['severity'] in [PlaybookSeverity.CRITICAL, PlaybookSeverity.HIGH]:
                    first_step = playbook.get('containment_steps', [{}])[0]
                    response_plan['critical_actions'].append({
                        'playbook': playbook['title'],
                        'action': first_step.get('action', 'Start investigation'),
                        'command': first_step.get('command', 'See playbook for details')
                    })
                
                response_plan['playbooks'].append(playbook)
        
        return response_plan
    
    @classmethod
    def _map_finding_to_playbook(cls, finding: Dict) -> str:
        """Map a finding dictionary to a playbook type"""
        finding_type = finding.get('type', '').lower()
        
        # Map finding types to playbook keys
        mapping = {
            'brute_force': 'brute_force_attack',
            'failed_login': 'brute_force_attack',
            'powershell': 'suspicious_powershell',
            'suspicious_powershell': 'suspicious_powershell',
            'privilege_escalation': 'privilege_escalation',
            'lateral_movement': 'lateral_movement',
            'exfiltration': 'data_exfiltration',
            'malware': 'malware_infection',
            'ransomware': 'malware_infection',
            'port_scan': 'port_scan',
            'scan': 'port_scan'
        }
        
        for key, playbook_key in mapping.items():
            if key in finding_type:
                return playbook_key
        
        return 'generic_compromise'
    
    @classmethod
    def export_playbook(cls, finding_type: str, format: str = 'json') -> str:
        """
        Export a playbook to specified format
        
        Args:
            finding_type: Type of finding
            format: 'json', 'markdown', or 'pdf'
            
        Returns:
            Formatted playbook string
        """
        playbook = cls.get_playbook(finding_type)
        if not playbook:
            return json.dumps({'error': f'Playbook not found: {finding_type}'})
        
        if format == 'json':
            # Convert severity enum to string for JSON serialization
            playbook_copy = playbook.copy()
            playbook_copy['severity'] = playbook_copy['severity'].value
            return json.dumps(playbook_copy, indent=2, default=str)
        
        elif format == 'markdown':
            markdown = f"""# {playbook['title']}

## Incident Response Playbook
- **ID:** {playbook['id']}
- **Severity:** {playbook['severity'].value}
- **MITRE Tactic:** {playbook['mitre_tactic']}
- **MITRE Technique:** {playbook['mitre_technique']}
- **Detection Method:** {playbook['detection_method']}

## Containment Steps
"""
            for step in playbook.get('containment_steps', []):
                markdown += f"\n### Step {step['step']}: {step['action']}\n"
                markdown += f"- **Command:** `{step['command']}`\n"
                markdown += f"- **Platform:** {step['platform']}\n"
                markdown += f"- **Estimated Time:** {step['estimated_time']}\n"
            
            markdown += "\n## Eradication Steps\n"
            for step in playbook.get('eradication_steps', []):
                markdown += f"- {step}\n"
            
            markdown += "\n## Recovery Steps\n"
            for step in playbook.get('recovery_steps', []):
                markdown += f"- {step}\n"
            
            markdown += f"\n## Verification\n{playbook['verification']}\n"
            
            return markdown
        
        return json.dumps(playbook, indent=2, default=str)


# ============================================
# CONVENIENCE FUNCTIONS
# ============================================

def get_remediation_plan(finding_type: str) -> Optional[Dict]:
    """Quick helper to get a remediation plan"""
    return RemediationPlaybooks.get_playbook(finding_type)


def generate_incident_response(findings: List[Dict]) -> Dict[str, Any]:
    """Generate complete incident response plan from findings"""
    return RemediationPlaybooks.generate_response_plan(findings)


def list_all_playbooks() -> List[Dict]:
    """List all available playbooks with summaries"""
    summaries = []
    for playbook_key in RemediationPlaybooks.PLAYBOOKS.keys():
        summaries.append(RemediationPlaybooks.get_playbook_summary(playbook_key))
    return summaries


# ============================================
# TESTING CODE
# ============================================

if __name__ == "__main__":
    print("🛡️ Testing Remediation Playbooks Module")
    print("=" * 60)
    
    # Test 1: Get a specific playbook
    print("\n📋 Test 1: Get Brute Force Playbook")
    playbook = RemediationPlaybooks.get_playbook("brute_force_attack")
    if playbook:
        print(f"   ✅ Found: {playbook['title']}")
        print(f"   Severity: {playbook['severity'].value}")
        print(f"   MITRE: {playbook['mitre_technique']}")
        print(f"   Containment Steps: {len(playbook['containment_steps'])}")
    
    # Test 2: Get playbook summary
    print("\n📋 Test 2: Get Playbook Summary")
    summary = RemediationPlaybooks.get_playbook_summary("suspicious_powershell")
    print(f"   {summary['title']} - {summary['estimated_response_time']}")
    
    # Test 3: Generate response plan from findings
    print("\n📋 Test 3: Generate Incident Response Plan")
    sample_findings = [
        {'type': 'brute_force', 'severity': 'HIGH'},
        {'type': 'suspicious_powershell', 'severity': 'CRITICAL'},
        {'type': 'port_scan', 'severity': 'MEDIUM'}
    ]
    
    response_plan = RemediationPlaybooks.generate_response_plan(sample_findings)
    print(f"   Total Findings: {response_plan['total_findings']}")
    print(f"   Priority Actions: {len(response_plan['critical_actions'])}")
    
    for action in response_plan['critical_actions'][:2]:
        print(f"   🔴 {action['playbook']}: {action['action'][:50]}...")
    
    # Test 4: Export playbook as markdown
    print("\n📋 Test 4: Export Playbook as Markdown")
    markdown = RemediationPlaybooks.export_playbook("port_scan", format='markdown')
    print(f"   Markdown length: {len(markdown)} characters")
    print(f"   Preview: {markdown[:200]}...")
    
    # Test 5: List all playbooks
    print("\n📋 Test 5: All Available Playbooks")
    all_playbooks = list_all_playbooks()
    for pb in all_playbooks[:5]:
        print(f"   {pb['id']}: {pb['title']} ({pb['severity']})")
    
    print("\n" + "=" * 60)
    print("✅ Remediation Playbooks Module Ready")