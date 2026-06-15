# app/reporting/mitre_mapper.py
"""
MITRE ATT&CK Mapper Module
Maps security findings to MITRE ATT&CK tactics, techniques, and procedures (TTPs)
Provides industry-standard threat classification
"""

import json
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime
from collections import defaultdict
import hashlib

# Import config
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))


class MITREMapper:
    """
    Maps security findings to MITRE ATT&CK Framework
    Includes tactics, techniques, mitigations, and detection methods
    """
    
    # Complete MITRE ATT&CK Tactics (Enterprise)
    MITRE_TACTICS = {
        "TA0001": {"name": "Initial Access", "description": "Techniques used to gain initial foothold"},
        "TA0002": {"name": "Execution", "description": "Techniques that run malicious code"},
        "TA0003": {"name": "Persistence", "description": "Techniques to maintain access"},
        "TA0004": {"name": "Privilege Escalation", "description": "Techniques to gain higher-level permissions"},
        "TA0005": {"name": "Defense Evasion", "description": "Techniques to avoid detection"},
        "TA0006": {"name": "Credential Access", "description": "Techniques to steal credentials"},
        "TA0007": {"name": "Discovery", "description": "Techniques to gather system information"},
        "TA0008": {"name": "Lateral Movement", "description": "Techniques to move through environment"},
        "TA0009": {"name": "Collection", "description": "Techniques to gather data of interest"},
        "TA0010": {"name": "Exfiltration", "description": "Techniques to steal data"},
        "TA0011": {"name": "Command and Control", "description": "Techniques to communicate with compromised systems"},
        "TA0040": {"name": "Impact", "description": "Techniques to disrupt or destroy systems"}
    }
    
    # MITRE Techniques Database
    MITRE_TECHNIQUES = {
        # Initial Access (TA0001)
        "T1078": {
            "name": "Valid Accounts",
            "tactic": "TA0001",
            "description": "Use of valid credentials to gain initial access",
            "detection": "Monitor for anomalous account usage",
            "mitigation": "M1027 - Password Policies, M1032 - Multi-factor Authentication"
        },
        "T1190": {
            "name": "Exploit Public-Facing Application",
            "tactic": "TA0001",
            "description": "Exploit vulnerable internet-facing applications",
            "detection": "Monitor web server logs for exploit attempts",
            "mitigation": "M1050 - Update Software, M1026 - Application Isolation"
        },
        "T1566": {
            "name": "Phishing",
            "tactic": "TA0001",
            "description": "Sending malicious emails to users",
            "detection": "Email gateway monitoring, user reporting",
            "mitigation": "M1054 - User Training, M1021 - Email Filtering"
        },
        
        # Execution (TA0002)
        "T1059": {
            "name": "Command and Scripting Interpreter",
            "tactic": "TA0002",
            "subtechniques": {
                "T1059.001": "PowerShell",
                "T1059.003": "Windows Command Shell",
                "T1059.005": "Visual Basic",
                "T1059.007": "JavaScript"
            },
            "description": "Using command-line or scripting environments",
            "detection": "Monitor process creation and command-line arguments",
            "mitigation": "M1042 - Disable or Restrict PowerShell"
        },
        "T1059.001": {
            "name": "PowerShell",
            "tactic": "TA0002",
            "parent_technique": "T1059",
            "description": "Using PowerShell for execution",
            "detection": "Enable PowerShell logging, monitor for suspicious commands",
            "mitigation": "M1042 - Constrained Language Mode, Script Block Logging"
        },
        "T1204": {
            "name": "User Execution",
            "tactic": "TA0002",
            "description": "User executes malicious file",
            "detection": "Monitor file execution events",
            "mitigation": "M1038 - Execution Prevention, M1040 - User Training"
        },
        
        # Persistence (TA0003)
        "T1547": {
            "name": "Boot or Logon Autostart Execution",
            "tactic": "TA0003",
            "description": "Persistence via startup items",
            "detection": "Monitor registry changes and startup folder modifications",
            "mitigation": "M1027 - Account Management, M1018 - User Account Control"
        },
        "T1053": {
            "name": "Scheduled Task/Job",
            "tactic": "TA0003",
            "description": "Persistence using scheduled tasks",
            "detection": "Monitor scheduled task creation and modification",
            "mitigation": "M1026 - Privileged Account Management"
        },
        "T1543": {
            "name": "Create or Modify System Process",
            "tactic": "TA0003",
            "description": "Persistence via service creation",
            "detection": "Monitor new service installations",
            "mitigation": "M1042 - Disable or Restrict Services"
        },
        
        # Privilege Escalation (TA0004)
        "T1068": {
            "name": "Exploitation for Privilege Escalation",
            "tactic": "TA0004",
            "description": "Exploiting vulnerabilities to elevate privileges",
            "detection": "Monitor privilege assignment events (Event ID 4672)",
            "mitigation": "M1051 - Update Software, M1026 - Application Isolation"
        },
        "T1078.002": {
            "name": "Domain Accounts",
            "tactic": "TA0004",
            "description": "Using domain admin credentials",
            "detection": "Monitor unusual admin account usage",
            "mitigation": "M1027 - PAM, M1015 - Active Directory Configuration"
        },
        "T1548": {
            "name": "Abuse Elevation Control Mechanism",
            "tactic": "TA0004",
            "description": "Bypassing UAC or sudo",
            "detection": "Monitor UAC bypass attempts",
            "mitigation": "M1051 - Secure UAC Settings"
        },
        
        # Defense Evasion (TA0005)
        "T1562": {
            "name": "Impair Defenses",
            "tactic": "TA0005",
            "description": "Disabling security tools",
            "detection": "Monitor for disabled services or stopped AV processes",
            "mitigation": "M1022 - Restrict File Permissions"
        },
        "T1027": {
            "name": "Obfuscated Files or Information",
            "tactic": "TA0005",
            "description": "Encoding or obfuscating malicious content",
            "detection": "Detect encoded PowerShell commands",
            "mitigation": "M1042 - Script Block Logging"
        },
        
        # Credential Access (TA0006)
        "T1110": {
            "name": "Brute Force",
            "tactic": "TA0006",
            "description": "Attempting multiple logins with different passwords",
            "detection": "Monitor multiple failed login attempts (Event ID 4625)",
            "mitigation": "M1032 - Multi-factor Authentication, Account Lockout Policies"
        },
        "T1555": {
            "name": "Credentials from Password Stores",
            "tactic": "TA0006",
            "description": "Dumping credentials from memory or stores",
            "detection": "Detect LSASS access attempts",
            "mitigation": "M1043 - Credential Guard, M1027 - Privileged Account Management"
        },
        
        # Discovery (TA0007)
        "T1087": {
            "name": "Account Discovery",
            "tactic": "TA0007",
            "description": "Enumerating user accounts",
            "detection": "Monitor net user, whoami commands",
            "mitigation": "M1027 - Account Monitoring"
        },
        "T1016": {
            "name": "System Network Configuration Discovery",
            "tactic": "TA0007",
            "description": "Enumerating network configuration",
            "detection": "Monitor ipconfig, ifconfig commands",
            "mitigation": "M1047 - Network Segmentation"
        },
        
        # Lateral Movement (TA0008)
        "T1021": {
            "name": "Remote Services",
            "tactic": "TA0008",
            "description": "Using remote services to move laterally",
            "detection": "Monitor PsExec, WMIC, WinRM usage",
            "mitigation": "M1047 - Network Segmentation, M1035 - Limit Access"
        },
        "T1021.002": {
            "name": "SMB/Windows Admin Shares",
            "tactic": "TA0008",
            "description": "Using admin shares (C$, ADMIN$)",
            "detection": "Monitor SMB connections to admin shares",
            "mitigation": "M1027 - Restrict Administrative Shares"
        },
        "T1570": {
            "name": "Lateral Tool Transfer",
            "tactic": "TA0008",
            "description": "Copying tools across network",
            "detection": "Monitor file copies across network",
            "mitigation": "M1035 - Network Access Controls"
        },
        
        # Collection (TA0009)
        "T1005": {
            "name": "Data from Local System",
            "tactic": "TA0009",
            "description": "Collecting data from local system",
            "detection": "Monitor file access patterns",
            "mitigation": "M1027 - File System Permissions"
        },
        
        # Exfiltration (TA0010)
        "T1048": {
            "name": "Exfiltration Over Alternative Protocol",
            "tactic": "TA0010",
            "description": "Exfiltrating data over different protocols",
            "detection": "Monitor large outbound data transfers",
            "mitigation": "M1037 - Network Traffic Filtering"
        },
        "T1567": {
            "name": "Exfiltration Over Web Service",
            "tactic": "TA0010",
            "description": "Exfiltrating via web services",
            "detection": "Monitor HTTP/S POST requests with large data",
            "mitigation": "M1037 - Web Filtering"
        },
        
        # Command and Control (TA0011)
        "T1071": {
            "name": "Application Layer Protocol",
            "tactic": "TA0011",
            "description": "Using legitimate protocols for C2",
            "detection": "Monitor DNS, HTTP, HTTPS for anomalies",
            "mitigation": "M1037 - Network Intrusion Prevention"
        },
        "T1568": {
            "name": "Dynamic Resolution",
            "tactic": "TA0011",
            "description": "Using dynamic DNS for C2",
            "detection": "Monitor DNS queries to dynamic domains",
            "mitigation": "M1037 - DNS Filtering"
        },
        
        # Impact (TA0040)
        "T1486": {
            "name": "Data Encrypted for Impact",
            "tactic": "TA0040",
            "description": "Ransomware encryption",
            "detection": "Monitor file modifications and extensions",
            "mitigation": "M1047 - Backups, M1053 - Anti-malware"
        }
    }
    
    # Finding type to MITRE technique mapping
    FINDING_MAPPINGS = {
        "failed_logins": {
            "technique_id": "T1110",
            "technique_name": "Brute Force",
            "confidence": "HIGH",
            "tactic": "Credential Access"
        },
        "brute_force": {
            "technique_id": "T1110",
            "technique_name": "Brute Force",
            "confidence": "HIGH",
            "tactic": "Credential Access"
        },
        "suspicious_powershell": {
            "technique_id": "T1059.001",
            "technique_name": "PowerShell",
            "confidence": "HIGH",
            "tactic": "Execution"
        },
        "privilege_escalation": {
            "technique_id": "T1068",
            "technique_name": "Exploitation for Privilege Escalation",
            "confidence": "MEDIUM",
            "tactic": "Privilege Escalation"
        },
        "lateral_movement": {
            "technique_id": "T1021",
            "technique_name": "Remote Services",
            "confidence": "HIGH",
            "tactic": "Lateral Movement"
        },
        "persistence_attempts": {
            "technique_id": "T1547",
            "technique_name": "Boot or Logon Autostart Execution",
            "confidence": "MEDIUM",
            "tactic": "Persistence"
        },
        "data_exfiltration": {
            "technique_id": "T1048",
            "technique_name": "Exfiltration Over Alternative Protocol",
            "confidence": "HIGH",
            "tactic": "Exfiltration"
        },
        "malware": {
            "technique_id": "T1486",
            "technique_name": "Data Encrypted for Impact",
            "confidence": "HIGH",
            "tactic": "Impact"
        },
        "port_scan": {
            "technique_id": "T1046",
            "technique_name": "Network Service Scanning",
            "confidence": "MEDIUM",
            "tactic": "Discovery"
        },
        "defense_evasion": {
            "technique_id": "T1562",
            "technique_name": "Impair Defenses",
            "confidence": "MEDIUM",
            "tactic": "Defense Evasion"
        }
    }
    
    @classmethod
    def get_technique(cls, technique_id: str) -> Optional[Dict]:
        """
        Get MITRE technique by ID
        
        Args:
            technique_id: MITRE technique ID (e.g., 'T1110')
            
        Returns:
            Technique dictionary or None
        """
        return cls.MITRE_TECHNIQUES.get(technique_id)
    
    @classmethod
    def get_tactic(cls, tactic_id: str) -> Optional[Dict]:
        """
        Get MITRE tactic by ID
        
        Args:
            tactic_id: MITRE tactic ID (e.g., 'TA0006')
            
        Returns:
            Tactic dictionary or None
        """
        return cls.MITRE_TACTICS.get(tactic_id)
    
    @classmethod
    def map_finding(cls, finding_type: str, finding_details: Dict = None) -> Dict[str, Any]:
        """
        Map a finding to MITRE ATT&CK
        
        Args:
            finding_type: Type of finding (e.g., 'suspicious_powershell')
            finding_details: Additional details about the finding
            
        Returns:
            MITRE mapping dictionary
        """
        # Get mapping
        mapping = cls.FINDING_MAPPINGS.get(finding_type.lower(), {})
        
        if not mapping:
            return {
                'technique_id': 'Unknown',
                'technique_name': 'Unknown',
                'tactic': 'Unknown',
                'confidence': 'LOW',
                'description': 'No MITRE mapping available'
            }
        
        # Get full technique details
        technique = cls.MITRE_TECHNIQUES.get(mapping['technique_id'], {})
        tactic = cls.MITRE_TACTICS.get(mapping.get('tactic_id', ''), {})
        
        return {
            'technique_id': mapping['technique_id'],
            'technique_name': mapping['technique_name'],
            'technique_description': technique.get('description', mapping.get('description', '')),
            'tactic': mapping['tactic'],
            'tactic_id': cls._get_tactic_id_by_name(mapping['tactic']),
            'confidence': mapping['confidence'],
            'detection': technique.get('detection', 'Monitor relevant logs'),
            'mitigation': technique.get('mitigation', 'Implement security controls'),
            'finding_type': finding_type,
            'timestamp': datetime.now().isoformat()
        }
    
    @classmethod
    def _get_tactic_id_by_name(cls, tactic_name: str) -> str:
        """Get tactic ID from tactic name"""
        tactic_map = {
            "Initial Access": "TA0001",
            "Execution": "TA0002",
            "Persistence": "TA0003",
            "Privilege Escalation": "TA0004",
            "Defense Evasion": "TA0005",
            "Credential Access": "TA0006",
            "Discovery": "TA0007",
            "Lateral Movement": "TA0008",
            "Collection": "TA0009",
            "Exfiltration": "TA0010",
            "Command and Control": "TA0011",
            "Impact": "TA0040"
        }
        return tactic_map.get(tactic_name, "Unknown")
    
    @classmethod
    def map_all_findings(cls, findings: Dict[str, Any]) -> Dict[str, Any]:
        """
        Map all findings from a threat detection report to MITRE
        
        Args:
            findings: Findings dictionary from ThreatDetector
            
        Returns:
            Complete MITRE mapping report
        """
        mitre_report = {
            'timestamp': datetime.now().isoformat(),
            'total_mapped_findings': 0,
            'tactics_summary': defaultdict(int),
            'techniques_used': [],
            'attack_chain': [],
            'mitre_matrix': {}
        }
        
        # Map each finding category
        for finding_type in ['failed_logins', 'suspicious_powershell', 'privilege_escalation',
                            'lateral_movement', 'persistence_attempts', 'high_risk_commands']:
            
            finding_list = findings.get(finding_type, [])
            if finding_list:
                mapping = cls.map_finding(finding_type)
                mitre_report['techniques_used'].append(mapping)
                mitre_report['tactics_summary'][mapping['tactic']] += len(finding_list)
                mitre_report['total_mapped_findings'] += len(finding_list)
        
        # Map anomalies
        for anomaly in findings.get('anomalies', []):
            anomaly_type = anomaly.get('type', 'unknown')
            mapping = cls.map_finding(anomaly_type)
            mitre_report['techniques_used'].append(mapping)
            mitre_report['tactics_summary'][mapping['tactic']] += 1
            mitre_report['total_mapped_findings'] += 1
        
        # Build attack chain (ordered by typical attack flow)
        attack_chain_order = [
            'Initial Access', 'Execution', 'Persistence', 'Privilege Escalation',
            'Defense Evasion', 'Credential Access', 'Discovery', 'Lateral Movement',
            'Collection', 'Exfiltration', 'Command and Control', 'Impact'
        ]
        
        for tactic in attack_chain_order:
            if tactic in mitre_report['tactics_summary']:
                mitre_report['attack_chain'].append({
                    'tactic': tactic,
                    'count': mitre_report['tactics_summary'][tactic],
                    'phase': len(mitre_report['attack_chain']) + 1
                })
        
        # Generate MITRE matrix (simplified)
        mitre_report['mitre_matrix'] = cls._generate_mitre_matrix(mitre_report['techniques_used'])
        
        return dict(mitre_report)
    
    @classmethod
    def _generate_mitre_matrix(cls, techniques: List[Dict]) -> Dict[str, List[str]]:
        """Generate a simplified MITRE matrix"""
        matrix = {
            'Reconnaissance': [],
            'Resource Development': [],
            'Initial Access': [],
            'Execution': [],
            'Persistence': [],
            'Privilege Escalation': [],
            'Defense Evasion': [],
            'Credential Access': [],
            'Discovery': [],
            'Lateral Movement': [],
            'Collection': [],
            'Command and Control': [],
            'Exfiltration': [],
            'Impact': []
        }
        
        for technique in techniques:
            tactic = technique.get('tactic', 'Unknown')
            if tactic in matrix:
                matrix[tactic].append(technique['technique_name'])
        
        return matrix
    
    @classmethod
    def generate_attack_flow(cls, findings: Dict[str, Any]) -> str:
        """
        Generate a text description of the attack flow
        
        Args:
            findings: Findings dictionary
            
        Returns:
            Attack flow description
        """
        mitre_report = cls.map_all_findings(findings)
        
        if not mitre_report['attack_chain']:
            return "No attack chain detected from findings."
        
        flow_parts = []
        previous_tactic = None
        
        for tactic_info in mitre_report['attack_chain']:
            tactic = tactic_info['tactic']
            count = tactic_info['count']
            
            if previous_tactic:
                flow_parts.append(f" → {tactic}")
            else:
                flow_parts.append(f"Starts with {tactic}")
            
            if count > 1:
                flow_parts.append(f" ({count} techniques)")
            previous_tactic = tactic
        
        return "".join(flow_parts)
    
    @classmethod
    def get_recommended_mitigations(cls, findings: Dict[str, Any]) -> List[Dict[str, str]]:
        """
        Get recommended mitigations based on findings
        
        Args:
            findings: Findings dictionary
            
        Returns:
            List of mitigation recommendations
        """
        mitigations = []
        seen = set()
        
        # Map findings to techniques and collect mitigations
        for finding_type in ['failed_logins', 'suspicious_powershell', 'privilege_escalation',
                            'lateral_movement', 'persistence_attempts']:
            
            if findings.get(finding_type):
                mapping = cls.map_finding(finding_type)
                technique = cls.MITRE_TECHNIQUES.get(mapping['technique_id'], {})
                
                mitigation_text = technique.get('mitigation', '')
                if mitigation_text and mitigation_text not in seen:
                    mitigations.append({
                        'technique': mapping['technique_name'],
                        'technique_id': mapping['technique_id'],
                        'mitigation': mitigation_text,
                        'priority': 'HIGH' if mapping['confidence'] == 'HIGH' else 'MEDIUM'
                    })
                    seen.add(mitigation_text)
        
        return mitigations[:10]  # Top 10 mitigations
    
    @classmethod
    def export_mitre_matrix(cls, findings: Dict[str, Any], format: str = 'json') -> str:
        """
        Export MITRE matrix in various formats
        
        Args:
            findings: Findings dictionary
            format: 'json', 'markdown', or 'csv'
            
        Returns:
            Formatted string
        """
        mitre_report = cls.map_all_findings(findings)
        
        if format == 'json':
            return json.dumps(mitre_report, indent=2, default=str)
        
        elif format == 'markdown':
            md = f"""# MITRE ATT&CK Analysis Report

## Attack Chain
{' → '.join([t['tactic'] for t in mitre_report['attack_chain']])}

## Techniques Detected

| Technique ID | Technique Name | Tactic | Confidence |
|-------------|---------------|--------|------------|
"""
            for technique in mitre_report['techniques_used']:
                md += f"| {technique['technique_id']} | {technique['technique_name']} | {technique['tactic']} | {technique['confidence']} |\n"
            
            md += f"""
## Tactic Summary

| Tactic | Finding Count |
|--------|---------------|
"""
            for tactic, count in mitre_report['tactics_summary'].items():
                md += f"| {tactic} | {count} |\n"
            
            return md
        
        elif format == 'csv':
            import io
            import pandas as pd
            df = pd.DataFrame(mitre_report['techniques_used'])
            output = io.StringIO()
            df.to_csv(output, index=False)
            return output.getvalue()
        
        return json.dumps(mitre_report, indent=2)
    
    @classmethod
    def get_technique_details(cls, technique_id: str) -> Dict[str, Any]:
        """
        Get detailed information about a specific technique
        
        Args:
            technique_id: MITRE technique ID
            
        Returns:
            Detailed technique information
        """
        technique = cls.MITRE_TECHNIQUES.get(technique_id, {})
        
        if not technique:
            return {'error': f'Technique {technique_id} not found'}
        
        # Get tactic information
        tactic = cls.MITRE_TACTICS.get(technique.get('tactic', ''), {})
        
        return {
            'technique_id': technique_id,
            'technique_name': technique.get('name', 'Unknown'),
            'tactic_id': technique.get('tactic', 'Unknown'),
            'tactic_name': tactic.get('name', 'Unknown'),
            'description': technique.get('description', ''),
            'detection': technique.get('detection', ''),
            'mitigation': technique.get('mitigation', ''),
            'subtechniques': technique.get('subtechniques', {})
        }


# ============================================
# CONVENIENCE FUNCTIONS
# ============================================

def map_to_mitre(findings: Dict[str, Any]) -> Dict[str, Any]:
    """Quick helper to map findings to MITRE"""
    return MITREMapper.map_all_findings(findings)


def get_attack_summary(findings: Dict[str, Any]) -> str:
    """Get human-readable attack summary"""
    mitre_report = MITREMapper.map_all_findings(findings)
    
    if not mitre_report['attack_chain']:
        return "No MITRE ATT&CK techniques identified."
    
    summary = f"Attack chain: {' → '.join([t['tactic'] for t in mitre_report['attack_chain']])}\n"
    summary += f"Total techniques: {len(mitre_report['techniques_used'])}\n"
    summary += f"Primary tactic: {mitre_report['attack_chain'][0]['tactic'] if mitre_report['attack_chain'] else 'Unknown'}"
    
    return summary


# ============================================
# TESTING CODE
# ============================================

if __name__ == "__main__":
    print("🎯 Testing MITRE ATT&CK Mapper Module")
    print("=" * 60)
    
    # Test finding mapping
    print("\n📋 Test 1: Map Single Finding")
    mapping = MITREMapper.map_finding("suspicious_powershell")
    print(f"   Technique: {mapping['technique_name']} ({mapping['technique_id']})")
    print(f"   Tactic: {mapping['tactic']}")
    print(f"   Confidence: {mapping['confidence']}")
    
    # Test technique details
    print("\n📋 Test 2: Get Technique Details")
    technique = MITREMapper.get_technique_details("T1110")
    print(f"   {technique['technique_name']} - {technique['description'][:60]}...")
    
    # Test complete report
    print("\n📋 Test 3: Map All Findings")
    test_findings = {
        'failed_logins': [{'count': 50}],
        'suspicious_powershell': [{'command': 'test'}],
        'privilege_escalation': [{'user': 'admin'}],
        'lateral_movement': [{'command': 'psexec'}],
        'anomalies': [{'type': 'port_scan'}]
    }
    
    mitre_report = MITREMapper.map_all_findings(test_findings)
    print(f"   Total Mapped Findings: {mitre_report['total_mapped_findings']}")
    print(f"   Techniques Used: {len(mitre_report['techniques_used'])}")
    
    # Test attack flow
    print("\n📋 Test 4: Attack Flow")
    attack_flow = MITREMapper.generate_attack_flow(test_findings)
    print(f"   {attack_flow}")
    
    # Test mitigations
    print("\n📋 Test 5: Recommended Mitigations")
    mitigations = MITREMapper.get_recommended_mitigations(test_findings)
    for mit in mitigations[:3]:
        print(f"   [{mit['priority']}] {mit['technique']}: {mit['mitigation'][:50]}...")
    
    # Test export
    print("\n📋 Test 6: Export MITRE Matrix")
    markdown_export = MITREMapper.export_mitre_matrix(test_findings, format='markdown')
    print(f"   Markdown length: {len(markdown_export)} characters")
    print(f"\n   Preview:\n{markdown_export[:300]}...")
    
    print("\n" + "=" * 60)
    print("✅ MITRE ATT&CK Mapper Module Ready")
    
    # Display some statistics
    print(f"\n📊 MITRE Database Statistics:")
    print(f"   Tactics: {len(MITREMapper.MITRE_TACTICS)}")
    print(f"   Techniques: {len(MITREMapper.MITRE_TECHNIQUES)}")
    print(f"   Finding Mappings: {len(MITREMapper.FINDING_MAPPINGS)}")