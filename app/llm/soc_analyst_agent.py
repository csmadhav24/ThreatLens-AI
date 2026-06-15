# app/llm/soc_analyst_agent.py
"""
Senior SOC Analyst Agent - Professional Incident Investigation
15+ years of IR experience embedded in code
Does NOT summarize logs - INVESTIGATES incidents
"""

import pandas as pd
import re
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Tuple
from collections import defaultdict
import json


class SOCAnalystAgent:
    """
    Senior SOC Analyst AI Agent
    Investigates incidents, builds attack chains, correlates events
    """
    
    # MITRE ATT&CK Techniques Database
    MITRE_TECHNIQUES = {
        'T1110': {'name': 'Brute Force', 'tactic': 'Credential Access'},
        'T1078': {'name': 'Valid Accounts', 'tactic': 'Initial Access'},
        'T1059.001': {'name': 'PowerShell', 'tactic': 'Execution'},
        'T1068': {'name': 'Exploitation for Privilege Escalation', 'tactic': 'Privilege Escalation'},
        'T1021': {'name': 'Remote Services', 'tactic': 'Lateral Movement'},
        'T1547': {'name': 'Boot or Logon Autostart Execution', 'tactic': 'Persistence'},
        'T1048': {'name': 'Exfiltration Over Alternative Protocol', 'tactic': 'Exfiltration'},
        'T1486': {'name': 'Data Encrypted for Impact', 'tactic': 'Impact'},
        'T1562': {'name': 'Impair Defenses', 'tactic': 'Defense Evasion'},
        'T1046': {'name': 'Network Service Scanning', 'tactic': 'Discovery'},
        'T1071': {'name': 'Application Layer Protocol', 'tactic': 'Command and Control'},
        'T1499': {'name': 'Endpoint Denial of Service', 'tactic': 'Impact'},
    }
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.conversation_history = []
        self.current_investigation = None
    
    def extract_suspicious_entities(self, df: pd.DataFrame, intelligence: Dict) -> Dict:

        suspicious = {
            'suspicious_ips': [],
            'suspicious_users': [],
            'total_suspicious_ips': 0,
            'total_suspicious_users': 0
        }
    
        # Patterns that indicate suspicious activity
        suspicious_patterns = [
            'failed login', 'brute force', 'unauthorized', 'privilege escalation',
            'suspicious', 'malicious', 'ransomware', 'encrypt', 'lockout',
            'excessive', 'anomaly', 'breach', 'compromise', 'attack'
        ]
    
        # Check if we have raw_log column
        if 'raw_log' in df.columns:
            for idx, row in df.iterrows():
                log = str(row.get('raw_log', ''))
                severity = str(row.get('severity', '')).upper()
            
                # Check if this event is suspicious
                is_suspicious = False
                for pattern in suspicious_patterns:
                    if pattern in log.lower():
                        is_suspicious = True
                        break
            
                # Also check severity
                if severity in ['CRITICAL', 'HIGH', 'EMERGENCY', 'ALERT']:
                    is_suspicious = True
            
                if is_suspicious:
                    # Extract IP from this log
                    ip_match = re.search(r'ip[=:]\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', log, re.IGNORECASE)
                    if ip_match:
                        ip = ip_match.group(1)
                        if ip not in suspicious['suspicious_ips']:
                            suspicious['suspicious_ips'].append(ip)
                
                    # Extract user from this log
                    user_match = re.search(r'user[=:]\s*([a-zA-Z0-9_-]+)', log, re.IGNORECASE)
                    if user_match:
                        user = user_match.group(1)
                        if user.lower() not in ['null', 'none', 'anonymous']:
                            if user not in suspicious['suspicious_users']:
                                suspicious['suspicious_users'].append(user)
    
        # Also check from intelligence (already extracted)+
        iocs = intelligence.get('iocs', {})
        if iocs.get('ip_addresses'):
            for ip in iocs['ip_addresses']:
                if ip not in suspicious['suspicious_ips']:
                    suspicious['suspicious_ips'].append(ip)
    
        if iocs.get('usernames'):
            for user in iocs['usernames']:
                if user not in suspicious['suspicious_users']:
                    suspicious['suspicious_users'].append(user)
    
        suspicious['total_suspicious_ips'] = len(suspicious['suspicious_ips'])
        suspicious['total_suspicious_users'] = len(suspicious['suspicious_users'])
    
        return suspicious
    def investigate(self, df: pd.DataFrame, user_question: str = None) -> Dict[str, Any]:
        """
        Main investigation method - Think like a senior SOC analyst
        """
        if df is None or df.empty:
            return self._empty_response()
        
        # Parse timestamps
        if 'timestamp' in df.columns:
            df['timestamp_parsed'] = pd.to_datetime(df['timestamp'], errors='coerce')
        
        # Step 1: Extract all relevant data
        extracted_data = self._extract_intelligence(df)
        
        # Step 2: Correlate events into attack chains
        attack_chains = self._correlate_attack_chains(df, extracted_data)
        
        # Step 3: Get correlations from extracted_data
        correlations = extracted_data.get('event_correlations', [])
        
        # Step 4: Build investigation
        investigation = {
            'executive_summary': self._generate_executive_summary(df, extracted_data, attack_chains),
            'incident_narrative': self._generate_incident_narrative(df, extracted_data, attack_chains),
            'attack_timeline': self._build_attack_timeline(df, attack_chains),
            'attack_chain': attack_chains,
            'indicators_of_compromise': extracted_data['iocs'],
            'mitre_mapping': self._map_to_mitre(df, attack_chains),
            'root_cause_analysis': self._analyze_root_cause(df, extracted_data, attack_chains),
            'affected_assets': extracted_data['affected_assets'],
            'confidence_scores': self._calculate_confidence_scores(df, attack_chains, extracted_data, correlations),
            'remediation_plan': self._generate_remediation_plan(attack_chains, extracted_data),
            'final_risk_assessment': self._assess_final_risk(df, attack_chains)
        }
        
        self.current_investigation = investigation
        return investigation
    
    def _extract_intelligence(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Extract all intelligence from logs - IMPROVED IP & USER EXTRACTION"""
        
        intelligence = {
            'iocs': {
                'ip_addresses': [],
                'usernames': [],
                'hostnames': [],
                'file_paths': [],
                'commands': [],
                'services': []
            },
            'affected_assets': {
                'users': [],
                'hosts': [],
                'services': [],
                'ip_addresses': []
            },
            'suspicious_patterns': [],
            'event_correlations': [],
            'anomaly_clusters': []
        }
        
        # Check if raw_log column exists
        if 'raw_log' not in df.columns:
            return intelligence
        
        all_raw_logs = df['raw_log'].astype(str)
        internal_prefixes = ('10.', '192.168.', '172.', '127.', '0.', '169.254.', '255.')
        
        # ============================================
        # IMPROVED IP ADDRESS EXTRACTION
        # ============================================
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        
        for idx, log in all_raw_logs.items():
            # Extract all IPs
            ips = re.findall(ip_pattern, log)
            for ip in ips:
                if not ip.startswith(internal_prefixes):
                    if ip not in intelligence['iocs']['ip_addresses']:
                        intelligence['iocs']['ip_addresses'].append(ip)
                    if ip not in intelligence['affected_assets']['ip_addresses']:
                        intelligence['affected_assets']['ip_addresses'].append(ip)
            
            # Look for source_ip=XXX pattern
            source_ip_match = re.search(r'source_ip[=:]\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', log, re.IGNORECASE)
            if source_ip_match:
                ip = source_ip_match.group(1)
                if not ip.startswith(internal_prefixes):
                    if ip not in intelligence['iocs']['ip_addresses']:
                        intelligence['iocs']['ip_addresses'].append(ip)
                    if ip not in intelligence['affected_assets']['ip_addresses']:
                        intelligence['affected_assets']['ip_addresses'].append(ip)
            
            # Look for ip=XXX pattern
            ip_match = re.search(r'ip[=:]\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', log, re.IGNORECASE)
            if ip_match:
                ip = ip_match.group(1)
                if not ip.startswith(internal_prefixes):
                    if ip not in intelligence['iocs']['ip_addresses']:
                        intelligence['iocs']['ip_addresses'].append(ip)
                    if ip not in intelligence['affected_assets']['ip_addresses']:
                        intelligence['affected_assets']['ip_addresses'].append(ip)
        
        # Extract from specific columns if they exist
        if 'source_ip' in df.columns:
            for ip in df['source_ip'].dropna().unique():
                ip_str = str(ip)
                if not ip_str.startswith(internal_prefixes):
                    if ip_str not in intelligence['iocs']['ip_addresses']:
                        intelligence['iocs']['ip_addresses'].append(ip_str)
                    if ip_str not in intelligence['affected_assets']['ip_addresses']:
                        intelligence['affected_assets']['ip_addresses'].append(ip_str)
        
        if 'src_ip' in df.columns:
            for ip in df['src_ip'].dropna().unique():
                ip_str = str(ip)
                if not ip_str.startswith(internal_prefixes):
                    if ip_str not in intelligence['iocs']['ip_addresses']:
                        intelligence['iocs']['ip_addresses'].append(ip_str)
                    if ip_str not in intelligence['affected_assets']['ip_addresses']:
                        intelligence['affected_assets']['ip_addresses'].append(ip_str)
        
        # ============================================
        # IMPROVED USERNAME EXTRACTION
        # ============================================
        user_patterns = [
            r'user[=:]\s*(\w+)',
            r'username[=:]\s*(\w+)',
            r'account[=:]\s*(\w+)',
            r'user\s+(\w+)',
            r'"user":\s*"(\w+)"',
            r"'user':\s*'(\w+)'",
            r'user_id[=:]\s*(\w+)',
            r'U(\d+)',
        ]
        
        for idx, log in all_raw_logs.items():
            for pattern in user_patterns:
                users = re.findall(pattern, log, re.IGNORECASE)
                for user in users:
                    user_lower = user.lower()
                    if user_lower not in ['null', 'none', 'anonymous', 'system', 'unknown', 'n/a', '']:
                        if user not in intelligence['iocs']['usernames']:
                            intelligence['iocs']['usernames'].append(user)
                        if user not in intelligence['affected_assets']['users']:
                            intelligence['affected_assets']['users'].append(user)
        
        if 'user' in df.columns:
            for user in df['user'].dropna().unique():
                user_str = str(user)
                if user_str.lower() not in ['null', 'none', 'anonymous', 'nan', '']:
                    if user_str not in intelligence['iocs']['usernames']:
                        intelligence['iocs']['usernames'].append(user_str)
                    if user_str not in intelligence['affected_assets']['users']:
                        intelligence['affected_assets']['users'].append(user_str)
        
        # ============================================
        # HOSTNAME EXTRACTION
        # ============================================
        host_patterns = [
            r'host[=:]\s*(\w+(?:[-\w]+)*)',
            r'server[=:]\s*(\w+(?:[-\w]+)*)',
            r'node[=:]\s*(\w+(?:[-\w]+)*)',
            r'computer[=:]\s*(\w+(?:[-\w]+)*)',
            r'hostname[=:]\s*(\w+(?:[-\w]+)*)',
        ]
        
        for idx, log in all_raw_logs.items():
            for pattern in host_patterns:
                hosts = re.findall(pattern, log, re.IGNORECASE)
                for host in hosts:
                    if host and host.lower() not in ['null', 'none', 'unknown']:
                        if host not in intelligence['iocs']['hostnames']:
                            intelligence['iocs']['hostnames'].append(host)
                        if host not in intelligence['affected_assets']['hosts']:
                            intelligence['affected_assets']['hosts'].append(host)
        
        if 'host' in df.columns:
            for host in df['host'].dropna().unique():
                host_str = str(host)
                if host_str.lower() not in ['null', 'none', '']:
                    if host_str not in intelligence['iocs']['hostnames']:
                        intelligence['iocs']['hostnames'].append(host_str)
                    if host_str not in intelligence['affected_assets']['hosts']:
                        intelligence['affected_assets']['hosts'].append(host_str)
        
        # ============================================
        # SERVICE EXTRACTION
        # ============================================
        if 'source' in df.columns:
            for service in df['source'].dropna().unique():
                service_str = str(service)
                if service_str not in intelligence['iocs']['services']:
                    intelligence['iocs']['services'].append(service_str)
                if service_str not in intelligence['affected_assets']['services']:
                    intelligence['affected_assets']['services'].append(service_str)
        
        service_pattern = r'service[=:]\s*(\w+(?:[-\w]+)*)'
        for idx, log in all_raw_logs.items():
            services = re.findall(service_pattern, log, re.IGNORECASE)
            for service in services:
                if service and service not in intelligence['iocs']['services']:
                    intelligence['iocs']['services'].append(service)
                if service and service not in intelligence['affected_assets']['services']:
                    intelligence['affected_assets']['services'].append(service)
        
        # ============================================
        # EXTRACT SUSPICIOUS COMMANDS
        # ============================================
        command_patterns = [
            r'cmd(?:\.exe)?\s+/c\s+(\S+)',
            r'powershell(?:\.exe)?\s+(.+?)(?:\s|$)',
            r'wmic\s+(.+)',
            r'net\s+(?:user|localgroup)\s+(.+)',
            r'"command":\s*"([^"]+)"',
            r'command[=:]\s*([^|&\s]+)',
        ]
        
        for idx, log in all_raw_logs.items():
            for pattern in command_patterns:
                commands = re.findall(pattern, log, re.IGNORECASE)
                for cmd in commands:
                    if len(cmd) > 5 and cmd not in intelligence['iocs']['commands']:
                        intelligence['iocs']['commands'].append(cmd[:200])
        
        # ============================================
        # SUSPICIOUS PATTERN DETECTION
        # ============================================
        
        # Pattern 1: Authentication failure cluster
        auth_failures = df[df['raw_log'].str.contains('login fail|auth fail|authentication failed|excessive login', case=False, na=False)]
        if len(auth_failures) > 5:
            intelligence['suspicious_patterns'].append({
                'pattern': 'authentication_failure_cluster',
                'count': len(auth_failures),
                'significance': 'HIGH' if len(auth_failures) > 20 else 'MEDIUM',
                'description': f'Cluster of {len(auth_failures)} authentication failures - possible brute force'
            })
        
        # Pattern 2: Privilege escalation
        priv_events = df[df['raw_log'].str.contains('privilege|admin role|elevated|unauthorized admin', case=False, na=False)]
        if len(priv_events) > 0:
            intelligence['suspicious_patterns'].append({
                'pattern': 'privilege_escalation',
                'count': len(priv_events),
                'significance': 'HIGH',
                'description': f'Privilege escalation activity detected ({len(priv_events)} events)'
            })
        
        # Pattern 3: Database issues
        db_issues = df[df['raw_log'].str.contains('database unavailable|replication lag|connection pool|db-', case=False, na=False)]
        if len(db_issues) > 0:
            intelligence['suspicious_patterns'].append({
                'pattern': 'database_availability',
                'count': len(db_issues),
                'significance': 'HIGH',
                'description': f'Database availability issues - potential DoS or compromise'
            })
        
        # Pattern 4: Ransomware indicators
        ransomware = df[df['raw_log'].str.contains('ransom|encrypt|encryption spike|ransomware', case=False, na=False)]
        if not ransomware.empty:
            intelligence['suspicious_patterns'].append({
                'pattern': 'ransomware_indicators',
                'count': len(ransomware),
                'significance': 'CRITICAL',
                'description': f'RANSOMWARE DETECTED - Immediate incident response required'
            })
        
        # Pattern 5: Time-based anomaly
        if 'timestamp_parsed' in df.columns:
            df_copy = df.copy()
            df_copy['hour'] = df_copy['timestamp_parsed'].dt.hour
            night_events = df_copy[df_copy['hour'].between(0, 5)]
            if len(night_events) > len(df) * 0.3:
                intelligence['suspicious_patterns'].append({
                    'pattern': 'off_hours_activity',
                    'count': len(night_events),
                    'significance': 'MEDIUM',
                    'description': f'High volume of activity during off-hours ({len(night_events)} events)'
                })
        
        # ============================================
        # EVENT CORRELATIONS
        # ============================================
        if len(auth_failures) > 5 and len(priv_events) > 0:
            intelligence['event_correlations'].append({
                'correlation': 'authentication_failure_to_privilege_escalation',
                'description': 'Authentication failures followed by privilege escalation - potential compromise chain'
            })
        
        if len(priv_events) > 0 and not ransomware.empty:
            intelligence['event_correlations'].append({
                'correlation': 'privilege_escalation_to_ransomware',
                'description': 'Privilege escalation preceded ransomware - active attack in progress'
            })
        
        # Print extracted data for debugging
        if self.verbose:
            print(f"\n📊 Extracted Intelligence:")
            print(f"   IPs: {intelligence['iocs']['ip_addresses']}")
            print(f"   Users: {intelligence['iocs']['usernames']}")
            print(f"   Hosts: {intelligence['iocs']['hostnames']}")
            print(f"   Services: {intelligence['iocs']['services']}")
        
        return intelligence
    
    def _correlate_attack_chains(self, df: pd.DataFrame, intelligence: Dict) -> List[Dict]:
        """Correlate events into actual attack chains - ANALYST THINKING"""
        
        attack_chains = []
        
        # Build attack chain from correlated events
        chain = {
            'id': 'CHAIN-001',
            'confidence': 0,
            'phases': [],
            'techniques': [],
            'affected_assets': []
        }
        
        # Phase 1: Initial Access
        initial_access = []
        for p in intelligence.get('suspicious_patterns', []):
            if p.get('pattern') == 'authentication_failure_cluster':
                initial_access.append({
                    'phase': 'Initial Access',
                    'technique': 'T1110 - Brute Force',
                    'description': 'Multiple authentication failures detected - potential password spraying/brute force',
                    'evidence': [p]
                })
        
        # Phase 2: Privilege Escalation
        privilege_esc = []
        for p in intelligence.get('suspicious_patterns', []):
            if p.get('pattern') == 'privilege_escalation':
                privilege_esc.append({
                    'phase': 'Privilege Escalation',
                    'technique': 'T1068 - Exploitation for Privilege Escalation',
                    'description': 'Privilege escalation activity detected - attacker gaining elevated access',
                    'evidence': [p]
                })
                chain['techniques'].append('T1068')
        
        # Phase 3: Persistence
        persistence = []
        if privilege_esc:
            persistence.append({
                'phase': 'Persistence',
                'technique': 'T1547 - Boot or Logon Autostart Execution',
                'description': 'Potential persistence mechanisms established after privilege escalation',
                'evidence': []
            })
            chain['techniques'].append('T1547')
        
        # Phase 4: Impact / Ransomware
        impact = []
        for p in intelligence.get('suspicious_patterns', []):
            if p.get('pattern') == 'ransomware_indicators':
                impact.append({
                    'phase': 'Impact',
                    'technique': 'T1486 - Data Encrypted for Impact',
                    'description': 'RANSOMWARE DETECTED - Active encryption in progress',
                    'evidence': [p]
                })
                chain['techniques'].append('T1486')
                chain['confidence'] = 95
            elif p.get('pattern') == 'database_availability':
                impact.append({
                    'phase': 'Impact',
                    'technique': 'T1499 - Endpoint Denial of Service',
                    'description': 'Database availability issues - potential DoS or database compromise',
                    'evidence': [p]
                })
                chain['techniques'].append('T1499')
                chain['confidence'] = 75
        
        if not impact:
            chain['confidence'] = 50
        
        # Assemble chain
        if initial_access:
            chain['phases'].extend(initial_access)
        if privilege_esc:
            chain['phases'].extend(privilege_esc)
        if persistence:
            chain['phases'].extend(persistence)
        if impact:
            chain['phases'].extend(impact)
        
        # Add affected assets
        chain['affected_assets'] = {
            'users': intelligence.get('affected_assets', {}).get('users', [])[:5],
            'hosts': intelligence.get('affected_assets', {}).get('hosts', [])[:5],
            'services': intelligence.get('affected_assets', {}).get('services', [])[:5],
            'ips': intelligence.get('affected_assets', {}).get('ip_addresses', [])[:5]
        }
        
        if chain['phases']:
            attack_chains.append(chain)
        
        return attack_chains
    
    def _generate_executive_summary(self, df: pd.DataFrame, intelligence: Dict, attack_chains: List) -> str:
        """Generate executive summary - FOR MANAGEMENT"""
        
        summary_lines = []
        summary_lines.append("=" * 70)
        summary_lines.append("EXECUTIVE SUMMARY")
        summary_lines.append("=" * 70)
        summary_lines.append("")
        
        # Determine incident severity
        has_ransomware = False
        has_privilege = False
        has_db_issue = False
        
        for p in intelligence.get('suspicious_patterns', []):
            pattern = p.get('pattern', '')
            if pattern == 'ransomware_indicators':
                has_ransomware = True
            elif pattern == 'privilege_escalation':
                has_privilege = True
            elif pattern == 'database_availability':
                has_db_issue = True
        
        if has_ransomware:
            severity = "CRITICAL - ACTIVE RANSOMWARE INCIDENT"
            urgency = "IMMEDIATE RESPONSE REQUIRED"
        elif has_privilege and has_db_issue:
            severity = "HIGH - Potential Active Compromise"
            urgency = "URGENT INVESTIGATION REQUIRED"
        elif has_privilege:
            severity = "MEDIUM-HIGH - Suspicious Activity Detected"
            urgency = "PRIORITY INVESTIGATION"
        else:
            severity = "MEDIUM - Anomalous Activity"
            urgency = "INVESTIGATE WITHIN 24 HOURS"
        
        summary_lines.append(f"INCIDENT SEVERITY: {severity}")
        summary_lines.append(f"URGENCY: {urgency}")
        summary_lines.append("")
        
        # Brief description
        if has_ransomware:
            summary_lines.append("INCIDENT SUMMARY:")
            summary_lines.append("Active ransomware incident detected with confirmed file encryption activity.")
            summary_lines.append("Immediate containment and isolation of affected systems is critical.")
        elif has_privilege:
            summary_lines.append("INCIDENT SUMMARY:")
            summary_lines.append("Privilege escalation activity detected following authentication anomalies.")
            summary_lines.append("Possible credential compromise and unauthorized access.")
        else:
            summary_lines.append("INCIDENT SUMMARY:")
            summary_lines.append("Suspicious patterns identified requiring further investigation.")
        
        summary_lines.append("")
        summary_lines.append(f"TOTAL EVENTS ANALYZED: {len(df)}")
        summary_lines.append(f"SUSPICIOUS PATTERNS: {len(intelligence.get('suspicious_patterns', []))}")
        summary_lines.append(f"AFFECTED USERS: {len(intelligence.get('affected_assets', {}).get('users', []))}")
        summary_lines.append(f"AFFECTED IPS: {len(intelligence.get('affected_assets', {}).get('ip_addresses', []))}")
        
        return "\n".join(summary_lines)
    
    def _generate_incident_narrative(self, df: pd.DataFrame, intelligence: Dict, attack_chains: List) -> str:
        """Generate narrative incident description - WHAT HAPPENED"""
        
        narrative = []
        narrative.append("=" * 70)
        narrative.append("INCIDENT NARRATIVE")
        narrative.append("=" * 70)
        narrative.append("")
        
        has_ransomware = False
        has_privilege = False
        has_auth_failures = False
        has_db_issue = False
        
        for p in intelligence.get('suspicious_patterns', []):
            pattern = p.get('pattern', '')
            if pattern == 'ransomware_indicators':
                has_ransomware = True
            elif pattern == 'privilege_escalation':
                has_privilege = True
            elif pattern == 'authentication_failure_cluster':
                has_auth_failures = True
            elif pattern == 'database_availability':
                has_db_issue = True
        
        if has_ransomware:
            narrative.append("**INCIDENT TYPE:** Ransomware / Data Destruction Incident")
            narrative.append("")
            narrative.append("**WHAT HAPPENED:**")
            narrative.append("The investigation has confirmed active ransomware activity within the environment.")
            narrative.append("File encryption indicators detected with significant impact on affected systems.")
            narrative.append("")
            narrative.append("**ATTACKER BEHAVIOR:**")
            narrative.append("- Unauthorized file encryption detected")
            narrative.append("- Ransomware deployment confirmed")
            narrative.append("- Potential data destruction in progress")
        
        elif has_privilege:
            narrative.append("**INCIDENT TYPE:** Privilege Escalation / Potential Compromise")
            narrative.append("")
            narrative.append("**WHAT HAPPENED:**")
            narrative.append("Suspicious privilege escalation activity detected following authentication anomalies.")
            narrative.append("Unauthorized administrative role assignments observed.")
            narrative.append("")
            if has_auth_failures:
                narrative.append("**ATTACKER BEHAVIOR:**")
                narrative.append("- Authentication failures preceded privilege escalation")
                narrative.append("- Pattern suggests credential compromise followed by lateral movement")
        
        elif has_db_issue:
            narrative.append("**INCIDENT TYPE:** Database Availability Incident")
            narrative.append("")
            narrative.append("**WHAT HAPPENED:**")
            narrative.append("Critical database availability issues detected with potential service impact.")
            narrative.append("Replication failures and database unavailability observed.")
            narrative.append("")
            narrative.append("**ATTACKER BEHAVIOR:**")
            narrative.append("- Database systems experiencing availability issues")
            narrative.append("- Potential DoS or compromise requiring investigation")
        
        else:
            narrative.append("**INCIDENT TYPE:** Suspicious Activity Investigation")
            narrative.append("")
            narrative.append("**WHAT HAPPENED:**")
            narrative.append("Anomalous patterns detected requiring further investigation.")
            narrative.append("No confirmed compromise at this time, but suspicious activity present.")
        
        return "\n".join(narrative)
    
    def _build_attack_timeline(self, df: pd.DataFrame, attack_chains: List) -> List[Dict]:
        """Build chronological attack timeline"""
        
        timeline = []
        
        if 'timestamp_parsed' not in df.columns:
            return timeline
        
        # Get all events with timestamps
        df_sorted = df.sort_values('timestamp_parsed')
        
        for idx, row in df_sorted.iterrows():
            ts = row.get('timestamp_parsed')
            if pd.isna(ts):
                continue
            
            severity = row.get('severity', 'INFO')
            source = row.get('source', 'Unknown')
            message = str(row.get('raw_log', ''))[:150]
            
            # Determine if this is a critical event
            is_critical = severity in ['EMERGENCY', 'CRITICAL', 'HIGH']
            
            timeline.append({
                'timestamp': ts.strftime('%Y-%m-%d %H:%M:%S'),
                'severity': severity,
                'source': source,
                'event': message,
                'is_critical': is_critical
            })
        
        return timeline
    
    def _map_to_mitre(self, df: pd.DataFrame, attack_chains: List) -> List[Dict]:
        """Map findings to MITRE ATT&CK"""
        
        mitre_findings = []
        
        for chain in attack_chains:
            for technique_id in chain.get('techniques', []):
                if technique_id in self.MITRE_TECHNIQUES:
                    technique = self.MITRE_TECHNIQUES[technique_id]
                    mitre_findings.append({
                        'technique_id': technique_id,
                        'technique_name': technique['name'],
                        'tactic': technique['tactic'],
                        'confidence': chain.get('confidence', 50),
                        'description': f"{technique['name']} detected in attack chain"
                    })
        
        return mitre_findings
    
    def _analyze_root_cause(self, df: pd.DataFrame, intelligence: Dict, attack_chains: List) -> str:
        """Determine likely root cause"""
        
        root_cause = []
        root_cause.append("=" * 70)
        root_cause.append("ROOT CAUSE ANALYSIS")
        root_cause.append("=" * 70)
        root_cause.append("")
        
        has_auth_failures = False
        has_privilege = False
        has_ransomware = False
        
        for p in intelligence.get('suspicious_patterns', []):
            pattern = p.get('pattern', '')
            if pattern == 'authentication_failure_cluster':
                has_auth_failures = True
            elif pattern == 'privilege_escalation':
                has_privilege = True
            elif pattern == 'ransomware_indicators':
                has_ransomware = True
        
        if has_ransomware:
            root_cause.append("**LIKELY ROOT CAUSE:** Credential Compromise leading to Ransomware Deployment")
            root_cause.append("")
            root_cause.append("**REASONING:**")
            root_cause.append("1. Authentication anomalies indicate potential credential compromise")
            root_cause.append("2. Privilege escalation suggests attacker gained elevated access")
            root_cause.append("3. Ransomware deployment confirms active attack")
            root_cause.append("")
            root_cause.append("**CONFIDENCE:** HIGH (85%) - Multiple correlated indicators present")
        
        elif has_privilege and has_auth_failures:
            root_cause.append("**LIKELY ROOT CAUSE:** Credential Compromise with Privilege Escalation")
            root_cause.append("")
            root_cause.append("**REASONING:**")
            root_cause.append("1. Authentication failure cluster suggests password guessing/brute force")
            root_cause.append("2. Subsequent privilege escalation indicates successful compromise")
            root_cause.append("3. Correlation between events strengthens the attack narrative")
            root_cause.append("")
            root_cause.append("**CONFIDENCE:** MEDIUM-HIGH (70%) - Correlated but not confirmed")
        
        elif has_privilege:
            root_cause.append("**LIKELY ROOT CAUSE:** Insider Threat or Malicious Privilege Escalation")
            root_cause.append("")
            root_cause.append("**REASONING:**")
            root_cause.append("1. Privilege escalation without preceding authentication failures")
            root_cause.append("2. Could indicate insider threat or vulnerability exploitation")
            root_cause.append("3. Requires additional investigation")
            root_cause.append("")
            root_cause.append("**CONFIDENCE:** MEDIUM (50%) - Multiple possibilities")
        
        else:
            root_cause.append("**LIKELY ROOT CAUSE:** Undetermined - Requires Further Investigation")
            root_cause.append("")
            root_cause.append("**REASONING:**")
            root_cause.append("1. Insufficient correlated events to determine root cause")
            root_cause.append("2. Anomalies present but no confirmed attack chain")
            root_cause.append("3. Additional log sources recommended")
            root_cause.append("")
            root_cause.append("**CONFIDENCE:** LOW (30%) - Inconclusive evidence")
        
        return "\n".join(root_cause)
    
    def _calculate_confidence_scores(
        self,
        df: pd.DataFrame,
        attack_chains: List,
        intelligence: Dict,
        correlations: List
    ) -> Dict:
        """Calculate confidence scores for findings - FIXED VERSION"""
        
        scores = {
            'overall_confidence': 0,
            'attack_chain_confidence': 0,
            'ioc_confidence': 0,
            'root_cause_confidence': 0,
            'factors': []
        }
        
        if not attack_chains:
            scores['overall_confidence'] = 20
            scores['factors'].append("No confirmed attack chain detected")
            return scores
        
        chain = attack_chains[0]
        scores['attack_chain_confidence'] = chain.get('confidence', 50)
        
        # Check for ransomware - using intelligence (the parameter, not undefined variable)
        has_ransomware = False
        for p in intelligence.get('suspicious_patterns', []):
            if p.get('pattern') == 'ransomware_indicators':
                has_ransomware = True
                break
        
        # Check correlations length
        has_correlations = len(correlations) > 0 if correlations else False
        
        if has_ransomware:
            scores['root_cause_confidence'] = 85
            scores['ioc_confidence'] = 80
            scores['overall_confidence'] = 85
            scores['factors'].append("Ransomware indicators provide high-confidence evidence")
        elif scores['attack_chain_confidence'] >= 70:
            scores['root_cause_confidence'] = 70
            scores['ioc_confidence'] = 65
            scores['overall_confidence'] = 70
            scores['factors'].append("Correlated attack chain with moderate evidence")
        elif scores['attack_chain_confidence'] >= 50:
            scores['root_cause_confidence'] = 50
            scores['ioc_confidence'] = 50
            scores['overall_confidence'] = 55
            scores['factors'].append("Partial attack chain with some correlation")
        else:
            scores['overall_confidence'] = 35
            scores['factors'].append("Limited evidence, low confidence")
        
        return scores
    
    def _generate_remediation_plan(self, attack_chains: List, intelligence: Dict) -> str:
        """Generate actionable remediation steps"""
        
        remediation = []
        remediation.append("=" * 70)
        remediation.append("REMEDIATION PLAN")
        remediation.append("=" * 70)
        remediation.append("")
        
        # Check patterns
        has_ransomware = False
        has_privilege = False
        has_auth_failures = False
        
        for p in intelligence.get('suspicious_patterns', []):
            pattern = p.get('pattern', '')
            if pattern == 'ransomware_indicators':
                has_ransomware = True
            elif pattern == 'privilege_escalation':
                has_privilege = True
            elif pattern == 'authentication_failure_cluster':
                has_auth_failures = True
        
        if has_ransomware:
            remediation.append("**IMMEDIATE CONTAINMENT (0-15 minutes):**")
            remediation.append("1. ISOLATE affected systems from network - disconnect immediately")
            remediation.append("2. Disable network shares and backup connections")
            remediation.append("3. Activate Incident Response Team")
            remediation.append("4. Preserve forensic evidence (memory, disk) before reboot")
            remediation.append("")
            remediation.append("**ERADICATION (15-60 minutes):**")
            remediation.append("1. Identify patient zero and infection vector")
            remediation.append("2. Block ransomware C2 domains/IPs at firewall")
            remediation.append("3. Reset ALL compromised credentials")
            remediation.append("4. Apply security patches for exploited vulnerabilities")
            remediation.append("")
            remediation.append("**RECOVERY (1-24 hours):**")
            remediation.append("1. Restore from clean, offline backups")
            remediation.append("2. Scan all restored files with updated AV/EDR signatures")
            remediation.append("3. Monitor for re-infection indicators")
            remediation.append("4. DO NOT PAY RANSOM - encourages further attacks")
        
        if has_privilege:
            remediation.append("**PRIVILEGE ESCALATION RESPONSE:**")
            remediation.append("1. Force password reset for all administrative accounts")
            remediation.append("2. Review and audit all privilege assignments in last 48 hours")
            remediation.append("3. Implement Just-In-Time (JIT) access for admin roles")
            remediation.append("4. Enable enhanced monitoring for affected accounts")
            remediation.append("5. Review and rotate service account credentials")
        
        if has_auth_failures:
            remediation.append("**AUTHENTICATION HARDENING:**")
            remediation.append("1. Enable Multi-Factor Authentication (MFA) for all users")
            remediation.append("2. Implement account lockout after 5 failed attempts")
            remediation.append("3. Block suspicious source IPs at perimeter firewall")
            remediation.append("4. Review and rotate credentials for affected user accounts")
            remediation.append("5. Implement passwordless authentication where possible")
        
        remediation.append("")
        remediation.append("**LONG-TERM SECURITY IMPROVEMENTS:**")
        remediation.append("1. Deploy Endpoint Detection and Response (EDR) solution")
        remediation.append("2. Implement Security Information and Event Management (SIEM)")
        remediation.append("3. Conduct regular security awareness training")
        remediation.append("4. Perform quarterly penetration testing")
        remediation.append("5. Maintain offline, immutable backups")
        
        return "\n".join(remediation)
    
    def _assess_final_risk(self, df: pd.DataFrame, attack_chains: List) -> str:
        """Final risk assessment"""
        
        assessment = []
        assessment.append("=" * 70)
        assessment.append("FINAL RISK ASSESSMENT")
        assessment.append("=" * 70)
        assessment.append("")
        
        if not attack_chains:
            assessment.append("**RISK LEVEL:** LOW")
            assessment.append("**BUSINESS IMPACT:** Minimal - No confirmed attack chain")
            assessment.append("**RECOMMENDATION:** Continue monitoring and investigate anomalies")
            assessment.append("**NEXT STEPS:** Enhance logging and review detection rules")
            return "\n".join(assessment)
        
        chain = attack_chains[0]
        confidence = chain.get('confidence', 50)
        
        if confidence >= 80:
            assessment.append("**RISK LEVEL:** CRITICAL")
            assessment.append("**LIKELIHOOD:** Confirmed - Active compromise detected")
            assessment.append("**BUSINESS IMPACT:** Critical - Data loss/ransomware confirmed")
            assessment.append("**RECOMMENDATION:** IMMEDIATE INCIDENT RESPONSE ACTIVATED")
            assessment.append("**NEXT STEPS:** Contain, eradicate, recover - executive notified")
        elif confidence >= 60:
            assessment.append("**RISK LEVEL:** HIGH")
            assessment.append("**LIKELIHOOD:** Likely - Strong evidence of compromise")
            assessment.append("**BUSINESS IMPACT:** High - Potential data breach/service disruption")
            assessment.append("**RECOMMENDATION:** URGENT INVESTIGATION - Escalate to IR team")
            assessment.append("**NEXT STEPS:** Full investigation within 4 hours")
        elif confidence >= 40:
            assessment.append("**RISK LEVEL:** MEDIUM")
            assessment.append("**LIKELIHOOD:** Possible - Suspicious activity detected")
            assessment.append("**BUSINESS IMPACT:** Medium - Potential unauthorized access")
            assessment.append("**RECOMMENDATION:** PRIORITY REVIEW - Investigate within 24 hours")
            assessment.append("**NEXT STEPS:** Deep dive analysis and log enrichment")
        else:
            assessment.append("**RISK LEVEL:** LOW-MEDIUM")
            assessment.append("**LIKELIHOOD:** Unlikely - Anomalous but not confirmed")
            assessment.append("**BUSINESS IMPACT:** Low - Limited evidence of compromise")
            assessment.append("**RECOMMENDATION:** STANDARD REVIEW - Investigate within 1 week")
            assessment.append("**NEXT STEPS:** Correlate with additional log sources")
        
        return "\n".join(assessment)
    
    # ============================================
    # NEW METHODS FOR SPECIFIC QUERIES
    # ============================================
    
    def investigate_incident(self, df: pd.DataFrame, intelligence: Dict) -> str:
        """Detailed incident investigation with suspicious IPs and users"""
    
        # Extract suspicious entities
        suspicious = self.extract_suspicious_entities(df, intelligence)
    
        lines = []
        lines.append("=" * 80)
        lines.append("🔍 INCIDENT INVESTIGATION REPORT")
        lines.append("=" * 80)
        lines.append("")
    
        # Determine incident type
        has_ransomware = False
        has_privilege = False
        has_auth_failures = False
        has_db_issue = False
    
        for p in intelligence.get('suspicious_patterns', []):
            pattern = p.get('pattern', '')
            if pattern == 'ransomware_indicators':
                has_ransomware = True
            elif pattern == 'privilege_escalation':
                has_privilege = True
            elif pattern == 'authentication_failure_cluster':
                has_auth_failures = True
            elif pattern == 'database_availability':
                has_db_issue = True
    
        lines.append("📋 INCIDENT CLASSIFICATION")
        lines.append("-" * 40)
    
        if has_ransomware:
            lines.append("Type: RANSOMWARE ATTACK (Critical)")
            lines.append("Status: Active - Immediate containment required")
            lines.append("Impact: Data encryption in progress")
        elif has_privilege and has_auth_failures:
            lines.append("Type: CREDENTIAL COMPROMISE with Privilege Escalation")
            lines.append("Status: Potential Active Compromise")
            lines.append("Impact: Unauthorized access to privileged accounts")
        elif has_privilege:
            lines.append("Type: PRIVILEGE ESCALATION Attempt")
            lines.append("Status: Investigation Required")
            lines.append("Impact: Potential insider threat or vulnerability exploit")
        elif has_db_issue:
            lines.append("Type: DATABASE AVAILABILITY Issue")
            lines.append("Status: Active Service Disruption")
            lines.append("Impact: Potential data breach or DoS")
        else:
            lines.append("Type: SUSPICIOUS ACTIVITY Investigation")
            lines.append("Status: Monitoring Required")
            lines.append("Impact: Under investigation")
    
        lines.append("")
        lines.append("🎯 ATTACKER BEHAVIOR ANALYSIS")
        lines.append("-" * 40)
    
        if has_ransomware:
            lines.append("1. Initial Access: Likely via compromised credentials")
            lines.append("2. Privilege Escalation: Attacker gained elevated rights")
            lines.append("3. Lateral Movement: Spread across environment")
            lines.append("4. Impact: Active ransomware deployment")
        elif has_privilege:
            lines.append("1. Suspicious authentication patterns detected")
            lines.append("2. Unauthorized privilege assignments observed")
            lines.append("3. Potential persistence mechanisms established")
    
        lines.append("")
        lines.append("📊 KEY FINDINGS")
        lines.append("-" * 40)
        lines.append(f"• Total suspicious patterns: {len(intelligence.get('suspicious_patterns', []))}")
        lines.append(f"• Affected users: {suspicious['total_suspicious_users']}")
        lines.append(f"• Suspicious IPs: {suspicious['total_suspicious_ips']}")
        lines.append(f"• Event correlations: {len(intelligence.get('event_correlations', []))}")
    
        # Display suspicious IPs
        if suspicious['suspicious_ips']:
            lines.append("\n🔴 SUSPICIOUS IP ADDRESSES FOUND:")
            for ip in suspicious['suspicious_ips'][:20]:
                lines.append(f"   • {ip}")
            if len(suspicious['suspicious_ips']) > 20:
                lines.append(f"   • ... and {len(suspicious['suspicious_ips']) - 20} more")
    
        # Display suspicious users
        if suspicious['suspicious_users']:
            lines.append("\n👤 SUSPICIOUS USERS FOUND:")
            for user in suspicious['suspicious_users'][:20]:
                lines.append(f"   • {user}")
            if len(suspicious['suspicious_users']) > 20:
                lines.append(f"   • ... and {len(suspicious['suspicious_users']) - 20} more")
    
        return "\n".join(lines)
    
    def show_attack_timeline(self, df: pd.DataFrame, intelligence: Dict) -> str:
        """Show detailed attack timeline"""
        
        lines = []
        lines.append("=" * 80)
        lines.append("📜 ATTACK TIMELINE - Chronological Event Sequence")
        lines.append("=" * 80)
        lines.append("")
        
        if 'timestamp_parsed' not in df.columns:
            return "No timestamp data available for timeline."
        
        # Sort by timestamp
        df_sorted = df.sort_values('timestamp_parsed')
        
        # Track phases
        phase_colors = {
            'recon': '🔍',
            'initial_access': '🚪',
            'execution': '⚡',
            'persistence': '💾',
            'privilege_escalation': '⬆️',
            'defense_evasion': '🛡️',
            'credential_access': '🔑',
            'discovery': '🔎',
            'lateral_movement': '🔄',
            'collection': '📦',
            'exfiltration': '📤',
            'impact': '💥'
        }
        
        phase = "recon"
        event_count = 0
        
        for idx, row in df_sorted.iterrows():
            ts = row.get('timestamp_parsed')
            if pd.isna(ts):
                continue
            
            severity = row.get('severity', 'INFO')
            source = row.get('source', 'Unknown')
            message = str(row.get('raw_log', ''))[:100]
            
            # Determine phase based on content
            if 'ransomware' in message.lower() or 'encrypt' in message.lower():
                phase = 'impact'
            elif 'privilege' in message.lower() or 'admin' in message.lower():
                phase = 'privilege_escalation'
            elif 'login fail' in message.lower() or 'auth' in message.lower():
                phase = 'credential_access'
            elif 'database unavailable' in message.lower():
                phase = 'impact'
            
            phase_icon = phase_colors.get(phase, '📌')
            
            lines.append(f"{phase_icon} [{ts.strftime('%Y-%m-%d %H:%M:%S')}] {phase.upper()}")
            lines.append(f"   Source: {source} | Severity: {severity}")
            lines.append(f"   Event: {message}")
            lines.append("")
            event_count += 1
            
            if event_count >= 30:
                lines.append(f"... and {len(df_sorted) - event_count} more events")
                break
        
        if event_count == 0:
            lines.append("No timeline events available.")
        
        return "\n".join(lines)
    
    def identify_root_cause(self, df: pd.DataFrame, intelligence: Dict) -> str:
        """Identify root cause of incident"""
        
        lines = []
        lines.append("=" * 80)
        lines.append("🎯 ROOT CAUSE ANALYSIS")
        lines.append("=" * 80)
        lines.append("")
        
        # Analyze patterns
        has_auth_failures = False
        has_privilege = False
        has_ransomware = False
        auth_count = 0
        
        for p in intelligence.get('suspicious_patterns', []):
            pattern = p.get('pattern', '')
            if pattern == 'authentication_failure_cluster':
                has_auth_failures = True
                auth_count = p.get('count', 0)
            elif pattern == 'privilege_escalation':
                has_privilege = True
            elif pattern == 'ransomware_indicators':
                has_ransomware = True
        
        lines.append("🔬 PRIMARY CAUSE")
        lines.append("-" * 40)
        
        if has_ransomware:
            lines.append("ROOT CAUSE: Credential Compromise leading to Ransomware Deployment")
            lines.append("")
            lines.append("EVIDENCE:")
            lines.append("1. Authentication anomalies detected - potential credential theft")
            lines.append("2. Privilege escalation confirms attacker gained elevated access")
            lines.append("3. Ransomware deployment confirms active attack")
            lines.append("")
            lines.append("LIKELY VECTOR: Phishing or password spray attack")
        
        elif has_privilege and has_auth_failures:
            lines.append("ROOT CAUSE: Credential Compromise with Privilege Escalation")
            lines.append("")
            lines.append("EVIDENCE:")
            lines.append(f"1. {auth_count} authentication failure events detected")
            lines.append("2. Successful privilege escalation following failures")
            lines.append("3. Correlation indicates successful compromise")
            lines.append("")
            lines.append("LIKELY VECTOR: Password brute force or credential stuffing")
        
        elif has_privilege:
            lines.append("ROOT CAUSE: Privilege Escalation (Insider or Vulnerability)")
            lines.append("")
            lines.append("EVIDENCE:")
            lines.append("1. Privilege escalation without authentication failures")
            lines.append("2. Unauthorized admin role assignments detected")
            lines.append("3. No preceding brute force indicators")
            lines.append("")
            lines.append("LIKELY VECTOR: Insider threat or unpatched vulnerability")
        
        else:
            lines.append("ROOT CAUSE: Under Investigation - Insufficient Evidence")
            lines.append("")
            lines.append("EVIDENCE:")
            lines.append("1. Anomalous patterns present but inconclusive")
            lines.append("2. Additional log sources recommended")
            lines.append("3. Enhanced monitoring enabled")
        
        lines.append("")
        lines.append("📋 CONTRIBUTING FACTORS")
        lines.append("-" * 40)
        
        if has_auth_failures:
            lines.append("• Weak password policies enabled")
            lines.append("• MFA not enforced for all accounts")
        if has_privilege:
            lines.append("• Excessive privileged accounts")
            lines.append("• Missing PAM solution")
        
        lines.append("• Insufficient logging on critical systems")
        
        return "\n".join(lines)
    
    def recommend_remediation(self, intelligence: Dict, attack_chains: List) -> str:
        """Generate remediation recommendations"""
        
        lines = []
        lines.append("=" * 80)
        lines.append("🛡️ REMEDIATION PLAN")
        lines.append("=" * 80)
        lines.append("")
        
        # Determine severity
        has_ransomware = False
        has_privilege = False
        for p in intelligence.get('suspicious_patterns', []):
            pattern = p.get('pattern', '')
            if pattern == 'ransomware_indicators':
                has_ransomware = True
            elif pattern == 'privilege_escalation':
                has_privilege = True
        
        lines.append("🚨 IMMEDIATE ACTIONS (0-1 hour)")
        lines.append("-" * 40)
        
        if has_ransomware:
            lines.append("1. [CRITICAL] ISOLATE affected systems from network")
            lines.append("2. [CRITICAL] Disable network shares and backup connections")
            lines.append("3. Activate Incident Response Team")
            lines.append("4. Capture forensic memory images before reboot")
            lines.append("5. Block identified C2 IPs at firewall")
        else:
            lines.append("1. Block suspicious source IPs at perimeter")
            lines.append("2. Force password reset for affected accounts")
            lines.append("3. Review and revoke suspicious admin privileges")
            lines.append("4. Enable enhanced logging on critical systems")
        
        lines.append("")
        lines.append("🛠️ SHORT-TERM ACTIONS (1-24 hours)")
        lines.append("-" * 40)
        
        if has_ransomware:
            lines.append("1. Identify patient zero and infection vector")
            lines.append("2. Rotate all KRBTGT and service account passwords")
            lines.append("3. Restore from clean, offline backups")
            lines.append("4. Scan all systems with updated AV signatures")
        else:
            lines.append("1. Review all admin account activities in last 7 days")
            lines.append("2. Implement JIT access for privileged accounts")
            lines.append("3. Deploy additional monitoring rules")
        
        lines.append("")
        lines.append("🔒 LONG-TERM ACTIONS (1-4 weeks)")
        lines.append("-" * 40)
        lines.append("1. Deploy Privileged Access Management (PAM) solution")
        lines.append("2. Implement Multi-Factor Authentication (MFA) for all users")
        lines.append("3. Deploy Endpoint Detection and Response (EDR)")
        lines.append("4. Conduct security awareness training")
        lines.append("5. Perform quarterly penetration testing")
        lines.append("6. Maintain offline, immutable backups")
        
        # Add specific IPs to block if found
        if intelligence.get('iocs', {}).get('ip_addresses'):
            lines.append("")
            lines.append("🔒 SPECIFIC IPs TO BLOCK:")
            for ip in intelligence['iocs']['ip_addresses'][:5]:
                lines.append(f"   • {ip}")
        
        return "\n".join(lines)
    
    def assess_risk_level(self, attack_chains: List, intelligence: Dict) -> str:
        """Assess risk level with detailed breakdown"""
        
        lines = []
        lines.append("=" * 80)
        lines.append("⚠️ RISK ASSESSMENT REPORT")
        lines.append("=" * 80)
        lines.append("")
        
        # Calculate risk scores
        has_ransomware = False
        has_privilege = False
        severity_scores = []
        
        for p in intelligence.get('suspicious_patterns', []):
            significance = p.get('significance', 'LOW')
            if significance == 'CRITICAL':
                severity_scores.append(95)
                if p.get('pattern') == 'ransomware_indicators':
                    has_ransomware = True
            elif significance == 'HIGH':
                severity_scores.append(75)
            elif significance == 'MEDIUM':
                severity_scores.append(50)
        
        if attack_chains:
            chain_confidence = attack_chains[0].get('confidence', 50)
        else:
            chain_confidence = 20
        
        avg_severity = sum(severity_scores) / len(severity_scores) if severity_scores else 20
        overall_risk = int((avg_severity + chain_confidence) / 2)
        
        if overall_risk >= 80:
            risk_level = "CRITICAL"
            risk_icon = "🔴"
            action = "IMMEDIATE INCIDENT RESPONSE - Executive notified"
        elif overall_risk >= 60:
            risk_level = "HIGH"
            risk_icon = "🟠"
            action = "URGENT INVESTIGATION - Escalate within 1 hour"
        elif overall_risk >= 40:
            risk_level = "MEDIUM"
            risk_icon = "🟡"
            action = "PRIORITY REVIEW - Investigate within 24 hours"
        else:
            risk_level = "LOW"
            risk_icon = "🟢"
            action = "STANDARD MONITORING - Review within 1 week"
        
        lines.append(f"{risk_icon} OVERALL RISK SCORE: {overall_risk}/100")
        lines.append(f"RISK LEVEL: {risk_level}")
        lines.append(f"RECOMMENDED ACTION: {action}")
        lines.append("")
        
        lines.append("📊 RISK COMPONENTS")
        lines.append("-" * 40)
        lines.append(f"• Attack Chain Confidence: {chain_confidence}/100")
        lines.append(f"• Severity Score: {int(avg_severity)}/100")
        lines.append(f"• Suspicious Patterns: {len(intelligence.get('suspicious_patterns', []))}")
        lines.append(f"• Affected Assets: {len(intelligence.get('affected_assets', {}).get('users', []))} users, {len(intelligence.get('affected_assets', {}).get('ip_addresses', []))} IPs")
        
        lines.append("")
        lines.append("🎯 BUSINESS IMPACT")
        lines.append("-" * 40)
        
        if has_ransomware:
            lines.append("Impact Level: CRITICAL")
            lines.append("Data Loss: Confirmed - Encryption in progress")
            lines.append("Operational Impact: Critical systems affected")
            lines.append("Recovery Time: 24-72 hours estimated")
        elif has_privilege:
            lines.append("Impact Level: HIGH")
            lines.append("Data Loss: Potential - Under investigation")
            lines.append("Operational Impact: Possible unauthorized access")
            lines.append("Recovery Time: 4-8 hours estimated")
        else:
            lines.append("Impact Level: LOW-MEDIUM")
            lines.append("Data Loss: None confirmed")
            lines.append("Operational Impact: Minimal")
            lines.append("Recovery Time: 1-2 hours estimated")
        
        return "\n".join(lines)
    
    def mitre_mapping(self, attack_chains: List) -> str:
        """Detailed MITRE ATT&CK mapping"""
        
        lines = []
        lines.append("=" * 80)
        lines.append("🧩 MITRE ATT&CK FRAMEWORK MAPPING")
        lines.append("=" * 80)
        lines.append("")
        
        if not attack_chains:
            return "No MITRE techniques identified."
        
        chain = attack_chains[0]
        techniques = chain.get('techniques', [])
        
        # Technique details
        technique_details = {
            'T1110': {'name': 'Brute Force', 'tactic': 'Credential Access', 'description': 'Multiple authentication attempts detected'},
            'T1078': {'name': 'Valid Accounts', 'tactic': 'Initial Access', 'description': 'Use of compromised credentials'},
            'T1059.001': {'name': 'PowerShell', 'tactic': 'Execution', 'description': 'PowerShell execution detected'},
            'T1068': {'name': 'Exploitation for Privilege Escalation', 'tactic': 'Privilege Escalation', 'description': 'Privilege escalation attempt'},
            'T1021': {'name': 'Remote Services', 'tactic': 'Lateral Movement', 'description': 'Remote execution detected'},
            'T1547': {'name': 'Boot or Logon Autostart Execution', 'tactic': 'Persistence', 'description': 'Persistence mechanism established'},
            'T1048': {'name': 'Exfiltration Over Alternative Protocol', 'tactic': 'Exfiltration', 'description': 'Data exfiltration detected'},
            'T1486': {'name': 'Data Encrypted for Impact', 'tactic': 'Impact', 'description': 'Ransomware encryption'},
            'T1562': {'name': 'Impair Defenses', 'tactic': 'Defense Evasion', 'description': 'Security control disabled'},
            'T1046': {'name': 'Network Service Scanning', 'tactic': 'Discovery', 'description': 'Port scan detected'},
            'T1071': {'name': 'Application Layer Protocol', 'tactic': 'Command and Control', 'description': 'C2 communication'},
            'T1499': {'name': 'Endpoint Denial of Service', 'tactic': 'Impact', 'description': 'DoS attack'}
        }
        
        lines.append("📋 DETECTED TECHNIQUES")
        lines.append("-" * 40)
        
        for tid in techniques:
            if tid in technique_details:
                details = technique_details[tid]
                lines.append(f"🔸 {tid} - {details['name']}")
                lines.append(f"   Tactic: {details['tactic']}")
                lines.append(f"   Description: {details['description']}")
                lines.append("")
        
        lines.append("🎯 ATTACK CHAIN")
        lines.append("-" * 40)
        attack_chain_sequence = [
            ("Initial Access", "T1078", "Valid Accounts"),
            ("Execution", "T1059.001", "PowerShell"),
            ("Persistence", "T1547", "Boot Autostart"),
            ("Privilege Escalation", "T1068", "Exploitation"),
            ("Defense Evasion", "T1562", "Impair Defenses"),
            ("Credential Access", "T1110", "Brute Force"),
            ("Discovery", "T1046", "Network Scanning"),
            ("Lateral Movement", "T1021", "Remote Services"),
            ("Collection", "T1005", "Data Collection"),
            ("Exfiltration", "T1048", "Data Exfiltration"),
            ("Command and Control", "T1071", "C2 Protocol"),
            ("Impact", "T1486", "Ransomware")
        ]
        
        found_techniques = set(techniques)
        for tactic, tid, name in attack_chain_sequence:
            if tid in found_techniques:
                lines.append(f"✅ {tactic}: {tid} - {name}")
            else:
                lines.append(f"❌ {tactic}: Not detected")
        
        lines.append("")
        lines.append("🛡️ RECOMMENDED DETECTIONS")
        lines.append("-" * 40)
        lines.append("• Enable PowerShell Script Block Logging (Event ID 4104)")
        lines.append("• Monitor for unusual admin privilege assignments (Event ID 4672)")
        lines.append("• Deploy EDR with behavioral detection")
        lines.append("• Implement User and Entity Behavior Analytics (UEBA)")
        
        return "\n".join(lines)
    
    def extract_iocs(self, intelligence: Dict) -> str:
        """Extract all Indicators of Compromise with full details"""
        
        lines = []
        lines.append("=" * 80)
        lines.append("🌐 INDICATORS OF COMPROMISE (IOCs) - Full Extraction")
        lines.append("=" * 80)
        lines.append("")
        
        iocs = intelligence.get('iocs', {})
        
        # IP Addresses
        lines.append("🖥️ IP ADDRESSES")
        lines.append("-" * 40)
        if iocs.get('ip_addresses'):
            for ip in iocs['ip_addresses']:
                lines.append(f"   🔴 {ip}")
            lines.append(f"\n   **Total: {len(iocs['ip_addresses'])} suspicious IPs**")
        else:
            lines.append("   • No suspicious IPs detected")
        lines.append("")
        
        # User Account Names
        lines.append("👤 USER ACCOUNT NAMES")
        lines.append("-" * 40)
        if iocs.get('usernames'):
            for user in iocs['usernames']:
                lines.append(f"   🟡 {user}")
            lines.append(f"\n   **Total: {len(iocs['usernames'])} affected users**")
        else:
            lines.append("   • No suspicious users detected")
        lines.append("")
        
        # Hostnames / Servers
        lines.append("🖥️ HOSTNAMES / SERVERS")
        lines.append("-" * 40)
        if iocs.get('hostnames'):
            for host in iocs['hostnames']:
                lines.append(f"   🟠 {host}")
            lines.append(f"\n   **Total: {len(iocs['hostnames'])} affected hosts**")
        else:
            lines.append("   • No affected hosts identified")
        lines.append("")
        
        # Services
        lines.append("🛠️ SERVICES / COMPONENTS")
        lines.append("-" * 40)
        if iocs.get('services'):
            for service in iocs['services']:
                lines.append(f"   📡 {service}")
            lines.append(f"\n   **Total: {len(iocs['services'])} services involved**")
        else:
            lines.append("   • No services identified")
        lines.append("")
        
        # Command Lines (if any)
        if iocs.get('commands'):
            lines.append("💻 SUSPICIOUS COMMANDS")
            lines.append("-" * 40)
            for cmd in iocs['commands'][:5]:
                lines.append(f"   • {cmd[:100]}")
            lines.append("")
        
        # IOC Summary
        lines.append("📊 IOC SUMMARY")
        lines.append("-" * 40)
        lines.append(f"| Type | Count |")
        lines.append(f"|------|-------|")
        lines.append(f"| IP Addresses | {len(iocs.get('ip_addresses', []))} |")
        lines.append(f"| Usernames | {len(iocs.get('usernames', []))} |")
        lines.append(f"| Hostnames | {len(iocs.get('hostnames', []))} |")
        lines.append(f"| Services | {len(iocs.get('services', []))} |")
        
        return "\n".join(lines)
    
    def list_affected_assets(self, intelligence: Dict) -> str:
        """List all affected assets with exact details"""
        
        lines = []
        lines.append("=" * 80)
        lines.append("🖥️ AFFECTED ASSETS - Exact Inventory")
        lines.append("=" * 80)
        lines.append("")
        
        affected = intelligence.get('affected_assets', {})
        
        # Users
        lines.append("👤 AFFECTED USERS")
        lines.append("-" * 40)
        if affected.get('users'):
            for user in affected['users']:
                lines.append(f"   • {user}")
            lines.append(f"\n   **Total: {len(affected['users'])} affected users**")
        else:
            lines.append("   • No affected users identified")
        lines.append("")
        
        # Hosts/Servers
        lines.append("🖥️ AFFECTED HOSTS / SERVERS")
        lines.append("-" * 40)
        if affected.get('hosts'):
            for host in affected['hosts']:
                lines.append(f"   • {host}")
            lines.append(f"\n   **Total: {len(affected['hosts'])} affected hosts**")
        else:
            lines.append("   • No affected hosts identified")
        lines.append("")
        
        # Services
        lines.append("🛠️ AFFECTED SERVICES")
        lines.append("-" * 40)
        if affected.get('services'):
            for service in affected['services']:
                status = "⚠️ IMPACTED" if service in ['DB-PRIMARY', 'SECURITY'] else "📡 MONITORING"
                lines.append(f"   • {service} - {status}")
            lines.append(f"\n   **Total: {len(affected['services'])} services affected**")
        else:
            lines.append("   • No affected services identified")
        lines.append("")
        
        # IP Addresses
        lines.append("🌐 AFFECTED IP ADDRESSES")
        lines.append("-" * 40)
        if affected.get('ip_addresses'):
            for ip in affected['ip_addresses']:
                lines.append(f"   • {ip}")
            lines.append(f"\n   **Total: {len(affected['ip_addresses'])} IPs affected**")
        else:
            lines.append("   • No affected IPs identified")
        
        return "\n".join(lines)
    
    def show_correlated_events(self, intelligence: Dict) -> str:
        """Show correlated events and attack chain connections"""
        
        lines = []
        lines.append("=" * 80)
        lines.append("🔗 CORRELATED EVENTS - Attack Chain Connections")
        lines.append("=" * 80)
        lines.append("")
        
        correlations = intelligence.get('event_correlations', [])
        
        if correlations:
            lines.append("📊 EVENT CORRELATIONS")
            lines.append("-" * 40)
            for corr in correlations:
                lines.append(f"🔄 {corr.get('correlation', 'Unknown').replace('_', ' ').title()}")
                lines.append(f"   Description: {corr.get('description', 'No description')}")
                lines.append("")
        else:
            lines.append("📊 EVENT CORRELATIONS")
            lines.append("-" * 40)
            lines.append("   No direct event correlations identified")
            lines.append("")
        
        # Build correlation map
        lines.append("🗺️ CORRELATION MAP")
        lines.append("-" * 40)
        lines.append("")
        
        has_auth = any(p.get('pattern') == 'authentication_failure_cluster' for p in intelligence.get('suspicious_patterns', []))
        has_priv = any(p.get('pattern') == 'privilege_escalation' for p in intelligence.get('suspicious_patterns', []))
        has_ransom = any(p.get('pattern') == 'ransomware_indicators' for p in intelligence.get('suspicious_patterns', []))
        
        if has_auth:
            lines.append("🔐 AUTHENTICATION FAILURES")
            lines.append("   └─ Possible credential compromise")
            lines.append("        └─ Could lead to Initial Access")
        
        if has_priv:
            lines.append("⬆️ PRIVILEGE ESCALATION")
            lines.append("   └─ Attacker gained elevated access")
            lines.append("        └─ Could enable Persistence")
        
        if has_ransom:
            lines.append("💥 RANSOMWARE DETECTION")
            lines.append("   └─ Active encryption in progress")
            lines.append("        └─ IMPACT - Critical systems affected")
        
        if not has_auth and not has_priv and not has_ransom:
            lines.append("   No correlation chains identified")
        
        return "\n".join(lines)
    
    def confidence_assessment(self, attack_chains: List, intelligence: Dict, correlations: List) -> str:
        """Detailed confidence assessment"""
        
        lines = []
        lines.append("=" * 80)
        lines.append("📊 CONFIDENCE ASSESSMENT - Evidence Quality")
        lines.append("=" * 80)
        lines.append("")
        
        # Calculate evidence scores
        evidence_scores = []
        
        # Check evidence types
        has_ransomware = any(p.get('pattern') == 'ransomware_indicators' for p in intelligence.get('suspicious_patterns', []))
        has_privilege = any(p.get('pattern') == 'privilege_escalation' for p in intelligence.get('suspicious_patterns', []))
        has_auth = any(p.get('pattern') == 'authentication_failure_cluster' for p in intelligence.get('suspicious_patterns', []))
        
        evidence_types = []
        if has_ransomware:
            evidence_types.append({"type": "Ransomware Indicators", "weight": 95, "confidence": "HIGH"})
        if has_privilege:
            evidence_types.append({"type": "Privilege Escalation", "weight": 85, "confidence": "HIGH"})
        if has_auth:
            auth_count = 0
            for p in intelligence.get('suspicious_patterns', []):
                if p.get('pattern') == 'authentication_failure_cluster':
                    auth_count = p.get('count', 0)
            weight = min(50 + (auth_count / 10), 85)
            evidence_types.append({"type": f"Authentication Failures ({auth_count})", "weight": weight, "confidence": "MEDIUM-HIGH"})
        
        if intelligence.get('iocs', {}).get('ip_addresses'):
            evidence_types.append({"type": "Suspicious IP Addresses", "weight": 60, "confidence": "MEDIUM"})
        
        if intelligence.get('event_correlations'):
            evidence_types.append({"type": "Event Correlations", "weight": 70, "confidence": "MEDIUM-HIGH"})
        
        lines.append("📋 EVIDENCE INVENTORY")
        lines.append("-" * 40)
        for ev in evidence_types:
            lines.append(f"• {ev['type']}: {ev['weight']}/100 - {ev['confidence']}")
        lines.append("")
        
        # Overall confidence
        if evidence_types:
            overall_conf = sum(e['weight'] for e in evidence_types) / len(evidence_types)
        else:
            overall_conf = 20
        
        if overall_conf >= 80:
            conf_level = "HIGH"
            conf_icon = "🟢"
        elif overall_conf >= 60:
            conf_level = "MEDIUM-HIGH"
            conf_icon = "🟡"
        elif overall_conf >= 40:
            conf_level = "MEDIUM"
            conf_icon = "🟠"
        else:
            conf_level = "LOW"
            conf_icon = "🔴"
        
        lines.append(f"{conf_icon} OVERALL CONFIDENCE: {conf_level} ({int(overall_conf)}/100)")
        lines.append("")
        
        lines.append("🔍 CONFIDENCE FACTORS")
        lines.append("-" * 40)
        lines.append("✓ Direct evidence of malicious activity")
        if has_ransomware:
            lines.append("✓ High-confidence ransomware indicators")
        if has_privilege and has_auth:
            lines.append("✓ Correlated attack chain with multiple phases")
        if len(evidence_types) >= 3:
            lines.append("✓ Multiple independent evidence sources")
        lines.append("")
        
        lines.append("⚠️ CONFIDENCE LIMITATIONS")
        lines.append("-" * 40)
        if not has_ransomware:
            lines.append("• No confirmed ransomware indicators")
        if not intelligence.get('event_correlations'):
            lines.append("• Limited event correlation available")
        lines.append("• Additional log sources would increase confidence")
        
        return "\n".join(lines)
    
    def _empty_response(self) -> Dict:
        """Empty response when no data"""
        return {
            'executive_summary': "No data loaded. Please upload logs for investigation.",
            'incident_narrative': "Unable to investigate without data.",
            'attack_timeline': [],
            'attack_chain': [],
            'indicators_of_compromise': {},
            'mitre_mapping': [],
            'root_cause_analysis': "Insufficient data for root cause analysis.",
            'affected_assets': {},
            'confidence_scores': {'overall_confidence': 0},
            'remediation_plan': "Load log data to generate remediation plan.",
            'final_risk_assessment': "Unable to assess risk without data."
        }
    
    def chat(self, user_question: str, df: pd.DataFrame) -> Dict:
        """
        Main chat interface - Routes to specific investigation methods
        """
        investigation = self.investigate(df, user_question)
    
        # Get intelligence and attack chains from investigation
        intelligence = self._extract_intelligence(df)
        attack_chains = investigation.get('attack_chain', [])
        correlations = intelligence.get('event_correlations', [])
    
        # ===== DEFINE SUSPICIOUS HERE =====
        suspicious = {
            'suspicious_ips': [],
            'suspicious_users': [],
            'total_suspicious_ips': 0,
            'total_suspicious_users': 0
        }
    
        question_lower = user_question.lower()
    
        # Route to specific method based on question
        if 'investigate' in question_lower or 'incident' in question_lower:
            insight = self.investigate_incident(df, intelligence)
        elif 'timeline' in question_lower:
            insight = self.show_attack_timeline(df, intelligence)
        elif 'root cause' in question_lower or 'identify root' in question_lower:
            insight = self.identify_root_cause(df, intelligence)
        elif 'remediation' in question_lower or 'recommend' in question_lower:
            insight = self.recommend_remediation(intelligence, attack_chains)
        elif 'risk' in question_lower or 'assess risk' in question_lower:
            insight = self.assess_risk_level(attack_chains, intelligence)
        elif 'mitre' in question_lower or 'attack' in question_lower:
            insight = self.mitre_mapping(attack_chains)
        elif 'ioc' in question_lower or 'indicator' in question_lower or 'extract' in question_lower:
            insight = self.extract_iocs(intelligence)
        elif 'asset' in question_lower or 'affected' in question_lower:
            insight = self.list_affected_assets(intelligence)
        elif 'correlated' in question_lower or 'correlation' in question_lower:
            insight = self.show_correlated_events(intelligence)
        elif 'confidence' in question_lower or 'assessment' in question_lower:
            insight = self.confidence_assessment(attack_chains, intelligence, correlations)
        else:
            # Default - full investigation summary
            insight = f"{investigation['executive_summary']}\n\n{investigation['incident_narrative']}\n\n{investigation['final_risk_assessment']}"
    
        return {
            'question': user_question,
            'results': df.head(20) if len(df) > 20 else df,
            'results_count': len(df),
            'insight': insight,
            'query_code': 'soc_analyst_investigation',

            'executive_summary': investigation.get('executive_summary', 'Investigation completed. Review findings above.'),
            'incident_narrative': investigation.get('incident_narrative', 'See attack timeline for details.'),
            'root_cause_analysis': investigation.get('root_cause_analysis', 'Review the attack chain for root cause analysis.'),
            'confidence_scores': investigation.get('confidence_scores', {
                'overall_confidence': 50,
                'attack_chain_confidence': 50,
                'root_cause_confidence': 50,
                'ioc_confidence': 50
            }),
            'remediation_plan': investigation.get('remediation_plan', 'See remediation recommendations below.'),
            'final_risk_assessment': investigation.get('final_risk_assessment', 'Risk level determined by severity scores.'),
            'indicators_of_compromise': intelligence.get('iocs', {}),
            'affected_assets': intelligence.get('affected_assets', {}),
            'attack_chain': attack_chains,
            'mitre_mapping': investigation.get('mitre_mapping', []),
    
            # Suspicious IPs & Users
            'suspicious_ips': suspicious.get('suspicious_ips', []),
            'suspicious_users': suspicious.get('suspicious_users', []),
            'total_suspicious_ips': suspicious.get('total_suspicious_ips', 0),
            'total_suspicious_users': suspicious.get('total_suspicious_users', 0)
        }
    
    def get_conversation_history(self) -> List:
        return self.conversation_history
    
    def clear_memory(self):
        self.conversation_history = []
        self.current_investigation = None


# ============================================
# TESTING
# ============================================

if __name__ == "__main__":
    print("🔬 Testing SOC Analyst Agent")
    print("=" * 60)
    
    # Create test data
    test_df = pd.DataFrame({
        'timestamp': [
            '2026-06-05T08:00:01.125Z', '2026-06-05T08:15:33.230Z',
            '2026-06-05T08:15:34.012Z', '2026-06-05T08:40:55.920Z',
            '2026-06-05T08:41:10.102Z', '2026-06-05T08:43:41.788Z',
            '2026-06-05T08:43:42.101Z', '2026-06-05T09:01:22.119Z',
            '2026-06-05T09:01:24.447Z'
        ],
        'severity': ['INFO', 'HIGH', 'HIGH', 'CRITICAL', 'CRITICAL', 'HIGH', 'CRITICAL', 'EMERGENCY', 'EMERGENCY'],
        'source': ['AUTH-SVC', 'SECURITY', 'SECURITY', 'DB-PRIMARY', 'DB-PRIMARY', 'SECURITY', 'SECURITY', 'SECURITY', 'SECURITY'],
        'raw_log': [
            'Service startup complete',
            'Excessive login failures user=admin source_ip=185.44.10.7 failures=25',
            'Account lockout triggered user=admin duration=30m',
            'Replication lag exceeded threshold lag_seconds=620',
            'Primary database unavailable node=db-prod-01',
            'Suspicious privilege escalation detected user=svc-reports',
            'Unauthorized admin role assignment user=svc-reports target_role=SUPER_ADMIN',
            'Potential ransomware activity detected host=finance-server-02',
            'File encryption spike detected affected_files=18423'
        ]
    })
    
    agent = SOCAnalystAgent(verbose=True)
    
    # Test IOC extraction
    print("Testing IOC Extraction...")
    result = agent.chat("extract IOCs", test_df)
    print(result['insight'])
    
    print("\n" + "=" * 60)
    print("✅ SOC Analyst Agent Ready")