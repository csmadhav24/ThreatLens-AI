# app/analyzers/threat_detector.py
"""
Threat Detector Module - Pattern matching, IOC detection, threat hunting
Updated to handle custom severity levels: HIGH, CRITICAL, EMERGENCY, ALERT
"""

import pandas as pd
import re
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import hashlib
import json

# Import config
import sys
sys.path.append(str(Path(__file__).parent.parent))
from config import SUSPICIOUS_PATTERNS, WINDOWS_EVENT_IDS


class ThreatDetector:
    """
    Threat detection engine for logs and network data
    """
    
    # Severity weights for risk calculation
    SEVERITY_WEIGHTS = {
        'EMERGENCY': 100,
        'CRITICAL': 90,
        'HIGH': 75,
        'ALERT': 70,
        'ERROR': 60,
        'WARN': 40,
        'WARNING': 40,
        'INFO': 10,
        'DEBUG': 5,
        'LOW': 20,
        'MEDIUM': 50
    }
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.detected_threats = []
        self.ioc_hits = []
        
        # Compile regex patterns
        self._compile_patterns()
    
    def _compile_patterns(self):
        """Compile regex patterns for faster matching"""
        self.compiled_patterns = {}
        
        for category, patterns in SUSPICIOUS_PATTERNS.get('command_patterns', {}).items():
            self.compiled_patterns[category] = patterns
        
        self.powershell_pattern_str = '|'.join(SUSPICIOUS_PATTERNS.get('powershell_suspicious_args', []))
        self.ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
        self.domain_pattern = re.compile(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b')
    
    def _get_column(self, df: pd.DataFrame, possible_names: List[str]) -> Optional[str]:
        """Find column by checking multiple possible names"""
        for name in possible_names:
            if name in df.columns:
                return name
            lower_name = name.lower()
            for col in df.columns:
                if col.lower() == lower_name:
                    return col
        return None
    
    def analyze_logs(self, df: pd.DataFrame) -> Dict[str, Any]:
        """
        Main analysis method for log data
        """
        if df is None or df.empty:
            return {'error': 'No data to analyze', 'risk_score': 0}
        
        if self.verbose:
            print(f"🔍 Analyzing {len(df)} log entries for threats")
            print(f"   Available columns: {list(df.columns)}")
        
        # Map column names
        self.timestamp_col = self._get_column(df, ['timestamp', 'time', 'datetime', 'date', '@timestamp'])
        self.user_col = self._get_column(df, ['user', 'username', 'user_name', 'account'])
        self.source_ip_col = self._get_column(df, ['source_ip', 'src_ip', 'ip', 'client_ip', 'source'])
        self.event_id_col = self._get_column(df, ['event_id', 'eventid', 'event_code', 'id'])
        self.process_col = self._get_column(df, ['process', 'process_name', 'image'])
        self.commandline_col = self._get_column(df, ['commandline', 'command_line', 'cmdline', 'args'])
        self.raw_log_col = self._get_column(df, ['raw_log', 'message', 'raw', 'log'])
        self.severity_col = self._get_column(df, ['severity', 'level', 'priority'])
        self.source_col = self._get_column(df, ['source', 'service', 'component', 'module'])
        
        findings = {
            'timestamp': datetime.now().isoformat(),
            'total_events': len(df),
            'failed_logins': [],
            'successful_logins': [],
            'suspicious_powershell': [],
            'privilege_escalation': [],
            'lateral_movement': [],
            'persistence_attempts': [],
            'high_risk_commands': [],
            'suspicious_processes': [],
            'ioc_matches': [],
            'anomalies': [],
            'severity_breakdown': {},
            'summary': {}
        }
        
        # Analyze severity distribution first (this affects risk score)
        self._analyze_severity_distribution(df, findings)
        
        # Run detection modules
        self._detect_security_events(df, findings)
        self._detect_authentication_anomalies(df, findings)
        self._detect_suspicious_processes(df, findings)
        self._detect_command_line_threats(df, findings)
        self._detect_persistence(df, findings)
        self._detect_lateral_movement(df, findings)
        self._detect_iocs(df, findings)
        self._detect_temporal_anomalies(df, findings)
        
        findings['summary'] = self._generate_summary(findings)
        findings['risk_score'] = self._calculate_risk_score(findings, df)
        
        if self.verbose:
            print(f"✅ Detection complete: {findings['risk_score']}/100 risk score")
            print(f"   Severities found: {findings.get('severity_breakdown', {})}")
        
        return findings
    
    def _analyze_severity_distribution(self, df: pd.DataFrame, findings: Dict):
        """Analyze severity distribution for risk calculation"""
        
        if self.severity_col and self.severity_col in df.columns:
            severity_counts = df[self.severity_col].value_counts().to_dict()
            findings['severity_breakdown'] = severity_counts
            
            if self.verbose:
                print(f"   Severity distribution: {severity_counts}")
            
            # Add high severity events as anomalies
            high_severities = ['EMERGENCY', 'CRITICAL', 'HIGH', 'ALERT']
            for severity in high_severities:
                if severity in severity_counts and severity_counts[severity] > 0:
                    findings['anomalies'].append({
                        'type': f'high_severity_{severity.lower()}_events',
                        'count': severity_counts[severity],
                        'severity': 'CRITICAL' if severity in ['EMERGENCY', 'CRITICAL'] else 'HIGH',
                        'details': f"{severity_counts[severity]} {severity} severity events detected"
                    })
    
    def _detect_security_events(self, df: pd.DataFrame, findings: Dict):
        """Detect security-related events from log messages"""
        
        if self.raw_log_col is None and self.source_col is None:
            return
        
        # Security-related keywords to look for
        security_events = {
            'excessive_login_failures': {
                'keywords': ['excessive login failures', 'brute force', 'password spraying'],
                'severity': 'HIGH'
            },
            'account_lockout': {
                'keywords': ['account lockout', 'locked out'],
                'severity': 'HIGH'
            },
            'privilege_escalation': {
                'keywords': ['privilege escalation', 'unauthorized admin role', 'privilege elevation'],
                'severity': 'CRITICAL'
            },
            'ransomware': {
                'keywords': ['ransomware', 'file encryption', 'encryption spike'],
                'severity': 'CRITICAL'
            },
            'unauthorized_access': {
                'keywords': ['unauthorized', 'permission denied', 'access denied'],
                'severity': 'HIGH'
            },
            'suspicious_activity': {
                'keywords': ['suspicious', 'malicious', 'anomaly detected'],
                'severity': 'HIGH'
            }
        }
        
        # Search in raw_log or message
        search_col = self.raw_log_col if self.raw_log_col else self.source_col
        if search_col and search_col in df.columns:
            for event_type, config in security_events.items():
                for keyword in config['keywords']:
                    mask = df[search_col].str.contains(keyword, case=False, na=False)
                    matches = df[mask]
                    
                    if not matches.empty:
                        for _, row in matches.iterrows():
                            finding = {
                                'timestamp': row.get(self.timestamp_col) if self.timestamp_col else None,
                                'event_type': event_type,
                                'severity': config['severity'],
                                'details': row.get(search_col, '')[:200]
                            }
                            
                            if event_type == 'privilege_escalation':
                                findings['privilege_escalation'].append(finding)
                            elif event_type == 'ransomware':
                                findings['high_risk_commands'].append(finding)
                            else:
                                findings['anomalies'].append({
                                    'type': event_type,
                                    'severity': config['severity'],
                                    'details': row.get(search_col, '')[:200]
                                })
    
    def _detect_authentication_anomalies(self, df: pd.DataFrame, findings: Dict):
        """Detect authentication failures and anomalies"""
        
        # Patterns for failed authentication
        failed_patterns = [
            'excessive login failures', 'failed login', 'authentication failed',
            'invalid credentials', 'account lockout', 'brute force'
        ]
        
        failed_mask = pd.Series([False] * len(df))
        search_col = self.raw_log_col if self.raw_log_col else self.source_col
        
        if search_col and search_col in df.columns:
            for pattern in failed_patterns:
                failed_mask |= df[search_col].str.contains(pattern, case=False, na=False)
        
        failed_events = df[failed_mask]
        
        if not failed_events.empty:
            result_columns = []
            if self.timestamp_col:
                result_columns.append(self.timestamp_col)
            if self.user_col:
                result_columns.append(self.user_col)
            if self.source_ip_col:
                result_columns.append(self.source_ip_col)
            if self.severity_col:
                result_columns.append(self.severity_col)
            if search_col:
                result_columns.append(search_col)
            
            if result_columns:
                findings['failed_logins'] = failed_events[result_columns].head(100).to_dict('records')
            else:
                findings['failed_logins'] = failed_events.head(100).to_dict('records')
            
            # Brute force detection
            if len(failed_events) > 5:
                findings['anomalies'].append({
                    'type': 'brute_force_suspected',
                    'failed_attempts': len(failed_events),
                    'severity': 'HIGH',
                    'details': f"{len(failed_events)} authentication failure events detected"
                })
    
    def _detect_suspicious_processes(self, df: pd.DataFrame, findings: Dict):
        """Detect suspicious process executions"""
        # This is more relevant for Windows logs, skip if not applicable
        pass
    
    def _detect_command_line_threats(self, df: pd.DataFrame, findings: Dict):
        """Detect threats in command line arguments"""
        # This is more relevant for Windows logs, skip if not applicable
        pass
    
    def _detect_persistence(self, df: pd.DataFrame, findings: Dict):
        """Detect persistence mechanisms"""
        # This is more relevant for Windows logs, skip if not applicable
        pass
    
    def _detect_lateral_movement(self, df: pd.DataFrame, findings: Dict):
        """Detect lateral movement indicators"""
        # This is more relevant for Windows logs, skip if not applicable
        pass
    
    def _detect_iocs(self, df: pd.DataFrame, findings: Dict):
        """Detect Indicators of Compromise (IOCs)"""
        findings['ioc_matches'] = []
    
    def _detect_temporal_anomalies(self, df: pd.DataFrame, findings: Dict):
        """Detect time-based anomalies"""
        
        if not self.timestamp_col:
            return
        
        try:
            df_copy = df.copy()
            df_copy[self.timestamp_col] = pd.to_datetime(df_copy[self.timestamp_col], errors='coerce')
            df_copy = df_copy.dropna(subset=[self.timestamp_col])
            
            if df_copy.empty:
                return
            
            df_copy['hour'] = df_copy[self.timestamp_col].dt.hour
            off_hours = df_copy[df_copy['hour'].isin([22, 23, 0, 1, 2, 3, 4, 5, 6])]
            
            if len(off_hours) > len(df_copy) * 0.3:
                findings['anomalies'].append({
                    'type': 'off_hours_activity',
                    'percentage': (len(off_hours) / len(df_copy)) * 100,
                    'severity': 'MEDIUM',
                    'details': f"{len(off_hours)} events occurred during off-hours"
                })
        except Exception as e:
            if self.verbose:
                print(f"Temporal analysis skipped: {e}")
    
    def _generate_summary(self, findings: Dict) -> Dict:
        """Generate summary of all findings"""
        summary = {
            'total_findings': 0,
            'critical_count': 0,
            'high_count': 0,
            'medium_count': 0,
            'low_count': 0,
            'categories': {}
        }
        
        for key, value in findings.items():
            if isinstance(value, list) and key not in ['summary', 'anomalies']:
                for item in value:
                    severity = item.get('severity', 'LOW')
                    if severity == 'CRITICAL':
                        summary['critical_count'] += 1
                    elif severity == 'HIGH':
                        summary['high_count'] += 1
                    elif severity == 'MEDIUM':
                        summary['medium_count'] += 1
                    else:
                        summary['low_count'] += 1
                    summary['total_findings'] += 1
        
        for anomaly in findings.get('anomalies', []):
            severity = anomaly.get('severity', 'LOW')
            if severity == 'CRITICAL':
                summary['critical_count'] += 1
            elif severity == 'HIGH':
                summary['high_count'] += 1
            else:
                summary['medium_count'] += 1
            summary['total_findings'] += 1
        
        # Add severity breakdown to summary
        summary['severity_breakdown'] = findings.get('severity_breakdown', {})
        
        return summary
    
    def _calculate_risk_score(self, findings: Dict, df: pd.DataFrame) -> int:
        """
        Calculate overall risk score based on severity levels and findings
        """
        score = 0
        
        # Factor 1: Severity distribution from logs (40% weight)
        severity_breakdown = findings.get('severity_breakdown', {})
        severity_score = 0
        total_severity_weight = 0
        
        for severity, count in severity_breakdown.items():
            weight = self.SEVERITY_WEIGHTS.get(severity.upper(), 20)
            # Cap at 100 per severity type
            severity_score += min(weight * min(count, 10) / 10, 100)
            total_severity_weight += 1
        
        if total_severity_weight > 0:
            severity_score = min(severity_score / total_severity_weight, 100)
        else:
            severity_score = 0
        
        score += severity_score * 0.4
        
        # Factor 2: Critical/High findings from detection (30% weight)
        critical_count = findings['summary'].get('critical_count', 0)
        high_count = findings['summary'].get('high_count', 0)
        
        detection_score = min((critical_count * 20 + high_count * 10), 100)
        score += detection_score * 0.3
        
        # Factor 3: Volume of events (15% weight)
        total_events = findings.get('total_events', 0)
        if total_events > 100:
            volume_score = min(70 + (total_events - 100) / 10, 100)
        elif total_events > 50:
            volume_score = 50
        elif total_events > 20:
            volume_score = 30
        elif total_events > 10:
            volume_score = 20
        else:
            volume_score = 10
        
        score += volume_score * 0.15
        
        # Factor 4: Recency (15% weight)
        recency_score = self._calculate_recency_score(df)
        score += recency_score * 0.15
        
        return min(int(score), 100)
    
    def _calculate_recency_score(self, df: pd.DataFrame) -> float:
        """Calculate recency score based on latest event timestamp"""
        
        if not self.timestamp_col or self.timestamp_col not in df.columns:
            return 50
        
        try:
            timestamps = pd.to_datetime(df[self.timestamp_col], errors='coerce')
            latest = timestamps.max()
            
            if pd.isna(latest):
                return 50
            
            now = datetime.now()
            time_diff = now - latest
            
            if time_diff.total_seconds() < 3600:  # Last hour
                return 100
            elif time_diff.total_seconds() < 86400:  # Last day
                return 80
            elif time_diff.total_seconds() < 604800:  # Last week
                return 50
            else:
                return 30
        except:
            return 50
    
    def analyze_pcap(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Analyze PCAP data for network threats"""
        return {'error': 'PCAP analysis requires Scapy'}


# ============================================
# TESTING CODE
# ============================================

if __name__ == "__main__":
    print("🧪 Testing Threat Detector Module")
    print("=" * 50)
    
    # Create test data with your log format
    test_data = pd.DataFrame({
        'timestamp': [
            '2026-06-05T08:15:33.230Z', '2026-06-05T08:41:10.102Z', 
            '2026-06-05T08:43:42.101Z', '2026-06-05T09:01:22.119Z'
        ],
        'severity': ['HIGH', 'CRITICAL', 'CRITICAL', 'EMERGENCY'],
        'source': ['SECURITY', 'DB-PRIMARY', 'SECURITY', 'SECURITY'],
        'raw_log': [
            'Excessive login failures user=admin source_ip=185.44.10.7',
            'Primary database unavailable node=db-prod-01',
            'Unauthorized admin role assignment user=svc-reports',
            'Potential ransomware activity detected host=finance-server-02'
        ]
    })
    
    detector = ThreatDetector(verbose=True)
    findings = detector.analyze_logs(test_data)
    
    print(f"\n📊 Results:")
    print(f"   Risk Score: {findings['risk_score']}/100")
    print(f"   Severity Breakdown: {findings.get('severity_breakdown', {})}")
    print(f"   Critical Findings: {findings['summary']['critical_count']}")
    print(f"   High Findings: {findings['summary']['high_count']}")
    
    print("\n" + "=" * 50)
    print("✅ Threat Detector Module Ready")