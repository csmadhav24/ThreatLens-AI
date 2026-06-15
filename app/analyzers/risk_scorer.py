# app/analyzers/risk_scorer.py
"""
Advanced Risk Scoring Module
Calculates risk scores based on multiple factors: severity, impact, likelihood, asset value
Provides prioritization and business impact assessment
"""

import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Tuple
from collections import defaultdict
import math

# Import config
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))
from config import RISK_THRESHOLDS, RISK_LEVELS


class RiskScorer:
    """
    Advanced risk scoring engine for security findings
    Calculates risk based on: severity, impact, likelihood, asset criticality
    """
    
    # Asset criticality weights
    ASSET_CRITICALITY = {
        'domain_controller': 100,
        'database_server': 95,
        'file_server': 80,
        'web_server': 75,
        'application_server': 70,
        'workstation': 50,
        'user_endpoint': 45,
        'network_device': 60,
        'unknown': 40
    }
    
    # Finding type base scores
    FINDING_BASE_SCORES = {
        'suspicious_powershell': 85,
        'lateral_movement': 90,
        'privilege_escalation': 95,
        'ransomware': 100,
        'data_exfiltration': 90,
        'malware': 85,
        'brute_force': 65,
        'failed_logins': 50,
        'port_scan': 40,
        'persistence_attempts': 75,
        'defense_evasion': 80,
        'anomaly': 45,
        'default': 50
    }
    
    # Time decay factors (newer events are more severe)
    TIME_DECAY_FACTORS = {
        'last_hour': 1.0,
        'last_day': 0.9,
        'last_week': 0.7,
        'last_month': 0.5,
        'older': 0.3
    }
    
    def __init__(self, organization_context: Dict[str, Any] = None):
        """
        Initialize risk scorer
        
        Args:
            organization_context: Organization-specific context (critical assets, etc.)
        """
        self.context = organization_context or {}
        self.risk_history = []
        
    def calculate_overall_risk(self, findings: Dict[str, Any]) -> Dict[str, Any]:
        """
        Calculate overall risk score from findings
        
        Args:
            findings: Findings dictionary from ThreatDetector
            
        Returns:
            Comprehensive risk assessment
        """
        # Calculate component scores
        severity_score = self._calculate_severity_score(findings)
        volume_score = self._calculate_volume_score(findings)
        recency_score = self._calculate_recency_score(findings)
        impact_score = self._calculate_impact_score(findings)
        likelihood_score = self._calculate_likelihood_score(findings)
        
        # Weighted average
        overall_score = (
            severity_score * 0.35 +
            volume_score * 0.15 +
            recency_score * 0.15 +
            impact_score * 0.20 +
            likelihood_score * 0.15
        )
        
        # Determine risk level
        risk_level = self._get_risk_level(overall_score)
        
        # Generate factors that contributed
        contributing_factors = self._identify_contributing_factors(findings)
        
        risk_assessment = {
            'overall_risk_score': round(overall_score, 2),
            'risk_level': risk_level['name'],
            'risk_color': risk_level['color'],
            'risk_emoji': risk_level['emoji'],
            'component_scores': {
                'severity': round(severity_score, 2),
                'volume': round(volume_score, 2),
                'recency': round(recency_score, 2),
                'impact': round(impact_score, 2),
                'likelihood': round(likelihood_score, 2)
            },
            'contributing_factors': contributing_factors[:10],
            'recommended_action': self._get_recommended_action(overall_score),
            'response_timeframe': self._get_response_timeframe(overall_score),
            'timestamp': datetime.now().isoformat()
        }
        
        # Store in history
        self.risk_history.append({
            'timestamp': datetime.now().isoformat(),
            'score': overall_score,
            'level': risk_level['name']
        })
        
        return risk_assessment
    
    def _calculate_severity_score(self, findings: Dict[str, Any]) -> float:
        """Calculate severity score based on finding types"""
        scores = []
        
        for finding_type, base_score in self.FINDING_BASE_SCORES.items():
            findings_list = findings.get(finding_type, [])
            if findings_list:
                # Weight by number of findings
                count = len(findings_list)
                weighted_score = base_score * min(count / 10, 1.5)  # Cap at 1.5x
                scores.append(weighted_score)
        
        # Add anomalies
        for anomaly in findings.get('anomalies', []):
            severity = anomaly.get('severity', 'MEDIUM')
            anomaly_scores = {'CRITICAL': 90, 'HIGH': 70, 'MEDIUM': 50, 'LOW': 30}
            scores.append(anomaly_scores.get(severity, 50))
        
        if not scores:
            return 0
        
        # Take maximum score (most severe finding)
        return min(max(scores), 100)
    
    def _calculate_volume_score(self, findings: Dict[str, Any]) -> float:
        """Calculate volume-based score (more findings = higher risk)"""
        total_findings = findings.get('summary', {}).get('total_findings', 0)
        
        if total_findings == 0:
            return 0
        elif total_findings <= 5:
            return 20
        elif total_findings <= 20:
            return 40
        elif total_findings <= 50:
            return 60
        elif total_findings <= 100:
            return 80
        else:
            return 100
    
    def _calculate_recency_score(self, findings: Dict[str, Any]) -> float:
        """Calculate recency score (newer events = higher risk)"""
        latest_timestamp = None
        
        # Find latest timestamp across all findings
        for finding_type in ['failed_logins', 'suspicious_powershell', 'privilege_escalation', 
                            'lateral_movement', 'persistence_attempts']:
            for finding in findings.get(finding_type, []):
                ts = finding.get('timestamp')
                if ts:
                    try:
                        if isinstance(ts, str):
                            ts = pd.to_datetime(ts)
                        if latest_timestamp is None or ts > latest_timestamp:
                            latest_timestamp = ts
                    except:
                        pass
        
        # Check anomalies
        for anomaly in findings.get('anomalies', []):
            ts = anomaly.get('timestamp')
            if ts:
                try:
                    if isinstance(ts, str):
                        ts = pd.to_datetime(ts)
                    if latest_timestamp is None or ts > latest_timestamp:
                        latest_timestamp = ts
                except:
                    pass
        
        if latest_timestamp is None:
            return 50  # Default medium score
        
        now = datetime.now()
        time_diff = now - latest_timestamp
        
        if time_diff.total_seconds() < 3600:  # Last hour
            return 100
        elif time_diff.total_seconds() < 86400:  # Last day
            return 85
        elif time_diff.total_seconds() < 604800:  # Last week
            return 60
        elif time_diff.total_seconds() < 2592000:  # Last month
            return 40
        else:
            return 20
    
    def _calculate_impact_score(self, findings: Dict[str, Any]) -> float:
        """Calculate potential business impact"""
        impact = 0
        
        # Check for findings with high impact
        if findings.get('suspicious_powershell'):
            impact += 25
        if findings.get('lateral_movement'):
            impact += 30
        if findings.get('privilege_escalation'):
            impact += 35
        if findings.get('data_exfiltration'):
            impact += 40
        if findings.get('persistence_attempts'):
            impact += 20
        
        # Check anomalies
        for anomaly in findings.get('anomalies', []):
            if 'exfiltration' in anomaly.get('type', '').lower():
                impact += 30
            if 'ransomware' in anomaly.get('type', '').lower():
                impact += 50
        
        # Consider asset criticality if available
        if self.context.get('affected_assets'):
            for asset in self.context['affected_assets']:
                asset_type = asset.get('type', 'unknown').lower()
                criticality = self.ASSET_CRITICALITY.get(asset_type, 40)
                impact += criticality * 0.1  # 10% of asset criticality
        
        return min(impact, 100)
    
    def _calculate_likelihood_score(self, findings: Dict[str, Any]) -> float:
        """Calculate likelihood of successful compromise"""
        likelihood = 0
        
        # Multiple failed logins increase likelihood
        failed_logins = len(findings.get('failed_logins', []))
        if failed_logins > 50:
            likelihood += 30
        elif failed_logins > 20:
            likelihood += 20
        elif failed_logins > 5:
            likelihood += 10
        
        # Suspicious PowerShell increases likelihood
        if findings.get('suspicious_powershell'):
            likelihood += 25
        
        # Privilege escalation attempts
        if findings.get('privilege_escalation'):
            likelihood += 30
        
        # Lateral movement
        if findings.get('lateral_movement'):
            likelihood += 35
        
        # Persistence attempts
        if findings.get('persistence_attempts'):
            likelihood += 20
        
        # Anomalies
        anomaly_count = len(findings.get('anomalies', []))
        likelihood += min(anomaly_count * 5, 25)
        
        return min(likelihood, 100)
    
    def _get_risk_level(self, score: float) -> Dict[str, Any]:
        """Get risk level based on score"""
        if score >= 90:
            return {'name': 'CRITICAL', 'color': '#8B0000', 'emoji': '🔴'}
        elif score >= 70:
            return {'name': 'HIGH', 'color': '#FF0000', 'emoji': '🟠'}
        elif score >= 40:
            return {'name': 'MEDIUM', 'color': '#FFA500', 'emoji': '🟡'}
        elif score >= 20:
            return {'name': 'LOW', 'color': '#FFFF00', 'emoji': '🔵'}
        else:
            return {'name': 'INFO', 'color': '#00FF00', 'emoji': 'ℹ️'}
    
    def _identify_contributing_factors(self, findings: Dict[str, Any]) -> List[str]:
        """Identify factors that contributed to the risk score"""
        factors = []
        
        if findings.get('suspicious_powershell'):
            factors.append(f"Suspicious PowerShell execution ({len(findings['suspicious_powershell'])} instances)")
        
        if findings.get('lateral_movement'):
            factors.append(f"Lateral movement detected ({len(findings['lateral_movement'])} attempts)")
        
        if findings.get('privilege_escalation'):
            factors.append(f"Privilege escalation attempts ({len(findings['privilege_escalation'])} events)")
        
        if findings.get('persistence_attempts'):
            factors.append(f"Persistence mechanisms detected ({len(findings['persistence_attempts'])} attempts)")
        
        failed_count = len(findings.get('failed_logins', []))
        if failed_count > 20:
            factors.append(f"High volume of failed logins ({failed_count} attempts)")
        
        anomaly_count = len(findings.get('anomalies', []))
        if anomaly_count > 5:
            factors.append(f"Multiple anomalies detected ({anomaly_count})")
        
        # Time-based factors
        if self._is_recent(findings):
            factors.append("Recent activity detected - immediate attention required")
        
        # Volume factors
        total_findings = findings.get('summary', {}).get('total_findings', 0)
        if total_findings > 50:
            factors.append(f"High volume of security events ({total_findings} total)")
        
        return factors
    
    def _is_recent(self, findings: Dict[str, Any]) -> bool:
        """Check if there are recent findings"""
        for finding_type in ['suspicious_powershell', 'lateral_movement', 'privilege_escalation']:
            for finding in findings.get(finding_type, []):
                ts = finding.get('timestamp')
                if ts:
                    try:
                        if isinstance(ts, str):
                            ts = pd.to_datetime(ts)
                        if (datetime.now() - ts).total_seconds() < 3600:
                            return True
                    except:
                        pass
        return False
    
    def _get_recommended_action(self, score: float) -> str:
        """Get recommended action based on risk score"""
        if score >= 90:
            return "IMMEDIATE INCIDENT RESPONSE - Activate IR team, isolate affected systems"
        elif score >= 70:
            return "URGENT INVESTIGATION - Escalate to senior analyst within 1 hour"
        elif score >= 40:
            return "PRIORITY REVIEW - Investigate within 24 hours"
        elif score >= 20:
            return "MONITOR - Add to watchlist for ongoing monitoring"
        else:
            return "INFORMATIONAL - No immediate action required"
    
    def _get_response_timeframe(self, score: float) -> str:
        """Get recommended response timeframe"""
        if score >= 90:
            return "Immediate (0-1 hour)"
        elif score >= 70:
            return "Urgent (1-4 hours)"
        elif score >= 40:
            return "Standard (24 hours)"
        elif score >= 20:
            return "Scheduled (1 week)"
        else:
            return "Informational (Next review cycle)"
    
    def prioritize_findings(self, findings: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Prioritize individual findings by risk score
        
        Args:
            findings: Findings dictionary
            
        Returns:
            Sorted list of findings with individual risk scores
        """
        prioritized = []
        
        # Process each finding type
        for finding_type, finding_list in findings.items():
            if finding_type in ['failed_logins', 'suspicious_powershell', 'privilege_escalation',
                               'lateral_movement', 'persistence_attempts', 'high_risk_commands']:
                
                base_score = self.FINDING_BASE_SCORES.get(finding_type, 50)
                
                for finding in finding_list:
                    # Calculate individual risk score
                    individual_score = self._calculate_individual_risk_score(finding, base_score)
                    
                    prioritized.append({
                        'type': finding_type,
                        'details': finding,
                        'risk_score': individual_score,
                        'risk_level': self._get_risk_level(individual_score)['name'],
                        'timestamp': finding.get('timestamp', datetime.now().isoformat())
                    })
        
        # Sort by risk score (highest first)
        prioritized.sort(key=lambda x: x['risk_score'], reverse=True)
        
        return prioritized
    
    def _calculate_individual_risk_score(self, finding: Dict, base_score: float) -> float:
        """Calculate risk score for an individual finding"""
        score = base_score
        
        # Boost for privileged users
        user = finding.get('user', '').lower()
        if user in ['admin', 'administrator', 'root', 'system']:
            score += 15
        
        # Boost for external IPs
        source_ip = finding.get('source_ip', '')
        if source_ip and not source_ip.startswith(('192.168.', '10.', '172.')):
            score += 10
        
        # Cap at 100
        return min(score, 100)
    
    def calculate_asset_risk(self, asset_name: str, asset_type: str, 
                             findings: List[Dict]) -> Dict[str, Any]:
        """
        Calculate risk for a specific asset
        
        Args:
            asset_name: Name of the asset
            asset_type: Type of asset (e.g., 'domain_controller')
            findings: Findings related to this asset
            
        Returns:
            Asset-specific risk assessment
        """
        asset_criticality = self.ASSET_CRITICALITY.get(asset_type, 40)
        
        # Calculate finding severity for this asset
        finding_scores = [self.FINDING_BASE_SCORES.get(f.get('type', 'default'), 50) 
                         for f in findings]
        
        avg_finding_score = np.mean(finding_scores) if finding_scores else 0
        
        # Combine asset criticality with finding severity
        asset_risk = (asset_criticality * 0.6 + avg_finding_score * 0.4)
        
        return {
            'asset_name': asset_name,
            'asset_type': asset_type,
            'asset_criticality': asset_criticality,
            'finding_count': len(findings),
            'risk_score': round(asset_risk, 2),
            'risk_level': self._get_risk_level(asset_risk)['name'],
            'recommendation': self._get_asset_recommendation(asset_risk, asset_type)
        }
    
    def _get_asset_recommendation(self, risk_score: float, asset_type: str) -> str:
        """Get recommendation for asset protection"""
        if risk_score >= 80:
            return f"IMMEDIATE: Isolate {asset_type} and conduct forensic analysis"
        elif risk_score >= 60:
            return f"HIGH PRIORITY: Escalate investigation for {asset_type}"
        elif risk_score >= 40:
            return f"REVIEW: Conduct vulnerability scan on {asset_type}"
        else:
            return f"MONITOR: Continue standard monitoring for {asset_type}"
    
    def generate_risk_report(self, findings: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate comprehensive risk report
        
        Args:
            findings: Findings dictionary
            
        Returns:
            Complete risk report with all metrics
        """
        overall = self.calculate_overall_risk(findings)
        prioritized = self.prioritize_findings(findings)
        
        return {
            'executive_summary': {
                'risk_score': overall['overall_risk_score'],
                'risk_level': overall['risk_level'],
                'risk_color': overall['risk_color'],
                'top_risk_factors': overall['contributing_factors'][:5]
            },
            'detailed_assessment': overall,
            'prioritized_findings': prioritized[:20],  # Top 20 findings
            'metrics': {
                'total_findings': len(prioritized),
                'critical_findings': len([f for f in prioritized if f['risk_level'] == 'CRITICAL']),
                'high_findings': len([f for f in prioritized if f['risk_level'] == 'HIGH']),
                'average_risk_score': np.mean([f['risk_score'] for f in prioritized]) if prioritized else 0
            },
            'risk_trend': self._calculate_risk_trend(),
            'recommendations': self._generate_risk_recommendations(overall, prioritized),
            'timestamp': datetime.now().isoformat()
        }
    
    def _calculate_risk_trend(self) -> Dict[str, Any]:
        """Calculate risk trend based on history"""
        if len(self.risk_history) < 2:
            return {'trend': 'STABLE', 'change': 0, 'description': 'Insufficient history'}
        
        # Compare last two risk scores
        current = self.risk_history[-1]['score']
        previous = self.risk_history[-2]['score']
        change = current - previous
        
        if change > 10:
            trend = 'INCREASING'
            description = f"Risk increased by {change:.1f} points"
        elif change < -10:
            trend = 'DECREASING'
            description = f"Risk decreased by {abs(change):.1f} points"
        else:
            trend = 'STABLE'
            description = "Risk level stable"
        
        return {
            'trend': trend,
            'change': round(change, 2),
            'description': description,
            'current_score': current,
            'previous_score': previous
        }
    
    def _generate_risk_recommendations(self, overall: Dict, prioritized: List) -> List[str]:
        """Generate actionable recommendations"""
        recommendations = []
        
        if overall['overall_risk_score'] >= 70:
            recommendations.append("Activate incident response plan immediately")
            recommendations.append("Isolate affected systems from the network")
            recommendations.append("Preserve forensic evidence")
        
        if any(f['type'] == 'suspicious_powershell' for f in prioritized[:5]):
            recommendations.append("Restrict PowerShell execution to signed scripts only")
            recommendations.append("Enable comprehensive PowerShell logging")
        
        if any(f['type'] == 'lateral_movement' for f in prioritized[:5]):
            recommendations.append("Restrict administrative access using JIT/PAM")
            recommendations.append("Implement network segmentation")
        
        if any(f['type'] == 'privilege_escalation' for f in prioritized[:5]):
            recommendations.append("Review and audit all privileged accounts")
            recommendations.append("Implement Privileged Access Workstations (PAWs)")
        
        if any(f['type'] == 'failed_logins' for f in prioritized[:10]):
            recommendations.append("Enable Multi-Factor Authentication (MFA)")
            recommendations.append("Implement account lockout policies")
        
        # General recommendations
        recommendations.append("Conduct security awareness training for all users")
        recommendations.append("Perform regular vulnerability assessments")
        
        return recommendations[:8]  # Max 8 recommendations
    
    def get_risk_summary(self, findings: Dict[str, Any]) -> str:
        """
        Get human-readable risk summary
        
        Args:
            findings: Findings dictionary
            
        Returns:
            Plain text risk summary
        """
        overall = self.calculate_overall_risk(findings)
        
        summary = f"""
RISK ASSESSMENT SUMMARY
{'=' * 50}

Overall Risk Score: {overall['overall_risk_score']}/100
Risk Level: {overall['risk_level']} {overall['risk_emoji']}

Component Scores:
- Severity: {overall['component_scores']['severity']}/100
- Volume: {overall['component_scores']['volume']}/100
- Recency: {overall['component_scores']['recency']}/100
- Impact: {overall['component_scores']['impact']}/100
- Likelihood: {overall['component_scores']['likelihood']}/100

Recommended Action:
{overall['recommended_action']}

Response Timeframe:
{overall['response_timeframe']}

Top Risk Factors:
{chr(10).join(['- ' + f for f in overall['contributing_factors'][:5]])}
"""
        return summary


# ============================================
# CONVENIENCE FUNCTIONS
# ============================================

def quick_risk_assessment(findings: Dict[str, Any]) -> Dict[str, Any]:
    """Quick risk assessment helper"""
    scorer = RiskScorer()
    return scorer.generate_risk_report(findings)


def assess_asset_risk(asset_name: str, asset_type: str, findings: List[Dict]) -> Dict[str, Any]:
    """Quick asset risk assessment"""
    scorer = RiskScorer()
    return scorer.calculate_asset_risk(asset_name, asset_type, findings)


# ============================================
# TESTING CODE
# ============================================

if __name__ == "__main__":
    print("🎯 Testing Risk Scorer Module")
    print("=" * 60)
    
    # Create sample findings
    sample_findings = {
        'total_events': 1000,
        'failed_logins': [
            {'timestamp': datetime.now().isoformat(), 'user': 'admin', 'source_ip': '10.0.2.45'},
            {'timestamp': datetime.now().isoformat(), 'user': 'admin', 'source_ip': '10.0.2.45'},
            {'timestamp': datetime.now().isoformat(), 'user': 'john', 'source_ip': '192.168.1.100'}
        ] * 10,
        'suspicious_powershell': [
            {'timestamp': datetime.now().isoformat(), 'user': 'admin', 'command': 'powershell -Enc encoded'},
            {'timestamp': datetime.now().isoformat(), 'user': 'SYSTEM', 'command': 'powershell IEX(DownloadString)'}
        ],
        'privilege_escalation': [
            {'timestamp': datetime.now().isoformat(), 'user': 'admin', 'command': 'whoami /priv'}
        ],
        'lateral_movement': [
            {'timestamp': datetime.now().isoformat(), 'user': 'admin', 'command': 'psexec'}
        ],
        'anomalies': [
            {'type': 'event_spike', 'severity': 'HIGH', 'timestamp': datetime.now().isoformat()},
            {'type': 'off_hours_activity', 'severity': 'MEDIUM', 'timestamp': datetime.now().isoformat()}
        ],
        'summary': {
            'total_findings': 35,
            'critical_count': 2,
            'high_count': 5,
            'medium_count': 8,
            'low_count': 20
        }
    }
    
    # Initialize risk scorer
    scorer = RiskScorer()
    
    # Test 1: Overall risk calculation
    print("\n📋 Test 1: Overall Risk Assessment")
    overall_risk = scorer.calculate_overall_risk(sample_findings)
    print(f"   Risk Score: {overall_risk['overall_risk_score']}/100")
    print(f"   Risk Level: {overall_risk['risk_level']} {overall_risk['risk_emoji']}")
    print(f"   Recommended Action: {overall_risk['recommended_action'][:60]}...")
    
    # Test 2: Component scores
    print("\n📋 Test 2: Component Scores")
    for component, score in overall_risk['component_scores'].items():
        print(f"   {component.capitalize()}: {score}/100")
    
    # Test 3: Prioritize findings
    print("\n📋 Test 3: Prioritized Findings")
    prioritized = scorer.prioritize_findings(sample_findings)
    for i, finding in enumerate(prioritized[:3], 1):
        print(f"   {i}. {finding['type']} - Risk: {finding['risk_score']}/100 ({finding['risk_level']})")
    
    # Test 4: Asset risk
    print("\n📋 Test 4: Asset Risk Assessment")
    asset_findings = [{'type': 'suspicious_powershell'}, {'type': 'privilege_escalation'}]
    asset_risk = scorer.calculate_asset_risk('DC01', 'domain_controller', asset_findings)
    print(f"   Asset: {asset_risk['asset_name']} ({asset_risk['asset_type']})")
    print(f"   Risk Score: {asset_risk['risk_score']}/100 ({asset_risk['risk_level']})")
    print(f"   Recommendation: {asset_risk['recommendation']}")
    
    # Test 5: Full risk report
    print("\n📋 Test 5: Complete Risk Report")
    risk_report = scorer.generate_risk_report(sample_findings)
    print(f"   Executive Summary:")
    print(f"     - Risk Score: {risk_report['executive_summary']['risk_score']}/100")
    print(f"     - Risk Level: {risk_report['executive_summary']['risk_level']}")
    print(f"     - Top Factors: {len(risk_report['executive_summary']['top_risk_factors'])} identified")
    print(f"   Metrics:")
    print(f"     - Total Findings: {risk_report['metrics']['total_findings']}")
    print(f"     - Critical: {risk_report['metrics']['critical_findings']}")
    print(f"     - High: {risk_report['metrics']['high_findings']}")
    
    # Test 6: Risk summary text
    print("\n📋 Test 6: Human-Readable Summary")
    summary_text = scorer.get_risk_summary(sample_findings)
    print(f"{summary_text[:300]}...")
    
    print("\n" + "=" * 60)
    print("✅ Risk Scorer Module Ready")