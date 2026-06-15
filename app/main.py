# app/main.py
"""
SOC Investigation Assistant - Professional Incident Investigation
Powered by Senior SOC Analyst AI Agent
"""

import streamlit as st
import pandas as pd
import sys
from pathlib import Path
from datetime import datetime
import traceback
import json

# Add parent directory to path
sys.path.append(str(Path(__file__).parent))

# Import all modules
from config import APP_NAME, APP_VERSION
from parsers.log_parser import LogParser
from parsers.pcap_parser import PCAPParser
from analyzers.threat_detector import ThreatDetector
from remediation.playbooks import RemediationPlaybooks
from reporting.mitre_mapper import MITREMapper
from reporting.report_generator import SOCReportGenerator
from reporting.chart_builder import ChartBuilder
from utils.exporters import ReportExporter

# Import SOC Analyst Agent (the brain)
try:
    from llm.soc_analyst_agent import SOCAnalystAgent
    AGENT_AVAILABLE = True
except ImportError as e:
    AGENT_AVAILABLE = False
    print(f"Agent import error: {e}")


# ============================================
# PAGE CONFIGURATION
# ============================================

st.set_page_config(
    page_title=f"{APP_NAME} - SOC Analyst",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)


# ============================================
# CUSTOM CSS
# ============================================

st.markdown("""
<style>
    .main-header {
        background: linear-gradient(135deg, #0f0c29, #302b63, #24243e);
        padding: 1.5rem;
        border-radius: 10px;
        margin-bottom: 2rem;
        text-align: center;
    }
    .main-header h1 {
        color: white;
        margin: 0;
    }
    .main-header p {
        color: #a0a0a0;
        margin: 0.5rem 0 0 0;
    }
    .risk-critical {
        background-color: #8B0000;
        padding: 0.75rem;
        border-radius: 8px;
        color: white;
        font-weight: bold;
        text-align: center;
        font-size: 1.2rem;
    }
    .risk-high {
        background-color: #CC5500;
        padding: 0.75rem;
        border-radius: 8px;
        color: white;
        font-weight: bold;
        text-align: center;
        font-size: 1.2rem;
    }
    .risk-medium {
        background-color: #DAA520;
        padding: 0.75rem;
        border-radius: 8px;
        color: black;
        font-weight: bold;
        text-align: center;
        font-size: 1.2rem;
    }
    .risk-low {
        background-color: #228B22;
        padding: 0.75rem;
        border-radius: 8px;
        color: white;
        font-weight: bold;
        text-align: center;
        font-size: 1.2rem;
    }
    .chat-message-user {
        background-color: #1e3a5f;
        padding: 12px;
        border-radius: 12px;
        margin: 8px 0;
        border-left: 4px solid #4fc3f7;
    }
    .chat-message-assistant {
        background-color: #2d2d30;
        padding: 12px;
        border-radius: 12px;
        margin: 8px 0;
        border-left: 4px solid #00bcd4;
        font-family: monospace;
        white-space: pre-wrap;
    }
    .stButton button {
        width: 100%;
        border-radius: 8px;
        transition: all 0.3s ease;
    }
    .stButton button:hover {
        transform: translateY(-2px);
        box-shadow: 0 4px 12px rgba(0,0,0,0.2);
    }
    footer {
        visibility: hidden;
    }
    .metric-card {
        background: linear-gradient(135deg, #1a1a2e, #16213e);
        padding: 1rem;
        border-radius: 10px;
        text-align: center;
        border: 1px solid #333;
    }
    .section-header {
        background: linear-gradient(90deg, #2a2a3e, #1a1a2e);
        padding: 0.5rem 1rem;
        border-radius: 8px;
        margin: 1rem 0;
        font-weight: bold;
    }
</style>
""", unsafe_allow_html=True)


# ============================================
# SESSION STATE INITIALIZATION
# ============================================

if 'current_df' not in st.session_state:
    st.session_state.current_df = None
if 'current_findings' not in st.session_state:
    st.session_state.current_findings = None
if 'current_report' not in st.session_state:
    st.session_state.current_report = None
if 'analysis_performed' not in st.session_state:
    st.session_state.analysis_performed = False
if 'mitre_map' not in st.session_state:
    st.session_state.mitre_map = None
if 'chat_history' not in st.session_state:
    st.session_state.chat_history = []
if 'soc_agent' not in st.session_state:
    st.session_state.soc_agent = None
if 'current_investigation' not in st.session_state:
    st.session_state.current_investigation = None
if 'show_preview' not in st.session_state:
    st.session_state.show_preview = False


# ============================================
# INITIALIZE SOC ANALYST AGENT
# ============================================

def init_soc_agent():
    """Initialize the SOC Analyst Agent"""
    if st.session_state.soc_agent is None and AGENT_AVAILABLE:
        try:
            st.session_state.soc_agent = SOCAnalystAgent(verbose=False)
            return True
        except Exception as e:
            st.session_state.soc_agent = None
            return False
    return st.session_state.soc_agent is not None


# ============================================
# SIDEBAR
# ============================================

with st.sidebar:
    st.markdown("### 🛡️ SOC Analyst AI")
    st.caption(f"Version {APP_VERSION}")
    st.caption("Senior Incident Response Agent")
    st.markdown("---")
    
    st.markdown("### 🔍 Investigation Capabilities")
    st.markdown("""
    - ✅ Attack Chain Correlation
    - ✅ Root Cause Analysis
    - ✅ IOC Extraction
    - ✅ MITRE ATT&CK Mapping
    - ✅ Confidence Scoring
    - ✅ Remediation Planning
    - ✅ Risk Assessment
    """)
    
    st.markdown("---")
    
    # Agent Status
    st.markdown("### 🧠 Agent Status")
    
    if AGENT_AVAILABLE:
        init_soc_agent()
        if st.session_state.soc_agent:
            st.success("✅ SOC Analyst Ready")
            st.caption("15+ years IR experience")
        else:
            st.warning("⚠️ Agent not initialized")
    else:
        st.error("❌ Agent not available")
    
    st.markdown("---")
    
    st.markdown("### 🔒 Privacy")
    st.markdown("""
    **100% Local Processing**
    - No data leaves your machine
    - AI runs completely offline
    - Your logs stay private
    """)
    
    st.markdown("---")
    
    # Quick Investigation Buttons
    st.markdown("### 🔍 Quick Investigate")
    
    if st.button("🔍 Investigate Incident", use_container_width=True):
        st.session_state.quick_question = "investigate this incident"
    
    if st.button("📜 Show Attack Timeline", use_container_width=True):
        st.session_state.quick_question = "show attack timeline"
    
    if st.button("🎯 Identify Root Cause", use_container_width=True):
        st.session_state.quick_question = "identify root cause"
    
    if st.button("🛡️ Recommend Remediation", use_container_width=True):
        st.session_state.quick_question = "recommend remediation"
    
    if st.button("⚠️ Assess Risk Level", use_container_width=True):
        st.session_state.quick_question = "assess risk level"
    
    if st.button("🧩 MITRE ATT&CK", use_container_width=True):
        st.session_state.quick_question = "MITRE ATT&CK mapping"
    
    if st.button("🌐 Extract IOCs", use_container_width=True):
        st.session_state.quick_question = "extract IOCs"
    
    if st.button("🖥️ List Affected Assets", use_container_width=True):
        st.session_state.quick_question = "list affected assets"
    
    if st.button("🔗 Show Correlated Events", use_container_width=True):
        st.session_state.quick_question = "show correlated events"
    
    if st.button("📊 Confidence Assessment", use_container_width=True):
        st.session_state.quick_question = "confidence assessment"
    
    st.markdown("---")
    
    # Clear chat button
    if st.button("🗑️ Clear Investigation", use_container_width=True):
        st.session_state.chat_history = []
        if st.session_state.soc_agent:
            st.session_state.soc_agent.clear_memory()
        st.session_state.current_investigation = None
        st.rerun()


# ============================================
# MAIN HEADER
# ============================================

st.markdown("""
<div class="main-header">
    <h1>🛡️ SOC Incident Investigator</h1>
    <p>Senior Analyst AI | 15+ Years IR Experience</p>
</div>
""", unsafe_allow_html=True)


# ============================================
# FILE UPLOAD SECTION
# ============================================

col1, col2 = st.columns([2, 1])

with col1:
    uploaded_file = st.file_uploader(
        "📂 Upload Log File for Investigation",
        type=['csv', 'json', 'evtx', 'log', 'xlsx'],
        help="Upload logs for AI-powered incident investigation"
    )

with col2:
    st.markdown("### 🚀 Quick Start")
    if st.button("📥 Load Sample Incident", use_container_width=True):
        # Create realistic incident sample
        sample_data = """2026-06-05T08:00:01.125Z INFO AUTH-SVC Service startup complete
2026-06-05T08:15:33.230Z HIGH SECURITY Excessive login failures user=admin source_ip=185.44.10.7 failures=25
2026-06-05T08:15:34.012Z HIGH SECURITY Account lockout triggered user=admin duration=30m
2026-06-05T08:40:55.920Z CRITICAL DB-PRIMARY Replication lag exceeded threshold lag_seconds=620
2026-06-05T08:41:10.102Z CRITICAL DB-PRIMARY Primary database unavailable node=db-prod-01
2026-06-05T08:43:41.788Z HIGH SECURITY Suspicious privilege escalation detected user=svc-reports
2026-06-05T08:43:42.101Z CRITICAL SECURITY Unauthorized admin role assignment user=svc-reports target_role=SUPER_ADMIN
2026-06-05T09:01:22.119Z EMERGENCY SECURITY Potential ransomware activity detected host=finance-server-02
2026-06-05T09:01:24.447Z EMERGENCY SECURITY File encryption spike detected affected_files=18423"""
        
        lines = sample_data.split('\n')
        data = []
        for line in lines:
            parts = line.split(maxsplit=3)
            if len(parts) >= 4:
                data.append({
                    'timestamp': parts[0],
                    'severity': parts[1],
                    'source': parts[2],
                    'raw_log': parts[3]
                })
        
        sample_df = pd.DataFrame(data)
        st.session_state.current_df = sample_df
        st.session_state.current_findings = None
        st.session_state.analysis_performed = False
        st.session_state.current_investigation = None
        st.success("✅ Sample incident loaded! Ask: 'Investigate this incident'")
        st.rerun()


# ============================================
# FILE PROCESSING
# ============================================

if uploaded_file is not None:
    with st.spinner("📂 Processing file..."):
        file_bytes = uploaded_file.getvalue()
        file_name = uploaded_file.name
        file_ext = Path(file_name).suffix.lower()
        
        parser = LogParser(verbose=False)
        df = parser.parse(file_bytes, file_name)
        
        if df is not None and not df.empty:
            st.session_state.current_df = df
            st.session_state.current_investigation = None
            st.success(f"✅ Loaded {len(df)} events for investigation")
            
            with st.expander("📊 Evidence Preview"):
                st.dataframe(df.head(10), use_container_width=True)
                st.caption(f"Columns: {', '.join(df.columns)}")
            
            # Run preliminary threat detection
            with st.spinner("Running preliminary analysis..."):
                try:
                    detector = ThreatDetector(verbose=False)
                    findings = detector.analyze_logs(df)
                    st.session_state.current_findings = findings
                    st.session_state.analysis_performed = True
                    
                    risk_score = findings.get('risk_score', 0)
                    if risk_score >= 70:
                        st.markdown(f'<div class="risk-critical">🔴 CRITICAL RISK: {risk_score}/100 - Active compromise indicators</div>', unsafe_allow_html=True)
                    elif risk_score >= 40:
                        st.markdown(f'<div class="risk-high">🟠 HIGH RISK: {risk_score}/100 - Suspicious activity detected</div>', unsafe_allow_html=True)
                    elif risk_score >= 20:
                        st.markdown(f'<div class="risk-medium">🟡 MEDIUM RISK: {risk_score}/100 - Anomalous behavior</div>', unsafe_allow_html=True)
                    else:
                        st.markdown(f'<div class="risk-low">🔵 LOW RISK: {risk_score}/100 - No immediate threats</div>', unsafe_allow_html=True)
                except Exception as e:
                    st.warning(f"Preliminary analysis: {str(e)[:100]}")
        else:
            st.error("Failed to parse file. Please check the format.")


# ============================================
# SOC ANALYST INVESTIGATION CHAT
# ============================================

st.markdown("---")
st.markdown("## 🔬 SOC Analyst Investigation")
st.markdown("*I don't summarize logs. I investigate incidents.*")

# Initialize agent
if AGENT_AVAILABLE and st.session_state.soc_agent is None:
    init_soc_agent()

# Check for quick question from sidebar
if 'quick_question' in st.session_state and st.session_state.quick_question:
    quick_q = st.session_state.quick_question
    st.session_state.quick_question = None
    # Process it like a normal chat input
    user_question = quick_q
else:
    user_question = None

# Display chat history
chat_container = st.container()

with chat_container:
    for msg in st.session_state.chat_history:
        if msg['role'] == 'user':
            st.markdown(f'<div class="chat-message-user">👤 <strong>You (Analyst):</strong><br>{msg["content"]}</div>', 
                       unsafe_allow_html=True)
        else:
            st.markdown(f'<div class="chat-message-assistant">🛡️ <strong>SOC Analyst AI:</strong><br>{msg["content"]}</div>', 
                       unsafe_allow_html=True)

# Chat input
if user_question is None:
    user_question = st.chat_input("Ask the SOC Analyst to investigate...", key="chat_input")

if user_question:
    # Add user message to history
    st.session_state.chat_history.append({'role': 'user', 'content': user_question})
    
    # Display user message immediately
    st.markdown(f'<div class="chat-message-user">👤 <strong>You (Analyst):</strong><br>{user_question}</div>', 
               unsafe_allow_html=True)
    
    # Generate investigation response
    with st.spinner("🔬 Investigating incident. Correlating events, building attack chain..."):
        response = ""
        
        # Check if we have data to investigate
        if st.session_state.current_df is None:
            response = """**No evidence loaded.** I cannot investigate without data.

Please upload log files or click 'Load Sample Incident' to begin investigation.

Once loaded, I can:
- 🔍 Investigate the full incident
- 📜 Show attack timeline
- 🎯 Identify root cause
- 🛡️ Recommend remediation
- ⚠️ Assess risk level
- 🧩 Map to MITRE ATT&CK
- 🌐 Extract IOCs
- 🖥️ List affected assets
- 🔗 Show correlated events
- 📊 Confidence assessment"""
        
        elif st.session_state.soc_agent is not None:
            try:
                # Run investigation using SOC Analyst Agent
                result = st.session_state.soc_agent.chat(user_question, st.session_state.current_df)
                response = result['insight']
                
                # Store full investigation if this was a general request
                if 'investigate' in user_question.lower() or 'full' in user_question.lower():
                    st.session_state.current_investigation = result
                    
            except Exception as e:
                response = f"❌ **Investigation Error:** {str(e)}\n\nPlease try rephrasing your question."
        
        elif AGENT_AVAILABLE is False:
            response = """**⚠️ SOC Analyst Agent not available.**

The investigation agent requires the SOC Analyst module. Please ensure:
- `llm/soc_analyst_agent.py` exists
- All dependencies are installed"""
        
        else:
            response = """**⚠️ Agent not initialized.** Please refresh the page or restart the app."""
        
        # Add assistant response to history
        st.session_state.chat_history.append({'role': 'assistant', 'content': response})
        
        # Display assistant response
        st.markdown(f'<div class="chat-message-assistant">🛡️ <strong>SOC Analyst AI:</strong><br>{response}</div>', 
                   unsafe_allow_html=True)
        
        # Rerun to update chat display
        st.rerun()


# ============================================
# DEBUG SECTION - Shows what data we have
# ============================================

with st.expander("🔧 Debug: View Raw Data (click to expand)", expanded=False):
    st.write("### Current Findings Data:")
    if st.session_state.current_findings:
        st.write(f"**Risk Score:** {st.session_state.current_findings.get('risk_score', 'Not found')}")
        st.write(f"**Total Events:** {st.session_state.current_findings.get('total_events', 'Not found')}")
        st.write(f"**Failed Logins Count:** {len(st.session_state.current_findings.get('failed_logins', []))}")
        st.write(f"**Suspicious PowerShell Count:** {len(st.session_state.current_findings.get('suspicious_powershell', []))}")
        st.write(f"**Keys in findings:** {list(st.session_state.current_findings.keys())}")
        
        if 'iocs' in st.session_state.current_findings:
            st.write("**IOCs data:**")
            st.json(st.session_state.current_findings['iocs'])
    else:
        st.write("⚠️ No findings data available. Run Threat Detection first.")
    
    st.write("---")
    st.write("### Current Investigation Data:")
    if st.session_state.current_investigation:
        st.write(f"**Keys in investigation:** {list(st.session_state.current_investigation.keys())}")
        if 'insight' in st.session_state.current_investigation:
            st.write("**Insight preview:**")
            st.text(st.session_state.current_investigation['insight'][:500])
    else:
        st.write("⚠️ No investigation data available. Ask 'investigate this incident' first.")


# ============================================
# INVESTIGATION DASHBOARD - READS FROM DATAFRAME
# ============================================

if st.session_state.current_df is not None:
    with st.expander("📋 Full Investigation Report", expanded=True):
        df = st.session_state.current_df
        
        st.markdown("---")
        
        # Extract data from dataframe
        suspicious_ips = []
        suspicious_users = []
        
        if 'source_ip' in df.columns:
            all_ips = df['source_ip'].dropna().unique().tolist()
        else:
            all_ips = []
        
        if 'user' in df.columns:
            all_users = df['user'].dropna().unique().tolist()
        else:
            all_users = []
        
        # Get high severity rows
        if 'severity' in df.columns:
            high_severity_rows = df[df['severity'].isin(['CRITICAL', 'HIGH', 'ERROR', 'ALERT', 'WARN'])]
            suspicious_ips = high_severity_rows['source_ip'].dropna().unique().tolist()
            suspicious_users = high_severity_rows['user'].dropna().unique().tolist()
            critical_count = len(df[df['severity'] == 'CRITICAL'])
            high_count = len(df[df['severity'].isin(['HIGH', 'ERROR', 'ALERT'])])
        else:
            suspicious_ips = all_ips
            suspicious_users = all_users
            critical_count = 0
            high_count = 0
        
        # Calculate risk score
        risk_score = min(100, critical_count * 10 + high_count * 5 + len(suspicious_ips))
        
        # Executive Summary
        st.markdown("### 📊 Executive Summary")
        
        if risk_score >= 70:
            st.error(f"🔴 CRITICAL RISK: {risk_score}/100 - Active compromise indicators")
        elif risk_score >= 40:
            st.warning(f"🟠 HIGH RISK: {risk_score}/100 - Suspicious activity detected")
        elif risk_score >= 20:
            st.warning(f"🟡 MEDIUM RISK: {risk_score}/100 - Anomalous behavior")
        else:
            st.info(f"🔵 LOW RISK: {risk_score}/100 - No immediate threats")
        
        st.markdown(f"**Total Events Analyzed:** {len(df)}")
        st.markdown(f"**Critical Events:** {critical_count}")
        st.markdown(f"**High Severity Events:** {high_count}")
        
        # Metrics
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Total Events", len(df))
        with col2:
            st.metric("Critical Events", critical_count)
        with col3:
            st.metric("Suspicious IPs", len(suspicious_ips))
        with col4:
            st.metric("Suspicious Users", len(suspicious_users))
        
        # Suspicious IPs
        if suspicious_ips:
            st.markdown("### 🔴 Suspicious IP Addresses")
            ip_counts = df[df['source_ip'].isin(suspicious_ips)]['source_ip'].value_counts()
            for ip, count in ip_counts.head(20).items():
                st.markdown(f"- `{ip}` (occurred {count} times)")
        else:
            st.info("No suspicious IPs detected")
        
        # Suspicious Users
        if suspicious_users:
            st.markdown("### 👤 Suspicious Users")
            user_counts = df[df['user'].isin(suspicious_users)]['user'].value_counts()
            for user, count in user_counts.head(20).items():
                st.markdown(f"- `{user}` (occurred {count} times)")
        else:
            st.info("No suspicious users detected")
        
        # High Severity Events Table
        if 'severity' in df.columns and not high_severity_rows.empty:
            st.markdown("### ⚠️ High Severity Events")
            display_cols = ['timestamp', 'severity', 'source', 'source_ip', 'user']
            available_cols = [c for c in display_cols if c in high_severity_rows.columns]
            st.dataframe(high_severity_rows[available_cols].head(10), use_container_width=True)
        
        # Remediation Plan
        st.markdown("### 🛡️ Remediation Plan")
        
        if suspicious_ips:
            st.markdown("**🚨 Immediate Actions:**")
            for ip in suspicious_ips[:5]:
                st.code(f"Block IP: {ip}")
            st.markdown("- Force password reset for affected users")
            st.markdown("- Enable MFA for critical accounts")
        
        st.markdown("**🔒 Recommendations:**")
        st.markdown("- Deploy Endpoint Detection and Response (EDR)")
        st.markdown("- Implement security awareness training")
        st.markdown("- Maintain offline backups")


# ============================================
# QUICK STATS DASHBOARD
# ============================================

if st.session_state.analysis_performed and st.session_state.current_findings:
    with st.expander("📊 Investigation Dashboard", expanded=False):
        findings = st.session_state.current_findings
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            severity_breakdown = findings.get('severity_breakdown', {})
            critical_count = severity_breakdown.get('CRITICAL', 0) + severity_breakdown.get('EMERGENCY', 0)
            st.markdown(f'<div class="metric-card"><span style="font-size: 2rem;">🔴</span><br/><span style="font-size: 1.5rem; font-weight: bold;">{critical_count}</span><br/>Critical Events</div>', unsafe_allow_html=True)
        
        with col2:
            high_count = severity_breakdown.get('HIGH', 0) + severity_breakdown.get('ALERT', 0)
            st.markdown(f'<div class="metric-card"><span style="font-size: 2rem;">🟠</span><br/><span style="font-size: 1.5rem; font-weight: bold;">{high_count}</span><br/>High Severity</div>', unsafe_allow_html=True)
        
        with col3:
            risk_score = findings.get('risk_score', 0)
            st.markdown(f'<div class="metric-card"><span style="font-size: 2rem;">📊</span><br/><span style="font-size: 1.5rem; font-weight: bold;">{risk_score}/100</span><br/>Risk Score</div>', unsafe_allow_html=True)
        
        with col4:
            total_events = findings.get('total_events', 0)
            st.markdown(f'<div class="metric-card"><span style="font-size: 2rem;">📝</span><br/><span style="font-size: 1.5rem; font-weight: bold;">{total_events}</span><br/>Events</div>', unsafe_allow_html=True)


# ============================================
# ADVANCED ANALYSIS TOOLS (NO HTML REPORT)
# ============================================

with st.expander("🛠️ Advanced Analysis Tools", expanded=False):
    col1, col2, col3 = st.columns(3)  # Only 3 columns now - removed HTML report button
    
    with col1:
        if st.button("🦠 Run Threat Detection", use_container_width=True):
            if st.session_state.current_df is not None:
                with st.spinner("Analyzing for threats..."):
                    try:
                        detector = ThreatDetector(verbose=False)
                        findings = detector.analyze_logs(st.session_state.current_df)
                        st.session_state.current_findings = findings
                        st.session_state.analysis_performed = True
                        risk_score = findings.get('risk_score', 0)
                        st.success(f"✅ Analysis complete! Risk Score: {risk_score}/100")
                        st.rerun()
                    except Exception as e:
                        st.error(f"Analysis failed: {e}")
            else:
                st.warning("⚠️ Please load a log file first")
    
    with col2:
        if st.button("🎯 MITRE Mapping", use_container_width=True):
            if st.session_state.current_findings:
                with st.spinner("Mapping to MITRE..."):
                    try:
                        mitre_map = MITREMapper.map_all_findings(st.session_state.current_findings)
                        st.session_state.mitre_map = mitre_map
                        techniques = mitre_map.get('techniques_used', [])
                        if techniques:
                            st.success(f"✅ Mapped {len(techniques)} MITRE techniques")
                            for t in techniques[:3]:
                                st.write(f"• {t['technique_id']} - {t['technique_name']}")
                        else:
                            st.info("No MITRE techniques identified")
                    except Exception as e:
                        st.error(f"MITRE error: {e}")
            else:
                st.warning("⚠️ Please run Threat Detection first")
    
    with col3:
        if st.button("🛡️ Show Remediation", use_container_width=True):
            if st.session_state.current_findings:
                with st.spinner("Loading remediation playbooks..."):
                    try:
                        findings = st.session_state.current_findings
                        playbooks_to_show = []
                        if findings.get('suspicious_powershell'):
                            playbooks_to_show.append('suspicious_powershell')
                        if findings.get('lateral_movement'):
                            playbooks_to_show.append('lateral_movement')
                        if findings.get('privilege_escalation'):
                            playbooks_to_show.append('privilege_escalation')
                        if findings.get('failed_logins') and len(findings['failed_logins']) > 10:
                            playbooks_to_show.append('brute_force_attack')
                        
                        if playbooks_to_show:
                            for pb_key in playbooks_to_show[:2]:
                                playbook = RemediationPlaybooks.get_playbook(pb_key)
                                if playbook:
                                    st.markdown(f"**{playbook['title']}**")
                                    st.markdown(f"Severity: {playbook['severity'].value}")
                                    for step in playbook.get('containment_steps', [])[:3]:
                                        st.markdown(f"{step['step']}. {step['action']}")
                                    st.markdown("---")
                        else:
                            st.info("No specific playbooks available for current findings")
                    except Exception as e:
                        st.error(f"Remediation error: {e}")
            else:
                st.warning("⚠️ Please run Threat Detection first")


# ============================================
# REPORT DOWNLOAD SECTION (JSON & Markdown ONLY)
# ============================================

if st.session_state.current_findings:
    st.markdown("---")
    st.subheader("📤 Export Findings")
    
    col1, col2 = st.columns(2)
    
    with col1:
        if st.button("📄 Download as JSON", use_container_width=True):
            json_str = json.dumps(st.session_state.current_findings, indent=2, default=str)
            st.download_button(
                label="📥 Download JSON",
                data=json_str,
                file_name=f"findings_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json",
                use_container_width=True
            )
    
    with col2:
        if st.button("📝 Download as Markdown", use_container_width=True):
            # Create simple markdown report
            findings = st.session_state.current_findings
            md_content = f"""# SOC Investigation Findings

## Summary
- **Risk Score:** {findings.get('risk_score', 0)}/100
- **Total Events:** {findings.get('total_events', 0)}
- **Failed Logins:** {len(findings.get('failed_logins', []))}
- **Suspicious PowerShell:** {len(findings.get('suspicious_powershell', []))}
- **Privilege Escalation:** {len(findings.get('privilege_escalation', []))}

## Detailed Findings
Generated by SOC Investigation Assistant on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
"""
            st.download_button(
                label="📥 Download Markdown",
                data=md_content,
                file_name=f"findings_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md",
                mime="text/markdown",
                use_container_width=True
            )


# ============================================
# EXPORT SECTION (For investigation results)
# ============================================

if st.session_state.current_investigation:
    with st.expander("📤 Export Investigation Report", expanded=False):
        st.info("Export the complete investigation report in your preferred format")
        
        col1, col2 = st.columns(2)
        
        try:
            exporter = ReportExporter()
            report_data = {
                'report_metadata': {
                    'report_id': f"SOC-IR-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
                    'generated_by': APP_NAME,
                    'version': APP_VERSION,
                    'analyst': 'AI SOC Analyst Agent'
                },
                'investigation': st.session_state.current_investigation
            }
            
            with col1:
                if st.button("📄 Export JSON", use_container_width=True):
                    path = exporter.export_json(report_data)
                    st.success(f"Saved: {path}")
            
            with col2:
                if st.button("📝 Export Markdown", use_container_width=True):
                    path = exporter.export_markdown(report_data)
                    st.success(f"Saved: {path}")
                    
        except Exception as e:
            st.warning(f"Export: {str(e)[:100]}")


# ============================================
# EXPORT DATA (Simple CSV/JSON from DataFrame)
# ============================================

if st.session_state.current_df is not None:
    with st.expander("📤 Export Raw Data", expanded=False):
        col1, col2 = st.columns(2)
        
        csv_data = st.session_state.current_df.to_csv(index=False)
        col1.download_button(
            label="📥 Download CSV",
            data=csv_data,
            file_name=f"security_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv"
        )
        
        json_data = st.session_state.current_df.to_json(orient='records', indent=2)
        col2.download_button(
            label="📥 Download JSON",
            data=json_data,
            file_name=f"security_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            mime="application/json"
        )


# ============================================
# FOOTER
# ============================================

st.markdown("---")
st.markdown(
    f"""
    <div style='text-align: center; color: gray; padding: 20px;'>
        <p>🛡️ {APP_NAME} v{APP_VERSION} | Senior SOC Analyst AI | 🔒 100% Local Processing</p>
        <p style='font-size: 12px;'>Correlates events | Builds attack chains | Maps to MITRE | Provides remediation</p>
    </div>
    """,
    unsafe_allow_html=True
)