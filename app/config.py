# app/config.py
"""
SOC Investigation Assistant - Configuration Module
Central location for all settings, paths, and thresholds
"""

import os
from pathlib import Path
from typing import Dict, List, Any
from datetime import datetime

# ============================================
# PATH CONFIGURATION
# ============================================

# Base directories
BASE_DIR = Path(__file__).resolve().parent.parent
APP_DIR = BASE_DIR / "app"
DATA_DIR = BASE_DIR / "data"
REPORTS_DIR = DATA_DIR / "reports"
CACHE_DIR = DATA_DIR / "cache"
IOC_DIR = DATA_DIR / "iocs"
TEMPLATES_DIR = APP_DIR / "reporting" / "templates"

# Create directories if they don't exist
for dir_path in [DATA_DIR, REPORTS_DIR, CACHE_DIR, IOC_DIR, TEMPLATES_DIR]:
    dir_path.mkdir(parents=True, exist_ok=True)

# ============================================
# LLM CONFIGURATION (Local Ollama)
# ============================================

OLLAMA_CONFIG = {
    "model": os.getenv("OLLAMA_MODEL", "llama3.2:3b"),  # Lightweight, fast
    "host": os.getenv("OLLAMA_HOST", "http://localhost:11434"),
    "timeout": 60,  # seconds
    "temperature": 0.1,  # Low for consistent responses
    "max_tokens": 500,
    "fallback_model": "phi3:mini"  # Even lighter fallback
}

# ============================================
# FILE PROCESSING LIMITS
# ============================================

FILE_LIMITS = {
    "max_log_rows": int(os.getenv("MAX_LOG_ROWS", "50000")),
    "max_pcap_packets": int(os.getenv("MAX_PCAP_PACKETS", "10000")),
    "max_file_size_mb": int(os.getenv("MAX_FILE_SIZE_MB", "100")),
    "max_upload_size_bytes": 100 * 1024 * 1024,  # 100MB
    "supported_log_extensions": ['.csv', '.json', '.evtx', '.txt', '.log'],
    "supported_pcap_extensions": ['.pcap', '.pcapng'],
    "supported_image_extensions": ['.png', '.jpg', '.jpeg']  # For report logos
}

# ============================================
# RISK SCORING THRESHOLDS
# ============================================

RISK_THRESHOLDS = {
    "critical": 90,
    "high": 70,
    "medium": 40,
    "low": 20,
    "informational": 0
}

RISK_LEVELS = {
    "CRITICAL": {"color": "#8B0000", "emoji": "🔴", "score_min": 90},
    "HIGH": {"color": "#FF0000", "emoji": "🟡", "score_min": 70},
    "MEDIUM": {"color": "#FFA500", "emoji": "🟠", "score_min": 40},
    "LOW": {"color": "#FFFF00", "emoji": "🔵", "score_min": 20},
    "INFO": {"color": "#00FF00", "emoji": "ℹ️", "score_min": 0}
}

# ============================================
# SECURITY INDICATORS (IOC Patterns)
# ============================================

SUSPICIOUS_PATTERNS = {
    # Network indicators
    "suspicious_ports": [4444, 1337, 6667, 31337, 5555, 3389, 23, 21, 445, 139],
    "malicious_ips": [],  # Load from file if exists
    "malicious_domains": [],  # Load from file if exists
    
    # Process indicators
    "suspicious_processes": [
        'powershell.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe', 
        'mshta.exe', 'regsvr32.exe', 'rundll32.exe', 'certutil.exe',
        'bitsadmin.exe', 'wmic.exe', 'schtasks.exe'
    ],
    
    # PowerShell suspicious arguments
    "powershell_suspicious_args": [
        '-enc', '-e ', 'bypass', 'hidden', 'windowstyle',
        'downloadstring', 'invoke-expression', 'iex', 
        'invoke-webrequest', 'net.webclient', 'base64'
    ],
    
    # Command line patterns
    "command_patterns": {
        "privilege_escalation": [
            'whoami /priv', 'net localgroup administrators', 
            'net group "domain admins"', 'secedit', 'auditpol'
        ],
        "persistence": [
            'schtasks /create', 'reg add.*run', 'new-itemproperty',
            'set-service', 'wmic.*create', 'sc config'
        ],
        "lateral_movement": [
            'psexec', 'wmic /node:', 'winrm', 'invoke-command',
            'enter-pssession', 'net use', 'mimikatz'
        ],
        "exfiltration": [
            'upload', 'download-file', 'send-mailmessage',
            'webclient.upload', 'ftp', 'curl.*-F'
        ]
    }
}

# ============================================
# LOG EVENT ID MAPPINGS (Windows)
# ============================================

WINDOWS_EVENT_IDS = {
    # Authentication
    "failed_login": 4625,
    "successful_login": 4624,
    "account_lockout": 4740,
    "logoff": 4647,
    
    # Privilege escalation
    "admin_assigned": 4672,
    "sensitive_privilege": 4673,
    "process_creation": 4688,
    
    # Persistence
    "service_installed": 4698,
    "scheduled_task_created": 4698,
    "registry_modification": 4657,
    
    # Defense evasion
    "audit_policy_changed": 4719,
    "service_stopped": 7036,
    
    # Lateral movement
    "network_connection": 5156,
    "share_access": 5140,
    
    "powershell_log": 4104,  # PowerShell script block
    "powershell_start": 4103
}

# ============================================
# REPORT CONFIGURATION
# ============================================

REPORT_CONFIG = {
    "company_name": os.getenv("COMPANY_NAME", "Security Operations Center"),
    "company_logo": None,  # Path to logo image
    "default_timezone": "UTC",
    "date_format": "%Y-%m-%d %H:%M:%S %Z",
    "include_charts": True,
    "include_timeline": True,
    "include_mitre_mapping": True,
    "include_recommendations": True,
    "chart_theme": "dark",  # dark or light
    "page_size": "A4",
    "font_family": "Arial"
}

# ============================================
# PCAP ANALYSIS CONFIGURATION
# ============================================

PCAP_CONFIG = {
    "protocols_to_analyze": ['TCP', 'UDP', 'ICMP', 'DNS', 'HTTP', 'HTTPS'],
    "suspicious_tcp_flags": ['S', 'SA', 'F', 'R'],  # SYN, SYN-ACK, FIN, RST
    "dns_suspicious_tlds": ['.xyz', '.top', '.tk', '.ml', '.ga', '.cf'],
    "max_packet_payload_bytes": 100,  # For analysis only, not storage
    "detect_port_scans": True,
    "scan_threshold": 100,  # packets to same IP in short time
    "detect_ddos": True,
    "ddos_threshold": 1000,  # packets per second
}

# ============================================
# CUSTOMER/ENVIRONMENT OVERRIDES
# ============================================

def load_custom_config():
    """Load custom configuration from environment or config file"""
    # Load malicious IPs from file if exists
    ioc_file = IOC_DIR / "malicious_ips.txt"
    if ioc_file.exists():
        with open(ioc_file, 'r') as f:
            SUSPICIOUS_PATTERNS["malicious_ips"] = [line.strip() for line in f if line.strip()]
    
    # Load malicious domains
    domain_file = IOC_DIR / "malicious_domains.txt"
    if domain_file.exists():
        with open(domain_file, 'r') as f:
            SUSPICIOUS_PATTERNS["malicious_domains"] = [line.strip() for line in f if line.strip()]
    
    # Load company logo
    logo_file = DATA_DIR / "logo.png"
    if logo_file.exists():
        REPORT_CONFIG["company_logo"] = str(logo_file)

# ============================================
# HELPER FUNCTIONS
# ============================================

def get_risk_level(score: int) -> Dict[str, Any]:
    """Get risk level configuration based on score"""
    for level, threshold in RISK_THRESHOLDS.items():
        if score >= threshold:
            return RISK_LEVELS[level.upper()]
    return RISK_LEVELS["INFO"]

def get_event_description(event_id: int) -> str:
    """Get human-readable description for Windows Event ID"""
    descriptions = {
        4625: "Failed logon attempt",
        4624: "Successful logon",
        4672: "Special privileges assigned to new logon",
        4688: "New process created",
        4104: "PowerShell script block logged"
    }
    return descriptions.get(event_id, f"Event ID {event_id}")

def get_file_size_mb(file_bytes) -> float:
    """Get file size in MB"""
    return len(file_bytes) / (1024 * 1024)

def is_file_allowed(filename: str) -> bool:
    """Check if file extension is allowed"""
    ext = Path(filename).suffix.lower()
    return (ext in FILE_LIMITS["supported_log_extensions"] or 
            ext in FILE_LIMITS["supported_pcap_extensions"])

# Load custom config on module import
load_custom_config()

# ============================================
# VERSION INFORMATION
# ============================================

APP_VERSION = "1.0.0"
APP_NAME = "SOC Investigation & Response Assistant"
APP_AUTHOR = "Security Operations Center"
APP_DESCRIPTION = "Local SOC analysis tool with AI-powered investigation and reporting"

# Display configuration on startup (for debugging)
def show_config():
    """Print configuration summary (for debugging)"""
    print(f"""
    ========================================
    {APP_NAME} v{APP_VERSION}
    ========================================
    Data Directory: {DATA_DIR}
    Reports Directory: {REPORTS_DIR}
    LLM Model: {OLLAMA_CONFIG['model']}
    Max Log Rows: {FILE_LIMITS['max_log_rows']}
    Max PCAP Packets: {FILE_LIMITS['max_pcap_packets']}
    Risk Thresholds: {RISK_THRESHOLDS}
    ========================================
    """)

if __name__ == "__main__":
    # If run directly, show configuration
    show_config()