# 🛡️ SOC Investigation Assistant

[![Python 3.10+](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://www.python.org/)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.28+-red.svg)](https://streamlit.io/)
[![Ollama](https://img.shields.io/badge/Ollama-0.1+-green.svg)](https://ollama.com/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## An AI-Powered Security Operations Center (SOC) Investigation Tool

**SOC Investigation Assistant** is a professional-grade security analysis tool that helps SOC analysts investigate security incidents using natural language. Just upload your logs and ask questions like *"Show failed logins"* or *"Find privilege escalation events"* — the AI does the rest!

🔒 **100% Local Processing** - No data ever leaves your machine. Works completely offline.

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🔍 **Universal Log Parser** | Supports CSV, JSON, EVTX, PCAP, Syslog, Apache, IIS, Wazuh, and custom formats |
| 🤖 **AI Chatbot** | Ask natural language questions about your security logs |
| 🎯 **MITRE ATT&CK Mapping** | Automatically maps findings to industry-standard tactics and techniques |
| 📊 **Risk Scoring** | Calculates risk scores (0-100) based on severity, volume, and recency |
| 🛡️ **Remediation Playbooks** | Provides actionable response steps for each finding |
| 📈 **Attack Timeline** | Chronological visualization of attack progression |
| 🌐 **IOC Extraction** | Extracts IPs, usernames, hostnames, and suspicious commands |
| 📄 **Multi-format Reports** | Export findings as JSON, Markdown, or CSV |
| 🔒 **100% Local** | No cloud dependencies - your logs stay private |

---

## 🎯 Use Cases

- **Incident Response** - Quickly investigate security alerts and breaches
- **Threat Hunting** - Search for IOCs across large log files
- **Compliance Audits** - Generate professional security reports
- **SOC Training** - Learn investigation workflows and attack patterns
- **Log Analysis** - Analyze any log format with natural language

---

## 🚀 Quick Start

### Prerequisites

- Python 3.10 or higher
- 4GB+ RAM (8GB recommended)
- Ollama (for AI features)

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/soc-investigation-assistant.git
cd soc-investigation-assistant

# Create virtual environment
python -m venv venv

# Activate it
# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Install Ollama (if not already installed)
# Download from https://ollama.com

# Pull the AI model (about 2GB)
ollama pull llama3.2:3b
```
Run the Application
```bash
# Terminal 1: Start Ollama service
ollama serve

# Terminal 2: Run the app
streamlit run app/main.py
```
Open your browser to http://localhost:8501

### 💬 Example Queries
Try asking the SOC Analyst AI:

```🔍 "Investigate this incident"
📜 "Show attack timeline"
🎯 "Identify root cause"
🛡️ "Recommend remediation"
⚠️ "Assess risk level"
🧩 "MITRE ATT&CK mapping"
🌐 "Extract IOCs"
👤 "List affected assets"
🔗 "Show correlated events"
📊 "Confidence assessment"
```
### 📁 Project Structure
```
text
soc-investigation-assistant/
├── app/
│   ├── main.py                 # Streamlit UI
│   ├── config.py               # Configuration settings
│   ├── parsers/                # Log & PCAP parsers
│   │   ├── log_parser.py       # Universal log parser
│   │   └── pcap_parser.py      # Network capture parser
│   ├── analyzers/              # Threat detection & risk scoring
│   │   ├── threat_detector.py  # Pattern-based detection
│   │   └── risk_scorer.py      # Risk calculation
│   ├── remediation/            # Incident response playbooks
│   │   └── playbooks.py        # Remediation steps
│   ├── reporting/              # MITRE mapping & reports
│   │   ├── mitre_mapper.py     # ATT&CK framework mapping
│   │   └── report_generator.py # Report generation
│   ├── llm/                    # AI chatbot agent
│   │   └── soc_analyst_agent.py # Senior SOC Analyst AI
│   └── utils/                  # Helper functions
│       └── exporters.py        # Multi-format export
├── data/                       # Sample data & reports
├── requirements.txt            # Python dependencies
├── .gitignore                  # Git ignore rules
└── README.md                   # This file
```
### 🛠️ Tech Stack
```
Component	Technology
Frontend	Streamlit
Data Processing	Pandas, NumPy
Local LLM	Ollama (Llama 3.2 3B)
PCAP Analysis	Scapy
Visualizations	Matplotlib, Plotly
Export Formats	JSON, CSV, Markdown
```
### 📊 Sample Output
```text
📊 Executive Summary
🔴 CRITICAL RISK: 85/100 - Active compromise indicators

Metrics:
├── Total Events: 50,000
├── Critical Events: 12
├── Suspicious IPs: 48,952
└── Suspicious Users: 5,000

🔴 Suspicious IP Addresses:
├── 96.43.44.157 (occurred 234 times)
├── 48.111.246.1 (occurred 189 times)
└── 156.47.178.129 (occurred 156 times)

👤 Suspicious Users:
├── user3233 (occurred 45 times)
├── user3364 (occurred 38 times)
└── user2680 (occurred 32 times)
```
### 🔒 Privacy & Security

100% Local Processing - No data ever leaves your machine

Offline Capable - Works without internet after initial setup

No Telemetry - No tracking, no analytics

Open Source - Fully auditable code

### 🤝 Contributing

Contributions are welcome! Here's how:

Fork the repository

Create your feature branch (git checkout -b feature/AmazingFeature)

Commit your changes (git commit -m 'Add some AmazingFeature')

Push to the branch (git push origin feature/AmazingFeature)

Open a Pull Request

### 📄 License

Distributed under the MIT License. See LICENSE file for more information.

### 🙏 Acknowledgments

Streamlit - Amazing web framework for data apps

Ollama - Local LLM inference

MITRE ATT&CK - Industry-standard framework

Llama 3.2 - Open-source LLM by Meta

### 📧 Contact

Your Name - @madhavrajsinh rana 

Project Link: https://github.com/csmadhav24/ThreatLens-AI

### ⭐ Show Your Support

If this project helped you, please give it a ⭐️!

### 🎯 Roadmap

Real-time log monitoring

Email/Slack alerting

ML-based anomaly detection

Multi-tenant support

Docker deployment

# Built with ❤️ for the security community
