# 🛡️ Mini-SOAR: Automated SOC Triage Tool

A Python-based Security Orchestration, Automation, and Response (SOAR) tool designed to automate Tier 1 SOC analyst tasks for phishing and malware alert triage.

## 📋 Overview

In a typical SOC, Tier 1 analysts spend hours manually checking IP addresses, file hashes, and URLs across multiple threat intelligence platforms. This tool automates that process by:
- Querying multiple threat intelligence APIs simultaneously
- Applying weighted scoring logic based on industry best practices
- Generating structured, actionable triage reports in JSON format
- Reducing manual triage time from minutes to seconds

## 🚀 Features

- **Multi-API Threat Enrichment:**
  - ✅ VirusTotal API - File hash reputation analysis
  - ✅ AbuseIPDB API - IP address reputation and abuse confidence scoring
  - ✅ GreyNoise API - Differentiation between targeted attacks and internet background noise
  - ✅ WHOIS lookup - Domain age analysis for phishing detection

- **Intelligent Scoring System:**
  - Weighted threat scoring based on multiple indicators
  - Automatic severity classification (MALICIOUS / BENIGN)
  - Configurable thresholds for SOC playbook tuning

- **Professional Output:**
  - Structured JSON reports ready for SIEM integration
  - Detailed triage notes for analyst review
  - Audit trail with timestamps

## 🛠️ Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/YOUR_USERNAME/mini-soar-triage.git
   cd mini-soar-triage
    Create a virtual environment:

    bash
    python -m venv venv
    source venv/bin/activate  # On Windows: venv\Scripts\activate

    Install dependencies:

    bash
    1 pip install -r requirements.txt

    Configure API keys:
        Create a config.py file in the root directory
        Add your API keys (see config.example.py for template)
        Note: config.py is gitignored to protect your credentials

📖 Usage

    Prepare your input CSV:
    Create a CSV file with the following columns:

    csv
    1
    2

    Run the triage engine:

    bash
    1

    Review the output:
    Check triage_report.json for enriched alert data and threat scores.

🎯 Real-World Use Cases

    Phishing Email Triage: Automatically analyze URLs and attachments from phishing reports
    SIEM Alert Enrichment: Integrate with Wazuh, Splunk, or Elastic via webhooks
    Incident Response: Rapidly triage IOCs during active security incidents
    Threat Hunting: Bulk analyze historical alert data for patterns

📊 Sample Output

{
    "timestamp": "2026-06-17T10:22:15",
    "user": "agarcia",
    "source_ip": "185.220.101.1",
    "threat_score": 50,
    "severity": "MALICIOUS",
    "triage_notes": [
        "AbuseIPDB HIGH CONFIDENCE (100%)",
        "GreyNoise: Internet Background Noise (Tor Exit Node)"
    ]
}

🔧 Architecture

┌─────────────────┐
│  Input Alerts   │ (CSV from SIEM/Email)
└────────────────┘
         │
┌────────▼────────┐
│  Mini-SOAR Core │
│  (Python Script)│
└────────┬────────┘
         │
    ┌────┴────┬─────────┬──────────┐
    │         │         │          │
┌───▼───┐ ┌──▼────┐ ┌──▼────┐ ┌──▼────┐
│Virus- │ │Abuse- │ │Grey-  │ │ WHOIS │
│ Total │ │ IPDB  │ │ Noise │ │       │
└───────┘ └───────┘ └───────┘ └───────┘
         │
┌────────▼────────┐
│  Triage Report  │ (JSON for SOC Analyst)
└─────────────────┘
🎓 Learning Objectives
This project demonstrates:

    ✅ Python programming for security automation
    ✅ REST API integration and error handling
    ✅ Threat intelligence platform usage
    ✅ SOC triage methodology and playbook development
    ✅ Secure coding practices (API key management)
    ✅ JSON data processing and reporting

🔐 Security Notes

    Never commit API keys to version control
    Use environment variables for production deployments
    Implement rate limiting for API calls
    Validate and sanitize all input data

📝 Future Enhancements

    Webhook integration for real-time SIEM alerts
    Slack/Teams notification integration
    Machine learning-based anomaly detection
    Docker containerization for easy deployment
    Web dashboard for report visualization

🤝 Contributing
Contributions are welcome! Please feel free to submit a Pull Request.
