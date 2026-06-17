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
