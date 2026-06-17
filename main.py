import csv
import json
import requests
import whois
from datetime import datetime, timedelta
from config import VT_API_KEY, ABUSEIPDB_API_KEY

# --- Configuration ---
VT_URL = "https://www.virustotal.com/api/v3/files/{}"
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
SCORE_THRESHOLD = 50 # Alerts scoring >= 50 are flagged as MALICIOUS

def check_abuseipdb(ip_address):
    """Queries AbuseIPDB for IP reputation."""
    if ip_address.startswith(('10.', '192.168.', '172.16.')):
        return {"is_malicious": False, "abuse_confidence": 0, "note": "Private IP"}
    
    headers = {'Key': ABUSEIPDB_API_KEY, 'Accept': 'application/json'}
    params = {'ipAddress': ip_address, 'maxAgeInDays': 90}
    
    try:
        response = requests.get(ABUSEIPDB_URL, headers=headers, params=params)
        response.raise_for_status()
        data = response.json()['data']
        return {
            "is_malicious": data['abuseConfidenceScore'] > 10,
            "abuse_confidence": data['abuseConfidenceScore'],
            "note": f"Reported {data['totalReports']} times"
        }
    except requests.exceptions.RequestException as e:
        return {"is_malicious": False, "error": str(e)}

def check_greynoise(ip_address):
    """Queries GreyNoise to see if the IP is internet noise or a targeted threat."""
    # The Community API is free and requires no API key!
    url = f"https://api.greynoise.io/v2/community/{ip_address}"
    
    try:
        response = requests.get(url)
        
        # If the IP has never been seen by GreyNoise, it returns a 404
        if response.status_code == 404:
            return {"is_malicious": False, "note": "IP not seen by GreyNoise (Clean)"}
            
        response.raise_for_status()
        data = response.json()
        
        # GreyNoise returns 'noise' (is it scanning the internet?) 
        # and 'classification' (benign, unknown, malicious)
        is_noise = data.get('noise', False)
        classification = data.get('classification', 'unknown')
        name = data.get('name', 'Unknown Bot')
        
        # If it's malicious and NOT just background noise, it's a high threat
        if classification == 'malicious' and not is_noise:
            return {
                "is_malicious": True, 
                "note": f"Targeted Malicious Activity by {name}"
            }
        elif is_noise:
            return {
                "is_malicious": False, 
                "note": f"Internet Background Noise ({name})"
            }
        else:
            return {"is_malicious": False, "note": f"Classified as {classification}"}
            
    except requests.exceptions.RequestException as e:
        return {"is_malicious": False, "error": str(e)}

def check_virustotal(file_hash):
    """Queries VirusTotal for file hash reputation."""
    if file_hash == "NA" or len(file_hash) < 32:
        return {"is_malicious": False, "note": "No valid hash provided"}
        
    headers = {'x-apikey': VT_API_KEY}
    url = VT_URL.format(file_hash)
    
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 404:
            return {"is_malicious": False, "note": "Hash not found in VT"}
        response.raise_for_status()
        data = response.json()['data']['attributes']
        stats = data['last_analysis_stats']
        malicious_count = stats['malicious'] + stats['suspicious']
        
        return {
            "is_malicious": malicious_count > 0,
            "malicious_count": malicious_count,
            "note": f"VT Score: {malicious_count} malicious/suspicious"
        }
    except requests.exceptions.RequestException as e:
        return {"is_malicious": False, "error": str(e)}

def check_domain_age(url):
    """Checks if a domain was registered in the last 30 days."""
    try:
        # Extract domain from URL (basic extraction)
        domain = url.split("//")[-1].split("/")[0]
        w = whois.whois(domain)
        creation_date = w.creation_date
        
        # Handle cases where creation_date is a list
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
            
        if creation_date:
            # Ensure timezone awareness for comparison
            if creation_date.tzinfo is None:
                creation_date = creation_date.replace(tzinfo=datetime.now().astimezone().tzinfo)
                
            days_old = (datetime.now(creation_date.tzinfo) - creation_date).days
            return {"is_suspicious": days_old < 30, "days_old": days_old}
        return {"is_suspicious": False, "note": "No creation date found"}
    except Exception:
        return {"is_suspicious": False, "note": "WHOIS lookup failed"}

# Make sure it has 4 arguments inside the parentheses!
def calculate_score(ip_result, vt_result, domain_result, gn_result):
    """Applies SOC triage logic to calculate a threat score."""
    score = 0
    reasons = []
    
    # 1. GreyNoise Check
    if gn_result.get("is_malicious"):
        score += 60  
        reasons.append(f"GreyNoise: {gn_result.get('note')}")
    elif "Internet Background Noise" in gn_result.get("note", ""):
        score += 10  
        reasons.append(f"GreyNoise: {gn_result.get('note')}")
        
    # 2. AbuseIPDB Check (UPDATED FOR REAL-WORLD TUNING)
    if ip_result.get("is_malicious"):
        confidence = ip_result.get('abuse_confidence', 0)
        if confidence >= 90:
            score += 50  # High confidence is an automatic trigger!
            reasons.append(f"AbuseIPDB HIGH CONFIDENCE ({confidence}%)")
        else:
            score += 30
            reasons.append(f"AbuseIPDB flagged (Confidence: {confidence}%)")
        
    # 3. VirusTotal Check
    if vt_result.get("is_malicious"):
        score += 50
        reasons.append(f"VirusTotal flagged ({vt_result.get('malicious_count')} engines)")
        
    # 4. Domain Age Check
    if domain_result.get("is_suspicious"):
        score += 20
        reasons.append(f"Domain is newly registered ({domain_result.get('days_old')} days old)")
        
    return score, reasons

def process_alerts(input_file, output_file):
    """Main orchestrator function."""
    triage_results = []
    
    with open(input_file, mode='r') as file:
        reader = csv.DictReader(file)
        for row in reader:
            print(f"[*] Triage in progress for User: {row['user']}...")
            
            # 1. Enrichment
            ip_data = check_abuseipdb(row['source_ip'])
            vt_data = check_virustotal(row['file_hash'])
            domain_data = check_domain_age(row['url_clicked'])
            gn_data = check_greynoise(row['source_ip']) # <--- NEW: Added GreyNoise check
            
            # 2. Scoring Logic
            # <--- UPDATED: Added gn_data to the function call
            threat_score, reasons = calculate_score(ip_data, vt_data, domain_data, gn_data) 
            severity = "MALICIOUS" if threat_score >= SCORE_THRESHOLD else "BENIGN / LOW RISK"
            
            # 3. Build Report Object
            report = {
                "timestamp": row['timestamp'],
                "user": row['user'],
                "source_ip": row['source_ip'],
                "url_clicked": row['url_clicked'],
                "file_hash": row['file_hash'],
                "threat_score": threat_score,
                "severity": severity,
                "triage_notes": reasons if reasons else ["No immediate threats detected"]
            }
            triage_results.append(report)
            
    # 4. Output Results
    with open(output_file, 'w') as out_file:
        json.dump(triage_results, out_file, indent=4)
    print(f"[+] Triage complete. Results saved to {output_file}")

if __name__ == "__main__":
    print("[*] Starting Mini-SOAR Triage Engine...")
    process_alerts("sample_alerts.csv", "triage_report.json")