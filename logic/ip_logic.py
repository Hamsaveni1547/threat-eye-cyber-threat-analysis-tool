# logic/ip_logic.py
import requests
import json
import ipaddress
from datetime import datetime


def is_valid_ip(ip_address):
    try:
        ipaddress.ip_address(ip_address)
        return True
    except ValueError:
        return False


def analyze_ip(ip_address, api_key):
    """
    Analyze an IP address using VirusTotal API
    """
    if not is_valid_ip(ip_address):
        return {
            "error": "Invalid IP address format",
            "ip_address": ip_address,
            "country": "Unknown",
            "asn": "Unknown",
            "as_owner": "Unknown",
            "malicious_count": 0,
            "suspicious_count": 0,
            "harmless_count": 0,
            "undetected_count": 0,
            "reputation": 0,
            "risk_level": "Unknown",
            "risk_color": "secondary",
            "security_score": 0,  # Add this line
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

    headers = {
        "x-apikey": api_key,
        "Accept": "application/json"
    }

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"

    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            attributes = data.get('data', {}).get('attributes', {})
            last_analysis_stats = attributes.get('last_analysis_stats', {})
            
            malicious_count = last_analysis_stats.get('malicious', 0)
            suspicious_count = last_analysis_stats.get('suspicious', 0)
            harmless_count = last_analysis_stats.get('harmless', 0)
            undetected_count = last_analysis_stats.get('undetected', 0)
            
            # Calculate security score (0-100)
            total_detections = malicious_count + suspicious_count + harmless_count + undetected_count
            if total_detections > 0:
                security_score = int(((harmless_count + undetected_count) / total_detections) * 100)
            else:
                security_score = 0
            # Determine risk level based on malicious detections
            malicious_count = last_analysis_stats.get('malicious', 0)
            suspicious_count = last_analysis_stats.get('suspicious', 0)

            if malicious_count > 5:
                risk_level = "High"
                risk_color = "danger"
            elif malicious_count > 0 or suspicious_count > 3:
                risk_level = "Medium"
                risk_color = "warning"
            else:
                risk_level = "Low"
                risk_color = "success"

            result = {
                "ip_address": ip_address,
                "country": attributes.get('country', 'Unknown'),
                "asn": attributes.get('asn', 'Unknown'),
                "as_owner": attributes.get('as_owner', 'Unknown'),
                "malicious_count": malicious_count,
                "suspicious_count": suspicious_count,
                "harmless_count": harmless_count,
                "undetected_count": undetected_count,
                "reputation": attributes.get('reputation', 0),
                "risk_level": risk_level,
                "risk_color": risk_color,
                "security_score": security_score,  # Add this line
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "raw_data": data
            }

            return result
        else:
            return {
                "error": f"API Error: {response.status_code}",
                "ip_address": ip_address,
                "country": "Unknown",
                "asn": "Unknown",
                "as_owner": "Unknown",
                "malicious_count": 0,
                "suspicious_count": 0,
                "harmless_count": 0,
                "undetected_count": 0,
                "reputation": 0,
                "risk_level": "Error",
                "risk_color": "danger",
                "security_score": 0,  # Add this line
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }

    except requests.exceptions.RequestException as e:
        return {
            "error": f"Request failed: {str(e)}",
            "ip_address": ip_address,
            "country": "Unknown",
            "asn": "Unknown",
            "as_owner": "Unknown",
            "malicious_count": 0,
            "suspicious_count": 0,
            "harmless_count": 0,
            "undetected_count": 0,
            "reputation": 0,
            "risk_level": "Error",
            "risk_color": "danger",
            "security_score": 0,  # Add this line
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
    