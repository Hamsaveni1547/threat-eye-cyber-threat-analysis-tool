# logic/website_logic.py
import requests
import json
import re
import base64
from urllib.parse import urlparse
from datetime import datetime


def is_valid_url(url):
    """Check if URL format is valid"""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except ValueError:
        return False


def scan_website(url, api_key):
    """
    Scan a website for security threats using VirusTotal API
    """
    if not is_valid_url(url):
        return {
            "error": "Invalid URL format",
            "stats": {
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0,
                "undetected": 0
            },
            "risk_level": "Unknown",
            "risk_color": "secondary",
            "vulnerabilities": [],
            "ssl_info": {
                "issuer": "N/A",
                "valid_from": "N/A",
                "valid_until": "N/A",
                "version": "N/A"
            },
            "categories": {},
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "url": url,
            "domain": ""
        }

    # Make sure URL has a scheme
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    headers = {
        "x-apikey": api_key,
        "Accept": "application/json"
    }

    # Get domain from URL
    domain = urlparse(url).netloc

    try:
        # First, check if there's existing analysis
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        check_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        response = requests.get(check_url, headers=headers)

        url_data = {}
        if response.status_code == 200:
            url_data = response.json()
        else:
            # Submit URL for scanning
            scan_url = "https://www.virustotal.com/api/v3/urls"
            form_data = {"url": url}
            scan_response = requests.post(scan_url, headers=headers, data=form_data)

            if scan_response.status_code == 200:
                scan_data = scan_response.json()
                url_id = scan_data.get('data', {}).get('id', '')
                analysis_id = scan_data.get('data', {}).get('id', '')

                # Wait and get results
                check_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
                response = requests.get(check_url, headers=headers)
                if response.status_code == 200:
                    url_data = response.json()

        # Also get domain information
        domain_url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        domain_response = requests.get(domain_url, headers=headers)
        domain_data = {}

        if domain_response.status_code == 200:
            domain_data = domain_response.json()

        # Extract security information
        attributes = url_data.get('data', {}).get('attributes', {})
        stats = attributes.get('last_analysis_stats', {})
        domain_attributes = domain_data.get('data', {}).get('attributes', {})

        # Get certificate info if available
        ssl_info = domain_attributes.get('last_https_certificate', {})

        # Calculate risk level
        malicious_count = stats.get('malicious', 0)
        suspicious_count = stats.get('suspicious', 0)

        if malicious_count > 3:
            risk_level = "High"
            risk_color = "danger"
        elif malicious_count > 0 or suspicious_count > 2:
            risk_level = "Medium"
            risk_color = "warning"
        else:
            risk_level = "Low"
            risk_color = "success"

        # Identify vulnerabilities (this is a simplified example)
        vulnerabilities = []

        if not domain_attributes.get('last_https_certificate'):
            vulnerabilities.append({
                "severity": "High",
                "title": "No SSL Certificate",
                "description": "Website does not use HTTPS encryption"
            })

        if domain_attributes.get('last_dns_records', []):
            spf_exists = False
            dmarc_exists = False

            for record in domain_attributes.get('last_dns_records', []):
                if record.get('type') == 'TXT' and 'spf' in record.get('value', '').lower():
                    spf_exists = True
                if record.get('type') == 'TXT' and 'dmarc' in record.get('value', '').lower():
                    dmarc_exists = True

            if not spf_exists:
                vulnerabilities.append({
                    "severity": "Medium",
                    "title": "Missing SPF Record",
                    "description": "Domain lacks Sender Policy Framework protection against email spoofing"
                })

            if not dmarc_exists:
                vulnerabilities.append({
                    "severity": "Medium",
                    "title": "Missing DMARC Record",
                    "description": "Domain lacks DMARC email authentication policy"
                })

        # Prepare result
        result = {
            "url": url,
            "domain": domain,
            "stats": {  # Changed from individual counts to a stats object
                "malicious": stats.get('malicious', 0),
                "suspicious": stats.get('suspicious', 0),
                "harmless": stats.get('harmless', 0),
                "undetected": stats.get('undetected', 0)
            },
            "risk_level": risk_level,
            "risk_color": risk_color,
            "vulnerabilities": vulnerabilities,
            "ssl_info": {
                "issuer": ssl_info.get('issuer', {}).get('O', 'N/A'),
                "valid_from": ssl_info.get('validity', {}).get('not_before', 'N/A'),
                "valid_until": ssl_info.get('validity', {}).get('not_after', 'N/A'),
                "version": ssl_info.get('version', 'N/A')
            },
            "categories": domain_attributes.get('categories', {}),
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "raw_url_data": url_data,
            "raw_domain_data": domain_data
        }

        return result

    except requests.exceptions.RequestException as e:
        return {
            "error": f"Request failed: {str(e)}",
            "stats": {
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0,
                "undetected": 0
            },
            "risk_level": "Error",
            "risk_color": "danger",
            "vulnerabilities": [],
            "ssl_info": {
                "issuer": "N/A",
                "valid_from": "N/A",
                "valid_until": "N/A",
                "version": "N/A"
            },
            "categories": {},
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "url": url,
            "domain": ""
        }
    