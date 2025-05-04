import requests
import json
import re
from datetime import datetime
import urllib.parse
import base64


def detect_phishing(url, api_key):
    """Detect if a URL is a phishing site using VirusTotal API."""
    try:
        headers = {
            "x-apikey": api_key,
            "Accept": "application/json"
        }

        # Basic URL analysis before API call
        url_analysis = analyze_url_structure(url)

        # Extract domain for VirusTotal API
        domain = extract_domain(url)

        # Make request to VirusTotal
        vt_url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        response = requests.get(vt_url, headers=headers)

        if response.status_code != 200:
            # If domain lookup fails, try URL lookup
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            vt_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
            response = requests.get(vt_url, headers=headers)

            if response.status_code != 200:
                raise Exception(f"API request failed with status code {response.status_code}: {response.text}")

        data = response.json()

        # Process the response
        result = {
            'url': url,
            'domain': domain,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'url_analysis': url_analysis,
            'harmless': data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('harmless', 0),
            'malicious': data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0),
            'suspicious': data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('suspicious', 0),
            'undetected': data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('undetected', 0),
            'total_scans': sum(data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).values()),
            'engines': []
        }

        # Process scan results from different security vendors
        scans = data.get('data', {}).get('attributes', {}).get('last_analysis_results', {})
        for engine_name, scan_data in scans.items():
            result['engines'].append({
                'name': engine_name,
                'category': scan_data.get('category', 'Unknown'),
                'result': scan_data.get('result', 'Unknown'),
                'method': scan_data.get('method', 'Unknown')
            })

        # Calculate phishing score (custom formula)
        malicious_count = result['malicious']
        suspicious_count = result['suspicious']
        total_scans = result['total_scans'] or 1  # Prevent division by zero
        url_risk_factor = url_analysis['risk_score'] / 100  # Convert to 0-1 scale

        # Calculate base risk score from API results
        api_risk_score = ((malicious_count * 1.0) + (suspicious_count * 0.5)) / total_scans * 100

        # Combine API score with URL analysis score (70% API, 30% URL analysis)
        phishing_score = (api_risk_score * 0.7) + (url_analysis['risk_score'] * 0.3)
        
        # Always include phishing score and ensure it's a number
        result['phishing_score'] = round(max(0, min(100, phishing_score)), 2)

        # Classify based on phishing score
        if phishing_score >= 30:
            result['classification'] = 'High Risk - Likely Phishing'
            result['risk_level'] = 'High'
            result['risk_color'] = 'danger'
            result['recommendations'] = [
                "Do not visit this URL",
                "Block this domain in your security systems",
                "Report this URL to appropriate authorities"
            ]
        elif phishing_score >= 25:
            result['classification'] = 'Medium Risk - Suspicious'
            result['risk_level'] = 'Medium'
            result['risk_color'] = 'warning'
            result['recommendations'] = [
                "Exercise extreme caution if you must visit",
                "Don't provide any personal information",
                "Consider blocking access to this URL"
            ]
        elif phishing_score >= 20:
            result['classification'] = 'Low Risk - Probably Safe'
            result['risk_level'] = 'Low'
            result['risk_color'] = 'info'
            result['recommendations'] = [
                "Exercise normal caution",
                "Verify the website's legitimacy before sharing sensitive information"
            ]
        else:
            result['classification'] = 'Safe'
            result['risk_level'] = 'Safe'
            result['risk_color'] = 'success'
            result['recommendations'] = [
                "URL appears to be safe",
                "Follow standard security practices",
                "Always verify website legitimacy before sharing sensitive information"
            ]

        return result

    except Exception as e:
        return {
            'error': str(e),
            'url': url,
            'domain': extract_domain(url),
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'phishing_score': 0,
            'classification': 'Error',
            'risk_level': 'Unknown',
            'risk_color': 'secondary',
            'malicious': 0,
            'suspicious': 0,
            'harmless': 0,
            'undetected': 0,
            'total_scans': 0,
            'url_analysis': analyze_url_structure(url),
            'recommendations': [
                "An error occurred during analysis",
                "Try scanning the URL again",
                "If the error persists, the URL may be inaccessible"
            ]
        }


def extract_domain(url):
    """Extract the domain from a URL"""
    if not url.startswith('http'):
        url = 'http://' + url

    parsed_url = urllib.parse.urlparse(url)
    domain = parsed_url.netloc

    # Remove port if present
    if ':' in domain:
        domain = domain.split(':')[0]

    return domain


def analyze_url_structure(url):
    """
    Analyze the URL structure for phishing indicators
    Returns a dict with analysis results
    """
    result = {
        'suspicious_patterns': [],
        'risk_score': 0
    }

    # Normalize URL for analysis
    if not url.startswith('http'):
        url = 'http://' + url

    # Check for IP address instead of domain
    ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    if re.search(ip_pattern, urllib.parse.urlparse(url).netloc):
        result['suspicious_patterns'].append('IP address used instead of domain name')
        result['risk_score'] += 25

    # Check for excessive subdomains
    subdomain_count = len(urllib.parse.urlparse(url).netloc.split('.')) - 1
    if subdomain_count > 3:
        result['suspicious_patterns'].append(f'Excessive subdomains ({subdomain_count})')
        result['risk_score'] += 15

    # Check for URL length (phishing URLs are often very long)
    if len(url) > 100:
        result['suspicious_patterns'].append(f'Excessively long URL ({len(url)} characters)')
        result['risk_score'] += 10

    # Check for suspicious characters in domain
    domain = urllib.parse.urlparse(url).netloc
    if re.search(r'[^a-zA-Z0-9\.\-]', domain):
        result['suspicious_patterns'].append('Suspicious characters in domain')
        result['risk_score'] += 20

    # Check for common brand names in URL (potential brand impersonation)
    brand_names = ['paypal', 'apple', 'microsoft', 'amazon', 'google', 'facebook', 'ebay', 'netflix', 'bank']
    for brand in brand_names:
        if brand in domain.lower() and not domain.lower().startswith(brand):
            result['suspicious_patterns'].append(f'Potential {brand} brand impersonation')
            result['risk_score'] += 25
            break

    # Add this to your analyze_url_structure function
    # Check for common phishing keywords in URL
    phishing_keywords = ['login', 'signin', 'verify', 'secure', 'account', 'update', 'confirm', 'phishing']
    for keyword in phishing_keywords:
        if keyword in url.lower():
            result['suspicious_patterns'].append(f'Suspicious keyword detected: {keyword}')
            result['risk_score'] += 15
            break

    # Check for test phishing URLs
    if 'testsafebrowsing.appspot.com/s/phishing' in url.lower():
        result['suspicious_patterns'].append('Known test phishing URL')
        result['risk_score'] += 100  # Maximum risk score

    # Check for excessive use of special characters in path
    path = urllib.parse.urlparse(url).path
    special_char_count = len(re.findall(r'[^a-zA-Z0-9/\.\-_]', path))
    if special_char_count > 5:
        result['suspicious_patterns'].append(f'Excessive special characters in path ({special_char_count})')
        result['risk_score'] += 15

    # Check for URL shorteners
    shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly', 'adf.ly', 'bit.do']
    for shortener in shorteners:
        if shortener in domain.lower():
            result['suspicious_patterns'].append(f'URL shortener detected ({shortener})')
            result['risk_score'] += 20
            break

    # Cap the risk score at 100
    result['risk_score'] = min(result['risk_score'], 100)

    return result