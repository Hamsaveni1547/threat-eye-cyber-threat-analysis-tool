# logic/website_logic.py
import requests
import json
import dns.resolver
import socket
import ssl
import concurrent.futures
import whois
from urllib.parse import urlparse
from datetime import datetime
import subprocess
import sys

def is_valid_url(url):
    """Check if URL format is valid"""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except ValueError:
        return False

def check_dns_records(domain):
    records = {
        'A': [], 'MX': [], 'NS': [], 'TXT': [], 'CNAME': []
    }
    for record_type in records.keys():
        try:
            answers = dns.resolver.resolve(domain, record_type)
            records[record_type] = [str(answer) for answer in answers]
        except:
            continue
    return records

def check_ssl_cert(hostname):
    try:
        # First try direct SSL connection
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                ssl_version = ssock.version()
                cipher = ssock.cipher()
                return {
                    'issuer': dict(x[0] for x in cert['issuer']),
                    'version': ssl_version,
                    'cipher': cipher[0],
                    'expires': cert['notAfter'],
                    'subject': dict(x[0] for x in cert['subject']),
                    'has_ssl': True,
                    'grade': 'A+' if 'TLSv1.3' in ssl_version else 'A'
                }
    except:
        # Try using requests as fallback
        try:
            response = requests.get(f'https://{hostname}', verify=True)
            return {
                'has_ssl': True,
                'grade': 'A',
                'version': 'TLS (version unknown)',
                'issuer': {'O': response.headers.get('Server', 'Unknown')},
                'expires': 'Unknown',
            }
        except:
            return {'has_ssl': False}

def check_security_headers(url):
    try:
        response = requests.get(url, timeout=10)
        headers = response.headers
        security_headers = {
            'Strict-Transport-Security': headers.get('Strict-Transport-Security', 'Not Set'),
            'X-Content-Type-Options': headers.get('X-Content-Type-Options', 'Not Set'),
            'X-Frame-Options': headers.get('X-Frame-Options', 'Not Set'),
            'Content-Security-Policy': headers.get('Content-Security-Policy', 'Not Set'),
            'X-XSS-Protection': headers.get('X-XSS-Protection', 'Not Set')
        }
        return security_headers
    except:
        return {}

def scan_common_ports(hostname):
    common_ports = [21, 22, 23, 25, 53, 80, 443, 445, 3306, 3389]
    open_ports = []
    
    def check_port(port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((hostname, port))
        sock.close()
        if result == 0:
            return port
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        results = executor.map(check_port, common_ports)
        open_ports = [port for port in results if port]
    
    return open_ports

def detect_technologies(url):
    try:
        response = requests.get(url, timeout=10, headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        headers = response.headers
        body = response.text.lower()
        
        technologies = []
        
        # Server software
        if 'server' in headers:
            technologies.append(('Web Server', headers['server']))
            
        # Security headers check
        if 'strict-transport-security' in headers:
            technologies.append(('Security', 'HSTS'))
        if 'content-security-policy' in headers:
            technologies.append(('Security', 'CSP'))
            
        # Common frameworks and libraries
        tech_signatures = {
            'jquery': 'jQuery',
            'react': 'React',
            'vue': 'Vue.js',
            'angular': 'Angular',
            'bootstrap': 'Bootstrap',
            'wordpress': 'WordPress',
            'joomla': 'Joomla',
            'drupal': 'Drupal',
            'laravel': 'Laravel',
            'django': 'Django',
            'nodejs': 'Node.js',
            'php': 'PHP',
            'aspnet': 'ASP.NET',
            'nginx': 'Nginx',
            'apache': 'Apache',
            'cloudflare': 'Cloudflare',
            'aws': 'AWS',
            'gsuite': 'Google Workspace',
            'google tag': 'Google Tag Manager',
            'analytics': 'Google Analytics'
        }
        
        for sig, tech in tech_signatures.items():
            if sig in body or sig in str(headers).lower():
                tech_type = 'CMS' if tech in ['WordPress', 'Joomla', 'Drupal'] else \
                           'Frontend' if tech in ['React', 'Vue.js', 'Angular', 'jQuery', 'Bootstrap'] else \
                           'Backend' if tech in ['Laravel', 'Django', 'Node.js', 'PHP', 'ASP.NET'] else \
                           'Server' if tech in ['Nginx', 'Apache'] else \
                           'Cloud' if tech in ['Cloudflare', 'AWS', 'Google Workspace'] else \
                           'Analytics'
                technologies.append((tech_type, tech))
        
        return list(set(technologies))  # Remove duplicates
    except:
        return []

def calculate_security_score(results):
    score = 100
    deductions = []
    
    # SSL scoring (30 points)
    if not results['ssl_info']['has_ssl']:
        score -= 30
        deductions.append(('No SSL Certificate', -30))
    elif results['ssl_info'].get('grade') == 'A+':
        pass  # No deduction for A+ grade
    elif results['ssl_info'].get('grade') == 'A':
        score -= 5
        deductions.append(('SSL Grade A (not A+)', -5))
    
    # Security headers scoring (25 points)
    important_headers = {
        'Strict-Transport-Security': 5,
        'Content-Security-Policy': 5,
        'X-Frame-Options': 5,
        'X-Content-Type-Options': 5,
        'X-XSS-Protection': 5
    }
    
    for header, points in important_headers.items():
        if results['security_headers'].get(header) == 'Not Set':
            score -= points
            deductions.append((f'Missing {header}', -points))
    
    # Technology diversity bonus (up to 10 points)
    tech_types = set(tech[0] for tech in results['technologies'])
    if len(tech_types) >= 4:
        score += 10
        deductions.append(('Technology Diversity Bonus', +10))
    elif len(tech_types) >= 2:
        score += 5
        deductions.append(('Technology Diversity Bonus', +5))
    
    # Modern technology bonus (up to 5 points)
    modern_techs = ['TLSv1.3', 'HTTP/2', 'HTTP/3', 'QUIC']
    for tech in modern_techs:
        if tech in str(results['ssl_info']):
            score += 5
            deductions.append((f'Modern Technology ({tech})', +5))
            break
    
    return max(0, min(100, score)), deductions

def scan_website(url, api_key):
    if not is_valid_url(url):
        return get_default_result(url, "Invalid URL format")

    try:
        # Normalize URL
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        parsed_url = urlparse(url)
        domain = parsed_url.netloc

        # Basic connectivity check
        try:
            response = requests.get(url, timeout=10)
            if response.status_code != 200:
                return get_default_result(url, f"Site returned status code {response.status_code}")
        except requests.RequestException as e:
            return get_default_result(url, f"Could not connect to site: {str(e)}")

        # Get whois info with error handling
        try:
            whois_info = whois.whois(domain)
            if not whois_info or not whois_info.domain_name:
                whois_info = {
                    "domain_name": domain,
                    "registrar": "Unknown",
                    "creation_date": "Unknown",
                    "expiration_date": "Unknown",
                    "country": "Unknown",
                    "state": "Unknown",
                    "status": "Unknown"
                }
        except Exception:
            whois_info = {
                "domain_name": domain,
                "registrar": "Unknown",
                "creation_date": "Unknown",
                "expiration_date": "Unknown",
                "country": "Unknown",
                "state": "Unknown",
                "status": "Unknown"
            }

        # Gather all information
        results = {
            "url": url,
            "domain": domain,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "dns_records": check_dns_records(domain) or {
                "A": [], "MX": [], "NS": [], "TXT": [], "CNAME": []
            },
            "ssl_info": check_ssl_cert(domain),
            "security_headers": check_security_headers(url),
            "open_ports": scan_common_ports(domain),
            "technologies": detect_technologies(url),
            "whois_info": whois_info,  # Changed from whois to whois_info
            "vulnerabilities": [],
            "stats": {
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0,
                "undetected": 0
            }
        }

        # Check for common vulnerabilities
        if not results['ssl_info']['has_ssl']:
            results['vulnerabilities'].append({
                'severity': 'High',
                'title': 'No SSL/TLS Encryption',
                'description': 'Website is not using HTTPS encryption'
            })

        for header, value in results['security_headers'].items():
            if value == 'Not Set':
                results['vulnerabilities'].append({
                    'severity': 'Medium',
                    'title': f'Missing Security Header: {header}',
                    'description': f'The {header} security header is not set'
                })

        for port in results['open_ports']:
            if port in [21, 23, 3389]:
                results['vulnerabilities'].append({
                    'severity': 'High',
                    'title': f'Risky Port {port} Open',
                    'description': f'Port {port} is open and could be exploited'
                })

        # Calculate security score
        results['security_score'], results['score_deductions'] = calculate_security_score(results)

        # Generate recommendations
        results['recommendations'] = []
        if not results['ssl_info']['has_ssl']:
            results['recommendations'].append('Implement SSL/TLS encryption (HTTPS)')
        if 'Strict-Transport-Security' not in results['security_headers']:
            results['recommendations'].append('Implement HTTP Strict Transport Security (HSTS)')
        if results['open_ports']:
            results['recommendations'].append('Review and close unnecessary open ports')

        return results

    except Exception as e:
        return get_default_result(url, f"Scan failed: {str(e)}")

def get_default_result(url, error_message):
    """Return a default result structure with error message"""
    return {
        "error": error_message,
        "url": url,
        "domain": "",
        "dns_records": {
            "A": [],
            "MX": [],
            "NS": [],
            "TXT": [],
            "CNAME": []
        },
        "whois_info": {  # Add default whois info
            "domain_name": "",
            "registrar": "Unknown",
            "creation_date": "Unknown",
            "expiration_date": "Unknown",
            "country": "Unknown",
            "state": "Unknown",
            "status": "Unknown"
        },
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "stats": {
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "undetected": 0
        }
    }