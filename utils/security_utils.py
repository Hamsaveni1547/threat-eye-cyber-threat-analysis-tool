import hashlib
import requests
import ssl
import socket
import whois
import dns.resolver
from datetime import datetime
import tldextract
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
import re

def calculate_file_hash(file_obj):
    """Calculate SHA-256 hash of uploaded file"""
    sha256_hash = hashlib.sha256()
    for byte_block in iter(lambda: file_obj.read(4096), b""):
        sha256_hash.update(byte_block)
    file_obj.seek(0)
    return sha256_hash.hexdigest()

def check_ssl_certificate(url):
    """Check SSL certificate details"""
    try:
        hostname = tldextract.extract(url).registered_domain
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                return {
                    'issuer': dict(x[0] for x in cert['issuer']),
                    'expiry': cert['notAfter'],
                    'subject': dict(x[0] for x in cert['subject']),
                    'version': cert['version']
                }
    except Exception as e:
        return {'error': str(e)}

def get_domain_info(url):
    """Get domain registration and age information"""
    try:
        domain = tldextract.extract(url).registered_domain
        w = whois.whois(domain)
        return {
            'registrar': w.registrar,
            'creation_date': w.creation_date,
            'expiration_date': w.expiration_date,
            'age_days': (datetime.now() - w.creation_date).days if w.creation_date else None
        }
    except Exception as e:
        return {'error': str(e)}

def capture_url_screenshot(url):
    """Capture screenshot of URL using headless Chrome"""
    try:
        chrome_options = Options()
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--window-size=1920x1080")
        driver = webdriver.Chrome(options=chrome_options)
        driver.get(url)
        screenshot = driver.get_screenshot_as_base64()
        driver.quit()
        return screenshot
    except Exception as e:
        return None

def check_dns_records(domain):
    """Check various DNS records"""
    results = {}
    record_types = ['A', 'MX', 'TXT', 'NS']
    
    for record_type in record_types:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            results[record_type] = [str(rdata) for rdata in answers]
        except Exception:
            results[record_type] = []
    
    return results
