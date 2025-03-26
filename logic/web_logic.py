import requests
import json
import time
import ssl
import socket
import whois
import hashlib
from urllib.parse import urlparse
import re
from datetime import datetime
import os
import urllib3
import warnings

# Suppress only the specific InsecureRequestWarning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class WebsiteScanner:
    def __init__(self, api_key):
        self.api_key = api_key
        self.vt_url = "https://www.virustotal.com/api/v3/"
        self.headers = {
            "x-apikey": self.api_key,
            "Content-Type": "application/json"
        }
        self.scan_results = {
            "url": None,
            "scan_id": None,
            "timestamp": None,
            "malware_detection": {},
            "phishing_detection": {},
            "ssl_info": {},
            "security_headers": {},
            "domain_info": {},
            "overall_score": 0,
            "risk_level": "Unknown"
        }

    def scan_website(self, url, scan_options=None):
        """
        Main method to scan a website with selected options
        """
        if not scan_options:
            scan_options = ["malware", "phishing", "ssl", "headers"]

        # Normalize URL
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url

        self.scan_results["url"] = url
        self.scan_results["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Domain information
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        self.scan_results["domain_info"] = self._get_domain_info(domain)

        # Run selected scans
        if "malware" in scan_options:
            self.scan_results["malware_detection"] = self._check_url_virustotal(url)

        if "phishing" in scan_options:
            self.scan_results["phishing_detection"] = self._check_phishing_indicators(url)

        if "ssl" in scan_options:
            self.scan_results["ssl_info"] = self._check_ssl_certificate(url)

        if "headers" in scan_options:
            self.scan_results["security_headers"] = self._check_security_headers(url)

        # Calculate overall risk score
        self._calculate_risk_score()

        return self.scan_results

    def _check_url_virustotal(self, url):
        """
        Check URL with VirusTotal API
        """
        result = {
            "status": "Unknown",
            "detections": {},
            "total_engines": 0,
            "malicious_count": 0,
            "suspicious_count": 0,
            "harmless_count": 0,
            "undetected_count": 0,
            "last_analysis_date": None,
            "vt_link": None
        }

        try:
            # First, check if URL is already in VT database
            url_id = hashlib.sha256(url.encode()).hexdigest()
            response = requests.get(
                f"{self.vt_url}urls/{url_id}",
                headers=self.headers,
                timeout=10
            )

            # If URL not found, submit it for analysis
            if response.status_code == 404:
                data = {"url": url}
                response = requests.post(
                    f"{self.vt_url}urls",
                    headers=self.headers,
                    data=json.dumps(data),
                    timeout=10
                )

                if response.status_code == 200:
                    submission_data = response.json()
                    # Extract the analysis ID from the submission response
                    analysis_id = None
                    if "data" in submission_data and "id" in submission_data["data"]:
                        analysis_id = submission_data["data"]["id"]

                    if not analysis_id:
                        result["error"] = "Failed to get analysis ID from submission"
                        return result

                    # Wait for analysis to complete (max 60 seconds)
                    for _ in range(30):
                        analysis_response = requests.get(
                            f"{self.vt_url}analyses/{analysis_id}",
                            headers=self.headers,
                            timeout=10
                        )

                        if analysis_response.status_code == 200:
                            analysis_data = analysis_response.json().get("data", {})
                            status = analysis_data.get("attributes", {}).get("status")

                            if status == "completed":
                                # Get URL ID from the completed analysis
                                url_id = analysis_data.get("meta", {}).get("url_info", {}).get("id")
                                if not url_id:
                                    result["error"] = "Failed to get URL ID from analysis"
                                    return result

                                # Get URL report
                                url_response = requests.get(
                                    f"{self.vt_url}urls/{url_id}",
                                    headers=self.headers,
                                    timeout=10
                                )
                                if url_response.status_code == 200:
                                    response = url_response
                                break

                        time.sleep(2)

            # Process results
            if response.status_code == 200:
                data = response.json().get("data", {})
                attributes = data.get("attributes", {})
                last_analysis_results = attributes.get("last_analysis_results", {})
                last_analysis_stats = attributes.get("last_analysis_stats", {})

                result["total_engines"] = sum(last_analysis_stats.values())
                result["malicious_count"] = last_analysis_stats.get("malicious", 0)
                result["suspicious_count"] = last_analysis_stats.get("suspicious", 0)
                result["harmless_count"] = last_analysis_stats.get("harmless", 0)
                result["undetected_count"] = last_analysis_stats.get("undetected", 0)

                if attributes.get("last_analysis_date"):
                    result["last_analysis_date"] = datetime.fromtimestamp(
                        attributes.get("last_analysis_date")
                    ).strftime("%Y-%m-%d %H:%M:%S")

                # Store detections from engines that found the URL malicious or suspicious
                for engine, engine_result in last_analysis_results.items():
                    category = engine_result.get("category")
                    if category in ["malicious", "suspicious"]:
                        result["detections"][engine] = {
                            "category": category,
                            "result": engine_result.get("result"),
                            "method": engine_result.get("method")
                        }

                # Set overall status
                if result["malicious_count"] > 0:
                    result["status"] = "Malicious"
                elif result["suspicious_count"] > 0:
                    result["status"] = "Suspicious"
                elif result["harmless_count"] > 0:
                    result["status"] = "Clean"
                else:
                    result["status"] = "Unknown"

                # Add VirusTotal link
                result["vt_link"] = f"https://www.virustotal.com/gui/url/{url_id}/detection"
            else:
                result["error"] = f"VirusTotal API error: {response.status_code} - {response.text}"

        except requests.exceptions.Timeout:
            result["error"] = "VirusTotal API request timed out"
        except requests.exceptions.RequestException as e:
            result["error"] = f"VirusTotal API request failed: {str(e)}"
        except Exception as e:
            result["error"] = f"Unexpected error in VirusTotal scan: {str(e)}"

        return result

    def _check_phishing_indicators(self, url):
        """
        Check for common phishing indicators in the URL and webpage
        """
        result = {
            "status": "Unknown",
            "suspicious_patterns": [],
            "is_suspicious": False,
            "risk_score": 0
        }

        try:
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            path = parsed_url.path

            # Check suspicious URL patterns
            suspicious_patterns = []

            # Check for IP address instead of domain
            if re.match(r'\d+\.\d+\.\d+\.\d+', domain):
                suspicious_patterns.append("IP address used instead of domain name")
                result["risk_score"] += 20

            # Check for suspicious keywords in domain and path
            suspicious_keywords = [
                'secure', 'account', 'banking', 'login', 'signin', 'verify', 'support',
                'update', 'confirm', 'paypal', 'payment', 'bank', 'verification', 'authenticate'
            ]

            # Check domain
            for keyword in suspicious_keywords:
                if keyword in domain.lower():
                    suspicious_patterns.append(f"Suspicious keyword '{keyword}' in domain")
                    result["risk_score"] += 5

            # Check path
            for keyword in suspicious_keywords:
                if keyword in path.lower():
                    suspicious_patterns.append(f"Suspicious keyword '{keyword}' in URL path")
                    result["risk_score"] += 3

            # Check for excessive subdomains
            subdomain_count = domain.count('.')
            if subdomain_count > 3:
                suspicious_patterns.append(f"Excessive subdomains ({subdomain_count})")
                result["risk_score"] += 10

            # Check for URL length
            if len(url) > 100:
                suspicious_patterns.append(f"Excessively long URL ({len(url)} characters)")
                result["risk_score"] += 5

            # Check for suspicious TLD
            suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.club', '.online']
            if any(domain.endswith(tld) for tld in suspicious_tlds):
                tld = next(tld for tld in suspicious_tlds if domain.endswith(tld))
                suspicious_patterns.append(f"Suspicious TLD: {tld}")
                result["risk_score"] += 15

            # Check for domains trying to mimic popular brands
            popular_brands = ['paypal', 'apple', 'microsoft', 'amazon', 'netflix', 'google', 'facebook',
                              'instagram', 'twitter', 'linkedin']

            for brand in popular_brands:
                if brand in domain.lower() and brand.lower() != domain.lower():
                    if re.search(f"{brand}[a-z0-9-]*\\.", domain.lower()) or re.search(f"\\.{brand}[a-z0-9-]*\\.",
                                                                                       domain.lower()):
                        suspicious_patterns.append(f"Possible {brand} brand impersonation in domain")
                        result["risk_score"] += 20

            # Fetch webpage content if protocol is https or http
            if parsed_url.scheme in ['https', 'http']:
                try:
                    with warnings.catch_warnings():
                        warnings.simplefilter("ignore")
                        response = requests.get(url, timeout=10, allow_redirects=True, verify=False)

                    # Check for login forms
                    if 'password' in response.text.lower() and (
                            'username' in response.text.lower() or 'email' in response.text.lower()):
                        suspicious_patterns.append("Login form detected")

                        # Check if secure connection for login form
                        if parsed_url.scheme != 'https':
                            suspicious_patterns.append("Login form on non-HTTPS connection")
                            result["risk_score"] += 25

                    # Check for brand impersonation in title
                    title_match = re.search(r'<title>(.*?)</title>', response.text, re.IGNORECASE)
                    if title_match:
                        title = title_match.group(1)
                        for brand in popular_brands:
                            if brand.lower() in title.lower() and brand.lower() not in domain.lower():
                                suspicious_patterns.append(f"Possible {brand} impersonation in page title")
                                result["risk_score"] += 30

                    # Check for obfuscated or hidden content
                    if 'visibility:hidden' in response.text.lower() or 'display:none' in response.text.lower():
                        suspicious_patterns.append("Hidden content detected (possible phishing)")
                        result["risk_score"] += 15

                    # Check for redirections
                    if len(response.history) > 2:
                        suspicious_patterns.append(f"Multiple redirects detected ({len(response.history)})")
                        result["risk_score"] += 10

                except requests.exceptions.Timeout:
                    suspicious_patterns.append("Timeout when connecting to website")
                except requests.exceptions.RequestException as e:
                    suspicious_patterns.append(f"Error fetching webpage: {str(e)}")
                except Exception as e:
                    suspicious_patterns.append(f"Error analyzing webpage: {str(e)}")

            # Save results
            result["suspicious_patterns"] = suspicious_patterns
            result["is_suspicious"] = len(suspicious_patterns) > 0

            # Set status based on risk score
            if result["risk_score"] >= 50:
                result["status"] = "High Risk"
            elif result["risk_score"] >= 30:
                result["status"] = "Medium Risk"
            elif result["risk_score"] >= 10:
                result["status"] = "Low Risk"
            else:
                result["status"] = "Clean"

        except Exception as e:
            result["error"] = f"Error in phishing check: {str(e)}"

        return result

    def _check_ssl_certificate(self, url):
        """
        Check SSL certificate information
        """
        result = {
            "has_ssl": False,
            "issued_to": None,
            "issued_by": None,
            "valid_from": None,
            "valid_until": None,
            "days_remaining": None,
            "is_expired": None,
            "certificate_version": None,
            "signature_algorithm": None,
            "status": "Unknown"
        }

        try:
            parsed_url = urlparse(url)

            # Only check SSL for HTTPS URLs
            if parsed_url.scheme != 'https':
                result["status"] = "No SSL"
                return result

            hostname = parsed_url.netloc

            # Remove port if present
            if ':' in hostname:
                hostname = hostname.split(':')[0]

            # Get SSL certificate with timeout
            context = ssl.create_default_context()
            conn = socket.create_connection((hostname, 443), timeout=10)

            try:
                sock = context.wrap_socket(conn, server_hostname=hostname)
                cert = sock.getpeercert()
            finally:
                conn.close()

            # Process certificate information
            result["has_ssl"] = True

            # Get subject (issued to)
            subject = dict(x[0] for x in cert['subject'])
            result["issued_to"] = {
                "common_name": subject.get('commonName'),
                "organization": subject.get('organizationName'),
                "organizational_unit": subject.get('organizationalUnitName')
            }

            # Get issuer
            issuer = dict(x[0] for x in cert['issuer'])
            result["issued_by"] = {
                "common_name": issuer.get('commonName'),
                "organization": issuer.get('organizationName')
            }

            # Get validity dates
            result["valid_from"] = cert['notBefore']
            result["valid_until"] = cert['notAfter']

            # Calculate days remaining
            expiry_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
            current_date = datetime.now()
            days_remaining = (expiry_date - current_date).days
            result["days_remaining"] = days_remaining
            result["is_expired"] = days_remaining < 0

            # Get certificate version and signature algorithm
            result["certificate_version"] = cert.get('version')
            result["signature_algorithm"] = cert.get('signatureAlgorithm')

            # Set status
            if result["is_expired"]:
                result["status"] = "Expired"
            elif days_remaining < 30:
                result["status"] = "Expiring Soon"
            else:
                result["status"] = "Valid"

        except socket.timeout:
            result["error"] = "Timeout while checking SSL certificate"
        except socket.gaierror:
            result["error"] = "DNS resolution failed"
        except ssl.SSLError as e:
            result["error"] = f"SSL error: {str(e)}"
        except Exception as e:
            result["error"] = f"Error checking SSL: {str(e)}"

        return result

    def _check_security_headers(self, url):
        """
        Check for important security headers
        """
        security_headers = {
            "Strict-Transport-Security": {
                "present": False,
                "value": None,
                "description": "Enforces secure (HTTPS) connections to the server"
            },
            "Content-Security-Policy": {
                "present": False,
                "value": None,
                "description": "Controls resources the user agent is allowed to load"
            },
            "X-Frame-Options": {
                "present": False,
                "value": None,
                "description": "Protects against clickjacking attacks"
            },
            "X-Content-Type-Options": {
                "present": False,
                "value": None,
                "description": "Prevents MIME-sniffing attacks"
            },
            "Referrer-Policy": {
                "present": False,
                "value": None,
                "description": "Controls how much referrer information should be included with requests"
            },
            "Permissions-Policy": {
                "present": False,
                "value": None,
                "description": "Controls which browser features and APIs can be used"
            },
            "X-XSS-Protection": {
                "present": False,
                "value": None,
                "description": "Filter for Cross-Site Scripting (XSS) attacks"
            }
        }

        result = {
            "headers_checked": security_headers,
            "headers_present": 0,
            "headers_missing": 0,
            "security_score": 0,
            "recommendations": []
        }

        try:
            # Request headers with proper error handling
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                response = requests.get(url, timeout=10, allow_redirects=True, verify=False)

            headers = response.headers

            # Check each security header
            for header, data in security_headers.items():
                if header in headers:
                    data["present"] = True
                    data["value"] = headers[header]
                    result["headers_present"] += 1
                else:
                    result["headers_missing"] += 1
                    result["recommendations"].append(f"Add {header} header for improved security")

            # Calculate security score
            total_headers = len(security_headers)
            result["security_score"] = int((result["headers_present"] / total_headers) * 100)

        except requests.exceptions.Timeout:
            result["error"] = "Timeout while fetching security headers"
        except requests.exceptions.RequestException as e:
            result["error"] = f"Error fetching security headers: {str(e)}"
        except Exception as e:
            result["error"] = f"Unexpected error checking headers: {str(e)}"

        return result

    def _get_domain_info(self, domain):
        """
        Get basic domain registration information
        """
        result = {
            "domain": domain,
            "registrar": None,
            "creation_date": None,
            "expiration_date": None,
            "last_updated": None,
            "name_servers": None,
            "age_days": None
        }

        try:
            # Skip IP addresses
            if re.match(r'\d+\.\d+\.\d+\.\d+', domain):
                return result

            # Remove port if present
            if ':' in domain:
                domain = domain.split(':')[0]

            try:
                w = whois.whois(domain)
            except Exception as e:
                result["error"] = f"WHOIS query failed: {str(e)}"
                return result

            # Process whois data
            result["registrar"] = w.registrar

            # Process creation date
            if w.creation_date:
                if isinstance(w.creation_date, list):
                    result["creation_date"] = str(w.creation_date[0])
                    created = w.creation_date[0]
                else:
                    result["creation_date"] = str(w.creation_date)
                    created = w.creation_date

                # Calculate domain age
                if isinstance(created, datetime):
                    result["age_days"] = (datetime.now() - created).days

            # Process expiration date
            if w.expiration_date:
                if isinstance(w.expiration_date, list):
                    result["expiration_date"] = str(w.expiration_date[0])
                else:
                    result["expiration_date"] = str(w.expiration_date)

            # Process last updated
            if w.updated_date:
                if isinstance(w.updated_date, list):
                    result["last_updated"] = str(w.updated_date[0])
                else:
                    result["last_updated"] = str(w.updated_date)

            # Process nameservers
            if w.name_servers:
                if isinstance(w.name_servers, list):
                    result["name_servers"] = w.name_servers
                else:
                    result["name_servers"] = [w.name_servers]

        except Exception as e:
            result["error"] = f"Error processing domain info: {str(e)}"

        return result

    def _calculate_risk_score(self):
        """
        Calculate overall risk score based on all scan results
        """
        score = 0
        max_score = 100

        # Weights for different check types
        weights = {
            "malware": 0.4,
            "phishing": 0.3,
            "ssl": 0.2,
            "headers": 0.1
        }

        # VirusTotal malware score (0-40)
        if "status" in self.scan_results["malware_detection"]:
            vt_status = self.scan_results["malware_detection"]["status"]
            if vt_status == "Malicious":
                malware_score = 40
            elif vt_status == "Suspicious":
                malware_score = 25
            elif vt_status == "Clean":
                malware_score = 0
            else:
                malware_score = 10  # Unknown status, moderate score

            score += malware_score * weights["malware"]

        # Phishing indicators score (0-30)
        if "risk_score" in self.scan_results["phishing_detection"]:
            phishing_risk = self.scan_results["phishing_detection"]["risk_score"]
            # Convert from 0-100 scale to 0-30
            phishing_score = min(phishing_risk / 100 * 30, 30)
            score += phishing_score * weights["phishing"]

        # SSL certificate score (0-20)
        if "status" in self.scan_results["ssl_info"]:
            ssl_status = self.scan_results["ssl_info"]["status"]
            if ssl_status == "No SSL":
                ssl_score = 20
            elif ssl_status == "Expired":
                ssl_score = 20
            elif ssl_status == "Expiring Soon":
                ssl_score = 10
            elif ssl_status == "Valid":
                ssl_score = 0
            else:
                ssl_score = 15  # Unknown status, moderate-high score

            score += ssl_score * weights["ssl"]

        # Security headers score (0-10)
        if "security_score" in self.scan_results["security_headers"]:
            header_security = self.scan_results["security_headers"]["security_score"]
            # Convert from 0-100 scale to 0-10 (inverted)
            header_score = (100 - header_security) / 100 * 10
            score += header_score * weights["headers"]

        # Set overall score
        self.scan_results["overall_score"] = int(score)

        # Set risk level
        if score >= 75:
            self.scan_results["risk_level"] = "Critical"
        elif score >= 50:
            self.scan_results["risk_level"] = "High"
        elif score >= 25:
            self.scan_results["risk_level"] = "Medium"
        elif score >= 10:
            self.scan_results["risk_level"] = "Low"
        else:
            self.scan_results["risk_level"] = "Safe"

        return self.scan_results["overall_score"]

    def generate_report(self, format="html"):
        """
        Generate a report based on scan results
        """
        if format == "html":
            # Generate HTML report (to be implemented)
            pass
        elif format == "json":
            return json.dumps(self.scan_results, indent=4)
        else:
            return self.scan_results


def scan_website(website_url, api_key, scan_options=None):
    """
    Function to be called from Flask route to scan a website
    """
    scanner = WebsiteScanner(api_key)
    results = scanner.scan_website(website_url, scan_options)
    return results