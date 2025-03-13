import re
import socket
import ipaddress


def analyze_ip(ip_address):
    """
    Analyzes an IP address and returns information about it.

    Args:
        ip_address (str): The IP address to analyze

    Returns:
        dict: Analysis results
    """
    # Initialize result dictionary
    result = {
        "ip_address": ip_address,
        "ip_type": "",
        "organization": "",
        "location": "",
        "location_details": "",
        "risk_level": "",
        "risk_percentage": 0,
        "threats": [],
        "recommendations": [],
        "ip_description": ""
    }

    # Validate IP address format
    try:
        ip_obj = ipaddress.ip_address(ip_address)

        # Check if it's a private IP
        if ip_obj.is_private:
            result["ip_type"] = "IPv{} Private Address".format(ip_obj.version)
            result["organization"] = "Private Network"
            result["location"] = "Local Network"
            result["location_details"] = "This IP address is part of a private network range."
            result["risk_level"] = "Low Risk"
            result["risk_percentage"] = 20
            result[
                "ip_description"] = f"This is a private IP address ({ip_address}) typically used in local networks and not accessible from the internet."

            # Add recommendations for private IP
            result["recommendations"] = [
                {
                    "icon": "shield-check",
                    "title": "Secure Your Network",
                    "description": "Ensure your private network is protected with a strong password and WPA2/WPA3 encryption if it's a wireless network."
                },
                {
                    "icon": "router",
                    "title": "Update Router Firmware",
                    "description": "Keep your router's firmware updated to protect against known vulnerabilities."
                },
                {
                    "icon": "lock",
                    "title": "Use Strong Credentials",
                    "description": "Make sure all network devices have strong, unique passwords and use two-factor authentication where possible."
                }
            ]

        # Public IP address
        else:
            result["ip_type"] = "IPv{} Public Address".format(ip_obj.version)

            # For demo purposes, we'll use conditionals to determine information
            # In a real app, you would query external APIs or databases

            # Extract organization based on IP patterns
            if ip_address.startswith('8.8'):
                result["organization"] = "Google LLC"
                result["location"] = "Mountain View, CA, United States"
                result["location_details"] = "This IP belongs to Google's public DNS service."
                result["risk_level"] = "Low Risk"
                result["risk_percentage"] = 15
                result["ip_description"] = "This is a public IP address belonging to Google's public DNS service."

            elif ip_address.startswith('1.1'):
                result["organization"] = "Cloudflare, Inc."
                result["location"] = "San Francisco, CA, United States"
                result["location_details"] = "This IP belongs to Cloudflare's DNS service."
                result["risk_level"] = "Low Risk"
                result["risk_percentage"] = 10
                result["ip_description"] = "This is a public IP address belonging to Cloudflare's public DNS service."

            else:
                # Generic public IP info
                result["organization"] = "Unknown Organization"
                result["location"] = "Unknown Location"
                result["location_details"] = "Location information not available for this IP address."
                result["risk_level"] = "Medium Risk"
                result["risk_percentage"] = 45
                result["ip_description"] = "This is a public IP address with limited information available."

                # Add a sample threat for demonstration
                result["threats"] = [
                    {
                        "icon": "exclamation-triangle",
                        "severity": "warning",
                        "title": "Suspicious Activity Detected",
                        "description": "This IP address has been flagged for suspicious activities in the past 30 days."
                    }
                ]

            # Add recommendations for public IP
            result["recommendations"] = [
                {
                    "icon": "shield-lock",
                    "title": "Monitor Network Traffic",
                    "description": "Keep an eye on traffic to and from this IP address to detect any unauthorized access attempts."
                },
                {
                    "icon": "gear",
                    "title": "Configure Firewall Rules",
                    "description": "Set up firewall rules to restrict communication with this IP if it's not a trusted service."
                }
            ]

    except ValueError:
        # Invalid IP address format
        result["ip_type"] = "Invalid IP Address"
        result["organization"] = "N/A"
        result["location"] = "N/A"
        result["location_details"] = "The provided string is not a valid IP address."
        result["risk_level"] = "Unknown Risk"
        result["risk_percentage"] = 50
        result["ip_description"] = f"The value '{ip_address}' is not a valid IP address format."

        result["recommendations"] = [
            {
                "icon": "question-circle",
                "title": "Check IP Format",
                "description": "Ensure you're entering a valid IP address in the format xxx.xxx.xxx.xxx for IPv4 or a valid IPv6 format."
            }
        ]

    return result