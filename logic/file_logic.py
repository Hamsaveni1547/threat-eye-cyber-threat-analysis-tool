import requests
import json
import hashlib
import time
from datetime import datetime
import os


def scan_file(file_path, api_key):
    try:
        # First, upload the file to VirusTotal
        url = "https://www.virustotal.com/vtapi/v2/file/scan"
        files = {'file': open(file_path, 'rb')}
        params = {'apikey': api_key}
        
        response = requests.post(url, files=files, params=params)
        upload_result = response.json()
        
        # Get the scan results using the resource
        url = "https://www.virustotal.com/vtapi/v2/file/report"
        params = {
            'apikey': api_key,
            'resource': upload_result['resource']
        }
        
        response = requests.get(url, params=params)
        result = response.json()
        
        # Format the response in the expected structure
        scan_result = {
            'filename': os.path.basename(file_path),
            'scan_id': result.get('scan_id', ''),
            'resource': result.get('resource', ''),
            'response_code': result.get('response_code', 0),
            'scan_date': result.get('scan_date', ''),
            'permalink': result.get('permalink', ''),
            'positives': result.get('positives', 0),
            'total': result.get('total', 0),
            'scans': result.get('scans', {}),
            'status': 'completed',
            'threat_level': 'clean' if result.get('positives', 0) == 0 else 'malicious',
            'message': 'File scan completed successfully'
        }
        
        return scan_result

    except Exception as e:
        # Return a properly structured error response
        return {
            'filename': os.path.basename(file_path),
            'status': 'error',
            'message': str(e),
            'threat_level': 'unknown',
            'positives': 0,
            'total': 0,
            'scans': {},
            'scan_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }


def calculate_file_hash(file_path):
    """Calculate MD5 hash of a file"""
    try:
        md5_hash = hashlib.md5()
        with open(file_path, "rb") as f:
            # Read the file in chunks
            for chunk in iter(lambda: f.read(4096), b""):
                md5_hash.update(chunk)
        return md5_hash.hexdigest()
    except:
        return None


def process_scan_results(hash_data, file_path):
    """Process scan results from a hash lookup"""
    # Extract file information
    attributes = hash_data.get("data", {}).get("attributes", {})

    result = {
        "filename": os.path.basename(file_path),
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "status": "completed",
        "md5": attributes.get("md5", ""),
        "sha1": attributes.get("sha1", ""),
        "sha256": attributes.get("sha256", ""),
        "size": attributes.get("size", 0),
        "type_description": attributes.get("type_description", "Unknown"),
        "last_analysis_stats": attributes.get("last_analysis_stats", {}),
        "last_analysis_results": attributes.get("last_analysis_results", {}),
        "first_submission_date": datetime.fromtimestamp(attributes.get("first_submission_date", 0)).strftime(
            "%Y-%m-%d") if attributes.get("first_submission_date") else "Unknown",
        "last_analysis_date": datetime.fromtimestamp(attributes.get("last_analysis_date", 0)).strftime(
            "%Y-%m-%d") if attributes.get("last_analysis_date") else "Unknown"
    }

    # Add file type tags
    result["tags"] = attributes.get("tags", [])

    # Calculate malware risk score
    stats = result["last_analysis_stats"]
    total_engines = sum(stats.values()) if stats else 0
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)

    if total_engines > 0:
        risk_percentage = ((malicious + suspicious) / total_engines) * 100
    else:
        risk_percentage = 0

    # Determine risk level
    if risk_percentage >= 10:
        risk_level = "high"
        status = "File may be malicious"
    elif risk_percentage >= 3:
        risk_level = "medium"
        status = "File is suspicious"
    else:
        risk_level = "low"
        status = "File appears safe"

    result["risk_percentage"] = risk_percentage
    result["risk_level"] = risk_level
    result["status_message"] = status

    # Extract detection types
    malware_types = {}
    for engine, data in result["last_analysis_results"].items():
        if data.get("category") in ["malicious", "suspicious"]:
            category = data.get("result", "Unknown")
            if category not in malware_types:
                malware_types[category] = []
            malware_types[category].append(engine)

    result["malware_types"] = malware_types

    # Extract additional file information if available
    if attributes.get("signature_info"):
        result["signature_info"] = attributes.get("signature_info", {})

    # Add MITRE ATT&CK information if available
    if attributes.get("popular_threat_classification"):
        result["threat_classification"] = attributes.get("popular_threat_classification", {})

    return result


def process_analysis_results(analysis_data, file_path):
    """Process results from analysis endpoint (fallback if hash lookup fails)"""
    # Extract basic file information
    attributes = analysis_data.get("data", {}).get("attributes", {})

    result = {
        "filename": os.path.basename(file_path),
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "status": "completed",
        "stats": attributes.get("stats", {}),
        "results": attributes.get("results", {})
    }

    # Calculate malware risk score
    stats = result["stats"]
    total_engines = sum(stats.values()) if stats else 0
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)

    if total_engines > 0:
        risk_percentage = ((malicious + suspicious) / total_engines) * 100
    else:
        risk_percentage = 0

    # Determine risk level
    if risk_percentage >= 10:
        risk_level = "high"
        status = "File may be malicious"
    elif risk_percentage >= 3:
        risk_level = "medium"
        status = "File is suspicious"
    else:
        risk_level = "low"
        status = "File appears safe"

    result["risk_percentage"] = risk_percentage
    result["risk_level"] = risk_level
    result["status_message"] = status

    # Extract detection types
    malware_types = {}
    for engine, data in result["results"].items():
        if data.get("category") in ["malicious", "suspicious"]:
            category = data.get("result", "Unknown")
            if category not in malware_types:
                malware_types[category] = []
            malware_types[category].append(engine)

    result["malware_types"] = malware_types

    return result


def generate_file_report(data, format_type="json"):
    """
    Generate a report in the specified format
    """
    if format_type == "json":
        return json.dumps(data, indent=4)
    elif format_type == "csv":
        # Create CSV for basic info
        headers = ["Filename", "File Type", "Size", "MD5", "SHA1", "SHA256", "Risk Level", "Risk Percentage", "Status",
                   "First Submission", "Last Analysis"]
        csv_data = ",".join(headers) + "\n"

        # Format file size
        size_kb = data.get("size", 0) / 1024
        if size_kb > 1024:
            size_str = f"{size_kb / 1024:.2f} MB"
        else:
            size_str = f"{size_kb:.2f} KB"

        row = [
            data["filename"],
            data.get("type_description", "Unknown"),
            size_str,
            data.get("md5", ""),
            data.get("sha1", ""),
            data.get("sha256", ""),
            data["risk_level"],
            f"{data['risk_percentage']:.2f}%",
            data["status_message"],
            data.get("first_submission_date", "Unknown"),
            data.get("last_analysis_date", "Unknown")
        ]

        csv_data += ",".join(row) + "\n"

        # Add detection stats
        stats = data.get("last_analysis_stats", {})
        csv_data += "\nDetection Stats\n"
        csv_data += f"Malicious,{stats.get('malicious', 0)}\n"
        csv_data += f"Suspicious,{stats.get('suspicious', 0)}\n"
        csv_data += f"Harmless,{stats.get('harmless', 0)}\n"
        csv_data += f"Undetected,{stats.get('undetected', 0)}\n"

        # Add malware types
        if data.get("malware_types"):
            csv_data += "\nMalware Type,Detection Engines\n"
            for malware_type, engines in data["malware_types"].items():
                row = [
                    malware_type,
                    "|".join(engines)
                ]
                csv_data += ",".join(row) + "\n"

        return csv_data
    elif format_type == "txt":
        # Plain text report
        lines = [
            f"FILE SECURITY ANALYSIS REPORT",
            f"============================",
            f"Generated on: {data['timestamp']}",
            f"",
            f"BASIC FILE INFORMATION",
            f"=====================",
            f"Filename: {data['filename']}",
            f"File Type: {data.get('type_description', 'Unknown')}"
        ]

        # Format file size
        if data.get("size"):
            size_kb = data["size"] / 1024
            if size_kb > 1024:
                size_str = f"{size_kb / 1024:.2f} MB"
            else:
                size_str = f"{size_kb:.2f} KB"
            lines.append(f"File Size: {size_str}")

        # Add hashes
        lines.extend([
            f"MD5: {data.get('md5', 'Unknown')}",
            f"SHA1: {data.get('sha1', 'Unknown')}",
            f"SHA256: {data.get('sha256', 'Unknown')}",
            f"First Submission: {data.get('first_submission_date', 'Unknown')}",
            f"Last Analysis: {data.get('last_analysis_date', 'Unknown')}",
            f"",
            f"SECURITY ASSESSMENT",
            f"==================",
            f"Risk Level: {data['risk_level'].upper()}",
            f"Risk Percentage: {data['risk_percentage']:.2f}%",
            f"Status: {data['status_message']}",
            f""
        ])

        # Add tags if available
        if data.get("tags"):
            lines.append("File Tags: " + ", ".join(data["tags"]))
            lines.append("")

        # Add detection stats
        stats = data.get("last_analysis_stats", {})
        lines.append("DETECTION STATS")
        lines.append("==============")
        lines.append(f"Malicious: {stats.get('malicious', 0)}")
        lines.append(f"Suspicious: {stats.get('suspicious', 0)}")
        lines.append(f"Harmless: {stats.get('harmless', 0)}")
        lines.append(f"Undetected: {stats.get('undetected', 0)}")
        lines.append("")

        # Add malware types
        if data.get("malware_types"):
            lines.append("MALWARE TYPES DETECTED")
            lines.append("=====================")
            for malware_type, engines in data["malware_types"].items():
                lines.append(f"Type: {malware_type}")
                lines.append(f"Detected by: {', '.join(engines)}")
                lines.append("")

        # Add signature info if available
        if data.get("signature_info"):
            lines.append("SIGNATURE INFORMATION")
            lines.append("====================")
            for key, value in data["signature_info"].items():
                lines.append(f"{key}: {value}")
            lines.append("")

        # Add threat classification if available
        if data.get("threat_classification"):
            threat_data = data["threat_classification"]
            if threat_data.get("suggested_threat_label"):
                lines.append("THREAT CLASSIFICATION")
                lines.append("====================")
                lines.append(f"Suggested Threat: {threat_data.get('suggested_threat_label')}")

                if threat_data.get("popular_threat_category"):
                    lines.append("Categories:")
                    for category in threat_data.get("popular_threat_category", []):
                        if isinstance(category, dict):
                            lines.append(f"- {category.get('value')} (Count: {category.get('count')})")

                if threat_data.get("popular_threat_name"):
                    lines.append("Names:")
                    for name in threat_data.get("popular_threat_name", []):
                        if isinstance(name, dict):
                            lines.append(f"- {name.get('value')} (Count: {name.get('count')})")

        return "\n".join(lines)
    else:
        return json.dumps(data, indent=4)  # Default to JSON