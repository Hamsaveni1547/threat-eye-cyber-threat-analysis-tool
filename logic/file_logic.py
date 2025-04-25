import requests
import json
import hashlib
import time
from datetime import datetime
import os.path
import pathlib


def scan_file(file_path, api_key):
    """
    Scans a file using VirusTotal API and returns the results.
    
    Args:
        file_path: Path to the file to scan
        api_key: VirusTotal API key
        
    Returns:
        Dictionary with scan results or error information
    """
    # Clean and normalize the file path
    try:
        file_path = str(pathlib.Path(file_path).resolve())
    except Exception:
        error_response['message'] = 'Invalid file path'
        return error_response

    # Set up default error response structure
    error_response = {
        'filename': os.path.basename(file_path) if file_path else 'Unknown',
        'status': 'error',
        'message': 'Unknown error',
        'threat_level': 'unknown',
        'positives': 0,
        'total': 0,
        'scans': {},
        'scan_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }
    
    try:
        # Validate file_path
        if not file_path:
            error_response['message'] = 'File path is empty'
            return error_response
        
        # Use pathlib to check if file exists and is readable
        file_path_obj = pathlib.Path(file_path)
        if not file_path_obj.is_file():
            error_response['message'] = f'File not found: {file_path}'
            return error_response
            
        # Check file size using pathlib
        file_size = file_path_obj.stat().st_size
        if file_size == 0:
            error_response['message'] = 'File is empty'
            return error_response
            
        # Validate API key
        if not api_key:
            error_response['message'] = 'API key is required'
            return error_response
        
        # First, upload the file to VirusTotal
        url = "https://www.virustotal.com/vtapi/v2/file/scan"
        
        # Using with statement for proper file handling
        with open(str(file_path_obj), 'rb') as file_obj:
            files = {'file': file_obj}
            params = {'apikey': api_key}
            
            response = requests.post(url, files=files, params=params)
            
            # Check if request was successful
            if response.status_code != 200:
                error_response['message'] = f'API request failed with status code: {response.status_code}'
                return error_response
            
            # Parse response as JSON
            try:
                upload_result = response.json()
            except json.JSONDecodeError:
                error_response['message'] = 'Failed to parse API response'
                return error_response
            
            # Check if response has the expected 'resource' field
            if 'resource' not in upload_result:
                error_response['message'] = 'Invalid API response: missing resource'
                return error_response
        
        # Get the scan results using the resource
        url = "https://www.virustotal.com/vtapi/v2/file/report"
        params = {
            'apikey': api_key,
            'resource': upload_result['resource']
        }
        
        response = requests.get(url, params=params)
        if response.status_code != 200:
            error_response['message'] = f'Failed to get scan results, status code: {response.status_code}'
            return error_response
        
        # Parse result as JSON
        try:
            result = response.json()
        except json.JSONDecodeError:
            error_response['message'] = 'Failed to parse scan results'
            return error_response
        
        # Process results - handle the case where response_code is not 1
        if result.get('response_code') != 1:
            # File not found in VirusTotal database
            return {
                'filename': os.path.basename(file_path),
                'scan_id': result.get('scan_id', ''),
                'resource': result.get('resource', ''),
                'response_code': result.get('response_code', 0),
                'scan_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'permalink': result.get('permalink', ''),
                'positives': 0,
                'total': 0,
                'scans': {},
                'status': 'pending',
                'threat_level': 'unknown',
                'message': 'File submitted for scanning. Results not available yet.'
            }
        
        # Calculate default threat level based on positives
        positives = result.get('positives', 0)
        total = result.get('total', 0)
        
        # Avoid division by zero when calculating threat percentage
        threat_percentage = 0
        if total > 0:
            threat_percentage = (positives / total) * 100
        
        # Determine threat level
        threat_level = 'clean'
        if threat_percentage > 0:
            if threat_percentage <= 5:
                threat_level = 'low'
            elif threat_percentage <= 20:
                threat_level = 'medium'
            else:
                threat_level = 'high'
        
        # Format the response in the expected structure
        scan_result = {
            'filename': os.path.basename(file_path),
            'scan_id': result.get('scan_id', ''),
            'resource': result.get('resource', ''),
            'response_code': result.get('response_code', 0),
            'scan_date': result.get('scan_date', datetime.now().strftime('%Y-%m-%d %H:%M:%S')),
            'permalink': result.get('permalink', ''),
            'positives': positives,
            'total': total,
            'threat_percentage': threat_percentage,
            'scans': result.get('scans', {}),
            'status': 'completed',
            'threat_level': threat_level,
            'message': 'File scan completed successfully'
        }
        
        return scan_result

    except FileNotFoundError:
        error_response['message'] = f'File not found: {file_path}'
        return error_response
    except PermissionError:
        error_response['message'] = f'Permission denied: {file_path}'
        return error_response
    except IsADirectoryError:
        error_response['message'] = f'Expected a file, got a directory: {file_path}'
        return error_response
    except Exception as e:
        error_response['message'] = str(e)
        return error_response
    

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