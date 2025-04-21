# # import os
# # import uuid
# # import json
# # from datetime import datetime
# # import requests
# # import pandas as pd
# # import matplotlib.pyplot as plt
# # import seaborn as sns
# #
# #
# # class FileAnalysisReport:
# #     def __init__(self, filepath):
# #         self.filepath = filepath
# #         self.report_id = str(uuid.uuid4())
# #         self.report_dir = 'reports'
# #         os.makedirs(self.report_dir, exist_ok=True)
# #
# #     def analyze_file(self):
# #         # VirusTotal API integration
# #         VIRUSTOTAL_API_KEY = 'YOUR_VIRUSTOTAL_API_KEY'
# #
# #         # Prepare multipart/form-data
# #         files = {'file': open(self.filepath, 'rb')}
# #         headers = {
# #             'apikey': VIRUSTOTAL_API_KEY
# #         }
# #
# #         try:
# #             # Send file to VirusTotal for scanning
# #             response = requests.post('https://www.virustotal.com/vtapi/v2/file/scan', files=files, headers=headers)
# #             scan_result = response.json()
# #
# #             # Get scan report
# #             params = {'apikey': VIRUSTOTAL_API_KEY, 'resource': scan_result['resource']}
# #             report_response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params)
# #             report = report_response.json()
# #
# #             # Prepare detailed analysis
# #             analysis_result = {
# #                 'report_id': self.report_id,
# #                 'file_name': os.path.basename(self.filepath),
# #                 'file_size': os.path.getsize(self.filepath),
# #                 'file_type': os.path.splitext(self.filepath)[1],
# #                 'scan_id': report.get('scan_id', 'N/A'),
# #                 'positives': report.get('positives', 0),
# #                 'total': report.get('total', 0),
# #                 'scan_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
# #                 'detailed_results': report.get('scans', {})
# #             }
# #
# #             # Generate visualization
# #             self._generate_threat_visualization(analysis_result)
# #
# #             # Generate detailed report
# #             self._generate_detailed_report(analysis_result)
# #
# #             return analysis_result
# #
# #         except Exception as e:
# #             return {
# #                 'error': str(e),
# #                 'message': 'Error during file analysis'
# #             }
# #
# #     def _generate_threat_visualization(self, analysis_result):
# #         # Create threat detection visualization
# #         plt.figure(figsize=(10, 6))
# #         sns.set_style("darkgrid")
# #
# #         # Prepare data for visualization
# #         vendors = list(analysis_result['detailed_results'].keys())
# #         detection_status = [result['detected'] for result in analysis_result['detailed_results'].values()]
# #
# #         plt.bar(vendors, detection_status)
# #         plt.title('Threat Detection by Antivirus Vendors')
# #         plt.xlabel('Antivirus Vendors')
# #         plt.ylabel('Threat Detected')
# #         plt.xticks(rotation=90)
# #         plt.tight_layout()
# #
# #         # Save the plot
# #         plot_path = os.path.join(self.report_dir, f'{self.report_id}_threat_plot.png')
# #         plt.savefig(plot_path)
# #         plt.close()
# #
# #     def _generate_detailed_report(self, analysis_result):
# #         # Create a comprehensive JSON report
# #         report_path = os.path.join(self.report_dir, f'{self.report_id}_report.json')
# #
# #         with open(report_path, 'w') as f:
# #             json.dump(analysis_result, f, indent=4)
# #
# #         # Create a readable PDF report (using pandas)
# #         df = pd.DataFrame.from_dict(analysis_result['detailed_results'], orient='index')
# #         df_path = os.path.join(self.report_dir, f'{self.report_id}_detailed_report.csv')
# #         df.to_csv(df_path)
# #
# #     @classmethod
# #     def get_report(cls, report_id):
# #         # Retrieve and read the report
# #         report_path = os.path.join('reports', f'{report_id}_report.json')
# #         plot_path = os.path.join('reports', f'{report_id}_threat_plot.png')
# #
# #         try:
# #             with open(report_path, 'r') as f:
# #                 report_data = json.load(f)
# #
# #             return {
# #                 'report_data': report_data,
# #                 'plot_path': plot_path
# #             }
# #         except Exception as e:
# #             return {'error': str(e)}
# #
# #
# # def analyze_file(filepath):
# #     analyzer = FileAnalysisReport(filepath)
# #     return analyzer.analyze_file()
#
# # logic/file_logic.py
# import requests
# import hashlib
# import time
# import os
# from flask import session
#
#
# def scan_file(file_path, api_key):
#     try:
#         # Calculate file hash (SHA-256)
#         file_hash = calculate_file_hash(file_path)
#
#         # First, check if the file hash has been analyzed before
#         headers = {
#             "x-apikey": api_key
#         }
#         check_url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
#         response = requests.get(check_url, headers=headers)
#
#         if response.status_code == 200:
#             # File has been scanned before, get results
#             results = response.json()
#             return process_scan_results(results, file_path)
#
#         elif response.status_code == 404:
#             # File hasn't been scanned before, upload and scan
#             upload_url = "https://www.virustotal.com/api/v3/files"
#
#             with open(file_path, 'rb') as file:
#                 files = {'file': (os.path.basename(file_path), file)}
#                 upload_response = requests.post(upload_url, headers=headers, files=files)
#
#             if upload_response.status_code == 200:
#                 upload_results = upload_response.json()
#                 analysis_id = upload_results.get('data', {}).get('id')
#
#                 # Wait for analysis to complete
#                 analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
#
#                 # Poll for results (with timeout)
#                 max_attempts = 10
#                 for attempt in range(max_attempts):
#                     time.sleep(3)  # Wait before checking
#                     analysis_response = requests.get(analysis_url, headers=headers)
#
#                     if analysis_response.status_code == 200:
#                         analysis_results = analysis_response.json()
#                         status = analysis_results.get('data', {}).get('attributes', {}).get('status')
#
#                         if status == 'completed':
#                             return process_scan_results(analysis_results, file_path)
#
#                 return {
#                     'filename': os.path.basename(file_path),
#                     'hash': file_hash,
#                     'status': 'Pending',
#                     'message': 'Analysis still in progress. Please check back later.'
#                 }
#             else:
#                 return {
#                     'filename': os.path.basename(file_path),
#                     'hash': file_hash,
#                     'status': 'Error',
#                     'message': f"Upload failed: {upload_response.status_code} - {upload_response.text}"
#                 }
#         else:
#             return {
#                 'filename': os.path.basename(file_path),
#                 'hash': file_hash,
#                 'status': 'Error',
#                 'message': f"Error: {response.status_code} - {response.text}"
#             }
#
#     except Exception as e:
#         return {
#             'filename': os.path.basename(file_path) if file_path else 'Unknown',
#             'status': 'Error',
#             'message': str(e)
#         }
#
#
# def calculate_file_hash(file_path):
#     sha256_hash = hashlib.sha256()
#     with open(file_path, "rb") as f:
#         for byte_block in iter(lambda: f.read(4096), b""):
#             sha256_hash.update(byte_block)
#     return sha256_hash.hexdigest()
#
#
# def process_scan_results(results, file_path):
#     try:
#         data = results.get('data', {})
#         attributes = data.get('attributes', {})
#
#         # For direct file lookup
#         if 'last_analysis_stats' in attributes:
#             stats = attributes.get('last_analysis_stats', {})
#             malicious = stats.get('malicious', 0)
#             suspicious = stats.get('suspicious', 0)
#             harmless = stats.get('harmless', 0)
#             undetected = stats.get('undetected', 0)
#         # For analysis results
#         else:
#             stats = attributes.get('stats', {})
#             malicious = stats.get('malicious', 0)
#             suspicious = stats.get('suspicious', 0)
#             harmless = stats.get('harmless', 0)
#             undetected = stats.get('undetected', 0)
#
#         total_checks = malicious + suspicious + harmless + undetected
#         if total_checks > 0:
#             detection_rate = round((malicious + suspicious) / total_checks * 100, 2)
#         else:
#             detection_rate = 0
#
#         filename = os.path.basename(file_path)
#         file_size = os.path.getsize(file_path)
#         file_hash = calculate_file_hash(file_path)
#
#         risk_level = "Low"
#         if detection_rate > 0 and detection_rate <= 5:
#             risk_level = "Low"
#         elif detection_rate > 5 and detection_rate <= 20:
#             risk_level = "Medium"
#         elif detection_rate > 20 and detection_rate <= 50:
#             risk_level = "High"
#         elif detection_rate > 50:
#             risk_level = "Critical"
#
#         return {
#             'filename': filename,
#             'file_size': file_size,
#             'hash': file_hash,
#             'detection_rate': detection_rate,
#             'detections': {
#                 'malicious': malicious,
#                 'suspicious': suspicious,
#                 'harmless': harmless,
#                 'undetected': undetected
#             },
#             'risk_level': risk_level,
#             'status': 'Completed'
#         }
#
#     except Exception as e:
#         return {
#             'filename': os.path.basename(file_path) if file_path else 'Unknown',
#             'status': 'Error',
#             'message': str(e)
#         }


# import requests
# import json
# import os
# import pandas as pd
# from datetime import datetime
# import hashlib
# from werkzeug.utils import secure_filename
#
# # VirusTotal API key - should be stored more securely in production
# API_KEY = "d6ce35993adbeb65730cf2f38fcbe2ae2a6ea08024385504d037b65563f01050"
# BASE_URL = "https://www.virustotal.com/api/v3/files"
#
#
# def scan_file(file):
#     """
#     Scan a file for viruses using VirusTotal API
#     """
#     headers = {
#         "x-apikey": API_KEY,
#         "Accept": "application/json"
#     }
#
#     # First, save the file temporarily
#     uploads_dir = "uploads"
#     os.makedirs(uploads_dir, exist_ok=True)
#
#     secure_name = secure_filename(file.filename)
#     file_path = os.path.join(uploads_dir, secure_name)
#     file.save(file_path)
#
#     try:
#         # Calculate file hash for lookup
#         with open(file_path, "rb") as f:
#             file_content = f.read()
#             file_hash = hashlib.sha256(file_content).hexdigest()
#
#         # First, try to get existing report for this hash
#         file_url = f"{BASE_URL}/files/{file_hash}"
#         response = requests.get(file_url, headers=headers)
#
#         # If file hasn't been analyzed yet, submit it for scanning
#         if response.status_code == 404:
#             # For files > 32MB, VirusTotal requires special upload URLs
#             # Here we'll assume smaller files for simplicity
#             files = {"file": (secure_name, open(file_path, "rb"))}
#
#             upload_url = f"{BASE_URL}/files"
#             scan_response = requests.post(upload_url, headers=headers, files=files)
#             scan_response.raise_for_status()
#
#             # Extract analysis ID
#             analysis_id = scan_response.json().get("data", {}).get("id")
#             analysis_url = f"{BASE_URL}/analyses/{analysis_id}"
#
#             # Check analysis status - in production, you'd want to implement
#             # polling or webhooks here
#             analysis_response = requests.get(analysis_url, headers=headers)
#             analysis_response.raise_for_status()
#             data = analysis_response.json()
#
#             # Flag as a fresh scan
#             fresh_scan = True
#         else:
#             response.raise_for_status()
#             data = response.json()
#             fresh_scan = False
#
#         # Process results
#         result = {
#             "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
#             "filename": secure_name,
#             "hash": file_hash,
#             "success": True,
#             "fresh_scan": fresh_scan,
#             "raw_data": data,
#             "summary": {}
#         }
#
#         # Extract key information
#         attributes = data.get("data", {}).get("attributes", {})
#
#         # File metadata
#         if "attributes" in data.get("data", {}):
#             result["summary"]["file_type"] = attributes.get("type_description", "Unknown")
#             result["summary"]["file_size"] = attributes.get("size", 0)
#             result["summary"]["md5"] = attributes.get("md5", "")
#             result["summary"]["sha1"] = attributes.get("sha1", "")
#             result["summary"]["sha256"] = attributes.get("sha256", file_hash)
#             result["summary"]["last_analysis_date"] = datetime.fromtimestamp(
#                 attributes.get("last_analysis_date", 0)
#             ).strftime("%Y-%m-%d %H:%M:%S")
#
#         # Analysis stats
#         result["summary"]["last_analysis_stats"] = attributes.get("last_analysis_stats", {})
#
#         # Calculate threat score
#         stats = attributes.get("last_analysis_stats", {})
#         total_scans = sum(stats.values()) if stats else 0
#         malicious = stats.get("malicious", 0)
#         suspicious = stats.get("suspicious", 0)
#
#         if total_scans > 0:
#             result["summary"]["threat_score"] = ((malicious + (suspicious * 0.5)) / total_scans) * 100
#         else:
#             result["summary"]["threat_score"] = 0
#
#         # Risk level based on threat score
#         if result["summary"]["threat_score"] >= 20:
#             result["summary"]["risk_level"] = "High"
#         elif result["summary"]["threat_score"] >= 5:
#             result["summary"]["risk_level"] = "Medium"
#         else:
#             result["summary"]["risk_level"] = "Low"
#
#         # Detection details
#         result["summary"]["scan_results"] = attributes.get("last_analysis_results", {})
#
#         # Get signatures
#         result["summary"]["signatures"] = attributes.get("signatures", [])
#
#         # Get popular threat labels
#         result["summary"]["popular_threat_classification"] = attributes.get("popular_threat_classification", {})
#
#         # Names of malware (if detected)
#         result["summary"]["detection_names"] = []
#         for engine, detection in attributes.get("last_analysis_results", {}).items():
#             if detection.get("category") == "malicious" and detection.get("result"):
#                 result["summary"]["detection_names"].append({
#                     "engine": engine,
#                     "name": detection.get("result")
#                 })
#
#         return result
#
#     except requests.exceptions.RequestException as e:
#         return {
#             "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
#             "filename": secure_name,
#             "hash": file_hash if 'file_hash' in locals() else "Unknown",
#             "success": False,
#             "error": str(e)
#         }
#     finally:
#         # Clean up temporary file
#         if os.path.exists(file_path):
#             os.remove(file_path)
#
#     def generate_report(filename, result, format):
#         """
#         Generate a downloadable report from the file scan results
#         """
#         reports_dir = "reports"
#         os.makedirs(reports_dir, exist_ok=True)
#
#         timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
#         safe_filename = secure_filename(filename)
#         if len(safe_filename) > 30:  # Limit filename length
#             safe_filename = safe_filename[:30]
#
#         report_filename = f"file_report_{safe_filename}_{timestamp}"
#
#         if format == "json":
#             filepath = os.path.join(reports_dir, f"{report_filename}.json")
#             with open(filepath, 'w') as f:
#                 json.dump(result, f, indent=4)
#
#         elif format == "csv":
#             filepath = os.path.join(reports_dir, f"{report_filename}.csv")
#
#             # Flatten the data for CSV format
#             flat_data = {
#                 "Filename": filename,
#                 "Timestamp": result["timestamp"],
#                 "File Hash (SHA-256)": result["summary"].get("sha256", ""),
#                 "File Type": result["summary"].get("file_type", "Unknown"),
#                 "File Size": result["summary"].get("file_size", 0),
#                 "Risk Level": result["summary"].get("risk_level", "Unknown"),
#                 "Threat Score": result["summary"].get("threat_score", 0),
#                 "Last Analysis Date": result["summary"].get("last_analysis_date", "Unknown"),
#                 "Malicious Detections": result["summary"].get("last_analysis_stats", {}).get("malicious", 0),
#                 "Suspicious Detections": result["summary"].get("last_analysis_stats", {}).get("suspicious", 0),
#                 "Clean Detections": result["summary"].get("last_analysis_stats", {}).get("harmless", 0)
#             }
#
#             # Add top detection names if available
#             detection_names = result["summary"].get("detection_names", [])
#             if detection_names:
#                 flat_data["Detection Names"] = "; ".join([d["name"] for d in detection_names[:5]])
#
#             pd.DataFrame([flat_data]).to_csv(filepath, index=False)
#
#         elif format == "pdf":
#             filepath = os.path.join(reports_dir, f"{report_filename}.pdf")
#
#             try:
#                 from reportlab.lib.pagesizes import letter
#                 from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
#                 from reportlab.lib.styles import getSampleStyleSheet
#                 from reportlab.lib import colors
#
#                 doc = SimpleDocTemplate(filepath, pagesize=letter)
#                 styles = getSampleStyleSheet()
#                 elements = []
#
#                 # Title
#                 title_style = styles["Heading1"]
#                 title = Paragraph(f"File Security Analysis Report", title_style)
#                 elements.append(title)
#                 elements.append(Spacer(1, 12))
#
#                 # File information
#                 summary_style = styles["Normal"]
#                 elements.append(Paragraph(f"Filename: {filename}", summary_style))
#                 elements.append(Paragraph(f"Date: {result['timestamp']}", summary_style))
#                 elements.append(
#                     Paragraph(f"Risk Level: {result['summary'].get('risk_level', 'Unknown')}", summary_style))
#                 elements.append(Spacer(1, 12))
#
#                 # Basic information
#                 elements.append(Paragraph("File Information", styles["Heading2"]))
#                 basic_info = [
#                     ["File Type", result["summary"].get("file_type", "Unknown")],
#                     ["File Size", f"{result['summary'].get('file_size', 0):,} bytes"],
#                     ["SHA-256", result["summary"].get("sha256", "")],
#                     ["MD5", result["summary"].get("md5", "")],
#                     ["Threat Score", f"{result['summary'].get('threat_score', 0):.2f}%"],
#                     ["Last Analysis Date", result["summary"].get("last_analysis_date", "Unknown")]
#                 ]
#
#                 t = Table(basic_info, colWidths=[150, 350])
#                 t.setStyle(TableStyle([
#                     ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
#                     ('TEXTCOLOR', (0, 0), (0, -1), colors.black),
#                     ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
#                     ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
#                     ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
#                     ('GRID', (0, 0), (-1, -1), 1, colors.black)
#                 ]))
#                 elements.append(t)
#                 elements.append(Spacer(1, 12))
#
#                 # Analysis results
#                 elements.append(Paragraph("Detection Summary", styles["Heading2"]))
#                 stats = result["summary"].get("last_analysis_stats", {})
#                 analysis_data = [
#                     ["Category", "Count"],
#                     ["Malicious", str(stats.get("malicious", 0))],
#                     ["Suspicious", str(stats.get("suspicious", 0))],
#                     ["Harmless", str(stats.get("harmless", 0))],
#                     ["Undetected", str(stats.get("undetected", 0))],
#                     ["Total", str(sum(stats.values()) if stats else 0)]
#                 ]
#
#                 t = Table(analysis_data, colWidths=[150, 350])
#                 t.setStyle(TableStyle([
#                     ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
#                     ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
#                     ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
#                     ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
#                     ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
#                     ('GRID', (0, 0), (-1, -1), 1, colors.black)
#                 ]))
#                 elements.append(t)
#                 elements.append(Spacer(1, 12))
#
#                 # Detection names
#                 detection_names = result["summary"].get("detection_names", [])
#                 if detection_names:
#                     elements.append(Paragraph("Malware Detections", styles["Heading2"]))
#                     detection_data = [["Antivirus Engine", "Detection Name"]]
#
#                     for detection in detection_names[:10]:  # Limit to top 10
#                         detection_data.append([detection["engine"], detection["name"]])
#
#                     t = Table(detection_data, colWidths=[150, 350])
#                     t.setStyle(TableStyle([
#                         ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
#                         ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
#                         ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
#                         ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
#                         ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
#                         ('GRID', (0, 0), (-1, -1), 1, colors.black)
#                     ]))
#                     elements.append(t)
#
#                 doc.build(elements)
#
#             except ImportError:
#                 # If ReportLab is not installed, fall back to JSON
#                 filepath = os.path.join(reports_dir, f"{report_filename}.json")
#                 with open(filepath, 'w') as f:
#                     json.dump(result, f, indent=4)
#         else:
#             # Default to JSON if format is not recognized
#             filepath = os.path.join(reports_dir, f"{report_filename}.json")
#             with open(filepath, 'w') as f:
#                 json.dump(result, f, indent=4)
#
#         return filepath


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