from flask import Flask, render_template, request, send_file, jsonify
import requests
import os
import io
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle


# Add these imports at the top of the file
from werkzeug.utils import secure_filename
from datetime import datetime
from logic.phishing_check_url import detect_phishing
from logic.ip_logic import analyze_ip
from logic.website_logic import scan_website
from logic.file_logic import scan_file
from logic.email_logic import check_email
from logic.site_down_checker import check_site_status


app = Flask(__name__)

app.secret_key = "your_secret_key_here"  # Change this to a secure random key

# Configure max file size for uploads (16MB)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
app.config['UPLOAD_FOLDER'] = 'uploads'

# Create uploads directory if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)


#Navigation routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/tool')
def tools():
    return render_template('tools.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

@app.route('/get')
def login():
    return render_template('/user/login.html')

@app.route('/privacy')
def privacy():
    return render_template('privacy_policy.html')

@app.route('/terms')
def terms():
    return render_template('terms.html')

@app.route('/site')
def site():
    return render_template('/tools/site_down_check.html')

@app.route('/password')
def password():
    return render_template('/tools/password.html')


# Virus Total API KEy
API_KEY = "d6ce35993adbeb65730cf2f38fcbe2ae2a6ea08024385504d037b65563f01050"


#PHISHING
@app.route('/phishing')
def phishing():
    """Render the main page with the URL input form."""
    return render_template('tools/phishing.html')


@app.route('/check', methods=['POST'])
def check():
    """Handle form submission and check the URL for phishing."""
    url = request.form.get('url')

    if not url:
        return render_template('result/result.html', 
                             result={
                                 'error': True,
                                 'message': 'Please provide a URL to analyze',
                                 'classification': 'Error',
                                 'phishing_score': 0,
                                 'url': '',
                                 'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                             })

    try:
        phishing_data = detect_phishing(url, API_KEY)
        return render_template('result/result.html', result=phishing_data)
    except Exception as e:
        error_message = str(e) if str(e) else "An unexpected error occurred"
        return render_template('result/result.html', 
                             result={
                                 'error': True,
                                 'message': f"Error analyzing URL: {error_message}",
                                 'classification': 'Error',
                                 'phishing_score': 0,
                                 'url': url,
                                 'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                             })

@app.route('/download-report/phishing', methods=['POST'])
def download_phishing_report():
    """Generate and download a PDF report for phishing analysis."""
    try:
        data = request.get_json()
        url = data.get('url')
        result = data.get('result')

        # Create PDF buffer
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter)
        styles = getSampleStyleSheet()
        elements = []

        # Custom style for headers
        header_style = ParagraphStyle(
            'CustomHeader',
            parent=styles['Heading1'],
            fontSize=16,
            spaceAfter=30
        )

        # Add report header
        elements.append(Paragraph("Phishing Analysis Report", header_style))
        elements.append(Paragraph(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
        elements.append(Spacer(1, 20))

        # Add URL information
        elements.append(Paragraph(f"Analyzed URL: {url}", styles['Normal']))
        elements.append(Spacer(1, 20))

        # Add risk assessment
        elements.append(Paragraph("Risk Assessment", styles['Heading2']))
        elements.append(Paragraph(f"Classification: {result['classification']}", styles['Normal']))
        elements.append(Paragraph(f"Risk Score: {result['phishing_score']}%", styles['Normal']))
        elements.append(Spacer(1, 20))

        # Add detection statistics
        stats_data = [
            ['Detection Type', 'Count'],
            ['Malicious', str(result['malicious'])],
            ['Suspicious', str(result['suspicious'])],
            ['Harmless', str(result['harmless'])],
            ['Undetected', str(result['undetected'])],
            ['Total Scans', str(result['total_scans'])]
        ]
        stats_table = Table(stats_data, colWidths=[200, 100])
        stats_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 14),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('TEXTCOLOR', (0, 1), (-1, -1), colors.black),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('BOX', (0, 0), (-1, -1), 2, colors.black),
            ('LINEBELOW', (0, 0), (-1, 0), 2, colors.black),
        ]))
        elements.append(stats_table)
        elements.append(Spacer(1, 20))

        # Add suspicious patterns if any
        if result.get('url_analysis', {}).get('suspicious_patterns'):
            elements.append(Paragraph("Suspicious Patterns Detected", styles['Heading2']))
            for pattern in result['url_analysis']['suspicious_patterns']:
                elements.append(Paragraph(f"• {pattern}", styles['Normal']))
            elements.append(Spacer(1, 20))

        # Add recommendations
        if result.get('recommendations'):
            elements.append(Paragraph("Security Recommendations", styles['Heading2']))
            for rec in result['recommendations']:
                elements.append(Paragraph(f"• {rec}", styles['Normal']))

        # Generate PDF
        doc.build(elements)
        buffer.seek(0)
        
        return send_file(
            buffer,
            download_name=f'phishing-analysis-report-{datetime.now().strftime("%Y%m%d-%H%M%S")}.pdf',
            as_attachment=True,
            mimetype='application/pdf'
        )

    except Exception as e:
        return jsonify({'error': str(e)}), 500


# File Virus Checker Routes
@app.route('/virus')
def virus():
    return render_template('/tools/file_virus.html')



# Add these configurations at the top of your app.py after creating the Flask app
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
ALLOWED_EXTENSIONS = {'txt', 'pdf'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Create uploads directory if it doesn't exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


# Expand the allowed file types
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'rtf', 'zip', 'exe', 'dll'}

def allowed_file(filename):
    """
    Checks if the provided filename has an allowed extension.
    
    Args:
        filename: The filename to check
        
    Returns:
        Boolean indicating if the file type is allowed
    """
    if not filename:
        return False
        
    # Check if the filename contains a dot and the extension is in our allowed list
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/scan_file', methods=['POST'])
def process_file():
    """
    Process a file upload, scan it for viruses, and return the results.
    """
    # Check if a file was included in the request
    if 'file' not in request.files:
        error_result = {
            "status": "error",
            "message": "No file part in the request",
            "threat_level": "unknown",
            "filename": "No file",
            "positives": 0,
            "total": 0
        }
        return render_template('result/file_result.html', result=error_result, filename="No file")
    
    file = request.files['file']
    
    # Check if a filename was provided
    if file.filename == '':
        error_result = {
            "status": "error",
            "message": "No file selected",
            "threat_level": "unknown",
            "filename": "No file",
            "positives": 0,
            "total": 0
        }
        return render_template('result/file_result.html', result=error_result, filename="No file")

    # Create uploads directory if it doesn't exist
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    
    filename = secure_filename(file.filename)
    temp_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    
    try:
        # Check file type
        if not allowed_file(filename):
            error_result = {
                "status": "error",
                "message": "File type not allowed",
                "threat_level": "unknown",
                "filename": filename,
                "positives": 0,
                "total": 0
            }
            return render_template('result/file_result.html', result=error_result, filename=filename)
        
        # Save the file
        file.save(temp_path)
        
        # Check if file was saved successfully
        if not os.path.exists(temp_path) or os.path.getsize(temp_path) == 0:
            error_result = {
                "status": "error",
                "message": "Failed to save file or file is empty",
                "threat_level": "unknown",
                "filename": filename,
                "positives": 0,
                "total": 0
            }
            return render_template('result/file_result.html', result=error_result, filename=filename)
        
        # Scan the file
        scan_result = scan_file(temp_path, API_KEY)
        
        # Clean up temporary file
        if os.path.exists(temp_path):
            os.remove(temp_path)
            
        return render_template('result/file_result.html', result=scan_result, filename=filename)
        
    except Exception as e:
        # Clean up on error
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except:
                pass  # Ignore errors during cleanup
                
        error_result = {
            "status": "error",
            "message": f"Error processing file: {str(e)}",
            "threat_level": "unknown",
            "filename": filename,
            "positives": 0,
            "total": 0
        }
        return render_template('result/file_result.html', result=error_result, filename=filename)
    
    
# Email Checker Routes
@app.route('/email')
def email():
    return render_template('/tools/email_checker.html')


@app.route('/check_email', methods=['POST'])
def process_email():
    email = request.form.get('email')
    if not email:
        return jsonify({"error": "Email is required"}), 400

    result = check_email(email, API_KEY)
    return render_template('result/email_result.html', result=result, email=email)


#Site down check
@app.route('/check_site_status', methods=['POST'])
def check_site():
    url = request.form.get('url')
    if not url:
        return jsonify({"error": "URL is required"}), 400
    result = check_site_status(url)

    return render_template('result/site_down_result.html', result=result, url=url)


# Report Generation Routes
@app.route('/download-report/<tool_type>', methods=['POST'])
def download_report(tool_type):
    data = request.json

    if tool_type == 'ip':
        from logic.ip_logic import generate_report
        report_path = generate_report(data['ip_address'], data['result'], data['format'])
    elif tool_type == 'website':
        from logic.website_logic import generate_report
        report_path = generate_report(data['url'], data['result'], data['format'])
    elif tool_type == 'file':
        from logic.file_logic import generate_report
        report_path = generate_report(data['filename'], data['result'], data['format'])
    elif tool_type == 'email':
        from logic.email_logic import generate_report
        report_path = generate_report(data['email'], data['result'], data['format'])
    else:
        return jsonify({"error": "Invalid tool type"}), 400

    return send_file(report_path, as_attachment=True)


# Website Scanner Routes
@app.route('/website')
def website():
    return render_template('/tools/website_scanner.html')


@app.route('/scan_website', methods=['POST'])
def process_website():
    url = request.form.get('url')
    if not url:
        return jsonify({"error": "URL is required"}), 400

    result = scan_website(url, API_KEY)
    return render_template('result/website_result.html', result=result, url=url)


# IP Address Analyzer Routes
@app.route('/ip')
def ip():
    return render_template('/tools/ip_address.html')


@app.route('/analyze_ip', methods=['POST'])
def process_ip():
    ip_address = request.form.get('ip_address')
    if not ip_address:
        return jsonify({"error": "IP address is required"}), 400

    try:
        result = analyze_ip(ip_address, API_KEY)
        if "error" in result:
            # Still render the template but with error information
            return render_template('result/ip_result.html', result=result)
        return render_template('result/ip_result.html', result=result)
    except Exception as e:
        error_result = {
            "error": str(e),
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
            "security_score": 0,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        return render_template('result/ip_result.html', result=error_result)


if __name__ == '__main__':
    app.run(debug=True)