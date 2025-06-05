"""
ThreatEye - Advanced Cyber Threat Analysis Tool
Flask Application - Main Entry Point
"""

# ==============================================================================
# IMPORTS
# ==============================================================================

# Standard Library Imports
import os
import io
import sqlite3
from datetime import datetime
from functools import wraps

# Third-Party Imports
from flask import (
    Flask, render_template, request, send_file, jsonify, 
    redirect, flash, session, url_for, g, make_response
)
import requests
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# ReportLab Imports for PDF Generation
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

# Local Module Imports
from utils import check_tool_limit, get_tool_usage
from logic.phishing_check_url import detect_phishing
from logic.ip_logic import analyze_ip
from logic.website_logic import scan_website
from logic.file_logic import scan_file
from logic.email_logic import check_email
from logic.site_down_checker import check_site_status

# ==============================================================================
# APPLICATION CONFIGURATION
# ==============================================================================

app = Flask(__name__)
app.secret_key = "your_secret_key_here"  # Change this to a secure random key

# File Upload Configuration
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.config['UPLOAD_FOLDER'] = 'uploads'
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'docx', 'xlsx'}

# API Configuration
API_KEY = "d6ce35993adbeb65730cf2f38fcbe2ae2a6ea08024385504d037b65563f01050"

# Database Configuration
DATABASE = 'threateye_db.db'

# Create necessary directories
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ==============================================================================
# DATABASE FUNCTIONS
# ==============================================================================

def get_db_connection():
    """Get database connection with row factory for dictionary-like access."""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initialize the database with schema."""
    with app.app_context():
        db = get_db_connection()
        with open('schema.sql', 'r') as f:
            db.executescript(f.read())
        db.commit()
        db.close()

def init_contact_db():
    """Initialize contact submissions database."""
    contact_db = 'contact_submissions.db'
    if not os.path.exists(contact_db):
        with open('schema.sql', 'w') as f:
            f.write('''
            DROP TABLE IF EXISTS contact_submissions;
            CREATE TABLE contact_submissions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL,
                company TEXT,
                subject TEXT,
                message TEXT NOT NULL,
                secure_contact BOOLEAN,
                submission_date TIMESTAMP NOT NULL
            );
            ''')
        init_db()

# Initialize contact database
init_contact_db()

# ==============================================================================
# UTILITY FUNCTIONS
# ==============================================================================

def allowed_file(filename):
    """
    Check if the provided filename has an allowed extension.
    
    Args:
        filename: The filename to check
        
    Returns:
        Boolean indicating if the file type is allowed
    """
    if not filename:
        return False
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def login_required(f):
    """Decorator to require user login for protected routes."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login first', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# ==============================================================================
# MAIN NAVIGATION ROUTES
# ==============================================================================

@app.route('/')
def index():
    """Home page route."""
    return render_template('index.html')

@app.route('/about')
def about():
    """About page route."""
    return render_template('about.html')

@app.route('/tool')
def tools():
    """Tools page route."""
    return render_template('tools.html')

@app.route('/contact')
def contact():
    """Contact page route."""
    return render_template('contact.html', session=session)

@app.route('/get')
def login():
    """Login page route."""
    return render_template('/user/login.html')

@app.route('/privacy')
def privacy():
    """Privacy policy page route."""
    return render_template('privacy_policy.html')

@app.route('/terms')
def terms():
    """Terms of service page route."""
    return render_template('terms.html')

@app.route('/help')
def help():
    """Help and support page route."""
    return render_template('user/help_support.html')

# ==============================================================================
# CONTACT FORM ROUTES
# ==============================================================================

@app.route('/contact', methods=['GET'])
def contact_page():
    """Contact form page route."""
    return render_template('contact.html')

# Replace the existing contact form submission route in app.py

@app.route('/api/submit-contact', methods=['POST'])
def submit_contact():
    """Handle contact form submission without login requirement."""
    try:
        # Get form data
        name = request.form.get('name')
        email = request.form.get('email')
        company = request.form.get('company', '')
        subject = request.form.get('subject', '')
        message = request.form.get('message')
        secure_contact = request.form.get('secure-contact') == 'on'
        
        # Validate required fields
        if not name or not email or not message:
            return jsonify({'success': False, 'message': 'Please fill in all required fields'}), 400
        
        # Basic email validation
        import re
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, email):
            return jsonify({'success': False, 'message': 'Please enter a valid email address'}), 400
        
        # Insert into database
        conn = sqlite3.connect('contact_submissions.db')
        conn.execute(
            'INSERT INTO contact_submissions (name, email, company, subject, message, secure_contact, submission_date) VALUES (?, ?, ?, ?, ?, ?, ?)',
            (name, email, company, subject, message, secure_contact, datetime.now())
        )
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'message': 'Your message has been sent successfully! We will get back to you soon.'})
        
    except Exception as e:
        return jsonify({'success': False, 'message': f'An error occurred: {str(e)}'}), 500
    

@app.route('/admin/submissions', methods=['GET'])
def view_submissions():
    """Admin route to view contact submissions."""
    # In a real application, you would add authentication here
    conn = sqlite3.connect('contact_submissions.db')
    conn.row_factory = sqlite3.Row
    submissions = conn.execute('SELECT * FROM contact_submissions ORDER BY submission_date DESC').fetchall()
    conn.close()
    return render_template('admin/submissions.html', submissions=submissions)


# ==============================================================================
# USER AUTHENTICATION ROUTES
# ==============================================================================

@app.route('/add', methods=['POST'])
def add_user():
    """Handle user registration."""
    try:
        fname = request.form['fname']
        lname = request.form['lname']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm-password']

        # Validate password match
        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return redirect(url_for('login'))

        # Check if user already exists
        conn = get_db_connection()
        existing_user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        
        if existing_user:
            flash('Email already registered', 'error')
            return redirect(url_for('login'))

        # Hash the password and add new user
        hashed_password = generate_password_hash(password)
        conn.execute("INSERT INTO users (fname, lname, email, password) VALUES (?, ?, ?, ?)",
                    (fname, lname, email, hashed_password))
        conn.commit()
        conn.close()

        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login', registration='success'))

    except Exception as e:
        flash('An error occurred during registration', 'error')
        return redirect(url_for('login'))

@app.route('/signin', methods=['POST'])
def signin():
    """Handle user sign in."""
    try:
        email = request.form['email']
        password = request.form['password']
        next_url = request.form.get('next', '/dashboard')

        conn = get_db_connection()
        user = conn.execute("SELECT id, fname, lname, email, password FROM users WHERE email = ?",
                          (email,)).fetchone()
        conn.close()

        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['user_email'] = user['email']
            session['user_name'] = f"{user['fname']} {user['lname']}"
            flash('Login successful!', 'success')
            return redirect(next_url)
        else:
            flash('Invalid email or password', 'error')
            return redirect(url_for('login', next=next_url))

    except Exception as e:
        flash(f'An error occurred during login: {str(e)}', 'error')
        return redirect(url_for('login'))

@app.route('/logout')
def logout():
    """Handle user logout."""
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

# ==============================================================================
# USER DASHBOARD ROUTES
# ==============================================================================

@app.route('/dashboard')
@login_required
def dashboard():
    """User dashboard route."""
    if 'user_email' not in session:
        flash('Please login first', 'error')
        return redirect(url_for('login'))
    return render_template('user/dashboard.html', user={'username': session.get('user_name', 'User')})

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    """User settings route."""
    user_id = session['user_id']
    conn = get_db_connection()

    if request.method == 'POST':
        fname = request.form['fname']
        lname = request.form['lname']
        email = request.form['email']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        # Check if password fields are filled
        if new_password or confirm_password:
            if new_password != confirm_password:
                flash('New password and confirm password do not match.', 'danger')
                conn.close()
                return redirect(url_for('settings'))

            # Update password along with other fields
            conn.execute(
                "UPDATE users SET fname = ?, lname = ?, email = ?, password = ? WHERE id = ?",
                (fname, lname, email, new_password, user_id)
            )
        else:
            # Update without changing password
            conn.execute(
                "UPDATE users SET fname = ?, lname = ?, email = ? WHERE id = ?",
                (fname, lname, email, user_id)
            )

        conn.commit()
        conn.close()

        session['user_email'] = email
        session['user_name'] = f"{fname} {lname}"

        flash('Profile updated successfully!', 'success')
        return redirect(url_for('settings'))

    else:
        user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        conn.close()
        return render_template('user/settings.html', user=user)

@app.route('/activities')
@login_required
def activities():
    """User activities route."""
    user_id = session.get('user_id')
    if not user_id:
        flash('Unauthorized access. Please login.', 'error')
        return redirect(url_for('login'))

    conn = get_db_connection()
    activities = conn.execute(
        "SELECT id, input_data, tool_name, usage_date FROM tool_usage WHERE user_id = ? ORDER BY usage_date DESC", 
        (user_id,)
    ).fetchall()
    conn.close()

    return render_template('user/activities.html', activities=activities)


# ==============================================================================
# TOOLS ROUTES  
# ==============================================================================

#===============================================================================
#PHISHING
#===============================================================================
@app.route('/phishing')
@login_required
def phishing():
    """Render the main page with the URL input form."""
    return render_template('/tools/phishing.html')

# Add tool usage endpoint
@app.route('/tool/usage')
@login_required
def tool_usage():
    usage = get_tool_usage(session['user_id'])
    return jsonify({'usage': usage})

# Update phishing check route
@app.route('/check', methods=['POST'])
@login_required
def check():
    """Handle form submission and check the URL for phishing."""
    url = request.form.get('url')
    robot_check = request.form.get('robot')

    if not url:
        return jsonify({'error': 'Please provide a URL to analyze'}), 400

    if not robot_check:
        return jsonify({'error': 'Please confirm you are not a robot'}), 400

    try:
        # Check usage limit
        can_use, message = check_tool_limit(session['user_id'], 'phishing_check', url)
        if not can_use:
            return jsonify({'error': message}), 429

        # Get phishing analysis results
        phishing_data = detect_phishing(url, API_KEY)
        
        # Render the template and create response
        html = render_template('result/result.html', result=phishing_data)
        response = make_response(html)
        response.headers['Content-Type'] = 'text/html'
        return response
        
    except Exception as e:
        error_msg = f"Error analyzing URL: {str(e)}"
        return jsonify({'error': error_msg}), 500

@app.route('/download-report/phishing', methods=['POST'])
@login_required
def download_phishing_report():
    """Generate and download a PDF report for phishing analysis."""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400

        url = data.get('url')
        result = data.get('result')

        if not url or not result:
            return jsonify({'error': 'Invalid data format'}), 400

        # Create PDF buffer
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter)
        styles = getSampleStyleSheet()
        elements = []

        # Custom style for headers
        header_style = ParagraphStyle(
            'CustomHeader',
            parent=styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            textColor=colors.HexColor('#00bcd4')
        )

        # Add report header
        elements.append(Paragraph("ThreatEye Phishing Analysis Report", header_style))
        elements.append(Paragraph(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
        elements.append(Spacer(1, 20))

        # Add URL information
        elements.append(Paragraph("Target Information", styles['Heading2']))
        elements.append(Paragraph(f"Analyzed URL: {url}", styles['Normal']))
        elements.append(Spacer(1, 20))

        # Add risk assessment
        elements.append(Paragraph("Risk Assessment", styles['Heading2']))
        elements.append(Paragraph(f"Classification: {result['classification']}", styles['Normal']))
        elements.append(Paragraph(f"Risk Score: {result['phishing_score']}%", styles['Normal']))
        elements.append(Spacer(1, 20))

        # Add detection statistics in a table
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
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#00bcd4')),
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
        if result['url_analysis'].get('suspicious_patterns'):
            elements.append(Paragraph("Suspicious Patterns Detected", styles['Heading2']))
            for pattern in result['url_analysis']['suspicious_patterns']:
                elements.append(Paragraph(f"• {pattern}", styles['Normal']))
            elements.append(Spacer(1, 20))

        # Add recommendations
        if result.get('recommendations'):
            elements.append(Paragraph("Security Recommendations", styles['Heading2']))
            for rec in result['recommendations']:
                elements.append(Paragraph(f"• {rec}", styles['Normal']))
            elements.append(Spacer(1, 20))

        # Add footer
        elements.append(Spacer(1, 30))
        footer_text = "This report was generated by ThreatEye - Advanced Cyber Threat Analysis Tool"
        elements.append(Paragraph(footer_text, ParagraphStyle(
            'Footer',
            parent=styles['Normal'],
            textColor=colors.gray,
            fontSize=8,
            alignment=1
        )))

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


#===============================================================================
# File Scanner Routes
#===============================================================================
@app.route('/virus')
@login_required
def virus():
    return render_template('/tools/file_virus.html')

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
@login_required
def process_file():
    """
    Process a file upload, scan it for viruses, and return the results.
    """
    # Check if a file was included in the request
    if 'file' not in request.files:
        return render_template('result/file_result.html', 
                             result={"status": "error", "message": "No file part"})

    can_use, message = check_tool_limit(session['user_id'], 'file_scan', '')
    if not can_use:
        return render_template('result/file_result.html', 
                             result={"status": "error", "message": message})

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
    
    
#===============================================================================
# Email Checker Routes
#===============================================================================
@app.route('/email')
@login_required
def email():
    return render_template('/tools/email_checker.html')


@app.route('/check_email', methods=['POST'])
@login_required
def process_email():
    email = request.form.get('email')
    if not email:
        return jsonify({"error": "Email is required"}), 400

    can_use, message = check_tool_limit(session['user_id'], 'email_check', email)
    if not can_use:
        return jsonify({"error": message}), 429

    result = check_email(email, API_KEY)
    return render_template('result/email_result.html', result=result, email=email)


# ==============================================================================
# Website Scanner Routes
# ==============================================================================
@app.route('/website')
@login_required
def website():
    return render_template('/tools/website_scanner.html')


@app.route('/scan_website', methods=['POST'])
@login_required
def process_website():
    url = request.form.get('url')
    if not url:
        return jsonify({"error": "URL is required"}), 400

    can_use, message = check_tool_limit(session['user_id'], 'website_scan', url)
    if not can_use:
        return jsonify({"error": message}), 429

    try:
        result = scan_website(url, API_KEY)
        if "error" in result:
            return jsonify({"error": result["error"]}), 400
        return render_template('result/website_result.html', result=result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ==============================================================================
# IP Address Analyzer Routes
# ==============================================================================
@app.route('/ip')
@login_required
def ip():
    return render_template('/tools/ip_address.html')


@app.route('/analyze_ip', methods=['POST'])
@login_required
def process_ip():
    ip_address = request.form.get('ip_address')
    if not ip_address:
        return jsonify({"error": "IP address is required"}), 400

    can_use, message = check_tool_limit(session['user_id'], 'ip_analysis', ip_address)
    if not can_use:
        return jsonify({"error": message}), 429

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


#===============================================================================
#Site down check
#===============================================================================
@app.route('/site')
@login_required
def site():
    return render_template('/tools/site_down_check.html')

@app.route('/check_site_status', methods=['POST'])
@login_required
def check_site():
    url = request.form.get('url')
    if not url:
        return jsonify({"error": "URL is required"}), 400

    can_use, message = check_tool_limit(session['user_id'], 'site_check', url)
    if not can_use:
        return jsonify({"error": message}), 429

    result = check_site_status(url)

    return render_template('result/site_down_result.html', result=result, url=url)


if __name__ == '__main__':
    app.run(debug=True)