from flask import Flask, render_template, request
from logic.phishing_check_url import check_phishing_url

app = Flask(__name__)

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
    return render_template('login.html')

@app.route('/email')
def email():
    return render_template('/tools/email_checker.html')

@app.route('/virus')
def virus():
    return render_template('/tools/file_virus.html')

@app.route('/website')
def website():
    return render_template('/tools/website_scanner.html')

@app.route('/network')
def network():
    return render_template('/tools/network_traffic.html')

@app.route('/site')
def site():
    return render_template('/tools/site_down_check.html')

@app.route('/ip')
def ip():
    return render_template('/tools/ip_address.html')

@app.route('/password')
def password():
    return render_template('/tools/password.html')



# Google Safe Browsing API Key (Replace with your actual API key)
API_KEY = "d6ce35993adbeb65730cf2f38fcbe2ae2a6ea08024385504d037b65563f01050"


@app.route('/phishing')
def phishing():
    """Render the main page with the URL input form."""
    return render_template('tools/phishing.html')


@app.route('/check', methods=['POST'])
def check():
    """Handle form submission and check the URL using Google Safe Browsing API."""
    url = request.form.get('url')

    if not url:
        return render_template('result/result.html', result="Invalid Input", color="orange")

    # Call the phishing check function with API key
    result, is_safe = check_phishing_url(url, API_KEY)

    # Choose color based on result
    color = "green" if is_safe else "red"

    return render_template('result/result.html', result=result, color=color)


if __name__ == '__main__':
    app.run(debug=True)
