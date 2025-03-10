from flask import Flask, render_template, request
from logic.phishing_check_url import check_phishing_url

app = Flask(__name__)

# Google Safe Browsing API Key (Replace with your actual API key)
API_KEY = "d6ce35993adbeb65730cf2f38fcbe2ae2a6ea08024385504d037b65563f01050"


@app.route('/')
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
