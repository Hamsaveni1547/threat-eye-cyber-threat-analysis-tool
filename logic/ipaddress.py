from flask import Flask, request, jsonify
import requests

app = Flask(__name__)

# API to check IP risk (Replace with a real threat intelligence API)
THREAT_INTELLIGENCE_API = "https://ipinfo.io/{}/json"

@app.route('/check_ip', methods=['POST'])
def check_ip():
    data = request.get_json()
    ip_address = data.get("ip")

    if not ip_address:
        return jsonify({"error": "No IP address provided"}), 400

    try:
        response = requests.get(THREAT_INTELLIGENCE_API.format(ip_address))
        if response.status_code == 200:
            ip_data = response.json()
            # Basic risk check: if IP belongs to a known VPN, Proxy, or has a bad reputation
            if "bogon" in ip_data or ip_data.get("privacy", {}).get("vpn") or ip_data.get("abuse"):
                return jsonify({"status": "risky"})
            else:
                return jsonify({"status": "safe"})
        else:
            return jsonify({"error": "Failed to fetch IP data"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
