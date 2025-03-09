import requests


def check_phishing_url(url, api_key):
    """
    Check if the given URL is safe using VirusTotal API.
    :param url: URL to check
    :param api_key: VirusTotal API Key
    :return: (result message, is_safe)
    """
    api_url = "https://www.virustotal.com/api/v3/urls"
    headers = {
        "x-apikey": api_key
    }

    try:
        # Submit the URL for analysis
        response = requests.post(api_url, headers=headers, data={"url": url})
        response_data = response.json()

        # Extract analysis ID
        if "data" in response_data and "id" in response_data["data"]:
            analysis_id = response_data["data"]["id"]

            # Get analysis results
            analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
            analysis_response = requests.get(analysis_url, headers=headers)
            analysis_data = analysis_response.json()

            # ✅ Print API response for debugging
            print("API Response:", analysis_data)

            # Check for malicious verdicts
            stats = analysis_data.get("data", {}).get("attributes", {}).get("stats", {})
            malicious_count = stats.get("malicious", 0)

            if malicious_count > 0:
                return "Phishing or Malware Detected ❌", False
            else:
                return "URL is Safe ✅", True
        else:
            return "Error: Unable to analyze URL", False

    except Exception as e:
        return f"Error: {str(e)}", False