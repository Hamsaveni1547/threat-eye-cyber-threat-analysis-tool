from flask import Flask, render_template, request, jsonify
import datetime
import uuid
import os
import random

app = Flask(__name__)

# In a real application, you would use a database
# For this example, we'll use an in-memory list
scan_activities = [
    {
        "id": 1,
        "content": "https://google.com/search",
        "type": "url",
        "date": "21/02/2025",
        "status": "Clean",
        "timestamp": 1708516800  # Unix timestamp
    },
    {
        "id": 2,
        "content": "invoice.pdf",
        "type": "file",
        "date": "08/03/2025",
        "status": "Analyzing",
        "timestamp": 1709884800  # Unix timestamp
    }
]


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/activities', methods=['GET'])
def get_activities():
    # Sort by timestamp (newest first)
    sorted_activities = sorted(scan_activities, key=lambda x: x['timestamp'], reverse=True)
    return jsonify(sorted_activities)


@app.route('/api/scan', methods=['POST'])
def add_scan():
    # Get data from request
    content = request.form.get('content')
    scan_type = request.form.get('type')

    if not content or not scan_type:
        return jsonify({"error": "Missing required fields"}), 400

    # In a real application, you would actually perform the scan here
    # For this example, we'll simulate a scan with random results

    # Create a new scan entry
    today = datetime.datetime.now()
    new_scan = {
        "id": len(scan_activities) + 1,
        "content": content,
        "type": scan_type,
        "date": today.strftime("%d/%m/%Y"),
        "status": random.choice(["Clean", "Suspicious", "Malicious"]),
        "timestamp": int(today.timestamp())
    }

    # Add to activities list
    scan_activities.insert(0, new_scan)

    return jsonify(new_scan)


@app.route('/api/delete_scan', methods=['POST'])
def delete_scan():
    scan_id = request.form.get('id')

    if not scan_id:
        return jsonify({"error": "Missing scan ID"}), 400

    scan_id = int(scan_id)

    global scan_activities
    scan_activities = [item for item in scan_activities if item['id'] != scan_id]

    return jsonify({"success": True, "message": f"Scan {scan_id} deleted successfully"})


if __name__ == '__main__':
    # Create templates folder if it doesn't exist
    if not os.path.exists('templates'):
        os.makedirs('templates')

    # Write the HTML template to the templates folder
    with open('templates/index.html', 'w') as f:
        f.write("""
<!DOCTYPE html>
<html lang="en">
<!-- Your HTML code from the previous artifact goes here -->
</html>
        """)

    app.run(debug=True)