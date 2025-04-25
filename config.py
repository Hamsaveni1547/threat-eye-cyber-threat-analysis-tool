import os
from dotenv import load_dotenv

load_dotenv()

# API Keys
VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY', 'your_default_key_here')
PHISHTANK_API_KEY = os.getenv('PHISHTANK_API_KEY', '')
ABUSEIPDB_API_KEY = os.getenv('ABUSEIPDB_API_KEY', '')
SHODAN_API_KEY = os.getenv('SHODAN_API_KEY', '')
MAXMIND_DB_PATH = os.getenv('MAXMIND_DB_PATH', 'GeoLite2-Country.mmdb')

# API Configuration
API_TIMEOUT = 10
MAX_RETRIES = 3

# Security Settings
ALLOWED_FILE_TYPES = {
    'txt', 'pdf', 'doc', 'docx', 'xls', 'xlsx',
    'png', 'jpg', 'jpeg', 'gif', 'zip', 'rar'
}
MAX_FILE_SIZE = 100 * 1024 * 1024  # 16MB

# Scanning Configuration
PHISHING_SCORE_THRESHOLD = {
    'high': 70,
    'medium': 40,
    'low': 20
}

# Cache Configuration
CACHE_TIMEOUT = 3600  # 1 hour
MAX_CACHE_ENTRIES = 1000