# logic/site_down_checker.py
import requests
import socket
import time
import whois
from datetime import datetime


def check_site_status(url):
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    result = {
        'url': url,
        'is_up': False,
        'response_time': None,
        'status_code': None,
        'dns_resolution': None,
        'whois_info': None,
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'error': None
    }

    try:
        # Extract domain from URL
        domain = url.split('//')[1].split('/')[0]

        # Check DNS resolution
        try:
            ip_address = socket.gethostbyname(domain)
            result['dns_resolution'] = {
                'resolved': True,
                'ip_address': ip_address
            }
        except socket.gaierror:
            result['dns_resolution'] = {
                'resolved': False,
                'ip_address': None
            }
            result['error'] = 'DNS resolution failed'
            return result

        # Try to get WHOIS information
        try:
            whois_info = whois.whois(domain)
            result['whois_info'] = {
                'registrar': whois_info.registrar,
                'creation_date': whois_info.creation_date[0].strftime('%Y-%m-%d') if isinstance(
                    whois_info.creation_date, list) else whois_info.creation_date.strftime(
                    '%Y-%m-%d') if whois_info.creation_date else None,
                'expiration_date': whois_info.expiration_date[0].strftime('%Y-%m-%d') if isinstance(
                    whois_info.expiration_date, list) else whois_info.expiration_date.strftime(
                    '%Y-%m-%d') if whois_info.expiration_date else None
            }
        except Exception as e:
            result['whois_info'] = None

        # Check website status
        start_time = time.time()
        response = requests.get(url, timeout=10)
        end_time = time.time()

        result['is_up'] = True
        result['response_time'] = round((end_time - start_time) * 1000, 2)  # in ms
        result['status_code'] = response.status_code

        # Analyze response time
        if result['response_time'] < 500:
            result['performance'] = 'Excellent'
        elif result['response_time'] < 1000:
            result['performance'] = 'Good'
        elif result['response_time'] < 2000:
            result['performance'] = 'Fair'
        else:
            result['performance'] = 'Poor'

        # Analyze status code
        if 200 <= response.status_code < 300:
            result['status_category'] = 'Success'
        elif 300 <= response.status_code < 400:
            result['status_category'] = 'Redirection'
        elif 400 <= response.status_code < 500:
            result['status_category'] = 'Client Error'
        elif 500 <= response.status_code < 600:
            result['status_category'] = 'Server Error'
        else:
            result['status_category'] = 'Unknown'

    except requests.exceptions.ConnectionError:
        result['error'] = 'Connection error'
    except requests.exceptions.Timeout:
        result['error'] = 'Request timed out'
    except requests.exceptions.RequestException as e:
        result['error'] = f'Request error: {str(e)}'
    except Exception as e:
        result['error'] = f'Error: {str(e)}'

    return result
