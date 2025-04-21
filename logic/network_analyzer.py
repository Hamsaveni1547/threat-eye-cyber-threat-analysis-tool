import os
import json
import re
import subprocess
import tempfile
from datetime import datetime
import ipaddress
import socket
import platform


def analyze_network(pcap_file):
    """
    Analyze network traffic from a PCAP file

    Args:
        pcap_file (str): Path to PCAP file

    Returns:
        dict: Analysis results
    """
    result = {
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'file': os.path.basename(pcap_file),
        'summary': {},
        'ip_stats': {},
        'protocols': {},
        'suspicious_traffic': [],
        'top_talkers': [],
        'geo_data': {},
        'port_usage': {},
        'recommendations': []
    }

    # Check if tshark (Wireshark CLI) is available
    if check_tshark_available():
        # Use tshark for analysis
        result.update(analyze_with_tshark(pcap_file))
    else:
        # Fallback to basic analysis
        result.update(basic_pcap_analysis(pcap_file))

    # Generate recommendations based on analysis
    result['recommendations'] = generate_recommendations(result)

    return result


def check_tshark_available():
    """Check if tshark is available on the system"""
    try:
        if platform.system() == "Windows":
            subprocess.run(['where', 'tshark'], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        else:
            subprocess.run(['which', 'tshark'], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return True
    except (subprocess.SubprocessError, FileNotFoundError):
        return False


def analyze_with_tshark(pcap_file):
    """Analyze PCAP file using tshark"""
    result = {
        'summary': {},
        'ip_stats': {},
        'protocols': {},
        'suspicious_traffic': [],
        'top_talkers': [],
        'port_usage': {}
    }

    # Get packet count
    cmd = ['tshark', '-r', pcap_file, '-q', '-z', 'io,phs']
    process = subprocess.run(cmd, capture_output=True, text=True)
    output = process.stdout

    # Parse total packet count
    match = re.search(r'Total packets:\s+(\d+)', output)
    if match:
        result['summary']['total_packets'] = int(match.group(1))

    # Get protocol hierarchy statistics
    cmd = ['tshark', '-r', pcap_file, '-q', '-z', 'io,phs']
    process = subprocess.run(cmd, capture_output=True, text=True)
    output = process.stdout

    # Parse protocol statistics
    protocol_lines = re.findall(r'(\s+)([a-zA-Z0-9\-\_\.]+)\s+(\d+)\s+packets', output)
    for indent, protocol, count in protocol_lines:
        result['protocols'][protocol] = int(count)

    # Get IP statistics
    cmd = ['tshark', '-r', pcap_file, '-q', '-z', 'ip_hosts,tree']
    process = subprocess.run(cmd, capture_output=True, text=True)
    output = process.stdout

    # Parse IP statistics
    ip_lines = re.findall(r'([0-9\.]+)\s+(\d+)\s+(\d+)\s+(\d+)', output)
    for ip, frames_sent, bytes_sent, frames_received in ip_lines:
        result['ip_stats'][ip] = {
            'frames_sent': int(frames_sent),
            'bytes_sent': int(bytes_sent),
            'frames_received': int(frames_received)
        }

    # Get top talkers (by packet count)
    top_talkers = sorted(result['ip_stats'].items(), key=lambda x: x[1]['frames_sent'] + x[1]['frames_received'],
                         reverse=True)
    result['top_talkers'] = [{'ip': ip, 'total_frames': stats['frames_sent'] + stats['frames_received']}
                             for ip, stats in top_talkers[:10]]

    # Get port statistics
    cmd = ['tshark', '-r', pcap_file, '-q', '-z', 'conv,tcp']
    process = subprocess.run(cmd, capture_output=True, text=True)
    output = process.stdout

    # Parse TCP port statistics
    port_lines = re.findall(r'([0-9\.]+):(\d+)\s+<->\s+([0-9\.]+):(\d+)', output)
    for src_ip, src_port, dst_ip, dst_port in port_lines:
        if src_port not in result['port_usage']:
            result['port_usage'][src_port] = {'count': 0, 'service': get_service_name(int(src_port))}
        if dst_port not in result['port_usage']:
            result['port_usage'][dst_port] = {'count': 0, 'service': get_service_name(int(dst_port))}

        result['port_usage'][src_port]['count'] += 1
        result['port_usage'][dst_port]['count'] += 1

    # Identify suspicious traffic
    result['suspicious_traffic'] = identify_suspicious_traffic(result)

    return result


def basic_pcap_analysis(pcap_file):
    """Basic PCAP analysis without tshark"""
    result = {
        'summary': {'total_packets': 0},
        'ip_stats': {},
        'protocols': {},
        'suspicious_traffic': [],
        'top_talkers': [],
        'port_usage': {}
    }

    # Note: This is a placeholder for basic PCAP analysis
    # In a real implementation, you would use a Python library like scapy
    # For now, we'll return a message about tshark being required

    result['summary']['note'] = "Full analysis requires tshark. Basic analysis provided."
    result['summary']['total_packets'] = "Unknown (tshark required)"
    result['recommendations'] = ["Install tshark for detailed network analysis"]

    return result


def identify_suspicious_traffic(analysis_data):
    """Identify potentially suspicious traffic patterns"""
    suspicious = []

    # Check for non-standard ports for common services
    common_service_ports = {
        'http': 80,
        'https': 443,
        'ssh': 22,
        'ftp': 21,
        'smtp': 25,
        'dns': 53
    }

    for port, data in analysis_data['port_usage'].items():
        port_num = int(port)
        service = data['service']

        # Check for HTTP/HTTPS on non-standard ports
        if service in ['http', 'https'] and port_num not in [80, 443, 8080, 8443]:
            suspicious.append({
                'type': 'non_standard_port',
                'description': f"{service.upper()} traffic on non-standard port {port_num}",
                'severity': 'medium'
            })

    # Check for potential port scanning
    ip_port_counts = {}
    for ip, stats in analysis_data['ip_stats'].items():
        if stats['frames_sent'] > 100 and stats['frames_received'] < 10:
            suspicious.append({
                'type': 'potential_scanning',
                'description': f"IP {ip} sent many packets but received few responses",
                'severity': 'high'
            })

    # Identify IPs communicating with many different ports (potential scanning)
    if len(analysis_data['port_usage']) > 30:
        suspicious.append({
            'type': 'many_ports',
            'description': f"Traffic to/from many different ports ({len(analysis_data['port_usage'])})",
            'severity': 'medium'
        })

    return suspicious


def get_service_name(port):
    """Get service name for common ports"""
    common_ports = {
        20: 'ftp-data',
        21: 'ftp',
        22: 'ssh',
        23: 'telnet',
        25: 'smtp',
        53: 'dns',
        80: 'http',
        110: 'pop3',
        119: 'nntp',
        123: 'ntp',
        143: 'imap',
        161: 'snmp',
        194: 'irc',
        443: 'https',
        445: 'smb',
        1433: 'mssql',
        3306: 'mysql',
        3389: 'rdp',
        5900: 'vnc',
        8080: 'http-alt',
        8443: 'https-alt'
    }

    return common_ports.get(port, 'unknown')


def generate_recommendations(analysis):
    """Generate security recommendations based on analysis"""
    recommendations = []

    # Check for suspicious traffic
    if analysis['suspicious_traffic']:
        for item in analysis['suspicious_traffic']:
            if item['severity'] == 'high':
                recommendations.append(f"Investigate {item['description']} immediately")
            else:
                recommendations.append(f"Review {item['description']}")

    # Check for common services on non-standard ports
    non_standard = [port for port, data in analysis.get('port_usage', {}).items()
                    if data['service'] in ['http', 'https', 'ssh'] and int(port) not in [22, 80, 443, 8080, 8443]]

    if non_standard:
        recommendations.append("Monitor services running on non-standard ports")

    # General recommendations
    recommendations.append("Regularly analyze network traffic for anomalies")
    recommendations.append("Ensure firewall rules are properly configured")
    recommendations.append("Monitor top talkers for unexpected communication patterns")

    return recommendations