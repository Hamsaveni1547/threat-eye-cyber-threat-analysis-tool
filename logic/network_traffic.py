# logic/network_traffic.py
import os
import json
import pandas as pd
import re
from datetime import datetime
import subprocess
import socket
from collections import Counter, defaultdict


def analyze_traffic(file_path):
    """Analyze network traffic capture files (PCAP, CSV)"""

    try:
        file_extension = os.path.splitext(file_path)[1].lower()

        # Check file type and process accordingly
        if file_extension == '.pcap' or file_extension == '.pcapng':
            # Use tshark (Wireshark CLI) if installed
            if is_tool_available('tshark'):
                result = analyze_pcap_tshark(file_path)
            else:
                result = {
                    'status': 'error',
                    'message': 'tshark not available. Install Wireshark to analyze PCAP files.',
                    'data': None
                }
        elif file_extension == '.csv':
            result = analyze_traffic_csv(file_path)
        else:
            return {
                'status': 'error',
                'message': f'Unsupported file format: {file_extension}',
                'data': None
            }

        return result

    except Exception as e:
        return {
            'status': 'error',
            'message': f'Error analyzing traffic: {str(e)}',
            'data': None
        }


def is_tool_available(name):
    """Check if a command-line tool is available"""
    try:
        devnull = open(os.devnull, 'w')
        subprocess.Popen([name], stdout=devnull, stderr=devnull).communicate()
    except OSError:
        return False
    return True


def analyze_pcap_tshark(file_path):
    """Analyze PCAP file using tshark (Wireshark CLI)"""
    try:
        # Run tshark to get packet summary
        cmd = ['tshark', '-r', file_path, '-T', 'fields',
               '-e', 'frame.time_epoch', '-e', 'ip.src', '-e', 'ip.dst',
               '-e', 'tcp.srcport', '-e', 'tcp.dstport', '-e', 'udp.srcport',
               '-e', 'udp.dstport', '-e', 'ip.proto', '-e', 'frame.len',
               '-E', 'header=y', '-E', 'separator=,']

        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, error = process.communicate()

        if process.returncode != 0:
            return {
                'status': 'error',
                'message': f'tshark error: {error.decode()}',
                'data': None
            }

        # Parse CSV output
        df = pd.read_csv(pd.compat.StringIO(output.decode('utf-8')))

        # Basic traffic stats
        packet_count = len(df)

        # IP analysis
        src_ips = df['ip.src'].dropna().tolist()
        dst_ips = df['ip.dst'].dropna().tolist()

        src_ip_counts = Counter(src_ips)
        dst_ip_counts = Counter(dst_ips)

        # Protocol analysis
        protocols = df['ip.proto'].dropna().tolist()
        proto_counts = Counter(protocols)

        # Convert numeric protocols to names
        proto_map = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
        protocol_stats = {proto_map.get(int(float(p)), 'Other'): count
                          for p, count in proto_counts.items() if not pd.isna(p)}

        # Port analysis
        tcp_src_ports = df['tcp.srcport'].dropna().tolist()
        tcp_dst_ports = df['tcp.dstport'].dropna().tolist()
        udp_src_ports = df['udp.srcport'].dropna().tolist()
        udp_dst_ports = df['udp.dstport'].dropna().tolist()

        # Combine all destination ports
        all_dst_ports = [p for p in tcp_dst_ports if not pd.isna(p)] + \
                        [p for p in udp_dst_ports if not pd.isna(p)]
        dst_port_counts = Counter([int(float(p)) for p in all_dst_ports if not pd.isna(p)])

        # Traffic volume
        total_bytes = df['frame.len'].sum()

        # Get well-known services for top ports
        top_ports = dst_port_counts.most_common(10)
        port_services = {}
        for port, count in top_ports:
            try:
                service = socket.getservbyport(int(port))
                port_services[port] = service
            except:
                port_services[port] = "Unknown"

        # Traffic flow analysis
        flows = defaultdict(int)
        for _, row in df.iterrows():
            if pd.notna(row.get('ip.src')) and pd.notna(row.get('ip.dst')):
                flow = f"{row['ip.src']} → {row['ip.dst']}"
                flows[flow] += 1

        top_flows = dict(Counter(flows).most_common(10))

        # Build result
        result = {
            'status': 'success',
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'file_info': {
                'filename': os.path.basename(file_path),
                'type': 'PCAP/PCAPNG'
            },
            'traffic_summary': {
                'packet_count': packet_count,
                'total_bytes': total_bytes,
                'avg_packet_size': total_bytes / packet_count if packet_count > 0 else 0
            },
            'ip_analysis': {
                'unique_src_ips': len(src_ip_counts),
                'unique_dst_ips': len(dst_ip_counts),
                'top_src_ips': dict(src_ip_counts.most_common(10)),
                'top_dst_ips': dict(dst_ip_counts.most_common(10))
            },
            'protocol_analysis': {
                'protocol_distribution': protocol_stats
            },
            'port_analysis': {
                'top_dst_ports': {str(port): {"count": count, "service": port_services.get(port, "Unknown")}
                                  for port, count in top_ports}
            },
            'flow_analysis': {
                'top_flows': top_flows
            }
        }

        # Look for potential security issues
        security_issues = detect_security_issues(df, src_ip_counts, dst_ip_counts, dst_port_counts)
        result['security_analysis'] = security_issues

        return result

    except Exception as e:
        return {
            'status': 'error',
            'message': f'Error analyzing PCAP: {str(e)}',
            'data': None
        }


def analyze_traffic_csv(file_path):
    """Analyze traffic data from CSV file (assumes columns like source, destination, etc.)"""
    try:
        # Read CSV file
        df = pd.read_csv(file_path)

        # Try to identify column names for source IP, destination IP, etc.
        # This assumes certain naming patterns in columns
        src_ip_col = next((col for col in df.columns if re.search(r'src.*ip|source.*ip|ip.*src', col.lower())), None)
        dst_ip_col = next((col for col in df.columns if re.search(r'dst.*ip|dest.*ip|ip.*dst', col.lower())), None)
        proto_col = next((col for col in df.columns if re.search(r'proto|protocol', col.lower())), None)
        bytes_col = next((col for col in df.columns if re.search(r'bytes|size|length', col.lower())), None)

        if not (src_ip_col and dst_ip_col):
            return {
                'status': 'error',
                'message': 'Could not identify source and destination IP columns in CSV',
                'data': None
            }

        # Basic traffic stats
        packet_count = len(df)

        # IP analysis
        src_ips = df[src_ip_col].dropna().tolist()
        dst_ips = df[dst_ip_col].dropna().tolist()

        src_ip_counts = Counter(src_ips)
        dst_ip_counts = Counter(dst_ips)

        # Protocol analysis
        protocol_stats = {}
        if proto_col:
            protocols = df[proto_col].dropna().tolist()
            proto_counts = Counter(protocols)
            protocol_stats = dict(proto_counts.most_common(10))

        # Traffic volume
        total_bytes = 0
        if bytes_col:
            total_bytes = df[bytes_col].sum()

        # Build result
        result = {
            'status': 'success',
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'file_info': {
                'filename': os.path.basename(file_path),
                'type': 'CSV'
            },
            'traffic_summary': {
                'packet_count': packet_count,
                'total_bytes': total_bytes,
                'avg_packet_size': total_bytes / packet_count if packet_count > 0 and total_bytes > 0 else 0
            },
            'ip_analysis': {
                'unique_src_ips': len(src_ip_counts),
                'unique_dst_ips': len(dst_ip_counts),
                'top_src_ips': dict(src_ip_counts.most_common(10)),
                'top_dst_ips': dict(dst_ip_counts.most_common(10))
            }
        }

        if protocol_stats:
            result['protocol_analysis'] = {
                'protocol_distribution': protocol_stats
            }

        return result

    except Exception as e:
        return {
            'status': 'error',
            'message': f'Error analyzing CSV traffic data: {str(e)}',
            'data': None
        }


def detect_security_issues(df, src_ip_counts, dst_ip_counts, dst_port_counts):
    """Detect potential security issues in traffic data"""

    security_issues = {
        'potential_issues': [],
        'severity': 'Low'
    }

    # Check for scanning behavior (many destinations from single source)
    for src_ip, count in src_ip_counts.items():
        # If a source IP is communicating with many different destinations
        if count > 30:
            destinations = sum(1 for _, row in df.iterrows() if row['ip.src'] == src_ip)
            if destinations > 20:
                security_issues['potential_issues'].append({
                    'type': 'Potential Port Scanning',
                    'details': f'Source IP {src_ip} connected to {destinations} different destinations'
                })
                security_issues['severity'] = 'Medium'

    # Check for common malicious ports
    malicious_ports = {
        22: 'SSH',
        3389: 'RDP',
        445: 'SMB',
        1433: 'MSSQL',
        3306: 'MySQL',
        5432: 'PostgreSQL'
    }

    for port, details in malicious_ports.items():
        if port in dst_port_counts:
            security_issues['potential_issues'].append({
                'type': 'Remote Access Service Detected',
                'details': f'Traffic to {details} port ({port}) detected - ensure this service is authorized'
            })

    # Check for unusual volumes (simple heuristic)
    very_high_volume_threshold = 100000000  # 100 MB
    if df['frame.len'].sum() > very_high_volume_threshold:
        security_issues['potential_issues'].append({
            'type': 'Unusual Traffic Volume',
            'details': f'Very high traffic volume detected ({df["frame.len"].sum() / 1000000:.2f} MB)'
        })
        security_issues['severity'] = 'Medium'

    # Return empty issues if none found
    if not security_issues['potential_issues']:
        security_issues['potential_issues'].append({
            'type': 'No Issues Detected',
            'details': 'No obvious security issues detected in the traffic sample'
        })

    return security_issues