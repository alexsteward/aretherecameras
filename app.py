#!/usr/bin/env python3
"""
Simple Network Scanner
"""

import streamlit as st
import socket
import requests
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import pandas as pd
import subprocess
import platform
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class NetworkScanner:
    def __init__(self):
        self.found_devices = []
        self.ports_to_scan = [
            21, 22, 23, 25, 53, 80, 81, 88, 110, 135, 139, 143, 443, 445, 
            554, 993, 995, 1080, 1433, 1521, 3389, 5432, 5900, 8000, 8008, 
            8080, 8081, 8088, 8443, 8888, 9000, 9001, 9080, 9090, 9999
        ]
        
    def get_hostname(self, ip):
        try:
            hostname = socket.gethostbyaddr(str(ip))[0]
            return hostname
        except:
            return "Unknown"
    
    def check_port(self, ip, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((str(ip), port))
            sock.close()
            return result == 0
        except:
            return False
    
    def get_web_content(self, ip, port):
        protocols = ['http']
        if port in [443, 8443]:
            protocols = ['https']
            
        for protocol in protocols:
            try:
                url = f"{protocol}://{ip}:{port}"
                response = requests.get(url, timeout=3, verify=False)
                if response.status_code in [200, 401, 403]:
                    return url, response.text, response.headers
            except:
                continue
        return None, None, None
    
    def identify_device(self, ip, url, content, headers):
        device_info = {
            'ip': str(ip),
            'url': url or 'No web interface',
            'hostname': self.get_hostname(ip),
            'device_type': 'Unknown Device',
            'brand': 'Unknown',
            'description': '',
            'status': 'Online'
        }
        
        if not content:
            return device_info
            
        content_lower = content.lower()
        
        # Check for router
        if str(ip).endswith('.1') or any(word in content_lower for word in ['router', 'gateway', 'admin', 'wireless']):
            device_info['device_type'] = '🌐 Router'
            device_info['description'] = 'Network router/gateway'
            
        # Check for camera
        elif any(word in content_lower for word in ['camera', 'webcam', 'surveillance', 'video']):
            device_info['device_type'] = '📷 IP Camera'
            device_info['description'] = 'Security camera'
            
        # Check for printer
        elif any(word in content_lower for word in ['printer', 'print']):
            device_info['device_type'] = '🖨️ Printer'
            device_info['description'] = 'Network printer'
            
        else:
            device_info['device_type'] = '📱 Network Device'
            device_info['description'] = 'Unknown network device'
            
        return device_info
    
    def scan_ip(self, ip):
        ip_str = str(ip)
        open_ports = []
        
        # Check all ports
        for port in self.ports_to_scan:
            if self.check_port(ip_str, port):
                open_ports.append(port)
        
        if not open_ports:
            return None
            
        # Try to get web content from open ports
        best_result = None
        for port in open_ports:
            url, content, headers = self.get_web_content(ip_str, port)
            if url:
                device_info = self.identify_device(ip, url, content, headers)
                device_info['open_ports'] = open_ports
                return device_info
        
        # No web content but has open ports
        return {
            'ip': ip_str,
            'url': 'No web interface',
            'hostname': self.get_hostname(ip_str),
            'device_type': '📱 Network Device',
            'brand': 'Unknown',
            'description': f'Open ports: {", ".join(map(str, open_ports))}',
            'status': 'Online',
            'open_ports': open_ports
        }
    
    def scan_network(self, network_range, progress_callback=None):
        self.found_devices = []
        
        try:
            network = ipaddress.IPv4Network(network_range, strict=False)
            hosts = list(network.hosts())
            
            st.info(f"Scanning {len(hosts)} hosts...")
            
            total_hosts = len(hosts)
            scanned = 0
            
            with ThreadPoolExecutor(max_workers=30) as executor:
                futures = {executor.submit(self.scan_ip, ip): ip for ip in hosts}
                
                for future in as_completed(futures):
                    scanned += 1
                    if progress_callback:
                        progress_callback(scanned, total_hosts)
                    
                    try:
                        result = future.result()
                        if result:
                            self.found_devices.append(result)
                    except:
                        pass
                        
        except Exception as e:
            st.error(f"Error: {str(e)}")

def main():
    st.set_page_config(page_title="Network Scanner", page_icon="🔍", layout="wide")
    
    st.title("🔍 Network Scanner")
    st.markdown("Find all devices on your network")
    
    scanner = NetworkScanner()
    
    # Input
    network_range = st.text_input(
        "Network Range:",
        value="192.168.12.0/24",
        help="Enter your network range (e.g., 192.168.12.0/24)"
    )
    
    if st.button("🚀 Start Scan", type="primary"):
        progress_bar = st.progress(0)
        status_text = st.empty()
        
        def update_progress(current, total):
            progress = current / total
            progress_bar.progress(progress)
            status_text.text(f"Scanning... {current}/{total}")
        
        start_time = time.time()
        
        scanner.scan_network(network_range, update_progress)
        
        end_time = time.time()
        
        progress_bar.empty()
        status_text.empty()
        
        if scanner.found_devices:
            st.success(f"Found {len(scanner.found_devices)} devices!")
            
            for device in sorted(scanner.found_devices, key=lambda x: ipaddress.IPv4Address(x['ip'])):
                with st.expander(f"{device['device_type']} - {device['ip']}"):
                    col1, col2 = st.columns(2)
                    with col1:
                        st.write(f"**IP:** {device['ip']}")
                        st.write(f"**Hostname:** {device['hostname']}")
                        st.write(f"**Type:** {device['device_type']}")
                    with col2:
                        st.write(f"**Description:** {device['description']}")
                        if 'open_ports' in device:
                            ports_str = ', '.join(map(str, device['open_ports'][:10]))
                            if len(device['open_ports']) > 10:
                                ports_str += '...'
                            st.write(f"**Ports:** {ports_str}")
                        if device['url'] != 'No web interface':
                            st.markdown(f"**Access:** [{device['url']}]({device['url']})")
        else:
            st.warning("No devices found")

if __name__ == "__main__":
    main()
