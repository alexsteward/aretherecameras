#!/usr/bin/env python3
"""
Auto Network Scanner - Detects your local network automatically
"""

import streamlit as st
import socket
import requests
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import netifaces
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class NetworkScanner:
    def __init__(self):
        self.found_devices = []
        self.ports_to_scan = [21, 22, 23, 25, 53, 80, 81, 88, 110, 135, 139, 143, 443, 445, 554, 993, 995, 1080, 1433, 1521, 3389, 5432, 5900, 8000, 8008, 8080, 8081, 8088, 8443, 8888, 9000, 9001, 9080, 9090, 9999]
        
    def get_local_network(self):
        """Auto-detect the local network range"""
        try:
            for interface in netifaces.interfaces():
                addrs = netifaces.ifaddresses(interface)
                if netifaces.AF_INET in addrs:
                    for addr in addrs[netifaces.AF_INET]:
                        ip = addr['addr']
                        netmask = addr.get('netmask', '255.255.255.0')
                        
                        if ip.startswith('127.'):
                            continue
                            
                        if (ip.startswith('192.168.') or ip.startswith('10.') or ip.startswith('172.')):
                            try:
                                network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                                return str(network.network_address) + '/' + str(network.prefixlen), ip
                            except:
                                continue
            return None, None
        except:
            return None, None
        
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
        
        if str(ip).endswith('.1') or any(word in content_lower for word in ['router', 'gateway', 'admin', 'wireless']):
            device_info['device_type'] = '🌐 Router'
            device_info['description'] = 'Network router/gateway'
        elif any(word in content_lower for word in ['camera', 'webcam', 'surveillance', 'video']):
            device_info['device_type'] = '📷 IP Camera'
            device_info['description'] = 'Security camera'
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
        
        for port in self.ports_to_scan:
            if self.check_port(ip_str, port):
                open_ports.append(port)
        
        if not open_ports:
            return None
            
        best_result = None
        for port in open_ports:
            url, content, headers = self.get_web_content(ip_str, port)
            if url:
                device_info = self.identify_device(ip, url, content, headers)
                device_info['open_ports'] = open_ports
                return device_info
        
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
    
    st.title("🔍 Auto Network Scanner")
    st.markdown("Automatically detects and scans your local network for devices")
    
    scanner = NetworkScanner()
    
    detected_network, your_ip = scanner.get_local_network()
    
    if detected_network:
        st.success(f"🎯 Auto-detected your network: **{detected_network}** (Your IP: {your_ip})")
        default_network = detected_network
    else:
        st.warning("⚠️ Could not auto-detect network. Please enter manually.")
        default_network = "192.168.1.0/24"
    
    col1, col2 = st.columns([3, 1])
    
    with col1:
        network_range = st.text_input(
            "Network Range:",
            value=default_network,
            help="Auto-detected or enter custom (e.g., 192.168.1.0/24)"
        )
    
    with col2:
        auto_scan = st.checkbox("Use auto-detected", value=True if detected_network else False)
    
    if auto_scan and detected_network:
        network_range = detected_network
        st.info(f"🤖 Using auto-detected network: {network_range}")
    
    if st.button("🚀 Start Scan", type="primary"):
        if not network_range:
            st.error("Please enter a network range")
            return
            
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
            st.success(f"🎉 Found {len(scanner.found_devices)} devices in {end_time-start_time:.1f} seconds!")
            
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.metric("📱 Total", len(scanner.found_devices))
            with col2:
                cameras = len([d for d in scanner.found_devices if '📷' in d['device_type']])
                st.metric("📷 Cameras", cameras)
            with col3:
                routers = len([d for d in scanner.found_devices if '🌐' in d['device_type']])
                st.metric("🌐 Routers", routers)
            with col4:
                st.metric("⏱️ Time", f"{end_time-start_time:.1f}s")
            
            for device in sorted(scanner.found_devices, key=lambda x: ipaddress.IPv4Address(x['ip'])):
                expanded = '📷' in device['device_type']
                with st.expander(f"{device['device_type']} - {device['ip']}", expanded=expanded):
                    col1, col2 = st.columns(2)
                    with col1:
                        st.write(f"**IP:** {device['ip']}")
                        st.write(f"**Hostname:** {device['hostname']}")
                        st.write(f"**Type:** {device['device_type']}")
                    with col2:
                        st.write(f"**Description:** {device['description']}")
                        if 'open_ports' in device:
                            ports = device['open_ports'][:10]
                            ports_str = ', '.join(map(str, ports))
                            if len(device['open_ports']) > 10:
                                ports_str += '...'
                            st.write(f"**Ports:** {ports_str}")
                        if device['url'] != 'No web interface':
                            st.markdown(f"**🔗 Access:** [{device['url']}]({device['url']})")
                            
                    if '📷' in device['device_type']:
                        st.success("🎥 **Camera found!** Click the access link above.")
        else:
            st.warning("❌ No devices found")
            st.info("💡 Try checking if devices are powered on or verify the network range")

if __name__ == "__main__":
    main()
