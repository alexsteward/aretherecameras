#!/usr/bin/env python3
"""
Local Network Device Scanner
Scans network by trying to access web interfaces on each IP
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
import re
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class NetworkDeviceScanner:
    def __init__(self):
        self.found_devices = []
        self.common_ports = [80, 8080, 443, 8443, 81, 8081, 8888, 9000]
        
    def ping_host(self, ip):
        """Check if host is alive using socket connection"""
        try:
            # Try socket connection first (faster and more reliable)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((str(ip), 80))
            sock.close()
            if result == 0:
                return True
                
            # Try HTTPS port
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((str(ip), 443))
            sock.close()
            if result == 0:
                return True
                
            # Try ping as backup
            param = "-n" if platform.system().lower() == "windows" else "-c"
            command = ["ping", param, "1", str(ip)]
            result = subprocess.run(command, capture_output=True, text=True, timeout=5)
            return result.returncode == 0
        except:
            return True  # If ping fails, still try to connect
    
    def get_hostname(self, ip):
        """Try to get hostname"""
        try:
            hostname = socket.gethostbyaddr(str(ip))[0]
            return hostname
        except:
            return "Unknown"
    
    def check_web_interface(self, ip, port):
        """Check if there's a web interface on this IP:port"""
        protocols = ['http']
        if port in [443, 8443]:
            protocols = ['https']
        
        for protocol in protocols:
            try:
                url = f"{protocol}://{ip}:{port}"
                response = requests.get(url, timeout=8, verify=False, 
                                      headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'},
                                      allow_redirects=True)
                
                if response.status_code in [200, 401, 403]:
                    return True, url, response.text, response.headers
                    
            except requests.exceptions.Timeout:
                continue
            except requests.exceptions.ConnectionError:
                continue
            except requests.exceptions.RequestException:
                continue
            except Exception:
                continue
                
        return False, None, None, None
    
    def identify_device(self, ip, url, content, headers):
        """Identify what type of device this is based on web content"""
        device_info = {
            'ip': str(ip),
            'url': url,
            'hostname': self.get_hostname(ip),
            'device_type': 'Unknown Device',
            'brand': 'Unknown',
            'description': '',
            'status': 'Online'
        }
        
        # Convert to lowercase for easier matching
        content_lower = content.lower() if content else ""
        headers_lower = str(headers).lower() if headers else ""
        combined_text = content_lower + " " + headers_lower
        
        # Special IP address patterns
        ip_str = str(ip)
        if ip_str.endswith('.1'):
            device_info['device_type'] = 'Router/Gateway'
            device_info['description'] = 'Likely main router/gateway'
        elif ip_str.endswith('.254'):
            device_info['device_type'] = 'Router/Gateway'
            device_info['description'] = 'Likely router/gateway'
        
        # Camera detection
        camera_keywords = [
            'camera', 'webcam', 'ipcam', 'surveillance', 'mjpeg', 'rtsp', 
            'onvif', 'video', 'snapshot', 'livestream', 'security camera'
        ]
        camera_brands = {
            'hikvision': 'Hikvision',
            'dahua': 'Dahua', 
            'axis': 'Axis',
            'foscam': 'Foscam',
            'vivotek': 'Vivotek',
            'panasonic': 'Panasonic',
            'sony': 'Sony',
            'bosch': 'Bosch',
            'pelco': 'Pelco',
            'honeywell': 'Honeywell'
        }
        
        if any(keyword in combined_text for keyword in camera_keywords):
            device_info['device_type'] = '📷 IP Camera'
            device_info['description'] = 'Security/surveillance camera'
            
            for brand_key, brand_name in camera_brands.items():
                if brand_key in combined_text:
                    device_info['brand'] = brand_name
                    break
        
        # Router detection  
        router_keywords = [
            'router', 'gateway', 'modem', 'access point', 'wireless', 
            'admin', 'configuration', 'settings', 'wifi', 'dhcp'
        ]
        router_brands = {
            'netgear': 'Netgear',
            'linksys': 'Linksys', 
            'asus': 'ASUS',
            'tp-link': 'TP-Link',
            'tplink': 'TP-Link',
            'd-link': 'D-Link',
            'dlink': 'D-Link',
            'belkin': 'Belkin',
            'cisco': 'Cisco',
            'ubiquiti': 'Ubiquiti'
        }
        
        if any(keyword in combined_text for keyword in router_keywords):
            device_info['device_type'] = '🌐 Router'
            device_info['description'] = 'Network router/access point'
            
            for brand_key, brand_name in router_brands.items():
                if brand_key in combined_text:
                    device_info['brand'] = brand_name
                    break
        
        # NAS/Storage detection
        nas_keywords = ['nas', 'storage', 'synology', 'qnap', 'drobo', 'buffalo']
        if any(keyword in combined_text for keyword in nas_keywords):
            device_info['device_type'] = '💾 NAS/Storage'
            device_info['description'] = 'Network storage device'
        
        # Printer detection
        printer_keywords = ['printer', 'print', 'canon', 'hp', 'epson', 'brother']
        if any(keyword in combined_text for keyword in printer_keywords):
            device_info['device_type'] = '🖨️ Printer'
            device_info['description'] = 'Network printer'
        
        # Smart home devices
        smart_keywords = ['smart', 'iot', 'home', 'automation', 'alexa', 'google']
        if any(keyword in combined_text for keyword in smart_keywords):
            device_info['device_type'] = '🏠 Smart Device'
            device_info['description'] = 'Smart home device'
            
        # Media devices
        media_keywords = ['plex', 'kodi', 'media', 'streaming', 'chromecast', 'roku']
        if any(keyword in combined_text for keyword in media_keywords):
            device_info['device_type'] = '📺 Media Device'
            device_info['description'] = 'Media streaming device'
        
        return device_info
    
    def scan_ip(self, ip):
        """Scan a single IP address"""
        ip_str = str(ip)
        
        # Try to find web interfaces on common ports
        for port in self.common_ports:
            has_web, url, content, headers = self.check_web_interface(ip_str, port)
            if has_web:
                device_info = self.identify_device(ip, url, content, headers)
                return device_info
        
        # If no web interface found, check if host responds at all
        if self.ping_host(ip_str):
            return {
                'ip': ip_str,
                'url': 'No web interface',
                'hostname': self.get_hostname(ip_str),
                'device_type': '📱 Network Device',
                'brand': 'Unknown',
                'description': 'Device online but no web interface on common ports',
                'status': 'Online'
            }
                
        return None
    
    def scan_network(self, network_range, progress_callback=None):
        """Scan entire network range"""
        self.found_devices = []
        
        try:
            network = ipaddress.IPv4Network(network_range, strict=False)
            hosts = list(network.hosts())
            
            if len(hosts) > 1000:
                st.warning(f"Large network range ({len(hosts)} hosts). This may take a while!")
            
            total_hosts = len(hosts)
            scanned = 0
            
            with ThreadPoolExecutor(max_workers=50) as executor:
                future_to_ip = {executor.submit(self.scan_ip, ip): ip for ip in hosts}
                
                for future in as_completed(future_to_ip):
                    scanned += 1
                    if progress_callback:
                        progress_callback(scanned, total_hosts)
                    
                    try:
                        result = future.result()
                        if result:
                            self.found_devices.append(result)
                    except Exception as e:
                        pass
                        
        except Exception as e:
            st.error(f"Error scanning network {network_range}: {str(e)}")

def main():
    st.set_page_config(page_title="Network Device Scanner", page_icon="🔍", layout="wide")
    
    st.title("🔍 Network Device Scanner")
    st.markdown("Discover all devices on your local network by checking their web interfaces")
    
    scanner = NetworkDeviceScanner()
    
    # Sidebar configuration
    st.sidebar.header("⚙️ Configuration")
    
    network_range = st.sidebar.text_input(
        "Network Range (CIDR):",
        value="192.168.0.0/24",
        help="Enter network range to scan (e.g., 192.168.1.0/24, 10.0.0.0/8)"
    )
    
    st.sidebar.markdown("**Examples:**")
    st.sidebar.markdown("• `192.168.1.0/24` - 192.168.1.1-254")
    st.sidebar.markdown("• `192.168.0.0/16` - All 192.168.x.x")
    st.sidebar.markdown("• `10.0.0.0/24` - 10.0.0.1-254")
    
    scan_button = st.sidebar.button("🚀 Start Scan", type="primary")
    
    # Main content
    if scan_button:
        progress_bar = st.progress(0)
        status_text = st.empty()
        
        def update_progress(current, total):
            progress = current / total
            progress_bar.progress(progress)
            status_text.text(f"Scanning... {current}/{total} hosts ({progress:.1%})")
        
        start_time = time.time()
        
        with st.spinner(f"Scanning network {network_range}..."):
            scanner.scan_network(network_range, update_progress)
        
        end_time = time.time()
        scan_duration = end_time - start_time
        
        # Clear progress
        progress_bar.empty()
        status_text.empty()
        
        # Display results
        if scanner.found_devices:
            st.success(f"🎉 Found {len(scanner.found_devices)} devices in {scan_duration:.1f} seconds!")
            
            # Create DataFrame
            df = pd.DataFrame(scanner.found_devices)
            
            # Statistics
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.metric("📱 Total Devices", len(scanner.found_devices))
            with col2:
                cameras = len([d for d in scanner.found_devices if '📷' in d['device_type']])
                st.metric("📷 Cameras", cameras)
            with col3:
                routers = len([d for d in scanner.found_devices if '🌐' in d['device_type']])
                st.metric("🌐 Routers", routers)
            with col4:
                st.metric("⏱️ Scan Time", f"{scan_duration:.1f}s")
            
            # Device list
            st.subheader("🔍 Discovered Devices")
            
            for device in sorted(scanner.found_devices, key=lambda x: ipaddress.IPv4Address(x['ip'])):
                with st.expander(f"{device['device_type']} - {device['ip']}", expanded=False):
                    col1, col2 = st.columns([1, 1])
                    
                    with col1:
                        st.write(f"**IP Address:** {device['ip']}")
                        st.write(f"**Hostname:** {device['hostname']}")
                        st.write(f"**Device Type:** {device['device_type']}")
                        st.write(f"**Brand:** {device['brand']}")
                    
                    with col2:
                        st.write(f"**Status:** {device['status']}")
                        st.write(f"**Description:** {device['description']}")
                        if device['url'] != 'No web interface':
                            st.write(f"**Access:** [Open Device]({device['url']})")
                        
                    # Special handling for cameras
                    if '📷' in device['device_type'] and device['url'] != 'No web interface':
                        st.info(f"🎥 **Camera Access:** You can try accessing this camera at {device['url']}")
            
            # Summary table
            st.subheader("📊 Device Summary")
            summary_df = df[['ip', 'hostname', 'device_type', 'brand', 'url']].copy()
            st.dataframe(summary_df, use_container_width=True)
            
        else:
            st.warning("❌ No devices found on the specified network range")
            st.info("Try:\n• Check if the network range is correct\n• Ensure devices are powered on\n• Some devices may not respond to ping or have web interfaces")
    
    # Instructions
    st.markdown("---")
    st.markdown("""
    **How it works:**
    1. Pings each IP to see if it's alive
    2. Checks common web ports (80, 8080, 443, etc.)
    3. Analyzes web content to identify device types
    4. Shows you direct links to access each device
    
    **Found a camera?** Click the link to access it directly in your browser!
    """)

if __name__ == "__main__":
    main()
