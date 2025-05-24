def scan_network(self, network_range, progress_callback=None):
        """Scan entire network range"""
        self.found_devices = []
        
        try:
            network = ipaddress.IPv4Network(network_range, strict=False)
            hosts = list(network.hosts())
            
            # Add some debug info
            st.info(f"Scanning {len(hosts)} hosts in range {network_range}")
            
            # Test your router IP specifically with multiple ports
            router_ip = "192.168.12.1"
            st.write(f"Testing router at {router_ip} on multiple ports:")
            
            test_ports = [80, 8080, 443, 8443, 81, 8081, 8888, 9000, 8000, 5000]
            for port in test_ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(3)
                    result = sock.connect_ex((router_ip, port))
                    sock.close()
                    
                    if result == 0:
                        st.success(f"✅ Port {port} is OPEN on {router_ip}")
                        # Try to get the web page
                        try:
                            url = f"http://{router_ip}:{port}"
                            response = requests.get(url, timeout=5, verify=False)
                            st.write(f"   HTTP response: {response.status_code}")
                            if len(response.text) > 0:
                                st.write(f"   Content preview: {response.text[:100]}...")
                        except Exception as e:
                            st.write(f"   HTTP error: {str(e)}")
                    else:
                        st.write(f"❌ Port {port} is CLOSED on {router_ip}")
                        
                except Exception as e:
                    st.write(f"❌ Port {port} error: {str(e)}")
            
            total_hosts = len(hosts)
            scanned = 0
            
            with ThreadPoolExecutor(max_workers=20) as executor:
                future_to_ip = {executor.submit(self.scan_ip, ip): ip for ip in hosts}
                
                for future in as_completed(future_to_ip):
                    scanned += 1
                    if progress_callback:
                        progress_callback(scanned, total_hosts)
                    
                    try:
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
        # Scan ALL the common ports!
        self.common_ports = [
            21, 22, 23, 25, 53, 80, 81, 88, 110, 135, 139, 143, 443, 445, 
            993, 995, 1080, 1433, 1521, 3389, 5432, 5900, 8000, 8008, 8080, 
            8081, 8088, 8443, 8888, 9000, 9001, 9080, 9090, 9999, 10000,
            # Camera specific ports
            554, 1024, 1025, 1026, 1027, 1028, 1029, 1030, 1031, 1032,
            2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009,
            3000, 3001, 3002, 3003, 3004, 3005, 3006, 3007, 3008, 3009,
            4000, 4001, 4002, 4003, 4004, 4005, 4006, 4007, 4008, 4009,
            5000, 5001, 5002, 5003, 5004, 5005, 5006, 5007, 5008, 5009,
            6000, 6001, 6002, 6003, 6004, 6005, 6006, 6007, 6008, 6009,
            7000, 7001, 7002, 7003, 7004, 7005, 7006, 7007, 7008, 7009,
            8001, 8002, 8003, 8004, 8005, 8006, 8007, 8009, 8010, 8011,
            8012, 8013, 8014, 8015, 8016, 8017, 8018, 8019, 8020, 8021,
            8022, 8023, 8024, 8025, 8026, 8027, 8028, 8029, 8030, 8031,
            8032, 8033, 8034, 8035, 8036, 8037, 8038, 8039, 8040, 8041,
            8042, 8043, 8044, 8045, 8046, 8047, 8048, 8049, 8050
        ]
        
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
        """Scan a single IP address across ALL ports"""
        ip_str = str(ip)
        found_ports = []
        
        # Test ALL the ports!
        for port in self.common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)  # Faster timeout since we're testing many ports
                result = sock.connect_ex((ip_str, port))
                sock.close()
                
                if result == 0:  # Port is open
                    found_ports.append(port)
                    
            except:
                continue
        
        if found_ports:
            # Try HTTP requests on open ports
            for port in found_ports:
                try:
                    protocols = ['http']
                    if port in [443, 8443]:
                        protocols = ['https']
                    
                    for protocol in protocols:
                        try:
                            url = f"{protocol}://{ip_str}:{port}"
                            response = requests.get(url, timeout=3, verify=False)
                            
                            if response.status_code in [200, 401, 403]:
                                device_info = self.identify_device(ip, url, response.text, response.headers)
                                device_info['open_ports'] = found_ports
                                return device_info
                        except:
                            continue
                            
                except:
                    continue
            
            # If we found open ports but no HTTP, still return device info
            return {
                'ip': ip_str,
                'url': f"Multiple ports open: {found_ports}",
                'hostname': self.get_hostname(ip_str),
                'device_type': '📱 Network Device',
                'brand': 'Unknown',
                'description': f'Open ports: {", ".join(map(str, found_ports[:10]))}{"..." if len(found_ports) > 10 else ""}',
                'status': 'Online',
                'open_ports': found_ports
            }
                
        return None
    
    def scan_network(self, network_range, progress_callback=None):
        """Scan entire network range"""
        self.found_devices = []
        
        try:
            network = ipaddress.IPv4Network(network_range, strict=False)
            hosts = list(network.hosts())
            
            # Add some debug info
            st.info(f"Scanning {len(hosts)} hosts in range {network_range}")
            
            total_hosts = len(hosts)
            scanned = 0
            
            # Test a few IPs manually first to debug
            test_ips = [str(hosts[0]), str(hosts[-1])]  # First and last IP
            if len(hosts) > 1:
                test_ips.append(str(hosts[len(hosts)//2]))  # Middle IP
                
            st.write(f"Testing sample IPs: {test_ips}")
            
            for test_ip in test_ips:
                try:
                    # Quick socket test on port 80
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    result = sock.connect_ex((test_ip, 80))
                    sock.close()
                    st.write(f"IP {test_ip} port 80: {'OPEN' if result == 0 else 'CLOSED'}")
                except Exception as e:
                    st.write(f"IP {test_ip} error: {str(e)}")
            
            with ThreadPoolExecutor(max_workers=20) as executor:
                future_to_ip = {executor.submit(self.scan_ip, ip): ip for ip in hosts}
                
                for future in as_completed(future_to_ip):
                    scanned += 1
                    if progress_callback:
                        progress_callback(scanned, total_hosts)
                    
                    try:
                        result = future.result()
                        if result:
                            self.found_devices.append(result)
                            st.write(f"Found device: {result['ip']} - {result['device_type']}")
                    except Exception as e:
                        pass
                        
        except Exception as e:
            st.error(f"Error scanning network {network_range}: {str(e)}")

def main():
    st.set_page_config(page_title="Network Device Scanner", page_icon="🔍", layout="wide")
    
    st.title("🔍 Network Device Scanner")
    st.markdown("🚀 **MEGA SCAN MODE** - Tests 100+ ports on every device!")
    
    scanner = NetworkDeviceScanner()
    
    # Sidebar configuration
    st.sidebar.header("⚙️ Configuration")
    
    network_range = st.sidebar.text_input(
        "Network Range (CIDR):",
        value="192.168.12.0/24",
        help="Enter network range to scan"
    )
    
    st.sidebar.markdown("**This will scan 100+ ports per IP!**")
    st.sidebar.markdown("• HTTP ports: 80, 8080, 8000, etc.")
    st.sidebar.markdown("• HTTPS ports: 443, 8443, etc.") 
    st.sidebar.markdown("• Camera ports: 554, 8888, etc.")
    st.sidebar.markdown("• Random ports: 1000-9999")
    
    st.sidebar.warning("⚠️ This is aggressive scanning - may take longer but finds EVERYTHING!")
    
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
                        if 'open_ports' in device:
                            st.write(f"**Open Ports:** {', '.join(map(str, device['open_ports'][:15]))}")
                        if device['url'] != 'No web interface' and not device['url'].startswith('Multiple'):
                            st.write(f"**Access:** [Open Device]({device['url']})")
                        elif 'open_ports' in device:
                            # Show clickable links for common web ports
                            web_ports = [p for p in device['open_ports'] if p in [80, 443, 8080, 8081, 8443, 8888]]
                            if web_ports:
                                links = []
                                for port in web_ports[:5]:  # Show first 5
                                    protocol = 'https' if port in [443, 8443] else 'http'
                                    links.append(f"[:{port}]({protocol}://{device['ip']}:{port})")
                                st.write(f"**Try:** {' | '.join(links)}")
                        
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
