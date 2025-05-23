#!/usr/bin/env python3
"""
Streamlit Network Camera Scanner
Web app to scan local network for IP cameras and webcams
"""

import streamlit as st
import socket
import threading
import requests
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import pandas as pd
from urllib.parse import urljoin
import netifaces

class CameraScanner:
    def __init__(self):
        self.found_cameras = []
        self.common_camera_ports = [80, 81, 554, 8080, 8081, 8888, 9000]
        self.camera_paths = [
            '/videostream.cgi',
            '/video.cgi',
            '/mjpg/video.mjpg',
            '/axis-cgi/mjpg/video.cgi',
            '/cgi-bin/hi3510/snap.cgi',
            '/snapshot.cgi',
            '/image.jpg',
            '/live/ch0',
            '/cam/realmonitor',
            '/web/tmpfs/snap.jpg',
            '/cgi-bin/snapshot.cgi',
            '/snapshot.jpg'
        ]
        
    def get_local_networks(self):
        """Get all local network ranges"""
        networks = []
        try:
            for interface in netifaces.interfaces():
                addrs = netifaces.ifaddresses(interface)
                if netifaces.AF_INET in addrs:
                    for addr in addrs[netifaces.AF_INET]:
                        ip = addr['addr']
                        netmask = addr.get('netmask', '255.255.255.0')
                        if not ip.startswith('127.'):
                            try:
                                network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                                networks.append(str(network.network_address) + '/' + str(network.prefixlen))
                            except:
                                pass
        except:
            # Fallback to common private ranges
            networks = ['192.168.1.0/24', '192.168.0.0/24', '10.0.0.0/24']
        
        return networks
    
    def port_scan(self, ip, port, timeout=1):
        """Check if a port is open on given IP"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except:
            return False
    
    def check_http_service(self, ip, port):
        """Check if HTTP service responds and looks like a camera"""
        protocols = ['http', 'https'] if port == 443 else ['http']
        
        for protocol in protocols:
            try:
                base_url = f"{protocol}://{ip}:{port}"
                response = requests.get(base_url, timeout=3, verify=False)
                
                # Check for camera-related keywords in response
                content = response.text.lower()
                headers = str(response.headers).lower()
                
                camera_indicators = [
                    'camera', 'webcam', 'ipcam', 'axis', 'hikvision', 
                    'dahua', 'foscam', 'vivotek', 'panasonic', 'sony',
                    'mjpeg', 'rtsp', 'onvif', 'surveillance'
                ]
                
                if any(indicator in content or indicator in headers for indicator in camera_indicators):
                    return True, base_url, "Camera interface detected"
                
                # Check camera-specific paths
                for path in self.camera_paths:
                    try:
                        cam_url = urljoin(base_url, path)
                        cam_response = requests.get(cam_url, timeout=2, verify=False)
                        if cam_response.status_code == 200:
                            content_type = cam_response.headers.get('content-type', '').lower()
                            if 'image' in content_type or 'video' in content_type:
                                return True, cam_url, f"Camera stream found at {path}"
                    except:
                        continue
                        
            except:
                continue
                
        return False, None, None
    
    def scan_ip(self, ip):
        """Scan a single IP for camera services"""
        results = []
        ip_str = str(ip)
        
        for port in self.common_camera_ports:
            if self.port_scan(ip_str, port):
                is_camera, url, description = self.check_http_service(ip_str, port)
                if is_camera:
                    results.append({
                        'ip': ip_str,
                        'port': port,
                        'url': url,
                        'description': description,
                        'status': 'Camera Found'
                    })
                else:
                    results.append({
                        'ip': ip_str,
                        'port': port,
                        'url': f"http://{ip_str}:{port}",
                        'description': 'Open port (unknown service)',
                        'status': 'Open Port'
                    })
        
        return results
    
    def scan_network(self, network_range, progress_callback=None):
        """Scan entire network range"""
        try:
            network = ipaddress.IPv4Network(network_range, strict=False)
            hosts = list(network.hosts())
            
            total_hosts = len(hosts)
            scanned = 0
            
            with ThreadPoolExecutor(max_workers=50) as executor:
                future_to_ip = {executor.submit(self.scan_ip, ip): ip for ip in hosts}
                
                for future in as_completed(future_to_ip):
                    scanned += 1
                    if progress_callback:
                        progress_callback(scanned, total_hosts)
                    
                    try:
                        results = future.result()
                        self.found_cameras.extend(results)
                    except Exception as e:
                        pass
                        
        except Exception as e:
            st.error(f"Error scanning network {network_range}: {str(e)}")

def main():
    st.set_page_config(page_title="Network Camera Scanner", page_icon="📷", layout="wide")
    
    st.title("🎥 Network Camera Scanner")
    st.markdown("Scan your local network for IP cameras and webcams")
    
    scanner = CameraScanner()
    
    # Sidebar for configuration
    st.sidebar.header("⚙️ Configuration")
    
    # Get available networks
    available_networks = scanner.get_local_networks()
    
    if available_networks:
        selected_network = st.sidebar.selectbox(
            "Select Network Range:",
            available_networks,
            help="Choose the network range to scan"
        )
    else:
        selected_network = st.sidebar.text_input(
            "Network Range (CIDR):",
            value="192.168.1.0/24",
            help="Enter network range in CIDR notation (e.g., 192.168.1.0/24)"
        )
    
    scan_button = st.sidebar.button("🔍 Start Scan", type="primary")
    
    # Main content area
    col1, col2 = st.columns([2, 1])
    
    with col2:
        st.subheader("📊 Scan Statistics")
        stats_placeholder = st.empty()
        
    with col1:
        st.subheader("🎯 Scan Results")
        results_placeholder = st.empty()
    
    if scan_button:
        scanner.found_cameras = []  # Reset results
        
        progress_bar = st.progress(0)
        status_text = st.empty()
        
        def update_progress(current, total):
            progress = current / total
            progress_bar.progress(progress)
            status_text.text(f"Scanning... {current}/{total} hosts checked")
        
        start_time = time.time()
        
        with st.spinner(f"Scanning network {selected_network}..."):
            scanner.scan_network(selected_network, update_progress)
        
        end_time = time.time()
        scan_duration = end_time - start_time
        
        # Clear progress indicators
        progress_bar.empty()
        status_text.empty()
        
        # Display results
        if scanner.found_cameras:
            # Create DataFrame for better display
            df = pd.DataFrame(scanner.found_cameras)
            
            # Separate cameras from other open ports
            cameras = df[df['status'] == 'Camera Found']
            open_ports = df[df['status'] == 'Open Port']
            
            # Display statistics
            with stats_placeholder.container():
                st.metric("🎥 Cameras Found", len(cameras))
                st.metric("🔓 Open Ports", len(open_ports))
                st.metric("⏱️ Scan Time", f"{scan_duration:.1f}s")
            
            # Display camera results
            with results_placeholder.container():
                if len(cameras) > 0:
                    st.success(f"Found {len(cameras)} potential camera(s)!")
                    
                    for _, camera in cameras.iterrows():
                        with st.expander(f"📷 Camera at {camera['ip']}:{camera['port']}", expanded=True):
                            st.write(f"**IP Address:** {camera['ip']}")
                            st.write(f"**Port:** {camera['port']}")
                            st.write(f"**Description:** {camera['description']}")
                            st.write(f"**URL:** {camera['url']}")
                            
                            # Try to display image if it's an image endpoint
                            if any(ext in camera['url'].lower() for ext in ['.jpg', '.jpeg', '.png', 'image']):
                                try:
                                    st.image(camera['url'], caption=f"Live feed from {camera['ip']}")
                                except:
                                    st.info("Could not display image (may require authentication)")
                
                if len(open_ports) > 0:
                    with st.expander(f"🔓 Other Open Ports ({len(open_ports)})"):
                        st.dataframe(open_ports[['ip', 'port', 'url']], use_container_width=True)
        else:
            with stats_placeholder.container():
                st.metric("🎥 Cameras Found", 0)
                st.metric("⏱️ Scan Time", f"{scan_duration:.1f}s")
            
            with results_placeholder.container():
                st.warning("No cameras found on the selected network range.")
                st.info("This could mean:\n- No cameras are present\n- Cameras are on different ports\n- Cameras require authentication\n- Firewall is blocking access")
    
    # Footer
    st.markdown("---")
    st.markdown("**Note:** This tool scans your local network for cameras. Ensure you have permission to scan the network you're testing.")

if __name__ == "__main__":
    main()
