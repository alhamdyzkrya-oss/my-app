# device_fingerprinting.py
"""
Advanced device fingerprinting system for professional network discovery.
Implements MAC address detection, vendor identification, hostname resolution, and device classification.
"""

import subprocess
import platform
import socket
import re
import logging
from typing import Dict, Optional, List, Tuple
from database import db

logger = logging.getLogger(__name__)


class DeviceFingerprinting:
    """Advanced device fingerprinting engine."""
    
    def __init__(self):
        self.oui_database = self._load_oui_database()
        self.common_device_patterns = {
            'router': {
                'ports': [22, 23, 80, 443, 8080],
                'mac_vendors': ['cisco', 'juniper', 'huawei', 'arista', 'brocade'],
                'hostnames': ['router', 'gateway', 'gw', 'rt'],
            },
            'switch': {
                'ports': [22, 23, 80, 443],
                'mac_vendors': ['cisco', 'hp', 'dell', 'netgear', 'tp-link', 'linksys'],
                'hostnames': ['switch', 'sw', 'switch-'],
            },
            'server': {
                'ports': [22, 80, 443, 3306, 5432, 1433],
                'mac_vendors': ['dell', 'hp', 'ibm', 'supermicro', 'lenovo'],
                'hostnames': ['server', 'srv', 'host', 'node', 'web', 'db', 'mail'],
            },
            'printer': {
                'ports': [80, 443, 631, 9100],
                'mac_vendors': ['hp', 'canon', 'brother', 'xerox', 'epson'],
                'hostnames': ['printer', 'print', 'prn'],
            },
            'camera': {
                'ports': [80, 443, 554, 8080],
                'mac_vendors': ['axis', 'hikvision', 'dahua', 'sony', 'panasonic'],
                'hostnames': ['camera', 'cam', 'ipcam'],
            },
            'iot': {
                'ports': [80, 443, 1883, 8883],
                'mac_vendors': ['raspberry', 'espressif', 'arduino', 'tuya'],
                'hostnames': ['iot', 'sensor', 'device'],
            }
        }
    
    def _load_oui_database(self) -> Dict[str, str]:
        """
        Load OUI (Organizationally Unique Identifier) database for vendor detection.
        Returns a dictionary mapping MAC prefixes to vendor names.
        """
        # Simplified OUI database with common vendors
        # In production, you might want to use a comprehensive OUI database
        oui_db = {
            # Network equipment vendors
            '00:1C:F0': 'Cisco',
            '00:1D:E5': 'Cisco',
            '00:23:04': 'Cisco',
            '00:27:0E': 'Cisco',
            '00:1B:54': 'Cisco',
            '00:17:94': 'Cisco',
            '00:19:06': 'Cisco',
            '00:21:1B': 'Cisco',
            '00:22:AA': 'Cisco',
            '00:24:94': 'Cisco',
            '00:25:B3': 'Cisco',
            '00:26:CB': 'Cisco',
            '00:50:56': 'VMware',
            '08:00:27': 'Oracle',
            '00:05:69': 'VMware',
            '00:0C:29': 'VMware',
            '00:1C:42': 'Parallels',
            '00:03:FF': 'Xensource',
            
            # HP/HPE
            '00:1A:4B': 'HP',
            '00:1F:29': 'HP',
            '00:21:70': 'HP',
            '00:23:7D': 'HP',
            '00:25:64': 'HP',
            '3C:D9:2B': 'HP',
            '18:03:73': 'HP',
            '34:17:EB': 'HP',
            'F4:CE:46': 'HP',
            'AC:E1:B1': 'HP',
            
            # Dell
            '00:14:22': 'Dell',
            '00:15:C5': 'Dell',
            '00:16:76': 'Dell',
            '00:17:A4': 'Dell',
            '00:18:8B': 'Dell',
            '00:1A:6B': 'Dell',
            '00:1E:4F': 'Dell',
            '00:21:70': 'Dell',
            '00:23:AE': 'Dell',
            '00:24:E8': 'Dell',
            '18:03:73': 'Dell',
            '34:17:EB': 'Dell',
            '84:2B:2B': 'Dell',
            'F8:B1:56': 'Dell',
            
            # IBM/Lenovo
            '00:0A:F7': 'IBM',
            '00:11:25': 'IBM',
            '00:15:58': 'IBM',
            '00:16:17': 'IBM',
            '00:1A:A0': 'IBM',
            '00:21:CC': 'IBM',
            '00:22:68': 'IBM',
            '00:26:B9': 'Lenovo',
            '00:E0:4C': 'Lenovo',
            '08:9E:01': 'Lenovo',
            '24:F5:A2': 'Lenovo',
            '3C:97:0E': 'Lenovo',
            '70:72:3C': 'Lenovo',
            '88:51:FB': 'Lenovo',
            'C8:5B:76': 'Lenovo',
            'F0:1F:AF': 'Lenovo',
            'F4:6D:04': 'Lenovo',
            
            # Apple
            '00:03:93': 'Apple',
            '00:0A:95': 'Apple',
            '00:0D:93': 'Apple',
            '00:0E:4C': 'Apple',
            '00:11:24': 'Apple',
            '00:13:02': 'Apple',
            '00:14:51': 'Apple',
            '00:16:CB': 'Apple',
            '00:17:C4': 'Apple',
            '00:17:F2': 'Apple',
            '00:19:E3': 'Apple',
            '00:1B:63': 'Apple',
            '00:1D:E5': 'Apple',
            '00:1E:C2': 'Apple',
            '00:1E:F1': 'Apple',
            '00:1F:F3': 'Apple',
            '00:21:E9': 'Apple',
            '00:23:12': 'Apple',
            '00:23:45': 'Apple',
            '00:23:DF': 'Apple',
            '00:24:36': 'Apple',
            '00:25:00': 'Apple',
            '00:25:4B': 'Apple',
            '00:26:08': 'Apple',
            '00:26:B9': 'Apple',
            '28:CF:E9': 'Apple',
            '40:A6:D9': 'Apple',
            '64:20:9F': 'Apple',
            '98:01:A7': 'Apple',
            'A4:C3:61': 'Apple',
            'B4:A9:5A': 'Apple',
            'C8:2A:DD': 'Apple',
            'D0:23:DB': 'Apple',
            'D4:9A:20': 'Apple',
            'F0:18:98': 'Apple',
            'F8:1E:DF': 'Apple',
            
            # Samsung
            '00:12:FB': 'Samsung',
            '00:16:32': 'Samsung',
            '00:17:C9': 'Samsung',
            '00:18:2D': 'Samsung',
            '00:1B:7A': 'Samsung',
            '00:1D:5E': 'Samsung',
            '00:21:1C': 'Samsung',
            '00:22:F0': 'Samsung',
            '00:23:15': 'Samsung',
            '00:24:54': 'Samsung',
            '00:26:4B': 'Samsung',
            '00:27:10': 'Samsung',
            '00:E0:4C': 'Samsung',
            '08:96:D7': 'Samsung',
            '0C:D2:92': 'Samsung',
            '18:87:96': 'Samsung',
            '28:10:7B': 'Samsung',
            '34:23:87': 'Samsung',
            '38:B1:DB': 'Samsung',
            '3C:D9:2B': 'Samsung',
            '4C:66:41': 'Samsung',
            '70:72:3C': 'Samsung',
            '78:11:DC': 'Samsung',
            '7C:05:07': 'Samsung',
            '8C:F5:A3': 'Samsung',
            'A0:99:9B': 'Samsung',
            'AC:5A:BE': 'Samsung',
            'B4:9E:46': 'Samsung',
            'C0:4A:00': 'Samsung',
            'C8:BA:94': 'Samsung',
            'CC:3A:61': 'Samsung',
            'D0:22:BE': 'Samsung',
            'D4:BE:D9': 'Samsung',
            'D8:50:E6': 'Samsung',
            'E0:DB:10': 'Samsung',
            'E8:50:8B': 'Samsung',
            'F0:27:65': 'Samsung',
            'F4:6D:04': 'Samsung',
            'F8:E7:1E': 'Samsung',
            
            # TP-Link
            '00:1D:0F': 'TP-Link',
            '00:25:86': 'TP-Link',
            '00:27:19': 'TP-Link',
            '00:B0:D0': 'TP-Link',
            '00:E0:4C': 'TP-Link',
            '04:CF:8C': 'TP-Link',
            '0C:72:DC': 'TP-Link',
            '10:FE:E7': 'TP-Link',
            '14:CC:32': 'TP-Link',
            '18:D6:C7': 'TP-Link',
            '20:DC:1F': 'TP-Link',
            '28:28:5D': 'TP-Link',
            '30:85:A9': 'TP-Link',
            '34:80:B3': 'TP-Link',
            '3C:84:27': 'TP-Link',
            '40:16:9F': 'TP-Link',
            '50:C7:BF': 'TP-Link',
            '52:54:AB': 'TP-Link',
            '58:88:C1': 'TP-Link',
            '60:45:BD': 'TP-Link',
            '64:20:1F': 'TP-Link',
            '68:7F:74': 'TP-Link',
            '70:4D:7B': 'TP-Link',
            '78:44:FD': 'TP-Link',
            '80:1A:86': 'TP-Link',
            '84:16:F9': 'TP-Link',
            '88:41:FC': 'TP-Link',
            '90:F5:DA': 'TP-Link',
            '94:53:A9': 'TP-Link',
            '98:48:27': 'TP-Link',
            'A0:63:B7': 'TP-Link',
            'A8:57:4E': 'TP-Link',
            'AC:84:78': 'TP-Link',
            'B0:4E:26': 'TP-Link',
            'B4:5D:50': 'TP-Link',
            'C0:4A:00': 'TP-Link',
            'C8:3A:35': 'TP-Link',
            'CC:34:29': 'TP-Link',
            'D0:37:45': 'TP-Link',
            'D4:6E:0E': 'TP-Link',
            'D8:07:1C': 'TP-Link',
            'DC:07:4C': 'TP-Link',
            'E0:63:DA': 'TP-Link',
            'E8:94:F6': 'TP-Link',
            'F0:7D:68': 'TP-Link',
            'F4:EC:38': 'TP-Link',
            'F8:D1:11': 'TP-Link',
            'FC:A1:83': 'TP-Link',
            
            # Netgear
            '00:09:5B': 'Netgear',
            '00:0C:F1': 'Netgear',
            '00:0E:B6': 'Netgear',
            '00:0F:B5': 'Netgear',
            '00:11:92': 'Netgear',
            '00:12:43': 'Netgear',
            '00:13:02': 'Netgear',
            '00:14:6C': 'Netgear',
            '00:15:05': 'Netgear',
            '00:16:01': 'Netgear',
            '00:17:3A': 'Netgear',
            '00:18:01': 'Netgear',
            '00:19:CB': 'Netgear',
            '00:1B:2F': 'Netgear',
            '00:1C:F0': 'Netgear',
            '00:21:40': 'Netgear',
            '00:22:3F': 'Netgear',
            '00:22:75': 'Netgear',
            '00:24:EB': 'Netgear',
            '00:26:44': 'Netgear',
            '00:90:F5': 'Netgear',
            '00:C0:02': 'Netgear',
            '00:E0:4F': 'Netgear',
            '04:A1:51': 'Netgear',
            '08:BD:43': 'Netgear',
            '0C:EA:E4': 'Netgear',
            '10:BF:48': 'Netgear',
            '14:6C:14': 'Netgear',
            '18:03:73': 'Netgear',
            '20:4F:42': 'Netgear',
            '24:0A:64': 'Netgear',
            '28:C6:3F': 'Netgear',
            '2C:30:33': 'Netgear',
            '30:85:A9': 'Netgear',
            '34:98:7A': 'Netgear',
            '38:60:77': 'Netgear',
            '3C:90:66': 'Netgear',
            '40:F4:07': 'Netgear',
            '44:94:FC': 'Netgear',
            '48:B0:D3': 'Netgear',
            '4C:72:05': 'Netgear',
            '50:AA:00': 'Netgear',
            '54:9A:1D': 'Netgear',
            '58:6D:B7': 'Netgear',
            '5C:57:C8': 'Netgear',
            '60:38:E0': 'Netgear',
            '64:68:C3': 'Netgear',
            '68:7F:74': 'Netgear',
            '6C:B0:CE': 'Netgear',
            '70:72:3C': 'Netgear',
            '78:24:AF': 'Netgear',
            '7C:04:D0': 'Netgear',
            '80:1A:86': 'Netgear',
            '84:1B:60': 'Netgear',
            '88:12:CA': 'Netgear',
            '8C:3A:D3': 'Netgear',
            '90:B1:1C': 'Netgear',
            '94:44:52': 'Netgear',
            '98:0F:3B': 'Netgear',
            '9C:93:4E': 'Netgear',
            'A0:21:B7': 'Netgear',
            'A4:52:06': 'Netgear',
            'A8:BD:27': 'Netgear',
            'AC:22:B9': 'Netgear',
            'B0:04:EA': 'Netgear',
            'B4:30:52': 'Netgear',
            'B8:27:EB': 'Netgear',
            'BC:14:01': 'Netgear',
            'C0:4A:00': 'Netgear',
            'C4:3D:C7': 'Netgear',
            'C8:BC:C4': 'Netgear',
            'CC:41:A9': 'Netgear',
            'D0:5B:E1': 'Netgear',
            'D4:15:63': 'Netgear',
            'D8:CB:8A': 'Netgear',
            'DC:3A:5E': 'Netgear',
            'E0:91:F5': 'Netgear',
            'E4:3F:13': 'Netgear',
            'E8:94:F6': 'Netgear',
            'EC:1A:59': 'Netgear',
            'F0:08:F1': 'Netgear',
            'F4:28:53': 'Netgear',
            'F8:E1:13': 'Netgear',
            'FC:AA:14': 'Netgear',
        }
        
        logger.info(f"[FINGERPRINT] Loaded OUI database with {len(oui_db)} vendors")
        return oui_db
    
    def get_mac_from_arp(self, ip: str) -> Optional[str]:
        """
        Get MAC address from ARP table for given IP.
        Works on Windows and Linux.
        """
        try:
            system = platform.system().lower()
            
            if system == 'windows':
                # Windows ARP command
                cmd = ['arp', '-a', ip]
            else:
                # Linux/Mac ARP command
                cmd = ['arp', '-n', ip]
            
            proc = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=5,
                text=True
            )
            
            if proc.returncode == 0:
                output = proc.stdout
                
                # Parse ARP output for MAC address
                # Windows: "  192.168.1.1           00-11-22-33-44-55     dynamic"
                # Linux: "192.168.1.1 ether 00:11:22:33:44:55 C eth0"
                
                mac_pattern = r'([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}'
                matches = re.findall(mac_pattern, output)
                
                if matches:
                    # Take the first match and normalize format
                    mac = matches[0][0] if isinstance(matches[0], tuple) else matches[0]
                    # Normalize to colon format
                    mac = mac.replace('-', ':').upper()
                    return mac
            
            return None
            
        except Exception as e:
            logger.debug(f"[FINGERPRINT] ARP lookup failed for {ip}: {e}")
            return None
    
    def get_vendor_from_mac(self, mac: str) -> Optional[str]:
        """
        Get vendor name from MAC address using OUI database.
        """
        if not mac or len(mac) < 8:
            return None
        
        # Normalize MAC format and get OUI (first 3 bytes)
        mac = mac.replace('-', ':').upper()
        oui = ':'.join(mac.split(':')[:3])
        
        # Look up vendor in OUI database
        vendor = self.oui_database.get(oui)
        
        if vendor:
            logger.debug(f"[FINGERPRINT] MAC {mac} -> Vendor: {vendor}")
        
        return vendor
    
    def get_hostname_from_ip(self, ip: str) -> Optional[str]:
        """
        Get hostname from IP address using reverse DNS lookup.
        """
        try:
            hostname, aliaslist, ipaddrlist = socket.gethostbyaddr(ip)
            logger.debug(f"[FINGERPRINT] IP {ip} -> Hostname: {hostname}")
            return hostname
        except (socket.herror, socket.gaierror, socket.timeout):
            return None
        except Exception as e:
            logger.debug(f"[FINGERPRINT] Hostname lookup failed for {ip}: {e}")
            return None
    
    def classify_device(self, ip: str, open_ports: List[int], mac: str = None, 
                       hostname: str = None, vendor: str = None) -> str:
        """
        Classify device type based on ports, MAC vendor, and hostname.
        Returns: 'router', 'switch', 'server', 'printer', 'camera', 'iot', 'unknown'
        """
        scores = {
            'router': 0,
            'switch': 0,
            'server': 0,
            'printer': 0,
            'camera': 0,
            'iot': 0,
            'unknown': 0
        }
        
        # Port-based classification
        for port in open_ports:
            if port in [22, 23, 80, 443, 8080]:
                scores['router'] += 2
            if port in [22, 23, 80, 443]:
                scores['switch'] += 2
            if port in [22, 80, 443, 3306, 5432, 1433, 21, 25]:
                scores['server'] += 2
            if port in [80, 443, 631, 9100]:
                scores['printer'] += 3
            if port in [80, 443, 554, 8080]:
                scores['camera'] += 3
            if port in [80, 443, 1883, 8883]:
                scores['iot'] += 2
        
        # Vendor-based classification
        if vendor:
            vendor_lower = vendor.lower()
            for device_type, patterns in self.common_device_patterns.items():
                if any(v in vendor_lower for v in patterns['mac_vendors']):
                    scores[device_type] += 3
        
        # Hostname-based classification
        if hostname:
            hostname_lower = hostname.lower()
            for device_type, patterns in self.common_device_patterns.items():
                if any(pattern in hostname_lower for pattern in patterns['hostnames']):
                    scores[device_type] += 2
        
        # Special cases
        if 23 in open_ports:  # Telnet - often older network gear
            scores['router'] += 3
            scores['switch'] += 3
        
        if 631 in open_ports:  # CUPS - printer
            scores['printer'] += 5
        
        if 554 in open_ports:  # RTSP - camera
            scores['camera'] += 5
        
        # Find the device type with highest score
        max_score = max(scores.values())
        if max_score == 0:
            return 'unknown'
        
        best_types = [dt for dt, score in scores.items() if score == max_score]
        if len(best_types) == 1:
            return best_types[0]
        
        # Tie-breaker: prioritize server > router > switch > others
        priority_order = ['server', 'router', 'switch', 'printer', 'camera', 'iot', 'unknown']
        for dt in priority_order:
            if dt in best_types:
                return dt
        
        return 'unknown'
    
    def generate_device_name(self, ip: str, device_type: str, hostname: str = None, 
                          vendor: str = None, mac: str = None) -> str:
        """
        Generate a meaningful device name based on available information.
        """
        if hostname and not hostname.startswith('192.168.') and not hostname.startswith('10.'):
            # Use hostname if it's meaningful (not just an IP)
            return hostname.split('.')[0].upper()
        
        # Generate name based on device type and other info
        if device_type == 'router':
            if vendor:
                return f"{vendor.upper()}-Router"
            return f"Router-{ip.split('.')[-1]}"
        
        elif device_type == 'switch':
            if vendor:
                return f"{vendor.upper()}-Switch"
            return f"Switch-{ip.split('.')[-1]}"
        
        elif device_type == 'server':
            if hostname:
                return hostname.upper()
            if vendor:
                return f"{vendor.upper()}-Server"
            return f"Server-{ip.split('.')[-1]}"
        
        elif device_type == 'printer':
            if vendor:
                return f"{vendor.upper()}-Printer"
            return f"Printer-{ip.split('.')[-1]}"
        
        elif device_type == 'camera':
            if vendor:
                return f"{vendor.upper()}-Camera"
            return f"Camera-{ip.split('.')[-1]}"
        
        elif device_type == 'iot':
            if vendor:
                return f"{vendor.upper()}-IoT"
            return f"IoT-{ip.split('.')[-1]}"
        
        else:
            return f"Device-{ip.replace('.', '_')}"
    
    def fingerprint_device(self, ip: str, open_ports: List[int], 
                         ping_success: bool = False) -> Dict:
        """
        Complete device fingerprinting.
        Returns comprehensive device information.
        """
        fingerprint = {
            'ip': ip,
            'alive': ping_success,
            'open_ports': open_ports,
            'mac_address': None,
            'vendor': None,
            'hostname': None,
            'device_type': 'unknown',
            'device_name': None,
            'status': 'DOWN',
            'confidence': 0
        }
        
        if not ping_success and not open_ports:
            return fingerprint
        
        # Get MAC address
        mac = self.get_mac_from_arp(ip)
        if mac:
            fingerprint['mac_address'] = mac
        
        # Get vendor from MAC
        vendor = self.get_vendor_from_mac(mac) if mac else None
        if vendor:
            fingerprint['vendor'] = vendor
        
        # Get hostname
        hostname = self.get_hostname_from_ip(ip)
        if hostname:
            fingerprint['hostname'] = hostname
        
        # Classify device type
        device_type = self.classify_device(ip, open_ports, mac, hostname, vendor)
        fingerprint['device_type'] = device_type
        
        # Generate device name
        device_name = self.generate_device_name(ip, device_type, hostname, vendor, mac)
        fingerprint['device_name'] = device_name
        
        # Determine status and confidence
        if ping_success:
            if device_type != 'unknown' and (mac or hostname or vendor):
                fingerprint['status'] = 'UP'
                fingerprint['confidence'] = 0.9
            elif open_ports:
                fingerprint['status'] = 'UP'
                fingerprint['confidence'] = 0.7
            else:
                fingerprint['status'] = 'WARNING'
                fingerprint['confidence'] = 0.5
        elif open_ports:
            fingerprint['status'] = 'WARNING'
            fingerprint['confidence'] = 0.4
        else:
            fingerprint['status'] = 'DOWN'
            fingerprint['confidence'] = 0.1
        
        logger.info(
            f"[FINGERPRINT] {ip} -> {device_name} ({device_type}) "
            f"[{fingerprint['status']}] MAC:{mac} Vendor:{vendor} Host:{hostname}"
        )
        
        return fingerprint


# Singleton instance
device_fingerprinting = DeviceFingerprinting()
