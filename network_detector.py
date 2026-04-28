# network_detector.py
import subprocess
import platform
import re
import logging
import ipaddress
from typing import List, Dict, Tuple
from config import Config

logger = logging.getLogger(__name__)


class NetworkDetector:
    """Auto-detect local networks from system routing table"""
    
    def __init__(self):
        self.system = platform.system().lower()
        
    def get_routing_table(self) -> str:
        """Get system routing table"""
        try:
            if self.system == 'windows':
                # Windows: route print
                result = subprocess.run(
                    ['route', 'print'],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                return result.stdout
            elif self.system == 'linux':
                # Linux: ip route show or route -n
                try:
                    result = subprocess.run(
                        ['ip', 'route', 'show'],
                        capture_output=True,
                        text=True,
                        timeout=10
                    )
                    return result.stdout
                except FileNotFoundError:
                    # Fallback to traditional route command
                    result = subprocess.run(
                        ['route', '-n'],
                        capture_output=True,
                        text=True,
                        timeout=10
                    )
                    return result.stdout
            else:
                logger.error(f"[NETWORK DETECTOR] Unsupported OS: {self.system}")
                return ""
                
        except subprocess.TimeoutExpired:
            logger.error("[NETWORK DETECTOR] Timeout reading routing table")
            return ""
        except FileNotFoundError:
            logger.error("[NETWORK DETECTOR] Route command not found")
            return ""
        except Exception as e:
            logger.error(f"[NETWORK DETECTOR] Error reading routing table: {e}")
            return ""
    
    def parse_windows_routes(self, route_output: str) -> List[Dict]:
        """Parse Windows routing table output"""
        networks = []
        
        try:
            lines = route_output.split('\n')
            # Find the start of the route table (look for "Network Destination")
            start_idx = -1
            for i, line in enumerate(lines):
                if 'Network Destination' in line and 'Netmask' in line:
                    start_idx = i + 2  # Skip header and separator lines
                    break
            
            if start_idx == -1:
                logger.warning("[NETWORK DETECTOR] Could not find routing table start")
                return networks
            
            # Parse each route line
            for line in lines[start_idx:]:
                line = line.strip()
                if not line or line.startswith('==='):
                    continue
                
                # Split by whitespace
                parts = re.split(r'\s+', line)
                if len(parts) < 4:
                    continue
                
                try:
                    destination = parts[0]
                    netmask = parts[1]
                    gateway = parts[2]
                    interface = parts[3] if len(parts) > 3 else ''
                    
                    # Skip loopback and multicast
                    if destination in ['127.0.0.0', '224.0.0.0', '255.255.255.255']:
                        continue
                    
                    # Convert to CIDR
                    if netmask == '255.255.255.255':
                        cidr = f"{destination}/32"
                    else:
                        # Count bits in netmask
                        mask_bits = sum(bin(int(x)).count('1') for x in netmask.split('.'))
                        cidr = f"{destination}/{mask_bits}"
                    
                    # Validate and only include private networks
                    try:
                        network = ipaddress.ip_network(cidr, strict=False)
                        if network.is_private:
                            networks.append({
                                'cidr': cidr,
                                'gateway': gateway,
                                'interface': interface,
                                'type': 'direct' if gateway in ['0.0.0.0', 'On-link'] else 'gateway'
                            })
                    except ValueError:
                        continue
                        
                except (ValueError, IndexError):
                    continue
                    
        except Exception as e:
            logger.error(f"[NETWORK DETECTOR] Error parsing Windows routes: {e}")
        
        return networks
    
    def parse_linux_routes(self, route_output: str) -> List[Dict]:
        """Parse Linux routing table output"""
        networks = []
        
        try:
            lines = route_output.split('\n')
            
            for line in lines:
                line = line.strip()
                if not line or line.startswith('default'):
                    continue
                
                # Parse route format: "192.168.1.0/24 dev eth0 proto kernel scope link src 192.168.1.10"
                parts = line.split()
                if len(parts) < 3:
                    continue
                
                try:
                    # First part should be the network in CIDR format
                    cidr = parts[0]
                    
                    # Validate and only include private networks
                    try:
                        network = ipaddress.ip_network(cidr, strict=False)
                        if network.is_private:
                            # Extract interface name
                            interface = ''
                            gateway = ''
                            
                            for i, part in enumerate(parts):
                                if part == 'dev' and i + 1 < len(parts):
                                    interface = parts[i + 1]
                                elif part == 'via' and i + 1 < len(parts):
                                    gateway = parts[i + 1]
                            
                            networks.append({
                                'cidr': cidr,
                                'gateway': gateway,
                                'interface': interface,
                                'type': 'direct' if not gateway else 'gateway'
                            })
                    except ValueError:
                        continue
                        
                except (ValueError, IndexError):
                    continue
                    
        except Exception as e:
            logger.error(f"[NETWORK DETECTOR] Error parsing Linux routes: {e}")
        
        return networks
    
    def detect_networks(self) -> List[Dict]:
        """Main method to detect local networks"""
        logger.info("[NETWORK DETECTOR] Starting network detection...")
        
        route_output = self.get_routing_table()
        if not route_output:
            logger.warning("[NETWORK DETECTOR] No routing table data available")
            return []
        
        # Parse based on OS
        if self.system == 'windows':
            networks = self.parse_windows_routes(route_output)
        else:
            networks = self.parse_linux_routes(route_output)
        
        # Remove duplicates and sort
        seen = set()
        unique_networks = []
        for network in networks:
            if network['cidr'] not in seen:
                seen.add(network['cidr'])
                unique_networks.append(network)
        
        # Sort by network address
        unique_networks.sort(key=lambda x: ipaddress.ip_network(x['cidr']).network_address)
        
        logger.info(f"[NETWORK DETECTOR] Detected {len(unique_networks)} networks")
        for network in unique_networks:
            logger.info(f"  - {network['cidr']} via {network['gateway']} ({network['interface']})")
        
        return unique_networks
    
    def get_network_summary(self) -> Dict:
        """Get summary of detected networks"""
        networks = self.detect_networks()
        
        summary = {
            'total_networks': len(networks),
            'networks': networks,
            'system': self.system,
            'timestamp': None
        }
        
        # Add timestamp
        from datetime import datetime
        summary['timestamp'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        return summary


# Singleton instance
network_detector = NetworkDetector()
