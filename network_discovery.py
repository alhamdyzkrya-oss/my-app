# network_discovery.py
"""
Network discovery module for automatic VLAN scanning.
Implements CIDR expansion, ping scanning, and port checking with threading.
"""

import ipaddress
import socket
import subprocess
import platform
import threading
import time
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import List, Dict, Tuple, Optional
from database import db
from scanner import NetworkScanner

logger = logging.getLogger(__name__)


class NetworkDiscovery:
    """Network discovery engine for automatic device detection."""
    
    def __init__(self):
        self.scanner = NetworkScanner()
        self.common_ports = [22, 80, 443]  # SSH, HTTP, HTTPS
        self.ping_timeout = 2
        self.port_timeout = 1
        self.max_threads = 50  # Adjust based on system performance
        
    def expand_cidr(self, cidr: str) -> List[str]:
        """
        Expand CIDR notation to list of IP addresses.
        Example: 192.168.1.0/24 -> ['192.168.1.1', '192.168.1.2', ..., '192.168.1.254']
        """
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            # Exclude network and broadcast addresses
            hosts = [str(host) for host in network.hosts()]
            logger.info(f"[DISCOVERY] Expanded {cidr} to {len(hosts)} hosts")
            return hosts
        except ValueError as e:
            logger.error(f"[DISCOVERY] Invalid CIDR {cidr}: {e}")
            return []
    
    def ping_host_fast(self, ip: str) -> bool:
        """
        Fast ping check using subprocess.
        Returns True if host responds to ping.
        """
        try:
            system = platform.system().lower()
            if system == 'windows':
                cmd = ['ping', '-n', '1', '-w', str(self.ping_timeout * 1000), ip]
            else:
                cmd = ['ping', '-c', '1', '-W', str(self.ping_timeout), ip]
            
            proc = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=self.ping_timeout + 1
            )
            return proc.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
            return False
    
    def check_ports_fast(self, ip: str) -> Tuple[bool, List[int]]:
        """
        Check common ports for the given IP.
        Returns (is_responsive, open_ports_list)
        """
        open_ports = []
        
        for port in self.common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.port_timeout)
                result = sock.connect_ex((ip, port))
                sock.close()
                
                if result == 0:
                    open_ports.append(port)
            except Exception:
                continue
        
        return len(open_ports) > 0, open_ports
    
    def scan_single_host(self, ip: str) -> Dict:
        """
        Scan a single host: ping + port check + advanced fingerprinting.
        Returns scan result dictionary.
        """
        # Basic ping and port scan
        ping_success = self.ping_host_fast(ip)
        is_responsive, open_ports = self.check_ports_fast(ip)
        
        # Advanced device fingerprinting
        from device_fingerprinting import device_fingerprinting
        fingerprint = device_fingerprinting.fingerprint_device(
            ip, open_ports, ping_success
        )
        
        # Convert fingerprint to scan result format
        result = {
            'ip': ip,
            'alive': fingerprint['alive'],
            'ping_ms': None,  # Could be added later
            'open_ports': fingerprint['open_ports'],
            'device_type': fingerprint['device_type'].title(),  # Capitalize for display
            'device_name': fingerprint['device_name'],
            'mac_address': fingerprint['mac_address'],
            'vendor': fingerprint['vendor'],
            'hostname': fingerprint['hostname'],
            'status': fingerprint['status'],
            'confidence': fingerprint['confidence'],
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        
        return result
    
    def scan_network(self, network_id: int, progress_callback=None) -> Dict:
        """
        Scan entire network CIDR and auto-discover devices.
        Returns comprehensive scan results.
        """
        # Get network info
        network = db.get_network_by_id(network_id)
        if not network:
            raise ValueError(f"Network {network_id} not found")
        
        cidr = network['cidr']
        logger.info(f"[DISCOVERY] Starting network scan for {network['name']} ({cidr})")
        
        # Security validation: ensure CIDR is valid and safe to scan
        if not self._validate_cidr_safety(cidr):
            raise ValueError(f"Unsafe CIDR for scanning: {cidr}")
        
        # Expand CIDR to IP list
        ips = self.expand_cidr(cidr)
        if not ips:
            return {'error': 'Invalid CIDR format'}
        
        # Additional security: limit scan size to prevent abuse
        if len(ips) > 1024:  # /22 or larger networks
            logger.warning(f"[DISCOVERY] Large network detected ({len(ips)} hosts). Limiting scan to first 1024 hosts.")
            ips = ips[:1024]
        
        # Initialize results
        results = {
            'network_id': network_id,
            'network_name': network['name'],
            'cidr': cidr,
            'total_ips': len(ips),
            'scanned_ips': 0,
            'alive_hosts': 0,
            'new_devices': 0,
            'updated_devices': 0,
            'discovered_devices': [],
            'scan_time': 0,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        
        # Get existing devices for this network
        existing_devices = {}
        all_equipments = db.get_all_equipments()
        for equipment in all_equipments:
            if equipment.get('network_id') == network_id:
                existing_devices[equipment['ip']] = equipment
        
        start_time = time.time()
        
        # Threaded scanning
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            # Submit all scan tasks
            future_to_ip = {executor.submit(self.scan_single_host, ip): ip for ip in ips}
            
            # Process results as they complete
            for future in as_completed(future_to_ip):
                ip = future_to_ip[future]
                
                try:
                    scan_result = future.result()
                    results['scanned_ips'] += 1
                    
                    if scan_result['alive']:
                        results['alive_hosts'] += 1
                        
                        # Check if device already exists
                        if ip in existing_devices:
                            # Update existing device with new fingerprinting data
                            existing = existing_devices[ip]
                            
                            # Update status
                            db.update_equipment_status(existing['id'], scan_result['status'])
                            
                            # Update advanced fields if new data is available
                            if (scan_result['mac_address'] and not existing.get('mac_address')) or \
                               (scan_result['vendor'] and not existing.get('vendor')) or \
                               (scan_result['hostname'] and not existing.get('hostname')) or \
                               (scan_result['device_type'] and existing.get('device_type') == 'unknown'):
                                db.update_equipment_advanced_fields(
                                    existing['id'],
                                    scan_result['mac_address'],
                                    scan_result['vendor'],
                                    scan_result['hostname'],
                                    scan_result['device_type'].lower()
                                )
                            
                            results['updated_devices'] += 1
                            
                            # Add to discovered list
                            scan_result['existing'] = True
                            scan_result['device_id'] = existing['id']
                            scan_result['device_name'] = existing['nom']
                            results['discovered_devices'].append(scan_result)
                        else:
                            # Auto-create new device with full fingerprinting data
                            try:
                                db.add_equipment_with_fingerprint(
                                    ip=ip,
                                    device_name=scan_result['device_name'],
                                    device_type=scan_result['device_type'].lower(),
                                    mac_address=scan_result['mac_address'],
                                    vendor=scan_result['vendor'],
                                    hostname=scan_result['hostname'],
                                    network_id=network_id,
                                    description=f"Auto-discovered on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} (Confidence: {scan_result['confidence']:.1f})"
                                )
                                results['new_devices'] += 1
                                
                                # Add to discovered list
                                scan_result['existing'] = False
                                results['discovered_devices'].append(scan_result)
                                
                                logger.info(f"[DISCOVERY] Auto-created device: {scan_result['device_name']} ({ip}) [{scan_result['device_type']}]")
                            except Exception as e:
                                logger.error(f"[DISCOVERY] Failed to create device {ip}: {e}")
                    
                    # Progress callback
                    if progress_callback:
                        progress = (results['scanned_ips'] / results['total_ips']) * 100
                        progress_callback({
                            'progress': progress,
                            'scanned': results['scanned_ips'],
                            'total': results['total_ips'],
                            'alive': results['alive_hosts'],
                            'current_ip': ip
                        })
                
                except Exception as e:
                    logger.error(f"[DISCOVERY] Error scanning {ip}: {e}")
                    results['scanned_ips'] += 1
        
        # Mark existing devices as DOWN if they didn't respond
        for ip, device in existing_devices.items():
            device_found = False
            for discovered in results['discovered_devices']:
                if discovered['ip'] == ip:
                    device_found = True
                    break
            
            if not device_found:
                db.update_equipment_status(device['id'], 'DOWN')
                logger.info(f"[DISCOVERY] Marked device as DOWN: {device['nom']} ({ip})")
        
        results['scan_time'] = round(time.time() - start_time, 2)
        
        logger.info(
            f"[DISCOVERY] Scan complete for {network['name']}: "
            f"{results['alive_hosts']}/{results['total_ips']} hosts alive, "
            f"{results['new_devices']} new devices, "
            f"{results['updated_devices']} updated, "
            f"took {results['scan_time']}s"
        )
        
        return results
    
    def _validate_cidr_safety(self, cidr: str) -> bool:
        """
        Security validation to ensure CIDR is safe for scanning.
        Prevents scanning of public networks and invalid ranges.
        """
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            
            # Check if it's a private network range
            if not network.is_private:
                logger.warning(f"[SECURITY] Blocked scan of public network: {cidr}")
                return False
            
            # Check for overly broad networks (smaller than /8)
            if network.prefixlen < 8:
                logger.warning(f"[SECURITY] Blocked scan of overly broad network: {cidr}")
                return False
            
            # Check for localhost/loopback networks (these are OK but we handle them specially)
            if network.is_loopback:
                logger.info(f"[SECURITY] Allowing loopback network scan: {cidr}")
                return True
            
            # Additional safety checks
            # Block link-local networks
            if network.is_link_local:
                logger.warning(f"[SECURITY] Blocked scan of link-local network: {cidr}")
                return False
            
            # Block multicast networks
            if network.is_multicast:
                logger.warning(f"[SECURITY] Blocked scan of multicast network: {cidr}")
                return False
            
            # Block reserved networks
            if network.is_reserved:
                logger.warning(f"[SECURITY] Blocked scan of reserved network: {cidr}")
                return False
            
            logger.info(f"[SECURITY] CIDR validation passed: {cidr}")
            return True
            
        except ValueError as e:
            logger.error(f"[SECURITY] Invalid CIDR format: {cidr} - {e}")
            return False

    def get_scan_statistics(self, network_id: int) -> Dict:
        """
        Get scan statistics for a network.
        """
        network = db.get_network_by_id(network_id)
        if not network:
            return {'error': 'Network not found'}
        
        # Count devices in network
        all_equipments = db.get_all_equipments()
        network_devices = [eq for eq in all_equipments if eq.get('network_id') == network_id]
        
        up_devices = [eq for eq in network_devices if eq.get('status') == 'UP']
        down_devices = [eq for eq in network_devices if eq.get('status') == 'DOWN']
        
        return {
            'network_id': network_id,
            'network_name': network['name'],
            'cidr': network['cidr'],
            'total_devices': len(network_devices),
            'up_devices': len(up_devices),
            'down_devices': len(down_devices),
            'last_scan': network.get('last_scan', 'Never')
        }


# Singleton instance
network_discovery = NetworkDiscovery()
