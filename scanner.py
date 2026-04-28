# scanner.py
import subprocess
import socket
import platform
import re
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from config import Config
try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False
    logging.warning("python-nmap not available, using basic scanning only")
import shutil

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class NetworkScanner:

    def __init__(self):
        self.ports_to_scan = Config.PORTS_TO_SCAN
        self.ping_timeout  = getattr(Config, 'PING_TIMEOUT', 3)
        self.port_timeout  = getattr(Config, 'PORT_TIMEOUT', 2)

        self.nm = None

        if NMAP_AVAILABLE:
            try:
                # Define common Nmap paths for Windows
                nmap_paths = [
                    r"C:\Program Files (x86)\Nmap\nmap.exe",
                    r"C:\Program Files\Nmap\nmap.exe",
                    r"C:\Nmap\nmap.exe",
                    "nmap.exe"  # Try PATH as fallback
                ]
                
                # Check if nmap exists in PATH first
                nmap_path = shutil.which("nmap")
                
                if nmap_path:
                    # Found in PATH, use it
                    self.nm = nmap.PortScanner()
                    logger.info(f"[SCANNER] Nmap initialized from PATH: {nmap_path}")
                else:
                    # Not in PATH, try explicit paths
                    for path in nmap_paths:
                        try:
                            if path == "nmap.exe":
                                # Try without explicit path (should fail but we catch it)
                                self.nm = nmap.PortScanner()
                            else:
                                # Try with explicit path
                                self.nm = nmap.PortScanner(nmap_search_path=(path,))
                            
                            # If we get here, it worked
                            logger.info(f"[SCANNER] Nmap initialized using path: {path}")
                            break
                        except Exception as path_error:
                            logger.debug(f"[SCANNER] Path {path} failed: {path_error}")
                            continue
                    else:
                        # All paths failed
                        raise Exception("Nmap not found in any standard location")

            except Exception as e:
                logger.warning(f"[SCANNER] Nmap init failed: {e}")
                logger.info("[SCANNER] Falling back to basic port scanning")
                self.nm = None
        else:
            self.nm = None

    # ── Validation ────────────────────────────────────────────────────────────

    def validate_ip(self, ip: str) -> bool:
        pattern = (
            r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
            r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        )
        return bool(re.match(pattern, ip))

    def is_ip_in_network(self, ip: str, network_cidr: str = None) -> bool:
        """
        Check if IP belongs to the configured network (CIDR).
        If network_cidr is None, use Config.LOCAL_NETWORK.
        """
        import ipaddress
        
        try:
            if not self.validate_ip(ip):
                return False
            
            ip_addr = ipaddress.ip_address(ip)
            network_cidr = network_cidr or getattr(Config, 'LOCAL_NETWORK', '192.168.0.0/16')
            network_addr = ipaddress.ip_network(network_cidr, strict=False)
            
            return ip_addr in network_addr
            
        except (ValueError, TypeError, AttributeError):
            return False

    # ── Ping ─────────────────────────────────────────────────────────────────
    #
    #  RULE: ping returncode is the ONLY source of truth for UP/DOWN.
    #  returncode 0  → UP
    #  returncode ≠0 → DOWN
    #  Open TCP ports alone do NOT make a device UP.

    def ping_host(self, ip: str) -> dict:
        """Real ICMP ping. Never returns a hardcoded value."""
        if not self.validate_ip(ip):
            return {'reachable': False, 'avg_ms': None, 'packet_loss': 100.0}

        system = platform.system().lower()
        cmd = (
            ['ping', '-n', '1', '-w', str(self.ping_timeout * 1000), ip]
            if system == 'windows'
            else ['ping', '-c', '1', '-W', str(self.ping_timeout), ip]
        )

        try:
            proc = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=self.ping_timeout + 3
            )

            # returncode is ground truth — never override it
            reachable = (proc.returncode == 0)

            if reachable:
                stdout = proc.stdout.decode('utf-8', errors='replace')
                avg_ms = self._parse_avg_ms(stdout, system)
                loss   = self._parse_packet_loss(stdout, system)
                logger.info(f"[PING] {ip} → UP (avg={avg_ms}ms)")
                return {'reachable': True, 'avg_ms': avg_ms, 'packet_loss': loss}
            else:
                logger.info(f"[PING] {ip} → DOWN (returncode={proc.returncode})")
                return {'reachable': False, 'avg_ms': None, 'packet_loss': 100.0}

        except subprocess.TimeoutExpired:
            logger.warning(f"[PING] Timeout → {ip} DOWN")
            return {'reachable': False, 'avg_ms': None, 'packet_loss': 100.0}
        except FileNotFoundError:
            logger.error("[PING] ping binary not found")
            return {'reachable': False, 'avg_ms': None, 'packet_loss': 100.0}
        except Exception as e:
            logger.error(f"[PING] {ip}: {e} → DOWN")
            return {'reachable': False, 'avg_ms': None, 'packet_loss': 100.0}

    # ── Port scan ─────────────────────────────────────────────────────────────

    def check_port(self, ip: str, port: int) -> dict:
        """TCP connection check."""
        if not self.validate_ip(ip) or not (1 <= port <= 65535):
            return {'status': 'ERROR', 'reason': 'Invalid', 'open': False}

        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.port_timeout)
            result  = sock.connect_ex((ip, port))
            is_open = (result == 0)
            return {
                'status': 'OPEN' if is_open else 'CLOSED',
                'reason': 'OK',
                'open':   is_open,
            }
        except socket.timeout:
            return {'status': 'ERROR', 'reason': 'Timeout', 'open': False}
        except ConnectionRefusedError:
            return {'status': 'CLOSED', 'reason': 'Refused', 'open': False}
        except OSError as e:
            return {'status': 'ERROR', 'reason': str(e), 'open': False}
        except Exception as e:
            return {'status': 'ERROR', 'reason': str(e), 'open': False}
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass

    def scan_ports_nmap(self, ip: str, ports: list = [22, 80, 443, 21]) -> list:
        """Use nmap to scan specific ports and return list of port results."""
        if not self.nm:
            logger.warning("[NMAP] Nmap not available, using basic port scan")
            return self._basic_port_scan(ip, ports)
        
        try:
            logger.info(f"[NMAP] Scanning {ip} for ports {ports}")
            result = self.nm.scan(ip, ports, arguments='-T4 --max-retries 1')
            
            port_results = []
            for port in ports:
                if ip in result['scan'] and 'tcp' in result['scan'][ip]:
                    port_info = result['scan'][ip]['tcp'].get(int(port), {})
                    state = port_info.get('state', 'closed')
                    port_results.append({
                        'port': int(port),
                        'state': 'open' if state == 'open' else 'closed'
                    })
                else:
                    port_results.append({
                        'port': int(port),
                        'state': 'closed'
                    })
            
            logger.info(f"[NMAP] {ip} scan complete")
            return port_results
            
        except Exception as e:
            logger.error(f"[NMAP] Scan failed: {e}")
            return self._basic_port_scan(ip, ports)
    
    def _basic_port_scan(self, ip: str, ports: list) -> list:
        """Fallback basic port scan when nmap is not available."""
        port_results = []
        for port in ports:
            check_result = self.check_port(ip, port)
            port_results.append({
                'port': port,
                'state': 'open' if check_result['open'] else 'closed'
            })
        return port_results

    def scan_ports(self, ip: str) -> dict:
        """Parallel port scan. Returns {port: {service, status, open}}"""
        results = {}
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {
                executor.submit(self.check_port, ip, port): (port, service)
                for port, service in self.ports_to_scan.items()
            }
            for future in as_completed(futures):
                port, service = futures[future]
                try:
                    r = future.result()
                    results[port] = {
                        'service': service,
                        'status':  r['status'],
                        'reason':  r.get('reason', ''),
                        'open':    r['open'],
                    }
                except Exception as e:
                    results[port] = {
                        'service': service,
                        'status':  'ERROR',
                        'reason':  str(e),
                        'open':    False,
                    }

        open_c = sum(1 for r in results.values() if r['open'])
        logger.info(f"[PORT] {ip} → {open_c}/{len(results)} open")
        return results

    # ── Main scan ─────────────────────────────────────────────────────────────

    def scan_equipment(self, ip: str, network_cidr: str = None) -> dict:
        """
        Full scan: network validation + ping + ports.

        NEW STATUS LOGIC:
          OUTSIDE = IP not in configured network (CIDR)
          DOWN    = ping FAIL
          WARNING = ping OK + no ports open
          UP      = ping OK + ports open
        """
        if not self.validate_ip(ip):
            raise ValueError(f"Invalid IP: {ip}")

        logger.info(f"[SCAN] {ip}")

        # Step 1 - Check if IP is in configured network
        ip_in_network = self.is_ip_in_network(ip, network_cidr)
        if not ip_in_network:
            # IP outside network - skip ping and port scan
            logger.info(f"[SCAN] {ip} -> OUTSIDE (not in network {network_cidr or getattr(Config, 'LOCAL_NETWORK', '192.168.0.0/16')})")
            return {
                'ip':          ip,
                'ping':        False,
                'ping_ms':     None,
                'packet_loss': 100.0,
                'ports':       {},
                'ports_list':  [],
                'open_ports':  [],
                'status':      'OUTSIDE',
                'timestamp':   datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'reason':      'IP outside configured network',
            }

        # Step 2 - Ping
        ping_data = self.ping_host(ip)
        ping_ok   = ping_data['reachable']

        if not ping_ok:
            # Ping FAIL -> DOWN
            logger.info(f"[SCAN] {ip} -> DOWN (ping failed)")
            return {
                'ip':          ip,
                'ping':        False,
                'ping_ms':     None,
                'packet_loss': ping_data['packet_loss'],
                'ports':       {},
                'ports_list':  [],
                'open_ports':  [],
                'status':      'DOWN',
                'timestamp':   datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'reason':      'Ping failed',
            }

        # Step 3 - Port scan (ping OK)
        port_map = self.scan_ports(ip)

        # Flat list for templates
        ports_list = [
            {
                'port':    port,
                'service': info['service'],
                'status':  info['status'],
                'reason':  info.get('reason', ''),
                'open':    info['open'],
            }
            for port, info in port_map.items()
        ]

        open_ports = [p['port'] for p in ports_list if p['open']]

        # Step 4 - Determine final status
        if len(open_ports) > 0:
            final_status = 'UP'
            reason = 'Ping OK and ports open'
        else:
            final_status = 'Active (No exposed services)'
            reason = 'Ping OK but no exposed services - normal for phones and secured devices'

        result = {
            'ip':          ip,
            'ping':        True,
            'ping_ms':     ping_data['avg_ms'],
            'packet_loss': ping_data['packet_loss'],
            'ports':       port_map,      # dict  - used by app.py
            'ports_list':  ports_list,    # list  - used by templates
            'open_ports':  open_ports,
            'status':      final_status,
            'reason':      reason,
            'timestamp':   datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        }

        logger.info(
            f"[SCAN] {ip} -> {result['status']} | "
            f"ping_ms={result['ping_ms']} | open_ports={open_ports} | {reason}"
        )
        return result

    # ── VLAN sweep ────────────────────────────────────────────────────────────

    def scan_vlan(self, network_cidr: str, max_hosts: int = 254) -> list:
        """
        Discover live hosts in a CIDR range.
        Included only if ping returncode == 0.
        """
        import ipaddress

        try:
            network = ipaddress.ip_network(network_cidr, strict=False)
        except ValueError:
            raise ValueError(f"Invalid CIDR: {network_cidr}")

        hosts = [str(h) for h in list(network.hosts())[:max_hosts]]
        if not hosts:
            return []

        logger.info(f"[VLAN SCAN] {network_cidr} — pinging {len(hosts)} hosts")

        # Parallel ping sweep
        live = []
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = {executor.submit(self.ping_host, ip): ip for ip in hosts}
            for future in as_completed(futures):
                ip = futures[future]
                try:
                    r = future.result()
                    if r['reachable']:       # ping returncode 0 only
                        live.append((ip, r))
                except Exception:
                    pass

        logger.info(f"[VLAN SCAN] {len(live)}/{len(hosts)} hosts alive")

        # Port scan live hosts
        results = []
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {
                executor.submit(self.scan_ports, ip): (ip, ping_data)
                for ip, ping_data in live
            }
            for future in as_completed(futures):
                ip, ping_data = futures[future]
                try:
                    port_map = future.result()
                except Exception:
                    port_map = {}

                ports_list = [
                    {
                        'port':    p,
                        'service': info['service'],
                        'status':  info['status'],
                        'open':    info['open'],
                    }
                    for p, info in port_map.items()
                ]
                open_ports = [p['port'] for p in ports_list if p['open']]

                results.append({
                    'ip':          ip,
                    'ping':        True,
                    'ping_ms':     ping_data['avg_ms'],
                    'packet_loss': ping_data['packet_loss'],
                    'ports':       port_map,
                    'ports_list':  ports_list,
                    'open_ports':  open_ports,
                    'status':      'UP',
                    'timestamp':   datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                })

        results.sort(key=lambda r: list(map(int, r['ip'].split('.'))))
        return results

    # ── Parse helpers ─────────────────────────────────────────────────────────

    @staticmethod
    def _parse_avg_ms(output: str, system: str):
        try:
            if system == 'windows':
                m = re.search(r'Average\s*=\s*(\d+)ms', output, re.IGNORECASE)
            else:
                m = re.search(r'rtt .+= [\d.]+/([\d.]+)/', output)
            if m:
                return float(m.group(1))
        except Exception:
            pass
        return None

    @staticmethod
    def _parse_packet_loss(output: str, system: str) -> float:
        try:
            if system == 'windows':
                m = re.search(r'(\d+)%\s+loss', output, re.IGNORECASE)
            else:
                m = re.search(r'(\d+(?:\.\d+)?)%\s+packet loss', output)
            if m:
                return float(m.group(1))
        except Exception:
            pass
        return 100.0


# Multi-subnet and VLAN-aware scanning methods
    def detect_subnet_from_ip(self, ip: str) -> str:
        """
        Automatically detect the most likely subnet for a given IP.
        Returns CIDR notation (e.g., '192.168.10.0/24').
        """
        import ipaddress
        
        try:
            ip_obj = ipaddress.IPv4Address(ip)
            
            # Common subnet sizes to try (in order of likelihood)
            common_masks = [24, 23, 22, 16, 8]  # /24, /23, /22, /16, /8
            
            for mask in common_masks:
                network = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
                if network.network_address == ip_obj:
                    continue  # Skip if IP is the network address
                
                # For /24 and smaller, assume standard private network classes
                if mask >= 24:
                    return str(network)
                # For /16 and larger, check if it's a standard private network
                elif mask == 16:
                    if ip_obj.is_private and (ip_obj.packed[0] in [192, 172, 10]):
                        return str(network)
                elif mask == 8:
                    if ip_obj.is_private:
                        return str(network)
            
            # Default to /24 if nothing else matches
            network = ipaddress.IPv4Network(f"{ip}/24", strict=False)
            return str(network)
            
        except Exception as e:
            logger.error(f"[SUBNET DETECTION] Error detecting subnet for {ip}: {e}")
            # Fallback to /24
            return f"{ip}/24"
    
    def scan_multiple_subnets(self, targets: list) -> list:
        """
        Scan multiple IPs across different subnets/VLANs.
        Automatically groups IPs by subnet and scans each subnet efficiently.
        
        Args:
            targets: List of IPs or CIDR networks (e.g., ['192.168.10.21', '192.168.20.0/24'])
        
        Returns:
            List of scan results from all subnets
        """
        import ipaddress
        
        logger.info(f"[MULTI-SUBNET] Starting scan for {len(targets)} targets")
        
        # Group targets by subnet
        subnet_groups = {}
        individual_ips = []
        
        for target in targets:
            try:
                # Check if target is already a CIDR network
                if '/' in target:
                    network = ipaddress.IPv4Network(target, strict=False)
                    subnet_key = str(network)
                    subnet_groups[subnet_key] = {
                        'type': 'cidr',
                        'network': network,
                        'targets': list(network.hosts())
                    }
                else:
                    # Individual IP - detect its subnet
                    subnet = self.detect_subnet_from_ip(target)
                    if subnet not in subnet_groups:
                        subnet_groups[subnet] = {
                            'type': 'detected',
                            'network': ipaddress.IPv4Network(subnet, strict=False),
                            'targets': set()
                        }
                    subnet_groups[subnet]['targets'].add(ipaddress.IPv4Address(target))
                    
            except Exception as e:
                logger.error(f"[MULTI-SUBNET] Invalid target {target}: {e}")
                continue
        
        # Convert target sets to lists and limit scan size
        for subnet_key, group in subnet_groups.items():
            if isinstance(group['targets'], set):
                group['targets'] = list(group['targets'])
            
            # Limit to reasonable number of hosts per subnet
            max_hosts = 254 if group['type'] == 'cidr' else 50
            if len(group['targets']) > max_hosts:
                group['targets'] = group['targets'][:max_hosts]
                logger.info(f"[MULTI-SUBNET] Limited {subnet_key} to {max_hosts} hosts")
        
        logger.info(f"[MULTI-SUBNET] Organized into {len(subnet_groups)} subnets")
        
        # Scan each subnet group
        all_results = []
        
        for subnet_key, group in subnet_groups.items():
            subnet_name = f"{group['network'].network_address}/{group['network'].prefixlen}"
            logger.info(f"[MULTI-SUBNET] Scanning subnet {subnet_name} ({len(group['targets'])} hosts)")
            
            # Convert IP objects to strings for scanning
            ip_targets = [str(ip) for ip in group['targets']]
            
            try:
                if group['type'] == 'cidr':
                    # Use existing VLAN scan for CIDR networks
                    subnet_results = self.scan_vlan(subnet_key, max_hosts=len(ip_targets))
                else:
                    # Use individual scans for detected subnets
                    subnet_results = self._scan_individual_hosts(ip_targets)
                
                # Add subnet information to results
                for result in subnet_results:
                    result['subnet'] = subnet_name
                    result['subnet_type'] = group['type']
                
                all_results.extend(subnet_results)
                
                # Log subnet results
                up_count = sum(1 for r in subnet_results if r['status'] == 'UP')
                logger.info(f"[MULTI-SUBNET] {subnet_name}: {up_count}/{len(subnet_results)} hosts UP")
                
            except Exception as e:
                logger.error(f"[MULTI-SUBNET] Error scanning {subnet_name}: {e}")
                continue
        
        # Sort results by IP for consistency
        all_results.sort(key=lambda r: tuple(map(int, r['ip'].split('.'))))
        
        # Final summary
        total_up = sum(1 for r in all_results if r['status'] == 'UP')
        logger.info(
            f"[MULTI-SUBNET] Completed: {total_up}/{len(all_results)} hosts UP "
            f"across {len(subnet_groups)} subnets"
        )
        
        return all_results
    
    def _scan_individual_hosts(self, ip_list: list) -> list:
        """
        Scan individual hosts with full port scanning for each.
        Used for detected subnets where we want detailed results.
        """
        logger.info(f"[INDIVIDUAL] Scanning {len(ip_list)} individual hosts")
        
        results = []
        
        # Full scan each host (ping + ports)
        with ThreadPoolExecutor(max_workers=30) as executor:
            futures = {executor.submit(self.scan_equipment, ip): ip for ip in ip_list}
            
            for future in as_completed(futures):
                ip = futures[future]
                try:
                    result = future.result()
                    results.append(result)
                    
                    status = result['status']
                    open_ports = len(result.get('open_ports', []))
                    logger.debug(f"[INDIVIDUAL] {ip} -> {status} ({open_ports} ports)")
                    
                except Exception as e:
                    logger.error(f"[INDIVIDUAL] Error scanning {ip}: {e}")
                    results.append({
                        'ip': ip,
                        'ping': False,
                        'ping_ms': None,
                        'packet_loss': 100.0,
                        'ports': {},
                        'ports_list': [],
                        'open_ports': [],
                        'status': 'DOWN',
                        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        'error': str(e)
                    })
        
        return results
    
    def scan_cross_vlan(self, target_ips: list, max_concurrent_subnets: int = 5) -> dict:
        """
        Advanced cross-VLAN scanning with routing awareness.
        Simulates Nmap-like behavior across multiple network segments.
        
        Args:
            target_ips: List of target IPs that may be in different VLANs
            max_concurrent_subnets: Maximum subnets to scan simultaneously
        
        Returns:
            Dict with scan results organized by subnet
        """
        import ipaddress
        from collections import defaultdict
        
        logger.info(f"[CROSS-VLAN] Starting cross-VLAN scan for {len(target_ips)} targets")
        
        # Organize targets by actual network segments
        network_segments = defaultdict(list)
        
        for ip in target_ips:
            try:
                ip_obj = ipaddress.IPv4Address(ip)
                
                # Determine network segment based on IP class and routing assumptions
                if ip_obj.is_private:
                    if ip_obj.packed[0] == 10:  # 10.0.0.0/8
                        segment = f"10.{ip_obj.packed[1]}.0.0/16"
                    elif ip_obj.packed[0] == 172 and 16 <= ip_obj.packed[1] <= 31:  # 172.16.0.0/12
                        segment = f"172.{ip_obj.packed[1]}.0.0/16"
                    elif ip_obj.packed[0] == 192 and ip_obj.packed[1] == 168:  # 192.168.0.0/16
                        segment = f"192.168.{ip_obj.packed[2]}.0/24"
                    else:
                        segment = f"{ip}/24"  # Fallback
                else:
                    segment = f"{ip}/32"  # Public IP - scan individually
                
                network_segments[segment].append(ip)
                
            except Exception as e:
                logger.error(f"[CROSS-VLAN] Invalid IP {ip}: {e}")
                continue
        
        logger.info(f"[CROSS-VLAN] Organized into {len(network_segments)} network segments")
        
        # Scan each segment with controlled concurrency
        all_results = {}
        segment_count = 0
        
        for segment, ips in network_segments.items():
            segment_count += 1
            
            # Limit concurrent subnet scanning
            if segment_count > max_concurrent_subnets:
                logger.info(f"[CROSS-VLAN] Reached max concurrent subnets ({max_concurrent_subnets})")
                break
            
            logger.info(f"[CROSS-VLAN] Scanning segment {segment} ({len(ips)} hosts)")
            
            try:
                # Use appropriate scanning method based on segment type
                if '/' in segment and segment.endswith('/24'):
                    # Standard /24 subnet - use VLAN scan
                    results = self.scan_vlan(segment, max_hosts=len(ips))
                elif '/' in segment and segment.endswith('/16'):
                    # Larger /16 network - limit scope and use individual scans
                    target_subnet = self.detect_subnet_from_ip(ips[0])
                    results = self._scan_individual_hosts(ips)
                else:
                    # Individual hosts or unusual segments
                    results = self._scan_individual_hosts(ips)
                
                # Filter results to only include our target IPs
                filtered_results = [r for r in results if r['ip'] in ips]
                
                # Add segment metadata
                for result in filtered_results:
                    result['network_segment'] = segment
                    result['routing_assumed'] = True
                
                all_results[segment] = {
                    'segment': segment,
                    'total_hosts': len(ips),
                    'scanned_hosts': len(filtered_results),
                    'up_hosts': sum(1 for r in filtered_results if r['status'] == 'UP'),
                    'results': filtered_results
                }
                
                # Log segment completion
                up_count = sum(1 for r in filtered_results if r['status'] == 'UP')
                logger.info(f"[CROSS-VLAN] {segment}: {up_count}/{len(filtered_results)} hosts UP")
                
            except Exception as e:
                logger.error(f"[CROSS-VLAN] Error scanning segment {segment}: {e}")
                all_results[segment] = {
                    'segment': segment,
                    'error': str(e),
                    'results': []
                }
        
        # Generate summary
        total_scanned = sum(seg.get('scanned_hosts', 0) for seg in all_results.values())
        total_up = sum(seg.get('up_hosts', 0) for seg in all_results.values())
        
        logger.info(
            f"[CROSS-VLAN] Completed: {total_up}/{total_scanned} hosts UP "
            f"across {len(all_results)} network segments"
        )
        
        return {
            'summary': {
                'total_segments': len(all_results),
                'total_scanned': total_scanned,
                'total_up': total_up,
                'segments_scanned': list(all_results.keys())
            },
            'segments': all_results
        }

# Singleton
scanner = NetworkScanner()