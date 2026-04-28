import ipaddress
import logging
import subprocess
import re

logger = logging.getLogger(__name__)

# ==============================
# 🔥 1. Detect local network auto
# ==============================
def get_network_from_ipconfig():
    try:
        output = subprocess.check_output("ipconfig", shell=True).decode(errors="ignore")

        ip_match = re.search(r"IPv4 Address.*: (\d+\.\d+\.\d+\.\d+)", output)
        mask_match = re.search(r"Subnet Mask.*: (\d+\.\d+\.\d+\.\d+)", output)

        if ip_match and mask_match:
            ip = ip_match.group(1)
            mask = mask_match.group(1)

            network = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
            return network

    except Exception as e:
        logger.error(f"Error detecting network: {e}")
    
    return None


# ==============================
# 🔥 2. Check if IP is allowed
# ==============================
def is_ip_in_local_network(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)

        local_network = get_network_from_ipconfig()

        if local_network and ip in local_network:
            return True

        # Allow localhost
        if ip in ipaddress.ip_network('127.0.0.0/8'):
            return True

        return False

    except Exception as e:
        logger.error(f"Error validating IP {ip_str}: {e}")
        return False


# ==============================
# 🔥 3. Validate IP (for UI)
# ==============================
def validate_ip_security(ip_str):
    try:
        ipaddress.ip_address(ip_str)

        if is_ip_in_local_network(ip_str):
            return True, "IP is allowed (local network)"
        else:
            return False, "IP is not in your local network"

    except ValueError:
        return False, f"Invalid IP format: {ip_str}"
    except Exception as e:
        return False, f"Error: {e}"


# ==============================
# 🔥 4. Get network info (for dashboard)
# ==============================
def get_network_info():
    try:
        network = get_network_from_ipconfig()

        if not network:
            return None

        return {
            'network': str(network.network_address),
            'netmask': str(network.netmask),
            'broadcast': str(network.broadcast_address),
            'num_addresses': network.num_addresses,
            'first_usable': str(network.network_address + 1),
            'last_usable': str(network.broadcast_address - 1)
        }

    except Exception as e:
        logger.error(f"Error getting network info: {e}")
        return None