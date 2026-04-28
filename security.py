# security.py
"""
Security layer for the network scanner.
- Only allows scanning of private/local network IPs
- Rate limiting per user to prevent abuse
- Full logging of all scan attempts (allowed and blocked)
"""

import re
import time
import logging
import ipaddress
import json
from collections import defaultdict
from functools import wraps
from flask import jsonify, request
from flask_login import current_user

import requests as _http_requests

logger = logging.getLogger(__name__)

# ── Private / local network ranges ───────────────────────────────────────────
ALLOWED_NETWORKS = [
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('127.0.0.0/8'),
]

# ── Rate limiter config ───────────────────────────────────────────────────────
_scan_timestamps: dict = defaultdict(list)
RATE_LIMIT_MAX    = 10   # max scans per user
RATE_LIMIT_WINDOW = 60   # seconds


# ── IP validation ─────────────────────────────────────────────────────────────

def is_local_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in ALLOWED_NETWORKS)
    except ValueError:
        return False


def is_valid_ip_format(ip: str) -> bool:
    pattern = (
        r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
        r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    )
    return bool(re.match(pattern, ip or ''))


# ── Rate limiter ──────────────────────────────────────────────────────────────

def check_rate_limit(user_id) -> tuple[bool, int]:
    now          = time.time()
    window_start = now - RATE_LIMIT_WINDOW
    _scan_timestamps[user_id] = [
        ts for ts in _scan_timestamps[user_id] if ts > window_start
    ]
    count     = len(_scan_timestamps[user_id])
    remaining = max(0, RATE_LIMIT_MAX - count)
    if count >= RATE_LIMIT_MAX:
        return False, 0
    _scan_timestamps[user_id].append(now)
    return True, remaining - 1


def get_rate_limit_reset(user_id) -> int:
    if not _scan_timestamps[user_id]:
        return 0
    oldest   = min(_scan_timestamps[user_id])
    reset_in = int(RATE_LIMIT_WINDOW - (time.time() - oldest))
    return max(0, reset_in)


# ── Authorization check ───────────────────────────────────────────────────────
# FIX: was "user.is_authenticated and user.is_admin()"
# → blocked all non-admin users (zakaria got 403 on /scan_all)
# Now any logged-in user can scan. Admins get no extra rate-limit bonus here;
# if you want admins to have unlimited scans, add: if user.is_admin(): return True

def can_scan(user) -> bool:
    return user.is_authenticated          # ← tous les users connectés peuvent scanner


# ── Decorator for scan routes ─────────────────────────────────────────────────

def scan_protected(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        # ── 1. Authentication check ───────────────────────────────────────
        if not can_scan(current_user):
            logger.warning(
                f"[SECURITY] Unauthorized scan attempt by user "
                f"'{getattr(current_user, 'username', 'anonymous')}' "
                f"from {request.remote_addr}"
            )
            if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({
                    'error': 'Unauthorized — please log in',
                    'code':  'UNAUTHORIZED'
                }), 403
            from flask import abort
            abort(403)

        # ── 2. Rate-limit check ───────────────────────────────────────────
        # Admins bypass the rate limit entirely
        if not current_user.is_admin():
            allowed, remaining = check_rate_limit(current_user.id)
            if not allowed:
                reset_in = get_rate_limit_reset(current_user.id)
                logger.warning(
                    f"[SECURITY] Rate limit exceeded for user "
                    f"'{current_user.username}' — reset in {reset_in}s"
                )
                if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    return jsonify({
                        'error':    f'Rate limit exceeded. Try again in {reset_in} seconds.',
                        'code':     'RATE_LIMITED',
                        'reset_in': reset_in,
                    }), 429
                from flask import flash, redirect, url_for
                flash(f'Too many scans. Please wait {reset_in} seconds.', 'warning')
                return redirect(url_for('equipements'))

        return f(*args, **kwargs)
    return decorated


# ── IP guard ──────────────────────────────────────────────────────────────────

def validate_scan_target(ip: str, user) -> tuple[bool, str]:
    if not is_valid_ip_format(ip):
        msg = f"Invalid IP address format: '{ip}'"
        logger.warning(f"[SECURITY] {msg} -- user '{user.username}'")
        return False, msg

    try:
        from database import db
        networks = db.get_all_networks()

        if not networks:
            # No networks configured → fall back to global private-IP check
            if not is_local_ip(ip):
                msg = (
                    f"IP '{ip}' is outside the local network. "
                    f"Only private IPs (192.168.x.x, 10.x.x.x, 172.16.x.x) are allowed."
                )
                logger.warning(f"[SECURITY] Blocked external scan: {ip} by '{user.username}'")
                return False, msg
        else:
            ip_addr          = ipaddress.ip_address(ip)
            found_in_network = False
            for network in networks:
                try:
                    if ip_addr in ipaddress.ip_network(network['cidr']):
                        found_in_network = True
                        break
                except ValueError:
                    continue
            if not found_in_network:
                msg = (
                    f"IP '{ip}' is not in any configured network. "
                    f"Please add the appropriate network first."
                )
                logger.warning(
                    f"[SECURITY] Blocked scan of unknown network: {ip} by '{user.username}'"
                )
                return False, msg

    except Exception as e:
        logger.error(f"[SECURITY] Error validating IP {ip}: {e}")
        if not is_local_ip(ip):
            return False, f"IP '{ip}' is outside allowed networks and validation failed"

    logger.info(f"[SECURITY] Scan authorized: {ip} by '{user.username}'")
    return True, ""


def validate_ip_in_network(ip: str, network_cidr: str) -> bool:
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(network_cidr)
    except (ValueError, TypeError):
        return False


# ── Ollama AI Integration ─────────────────────────────────────────────────────

def ask_ollama(prompt: str, model: str = None) -> str:
    """
    Send a prompt to Ollama and return the AI response text.
    Tries installed models smallest-first; skips on OOM.
    Never raises — always returns a human-readable string.
    """
    # Step 1 — get installed models
    try:
        tags_resp  = _http_requests.get("http://localhost:11434/api/tags", timeout=10)
        tags_resp.raise_for_status()
        raw_models = tags_resp.json().get("models", [])
    except _http_requests.exceptions.ConnectionError:
        logger.error("[AI] Ollama not running")
        return (
            "⚠️ Ollama service is not running.\n"
            "Start it with:  ollama serve\n"
            "Then try again."
        )
    except Exception as e:
        logger.error(f"[AI] Cannot reach Ollama /api/tags: {e}")
        return f"⚠️ Cannot reach Ollama: {e}"

    if not raw_models:
        return (
            "⚠️ Ollama has no models installed.\n"
            "Run:  ollama pull tinyllama\n"
            "(Only ~600 MB — works on low-RAM machines.)"
        )

    # Step 2 — sort smallest first
    sorted_models  = sorted(raw_models, key=lambda m: m.get("size", 0))
    installed_names = [m["name"] for m in sorted_models]
    logger.info(f"[AI] Installed models (smallest first): {installed_names}")

    # Step 3 — build try-order (preferred model first if specified)
    if model:
        preferred  = [m for m in installed_names if model in m or m.startswith(model.split(":")[0])]
        others     = [m for m in installed_names if m not in preferred]
        try_order  = preferred + others
    else:
        try_order  = installed_names

    logger.info(f"[AI] Will try models in order: {try_order}")

    # Step 4 — try each model
    url        = "http://localhost:11434/api/generate"
    last_error = ""

    for chosen in try_order:
        logger.info(f"[AI] Trying model: {chosen}")
        try:
            resp = _http_requests.post(
                url,
                json={"model": chosen, "prompt": prompt, "stream": False},
                timeout=180,
            )

            if not resp.ok:
                try:
                    err_msg = resp.json().get("error", resp.text)
                except Exception:
                    err_msg = resp.text

                logger.warning(f"[AI] {chosen} → HTTP {resp.status_code}: {err_msg}")

                if resp.status_code == 500 and "memory" in err_msg.lower():
                    last_error = f"Not enough RAM for '{chosen}' ({err_msg})"
                    logger.warning(f"[AI] OOM for {chosen}, trying next model…")
                    continue

                return (
                    f"⚠️ Ollama error (model: {chosen}).\n"
                    f"Details: {err_msg}"
                )

            text = resp.json().get("response", "").strip()
            if not text:
                return "⚠️ Ollama returned an empty response. Try again."

            logger.info(f"[AI] Success with model: {chosen}")
            return text

        except _http_requests.exceptions.Timeout:
            logger.error(f"[AI] Timeout with model: {chosen}")
            last_error = f"Timed out waiting for '{chosen}'"
            continue
        except Exception as e:
            logger.error(f"[AI] Unexpected error with {chosen}: {e}")
            last_error = str(e)
            continue

    # Step 5 — nothing worked
    return (
        "⚠️ No installed model fits in available RAM.\n\n"
        f"Last error: {last_error}\n\n"
        "Fix — pull a small model (~600 MB):\n"
        "  ollama pull tinyllama\n\n"
        "Or free up RAM and restart Ollama:\n"
        "  ollama serve"
    )


# ── Network Analysis Report Generator ────────────────────────────────────────

PORT_SECURITY_INFO = {
    21:   {"service": "FTP",        "risk": "HIGH",   "description": "Transmits credentials in cleartext"},
    22:   {"service": "SSH",        "risk": "LOW",    "description": "Encrypted remote access"},
    23:   {"service": "Telnet",     "risk": "HIGH",   "description": "Unencrypted remote access — HIGH RISK"},
    25:   {"service": "SMTP",       "risk": "MEDIUM", "description": "Simple Mail Transfer Protocol"},
    53:   {"service": "DNS",        "risk": "LOW",    "description": "Domain Name System"},
    80:   {"service": "HTTP",       "risk": "MEDIUM", "description": "Unencrypted web traffic"},
    110:  {"service": "POP3",       "risk": "MEDIUM", "description": "Email retrieval (unencrypted)"},
    135:  {"service": "RPC",        "risk": "MEDIUM", "description": "Windows RPC endpoint"},
    139:  {"service": "NetBIOS",    "risk": "MEDIUM", "description": "Windows file sharing"},
    143:  {"service": "IMAP",       "risk": "MEDIUM", "description": "Email retrieval (unencrypted)"},
    161:  {"service": "SNMP",       "risk": "MEDIUM", "description": "Network device management"},
    389:  {"service": "LDAP",       "risk": "MEDIUM", "description": "Directory services"},
    443:  {"service": "HTTPS",      "risk": "LOW",    "description": "Encrypted web traffic"},
    445:  {"service": "SMB",        "risk": "MEDIUM", "description": "Windows file sharing"},
    993:  {"service": "IMAPS",      "risk": "LOW",    "description": "Encrypted email retrieval"},
    995:  {"service": "POP3S",      "risk": "LOW",    "description": "Encrypted email retrieval"},
    1433: {"service": "MSSQL",      "risk": "MEDIUM", "description": "Microsoft SQL Server"},
    1521: {"service": "Oracle",     "risk": "MEDIUM", "description": "Oracle Database"},
    3306: {"service": "MySQL",      "risk": "MEDIUM", "description": "MySQL Database"},
    3389: {"service": "RDP",        "risk": "MEDIUM", "description": "Windows Remote Desktop"},
    5432: {"service": "PostgreSQL", "risk": "MEDIUM", "description": "PostgreSQL Database"},
    5900: {"service": "VNC",        "risk": "MEDIUM", "description": "Virtual Network Computing"},
    6379: {"service": "Redis",      "risk": "MEDIUM", "description": "Redis in-memory database"},
    8080: {"service": "HTTP-Alt",   "risk": "MEDIUM", "description": "Alternate HTTP port"},
    8443: {"service": "HTTPS-Alt",  "risk": "LOW",    "description": "Alternate HTTPS port"},
}


def analyze_device_type(ip: str, open_ports: list) -> str:
    if not open_ports:
        return "Unknown"
    if {53, 161, 443, 80, 8080}.intersection(set(open_ports)):
        return "Router/Network Device"
    if len({22, 80, 443, 3306, 5432, 1433, 25, 110, 143}.intersection(set(open_ports))) >= 2:
        return "Server"
    if {135, 139, 445, 3389}.intersection(set(open_ports)):
        return "Windows PC"
    if {22, 111, 2049}.intersection(set(open_ports)):
        return "Linux/Unix System"
    return "Generic Device"


def calculate_device_risk(status: str, open_ports: list) -> str:
    if status == "DOWN":
        return "LOW"
    if not open_ports:
        return "MEDIUM"
    score = 0
    for port in open_ports:
        if port in [21, 23]:
            score += 3
        elif port in PORT_SECURITY_INFO:
            score += 2 if PORT_SECURITY_INFO[port]["risk"] == "HIGH" else 1
    if len(open_ports) > 10:
        score += 2
    elif len(open_ports) > 5:
        score += 1
    return "HIGH" if score >= 4 else "MEDIUM" if score >= 2 else "LOW"


def identify_issues(status: str, open_ports: list) -> list:
    issues = []
    if status == "DOWN":
        return ["Device is DOWN — unreachable"]
    if 21 in open_ports:
        issues.append("FTP (21) — transmits credentials in cleartext")
    if 23 in open_ports:
        issues.append("Telnet (23) — HIGH RISK: unencrypted remote access")
    if len(open_ports) > 10:
        issues.append(f"Too many open ports ({len(open_ports)}) — increases attack surface")
    unenc = []
    if 80 in open_ports and 443 not in open_ports:
        unenc.append("HTTP without HTTPS")
    if 110 in open_ports and 995 not in open_ports:
        unenc.append("POP3 without encryption")
    if 143 in open_ports and 993 not in open_ports:
        unenc.append("IMAP without encryption")
    if unenc:
        issues.append(f"Unencrypted services: {', '.join(unenc)}")
    return issues


def generate_recommendations(issues: list, open_ports: list) -> list:
    recs = []
    for issue in issues:
        if "FTP"            in issue: recs.append("Disable FTP — use SFTP/SCP instead")
        elif "Telnet"       in issue: recs.append("Replace Telnet with SSH immediately")
        elif "Too many"     in issue: recs.append("Configure firewall to close unused ports")
        elif "DOWN"         in issue: recs.append("Check device connectivity and power")
        elif "Unencrypted"  in issue:
            if "HTTP"  in issue: recs.append("Enable HTTPS (443) and disable plain HTTP (80)")
            if "POP3"  in issue: recs.append("Use POP3S (995) instead of POP3 (110)")
            if "IMAP"  in issue: recs.append("Use IMAPS (993) instead of IMAP (143)")
    if open_ports:
        recs.append("Keep all services and OS patches up-to-date")
        recs.append("Implement network segmentation for critical services")
    return recs


def generate_network_analysis_report(devices_data: list) -> str:
    if not devices_data:
        return "=== NO DATA ===\nNo device data provided.\n"

    report_lines = []
    total = len(devices_data)
    up = down = risky = 0
    all_ports = []

    for device in devices_data:
        ip     = device.get("ip", "Unknown")
        status = device.get("status", "Unknown").upper()
        ports  = device.get("ports", [])
        open_ports = sorted([p["port"] for p in ports if p.get("status", "").upper() == "OPEN"])

        dtype      = analyze_device_type(ip, open_ports)
        issues     = identify_issues(status, open_ports)
        risk       = calculate_device_risk(status, open_ports)
        recs       = generate_recommendations(issues, open_ports)

        port_desc = []
        for p in open_ports:
            if p in PORT_SECURITY_INFO:
                info = PORT_SECURITY_INFO[p]
                port_desc.append(f"{p}/{info['service']} ({info['risk']} risk)")
            else:
                port_desc.append(f"{p}/Unknown")

        if status == "UP": up   += 1
        else:              down += 1
        if risk in ("MEDIUM", "HIGH"): risky += 1
        all_ports.extend(open_ports)

        report_lines.append(
            f"=== DEVICE ===\n"
            f"IP: {ip}\nStatus: {status}\n"
            f"Open Ports: {', '.join(map(str, open_ports)) or 'None'}\n"
            f"Port Details:\n" + ("\n".join(f"  - {d}" for d in port_desc) or "  - None") + "\n"
            f"Device Type: {dtype}\n"
            f"Issues:\n"     + ("\n".join(f"  - {i}" for i in issues) or "  - None") + "\n"
            f"Risk Level: {risk}\n"
            f"Recommendations:\n" + ("\n".join(f"  - {r}" for r in recs) or "  - None") + "\n"
        )

    freq = {}
    for p in all_ports:
        freq[p] = freq.get(p, 0) + 1
    top5 = ", ".join(
        f"{p}({c})" for p, c in sorted(freq.items(), key=lambda x: -x[1])[:5]
    )

    report_lines.append(
        f"=== GLOBAL SUMMARY ===\n"
        f"Total Devices: {total}\nDevices UP: {up}\nDevices DOWN: {down}\n"
        f"Risky Devices (MEDIUM/HIGH): {risky}\n"
        f"Most Common Open Ports: {top5 or 'None'}\n"
    )
    return "\n".join(report_lines)