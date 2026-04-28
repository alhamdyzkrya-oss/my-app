import bcrypt
import logging
from flask import (Flask, render_template, request, redirect,
                   url_for, flash, session, jsonify, abort)
from flask_login import (LoginManager, UserMixin, login_user, logout_user,
                         login_required, current_user)
import logging
from datetime import datetime
import re
import os
import atexit
from functools import wraps

# Local imports
from database import db
from scanner import NetworkScanner, scanner
from security import ask_ollama, validate_scan_target, scan_protected
from config import Config

# ── Email Notifier ────────────────────────────────────────────────────────────
from email_notifier import init_mail, send_alert_email

# ── Auto-Scan Scheduler ───────────────────────────────────────────────────────
from apscheduler.schedulers.background import BackgroundScheduler

# ── Network Detector ──────────────────────────────────────────────────────────
try:
    from network_detector import network_detector
except ImportError:
    network_detector = None
    logging.warning("[INIT] network_detector module not found – detection routes will be disabled")

logging.basicConfig(level=Config.LOG_LEVEL)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key                           = Config.SECRET_KEY
app.config['SESSION_COOKIE_SECURE']     = Config.SESSION_COOKIE_SECURE
app.config['SESSION_COOKIE_HTTPONLY']   = Config.SESSION_COOKIE_HTTPONLY
app.config['SESSION_COOKIE_SAMESITE']   = Config.SESSION_COOKIE_SAMESITE
app.config['PERMANENT_SESSION_LIFETIME'] = Config.PERMANENT_SESSION_LIFETIME

app.config['DEBUG']                      = True
app.config['TEMPLATES_AUTO_RELOAD']      = True
app.config['SEND_FILE_MAX_AGE_DEFAULT']  = 0
app.jinja_env.auto_reload                = True

# ── Init Flask-Mail ───────────────────────────────────────────────────────────
init_mail(app)

# ── Flask-Login ───────────────────────────────────────────────────────────────
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view    = 'login'
login_manager.login_message = 'Veuillez vous connecter pour accéder à cette application'


class User(UserMixin):
    def __init__(self, id, username, role='user'):
        self.id       = id
        self.username = username
        self.role     = role

    def is_admin(self):
        return self.role == 'admin'


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin():
            abort(403)
        return f(*args, **kwargs)
    return decorated_function


@login_manager.user_loader
def load_user(user_id):
    user_data = db.get_user_by_id(int(user_id))
    if user_data:
        return User(user_data['id'], user_data['username'],
                    user_data.get('role', 'user'))
    return None


# ── Startup ───────────────────────────────────────────────────────────────────
db.init_all_tables()

if not db.get_user_by_username('admin'):
    pw_hash = bcrypt.hashpw('admin123'.encode('utf-8'), bcrypt.gensalt())
    db.create_user('admin', pw_hash.decode('utf-8'), 'admin')
    logger.info("[INIT] Admin user created: admin / admin123")


# ── Auto-Scan Function ────────────────────────────────────────────────────────
def auto_scan_all():
    """تتشغل تلقائياً كل 5 دقايق"""
    with app.app_context():
        try:
            equipments = db.get_all_equipments()
            if not equipments:
                logger.info("[AUTO-SCAN] No equipments to scan")
                return

            logger.info(f"[AUTO-SCAN] Starting scheduled scan for {len(equipments)} devices...")

            for eq in equipments:
                try:
                    network_cidr = None
                    if eq.get('network_id'):
                        network = db.get_network_by_id(eq['network_id'])
                        if network:
                            network_cidr = network['cidr']

                    result     = scanner.scan_equipment(eq['ip'], network_cidr)
                    new_status = result['status']
                    db.update_equipment_status(eq['id'], new_status)
                    db.update_equipment_ports(eq['id'], result.get('ports', []))

                    if new_status == 'DOWN':
                        db.creer_alerte_unique(eq['id'], 'ping_failed',
                            f"[AUTO] {eq['nom']} ({eq['ip']}) ne répond pas", 'critique')
                        send_alert_email(
                            alert_type='ping_failed',
                            equipment_name=eq['nom'],
                            ip=eq['ip'],
                            message="[AUTO-SCAN] Device ne répond pas au ping",
                            severity='critique'
                        )
                    elif new_status == 'OUTSIDE':
                        db.creer_alerte_unique(eq['id'], 'ip_outside_network',
                            f"[AUTO] {eq['nom']} ({eq['ip']}) hors réseau", 'critique')
                        send_alert_email(
                            alert_type='ip_outside_network',
                            equipment_name=eq['nom'],
                            ip=eq['ip'],
                            message="[AUTO-SCAN] IP hors réseau configuré",
                            severity='critique'
                        )
                    elif new_status == 'Active (No exposed services)':
                        db.creer_alerte_unique(eq['id'], 'no_ports_open',
                            f"[AUTO] {eq['nom']} ({eq['ip']}) actif sans services", 'info')

                except Exception as e:
                    logger.error(f"[AUTO-SCAN] Error scanning {eq['ip']}: {e}")

            logger.info(f"[AUTO-SCAN] Completed — {len(equipments)} devices scanned")

        except Exception as e:
            logger.error(f"[AUTO-SCAN] Fatal error: {e}")


# ── Start Scheduler ───────────────────────────────────────────────────────────
scheduler = BackgroundScheduler()
scheduler.add_job(
    func=auto_scan_all,
    trigger='interval',
    minutes=5,
    id='auto_scan',
    name='Automatic Network Scan',
    replace_existing=True
)
scheduler.start()
atexit.register(lambda: scheduler.shutdown())
logger.info("[SCHEDULER] Auto-scan started — every 5 minutes")


# ── Custom Template Filters ───────────────────────────────────────────────────
@app.template_filter('from_json')
def from_json_filter(value):
    if value is None:
        return []
    if isinstance(value, str):
        try:
            import json
            return json.loads(value)
        except (json.JSONDecodeError, TypeError):
            return []
    return value if (isinstance(value, list) or isinstance(value, dict)) else []


# ── Global template context ───────────────────────────────────────────────────
@app.context_processor
def inject_globals():
    count = 0
    if current_user.is_authenticated:
        try:
            count = len(db.get_alertes_non_lues())
        except Exception:
            pass
    return {'global_alertes_count': count}


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route('/')
def root():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username         = request.form.get('username', '').strip()
        email            = request.form.get('email', '').strip()
        password         = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')

        if not username or not email or not password:
            flash('All fields are required', 'error')
            return render_template('signup.html')

        if len(username) < 3 or len(username) > 20:
            flash('Username must be between 3 and 20 characters', 'error')
            return render_template('signup.html')

        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return render_template('signup.html')

        if len(password) < 8:
            flash('Password must be at least 8 characters long', 'error')
            return render_template('signup.html')

        email_pattern = r'^[^\s@]+@[^\s@]+\.[^\s@]+$'
        if not re.match(email_pattern, email):
            flash('Please enter a valid email address', 'error')
            return render_template('signup.html')

        try:
            from werkzeug.security import generate_password_hash
            password_hash = generate_password_hash(password, method='scrypt', salt_length=16)
            db.create_user(username, email, password_hash, role='user')
            flash('Account created successfully! Please log in.', 'success')
            return redirect(url_for('login'))

        except ValueError as e:
            flash(str(e), 'error')
            return render_template('signup.html')
        except Exception as e:
            logger.error(f"Error creating user: {e}")
            flash('An error occurred while creating your account', 'error')
            return render_template('signup.html')

    return render_template('signup.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        user_data = db.get_user_by_username_or_email(username)
        if user_data:
            password_hash = user_data['password_hash']

            if password_hash.startswith(('pbkdf2:', 'scrypt:', 'sha256$')):
                try:
                    from werkzeug.security import check_password_hash
                    if check_password_hash(password_hash, password):
                        user = User(user_data['id'], user_data['username'],
                                    user_data.get('role', 'user'))
                        login_user(user)
                        flash(f'Welcome back {user_data["username"]}!', 'success')
                        return redirect(url_for('dashboard'))
                except Exception:
                    pass
            else:
                try:
                    if bcrypt.checkpw(
                        password.encode('utf-8'),
                        password_hash.encode('utf-8')
                    ):
                        user = User(user_data['id'], user_data['username'],
                                    user_data.get('role', 'user'))
                        login_user(user)
                        flash(f'Welcome back {user_data["username"]}!', 'success')
                        return redirect(url_for('dashboard'))
                except Exception:
                    pass

        flash("Nom d'utilisateur ou mot de passe incorrect", 'error')

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Vous avez été déconnecté', 'info')
    return redirect(url_for('login'))


@app.route('/dashboard')
@login_required
def dashboard():
    stats       = db.get_stats()
    equipements = db.get_all_equipments()
    alertes     = db.get_alertes_non_lues()
    return render_template('dashboard.html',
                           stats=stats,
                           equipements=equipements,
                           alertes=alertes,
                           current_user=current_user)


@app.route('/equipements')
@login_required
def equipements():
    equipments       = db.get_all_equipments()
    alertes_non_lues = db.get_alertes_non_lues()
    stats            = db.get_stats()
    return render_template('index.html',
                           equipments=equipments,
                           alertes_non_lues=alertes_non_lues,
                           stats=stats,
                           current_user=current_user)


@app.route('/add_device', methods=['GET', 'POST'])
@login_required
def add_device():
    if request.method == 'POST':
        nom             = request.form.get('nom', '').strip()
        ip              = request.form.get('ip', '').strip()
        type_equipement = request.form.get('type')
        description     = request.form.get('description', '').strip()
        network_id      = request.form.get('network_id')

        if network_id:
            try:
                network_id = int(network_id)
            except ValueError:
                network_id = None

        try:
            is_valid, reason = validate_scan_target(ip, current_user)
            if not is_valid:
                flash(f'Security error: {reason}', 'error')
                networks = db.get_networks_for_dropdown()
                return render_template('add_equipment.html',
                                       equipment_types=Config.EQUIPMENT_TYPES,
                                       networks=networks,
                                       nom=nom, ip=ip,
                                       type_equipement=type_equipement,
                                       description=description,
                                       network_id=network_id)

            db.update_equipment_with_network_validation(nom, ip, type_equipement, description, network_id)
            flash(f'Device {nom} added successfully', 'success')
            return redirect(url_for('dashboard'))
        except ValueError as e:
            flash(f'Error: {str(e)}', 'error')
        except Exception as e:
            logger.error(f"Error adding device: {e}")
            flash('Technical error, please try again', 'error')

    networks = db.get_networks_for_dropdown()
    return render_template('add_equipment.html',
                           equipment_types=Config.EQUIPMENT_TYPES,
                           networks=networks)


@app.route('/delete/<int:equipment_id>', methods=['GET', 'POST'])
@login_required
def delete_equipment(equipment_id):
    try:
        db.delete_equipment(equipment_id)
        flash('Équipement supprimé', 'success')
    except ValueError as e:
        flash(str(e), 'error')
    except Exception as e:
        logger.error(f"Error deleting equipment {equipment_id}: {e}")
        flash('Erreur technique, veuillez réessayer', 'error')
    return redirect(url_for('dashboard'))


@app.route('/scan/equipment/<int:equipment_id>')
@login_required
@scan_protected
def scan_equipment(equipment_id):
    equipment = db.get_equipment_by_id(equipment_id)
    if not equipment:
        flash('Équipement non trouvé', 'error')
        return redirect(url_for('equipements'))

    try:
        network_cidr = None
        if equipment.get('network_id'):
            network = db.get_network_by_id(equipment['network_id'])
            if network:
                network_cidr = network['cidr']

        scan_results = scanner.scan_equipment(equipment['ip'], network_cidr)
        new_status   = scan_results['status']
        db.update_equipment_status(equipment_id, new_status)
        db.update_equipment_ports(equipment_id, scan_results.get('ports', []))

        if scan_results['status'] == 'OUTSIDE':
            db.creer_alerte_unique(equipment_id, 'ip_outside_network',
                f"Équipement {equipment['nom']} ({equipment['ip']}) "
                f"est en dehors du réseau configuré", 'critique')
            send_alert_email(
                alert_type='ip_outside_network',
                equipment_name=equipment['nom'],
                ip=equipment['ip'],
                message="IP est en dehors du réseau configuré",
                severity='critique'
            )
        elif scan_results['status'] == 'DOWN':
            db.creer_alerte_unique(equipment_id, 'ping_failed',
                f"Équipement {equipment['nom']} ({equipment['ip']}) "
                f"ne répond pas au ping", 'critique')
            send_alert_email(
                alert_type='ping_failed',
                equipment_name=equipment['nom'],
                ip=equipment['ip'],
                message="Device ne répond pas au ping",
                severity='critique'
            )
        elif scan_results['status'] == 'Active (No exposed services)':
            db.creer_alerte_unique(equipment_id, 'no_ports_open',
                f"Équipement {equipment['nom']} ({equipment['ip']}) "
                f"est actif mais aucun service exposé", 'info')
            send_alert_email(
                alert_type='no_ports_open',
                equipment_name=equipment['nom'],
                ip=equipment['ip'],
                message="Device actif mais aucun service exposé",
                severity='info'
            )
        else:
            critical_ports = {22: 'SSH', 80: 'HTTP', 443: 'HTTPS'}
            for port_info in scan_results.get('ports', []):
                if isinstance(port_info, dict) and port_info.get('port') in critical_ports \
                        and port_info.get('status') == 'CLOSED':
                    service = critical_ports[port_info['port']]
                    db.creer_alerte_unique(equipment_id, 'port_ferme',
                        f"Port {port_info['port']} ({service}) fermé sur {equipment['nom']}",
                        'important')
                    send_alert_email(
                        alert_type='port_ferme',
                        equipment_name=equipment['nom'],
                        ip=equipment['ip'],
                        message=f"Port {port_info['port']} ({service}) fermé",
                        severity='important'
                    )

        return render_template('scan_result.html', equipment=equipment, scan=scan_results)

    except ValueError as e:
        flash(str(e), 'error')
    except Exception as e:
        logger.error(f"Error scanning equipment {equipment_id}: {e}")
        flash(f'Erreur lors du scan: {str(e)}', 'error')

    return redirect(url_for('equipements'))


@app.route('/scan')
@login_required
@scan_protected
def scan():
    return redirect(url_for('scan_all'))


@app.route('/scan_all')
@login_required
@scan_protected
def scan_all():
    try:
        equipments = db.get_all_equipments()
        if not equipments:
            flash('Aucun équipement à scanner', 'info')
            return redirect(url_for('equipements'))

        all_networks = db.get_all_networks()
        if not all_networks:
            if network_detector is None:
                flash('No networks configured and network_detector module is unavailable', 'warning')
                return redirect(url_for('equipements'))
            logger.info("[SCAN_ALL] No networks found - triggering auto-detection")
            try:
                detected_networks = network_detector.detect_networks()
                if detected_networks:
                    db.store_detected_networks(detected_networks)
                    flash(f'Auto-detected {len(detected_networks)} networks before scanning', 'info')
                else:
                    flash('No networks configured and auto-detection failed', 'warning')
                    return redirect(url_for('equipements'))
            except Exception as e:
                logger.error(f"[SCAN_ALL] Auto-detection failed: {e}")
                flash('Network auto-detection failed. Please configure networks manually.', 'warning')
                return redirect(url_for('equipements'))

        results = []
        status_counts = {
            'UP': 0, 'DOWN': 0, 'WARNING': 0,
            'OUTSIDE': 0, 'Active (No exposed services)': 0
        }

        for eq in equipments:
            try:
                network_cidr = None
                if eq.get('network_id'):
                    network = db.get_network_by_id(eq['network_id'])
                    if network:
                        network_cidr = network['cidr']

                result     = scanner.scan_equipment(eq['ip'], network_cidr)
                new_status = result['status']
                db.update_equipment_status(eq['id'], new_status)
                db.update_equipment_ports(eq['id'], result.get('ports', []))

                status_counts[new_status] = status_counts.get(new_status, 0) + 1

                if new_status == 'OUTSIDE':
                    db.creer_alerte_unique(eq['id'], 'ip_outside_network',
                        f"Équipement {eq['nom']} ({eq['ip']}) est en dehors du réseau configuré",
                        'critique')
                    send_alert_email(
                        alert_type='ip_outside_network',
                        equipment_name=eq['nom'],
                        ip=eq['ip'],
                        message="IP est en dehors du réseau configuré",
                        severity='critique'
                    )
                elif new_status == 'DOWN':
                    db.creer_alerte_unique(eq['id'], 'ping_failed',
                        f"Équipement {eq['nom']} ({eq['ip']}) ne répond pas", 'critique')
                    send_alert_email(
                        alert_type='ping_failed',
                        equipment_name=eq['nom'],
                        ip=eq['ip'],
                        message="Device ne répond pas au ping",
                        severity='critique'
                    )
                elif new_status == 'Active (No exposed services)':
                    db.creer_alerte_unique(eq['id'], 'no_ports_open',
                        f"Équipement {eq['nom']} ({eq['ip']}) est actif mais aucun service exposé",
                        'info')
                    send_alert_email(
                        alert_type='no_ports_open',
                        equipment_name=eq['nom'],
                        ip=eq['ip'],
                        message="Device actif mais aucun service exposé",
                        severity='info'
                    )

                results.append({'equipment': eq, 'scan': result})

            except Exception as e:
                logger.error(f"Error scanning {eq['ip']}: {e}")
                status_counts['DOWN'] = status_counts.get('DOWN', 0) + 1
                results.append({
                    'equipment': eq,
                    'scan': {
                        'ip': eq['ip'], 'ping': False, 'ping_ms': None,
                        'packet_loss': 100.0, 'ports': {}, 'open_ports': [],
                        'status': 'DOWN', 'timestamp': '', 'reason': 'Scan error',
                    }
                })

        status_parts = [f"{count} {status}"
                        for status, count in status_counts.items() if count > 0]
        flash(f'Scan terminé - {len(results)} équipements: {", ".join(status_parts)}', 'success')
        return render_template('scan_result.html', results=results, scan_all=True)

    except Exception as e:
        logger.error(f"Error in scan_all: {e}")
        flash('Erreur lors du scan global', 'error')
        return redirect(url_for('dashboard'))


# ── Multi-subnet / cross-VLAN routes ─────────────────────────────────────────

@app.route('/scan_multiple_subnets', methods=['POST'])
@login_required
@scan_protected
def scan_multiple_subnets_route():
    try:
        data = request.get_json()
        if not data or 'targets' not in data:
            return jsonify({'error': 'No targets provided'}), 400

        targets = data['targets']
        if not isinstance(targets, list) or len(targets) == 0:
            return jsonify({'error': 'Targets must be a non-empty list'}), 400

        import ipaddress
        for target in targets:
            if '/' in target:
                network = ipaddress.IPv4Network(target, strict=False)
                if not network.is_private:
                    return jsonify({'error': f'Only private networks allowed: {target}'}), 403
            else:
                ip = ipaddress.IPv4Address(target)
                if not ip.is_private:
                    return jsonify({'error': f'Only private IPs allowed: {target}'}), 403

        logger.info(f"[MULTI-SUBNET] User {current_user.username} scanning {len(targets)} targets")
        results = scanner.scan_multiple_subnets(targets)

        up_count   = sum(1 for r in results if r['status'] == 'UP')
        down_count = len(results) - up_count

        subnet_groups = {}
        for result in results:
            subnet = result.get('subnet', 'Unknown')
            subnet_groups.setdefault(subnet, []).append(result)

        return jsonify({
            'success': True,
            'summary': {
                'total_scanned':   len(results),
                'total_up':        up_count,
                'total_down':      down_count,
                'subnets_scanned': len(subnet_groups)
            },
            'results':       results,
            'subnet_groups': subnet_groups,
            'message': (f'Multi-subnet scan completed: {up_count} hosts UP, '
                        f'{down_count} hosts DOWN across {len(subnet_groups)} subnets')
        })

    except Exception as e:
        logger.error(f"[MULTI-SUBNET] Error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/scan_cross_vlan', methods=['POST'])
@login_required
@scan_protected
def scan_cross_vlan_route():
    try:
        data = request.get_json()
        if not data or 'targets' not in data:
            return jsonify({'error': 'No targets provided'}), 400

        targets = data['targets']
        if not isinstance(targets, list) or len(targets) == 0:
            return jsonify({'error': 'Targets must be a non-empty list'}), 400

        max_concurrent = data.get('max_concurrent_subnets', 5)

        import ipaddress
        for target in targets:
            ip = ipaddress.IPv4Address(target)
            if not ip.is_private:
                return jsonify({'error': f'Only private IPs allowed: {target}'}), 403

        logger.info(f"[CROSS-VLAN] User {current_user.username} cross-VLAN scan {len(targets)} targets")
        scan_results = scanner.scan_cross_vlan(targets, max_concurrent_subnets=max_concurrent)

        return jsonify({
            'success': True,
            'results': scan_results,
            'message': (f"Cross-VLAN scan completed: "
                        f"{scan_results['summary']['total_up']}/"
                        f"{scan_results['summary']['total_scanned']} hosts UP across "
                        f"{scan_results['summary']['total_segments']} network segments")
        })

    except Exception as e:
        logger.error(f"[CROSS-VLAN] Error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/detect_subnet/<path:ip>')
@login_required
def detect_subnet_route(ip):
    try:
        import ipaddress
        ip_obj = ipaddress.IPv4Address(ip)
        if not ip_obj.is_private:
            return jsonify({'error': 'Only private IPs can be analyzed'}), 403

        subnet = scanner.detect_subnet_from_ip(ip)
        return jsonify({'success': True, 'ip': ip, 'detected_subnet': subnet,
                        'message': f'Detected subnet {subnet} for IP {ip}'})

    except ValueError as e:
        return jsonify({'error': f'Invalid IP: {str(e)}'}), 400
    except Exception as e:
        logger.error(f"[SUBNET DETECTION] Error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/scan_subnet/<path:cidr>')
@login_required
@scan_protected
def scan_subnet_route(cidr):
    try:
        import ipaddress
        network = ipaddress.IPv4Network(cidr, strict=False)
        if not network.is_private:
            flash('Error: Only private networks can be scanned', 'error')
            return redirect(url_for('dashboard'))

        logger.info(f"[SUBNET] User {current_user.username} scanning subnet {cidr}")
        results    = scanner.scan_multiple_subnets([cidr])
        up_count   = sum(1 for r in results if r['status'] == 'UP')
        down_count = len(results) - up_count

        flash(f'Subnet scan completed: {up_count} hosts UP, {down_count} hosts DOWN in {cidr}', 'success')
        return render_template(
            'scan_result.html',
            results=[{'scan': r, 'equipment': {'nom': f'Host {r["ip"]}', 'ip': r['ip']}}
                     for r in results],
            scan_all=True,
            subnet_info={'cidr': cidr, 'up': up_count, 'down': down_count}
        )

    except ValueError as e:
        flash(f'Invalid subnet format: {str(e)}', 'error')
    except Exception as e:
        logger.error(f"Error in subnet scan: {e}")
        flash('Error during subnet scan', 'error')

    return redirect(url_for('dashboard'))


# ── Alert Generation Functions ────────────────────────────────────────────────

def generate_alert_from_scan(scan_result, equipment_name):
    ping_ok    = scan_result.get('ping', False)
    ports      = scan_result.get('ports', [])
    open_ports = []

    for port_info in ports:
        if isinstance(port_info, dict):
            if port_info.get('status') == 'OPEN':
                open_ports.append(port_info.get('port'))
        elif isinstance(port_info, (int, str)):
            open_ports.append(int(port_info))

    if not ping_ok:
        return {'status': 'DOWN', 'alert': 'Device is unreachable', 'severity': 'HIGH'}

    elif ping_ok and open_ports:
        critical_ports   = {21: 'FTP', 22: 'SSH', 80: 'HTTP', 443: 'HTTPS'}
        high_risk_ports  = [21]
        medium_risk_ports = [22, 80]

        alert_messages = []
        severity       = 'MEDIUM'

        for port in open_ports:
            if port in high_risk_ports:
                service = critical_ports.get(port, f'Port {port}')
                alert_messages.append(f'{service} port open → security risk')
                severity = 'HIGH'

        if severity != 'HIGH':
            for port in open_ports:
                if port in medium_risk_ports:
                    service = critical_ports.get(port, f'Port {port}')
                    alert_messages.append(f'{service} port open → potential exposure')

        if len(open_ports) > 3:
            alert_messages.append(f'Multiple ports open ({len(open_ports)}) → increased attack surface')
            severity = 'HIGH'

        if not alert_messages:
            alert_messages.append(f'Device has open ports ({len(open_ports)})')

        return {'status': 'UP', 'alert': '; '.join(alert_messages), 'severity': severity}

    else:
        return {'status': 'ACTIVE', 'alert': 'Secured device (no exposed services)', 'severity': 'LOW'}


# ── API: Scheduler status ─────────────────────────────────────────────────────

@app.route('/api/scheduler/status')
@login_required
def api_scheduler_status():
    try:
        job = scheduler.get_job('auto_scan')
        return jsonify({
            'running':   scheduler.running,
            'job_id':    job.id if job else None,
            'next_run':  str(job.next_run_time) if job else None,
            'interval':  '5 minutes'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/scheduler/trigger', methods=['POST'])
@login_required
@admin_required
def api_trigger_scan():
    """تشغيل الـ auto-scan يدوياً من الـ API"""
    try:
        scheduler.get_job('auto_scan').modify(next_run_time=datetime.now())
        return jsonify({'success': True, 'message': 'Auto-scan triggered manually'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ── API: real-time status ─────────────────────────────────────────────────────

@app.route('/api/equipments/status', methods=['GET'])
@login_required
def api_equipments_status():
    try:
        equipments  = db.get_all_equipments()
        status_data = []
        for eq in equipments:
            ports = []
            if eq.get('open_ports'):
                try:
                    import json
                    raw   = eq['open_ports']
                    ports = json.loads(raw) if isinstance(raw, str) else raw
                    if not isinstance(ports, list):
                        ports = []
                except (json.JSONDecodeError, TypeError):
                    ports = []

            db_status = eq.get('status', 'DOWN')

            if db_status == 'DOWN':
                alert_data = {'status': 'DOWN', 'alert': 'Appareil hors ligne (ping échoué)', 'severity': 'HIGH'}
            elif db_status == 'OUTSIDE':
                alert_data = {'status': 'OUTSIDE', 'alert': 'IP hors réseau configuré', 'severity': 'HIGH'}
            else:
                ping_ok    = db_status not in ('DOWN', 'OUTSIDE')
                scan_result = {'ping': ping_ok, 'ports': ports}
                alert_data  = generate_alert_from_scan(scan_result, eq['nom'])

            status_data.append({
                'id':       eq['id'],
                'nom':      eq['nom'],
                'ip':       eq['ip'],
                'status':   alert_data['status'],
                'type':     eq['type'],
                'ports':    ports,
                'alert':    alert_data['alert'],
                'severity': alert_data['severity']
            })
        return jsonify(status_data)
    except Exception as e:
        logger.error(f"[API] Error getting equipments status: {e}")
        return jsonify({'error': str(e)}), 500


# ── API: scan single device (AJAX) ────────────────────────────────────────────

@app.route('/api/scan/<int:equipment_id>', methods=['POST'])
@login_required
@scan_protected
def api_scan(equipment_id):
    equipment = db.get_equipment_by_id(equipment_id)
    if not equipment:
        return jsonify({'error': 'Equipment not found'}), 404

    try:
        network_cidr = None
        if equipment.get('network_id'):
            network = db.get_network_by_id(equipment['network_id'])
            if network:
                network_cidr = network['cidr']

        result     = scanner.scan_equipment(equipment['ip'], network_cidr)
        new_status = result['status']
        db.update_equipment_status(equipment_id, new_status)
        db.update_equipment_ports(equipment_id, result.get('ports', []))

        if new_status == 'OUTSIDE':
            db.creer_alerte_unique(equipment_id, 'ip_outside_network',
                f"Équipement {equipment['nom']} ({equipment['ip']}) "
                f"est en dehors du réseau configuré", 'critique')
            send_alert_email(
                alert_type='ip_outside_network',
                equipment_name=equipment['nom'],
                ip=equipment['ip'],
                message="IP est en dehors du réseau configuré",
                severity='critique'
            )
        elif new_status == 'DOWN':
            db.creer_alerte_unique(equipment_id, 'ping_failed',
                f"Équipement {equipment['nom']} ne répond pas au ping", 'critique')
            send_alert_email(
                alert_type='ping_failed',
                equipment_name=equipment['nom'],
                ip=equipment['ip'],
                message="Device ne répond pas au ping",
                severity='critique'
            )
        elif new_status == 'Active (No exposed services)':
            db.creer_alerte_unique(equipment_id, 'no_ports_open',
                f"Équipement {equipment['nom']} ({equipment['ip']}) "
                f"est actif mais aucun service exposé", 'info')
            send_alert_email(
                alert_type='no_ports_open',
                equipment_name=equipment['nom'],
                ip=equipment['ip'],
                message="Device actif mais aucun service exposé",
                severity='info'
            )

        alert_data = generate_alert_from_scan(result, equipment['nom'])

        return jsonify({
            'status':      alert_data['status'],
            'ping':        result['ping'],
            'ping_ms':     result.get('ping_ms'),
            'packet_loss': result.get('packet_loss', 100.0),
            'ports':       result.get('open_ports', []),
            'timestamp':   result.get('timestamp', ''),
            'reason':      result.get('reason', ''),
            'alert':       alert_data['alert'],
            'severity':    alert_data['severity']
        })

    except Exception as e:
        logger.error(f"[API] Scan error for {equipment_id}: {e}")
        return jsonify({'error': str(e)}), 500


# ── Mini-Nmap ─────────────────────────────────────────────────────────────────

@app.route('/scan/ip/<path:ip>')
@login_required
def scan_ip(ip):
    try:
        if not scanner.validate_ip(ip):
            return jsonify({'error': 'Invalid IP address format', 'status': 'error'}), 400

        scan_result = scanner.scan_equipment(ip)
        ports       = scanner.scan_ports_nmap(ip, [22, 80, 443, 21])

        scan_result = {
            'ip':        ip,
            'ping':      scan_result['ping'],
            'ping_ms':   scan_result.get('ping_ms'),
            'timestamp': scan_result['timestamp'],
            'ports':     ports
        }
        alert_data = generate_alert_from_scan(scan_result, f'Device {ip}')

        response = {
            'ip':        scan_result['ip'],
            'status':    alert_data['status'],
            'ports':     ports,
            'ping_ms':   scan_result.get('ping_ms'),
            'timestamp': scan_result['timestamp'],
            'alert':     alert_data['alert'],
            'severity':  alert_data['severity']
        }

        logger.info(f"[SCAN] Device scan completed for {ip}: {response['status']}")
        return jsonify(response)

    except ValueError as e:
        return jsonify({'error': str(e), 'status': 'error'}), 400
    except Exception as e:
        logger.error(f"Scan error for {ip}: {e}")
        return jsonify({'error': 'Scan failed', 'status': 'error'}), 500


@app.route('/mini-scan')
@login_required
def mini_scan():
    return render_template('mini_scan.html', current_user=current_user)


# ── Test / debug routes ───────────────────────────────────────────────────────

@app.route('/test-ai')
def test_ai():
    return app.send_static_file('test_ai_button.html')


@app.route('/test-ai-analysis', methods=['POST'])
def test_ai_analysis():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400

        devices = data.get('devices', [])
        if not devices:
            return jsonify({'error': 'No device data provided'}), 400

        device_info = []
        for device in devices:
            ip         = device.get('ip', 'Unknown')
            status     = device.get('status', 'Unknown')
            ports      = device.get('ports', [])
            open_ports = []
            for port in ports:
                if isinstance(port, dict):
                    if port.get('status') == 'OPEN':
                        open_ports.append(port.get('port'))
                elif isinstance(port, (int, str)):
                    open_ports.append(port)
            device_info.append(f"IP: {ip}, Status: {status}, Open Ports: {open_ports}")

        prompt = (
            "As a senior network engineer and cybersecurity expert, "
            "analyze the following network scan results and provide a concise security assessment:\n\n"
            "Device Information:\n" + "\n".join(device_info) +
            "\n\nPlease provide:\n"
            "1. Overall security assessment\n"
            "2. Key security concerns\n"
            "3. Recommended actions\n\n"
            "Keep the analysis brief and actionable."
        )

        ai_response = ask_ollama(prompt)
        logger.info(f"[TEST-AI] Analysis requested for {len(devices)} devices")

        return jsonify({
            'analysis':         ai_response,
            'devices_analyzed': len(devices),
            'timestamp':        None,
            'test_mode':        True
        })

    except Exception as e:
        logger.error(f"[TEST-AI] Error in AI analysis: {e}")
        return jsonify({'error': f'AI analysis failed: {str(e)}'}), 500


# ── AI Report ─────────────────────────────────────────────────────────────────

@app.route('/generate-ai-report', methods=['POST'])
@login_required
def generate_ai_report():
    logger.info(f"[AI] Report requested by '{current_user.username}'")

    try:
        devices = db.get_all_equipments()
        if not devices:
            return jsonify({'error': 'No devices found in database'}), 404

        device_lines = []
        for dev in devices:
            ip     = dev.get('ip', 'Unknown')
            status = dev.get('status', 'Unknown')

            open_ports = []
            raw = dev.get('open_ports')
            if raw:
                try:
                    import json
                    ports = json.loads(raw) if isinstance(raw, str) else raw
                    if isinstance(ports, list):
                        for p in ports:
                            if isinstance(p, dict) and p.get('status') == 'OPEN':
                                open_ports.append(str(p.get('port', '?')))
                            elif isinstance(p, (int, str)):
                                open_ports.append(str(p))
                except (json.JSONDecodeError, TypeError):
                    pass

            device_lines.append(
                f"  - IP: {ip}, Status: {status}, "
                f"Open Ports: [{', '.join(open_ports) if open_ports else 'none'}]"
            )

        prompt = (
            "You are a senior network security engineer.\n"
            "Analyze the following network scan results and provide a concise report.\n\n"
            "DEVICES:\n" + "\n".join(device_lines) +
            "\n\nProvide:\n"
            "1. Overall security assessment (1-2 sentences)\n"
            "2. Top security concerns (bullet points)\n"
            "3. Recommended actions (bullet points)\n\n"
            "Keep the response under 300 words."
        )

        ai_response = ask_ollama(prompt)
        return jsonify({'result': ai_response, 'devices_analyzed': len(devices)})

    except Exception as exc:
        logger.error(f"[AI] Error in generate_ai_report: {exc}", exc_info=True)
        return jsonify({'error': f'AI analysis failed: {str(exc)}'}), 500


# ── Scan Device (dashboard AJAX button) ──────────────────────────────────────

@app.route('/scan-device', methods=['POST'])
@login_required
def scan_device():
    try:
        data = request.get_json()
        if not data or 'ip' not in data:
            return jsonify({'error': 'IP address required'}), 400

        ip = data['ip'].strip()

        if not scanner.validate_ip(ip):
            return jsonify({'error': 'Invalid IP address format'}), 400

        is_valid, reason = validate_scan_target(ip, current_user)
        if not is_valid:
            return jsonify({'error': f'IP address not allowed: {reason}'}), 403

        logger.info(f"[SCAN] Device scan requested for {ip} by user {current_user.username}")

        scan_result = scanner.scan_equipment(ip)
        ports       = scanner.scan_ports_nmap(ip, [22, 80, 443, 21])

        enhanced_scan_result = {
            'ip':        ip,
            'ping':      scan_result['ping'],
            'ping_ms':   scan_result.get('ping_ms'),
            'timestamp': scan_result['timestamp'],
            'ports':     ports
        }
        alert_data = generate_alert_from_scan(enhanced_scan_result, f'Device {ip}')

        response = {
            'ip':        scan_result['ip'],
            'status':    alert_data['status'],
            'ports':     ports,
            'ping_ms':   scan_result.get('ping_ms'),
            'timestamp': scan_result['timestamp'],
            'alert':     alert_data['alert'],
            'severity':  alert_data['severity']
        }

        logger.info(f"[SCAN] Device scan completed for {ip}: {response['status']}")
        return jsonify(response)

    except Exception as e:
        logger.error(f"[SCAN] Error scanning device: {e}")
        return jsonify({'error': f'Scan failed: {str(e)}'}), 500


@app.route('/ai-analysis', methods=['POST'])
@login_required
def ai_analysis():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400

        devices = data.get('devices', [])
        if not devices:
            return jsonify({'error': 'No device data provided'}), 400

        device_info = []
        for device in devices:
            ip         = device.get('ip', 'Unknown')
            status     = device.get('status', 'Unknown')
            ports      = device.get('ports', [])
            open_ports = []
            for port in ports:
                if isinstance(port, dict):
                    if port.get('status') == 'OPEN':
                        open_ports.append(port.get('port'))
                elif isinstance(port, (int, str)):
                    open_ports.append(port)
            device_info.append(f"IP: {ip}, Status: {status}, Open Ports: {open_ports}")

        prompt = (
            "As a senior network engineer and cybersecurity expert, "
            "analyze the following network scan results and provide a concise security assessment:\n\n"
            "Device Information:\n" + "\n".join(device_info) +
            "\n\nPlease provide:\n"
            "1. Overall security assessment\n"
            "2. Key security concerns\n"
            "3. Recommended actions\n\n"
            "Keep the analysis brief and actionable."
        )

        ai_response = ask_ollama(prompt)
        logger.info(f"[AI] Analysis requested by user '{current_user.username}' for {len(devices)} devices")

        return jsonify({
            'analysis':         ai_response,
            'devices_analyzed': len(devices),
            'timestamp':        None
        })

    except Exception as e:
        logger.error(f"[AI] Error in AI analysis: {e}")
        return jsonify({'error': 'AI analysis failed'}), 500


# ── OCP Dashboard ─────────────────────────────────────────────────────────────

@app.route('/ocp-dashboard')
@login_required
def ocp_dashboard():
    return render_template('ocp_dashboard.html', current_user=current_user)


# ── Alerts ────────────────────────────────────────────────────────────────────

@app.route('/alertes')
@login_required
def alertes():
    toutes   = db.get_toutes_alertes(limit=100)
    non_lues = db.get_alertes_non_lues()
    return render_template('alertes.html', alertes=toutes, alertes_non_lues=non_lues)


@app.route('/alertes/marquer/<int:alerte_id>')
@login_required
def marquer_alerte(alerte_id):
    db.marquer_alerte_lue(alerte_id)
    return redirect(request.referrer or url_for('dashboard'))


@app.route('/alertes/marquer_tout')
@login_required
def marquer_tout():
    db.marquer_toutes_alertes_lues()
    flash('Toutes les alertes ont été marquées comme lues', 'success')
    return redirect(request.referrer or url_for('dashboard'))


# ── Network management ────────────────────────────────────────────────────────

@app.route('/networks/detect')
@login_required
@admin_required
def detect_networks():
    if network_detector is None:
        flash('network_detector module is not available', 'error')
        return redirect(url_for('equipements'))
    try:
        detected_networks = network_detector.detect_networks()
        if not detected_networks:
            flash('No networks detected. Check system routing table.', 'warning')
            return redirect(url_for('equipements'))

        summary       = db.store_detected_networks(detected_networks)
        message_parts = []
        if summary['new_networks']     > 0: message_parts.append(f"Added {summary['new_networks']} new networks")
        if summary['updated_networks'] > 0: message_parts.append(f"Updated {summary['updated_networks']} existing networks")
        if summary['errors']:               message_parts.append(f"Encountered {len(summary['errors'])} errors")

        flash(f"Network detection completed: {', '.join(message_parts)}", 'success')
        for error in summary['errors']:
            logger.error(f"[NETWORK DETECTION] {error}")

        return redirect(url_for('networks_management'))

    except Exception as e:
        logger.error(f"[NETWORK DETECTION] Error: {e}")
        flash(f'Network detection failed: {str(e)}', 'error')
        return redirect(url_for('equipements'))


@app.route('/networks')
@login_required
@admin_required
def networks_management():
    try:
        all_networks      = db.get_all_networks()
        detected_networks = db.get_detected_networks()
        manual_networks   = [n for n in all_networks if not n['name'].startswith('Auto-')]
        summary           = network_detector.get_network_summary() if network_detector else {}

        return render_template('networks.html',
                               all_networks=all_networks,
                               detected_networks=detected_networks,
                               manual_networks=manual_networks,
                               detection_summary=summary,
                               current_user=current_user)
    except Exception as e:
        logger.error(f"[NETWORKS] Error loading networks page: {e}")
        flash('Error loading networks page', 'error')
        return redirect(url_for('equipements'))


@app.route('/networks/clear-detected', methods=['POST'])
@login_required
@admin_required
def clear_detected_networks():
    try:
        deleted_count = db.clear_detected_networks()
        flash(f'Cleared {deleted_count} auto-detected networks', 'success')
        logger.info(f"[NETWORKS] User {current_user.username} cleared {deleted_count} detected networks")
    except Exception as e:
        logger.error(f"[NETWORKS] Error clearing detected networks: {e}")
        flash('Error clearing detected networks', 'error')
    return redirect(url_for('networks_management'))


@app.route('/api/networks/detect', methods=['POST'])
@login_required
@admin_required
def api_detect_networks():
    if network_detector is None:
        return jsonify({'success': False, 'error': 'network_detector module not available'}), 500
    try:
        detected_networks = network_detector.detect_networks()
        summary           = db.store_detected_networks(detected_networks)
        return jsonify({
            'success':           True,
            'detected_networks': detected_networks,
            'summary':           summary,
            'message': (f"Detected {len(detected_networks)} networks: "
                        f"{summary['new_networks']} new, {summary['updated_networks']} updated")
        })
    except Exception as e:
        logger.error(f"[API] Network detection error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/networks/status')
@login_required
def api_networks_status():
    try:
        all_networks      = db.get_all_networks()
        detected_networks = db.get_detected_networks()
        return jsonify({
            'total_networks':    len(all_networks),
            'detected_networks': len(detected_networks),
            'manual_networks':   len(all_networks) - len(detected_networks),
            'networks':          all_networks
        })
    except Exception as e:
        logger.error(f"[API] Error getting networks status: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/add_network', methods=['GET', 'POST'])
@login_required
@admin_required
def add_network():
    if request.method == 'POST':
        name        = request.form.get('name', '').strip()
        cidr        = request.form.get('cidr', '').strip()
        description = request.form.get('description', '').strip()
        try:
            db.add_network(name, cidr, description)
            flash(f'Network {name} ({cidr}) added successfully', 'success')
            return redirect(url_for('networks_management'))
        except ValueError as e:
            flash(f'Error: {str(e)}', 'error')
        except Exception as e:
            logger.error(f"Error adding network: {e}")
            flash('Technical error, please try again', 'error')

    return render_template('add_network.html', current_user=current_user)


@app.route('/delete_network/<int:network_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def delete_network(network_id):
    try:
        db.delete_network(network_id)
        flash('Network deleted successfully', 'success')
    except ValueError as e:
        flash(str(e), 'error')
    except Exception as e:
        logger.error(f"Error deleting network {network_id}: {e}")
        flash('Technical error, please try again', 'error')
    return redirect(url_for('networks_management'))


@app.route('/scan_network/<int:network_id>', methods=['POST'])
@login_required
@admin_required
def scan_network(network_id):
    try:
        from network_discovery import network_discovery

        network = db.get_network_by_id(network_id)
        if not network:
            return jsonify({'error': 'Network not found'}), 404

        logger.info(f"[SCAN] Starting network discovery for {network['name']} ({network['cidr']})")
        results = network_discovery.scan_network(network_id)

        logger.info(
            f"[SCAN] Network discovery completed: "
            f"{results['alive_hosts']}/{results['total_ips']} hosts alive, "
            f"{results['new_devices']} new devices added"
        )
        flash(
            f"Network scan completed: {results['alive_hosts']} hosts alive, "
            f"{results['new_devices']} new devices discovered in {results['scan_time']}s",
            'success'
        )
        return jsonify({
            'success': True,
            'results': results,
            'message': f"Scan completed: {results['alive_hosts']} hosts alive, {results['new_devices']} new devices"
        })

    except ValueError as e:
        logger.error(f"[SCAN] Validation error: {e}")
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        logger.error(f"[SCAN] Network scan error: {e}")
        return jsonify({'error': 'Scan failed - please try again'}), 500


@app.route('/about')
@login_required
def about():
    return render_template('about.html')


# ── Error handlers ────────────────────────────────────────────────────────────

@app.errorhandler(403)
def forbidden(e):
    return render_template('404.html'), 403


@app.errorhandler(404)
def not_found(e):
    return render_template('404.html'), 404


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == '__main__':
    print("\n" + "=" * 50)
    print("  INFRASCAN")
    print("=" * 50)
    print(f"  URL      : http://{Config.HOST}:{Config.PORT}")
    print(f"  Login    : admin")
    print(f"  Password : admin123")
    print(f"  Auto-scan: every 5 minutes")
    print("=" * 50 + "\n")

    app.run(
        debug=True,
        host=Config.HOST,
        port=Config.PORT,
        use_reloader=False,   # False باش ما يبداش scheduler مرتين
        threaded=True
    )
