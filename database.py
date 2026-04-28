# database.py
import pymysql
import logging
from contextlib import contextmanager
from config import Config

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class Database:
    """Gestionnaire de base de données MySQL"""

    def __init__(self):
        self.config = {
            'host':        Config.MYSQL_HOST,
            'user':        Config.MYSQL_USER,
            'password':    Config.MYSQL_PASSWORD,
            'database':    Config.MYSQL_DATABASE,
            'charset':     'utf8mb4',
            'cursorclass': pymysql.cursors.DictCursor,
            'autocommit':  True,
            'connect_timeout': 10,
            'read_timeout':    30,
            'write_timeout':   30,
        }

    # ── Connection ────────────────────────────────────────────────────────────

    @contextmanager
    def get_connection(self):
        conn = None
        try:
            conn = pymysql.connect(**self.config)
            yield conn
        except pymysql.Error as e:
            logger.error(f"Database error: {e}")
            if conn:
                conn.rollback()
            raise
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            if conn:
                conn.rollback()
            raise
        finally:
            if conn:
                conn.close()

    # ── Schema helpers ────────────────────────────────────────────────────────

    def _column_exists(self, conn, table: str, column: str) -> bool:
        with conn.cursor() as cursor:
            cursor.execute('''
                SELECT COUNT(*) AS cnt
                FROM information_schema.COLUMNS
                WHERE TABLE_SCHEMA = %s
                  AND TABLE_NAME   = %s
                  AND COLUMN_NAME  = %s
            ''', (Config.MYSQL_DATABASE, table, column))
            return cursor.fetchone()['cnt'] > 0

    # ── Initialisation ────────────────────────────────────────────────────────

    def init_all_tables(self):
        try:
            # Create database if needed
            tmp = self.config.copy()
            tmp['database'] = 'mysql'
            with pymysql.connect(**tmp) as conn:
                with conn.cursor() as cursor:
                    cursor.execute(
                        f"CREATE DATABASE IF NOT EXISTS `{Config.MYSQL_DATABASE}` "
                        f"CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"
                    )

            # networks table first (referenced by equipements)
            with self.get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute('''
                        CREATE TABLE IF NOT EXISTS networks (
                            id          INT AUTO_INCREMENT PRIMARY KEY,
                            name        VARCHAR(100) NOT NULL UNIQUE,
                            cidr        VARCHAR(18)  NOT NULL UNIQUE,
                            description TEXT,
                            date_ajout  TIMESTAMP    DEFAULT CURRENT_TIMESTAMP
                        )
                    ''')

            # equipements
            with self.get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute('''
                        CREATE TABLE IF NOT EXISTS equipements (
                            id          INT AUTO_INCREMENT PRIMARY KEY,
                            nom         VARCHAR(100) NOT NULL DEFAULT '',
                            ip          VARCHAR(15)  NOT NULL DEFAULT '',
                            type        VARCHAR(20)  NOT NULL,
                            description TEXT,
                            status      VARCHAR(40)  DEFAULT 'UP',
                            network_id  INT,
                            mac_address VARCHAR(17)  DEFAULT NULL,
                            vendor      VARCHAR(50)  DEFAULT NULL,
                            hostname    VARCHAR(100) DEFAULT NULL,
                            device_type VARCHAR(20)  DEFAULT 'unknown',
                            open_ports  JSON         DEFAULT NULL,
                            date_ajout  TIMESTAMP    DEFAULT CURRENT_TIMESTAMP,
                            UNIQUE KEY unique_ip (ip),
                            INDEX idx_mac         (mac_address),
                            INDEX idx_vendor      (vendor),
                            INDEX idx_device_type (device_type),
                            FOREIGN KEY (network_id) REFERENCES networks(id) ON DELETE SET NULL
                        )
                    ''')

                # Migrations for existing tables
                migrations = [
                    ('status',      "ADD COLUMN status VARCHAR(40) NOT NULL DEFAULT 'UP'"),
                    ('network_id',  "ADD COLUMN network_id INT, ADD CONSTRAINT fk_equipment_network FOREIGN KEY (network_id) REFERENCES networks(id) ON DELETE SET NULL"),
                    ('mac_address', "ADD COLUMN mac_address VARCHAR(17) DEFAULT NULL, ADD INDEX idx_mac (mac_address)"),
                    ('vendor',      "ADD COLUMN vendor VARCHAR(50) DEFAULT NULL, ADD INDEX idx_vendor (vendor)"),
                    ('hostname',    "ADD COLUMN hostname VARCHAR(100) DEFAULT NULL"),
                    ('device_type', "ADD COLUMN device_type VARCHAR(20) DEFAULT 'unknown', ADD INDEX idx_device_type (device_type)"),
                    ('open_ports',  "ADD COLUMN open_ports JSON DEFAULT NULL"),
                ]
                for col, sql in migrations:
                    if not self._column_exists(conn, 'equipements', col):
                        with conn.cursor() as cursor:
                            cursor.execute(f"ALTER TABLE equipements {sql}")
                        logger.info(f"[MIGRATION] Column '{col}' added to equipements")

            # users
            with self.get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute('''
                        CREATE TABLE IF NOT EXISTS users (
                            id            INT AUTO_INCREMENT PRIMARY KEY,
                            username      VARCHAR(50)  UNIQUE NOT NULL,
                            email         VARCHAR(100) UNIQUE NOT NULL DEFAULT '',
                            password_hash VARCHAR(255) NOT NULL,
                            role          VARCHAR(20)  DEFAULT 'user',
                            created_at    TIMESTAMP    DEFAULT CURRENT_TIMESTAMP
                        )
                    ''')
                if not self._column_exists(conn, 'users', 'email'):
                    with conn.cursor() as cursor:
                        cursor.execute(
                            "ALTER TABLE users "
                            "ADD COLUMN email VARCHAR(100) UNIQUE NOT NULL "
                            "DEFAULT 'temp@example.com' AFTER username"
                        )
                    logger.info("[MIGRATION] Column 'email' added to users table")

            # alertes
            with self.get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute('''
                        CREATE TABLE IF NOT EXISTS alertes (
                            id            INT AUTO_INCREMENT PRIMARY KEY,
                            equipment_id  INT         NOT NULL,
                            type_alerte   VARCHAR(50) NOT NULL,
                            message       TEXT        NOT NULL,
                            niveau        VARCHAR(20) DEFAULT 'info',
                            date_creation TIMESTAMP   DEFAULT CURRENT_TIMESTAMP,
                            date_lecture  TIMESTAMP   NULL,
                            status        VARCHAR(20) DEFAULT 'non_lu',
                            FOREIGN KEY (equipment_id)
                                REFERENCES equipements(id) ON DELETE CASCADE
                        )
                    ''')

            logger.info("[OK] All tables are ready")
            return True

        except Exception as e:
            logger.error(f"[ERROR] Table init failed: {e}")
            return False

    # ── Equipment CRUD ────────────────────────────────────────────────────────

    def add_equipment(self, nom: str, ip: str, type_equipement: str,
                      description: str = "") -> bool:
        if not nom or not ip or not type_equipement:
            raise ValueError("Nom, IP et type sont obligatoires")
        if type_equipement not in Config.EQUIPMENT_TYPES:
            raise ValueError(f"Type invalide. Valeurs acceptées: {Config.EQUIPMENT_TYPES}")
        try:
            with self.get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute('''
                        INSERT INTO equipements (nom, ip, type, description)
                        VALUES (%s, %s, %s, %s)
                    ''', (nom.strip(), ip.strip(), type_equipement, description.strip()))
            logger.info(f"Equipment '{nom}' ({ip}) added")
            return True
        except pymysql.IntegrityError:
            raise ValueError("Cette adresse IP existe déjà")
        except Exception as e:
            logger.error(f"Error adding equipment: {e}")
            raise

    def get_all_equipments(self) -> list:
        with self.get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute('SELECT * FROM equipements ORDER BY date_ajout DESC')
                return cursor.fetchall()

    def get_equipment_by_id(self, equipment_id: int):
        with self.get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute('SELECT * FROM equipements WHERE id = %s', (equipment_id,))
                return cursor.fetchone()

    def get_equipment_by_ip(self, ip: str):
        with self.get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute('SELECT * FROM equipements WHERE ip = %s', (ip,))
                return cursor.fetchone()

    def delete_equipment(self, equipment_id: int) -> bool:
        if not equipment_id or equipment_id <= 0:
            raise ValueError("ID d'équipement invalide")
        with self.get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute('DELETE FROM alertes WHERE equipment_id = %s', (equipment_id,))
                rows = cursor.execute('DELETE FROM equipements WHERE id = %s', (equipment_id,))
                if rows == 0:
                    raise ValueError("Équipement non trouvé")
        logger.info(f"Equipment {equipment_id} deleted")
        return True

    def update_equipment_status(self, equipment_id: int, status: str) -> bool:
        allowed = ('UP', 'DOWN', 'WARNING', 'OUTSIDE', 'Active (No exposed services)')
        if status not in allowed:
            raise ValueError(f"Status must be one of: {allowed}")
        with self.get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    'UPDATE equipements SET status = %s WHERE id = %s',
                    (status, equipment_id)
                )
        logger.info(f"Equipment {equipment_id} -> {status}")
        return True

    def update_equipment_ports(self, equipment_id: int, ports_data: list) -> bool:
        import json
        with self.get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    'UPDATE equipements SET open_ports = %s WHERE id = %s',
                    (json.dumps(ports_data) if ports_data else None, equipment_id)
                )
        logger.info(f"Equipment {equipment_id} ports updated: {len(ports_data) if ports_data else 0} ports")
        return True

    def update_equipment_advanced_fields(self, equipment_id: int, mac_address: str = None,
                                         vendor: str = None, hostname: str = None,
                                         device_type: str = None) -> bool:
        with self.get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute('''
                    UPDATE equipements
                    SET mac_address = %s, vendor = %s, hostname = %s, device_type = %s
                    WHERE id = %s
                ''', (mac_address, vendor, hostname, device_type, equipment_id))
        logger.info(f"Equipment {equipment_id} advanced fields updated")
        return True

    def add_equipment_with_fingerprint(self, ip: str, device_name: str = None,
                                       device_type: str = 'unknown', mac_address: str = None,
                                       vendor: str = None, hostname: str = None,
                                       network_id: int = None, description: str = None) -> bool:
        if not ip:
            raise ValueError("IP address is required")
        if not device_name:
            device_name = f"Device_{ip.replace('.', '_')}"
        try:
            with self.get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute('''
                        INSERT INTO equipements
                        (nom, ip, type, description, network_id, mac_address, vendor, hostname, device_type)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ''', (device_name.strip(), ip.strip(), 'Other',
                          description or '', network_id, mac_address, vendor, hostname, device_type))
            logger.info(f"Equipment '{device_name}' ({ip}) added with fingerprint data")
            return True
        except pymysql.IntegrityError:
            existing = self.get_equipment_by_ip(ip)
            if existing:
                return self.update_equipment_advanced_fields(
                    existing['id'], mac_address, vendor, hostname, device_type
                )
            raise ValueError("This IP address already exists but cannot be retrieved")
        except Exception as e:
            logger.error(f"Error adding equipment with fingerprint: {e}")
            raise

    # ── Network CRUD ──────────────────────────────────────────────────────────

    def add_network(self, name: str, cidr: str, description: str = "") -> bool:
        if not name or not cidr:
            raise ValueError("Name and CIDR are required")
        try:
            import ipaddress
            ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            raise ValueError("Invalid CIDR format. Example: 192.168.1.0/24")
        try:
            with self.get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute('''
                        INSERT INTO networks (name, cidr, description)
                        VALUES (%s, %s, %s)
                    ''', (name.strip(), cidr.strip(), description.strip()))
            logger.info(f"Network '{name}' ({cidr}) added")
            return True
        except pymysql.IntegrityError as e:
            if "name" in str(e):
                raise ValueError("Network name already exists")
            elif "cidr" in str(e):
                raise ValueError("CIDR already exists")
            raise ValueError("Network already exists")
        except Exception as e:
            logger.error(f"Error adding network: {e}")
            raise

    def get_all_networks(self) -> list:
        with self.get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute('''
                    SELECT n.*, COUNT(e.id) AS equipment_count
                    FROM networks n
                    LEFT JOIN equipements e ON n.id = e.network_id
                    GROUP BY n.id
                    ORDER BY n.date_ajout DESC
                ''')
                return cursor.fetchall()

    def get_network_by_id(self, network_id: int):
        with self.get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute('SELECT * FROM networks WHERE id = %s', (network_id,))
                return cursor.fetchone()

    def delete_network(self, network_id: int) -> bool:
        if not network_id or network_id <= 0:
            raise ValueError("Invalid network ID")
        with self.get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    'UPDATE equipements SET network_id = NULL WHERE network_id = %s',
                    (network_id,)
                )
                rows = cursor.execute('DELETE FROM networks WHERE id = %s', (network_id,))
                if rows == 0:
                    raise ValueError("Network not found")
        logger.info(f"Network {network_id} deleted")
        return True

    def get_networks_for_dropdown(self) -> list:
        with self.get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute('SELECT id, name, cidr FROM networks ORDER BY name ASC')
                return cursor.fetchall()

    def validate_ip_in_network(self, ip: str, network_id: int) -> bool:
        try:
            import ipaddress
            network = self.get_network_by_id(network_id)
            if not network:
                return False
            return ipaddress.ip_address(ip) in ipaddress.ip_network(network['cidr'])
        except (ValueError, TypeError):
            return False

    def update_equipment_with_network(self, equipment_id: int, network_id: int = None) -> bool:
        with self.get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    'UPDATE equipements SET network_id = %s WHERE id = %s',
                    (network_id, equipment_id)
                )
        logger.info(f"Equipment {equipment_id} linked to network {network_id}")
        return True

    def update_equipment_with_network_validation(self, nom: str, ip: str, type_equipement: str,
                                                  description: str = "", network_id: int = None) -> bool:
        if not nom or not ip or not type_equipement:
            raise ValueError("Name, IP and type are required")
        if type_equipement not in Config.EQUIPMENT_TYPES:
            raise ValueError(f"Invalid type. Accepted values: {Config.EQUIPMENT_TYPES}")
        if network_id and not self.validate_ip_in_network(ip, network_id):
            raise ValueError(f"IP {ip} is not in the selected network")
        try:
            with self.get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute('''
                        INSERT INTO equipements (nom, ip, type, description, network_id)
                        VALUES (%s, %s, %s, %s, %s)
                    ''', (nom.strip(), ip.strip(), type_equipement, description.strip(), network_id))
            logger.info(f"Equipment '{nom}' ({ip}) added to network {network_id}")
            return True
        except pymysql.IntegrityError:
            raise ValueError("This IP address already exists")
        except Exception as e:
            logger.error(f"Error adding equipment: {e}")
            raise

    def store_detected_networks(self, networks: list) -> dict:
        summary = {'total_detected': len(networks), 'new_networks': 0,
                   'updated_networks': 0, 'errors': []}
        try:
            with self.get_connection() as conn:
                with conn.cursor() as cursor:
                    for network in networks:
                        try:
                            cidr = network.get('cidr')
                            if not cidr:
                                continue
                            cursor.execute('SELECT id FROM networks WHERE cidr = %s', (cidr,))
                            existing = cursor.fetchone()
                            if existing:
                                cursor.execute(
                                    'UPDATE networks SET name = %s, description = %s WHERE cidr = %s',
                                    (f"Auto-{cidr.replace('/', '-')}",
                                     f"Auto-detected via {network.get('interface', 'unknown')}", cidr)
                                )
                                summary['updated_networks'] += 1
                            else:
                                cursor.execute(
                                    'INSERT INTO networks (name, cidr, description) VALUES (%s, %s, %s)',
                                    (f"Auto-{cidr.replace('/', '-')}", cidr,
                                     f"Auto-detected via {network.get('interface', 'unknown')} "
                                     f"gateway {network.get('gateway', 'N/A')}")
                                )
                                summary['new_networks'] += 1
                        except Exception as e:
                            summary['errors'].append(f"Error with {network.get('cidr', 'unknown')}: {e}")
        except Exception as e:
            logger.error(f"[NETWORK] Database error storing networks: {e}")
            summary['errors'].append(f"Database error: {str(e)}")
        return summary

    def get_detected_networks(self) -> list:
        with self.get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    "SELECT * FROM networks WHERE name LIKE 'Auto-%' ORDER BY cidr"
                )
                return cursor.fetchall()

    def clear_detected_networks(self) -> int:
        try:
            with self.get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute('''
                        UPDATE equipements e
                        SET e.network_id = NULL
                        WHERE e.network_id IN (SELECT id FROM networks WHERE name LIKE 'Auto-%')
                    ''')
                    cursor.execute("DELETE FROM networks WHERE name LIKE 'Auto-%'")
                    deleted = cursor.rowcount
                    logger.info(f"[NETWORK] Cleared {deleted} auto-detected networks")
                    return deleted
        except Exception as e:
            logger.error(f"[NETWORK] Error clearing detected networks: {e}")
            return 0

    def is_ip_in_any_detected_network(self, ip: str) -> bool:
        try:
            import ipaddress
            ip_addr = ipaddress.ip_address(ip)
            for network in self.get_detected_networks():
                try:
                    if ip_addr in ipaddress.ip_network(network['cidr']):
                        return True
                except ValueError:
                    continue
            return False
        except (ValueError, TypeError):
            return False

    def get_device_statistics(self) -> dict:
        with self.get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute('SELECT COUNT(*) AS total FROM equipements')
                total = cursor.fetchone()['total']
                cursor.execute('SELECT status, COUNT(*) AS count FROM equipements GROUP BY status')
                status_counts = {r['status']: r['count'] for r in cursor.fetchall()}
                cursor.execute('SELECT device_type, COUNT(*) AS count FROM equipements GROUP BY device_type')
                device_type_counts = {r['device_type']: r['count'] for r in cursor.fetchall()}
                cursor.execute('SELECT vendor, COUNT(*) AS count FROM equipements WHERE vendor IS NOT NULL GROUP BY vendor')
                vendor_counts = {r['vendor']: r['count'] for r in cursor.fetchall()}
                cursor.execute('''
                    SELECT n.name, COUNT(e.id) AS count
                    FROM networks n LEFT JOIN equipements e ON n.id = e.network_id
                    GROUP BY n.id, n.name
                ''')
                network_counts = {r['name']: r['count'] for r in cursor.fetchall()}
        return {
            'total_devices':      total,
            'status_counts':      status_counts,
            'device_type_counts': device_type_counts,
            'vendor_counts':      vendor_counts,
            'network_counts':     network_counts,
        }

    # ── User CRUD ─────────────────────────────────────────────────────────────

    def get_user_by_username(self, username: str):
        with self.get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
                return cursor.fetchone()

    def get_user_by_id(self, user_id: int):
        with self.get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))
                return cursor.fetchone()

    def get_user_by_username_or_email(self, identifier: str):
        with self.get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    'SELECT * FROM users WHERE username = %s OR email = %s',
                    (identifier, identifier.lower())
                )
                return cursor.fetchone()

    def create_user(self, username: str, password_hash: str, role: str = 'user',
                    email: str = None) -> bool:
        """
        Flexible create_user:
          - Admin init  : create_user('admin', hash, 'admin')
          - Signup      : create_user('zakaria', hash, 'user', email='z@x.com')
        Email defaults to username@local if not provided.
        """
        if not username or not password_hash:
            raise ValueError("Username and password hash are required")
        if email is None:
            email = f"{username}@local"
        try:
            with self.get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute(
                        'INSERT INTO users (username, email, password_hash, role) '
                        'VALUES (%s, %s, %s, %s)',
                        (username.strip(), email.strip().lower(), password_hash, role)
                    )
            logger.info(f"User '{username}' created successfully")
            return True
        except pymysql.IntegrityError as e:
            if "username" in str(e):
                raise ValueError("Username already exists")
            elif "email" in str(e):
                raise ValueError("Email already exists")
            raise ValueError("User already exists")
        except Exception as e:
            logger.error(f"Error creating user: {e}")
            raise

    # ── Alerts ────────────────────────────────────────────────────────────────

    def creer_alerte(self, equipment_id: int, type_alerte: str,
                     message: str, niveau: str = 'info') -> None:
        """Insert alert every time — use creer_alerte_unique to avoid duplicates."""
        with self.get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute('''
                    INSERT INTO alertes (equipment_id, type_alerte, message, niveau, status)
                    VALUES (%s, %s, %s, %s, 'non_lu')
                ''', (equipment_id, type_alerte, message, niveau))

    def creer_alerte_unique(self, equipment_id: int, type_alerte: str,
                            message: str, niveau: str = 'info') -> bool:
        """
        Insert alert ONLY if no unread alert of the same type already exists
        for this equipment.  Returns True if inserted, False if skipped.
        """
        with self.get_connection() as conn:
            with conn.cursor() as cursor:
                # Check for existing unread alert with same equipment + type
                cursor.execute('''
                    SELECT id FROM alertes
                    WHERE equipment_id = %s
                      AND type_alerte  = %s
                      AND status       = 'non_lu'
                    LIMIT 1
                ''', (equipment_id, type_alerte))

                if cursor.fetchone():
                    # Already exists — skip silently
                    logger.debug(
                        f"[ALERT] Skipped duplicate: equipment={equipment_id} type={type_alerte}"
                    )
                    return False

                # Not found — insert
                cursor.execute('''
                    INSERT INTO alertes (equipment_id, type_alerte, message, niveau, status)
                    VALUES (%s, %s, %s, %s, 'non_lu')
                ''', (equipment_id, type_alerte, message, niveau))
                logger.info(
                    f"[ALERT] Created: equipment={equipment_id} type={type_alerte} niveau={niveau}"
                )
                return True

    def get_alertes_non_lues(self) -> list:
        with self.get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute('''
                    SELECT a.*, e.nom AS equipment_nom, e.ip
                    FROM   alertes a
                    JOIN   equipements e ON a.equipment_id = e.id
                    WHERE  a.status = 'non_lu'
                    ORDER  BY a.date_creation DESC
                ''')
                return cursor.fetchall()

    def get_toutes_alertes(self, limit: int = 50) -> list:
        with self.get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute('''
                    SELECT a.*, e.nom AS equipment_nom, e.ip
                    FROM   alertes a
                    JOIN   equipements e ON a.equipment_id = e.id
                    ORDER  BY a.date_creation DESC
                    LIMIT  %s
                ''', (limit,))
                return cursor.fetchall()

    def marquer_alerte_lue(self, alerte_id: int) -> None:
        with self.get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute('''
                    UPDATE alertes
                    SET status = 'lu', date_lecture = CURRENT_TIMESTAMP
                    WHERE id = %s
                ''', (alerte_id,))

    def marquer_toutes_alertes_lues(self) -> None:
        with self.get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute('''
                    UPDATE alertes
                    SET status = 'lu', date_lecture = CURRENT_TIMESTAMP
                    WHERE status = 'non_lu'
                ''')

    # ── Stats ─────────────────────────────────────────────────────────────────

    def get_stats(self) -> dict:
        with self.get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute('SELECT COUNT(*) AS n FROM equipements')
                total = cursor.fetchone()['n']

                cursor.execute("SELECT COUNT(*) AS n FROM equipements WHERE status = 'UP'")
                up = cursor.fetchone()['n']

                cursor.execute("SELECT COUNT(*) AS n FROM equipements WHERE status = 'DOWN'")
                down = cursor.fetchone()['n']

                cursor.execute("SELECT COUNT(*) AS n FROM alertes WHERE status = 'non_lu'")
                alerts = cursor.fetchone()['n']

                cursor.execute("SELECT COUNT(*) AS n FROM equipements WHERE type = 'Routeur'")
                routeurs = cursor.fetchone()['n']

                cursor.execute("SELECT COUNT(*) AS n FROM equipements WHERE type = 'Switch'")
                switches = cursor.fetchone()['n']

        return {
            'total_equipements': total,
            'devices_up':        up,
            'devices_down':      down,
            'alertes_non_lues':  alerts,
            'routeurs':          routeurs,
            'switches':          switches,
        }


db = Database()