# alertes.py
from datetime import datetime
from database import db

class Alerte:
    """Gestionnaire d'alertes"""
    
    @staticmethod
    def creer_alerte(equipment_id, type_alerte, message, niveau='info'):
        """Créer une nouvelle alerte"""
        try:
            with db.get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute('''
                        INSERT INTO alertes (equipment_id, type_alerte, message, niveau, date_creation, status)
                        VALUES (%s, %s, %s, %s, %s, %s)
                    ''', (equipment_id, type_alerte, message, niveau, datetime.now(), 'non_lu'))
            return True
        except Exception as e:
            print(f"Erreur creation alerte: {e}")
            return False
    
    @staticmethod
    def get_alertes_non_lues():
        """Récupérer toutes les alertes non lues"""
        try:
            with db.get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute('''
                        SELECT a.*, e.nom as equipment_nom, e.ip
                        FROM alertes a
                        JOIN equipements e ON a.equipment_id = e.id
                        WHERE a.status = 'non_lu'
                        ORDER BY a.date_creation DESC
                    ''')
                    return cursor.fetchall()
        except Exception as e:
            print(f"Erreur: {e}")
            return []
    
    @staticmethod
    def get_toutes_alertes(limit=50):
        """Récupérer toutes les alertes"""
        try:
            with db.get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute('''
                        SELECT a.*, e.nom as equipment_nom, e.ip
                        FROM alertes a
                        JOIN equipements e ON a.equipment_id = e.id
                        ORDER BY a.date_creation DESC
                        LIMIT %s
                    ''', (limit,))
                    return cursor.fetchall()
        except Exception as e:
            print(f"Erreur: {e}")
            return []
    
    @staticmethod
    def marquer_comme_lu(alerte_id):
        """Marquer une alerte comme lue"""
        try:
            with db.get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute('''
                        UPDATE alertes SET status = 'lu', date_lecture = %s
                        WHERE id = %s
                    ''', (datetime.now(), alerte_id))
            return True
        except Exception as e:
            print(f"Erreur: {e}")
            return False
    
    @staticmethod
    def marquer_tout_lu():
        """Marquer toutes les alertes comme lues"""
        try:
            with db.get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute('''
                        UPDATE alertes SET status = 'lu', date_lecture = %s
                        WHERE status = 'non_lu'
                    ''', (datetime.now(),))
            return True
        except Exception as e:
            print(f"Erreur: {e}")
            return False
    
    @staticmethod
    def init_alertes_table():
        """Initialiser la table des alertes"""
        with db.get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS alertes (
                        id INT AUTO_INCREMENT PRIMARY KEY,
                        equipment_id INT NOT NULL,
                        type_alerte VARCHAR(50) NOT NULL,
                        message TEXT NOT NULL,
                        niveau VARCHAR(20) DEFAULT 'info',
                        date_creation TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        date_lecture TIMESTAMP NULL,
                        status VARCHAR(20) DEFAULT 'non_lu',
                        FOREIGN KEY (equipment_id) REFERENCES equipements(id) ON DELETE CASCADE
                    )
                ''')
        print("[ALERTES] Table alertes initialisee")
    
    @staticmethod
    def analyser_scan_et_creer_alertes(equipment_id, scan_results):
        """Analyser les résultats de scan et créer des alertes si nécessaire"""
        alertes_crees = []
        
        # Alerte si équipement DOWN
        if not scan_results['ping']:
            msg = f"Equipement ne repond pas au ping"
            Alerte.creer_alerte(equipment_id, 'ping_failed', msg, 'critique')
            alertes_crees.append('ping_failed')
        
        # Alerte si ports critiques sont fermés
        ports_critiques = {22: 'SSH', 23: 'Telnet', 443: 'HTTPS'}
        for port, service in ports_critiques.items():
            if port in scan_results['ports'] and not scan_results['ports'][port]['open']:
                msg = f"Port critique {port} ({service}) est ferme"
                Alerte.creer_alerte(equipment_id, 'port_critique_ferme', msg, 'important')
                alertes_crees.append(f'port_{port}_closed')
        
        # Alerte si aucun port n'est ouvert
        ports_ouverts = [p for p, info in scan_results['ports'].items() if info['open']]
        if len(ports_ouverts) == 0:
            msg = "Aucun port ouvert detecte sur cet equipement"
            Alerte.creer_alerte(equipment_id, 'aucun_port_ouvert', msg, 'warning')
            alertes_crees.append('no_ports_open')
        
        return alertes_crees