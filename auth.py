# auth.py
import bcrypt
from flask_login import UserMixin
from database import db

class User(UserMixin):
    """Modèle utilisateur pour Flask-Login"""
    
    def __init__(self, id, username, password_hash):
        self.id = id
        self.username = username
        self.password_hash = password_hash
    
    @staticmethod
    def get(user_id):
        """Récupérer un utilisateur par ID"""
        with db.get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))
                user_data = cursor.fetchone()
                if user_data:
                    return User(
                        id=user_data['id'],
                        username=user_data['username'],
                        password_hash=user_data['password_hash']
                    )
        return None
    
    @staticmethod
    def find_by_username(username):
        """Trouver un utilisateur par nom d'utilisateur"""
        with db.get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
                user_data = cursor.fetchone()
                if user_data:
                    return User(
                        id=user_data['id'],
                        username=user_data['username'],
                        password_hash=user_data['password_hash']
                    )
        return None
    
    @staticmethod
    def create_admin_user():
        """Créer un utilisateur admin par défaut s'il n'existe pas"""
        with db.get_connection() as conn:
            with conn.cursor() as cursor:
                # Vérifier si l'admin existe
                cursor.execute('SELECT * FROM users WHERE username = %s', ('admin',))
                if not cursor.fetchone():
                    # Créer l'admin avec mot de passe: admin123
                    password_hash = bcrypt.hashpw('admin123'.encode('utf-8'), bcrypt.gensalt())
                    cursor.execute(
                        'INSERT INTO users (username, password_hash, role) VALUES (%s, %s, %s)',
                        ('admin', password_hash.decode('utf-8'), 'admin')
                    )
                    print("[AUTH] Utilisateur admin créé (login: admin, password: admin123)")
    
    @staticmethod
    def verify_password(stored_hash, password):
        """Vérifier le mot de passe"""
        return bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8'))

def init_auth_table():
    """Initialiser la table users"""
    with db.get_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(50) UNIQUE NOT NULL,
                    password_hash VARCHAR(255) NOT NULL,
                    role VARCHAR(20) DEFAULT 'user',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
    print("[AUTH] Table users initialisee")