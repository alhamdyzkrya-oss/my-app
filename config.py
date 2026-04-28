# config.py
import os
import secrets
from datetime import timedelta

class Config:
    """Configuration de l'application"""
    
    # Configuration MySQL (XAMPP)
    MYSQL_HOST = os.getenv('MYSQL_HOST', 'localhost')
    MYSQL_USER = os.getenv('MYSQL_USER', 'root')
    MYSQL_PASSWORD = os.getenv('MYSQL_PASSWORD', '')
    MYSQL_DATABASE = os.getenv('MYSQL_DATABASE', 'gns3_monitor')
    
    # Configuration Flask
    SECRET_KEY = os.getenv('SECRET_KEY') or secrets.token_urlsafe(32)
    DEBUG = os.getenv('DEBUG', 'True').lower() == 'true'
    PORT = int(os.getenv('PORT', 5000))
    HOST = os.getenv('HOST', '127.0.0.1')
    
    # Security settings
    SESSION_COOKIE_SECURE = not DEBUG
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = timedelta(hours=2)
    
    # Application settings
    MAX_LOGIN_ATTEMPTS = 5
    LOGIN_TIMEOUT = 15  # minutes
    EQUIPMENT_TYPES = ['Routeur', 'Switch', 'Serveur', 'Autre']
    
    # Network scanning ports
    PORTS_TO_SCAN = {
        22: 'SSH',
        23: 'Telnet', 
        80: 'HTTP',
        443: 'HTTPS',
        21: 'FTP',
        25: 'SMTP',
        53: 'DNS',
        161: 'SNMP'
    }
    
    # Scan timeouts
    PING_TIMEOUT = int(os.getenv('PING_TIMEOUT', '3'))
    PORT_TIMEOUT = int(os.getenv('PORT_TIMEOUT', '2'))
    
    # Security - Local Network Restriction
    LOCAL_NETWORK = os.getenv('LOCAL_NETWORK', '192.168.0.0/16')
    ALLOW_PRIVATE_NETWORKS = os.getenv('ALLOW_PRIVATE_NETWORKS', 'False').lower() == 'false'
    
    # Logging
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')

    # Email Settings
    MAIL_SERVER = 'zk455477@gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = 'zh455477@gmail.com'
    MAIL_PASSWORD = 'xfkhwbeysauwxafn'
    MAIL_DEFAULT_SENDER = 'zh455477@gmail.com'
    ALERT_EMAIL_RECIPIENT = 'zh455477@gmail.com'