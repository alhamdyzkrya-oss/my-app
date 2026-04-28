# GNS3 Network Monitor

Une application Flask pour surveiller les équipements réseau dans votre environnement GNS3.

## Fonctionnalités

- **Gestion des équipements**: Ajouter, supprimer et lister les équipements réseau
- **Surveillance réseau**: Scan de ping et de ports pour détecter les problèmes
- **Alertes**: Système d'alertes pour les équipements indisponibles
- **Gestion des utilisateurs**: Authentification avec rôles (admin/utilisateur)
- **Tableau de bord**: Vue d'ensemble des équipements et alertes

## Installation

1. Cloner le repository:
```bash
git clone <repository-url>
cd 2zizo
```

2. Installer les dépendances:
```bash
pip install -r requirements.txt
```

3. Configurer la base de données MySQL:
   - Assurez-vous que MySQL/XAMPP est installé et en cours d'exécution
   - Créez une base de données nommée `gns3_monitor`

4. Configurer l'environnement (optionnel):
```bash
cp .env.example .env
# Éditez .env avec votre configuration
```

5. Lancer l'application:
```bash
python app.py
```

## Configuration par défaut

- **URL**: http://127.0.0.1:5000
- **Admin**: admin / admin123

## Structure des fichiers

```
2zizo/
|-- app.py              # Application Flask principale
|-- database.py         # Gestion de la base de données
|-- scanner.py          # Scanner réseau
|-- config.py           # Configuration de l'application
|-- requirements.txt    # Dépendances Python
|-- .env.example        # Exemple de configuration environnement
|-- templates/          # Templates HTML
|-- static/             # Fichiers statiques
```

## Rôles utilisateurs

- **Admin**: Accès complet (ajout/suppression d'équipements)
- **Utilisateur**: Visualisation et scan uniquement

## Ports scannés par défaut

- 22: SSH
- 23: Telnet
- 80: HTTP
- 443: HTTPS
- 53: DNS
- 161: SNMP

## Sécurité

- Hashage des mots de passe avec bcrypt
- Protection CSRF
- Cookies sécurisés en production
- Validation des entrées utilisateur
- SQL injection prevention

## Développement

Pour le développement, vous pouvez activer le mode debug:
```bash
export DEBUG=True
python app.py
```

## Licence

MIT License
