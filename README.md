# Python Mini-Firewall

Un pare-feu simple mais efficace écrit en Python, avec une interface web pour la gestion des règles.

## 📋 Fonctionnalités

- Filtrage de paquets réseau basé sur IP et ports
- Détection automatique des scans de ports
- Blocage configurable des paquets ICMP (ping)
- Interface web pour la gestion des règles en temps réel
- Logging complet des activités du pare-feu

## 🔧 Prérequis

- Python 3.6+
- iptables (Linux)
- Modules Python : flask, netfilterqueue, scapy

## 📦 Installation

```bash
# Cloner le repository
git clone https://github.com/abdelaaziz0/FIREWALL.git

# Installer les dépendances
pip install flask netfilterqueue scapy

# Configuration des règles iptables (nécessite les droits root)
sudo iptables -F
sudo iptables -A INPUT -j NFQUEUE --queue-num 1
sudo iptables -A OUTPUT -j NFQUEUE --queue-num 1
```

## 🚀 Utilisation

Lancez le pare-feu avec les droits root :

```bash
sudo python3 firewall.py
```

Cela démarrera :
- Le moteur de filtrage du pare-feu
- L'interface web accessible à l'adresse `http://localhost:5000`

## 📝 Configuration

Les règles par défaut sont définies dans la variable `FIREWALL_RULES` au début du script. Vous pouvez les modifier directement dans le code ou via l'interface web.

```python
FIREWALL_RULES = {
    "block_ips": set(),       # IP à bloquer explicitement
    "allow_ips": set(),       # IP à autoriser explicitement
    "block_ports": set(),     # Ports à bloquer (TCP/UDP)
    "allow_ports": set(),     # Ports à autoriser
    "block_icmp": False,      # True -> bloquer ICMP (ping)
    "scan_detection_threshold": 5,   # Seuil de détection de scan de ports
    "scan_time_window": 10,          # Fenêtre de temps en secondes
}
```

## 🔍 Détection de scan de ports

Le pare-feu détecte automatiquement les tentatives de scan de ports et ajoute les IP suspectes à la liste noire. Vous pouvez ajuster les paramètres de détection dans la configuration :

- `scan_detection_threshold` : nombre de ports différents tentés
- `scan_time_window` : période d'observation en secondes

## 📊 Logs

Les logs sont enregistrés dans le fichier `firewall.log` au format :

```
2023-03-17 14:30:45 [INFO] New Packet: 192.168.1.100 -> 8.8.8.8, proto=6
2023-03-17 14:31:10 [WARNING] Port scan detected from 192.168.1.105, IP blocked!
```

## ⚠️ Limitations

- Ce pare-feu est conçu à des fins éducatives et pour des petits réseaux
- Il ne remplace pas un pare-feu professionnel pour des environnements de production
- Fonctionne uniquement sur Linux avec iptables

## 🛠️ Personnalisation

Vous pouvez adapter le code pour ajouter des fonctionnalités comme :
- Support IPv6
- Règles basées sur les signatures de paquets
- Filtrage par domaine
- Ajout d'alertes par email

## 📄 Licence

Ce projet est sous licence MIT. Voir le fichier LICENSE pour plus de détails.
