#!/usr/bin/python3

from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSKernelSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink

# Importation des modules spécifiques à Mininet-wifi
from mn_wifi.net import Mininet_wifi
from mn_wifi.node import OVSKernelAP, Station
from mn_wifi.link import wmediumd, TCLink
from mn_wifi.wmediumd import phy80211const # Potentiellement utile pour des modèles de propagation spécifiques
from mn_wifi.cli import CLI_wifi # CLI_wifi est recommandé pour les topologies wifi
from mn_wifi.telemetry import telemetry # Pour la visualisation (optionnel)

def complex_wifi_topology():
    "Crée une topologie Mininet-wifi complexe avec APs, Stations, Switch et un Serveur"

    info("*** Début de la création de la topologie Mininet-wifi\n")

    # IMPORTANT : Assurez-vous de démarrer votre contrôleur (ex: Ryu, POX, Floodlight)
    # dans un terminal séparé AVANT d'exécuter ce script.
    # Exemples :
    # Pour Ryu : ryu-manager --app-list ryu.app.simple_switch_13 --wsapi-port 8080
    # Pour POX : ./pox.py openflow.of_01 --port=6653 l2_learning
    # Le message 'Unable to contact the remote controller' signifie qu'il n'est pas en cours d'exécution.

    # 1. Définition du réseau Mininet-wifi
    net = Mininet_wifi(controller=RemoteController, accessPoint=OVSKernelAP,
                       link=TCLink, sta_type=Station) # Utilise Station pour les hôtes sans fil

    info("*** Ajout du Contrôleur\n")
    # Ajout d'un contrôleur distant (vous devez le lancer séparément)
    c0 = net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6653)

    info("*** Création des Points d'Accès (APs)\n")
    # APs (de type OVSKernelAP) avec SSID, mode, canal et position
    ap1 = net.addAccessPoint('ap1', ssid='ap1-ssid', mode='g', channel='1', position='10,10,0')
    ap2 = net.addAccessPoint('ap2', ssid='ap2-ssid', mode='g', channel='6', position='50,10,0')

    info("*** Création des Commutateurs\n")
    s1 = net.addSwitch('s1')

    info("*** Création des Stations (Hôtes Sans Fil)\n")
    # Stations (Hôtes Sans Fil) avec IP, MAC et position
    sta1 = net.addStation('sta1', ip='10.0.0.10/24', mac='00:00:00:00:00:01', position='8,10,0')
    sta2 = net.addStation('sta2', ip='10.0.0.11/24', mac='00:00:00:00:00:02', position='12,10,0')
    sta3 = net.addStation('sta3', ip='10.0.1.10/24', mac='00:00:00:00:00:03', position='48,10,0')
    sta4 = net.addStation('sta4', ip='10.0.1.11/24', mac='00:00:00:00:00:04', position='52,10,0')

    info("*** Création de l'Hôte Filaire (Serveur)\n")
    server1 = net.addHost('server1', ip='10.0.0.100/24', mac='00:00:00:00:00:05')

    info("*** Configuration des Liens (FILAIRES et SANS FIL)\n")
    # TOUS les appels net.addLink doivent se faire AVANT net.build()
    # 2. Liens filaires entre les APs/Serveur et le Core Switch
    net.addLink(ap1, s1)
    net.addLink(ap2, s1)
    net.addLink(server1, s1)

    # 3. Liens Sans Fil : Stations vers Points d'Accès
    # Ces appels CRÉENT les interfaces sans fil sur les Stations et les APs.
    net.addLink(sta1, ap1, ssid='ap1-ssid', mode='g', channel='1', ht_cap='HT40+', intf='sta1-wlan0')
    net.addLink(sta2, ap1, ssid='ap1-ssid', mode='g', channel='1', ht_cap='HT40+', intf='sta2-wlan0')

    net.addLink(sta3, ap2, ssid='ap2-ssid', mode='g', channel='6', ht_cap='HT40+', intf='sta3-wlan0')
    net.addLink(sta4, ap2, ssid='ap2-ssid', mode='g', channel='6', ht_cap='HT40+', intf='sta4-wlan0')

    info("*** Construction du réseau\n")
    # 4. net.build() : Cette étape essentielle crée toutes les interfaces définies
    #    par les appels addLink et les rend accessibles via node.wintfs etc.
    net.build()

    info("*** Démarrage du Contrôleur\n")
    c0.start() # Démarrage du contrôleur après la construction du réseau

    info("*** Démarrage des APs et du Switch\n")
    # 5. Démarrage des APs et du Switch, en les connectant au contrôleur 'c0'
    #    Ceci doit être fait APRÈS net.build()
    ap1.start([c0])
    ap2.start([c0])
    s1.start([c0])

    info("*** Configuration de la portée des APs/Stations\n")
    # 6. Configuration de la portée des APs et Stations
    #    Ceci doit être fait APRÈS net.build() car les interfaces sans fil existent maintenant.
    ap1.setRange(25)
    ap2.setRange(25)
    sta1.setRange(25) # Les stations peuvent aussi avoir une portée
    sta2.setRange(25)
    sta3.setRange(25)
    sta4.setRange(25)

    info("*** Configuration des adresses IP des interfaces filaires des APs\n")
    # 7. Configuration des adresses IP sur les interfaces filaires des APs
    #    (si elles agissent comme des passerelles pour leurs sous-réseaux respectifs)
    #    Ceci doit être fait APRÈS net.build() et le démarrage des nœuds.
    ap1.cmd('ifconfig ap1-eth1 10.0.0.1/24 up')
    ap2.cmd('ifconfig ap2-eth1 10.0.1.1/24 up')
    server1.cmd('ifconfig server1-eth0 10.0.0.100/24 up') # S'assurer que l'IP du serveur est configurée

    info("*** Lancement de l'interface de ligne de commande (CLI)\n")
    # Optionnel : activez la télémétrie pour une visualisation
    # telemetry(net) # Décommenter si vous souhaitez utiliser la télémétrie

    CLI(net) # Lance l'interface de ligne de commande Mininet-wifi

    info("*** Arrêt du réseau\n")
    net.stop() # Arrête le réseau et nettoie les ressources

if __name__ == '__main__':
    setLogLevel('info') # Définit le niveau de log à 'info'
    complex_wifi_topology() # Exécute la fonction de création de topologie