# ~/ryu_apps/my_sdn_app_ml.py
import joblib
import os
import pandas as pd # Utile pour structurer les données des features

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, ipv4, tcp, udp, icmp # Importations supplémentaires pour les protocoles
from ryu.lib.packet import ether_types

# Assurez-vous que ces fichiers sont dans le répertoire d'où ryu-manager est lancé, ou spécifiez le chemin absolu
MODEL_PATH = '/home/henri/ml_scripts/traffic_classifier_model.pkl' # Adaptez le chemin
SCALER_PATH = '/home/henri/ml_scripts/scaler.pkl' # Adaptez le chemin

class SmartSDNApp(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SmartSDNApp, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.model = None
        self.scaler = None
        self._load_ml_components()

    def _load_ml_components(self):
        """Charge le modèle de classification et le scaler."""
        if os.path.exists(MODEL_PATH) and os.path.exists(SCALER_PATH):
            self.model = joblib.load(MODEL_PATH)
            self.scaler = joblib.load(SCALER_PATH)
            self.logger.info("Modèle ML et Scaler chargés avec succès.")
        else:
            self.logger.error("Erreur: Fichiers modèle ML ou scaler introuvables. Assurez-vous des chemins corrects.")
            self.model = None # S'assurer que le modèle est None pour ne pas tenter de l'utiliser
            self.scaler = None

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Règle par défaut: envoyer tous les paquets non-correspondants au contrôleur
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        self.logger.info(f"Switch {datapath.id} connecté. Règle par défaut installée.")

    def add_flow(self, datapath, priority, match, actions, buffer_id=None, hard_timeout=0, idle_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst,
                                hard_timeout=hard_timeout, idle_timeout=idle_timeout)
        if buffer_id is not None:
            mod.buffer_id = buffer_id
        datapath.send_msg(mod)

    def _extract_features(self, pkt, in_port, datapath_id):
        """
        Extrait les caractéristiques d'un paquet.
        Ceci est un exemple simplifié. Adaptez-le pour correspondre aux caractéristiques de VOTRE modèle.
        """
        features = {}
        # Longueur du paquet
        features['packet_length'] = len(pkt)

        # Protocoles
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        udp_pkt = pkt.get_protocol(udp.udp)
        icmp_pkt = pkt.get_protocol(icmp.icmp)

        features['protocol_ip'] = 0 # Par défaut, pas IP
        features['src_port'] = 0
        features['dst_port'] = 0
        features['tcp_flags_syn'] = 0
        features['tcp_flags_ack'] = 0
        features['tcp_flags_fin'] = 0

        if ip_pkt:
            features['protocol_ip'] = ip_pkt.proto # 6 for TCP, 17 for UDP, 1 for ICMP
            if tcp_pkt:
                features['src_port'] = tcp_pkt.src_port
                features['dst_port'] = tcp_pkt.dst_port
                features['tcp_flags_syn'] = 1 if tcp_pkt.has_syn else 0
                features['tcp_flags_ack'] = 1 if tcp_pkt.has_ack else 0
                features['tcp_flags_fin'] = 1 if tcp_pkt.has_fin else 0
            elif udp_pkt:
                features['src_port'] = udp_pkt.src_port
                features['dst_port'] = udp_pkt.dst_port
        elif icmp_pkt:
             features['protocol_ip'] = 1 # ICMP

        # Convertir en DataFrame pour la normalisation et la prédiction
        # Assurez-vous que l'ordre des colonnes et les noms correspondent à VOTRE entraînement
        # C'est l'étape la plus critique pour la compatibilité !
        # Il est recommandé de générer une liste ordonnée des noms de features lors de l'entraînement
        # et de l'utiliser ici. Pour cet exemple, je suppose un ordre simple.
        # Votre vrai code ML_feature_extraction.py doit exporter cette liste de colonnes.

        # Exemple d'ordre de colonnes (À ADAPTER STRICTEMENT À VOTRE TRAIN_CLASSIFIER.PY)
        # Supposons que votre modèle a été entraîné sur ces colonnes dans cet ordre:
        # ['packet_length', 'protocol_ip', 'src_port', 'dst_port', 'tcp_flags_syn', 'tcp_flags_ack', 'tcp_flags_fin']
        # C'est une simplification pour l'exemple. Un système robuste utilise une liste de colonnes prédéfinie.

        feature_names_ordered = [
            'packet_length', 'protocol_ip', 'src_port', 'dst_port',
            'tcp_flags_syn', 'tcp_flags_ack', 'tcp_flags_fin'
            # Ajoutez TOUTES les features de votre modèle ici, dans le même ordre
        ]

        # Créer un DataFrame avec une seule ligne, en s'assurant que l'ordre des colonnes est correct
        # Remplir avec 0 les features qui ne sont pas extraites pour ce paquet (si elles sont présentes dans feature_names_ordered)
        row_data = {col: features.get(col, 0) for col in feature_names_ordered}
        df_features = pd.DataFrame([row_data])

        # Assurez-vous que les types de données sont corrects (ex: int pour les flags)
        # Convertir les colonnes booléennes ou autres types non numériques en numériques si nécessaire
        for col in df_features.columns:
            if df_features[col].dtype == 'object': # Si la colonne est de type objet (string)
                # Gérer l'encodage One-Hot si utilisé lors de l'entraînement
                # Ceci est complexe car il faut recréer les mêmes colonnes dummy.
                # Pour la simplicité ici, on suppose que toutes les features sont numériques ou ont été gérées.
                pass # À adapter
            elif df_features[col].dtype == 'bool': # Si la colonne est booléenne
                df_features[col] = df_features[col].astype(int)

        return df_features


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        if self.model is None or self.scaler is None:
            self.logger.warning("Modèle ML ou scaler non chargé. Le trafic ne sera pas classifié.")
            return # Ne pas procéder si le ML n'est pas prêt

        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        # Ignorer certains types de paquets non pertinents pour la classification d'application
        if eth.ethertype == ether_types.ETH_TYPE_LLDP or eth.ethertype == ether_types.ETH_TYPE_IPV6:
            return

        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # Apprendre l'adresse MAC (comportement de base d'un switch)
        self.mac_to_port[dpid][src] = in_port

        # --- Extraction des caractéristiques ---
        raw_features_df = self._extract_features(pkt, in_port, dpid)

        # --- Normalisation des caractéristiques ---
        # IMPORTANT: Assurez-vous que le scaler est appliqué aux MÊMES colonnes
        # et dans le MÊME ORDRE que lors de l'entraînement.
        # Le scaler.transform() attend un DataFrame avec le même nombre et ordre de colonnes.
        try:
            scaled_features = self.scaler.transform(raw_features_df)
        except Exception as e:
            self.logger.error(f"Erreur lors de la normalisation des caractéristiques: {e}. Vérifiez la cohérence des features.")
            # Fallback à un comportement par défaut si le ML échoue
            out_port = ofproto.OFPP_FLOOD
            actions = [parser.OFPActionOutput(out_port)]
            self._send_packet_out(datapath, msg.buffer_id, in_port, actions, msg.data)
            return

        # --- Classification du trafic ---
        predicted_class = self.model.predict(scaled_features)[0]
        # print(f"DEBUG: Features: {raw_features_df.iloc[0].to_dict()}, Scaled: {scaled_features}, Predicted Class: {predicted_class}")
        self.logger.info(f"Paquet classifié sur SW:{dpid} (src:{src}, dst:{dst}) as: {predicted_class}")

        # --- Application des politiques de QoS ---
        out_port = ofproto.OFPP_FLOOD # Comportement par défaut si pas de destination MAC apprise
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]

        # Appliquez des actions différentes selon la classe prédite
        actions = [parser.OFPActionOutput(out_port)]
        flow_priority = 1 # Priorité de base pour les flux appris

        if predicted_class == 'VoIP':
            self.logger.info(f"Appliquant QoS pour VoIP sur SW:{dpid}")
            # Exemple: Utiliser une queue de haute priorité (si configurée sur les interfaces)
            # Note: La configuration des queues dans Mininet-wifi/OVS doit être faite AVANT.
            # ofproto_v1_3.OFPActionSetQueue(queue_id)
            # actions.append(parser.OFPActionSetQueue(queue_id=1)) # Supposons queue 1 pour VoIP
            flow_priority = 10 # Priorité plus haute pour VoIP

        elif predicted_class == 'Gaming':
            self.logger.info(f"Appliquant QoS pour Gaming sur SW:{dpid}")
            # actions.append(parser.OFPActionSetQueue(queue_id=2)) # Supposons queue 2 pour Gaming
            flow_priority = 8 # Haute priorité

        elif predicted_class == 'Video':
            self.logger.info(f"Appliquant QoS pour Video sur SW:{dpid}")
            # actions.append(parser.OFPActionSetQueue(queue_id=3)) # Supposons queue 3 pour Video
            flow_priority = 6 # Priorité moyenne

        elif predicted_class == 'Web':
            self.logger.info(f"Appliquant QoS pour Web sur SW:{dpid}")
            # actions.append(parser.OFPActionSetQueue(queue_id=4)) # Supposons queue 4 pour Web
            flow_priority = 4 # Priorité plus basse

        # Installez la règle de flux sur le commutateur
        # Utilisez un timeout pour que les règles expirent après un certain temps (pour s'adapter aux changements)
        # idle_timeout: expire si pas de trafic pendant X secondes
        # hard_timeout: expire après X secondes, même s'il y a du trafic
        flow_idle_timeout = 60 # Ex: la règle expire si inactive pendant 60 secondes
        flow_hard_timeout = 300 # Ex: la règle expire au maximum après 300 secondes

        if out_port != ofproto.OFPP_FLOOD: # N'installe pas de règles de flooding dans la table
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            self.add_flow(datapath, flow_priority, match, actions, msg.buffer_id,
                          idle_timeout=flow_idle_timeout, hard_timeout=flow_hard_timeout)

        # Re-envoyer le paquet initial (si bufferisé) ou le paquet de données
        self._send_packet_out(datapath, msg.buffer_id, in_port, actions, msg.data)

    def _send_packet_out(self, datapath, buffer_id, in_port, actions, data):
        """Helper function to send a packet_out message."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)