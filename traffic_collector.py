# network/traffic_collector.py
import time
from scapy.all import sniff
import numpy as np
from qml_ids_loader import QMLPredictor

# initialize model once
_ids_model = None
def get_model():
    global _ids_model
    if _ids_model is None:
        _ids_model = QMLPredictor("qml_model.pkl")
    return _ids_model

def extract_features(pkt):
    # Minimal, robust feature vector (8 dims) — adjust to match training features order
    try:
        length = len(pkt)
        ts = pkt.time % 60
        has_tcp = int(pkt.haslayer("TCP"))
        has_udp = int(pkt.haslayer("UDP"))
        sport = int(pkt.sport) if hasattr(pkt, "sport") else 0
        dport = int(pkt.dport) if hasattr(pkt, "dport") else 0
        ttl = int(pkt.ttl) if hasattr(pkt, "ttl") else 0
        flags = 0
        if pkt.haslayer("TCP") and hasattr(pkt["TCP"], "flags"):
            flags = int(pkt["TCP"].flags)
        # Compose compact vector — align it with the features used to train your model
        vec = np.array([length, ts, has_tcp, has_udp, sport, dport, ttl, flags], dtype=float)
        return vec
    except Exception:
        return None

def start_collector(client_ip, session_id, stop_event, ids_flags, window_count=500):
    """
    Sniffs packets for client_ip. On every packet, extract features and run the QML predictor.
    If predictor flags attack (1), set ids_flags[session_id] = {...} and stop_event.set()
    """
    model = get_model()
    def packet_callback(pkt):
        if stop_event.is_set():
            return True  # stop sniffing

        # filter by host ip
        try:
            if pkt.haslayer("IP") and (pkt["IP"].src == client_ip or pkt["IP"].dst == client_ip):
                vec = extract_features(pkt)
                if vec is None:
                    return
                pred = model.predict([vec])[0]  # 0 normal, 1 attack
                if int(pred) == 1:
                    ids_flags[session_id] = {"alert": True, "timestamp": time.time(), "detail": {"pred": int(pred)}}
                    stop_event.set()
        except Exception:
            pass

    sniff(filter=f"host {client_ip}", prn=packet_callback, store=False, stop_filter=lambda x: stop_event.is_set())
