# ids/feature_collector.py
from scapy.all import sniff
from queue import Queue
import numpy as np

feature_queue = Queue()

def extract_features(pkt):
    try:
        length = len(pkt)
        ts_mod = pkt.time % 60
        has_tcp = int(pkt.haslayer("TCP"))
        has_udp = int(pkt.haslayer("UDP"))
        sport = getattr(pkt, "sport", 0)
        dport = getattr(pkt, "dport", 0)
        ttl = getattr(pkt, "ttl", 0)
        flags = 0
        if pkt.haslayer("TCP") and hasattr(pkt["TCP"], "flags"):
            flags = int(pkt["TCP"].flags)
        return np.array([length, ts_mod, has_tcp, has_udp, sport, dport, ttl, flags], dtype=float)
    except Exception:
        return None

def start_session_collector(qkd, session_id, window_sec=1.0):
    import threading
    stop_event = threading.Event()

    def pkt_callback(pkt):
        vec = extract_features(pkt)
        if vec is not None:
            feature_queue.put((session_id, vec))

    t = threading.Thread(
        target=sniff,
        kwargs={
            "prn": pkt_callback,
            "store": False,
            "stop_filter": lambda x: stop_event.is_set()
        },
        daemon=True
    )
    t.start()
    return stop_event
