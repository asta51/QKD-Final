# ids/feature_collector.py
# Emits feature vectors for each QKD session window and forwards them to the IDS worker.
# Integrate this into your server (and client optionally). Non-blocking.

import time
import threading
import queue
from typing import Dict, Any

# Shared queue used to communicate with the IDS worker
feature_queue = queue.Queue(maxsize=4096)

DEFAULT_WINDOW_SEC = 1.0

def safe_get_qkd_stats(qkd):
    """
    Try to read useful stats from your QKDProtocol object.
    If your QKDProtocol has different attribute names, replace here.
    Expected return (dict): { qber, detection_rate, sift_ratio, key_rate, pkt_count, avg_pkt_size, interarrival_mean, retrans_count }
    """
    try:
        # try common names; adapt if your QKDProtocol differs
        stats = {
            "qber": getattr(qkd, "qber", None),
            "detection_rate": getattr(qkd, "detection_rate", None),
            "sift_ratio": getattr(qkd, "sift_ratio", None),
            "key_rate": getattr(qkd, "key_rate", None),
            "pkt_count": getattr(qkd, "pkt_count", None),
            "avg_pkt_size": getattr(qkd, "avg_pkt_size", None),
            "interarrival_mean": getattr(qkd, "interarrival_mean", None),
            "retrans_count": getattr(qkd, "retrans_count", None),
        }
        # If the QKD object exposes a method get_stats(), prefer it
        if hasattr(qkd, "get_stats"):
            s = qkd.get_stats()
            if isinstance(s, dict):
                stats.update(s)
    except Exception:
        stats = {k: None for k in ["qber","detection_rate","sift_ratio","key_rate","pkt_count","avg_pkt_size","interarrival_mean","retrans_count"]}
    # normalize missing values to 0
    for k,v in stats.items():
        if v is None:
            stats[k] = 0.0
    return stats

def session_collector(qkd_obj, session_id: str, stop_event: threading.Event, window_sec=DEFAULT_WINDOW_SEC):
    """
    Collect feature windows for a given session and push to feature_queue as:
    (timestamp, session_id, feature_vector_dict)
    """
    while not stop_event.is_set():
        stats = safe_get_qkd_stats(qkd_obj)
        ts = time.time()
        rec = {
            "timestamp": ts,
            "session_id": session_id,
            **stats
        }
        try:
            feature_queue.put_nowait(rec)
        except queue.Full:
            # drop if queue full (backpressure)
            pass
        time.sleep(window_sec)

# Minimal helper: create thread and return stop_event
def start_session_collector(qkd_obj, session_id: str, window_sec=DEFAULT_WINDOW_SEC):
    stop_event = threading.Event()
    t = threading.Thread(target=session_collector, args=(qkd_obj, session_id, stop_event, window_sec), daemon=True)
    t.start()
    return stop_event
