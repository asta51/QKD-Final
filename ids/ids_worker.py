# ids/ids_worker.py
import threading
import time
from queue import Empty
from .feature_collector import feature_queue
from .qml_ids_loader import QMLPredictor

ids_flags = {}
_running = False

def ids_loop():
    model = QMLPredictor("qml_model.pkl")
    while _running:
        try:
            session_id, features = feature_queue.get(timeout=1.0)
        except Empty:
            continue
        try:
            pred = model.predict([features])[0]
            if int(pred) == 1:  # 1 means attack
                ids_flags[session_id] = {
                    "alert": True,
                    "timestamp": time.time(),
                    "detail": {"pred": int(pred)}
                }
                print(f"[IDS] ALERT for session {session_id} at {time.ctime()}")
        except Exception as e:
            print(f"[IDS] Prediction error: {e}")

def start_ids_worker():
    global _running
    _running = True
    threading.Thread(target=ids_loop, daemon=True).start()

def stop_ids_worker():
    global _running
    _running = False
