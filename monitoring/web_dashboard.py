# monitoring/web_dashboard.py
from flask import Flask, render_template, jsonify
from flask_socketio import SocketIO
import threading
import time
import random
from collections import deque

app = Flask(__name__)
app.config['SECRET_KEY'] = 'quantum-secret!'
socketio = SocketIO(app, async_mode='threading')

class QuantumMonitor:
    def __init__(self):
        self.connections = 0
        self.total_connections = 0
        self.anomalies = deque(maxlen=100)
        self.throughput = deque(maxlen=60)
        self.packet_sizes = deque(maxlen=100)
        self.processing_times = deque(maxlen=100)
        
    def update_metrics(self, size, proc_time):
        self.packet_sizes.append(size)
        self.processing_times.append(proc_time)
        self.throughput.append(time.time())
        
    def add_anomaly(self, score):
        self.anomalies.append({
            'time': time.time(),
            'score': score
        })
        socketio.emit('anomaly', {
            'time': time.strftime("%H:%M:%S"),
            'score': score
        })

monitor = QuantumMonitor()

@app.route('/')
def dashboard():
    return render_template('dashboard.html')

@app.route('/data')
def get_data():
    return jsonify({
        'connections': monitor.connections,
        'total_connections': monitor.total_connections,
        'throughput': len([t for t in monitor.throughput 
                          if time.time() - t < 60]),
        'avg_packet': sum(monitor.packet_sizes) / max(1, len(monitor.packet_sizes)),
        'avg_time': sum(monitor.processing_times) / max(1, len(monitor.processing_times)),
        'anomalies': list(monitor.anomalies)
    })

def simulate_traffic():
    """Simulate network traffic for demo purposes"""
    while True:
        time.sleep(random.uniform(0.1, 0.5))
        size = random.randint(500, 1500)
        proc_time = random.uniform(0.05, 0.2)
        
        # Occasionally generate anomalies
        if random.random() < 0.05:
            size *= random.uniform(3, 10)
            proc_time *= random.uniform(3, 8)
            score = random.uniform(3.5, 10)
            monitor.add_anomaly(score)
            
        monitor.update_metrics(size, proc_time)
        socketio.emit('update', {
            'size': size,
            'time': proc_time
        })

if __name__ == '__main__':
    # Start simulation thread
    sim_thread = threading.Thread(target=simulate_traffic, daemon=True)
    sim_thread.start()
    
    socketio.run(app, port=5000, debug=True)
