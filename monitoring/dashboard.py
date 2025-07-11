# monitoring/dashboard.py
from flask import Flask, render_template, jsonify
import threading
import time
from datetime import datetime
import json
from collections import deque
import socket

app = Flask(__name__)

# Mock data storage (in a real app, use a database)
security_events = deque(maxlen=100)
server_stats = {
    'connections': 0,
    'throughput': 0,
    'start_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    'anomalies': 0,
    'intrusions': 0
}

def read_logs():
    """Read logs from files"""
    try:
        with open("anomalies.log", "r") as f:
            anomalies = [json.loads(line) for line in f.readlines()]
    except FileNotFoundError:
        anomalies = []
    
    try:
        with open("intrusions.log", "r") as f:
            intrusions = [json.loads(line) for line in f.readlines()]
    except FileNotFoundError:
        intrusions = []
    
    return anomalies, intrusions

@app.route('/')
def dashboard():
    anomalies, intrusions = read_logs()
    return render_template('dashboard.html',
                         stats=server_stats,
                         anomalies=anomalies[-10:],
                         intrusions=intrusions[-10:])

@app.route('/api/stats')
def get_stats():
    anomalies, intrusions = read_logs()
    return jsonify({
        'connections': server_stats['connections'],
        'throughput': server_stats['throughput'],
        'uptime': str(datetime.now() - datetime.strptime(server_stats['start_time'], "%Y-%m-%d %H:%M:%S")),
        'anomalies': len(anomalies),
        'intrusions': len(intrusions),
        'recent_anomalies': anomalies[-5:],
        'recent_intrusions': intrusions[-5:]
    })

@app.route('/api/events')
def get_events():
    return jsonify(list(security_events))

def start_monitoring(server):
    """Background thread to update monitoring data"""
    while True:
        anomalies, intrusions = read_logs()
        server_stats.update({
            'connections': server.connection_stats['active'],
            'throughput': server.connection_stats['throughput'],
            'anomalies': len(anomalies),
            'intrusions': len(intrusions)
        })
        time.sleep(2)

def run_dashboard(host='0.0.0.0', port=5000, server=None):
    if server:
        monitor_thread = threading.Thread(target=start_monitoring, args=(server,))
        monitor_thread.daemon = True
        monitor_thread.start()
    
    app.run(host=host, port=port)

if __name__ == '__main__':
    run_dashboard()
