import matplotlib.pyplot as plt
from matplotlib.animation import FuncAnimation
import numpy as np
import time
from datetime import datetime
import json
from collections import deque
from network.secure_server import SecureServer

class QuantumSecurityDashboard:
    def __init__(self, server_instance=None, update_interval=2):
        self.server = server_instance
        self.update_interval = update_interval
        self.fig = plt.figure(figsize=(15, 10))
        self.fig.suptitle("Quantum Security Monitoring Dashboard", fontsize=16)
        
        # Create subplots grid
        self.ax1 = plt.subplot2grid((3, 2), (0, 0))  # Anomaly Scores
        self.ax2 = plt.subplot2grid((3, 2), (0, 1))  # Intrusion Detection
        self.ax3 = plt.subplot2grid((3, 2), (1, 0), colspan=2)  # Traffic Flow
        self.ax4 = plt.subplot2grid((3, 2), (2, 0))  # Connection Stats
        self.ax5 = plt.subplot2grid((3, 2), (2, 1))  # Quantum Metrics
        
        # Initialize data structures with at least one value
        self.time_window = 300  # 5 minutes
        self.anomaly_scores = deque([0], maxlen=100)
        self.intrusion_scores = {
            'timing': deque([0], maxlen=100),
            'pattern': deque([0], maxlen=100),
            'quantum': deque([0], maxlen=100)
        }
        self.traffic_data = {
            'incoming': deque([0], maxlen=100),
            'outgoing': deque([0], maxlen=100)
        }
        self.connection_stats = {
            'active': deque([0], maxlen=100),
            'blocked': deque([0], maxlen=100)
        }
        self.quantum_metrics = {
            'key_gen_time': deque([0], maxlen=100),
            'error_rate': deque([0], maxlen=100)
        }
        self.timestamps = deque([datetime.now()], maxlen=100)
        
        # Initialize plots with valid data
        self._init_plots()
        
    def _init_plots(self):
        """Initialize all plot elements with valid data"""
        # Anomaly Scores Plot
        self.anomaly_line, = self.ax1.plot(
            [0], [0], 'r-', label='Anomaly Score')
        self.ax1.set_title("Real-time Anomaly Detection")
        self.ax1.set_ylabel("Z-Score")
        self.ax1.set_ylim(0, 10)
        self.ax1.axhline(y=2.5, color='orange', linestyle='--', label='Warning')
        self.ax1.axhline(y=3.5, color='red', linestyle='--', label='Critical')
        self.ax1.legend()
        
        # Intrusion Detection Plot
        self.timing_line, = self.ax2.plot(
            [0], [0], 'b-', label='Timing')
        self.pattern_line, = self.ax2.plot(
            [0], [0], 'g-', label='Pattern')
        self.quantum_line, = self.ax2.plot(
            [0], [0], 'm-', label='Quantum')
        self.ax2.set_title("Intrusion Detection Scores")
        self.ax2.set_ylim(-1, 1)
        self.ax2.axhline(y=0, color='gray', linestyle='-')
        self.ax2.axhline(y=-0.5, color='orange', linestyle='--')
        self.ax2.legend()
        
        # Traffic Flow Plot
        self.incoming_line, = self.ax3.plot(
            [0], [0], 'b-', label='Incoming')
        self.outgoing_line, = self.ax3.plot(
            [0], [0], 'g-', label='Outgoing')
        self.ax3.set_title("Network Traffic Flow (bytes/sec)")
        self.ax3.legend()
        
        # Connection Stats Plot
        self.conn_plot = self.ax4.bar(
            ['Active', 'Blocked'], [1, 0], color=['blue', 'red'])
        self.ax4.set_title("Connection Statistics")
        self.ax4.set_ylim(0, 20)
        
        # Quantum Metrics Plot
        self.key_gen_line, = self.ax5.plot(
            [0], [0], 'b-', label='Key Gen Time')
        self.error_line, = self.ax5.plot(
            [0], [0], 'r-', label='Error Rate')
        self.ax5.set_title("Quantum Channel Metrics")
        self.ax5.legend()
        
        plt.tight_layout()
        
    def _update_data(self):
        """Collect current metrics"""
        timestamp = datetime.now()
        self.timestamps.append(timestamp)
        
        # Simulate data if no server connected
        if self.server is None:
            self._simulate_data()
            return
        
        # Get real data from server if available
        self._get_server_data()
        
    def _simulate_data(self):
        """Generate simulated monitoring data"""
        self.anomaly_scores.append(np.random.uniform(0, 5))
        self.intrusion_scores['timing'].append(np.random.uniform(-1, 1))
        self.intrusion_scores['pattern'].append(np.random.uniform(-1, 1))
        self.intrusion_scores['quantum'].append(np.random.uniform(-1, 1))
        self.traffic_data['incoming'].append(np.random.randint(500, 1500))
        self.traffic_data['outgoing'].append(np.random.randint(300, 1200))
        self.connection_stats['active'].append(np.random.randint(1, 10))
        self.connection_stats['blocked'].append(np.random.randint(0, 3))
        self.quantum_metrics['key_gen_time'].append(np.random.uniform(0.1, 0.5))
        self.quantum_metrics['error_rate'].append(np.random.uniform(0.01, 0.15))
        
    def _get_server_data(self):
        """Get real data from server"""
        if hasattr(self.server, 'anomaly_detector'):
            try:
                _, score = self.server.anomaly_detector.detect_anomaly()
                self.anomaly_scores.append(score)
            except:
                self.anomaly_scores.append(np.random.uniform(0, 5))
        
        # Add more real data collection from server here
        
    def update(self, frame):
        """Update all plots with new data"""
        self._update_data()
        
        # Ensure we have valid data
        if len(self.timestamps) < 1:
            return []
            
        # Convert timestamps to relative seconds
        time_axis = [(t - self.timestamps[0]).total_seconds() 
                    for t in self.timestamps]
        
        # Update all plots
        self._update_anomaly_plot(time_axis)
        self._update_intrusion_plot(time_axis)
        self._update_traffic_plot(time_axis)
        self._update_connection_stats()
        self._update_quantum_metrics(time_axis)
        self._update_status_indicators()
        
        return self._get_all_artists()
    
    def _update_anomaly_plot(self, time_axis):
        """Update anomaly detection plot"""
        self.anomaly_line.set_data(time_axis, self.anomaly_scores)
        self.ax1.set_xlim(0, max(10, time_axis[-1] if time_axis else 0))
        self.ax1.relim()
        self.ax1.autoscale_view()
        
    def _update_intrusion_plot(self, time_axis):
        """Update intrusion detection plot"""
        self.timing_line.set_data(time_axis, self.intrusion_scores['timing'])
        self.pattern_line.set_data(time_axis, self.intrusion_scores['pattern'])
        self.quantum_line.set_data(time_axis, self.intrusion_scores['quantum'])
        self.ax2.set_xlim(self.ax1.get_xlim())
        
    def _update_traffic_plot(self, time_axis):
        """Update traffic flow plot"""
        self.incoming_line.set_data(time_axis, self.traffic_data['incoming'])
        self.outgoing_line.set_data(time_axis, self.traffic_data['outgoing'])
        self.ax3.set_xlim(self.ax1.get_xlim())
        
    def _update_connection_stats(self):
        """Update connection statistics"""
        for i, (rect, val) in enumerate(zip(self.conn_plot, 
                                          [self.connection_stats['active'][-1] if self.connection_stats['active'] else 1,
                                           self.connection_stats['blocked'][-1] if self.connection_stats['blocked'] else 0])):
            rect.set_height(val)
        self.ax4.relim()
        self.ax4.autoscale_view()
        
    def _update_quantum_metrics(self, time_axis):
        """Update quantum metrics plot"""
        self.key_gen_line.set_data(time_axis, self.quantum_metrics['key_gen_time'])
        self.error_line.set_data(time_axis, self.quantum_metrics['error_rate'])
        self.ax5.set_xlim(self.ax1.get_xlim())
        
    def _update_status_indicators(self):
        """Update status indicators"""
        for ax in [self.ax1, self.ax2, self.ax3, self.ax5]:
            for txt in ax.texts:
                txt.remove()
                
        if len(self.anomaly_scores) > 0:
            status = "CRITICAL" if self.anomaly_scores[-1] > 3.5 else \
                    "WARNING" if self.anomaly_scores[-1] > 2.5 else "NORMAL"
            color = "red" if status == "CRITICAL" else \
                   "orange" if status == "WARNING" else "green"
            self.ax1.text(0.98, 0.95, status, transform=self.ax1.transAxes,
                         color=color, ha='right', va='top', fontsize=12,
                         bbox=dict(facecolor='white', alpha=0.7))
        
    def _get_all_artists(self):
        """Get all artists for animation"""
        artists = [self.anomaly_line, self.timing_line, self.pattern_line,
                  self.quantum_line, self.incoming_line, self.outgoing_line,
                  *self.conn_plot, self.key_gen_line, self.error_line]
        
        # Ensure all artists have valid data
        return [a for a in artists if a is not None and hasattr(a, 'get_data')]
    
    def start(self):
        """Start the real-time dashboard"""
        # Initial draw to set up valid state
        self.update(0)
        
        # Start animation with proper parameters
        self.ani = FuncAnimation(
            self.fig, 
            self.update, 
            init_func=lambda: self._get_all_artists(),
            interval=self.update_interval*1000,
            cache_frame_data=False,
            save_count=100,
            blit=True
        )
        plt.show()

if __name__ == "__main__":
    # Example usage with a dummy server
    class DummyServer:
        def __init__(self):
            class AnomalyDetector:
                def detect_anomaly(self):
                    return False, np.random.uniform(0, 5)
            self.anomaly_detector = AnomalyDetector()
            self.active_connections = {}
    
    server = SecureServer()
    dashboard = QuantumSecurityDashboard(server)
    dashboard.start()
