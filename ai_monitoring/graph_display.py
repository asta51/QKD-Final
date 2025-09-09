import matplotlib.pyplot as plt
import matplotlib.animation as animation
from ai_detection.ai_engine import AIDetectionSystem
import random
import time

# Initialize detection system
detector = AIDetectionSystem()

# For demo: generate random packets
def generate_fake_packet():
    return {
        'data': 'Hello World',
        'timestamp': time.time(),
        'source_port': random.randint(1000, 9000),
        'destination_port': random.randint(1000, 9000),
        'headers': {'User-Agent': 'test'},
        'protocol': 6,  # TCP
        'source_ip': '192.168.0.1',
        'action': random.choice(['login', 'download', 'upload', 'delete'])
    }

traffic_scores = []
behavior_scores = []
timestamps = []

def update_graph(i):
    packet = generate_fake_packet()
    result = detector.analyze_packet(packet)
    
    traffic_scores.append(result['traffic_score'])
    behavior_scores.append(result['behavior_score'])
    timestamps.append(time.strftime("%H:%M:%S"))
    
    traffic_scores_plot.set_data(range(len(traffic_scores)), traffic_scores)
    behavior_scores_plot.set_data(range(len(behavior_scores)), behavior_scores)

    ax.relim()
    ax.autoscale_view()

# Setup plot
fig, ax = plt.subplots()
traffic_scores_plot, = ax.plot([], [], label='Traffic Score', color='red')
behavior_scores_plot, = ax.plot([], [], label='Behavior Score', color='blue')
ax.set_title("Intrusion Detection Scores Over Time")
ax.set_xlabel("Time (intervals)")
ax.set_ylabel("Anomaly Score")
ax.legend()

ani = animation.FuncAnimation(fig, update_graph, interval=1000)
plt.show()
