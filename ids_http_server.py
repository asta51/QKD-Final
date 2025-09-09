from flask import Flask, request, jsonify
import time
from ids.real_time_ids import IntrusionDetector

app = Flask(__name__)
ids = IntrusionDetector()

@app.route("/test", methods=["POST"])
def test_ids():
    ip = request.remote_addr
    msg = request.data.decode()
    log = {
        "ip": ip,
        "timestamp": time.time(),
        "length": len(msg),
        "message": msg
    }
    result = ids.process(log)
    return jsonify({
        "anomaly": result["anomaly"],
        "details": result["anomaly_details"]
    })

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
