import eventlet
eventlet.monkey_patch()  # Essential: must be called before any other imports

import time
import math
import threading
import logging
import random
from collections import deque, Counter
from flask import Flask, request, jsonify
from flask_socketio import SocketIO
from flask_cors import CORS
from sklearn.ensemble import IsolationForest
import numpy as np

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

app = Flask(__name__)
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')

# ---------------------------------------------------------------------------
# Shared State — all reads/writes protected by data_lock
# ---------------------------------------------------------------------------
request_logs = deque(maxlen=10000)   # Sliding window log store
recent_events = deque(maxlen=10)     # Ring buffer for dashboard event log

SYSTEM_STATE = "TRAINING"            # TRAINING → NORMAL → ALERT → ATTACK_CONFIRMED → RECOVERING
MITIGATION_ACTION = "NONE"           # NONE, RATE_LIMIT_GLOBAL, RATE_LIMIT_UE, RATE_LIMIT_SLICE
is_model_trained = False
model = IsolationForest(contamination=0.05, random_state=42)
training_data = []
baseline_req_rate = 1.0              # FIX Bug 1: updated to AVERAGE (not max) after training
recovering_ticks = 0                 # FIX Bug 2: cooldown counter before returning to NORMAL
start_time = time.time()

data_lock = threading.Lock()         # FIX Bug 3: guards ALL shared mutable state

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def calculate_entropy(endpoints):
    """Shannon entropy of endpoint distribution.
    High entropy = traffic spread across endpoints (normal behavior).
    Low entropy  = traffic hammering one endpoint (signaling storm / slice exhaustion).
    """
    if not endpoints:
        return 0.0
    counts = Counter(endpoints)
    total = len(endpoints)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def process_request(endpoint, logic_func):
    """Execute endpoint logic, measure latency, and append structured log entry."""
    t0 = time.time()

    global MITIGATION_ACTION

    # Respect X-Forwarded-For set by attacker.py to simulate spoofed source IPs
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    if client_ip:
        client_ip = client_ip.split(',')[0].strip()

    # --- Auto Mitigation Enforcement ---
    with data_lock:
        current_mitigation = MITIGATION_ACTION
        
    if current_mitigation != "NONE":
        drop_request = False
        # Drop 80% globally or 90% specifically to save backend
        if current_mitigation == "RATE_LIMIT_GLOBAL" and random.random() < 0.8:
            drop_request = True
        elif current_mitigation == "RATE_LIMIT_UE" and endpoint == '/ue-registration' and random.random() < 0.9:
            drop_request = True
        elif current_mitigation == "RATE_LIMIT_SLICE" and endpoint == '/slice/allocate' and random.random() < 0.9:
            drop_request = True
            
        if drop_request:
            # Tarpit: Hold the connection for 2 seconds to simulate a network-level DROP
            # This exhausts the attacker's concurrency limit, effectively throttling them!
            time.sleep(2.0)
            
            # Crucial Fix: DO NOT append to request_logs! 
            # If we log dropped requests, the req_rate stays artificially high,
            # and the system never transitions out of ATTACK_CONFIRMED.
            # By not logging it, the server sees a drop in "successful" requests
            # and can transition to RECOVERING when the attacker stops.
            return jsonify({"error": "Rate limited by Auto-Mitigation AI"}), 429

    error = False
    try:
        result = logic_func()
        response = jsonify(result)
    except Exception as e:
        error = True
        response = jsonify({"error": str(e)}), 500

    response_time = time.time() - t0

    with data_lock:
        request_logs.append({
            'timestamp': time.time(),
            'ip': client_ip,
            'endpoint': endpoint,
            'response_time': response_time,
            'error': error
        })

    return response

# ---------------------------------------------------------------------------
# 5G SBA Endpoints
# ---------------------------------------------------------------------------

@app.route('/')
def health():
    return jsonify({"status": "5G SBA Simulator running",
                    "endpoints": ["/ue-registration", "/nrf/discover", "/slice/allocate"]})


@app.route('/ue-registration', methods=['POST'])
def ue_registration():
    """AMF — UE authentication and registration into the 5G Core."""
    def logic():
        time.sleep(random.uniform(0.01, 0.05))
        ue_id = (request.json or {}).get("ue_id", "UE-unknown")
        return {"status": "registered", "ue_id": ue_id}
    return process_request('/ue-registration', logic)


@app.route('/nrf/discover', methods=['GET'])
def nrf_discover():
    """NRF — Network Function discovery (service registry lookup)."""
    def logic():
        time.sleep(random.uniform(0.005, 0.02))
        return {"status": "ok", "services": ["AMF", "SMF", "UPF", "AUSF"]}
    return process_request('/nrf/discover', logic)


@app.route('/slice/allocate', methods=['POST'])
def slice_allocate():
    """SMF — Network Slice resource allocation (resource-intensive operation)."""
    def logic():
        time.sleep(random.uniform(0.02, 0.08))
        return {"status": "allocated", "slice_id": f"slice-{int(time.time() * 1000) % 9999}"}
    return process_request('/slice/allocate', logic)

# ---------------------------------------------------------------------------
# Background Analysis Thread — runs every 1 second
# ---------------------------------------------------------------------------

def analysis_thread():
    global SYSTEM_STATE, is_model_trained, baseline_req_rate, training_data, recovering_ticks, MITIGATION_ACTION

    while True:
        time.sleep(1)
        now = time.time()
        uptime = now - start_time

        # --- Snapshot last 5 seconds via sliding window ---
        with data_lock:
            window_logs = [log for log in request_logs if now - log['timestamp'] <= 5]

        total_req = len(window_logs)
        req_rate = total_req / 5.0

        unique_ips = len(set(log['ip'] for log in window_logs)) if window_logs else 0
        avg_response_time = (
            sum(log['response_time'] for log in window_logs) / total_req if total_req else 0
        )
        error_rate = (
            sum(1 for log in window_logs if log['error']) / total_req if total_req else 0
        )
        endpoint_entropy = calculate_entropy([log['endpoint'] for log in window_logs])

        # Feature vector fed to IsolationForest
        feature_vector = [req_rate, unique_ips, avg_response_time, error_rate, endpoint_entropy]

        # --- Phase 1: Collect baseline training data for first 30 seconds ---
        if uptime < 30:
            with data_lock:
                training_data.append(feature_vector)
            SYSTEM_STATE = "TRAINING"

        # --- Train IsolationForest once at the 30-second mark ---
        elif not is_model_trained:
            with data_lock:
                snapshot = list(training_data)

            logging.info("Training IsolationForest on %d samples...", len(snapshot))
            model.fit(snapshot)
            is_model_trained = True

            # FIX Bug 1: baseline = AVERAGE of training rates, not max()
            # Using max() caused inflated threshold if any early spike occurred
            rates = [row[0] for row in snapshot]
            with data_lock:
                baseline_req_rate = sum(rates) / len(rates) if rates else 1.0

            logging.info("Training complete. Baseline = %.2f req/s", baseline_req_rate)
            with data_lock:
                recent_events.append({
                    "time": time.strftime("%H:%M:%S"),
                    "event": "MODEL READY",
                    "detail": f"Baseline = {baseline_req_rate:.1f} req/s. Detection active."
                })
            SYSTEM_STATE = "NORMAL"

        # --- Phase 2: Active monitoring ---
        else:
            with data_lock:
                current_baseline = baseline_req_rate
                current_state = SYSTEM_STATE

            effective_baseline = max(current_baseline, 3.0)  # Floor prevents noise from triggering at near-zero baseline

            # Layer 1: Statistical — immediate, but coarse
            layer1_alert = req_rate > (effective_baseline * 3)

            # Layer 2: ML anomaly — slower to confirm, fewer false positives
            X = np.array(feature_vector).reshape(1, -1)
            prediction = model.predict(X)[0]
            layer2_anomaly = (prediction == -1)

            # --- State machine ---
            # FIX Bug 2: RECOVERING requires 5 consecutive clean ticks (~5 seconds)
            # before returning to NORMAL, preventing rapid flip-flop on burst attacks

            if layer1_alert and layer2_anomaly:
                recovering_ticks = 0
                if current_state != "ATTACK_CONFIRMED":
                    new_state = "ATTACK_CONFIRMED"
                    
                    # --- AI Mitigation Decision Engine ---
                    new_mitigation = "RATE_LIMIT_GLOBAL"
                    if endpoint_entropy < 1.0: # Highly concentrated attack on specific endpoints
                        with data_lock:
                            endpoints_arr = [log['endpoint'] for log in window_logs]
                        most_common = Counter(endpoints_arr).most_common(1)
                        if most_common:
                            if most_common[0][0] == '/ue-registration':
                                new_mitigation = "RATE_LIMIT_UE"
                            elif most_common[0][0] == '/slice/allocate':
                                new_mitigation = "RATE_LIMIT_SLICE"
                                
                    with data_lock:
                        MITIGATION_ACTION = new_mitigation
                        recent_events.append({
                            "time": time.strftime("%H:%M:%S"),
                            "event": "⚠ ATTACK CONFIRMED",
                            "detail": f"Rate {req_rate:.0f}/s — {unique_ips} IPs — ML anomaly"
                        })
                        recent_events.append({
                            "time": time.strftime("%H:%M:%S"),
                            "event": "🛡 MITIGATION",
                            "detail": f"AI Engine activated: {new_mitigation}"
                        })
                    logging.warning("ATTACK_CONFIRMED: %.0f req/s, %d IPs", req_rate, unique_ips)
                else:
                    new_state = "ATTACK_CONFIRMED"

            elif layer1_alert or layer2_anomaly:
                recovering_ticks = 0
                if current_state == "ATTACK_CONFIRMED":
                    new_state = "ATTACK_CONFIRMED"  # Stay confirmed until fully clear
                else:
                    if current_state != "ALERT":
                        with data_lock:
                            recent_events.append({
                                "time": time.strftime("%H:%M:%S"),
                                "event": "ALERT",
                                "detail": f"Rate {req_rate:.0f}/s — threshold breached"
                            })
                    new_state = "ALERT"

            else:
                if current_state in ("ATTACK_CONFIRMED", "ALERT"):
                    # Transition to cooldown period
                    recovering_ticks = 0
                    new_state = "RECOVERING"
                    with data_lock:
                        if MITIGATION_ACTION != "NONE":
                            recent_events.append({
                                "time": time.strftime("%H:%M:%S"),
                                "event": "🛡 MITIGATION",
                                "detail": f"AI Engine deactivating {MITIGATION_ACTION}"
                            })
                            MITIGATION_ACTION = "NONE"
                            
                        recent_events.append({
                            "time": time.strftime("%H:%M:%S"),
                            "event": "RECOVERING",
                            "detail": "Attack traffic subsiding"
                        })
                elif current_state == "RECOVERING":
                    recovering_ticks += 1
                    if recovering_ticks >= 5:
                        new_state = "NORMAL"
                        with data_lock:
                            recent_events.append({
                                "time": time.strftime("%H:%M:%S"),
                                "event": "✓ NORMAL",
                                "detail": "System fully recovered"
                            })
                    else:
                        new_state = "RECOVERING"
                else:
                    recovering_ticks = 0
                    new_state = "NORMAL"

            with data_lock:
                SYSTEM_STATE = new_state

        # --- Emit metrics snapshot to all dashboard WebSocket clients ---
        with data_lock:
            events_snapshot = list(recent_events)
            emit_state = SYSTEM_STATE
            emit_baseline = baseline_req_rate
            emit_mitigation = MITIGATION_ACTION

        socketio.emit('metrics_update', {
            'req_rate': round(req_rate, 2),
            'unique_ips': unique_ips,
            'avg_response_time': round(avg_response_time * 1000, 2),
            'error_rate': round(error_rate * 100, 2),
            'system_state': emit_state,
            'baseline_rate': round(emit_baseline, 2),
            'threshold_rate': round(max(emit_baseline, 3.0) * 3, 2),
            'uptime': round(uptime, 1),
            'recent_events': events_snapshot,
            'mitigation_action': emit_mitigation
        })


if __name__ == '__main__':
    logging.info("Starting 5G SBA Simulator on http://localhost:5000 ...")
    t = threading.Thread(target=analysis_thread, daemon=True)
    t.start()
    socketio.run(app, host='0.0.0.0', port=5000, debug=False)