import random
import threading
import time
from collections import defaultdict, deque

from flask import Flask, g, jsonify, request
from flask_cors import CORS
from werkzeug.middleware.proxy_fix import ProxyFix

from shared_state import request_log, request_log_lock


RATE_LIMIT_THRESHOLD = 100
RATE_LIMIT_WINDOW_SECONDS = 10
HIGH_RPS_THRESHOLD = 300
CIRCUIT_BREAKER_OPEN_SECONDS = 10

app = Flask(__name__)
CORS(app)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

state_lock = threading.Lock()
per_ip_windows = defaultdict(deque)
global_request_times = deque()
blocked_ips = set()
current_req_per_sec = 0
circuit_breaker_state = "CLOSED"
consecutive_high_seconds = 0
open_until = 0.0
half_open_started = 0.0
monitor_started = False

INTERNAL_ENDPOINTS = {"/internal/mitigation-status", "/internal/logs"}


def _purge_stale_entries(now):
    while global_request_times and now - global_request_times[0] > 1:
        global_request_times.popleft()

    for ip, timestamps in list(per_ip_windows.items()):
        while timestamps and now - timestamps[0] > RATE_LIMIT_WINDOW_SECONDS:
            timestamps.popleft()
        if timestamps:
            if len(timestamps) >= RATE_LIMIT_THRESHOLD:
                blocked_ips.add(ip)
            else:
                blocked_ips.discard(ip)
        else:
            blocked_ips.discard(ip)
            del per_ip_windows[ip]


def _monitor_mitigation_state():
    global current_req_per_sec, circuit_breaker_state, consecutive_high_seconds
    global open_until, half_open_started

    while True:
        time.sleep(1)
        now = time.time()
        with state_lock:
            _purge_stale_entries(now)
            current_req_per_sec = len(global_request_times)

            if circuit_breaker_state == "CLOSED":
                if current_req_per_sec > HIGH_RPS_THRESHOLD:
                    consecutive_high_seconds += 1
                else:
                    consecutive_high_seconds = 0

                if consecutive_high_seconds >= 3:
                    circuit_breaker_state = "OPEN"
                    open_until = now + CIRCUIT_BREAKER_OPEN_SECONDS
                    half_open_started = 0.0
                    consecutive_high_seconds = 0

            elif circuit_breaker_state == "OPEN":
                if now >= open_until:
                    circuit_breaker_state = "HALF_OPEN"
                    half_open_started = now

            elif circuit_breaker_state == "HALF_OPEN":
                if current_req_per_sec <= HIGH_RPS_THRESHOLD:
                    circuit_breaker_state = "CLOSED"
                    consecutive_high_seconds = 0
                    open_until = 0.0
                    half_open_started = 0.0
                else:
                    circuit_breaker_state = "OPEN"
                    open_until = now + CIRCUIT_BREAKER_OPEN_SECONDS
                    half_open_started = 0.0


def _ensure_monitor_started():
    global monitor_started
    if monitor_started:
        return
    monitor_started = True
    thread = threading.Thread(target=_monitor_mitigation_state, daemon=True)
    thread.start()


@app.before_request
def mitigation_layer():
    g.request_start = time.time()
    g.blocked = False

    if request.path in INTERNAL_ENDPOINTS:
        return None

    now = time.time()
    ip_address = request.remote_addr or "unknown"

    with state_lock:
        global_request_times.append(now)
        while global_request_times and now - global_request_times[0] > 1:
            global_request_times.popleft()

        if circuit_breaker_state == "OPEN":
            g.blocked = True
            return jsonify({"error": "circuit_breaker_open", "state": circuit_breaker_state}), 503

        timestamps = per_ip_windows[ip_address]
        while timestamps and now - timestamps[0] > RATE_LIMIT_WINDOW_SECONDS:
            timestamps.popleft()

        if len(timestamps) >= RATE_LIMIT_THRESHOLD:
            blocked_ips.add(ip_address)
            g.blocked = True
            return jsonify({"error": "rate_limit_exceeded", "ip": ip_address}), 429

        timestamps.append(now)
        blocked_ips.discard(ip_address)


@app.after_request
def log_request(response):
    response_time = time.time() - getattr(g, "request_start", time.time())
    blocked = bool(getattr(g, "blocked", False) or response.status_code in {429, 503})
    log_entry = {
        "timestamp": time.time(),
        "ip": request.remote_addr,
        "endpoint": request.path,
        "method": request.method,
        "response_time": response_time,
        "status_code": response.status_code,
        "blocked": blocked,
    }

    with request_log_lock:
        request_log.append(log_entry)

    return response


@app.get("/internal/mitigation-status")
def mitigation_status():
    with state_lock:
        payload = {
            "rate_limit_active": bool(blocked_ips),
            "circuit_breaker_state": circuit_breaker_state,
            "blocked_ips": sorted(blocked_ips),
            "current_req_per_sec": current_req_per_sec,
        }
    return jsonify(payload)


@app.get("/internal/logs")
def internal_logs():
    try:
        limit = int(request.args.get("limit", "100"))
    except ValueError:
        limit = 100
    limit = max(1, min(limit, 10000))

    with request_log_lock:
        items = list(request_log)[-limit:]
    return jsonify(items)


@app.post("/ue-registration")
def ue_registration():
    payload = request.get_json(silent=True) or {}
    ue_id = payload.get("ue_id", f"ue-{random.randint(1000, 9999)}")
    slice_type = payload.get("slice_type", random.choice(["eMBB", "uRLLC", "mMTC"]))
    time.sleep(random.uniform(0.01, 0.05))
    amf_id = f"amf-{random.randint(100, 999)}"
    return jsonify(
        {
            "status": "registered",
            "ue_id": ue_id,
            "slice_type": slice_type,
            "amf_id": amf_id,
            "timestamp": time.time(),
        }
    )


@app.get("/nrf/discover")
def nrf_discover():
    nf_type = request.args.get("nf_type", "AMF").upper()
    if nf_type not in {"AMF", "SMF", "UPF"}:
        nf_type = "AMF"

    time.sleep(random.uniform(0.005, 0.02))
    return jsonify(
        {
            "status": "discovered",
            "nf_type": nf_type,
            "nf_id": f"{nf_type.lower()}-{random.randint(100, 999)}",
            "services": [f"{nf_type.lower()}-service-1", f"{nf_type.lower()}-service-2"],
            "timestamp": time.time(),
        }
    )


@app.post("/slice/allocate")
def slice_allocate():
    payload = request.get_json(silent=True) or {}
    slice_type = payload.get("slice_type", random.choice(["eMBB", "uRLLC", "mMTC"]))
    ue_id = payload.get("ue_id", f"ue-{random.randint(1000, 9999)}")
    time.sleep(random.uniform(0.01, 0.04))
    return jsonify(
        {
            "status": "allocated",
            "slice_type": slice_type,
            "ue_id": ue_id,
            "slice_id": f"slice-{random.randint(10000, 99999)}",
            "timestamp": time.time(),
        }
    )


def main():
    _ensure_monitor_started()
    app.run(host="0.0.0.0", port=5000, debug=False, use_reloader=False, threaded=True)


if __name__ == "__main__":
    main()
