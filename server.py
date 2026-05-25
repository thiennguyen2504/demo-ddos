import random
import threading
import time
from collections import defaultdict, deque

from flask import Flask, g, jsonify, request
from flask_cors import CORS
from werkzeug.middleware.proxy_fix import ProxyFix

from shared_state import request_log, request_log_lock


app = Flask(__name__)
CORS(app)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

state_lock = threading.Lock()
global_request_times = deque()
per_ip_windows = defaultdict(deque)
endpoint_windows = defaultdict(deque)

mitigation_state = {
    "active": False,
    "mode": None,   # "rate_limit" | "ue_throttle" | "slice_cap"
    "blocked_ips": set(),
    "blocked_endpoints": set(),
    "throttle_endpoint": None,
    "cap_endpoint": None,
    "actions_log": []
}

INTERNAL_ENDPOINTS = {"/internal/mitigation-status", "/internal/logs", "/internal/mitigation/activate", "/internal/mitigation/deactivate"}


@app.before_request
def mitigation_layer():
    g.request_start = time.time()
    g.blocked = False
    g.mitigation_delay = 0

    if request.path in INTERNAL_ENDPOINTS:
        return None

    now = time.time()
    ip_address = request.headers.get('X-Forwarded-For', request.remote_addr) or "unknown"
    print(f"[DEBUG] mitigation_layer - remote_addr: {request.remote_addr}, X-Forwarded-For: {request.headers.get('X-Forwarded-For')}, Selected IP: {ip_address}")
    path = request.path

    with state_lock:
        global_request_times.append(now)
        while global_request_times and now - global_request_times[0] > 1:
            global_request_times.popleft()

        # Always track per IP history
        ip_timestamps = per_ip_windows[ip_address]
        while ip_timestamps and now - ip_timestamps[0] > 5:
            ip_timestamps.popleft()
        ip_timestamps.append(now)

        # Always track per endpoint history
        ep_timestamps = endpoint_windows[path]
        while ep_timestamps and now - ep_timestamps[0] > 1:
            ep_timestamps.popleft()
        ep_timestamps.append(now)

        if not mitigation_state["active"]:
            return None

        mode = mitigation_state["mode"]

        if mode == "rate_limit":
            if len(ip_timestamps) > 20 and ip_address not in mitigation_state["blocked_ips"]:
                mitigation_state["blocked_ips"].add(ip_address)
                mitigation_state["actions_log"].append({
                    "time": now,
                    "action": f"Blocked IP {ip_address} — exceeded 20 req/5s"
                })
                if len(mitigation_state["actions_log"]) > 100:
                    mitigation_state["actions_log"].pop(0)

            if ip_address in mitigation_state["blocked_ips"]:
                g.blocked = True
                return jsonify({"error": "rate_limit_exceeded", "ip": ip_address}), 429

        elif mode == "ue_throttle" and path == "/ue-registration":
            if len(ep_timestamps) > 30:
                mitigation_state["actions_log"].append({
                    "time": now,
                    "action": f"Throttled /ue-registration — rate {len(ep_timestamps)} req/s exceeds limit"
                })
                if len(mitigation_state["actions_log"]) > 100:
                    mitigation_state["actions_log"].pop(0)
                g.blocked = True
                return jsonify({"error": "throttle_exceeded", "endpoint": path}), 429
            else:
                g.mitigation_delay = 0.5

        elif mode == "slice_cap" and path == "/slice/allocate":
            if len(ep_timestamps) > 20:
                mitigation_state["actions_log"].append({
                    "time": now,
                    "action": "Queued /slice/allocate request — cap reached"
                })
                if len(mitigation_state["actions_log"]) > 100:
                    mitigation_state["actions_log"].pop(0)
                g.mitigation_delay = 1.0

    if getattr(g, "mitigation_delay", 0) > 0:
        time.sleep(g.mitigation_delay)


@app.after_request
def log_request(response):
    response_time = time.time() - getattr(g, "request_start", time.time())
    blocked = bool(getattr(g, "blocked", False) or response.status_code in {429, 503})
    log_entry = {
        "timestamp": time.time(),
        "ip": request.headers.get('X-Forwarded-For', request.remote_addr) or "unknown",
        "endpoint": request.path,
        "method": request.method,
        "response_time": response_time,
        "status_code": response.status_code,
        "blocked": blocked,
    }

    with request_log_lock:
        request_log.append(log_entry)

    return response


@app.post("/internal/mitigation/activate")
def mitigation_activate():
    payload = request.get_json(silent=True) or {}
    mode = payload.get("mode")
    if mode not in ["rate_limit", "ue_throttle", "slice_cap"]:
        return jsonify({"error": "invalid mode"}), 400
        
    with state_lock:
        mitigation_state["active"] = True
        mitigation_state["mode"] = mode
        if mode == "rate_limit":
            mitigation_state["throttle_endpoint"] = None
            mitigation_state["cap_endpoint"] = None
        elif mode == "ue_throttle":
            mitigation_state["throttle_endpoint"] = "/ue-registration"
            mitigation_state["cap_endpoint"] = None
        elif mode == "slice_cap":
            mitigation_state["throttle_endpoint"] = None
            mitigation_state["cap_endpoint"] = "/slice/allocate"
            
    return jsonify({"status": "activated", "mode": mode})

@app.post("/internal/mitigation/deactivate")
def mitigation_deactivate():
    with state_lock:
        mitigation_state["active"] = False
        mitigation_state["mode"] = None
        mitigation_state["blocked_ips"].clear()
        mitigation_state["blocked_endpoints"].clear()
        mitigation_state["throttle_endpoint"] = None
        mitigation_state["cap_endpoint"] = None
        mitigation_state["actions_log"].clear()
        per_ip_windows.clear()
        endpoint_windows.clear()
        
    return jsonify({"status": "deactivated"})

@app.get("/internal/mitigation-status")
def mitigation_status():
    with state_lock:
        payload = {
            "active": mitigation_state["active"],
            "mode": mitigation_state["mode"],
            "blocked_ips": sorted(list(mitigation_state["blocked_ips"])),
            "blocked_endpoints": sorted(list(mitigation_state["blocked_endpoints"])),
            "throttle_endpoint": mitigation_state["throttle_endpoint"],
            "cap_endpoint": mitigation_state["cap_endpoint"],
            "actions_log": list(mitigation_state["actions_log"])[-50:],
            "current_req_per_sec": len(global_request_times)
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
    app.run(host="0.0.0.0", port=5000, debug=False, use_reloader=False, threaded=True)


if __name__ == "__main__":
    main()
