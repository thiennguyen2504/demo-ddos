import json
import time
import urllib.error
import urllib.request
from collections import deque
from statistics import mean
from threading import Event, Thread

import numpy as np
from sklearn.ensemble import IsolationForest

from shared_state import detection_state, detection_state_lock


SERVER_LOGS_URL = "http://127.0.0.1:5000/internal/logs?limit=10000"
NORMAL_WINDOW_SECONDS = 5
BASELINE_SECONDS = 30
POLL_INTERVAL_SECONDS = 1

stop_event = Event()
thread_started = False


def _fetch_logs():
    request = urllib.request.Request(SERVER_LOGS_URL, headers={"Accept": "application/json"})
    with urllib.request.urlopen(request, timeout=1.0) as response:
        return json.loads(response.read().decode("utf-8"))


def _compute_features(logs, now):
    recent_logs = [
        entry
        for entry in logs
        if now - float(entry.get("timestamp", 0)) <= NORMAL_WINDOW_SECONDS
        and entry.get("endpoint") not in {"/internal/logs", "/internal/mitigation-status"}
    ]

    total = len(recent_logs)
    req_rate = total / NORMAL_WINDOW_SECONDS
    unique_ips = len({entry.get("ip") for entry in recent_logs if entry.get("ip")})
    avg_response_time = mean([float(entry.get("response_time", 0)) for entry in recent_logs]) if recent_logs else 0.0
    error_rate = (
        len([entry for entry in recent_logs if int(entry.get("status_code", 0)) >= 400]) / total if total else 0.0
    )

    endpoint_counts = {}
    for entry in recent_logs:
        endpoint = entry.get("endpoint", "unknown")
        endpoint_counts[endpoint] = endpoint_counts.get(endpoint, 0) + 1

    endpoint_distribution = {
        endpoint: count / total for endpoint, count in endpoint_counts.items()
    } if total else {}

    top_endpoint = None
    top_endpoint_ratio = 0.0
    if endpoint_distribution:
        top_endpoint, top_endpoint_ratio = max(endpoint_distribution.items(), key=lambda item: item[1])

    features = [req_rate, unique_ips, avg_response_time, error_rate, top_endpoint_ratio]
    return {
        "features": features,
        "req_rate": req_rate,
        "unique_ips": unique_ips,
        "avg_response_time": avg_response_time,
        "error_rate": error_rate,
        "endpoint_distribution": endpoint_distribution,
        "top_endpoint": top_endpoint,
        "top_endpoint_ratio": top_endpoint_ratio,
    }


def _classify_attack(snapshot):
    req_rate = snapshot["req_rate"]
    unique_ips = snapshot["unique_ips"]
    error_rate = snapshot["error_rate"]
    top_endpoint = snapshot["top_endpoint"] or ""
    top_endpoint_ratio = snapshot["top_endpoint_ratio"]

    if top_endpoint == "/ue-registration" and req_rate >= 120 and unique_ips >= 25:
        return "SIGNALING_STORM"
    if top_endpoint == "/slice/allocate" and top_endpoint_ratio >= 0.6 and req_rate >= 80:
        return "SLICE_EXHAUSTION"
    if req_rate >= 150 and unique_ips <= 50 and error_rate >= 0.15:
        return "HTTP_FLOOD"
    return "UNKNOWN_DDOS"


def _mitigation_recommendation(attack_type):
    mapping = {
        "HTTP_FLOOD": "Activate rate limiting + IP blocking",
        "SIGNALING_STORM": "Enable UE registration throttling + Circuit breaker",
        "SLICE_EXHAUSTION": "Cap slice allocation rate + Queue requests",
    }
    return mapping.get(attack_type)


def _set_detection_state(updates):
    with detection_state_lock:
        detection_state.update(updates)


def _detection_loop():
    start_time = time.time()
    training_samples = []
    baseline_samples = []
    model = None
    baseline_req_rate = 0.0
    history = deque(maxlen=60)

    while not stop_event.is_set():
        now = time.time()
        try:
            logs = _fetch_logs()
        except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError):
            logs = []

        snapshot = _compute_features(logs, now)
        features = snapshot["features"]

        if now - start_time < BASELINE_SECONDS:
            training_samples.append(features)
            baseline_samples.append(snapshot["req_rate"])

        if model is None and now - start_time >= BASELINE_SECONDS and len(training_samples) >= 5:
            training_array = np.array(training_samples[:30], dtype=float)
            model = IsolationForest(contamination=0.05, random_state=42)
            model.fit(training_array)
            baseline_req_rate = float(np.mean(baseline_samples[:30])) if baseline_samples else 0.0

        ml_trained = model is not None
        ml_score = None
        ml_anomaly = False

        if ml_trained:
            prediction = int(model.predict([features])[0])
            ml_score = float(model.decision_function([features])[0])
            ml_anomaly = prediction == -1

        statistical_alert = baseline_req_rate > 0 and snapshot["req_rate"] > baseline_req_rate * 3
        alert_triggered = statistical_alert or ml_anomaly
        attack_type = _classify_attack(snapshot) if alert_triggered else None
        if alert_triggered and attack_type is None:
            attack_type = "UNKNOWN_DDOS"

        if attack_type and attack_type != "UNKNOWN_DDOS":
            alert_level = "CRITICAL"
        elif alert_triggered:
            alert_level = "WARNING"
        else:
            alert_level = "NORMAL"

        mitigation_recommendation = _mitigation_recommendation(attack_type) if attack_type else None

        history.append(
            {
                "timestamp": now,
                "req_rate": snapshot["req_rate"],
                "unique_ips": snapshot["unique_ips"],
                "avg_response_time": snapshot["avg_response_time"],
                "error_rate": snapshot["error_rate"],
                "endpoint_distribution": snapshot["endpoint_distribution"],
                "alert_level": alert_level,
                "attack_type": attack_type,
                "ml_score": ml_score,
            }
        )

        _set_detection_state(
            {
                "current_req_rate": round(snapshot["req_rate"], 2),
                "unique_ips": snapshot["unique_ips"],
                "avg_response_time": round(snapshot["avg_response_time"], 4),
                "error_rate": round(snapshot["error_rate"], 4),
                "alert_level": alert_level,
                "attack_type": attack_type,
                "ml_trained": ml_trained,
                "ml_score": round(ml_score, 4) if ml_score is not None else None,
                "mitigation_recommendation": mitigation_recommendation,
                "history": list(history),
                "baseline_req_rate": round(baseline_req_rate, 2),
                "endpoint_distribution": snapshot["endpoint_distribution"],
            }
        )

        stop_event.wait(POLL_INTERVAL_SECONDS)


def start_detection_engine():
    global thread_started
    if thread_started:
        return
    thread_started = True
    thread = Thread(target=_detection_loop, daemon=True)
    thread.start()


def stop_detection_engine():
    stop_event.set()
