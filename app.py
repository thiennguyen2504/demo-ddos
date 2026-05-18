import atexit
import json
import os
import signal
import subprocess
import sys
import threading
import urllib.error
import urllib.request
from pathlib import Path

import eventlet

eventlet.monkey_patch()

from flask import Flask, jsonify, render_template  # noqa: E402
from flask_cors import CORS  # noqa: E402
from flask_socketio import SocketIO  # noqa: E402

from detection import start_detection_engine, stop_detection_engine  # noqa: E402
from shared_state import copy_detection_state  # noqa: E402


BASE_DIR = Path(__file__).resolve().parent
SERVER_URL = "http://127.0.0.1:5000"

app = Flask(__name__, template_folder=str(BASE_DIR / "templates"))
app.config["SECRET_KEY"] = "5g-ddos-demo"
CORS(app)
socketio = SocketIO(app, async_mode="eventlet", cors_allowed_origins="*")

processes = []
shutdown_lock = threading.Lock()
shutdown_started = False
last_mitigation_status = {
    "rate_limit_active": False,
    "circuit_breaker_state": "CLOSED",
    "blocked_ips": [],
    "current_req_per_sec": 0,
}


def _fetch_json(url, timeout=1.5):
    request = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def _start_subprocess(script_name):
    script_path = str(BASE_DIR / script_name)
    creationflags = 0
    if os.name == "nt" and hasattr(subprocess, "CREATE_NEW_PROCESS_GROUP"):
        creationflags = subprocess.CREATE_NEW_PROCESS_GROUP
    return subprocess.Popen([sys.executable, script_path], cwd=str(BASE_DIR), creationflags=creationflags)


def _stop_subprocesses():
    for process in processes:
        if process.poll() is None:
            process.terminate()
    for process in processes:
        if process.poll() is None:
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()


def _shutdown(*_args):
    global shutdown_started
    with shutdown_lock:
        if shutdown_started:
            return
        shutdown_started = True
    stop_detection_engine()
    _stop_subprocesses()


def _signal_shutdown(*_args):
    _shutdown()
    raise SystemExit(0)


@app.route("/")
def dashboard():
    return render_template("dashboard.html")


@app.route("/attack")
def attack_panel():
    return render_template("attacker.html")


@app.get("/api/logs")
def api_logs():
    try:
        logs = _fetch_json(f"{SERVER_URL}/internal/logs?limit=100")
    except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError):
        logs = []
    return jsonify(logs)


@app.get("/api/detection-state")
def api_detection_state():
    return jsonify(copy_detection_state())


def _broadcast_metrics():
    global last_mitigation_status
    while True:
        detection_snapshot = copy_detection_state()
        try:
            last_mitigation_status = _fetch_json(f"{SERVER_URL}/internal/mitigation-status")
        except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError):
            pass

        payload = dict(detection_snapshot)
        payload["mitigation_status"] = last_mitigation_status
        socketio.emit("metrics_update", payload)
        socketio.sleep(1)


def main():
    processes.append(_start_subprocess("server.py"))
    processes.append(_start_subprocess("attacker.py"))

    start_detection_engine()
    socketio.start_background_task(_broadcast_metrics)

    signal.signal(signal.SIGINT, _signal_shutdown)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, _signal_shutdown)
    atexit.register(_shutdown)

    try:
        socketio.run(app, host="0.0.0.0", port=8080, debug=False, use_reloader=False)
    finally:
        _shutdown()


if __name__ == "__main__":
    main()
