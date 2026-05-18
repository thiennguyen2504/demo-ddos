from collections import deque
from copy import deepcopy
from threading import Lock


REQUEST_LOG_MAXLEN = 10000

request_log = deque(maxlen=REQUEST_LOG_MAXLEN)
request_log_lock = Lock()

detection_state = {
    "current_req_rate": 0,
    "unique_ips": 0,
    "avg_response_time": 0,
    "error_rate": 0,
    "alert_level": "NORMAL",
    "attack_type": None,
    "ml_trained": False,
    "ml_score": None,
    "mitigation_recommendation": None,
    "endpoint_distribution": {},
    "baseline_req_rate": 0,
    "history": [],
}

detection_state_lock = Lock()


def copy_detection_state():
    with detection_state_lock:
        return deepcopy(detection_state)


def update_detection_state(updates):
    with detection_state_lock:
        detection_state.update(updates)
        return deepcopy(detection_state)
