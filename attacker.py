import argparse
import asyncio
import random
import time
from typing import Optional

import aiohttp
from aiohttp import web


SERVER_BASE_URL = "http://127.0.0.1:5000"

app = web.Application()


@web.middleware
async def cors_middleware(request, handler):
    if request.method == "OPTIONS":
        return web.Response(
            status=204,
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
                "Access-Control-Allow-Headers": "Content-Type,Authorization",
            },
        )

    response = await handler(request)
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET,POST,OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type,Authorization"
    return response


app.middlewares.append(cors_middleware)

running = False
current_mode: Optional[str] = None
current_duration = 0
attack_started_at = 0.0
requests_sent = 0
stop_event = asyncio.Event()
attack_task: Optional[asyncio.Task] = None
counter_lock = asyncio.Lock()


def _random_ip():
    return f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"


def _endpoint_payload(mode):
    if mode == "normal":
        endpoint = random.choice(["/nrf/discover", "/slice/allocate", "/ue-registration"])
        if endpoint == "/nrf/discover":
            return "GET", endpoint, None
        return "POST", endpoint, {
            "ue_id": f"ue-{random.randint(1000, 9999)}",
            "slice_type": random.choice(["eMBB", "uRLLC", "mMTC"]),
        }

    if mode == "http_flood":
        endpoint = random.choice(["/nrf/discover", "/slice/allocate", "/ue-registration"])
        if endpoint == "/nrf/discover":
            return "GET", endpoint, None
        return "POST", endpoint, {
            "ue_id": f"ue-{random.randint(1000, 9999)}",
            "slice_type": random.choice(["eMBB", "uRLLC", "mMTC"]),
        }

    if mode == "signaling_storm":
        return "POST", "/ue-registration", {
            "ue_id": f"ue-{int(time.time() * 1000)}-{random.randint(100000, 999999)}",
            "slice_type": random.choice(["eMBB", "uRLLC", "mMTC"]),
        }

    if mode == "slice_exhaustion":
        if random.random() < 0.9:
            return "POST", "/slice/allocate", {
                "ue_id": f"ue-{random.randint(1000, 9999)}",
                "slice_type": random.choice(["eMBB", "uRLLC", "mMTC"]),
            }
        return "POST", "/ue-registration", {
            "ue_id": f"ue-{random.randint(1000, 9999)}",
            "slice_type": random.choice(["eMBB", "uRLLC", "mMTC"]),
        }

    return "GET", "/nrf/discover", None


async def _send_request(session, mode):
    global requests_sent

    method, endpoint, payload = _endpoint_payload(mode)
    headers = {"X-Forwarded-For": _random_ip()}
    url = f"{SERVER_BASE_URL}{endpoint}"

    try:
        if method == "GET":
            async with session.get(url, headers=headers, timeout=5) as response:
                await response.text()
        else:
            async with session.post(url, json=payload, headers=headers, timeout=5) as response:
                await response.text()
    except Exception:
        pass
    finally:
        async with counter_lock:
            requests_sent += 1


async def _run_normal_mode(session, end_time):
    while not stop_event.is_set() and time.time() < end_time:
        batch = random.randint(5, 10)
        for _ in range(batch):
            await _send_request(session, "normal")
            await asyncio.sleep(random.uniform(0.1, 0.2))


async def _run_worker_loop(session, mode, end_time, delay):
    while not stop_event.is_set() and time.time() < end_time:
        await _send_request(session, mode)
        await asyncio.sleep(delay)


async def _run_flood_mode(session, mode, end_time, rate_min, rate_max, worker_count=200):
    while not stop_event.is_set() and time.time() < end_time:
        target_rate = random.randint(rate_min, rate_max)
        delay = max(0.001, worker_count / float(target_rate))
        workers = [asyncio.create_task(_run_worker_loop(session, mode, min(end_time, time.time() + 1), delay)) for _ in range(worker_count)]
        await asyncio.gather(*workers, return_exceptions=True)


async def _attack_controller(mode, duration):
    global running, current_mode, current_duration, attack_started_at, requests_sent
    stop_event.clear()
    running = True
    current_mode = mode
    current_duration = duration
    attack_started_at = time.time()
    requests_sent = 0

    async with aiohttp.ClientSession() as session:
        end_time = attack_started_at + duration
        if mode == "normal":
            await _run_normal_mode(session, end_time)
        elif mode == "http_flood":
            await _run_flood_mode(session, mode, end_time, 500, 2000)
        elif mode == "signaling_storm":
            await _run_flood_mode(session, mode, end_time, 800, 1500)
        elif mode == "slice_exhaustion":
            await _run_flood_mode(session, mode, end_time, 300, 600)
        else:
            await _run_normal_mode(session, end_time)

    running = False
    current_mode = None
    current_duration = 0


async def _start_attack(request):
    global attack_task
    if attack_task and not attack_task.done():
        return web.json_response({"status": "already_running"}, status=409)

    body = await request.json()
    mode = body.get("mode", "normal")
    duration = int(body.get("duration", 30))
    duration = max(1, min(duration, 120))

    attack_task = asyncio.create_task(_attack_controller(mode, duration))
    return web.json_response({"status": "started", "mode": mode, "duration": duration})


async def _stop_attack(request):
    global attack_task, running, current_mode, current_duration
    stop_event.set()
    if attack_task and not attack_task.done():
        attack_task.cancel()
        try:
            await attack_task
        except Exception:
            pass
    running = False
    current_mode = None
    current_duration = 0
    return web.json_response({"status": "stopped"})


async def _attack_status(request):
    if running:
        elapsed = time.time() - attack_started_at
        remaining = max(0, int(current_duration - elapsed))
        progress = 0 if current_duration <= 0 else min(100, int((elapsed / current_duration) * 100))
    else:
        remaining = 0
        progress = 0

    return web.json_response(
        {
            "running": running,
            "mode": current_mode or "idle",
            "duration_remaining": remaining,
            "requests_sent": requests_sent,
            "progress": progress,
        }
    )


def _build_app():
    app.add_routes(
        [
            web.post("/attack/start", _start_attack),
            web.post("/attack/stop", _stop_attack),
            web.get("/attack/status", _attack_status),
        ]
    )
    return app


def _parse_args():
    parser = argparse.ArgumentParser(description="5G DDoS attack simulator")
    parser.add_argument("--mode", choices=["normal", "http_flood", "signaling_storm", "slice_exhaustion"], default=None)
    parser.add_argument("--duration", type=int, default=30)
    parser.add_argument("--start", action="store_true")
    return parser.parse_args()


def main():
    args = _parse_args()
    _build_app()

    if args.start and args.mode:
        async def start_on_boot(_app):
            await asyncio.sleep(0.5)
            asyncio.create_task(_attack_controller(args.mode, max(1, min(args.duration, 120))))

        app.on_startup.append(start_on_boot)

    web.run_app(app, host="0.0.0.0", port=5001)


if __name__ == "__main__":
    main()
