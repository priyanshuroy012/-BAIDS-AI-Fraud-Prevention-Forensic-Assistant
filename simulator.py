import random
import requests
import time
import argparse
import json
import os

API_URL = "http://127.0.0.1:5000/predict"

# ---------------------------
# Event Generator
# ---------------------------
def generate_event(event_type="normal"):
    base = {
        "email": f"user{random.randint(1,100)}@example.com",
        "ip": f"192.168.{random.randint(0,1)}.{random.randint(1,254)}",
        "device_id": "DEVICE123",
        "imei": "123456789012345",
        "location": "Delhi, IN",
        "timestamp": time.time()
    }

    if event_type == "normal":
        return base
    elif event_type == "suspicious":
        base["device_id"] = f"DEV{random.randint(1000,9999)}"
        return base
    elif event_type == "fraud":
        base["ip"] = f"203.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
        base["imei"] = f"{random.randint(100000000000000,999999999999999)}"
        base["location"] = random.choice(["Moscow, RU", "Lagos, NG", "Sao Paulo, BR", "Beijing, CN"])
        return base

# ---------------------------
# Simulator Loops
# ---------------------------
def run_simulator(mode="demo"):
    if mode == "demo":
        weights, delay = [0.5, 0.3, 0.2], 2
    elif mode == "stress":
        weights, delay = [0.3, 0.3, 0.4], 0.5
    else:
        weights, delay = [0.5, 0.3, 0.2], 2

    while True:
        choice = random.choices(["normal", "suspicious", "fraud"], weights=weights)[0]
        event = generate_event(choice)
        try:
            r = requests.post(API_URL, json=event)
            print(f"Sent {choice} event → {r.status_code}")
        except Exception as e:
            print(f"Error sending event: {e}")
        time.sleep(delay)

def replay_from_log(file_path):
    try:
        with open(file_path, "r") as f:
            for line in f:
                entry = json.loads(line)
                event = entry.get("event", {})
                try:
                    r = requests.post(API_URL, json=event)
                    print(f"Replayed event → {r.status_code}")
                except Exception as e:
                    print(f"Replay error: {e}")
                time.sleep(1.5)  # pacing for replay
    except Exception as e:
        print(f"Could not replay log: {e}")

# ---------------------------
# CLI Entrypoint
# ---------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="BAIDS Simulator")
    parser.add_argument("--mode", choices=["demo", "stress", "replay"], default="demo",
                        help="Mode: demo (balanced), stress (high fraud), replay (from file)")
    parser.add_argument("--file", type=str, help="Path to .jsonl file for replay mode")
    args = parser.parse_args()

    if args.mode == "replay":
        if not args.file:
            print("Replay mode requires --file <path_to_log.jsonl>")
        else:
            replay_from_log(args.file)
    else:
        run_simulator(args.mode)



