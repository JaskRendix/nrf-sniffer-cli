import json
import time

TARGET_NAME = "MySensor"


def watch_target(filename):
    with open(filename, "r") as f:
        f.seek(0, 2)
        print(f"--- Monitoring for {TARGET_NAME} ---")
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.1)
                continue

            data = json.loads(line)
            ble = data.get("ble", {})

            if ble.get("name") == TARGET_NAME:
                print(
                    f"[{data.get('timestamp')}] Target Seen! RSSI: {data.get('rssi')} dBm"
                )


watch_target("packets.json")
