import json
import time


def monitor_battery(filename: str) -> None:
    last_level = None

    with open(filename, "r") as f:
        f.seek(0, 2)
        print("--- Searching for Battery Level Updates (UUID 0x2A19) ---")

        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue

            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue

            ble_data = data.get("ble", {})

            # Data PDUs (type 1) may contain battery notifications
            if ble_data.get("type") != 1:
                continue

            payload = ble_data.get("payload", "")
            if not payload:
                continue

            # Last byte is often the battery percentage
            level_hex = payload[-2:]

            try:
                level_dec = int(level_hex, 16)
            except ValueError:
                continue

            if 0 <= level_dec <= 100 and level_dec != last_level:
                print(f"\n Battery Update: {level_dec}%")
                last_level = level_dec


if __name__ == "__main__":
    monitor_battery("packets.json")
