import json
import time


def tail_sniffer_json(filename):
    with open(filename, "r") as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.1)
                continue

            data = json.loads(line)
            rssi = data.get("rssi", -100)

            bar_len = max(0, min(20, (rssi + 100) // 4))
            bar = "█" * bar_len + "-" * (20 - bar_len)

            print(f"Signal: {rssi:4} dBm |{bar}|")


tail_sniffer_json("packets.json")
