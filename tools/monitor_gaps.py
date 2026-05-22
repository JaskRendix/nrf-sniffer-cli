import json
import time


def monitor_gaps(filename, threshold=1.5):
    last_ts = None
    with open(filename, "r") as f:
        f.seek(0, 2)
        print(f"--- Monitoring for Gaps > {threshold}s ---")

        while True:
            line = f.readline()
            if not line:
                time.sleep(0.1)
                continue

            data = json.loads(line)
            ts = data.get("timestamp") or time.time()

            if last_ts is not None:
                gap = ts - last_ts
                if gap > threshold:
                    print(f"DROPOUT: {gap:.2f}s at {time.ctime(ts)}")
                else:
                    print(".", end="", flush=True)

            last_ts = ts


monitor_gaps("packets.json")
