import json
import os
import time


def channel_heatmap(filename: str) -> None:
    stats = {37: 0, 38: 0, 39: 0}
    total = 0

    with open(filename, "r") as f:
        f.seek(0, 2)  # jump to end of file

        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue

            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue

            ch = data.get("channel")
            if ch in stats:
                stats[ch] += 1
                total += 1

            # Refresh every 10 packets
            if total > 0 and total % 10 == 0:
                os.system("cls" if os.name == "nt" else "clear")
                print("--- BLE Advertising Channel Heatmap ---")

                for channel in [37, 38, 39]:
                    count = stats[channel]
                    percent = count / total * 100
                    bar = "█" * int(percent / 2)
                    print(f"CH {channel}: {percent:5.1f}% {bar}")

                print(f"\nTotal Packets: {total}")


if __name__ == "__main__":
    channel_heatmap("packets.json")
