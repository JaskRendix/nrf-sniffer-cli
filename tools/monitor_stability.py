import time


def monitor_stability(filename):
    with open(filename, "r") as f:
        f.seek(0, 2)
        packet_count = 0
        start = time.time()

        while True:
            line = f.readline()
            if not line:
                now = time.time()
                if now - start >= 5:
                    pps = packet_count / (now - start)
                    status = "GOOD" if pps > 5 else "WEAK"
                    print(f"Throughput: {pps:.1f} packets/sec | {status}")
                    packet_count = 0
                    start = now
                time.sleep(0.1)
                continue

            packet_count += 1


monitor_stability("packets.json")
