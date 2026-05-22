import time

from SnifferAPI import Sniffer

TARGET_ADDR = "aa1122334455"


def start_watchdog():
    s = Sniffer.Sniffer(portnum="COM3")
    s.start()
    s.scan()

    last_seen = time.time()
    print(f"Monitoring {TARGET_ADDR}...")

    while True:
        time.sleep(1)
        devices = s.getDevices().asList()
        found = any(
            "".join(f"{b:02x}" for b in d.address[:6]) == TARGET_ADDR for d in devices
        )

        if found:
            last_seen = time.time()
        elif time.time() - last_seen > 10:
            print("ALERT: Device offline!")
            last_seen = time.time()


start_watchdog()
