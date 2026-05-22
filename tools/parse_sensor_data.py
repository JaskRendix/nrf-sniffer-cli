import json
import time


def parse_sensor_data(filename: str) -> None:
    print("--- Monitoring for Broadcast Sensor Data ---")

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

            ble = data.get("ble", {})
            if ble.get("type") != 0:  # Advertising PDU
                continue

            payload = ble.get("payload", "")
            if not payload:
                continue

            # Example: Govea manufacturer ID (placeholder)
            if "0188ec" in payload.lower():
                # Example offset: bytes 14–16 (28–32 hex chars)
                temp_hex = payload[28:32]

                try:
                    temp_raw = int(temp_hex, 16)
                except ValueError:
                    continue

                # Handle signed 16-bit values
                if temp_raw > 0x8000:
                    temp_raw -= 0x10000

                temp_c = temp_raw / 100.0
                rssi = data.get("rssi")

                print(f" Temp: {temp_c:.2f}°C | RSSI: {rssi} dBm")


if __name__ == "__main__":
    parse_sensor_data("packets.json")
