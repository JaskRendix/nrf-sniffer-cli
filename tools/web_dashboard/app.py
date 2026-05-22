import json
import threading
import time

from flask import Flask, render_template
from flask_socketio import SocketIO

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")


def tail_to_websocket():
    """Reads packets.json and streams updates to the browser."""
    with open("packets.json", "r") as f:
        f.seek(0, 2)  # jump to end of file

        while True:
            line = f.readline()
            if not line:
                time.sleep(0.1)
                continue

            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue

            socketio.emit(
                "new_packet",
                {
                    "rssi": data.get("rssi"),
                    "name": data.get("ble", {}).get("name", "Unknown"),
                    "ts": data.get("timestamp"),
                },
            )


@app.route("/")
def index():
    return render_template("index.html")


if __name__ == "__main__":
    threading.Thread(target=tail_to_websocket, daemon=True).start()
    socketio.run(app, host="0.0.0.0", port=5000)
