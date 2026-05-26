from flask import Flask, send_from_directory
from flask_socketio import SocketIO
from sniffer.backend.capture.linux_capture import capture_packet
from sniffer.backend.protocols.ethernet import parse_ethernet
from sniffer.backend.protocols.ipv4 import parse_ipv4
import os
import time
import traceback

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FRONTEND_DIR = os.path.join(BASE_DIR, "frontend")

app = Flask(__name__, static_folder=FRONTEND_DIR)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")


# =========================
# ROUTES
# =========================
@app.route("/")
def index():
    return send_from_directory(FRONTEND_DIR, "index.html")


@app.route("/<path:path>")
def static_files(path):
    return send_from_directory(FRONTEND_DIR, path)


# =========================
# SAFE PARSER WRAPPER
# =========================
def safe_parse_ipv4(payload):
    try:
        return parse_ipv4(payload)
    except Exception as e:
        print("IPv4 PARSE ERROR:", e)
        return {
            "error": str(e)
        }


# =========================
# ETHERTYPE SAFE PARSE
# =========================
def normalize_ethertype(value):
    try:
        if isinstance(value, str):
            return int(value, 16)
        if isinstance(value, bytes):
            return int.from_bytes(value, "big")
        if value is None:
            return 0
        return int(value)
    except:
        return 0


# =========================
# STREAM LOOP (ROCK SOLID)
# =========================
def packet_stream():
    print("🔥 PACKET STREAM STARTED")

    while True:
        try:
            raw = capture_packet()
            if not raw:
                continue

            eth = parse_ethernet(raw)

            ethertype = normalize_ethertype(
                eth.get("ethertype", {}).get("value")
            )

            packet = {
                "ethernet": {k: v for k, v in eth.items() if k != "payload"},
                "payload_hex": eth["payload"].hex(),
                "type": "UNKNOWN",
                "ipv4": None
            }

            # =========================
            # CLASSIFICATION
            # =========================
            if ethertype == 0x0800:
                packet["type"] = "IPv4"
                packet["ipv4"] = safe_parse_ipv4(eth["payload"])

            elif ethertype == 0x0806:
                packet["type"] = "ARP"

            elif ethertype == 0x86DD:
                packet["type"] = "IPv6"

            else:
                packet["type"] = f"UNKNOWN(0x{ethertype:04X})"

            socketio.emit("packet", packet)

            time.sleep(0.2)

        except Exception as e:
            print("STREAM ERROR:")
            traceback.print_exc()


# =========================
# MAIN
# =========================
if __name__ == "__main__":
    print("🔥 APP STARTING")

    socketio.start_background_task(packet_stream)

    socketio.run(
        app,
        host="0.0.0.0",
        port=5000,
        debug=True,
        use_reloader=False
    )