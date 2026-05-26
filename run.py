#!/usr/bin/env python3

from sniffer.backend.app import socketio, app, packet_stream

if __name__ == "__main__":
    socketio.start_background_task(packet_stream)

    socketio.run(
        app,
        host="0.0.0.0",
        port=5000,
        debug=False,
        use_reloader=False
    )