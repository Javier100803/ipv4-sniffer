from flask import Flask, jsonify

from capture.linux_capture import capture_packet

from protocols.ethernet import parse_ethernet
from protocols.ipv4 import parse_ipv4

app = Flask(__name__)


@app.route('/packet')

def packet():

    raw_data = capture_packet()

    ethernet_frame = parse_ethernet(raw_data)

    response = {

        "ethernet": ethernet_frame
    }

    if ethernet_frame["ethertype"]["value"] == 0x0800:

        ipv4_packet = parse_ipv4(
            ethernet_frame["payload"]
        )

        response["ipv4"] = ipv4_packet

    return jsonify(response)


if __name__ == '__main__':

    app.run(
        host='0.0.0.0',
        port=5000,
        debug=True
    )