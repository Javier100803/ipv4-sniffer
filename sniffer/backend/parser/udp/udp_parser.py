import struct

def parse_udp(data):

    source_port, dest_port, length, checksum = struct.unpack(
        "!HHHH",
        data[:8]
    )

    return {

        "type": "UDP",

        "header": {

            "source_port": {
                "value": source_port,
                "offset": 0,
                "length": 2,
                "raw_hex": f"{source_port:04X}"
            },

            "destination_port": {
                "value": dest_port,
                "offset": 2,
                "length": 2,
                "raw_hex": f"{dest_port:04X}"
            },

            "length": {
                "value": length,
                "offset": 4,
                "length": 2,
                "raw_hex": f"{length:04X}"
            },

            "checksum": {
                "value": checksum,
                "offset": 6,
                "length": 2,
                "raw_hex": f"{checksum:04X}"
            }
        },

        "payload": data[8:].hex(),

        "raw_bytes": [
            f"{b:02X}" for b in data[:8]
        ]
    }