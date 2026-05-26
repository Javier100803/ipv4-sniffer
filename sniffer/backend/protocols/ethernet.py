import struct
from sniffer.backend.tables.ethertypes import ETHERTYPES

def format_mac(mac_bytes):

    return ':'.join(
        f'{byte:02X}'
        for byte in mac_bytes
    )


def parse_ethernet(data):

    destination, source, ethertype = struct.unpack(

        '!6s6sH',
        data[:14]
    )

    return {

        "destination_mac":
            format_mac(destination),

        "source_mac":
            format_mac(source),

        "ethertype": {

            "value": ethertype,

            "hex":
                f"0x{ethertype:04X}",

            "name":
                ETHERTYPES.get(
                    ethertype,
                    "UNKNOWN"
                )
        },

        "payload": data[14:]
    }