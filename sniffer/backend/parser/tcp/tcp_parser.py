from sniffer.backend.parser.tcp.source_port import parse_source_port
from sniffer.backend.parser.tcp.destination_port import parse_destination_port
from sniffer.backend.parser.tcp.flags import parse_tcp_flags
def parse_tcp(data):

    return {

        "header": {

            "source_port":
                parse_source_port(data),

            "destination_port":
                parse_destination_port(data),

            "flags":
                parse_tcp_flags(data)
        },

        "raw_bytes": [

            format(b, '02X')
            for b in data[:20]
        ]
    }