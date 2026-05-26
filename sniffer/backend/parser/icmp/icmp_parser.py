from sniffer.backend.parser.icmp.icmp_type import parse_icmp_type
from sniffer.backend.parser.icmp.code import parse_code
from sniffer.backend.parser.icmp.checksum import parse_checksum
from sniffer.backend.parser.icmp.identifier import parse_identifier
from sniffer.backend.parser.icmp.sequence import parse_sequence
from sniffer.backend.parser.icmp.payload import parse_payload
def parse_icmp(data):

    return {

        "type": "ICMP",

        "header": {

            "icmp_type":
                parse_icmp_type(data),

            "code":
                parse_code(data),

            "checksum":
                parse_checksum(data),

            "identifier":
                parse_identifier(data),

            "sequence":
                parse_sequence(data)
        },

        "payload":
            parse_payload(data),

        "raw_bytes": [

            f"{byte:02X}"

            for byte in data[:8]
        ]
    }