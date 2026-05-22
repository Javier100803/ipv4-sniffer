from parser.version_ihl import parse_version_ihl
from parser.dscp_ecn import parse_dscp_ecn
from parser.flags_fragment import parse_flags_fragment

from parser.total_length import parse_total_length
from parser.identification import parse_identification
from parser.ttl import parse_ttl
from parser.protocol import parse_protocol
from parser.checksum import parse_checksum
from parser.source_ip import parse_source_ip
from parser.destination_ip import parse_destination_ip

from parser.tcp.tcp_parser import parse_tcp


def parse_ipv4(data):

    ihl = data[0] & 0x0F

    protocol = data[9]

    transport = None

    if protocol == 6:

        tcp_start = ihl * 4

        transport = {

            "tcp":
                parse_tcp(
                    data[tcp_start:]
                )
        }

    return {

        "header": {

            "version_ihl":
                parse_version_ihl(data),

            "dscp_ecn":
                parse_dscp_ecn(data),

            "total_length":
                parse_total_length(data),

            "identification":
                parse_identification(data),

            "flags_fragment":
                parse_flags_fragment(data),

            "ttl":
                parse_ttl(data),

            "protocol":
                parse_protocol(data),

            "checksum":
                parse_checksum(data),

            "source_ip":
                parse_source_ip(data),

            "destination_ip":
                parse_destination_ip(data)
        },

        "transport":
            transport,

        "raw_bytes": [

            format(b, '02X')
            for b in data[:ihl * 4]
        ]
    }