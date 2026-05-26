from sniffer.backend.parser.version_ihl import parse_version_ihl
from sniffer.backend.parser.dscp_ecn import parse_dscp_ecn
from sniffer.backend.parser.total_length import parse_total_length
from sniffer.backend.parser.identification import parse_identification
from sniffer.backend.parser.flags_fragment import parse_flags_fragment
from sniffer.backend.parser.ttl import parse_ttl
from sniffer.backend.parser.protocol import parse_protocol
from sniffer.backend.parser.checksum import parse_checksum
from sniffer.backend.parser.source_ip import parse_source_ip
from sniffer.backend.parser.destination_ip import parse_destination_ip

from sniffer.backend.parser.tcp.tcp_parser import parse_tcp
from sniffer.backend.parser.udp.udp_parser import parse_udp
from sniffer.backend.parser.icmp.icmp_parser import parse_icmp
def parse_ipv4(data):

    protocol = data[9]
    ihl = data[0] & 0x0F
    l4_start = ihl * 4

    # =========================
    # TRANSPORT LAYER
    # =========================
    transport = None

    if protocol == 6:  # TCP
        transport = {"tcp": parse_tcp(data[l4_start:])}

    elif protocol == 17:  # UDP
        transport = {"udp": parse_udp(data[l4_start:])}

    elif protocol == 1:  # ICMP
        transport = {"icmp": parse_icmp(data[l4_start:])}

    # =========================
    # RETURN SIEMPRE (CRÍTICO)
    # =========================
    return {
        "header": {
            "version_ihl": parse_version_ihl(data),
            "dscp_ecn": parse_dscp_ecn(data),
            "total_length": parse_total_length(data),
            "identification": parse_identification(data),
            "flags_fragment": parse_flags_fragment(data),
            "ttl": parse_ttl(data),
            "protocol": parse_protocol(data),
            "checksum": parse_checksum(data),
            "source_ip": parse_source_ip(data),
            "destination_ip": parse_destination_ip(data)
        },
        "transport": transport,
        "raw_bytes": [format(b, '02X') for b in data[:ihl * 4]]
    }