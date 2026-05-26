ICMP_TYPES = {
    0: "Echo Reply",
    3: "Destination Unreachable",
    5: "Redirect",
    8: "Echo Request",
    11: "Time Exceeded"
}


def parse_icmp_type(data):

    value = data[0]

    return {
        "offset": 0,
        "length": 1,
        "raw_hex": f"{value:02X}",
        "raw_binary": f"{value:08b}",
        "value": value,
        "meaning": ICMP_TYPES.get(
            value,
            "Unknown"
        )
    }