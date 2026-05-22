PROTOCOLS = {

    1: "ICMP",
    6: "TCP",
    17: "UDP"
}


def parse_protocol(data):

    raw = data[9:10]

    value = raw[0]

    meaning = PROTOCOLS.get(
        value,
        f"UNKNOWN ({value})"
    )

    return {

        "offset": 9,

        "length": 1,

        "raw_hex":
            raw.hex().upper(),

        "raw_binary":
            format(raw[0], '08b'),

        "value": value,

        "meaning": meaning
    }