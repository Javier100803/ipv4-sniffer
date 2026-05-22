def parse_destination_port(data):

    raw = data[2:4]

    value = (
        (raw[0] << 8)
        |
        raw[1]
    )

    return {

        "offset": 2,

        "length": 2,

        "raw_hex":
            raw.hex().upper(),

        "raw_binary":
            ''.join(
                format(b, '08b')
                for b in raw
            ),

        "value": value,

        "meaning":
            f"TCP Destination Port {value}"
    }