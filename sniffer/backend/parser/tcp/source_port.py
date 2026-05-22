def parse_source_port(data):

    raw = data[0:2]

    value = (
        (raw[0] << 8)
        |
        raw[1]
    )

    return {

        "offset": 0,

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
            f"TCP Source Port {value}"
    }