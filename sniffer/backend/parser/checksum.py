def parse_checksum(data):

    raw = data[10:12]

    value = (
        (raw[0] << 8)
        |
        raw[1]
    )

    return {

        "offset": 10,

        "length": 2,

        "raw_hex":
            raw.hex().upper(),

        "raw_binary":
            ''.join(
                format(b, '08b')
                for b in raw
            ),

        "value":
            hex(value),

        "meaning":
            "IPv4 Header Checksum"
    }