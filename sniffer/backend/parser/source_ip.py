def parse_source_ip(data):

    raw = data[12:16]

    ip = '.'.join(
        str(b)
        for b in raw
    )

    return {

        "offset": 12,

        "length": 4,

        "raw_hex":
            raw.hex().upper(),

        "raw_binary":
            ''.join(
                format(b, '08b')
                for b in raw
            ),

        "value": ip,

        "meaning":
            "Source IPv4 Address"
    }