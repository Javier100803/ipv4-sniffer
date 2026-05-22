def parse_destination_ip(data):

    raw = data[16:20]

    ip = '.'.join(
        str(b)
        for b in raw
    )

    return {

        "offset": 16,

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
            "Destination IPv4 Address"
    }