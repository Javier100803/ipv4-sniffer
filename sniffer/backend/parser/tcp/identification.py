def parse_identification(data):

    raw = data[4:6]

    value = (
        (raw[0] << 8)
        |
        raw[1]
    )

    return {

        "offset": 4,

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
            f"Fragment ID {value}"
    }