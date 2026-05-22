def parse_ttl(data):

    raw = data[8:9]

    value = raw[0]

    return {

        "offset": 8,

        "length": 1,

        "raw_hex":
            raw.hex().upper(),

        "raw_binary":
            format(raw[0], '08b'),

        "value": value,

        "meaning":
            f"{value} hops remaining"
    }