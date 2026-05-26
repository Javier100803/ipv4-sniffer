def parse_code(data):

    value = data[1]

    return {
        "offset": 1,
        "length": 1,
        "raw_hex": f"{value:02X}",
        "raw_binary": f"{value:08b}",
        "value": value
    }