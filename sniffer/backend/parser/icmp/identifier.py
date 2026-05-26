import struct

def parse_identifier(data):

    value = struct.unpack(
        "!H",
        data[4:6]
    )[0]

    return {
        "offset": 4,
        "length": 2,
        "raw_hex": f"{value:04X}",
        "raw_binary": f"{value:016b}",
        "value": value
    }