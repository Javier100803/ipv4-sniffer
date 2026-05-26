import struct

def parse_sequence(data):

    value = struct.unpack(
        "!H",
        data[6:8]
    )[0]

    return {
        "offset": 6,
        "length": 2,
        "raw_hex": f"{value:04X}",
        "raw_binary": f"{value:016b}",
        "value": value
    }