import struct


def parse_checksum(data):

    checksum = struct.unpack(
        "!H",
        data[2:4]
    )[0]

    return {
        "offset": 2,
        "length": 2,
        "raw_hex": f"{checksum:04X}",
        "raw_binary": f"{checksum:016b}",
        "value": f"0x{checksum:04x}"
    }