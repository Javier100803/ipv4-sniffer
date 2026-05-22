from tables.protocols import PROTOCOLS


def parse_total_length(raw):

    value = int.from_bytes(
        raw,
        'big'
    )

    return {

        "raw_hex":
            raw.hex().upper(),

        "raw_binary":

            ' '.join(
                format(byte, '08b')
                for byte in raw
            ),

        "value":
            value,

        "meaning":
            f"{value} bytes"
    }


def parse_identification(raw):

    value = int.from_bytes(
        raw,
        'big'
    )

    return {

        "raw_hex":
            raw.hex().upper(),

        "raw_binary":

            ' '.join(
                format(byte, '08b')
                for byte in raw
            ),

        "value":
            value
    }


def parse_ttl(byte):

    return {

        "raw_hex":
            f"{byte:02X}",

        "raw_binary":
            format(byte, '08b'),

        "value":
            byte
    }


def parse_protocol(byte):

    return {

        "raw_hex":
            f"{byte:02X}",

        "raw_binary":
            format(byte, '08b'),

        "value":
            byte,

        "meaning":
            PROTOCOLS.get(
                byte,
                "UNKNOWN"
            )
    }


def parse_checksum(raw):

    value = int.from_bytes(
        raw,
        'big'
    )

    return {

        "raw_hex":
            raw.hex().upper(),

        "raw_binary":

            ' '.join(
                format(byte, '08b')
                for byte in raw
            ),

        "value":
            value
    }


def parse_ip(raw):

    ip = '.'.join(
        str(byte)
        for byte in raw
    )

    return {

        "raw_hex":
            raw.hex().upper(),

        "raw_binary":

            ' '.join(
                format(byte, '08b')
                for byte in raw
            ),

        "value":
            ip
    }