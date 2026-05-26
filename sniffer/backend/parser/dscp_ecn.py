def parse_dscp_ecn(data):

    byte = data[1]

    dscp = (byte >> 2) & 0x3F
    ecn = byte & 0x03

    return {

        "offset": 1,
        "length": 1,

        "raw_hex":
            format(byte, "02X"),

        "raw_binary":
            format(byte, "08b"),

        "breakdown": {

            "dscp": {

                "bits":
                    format(dscp, "06b"),

                "value":
                    dscp,

                "class":
                    f"DSCP {dscp}",

                "usage":
                    "Differentiated Services Code Point"
            },

            "ecn": {

                "bits":
                    format(ecn, "02b"),

                "value":
                    ecn
            }
        }
    }
