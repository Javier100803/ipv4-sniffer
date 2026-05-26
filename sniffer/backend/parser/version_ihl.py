def parse_version_ihl(data):

    byte = data[0]

    version = (byte >> 4) & 0x0F
    ihl = byte & 0x0F

    return {

        "offset": 0,
        "length": 1,

        "raw_hex":
            format(byte, "02X"),

        "raw_binary":
            format(byte, "08b"),

        "breakdown": {

            "version": {

                "bits":
                    format(version, "04b"),

                "value":
                    version
            },

            "ihl": {

                "bits":
                    format(ihl, "04b"),

                "value":
                    ihl,

                "meaning":
                    f"{ihl * 4} bytes"
            }
        }
    }
