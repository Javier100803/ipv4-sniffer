def parse_version_ihl(byte):

    binary = format(byte, '08b')

    version_bits = binary[:4]
    ihl_bits = binary[4:]

    version_value = int(version_bits, 2)
    ihl_value = int(ihl_bits, 2)

    return {

        "raw_hex":
            f"{byte:02X}",

        "raw_binary":
            binary,

        "breakdown": {

            "version": {

                "bits":
                    version_bits,

                "value":
                    version_value,

                "meaning":
                    f"IPv{version_value}"
            },

            "ihl": {

                "bits":
                    ihl_bits,

                "value":
                    ihl_value,

                "meaning":
                    f"{ihl_value * 4} bytes"
            }
        }
    }