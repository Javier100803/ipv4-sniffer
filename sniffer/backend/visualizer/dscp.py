from tables.dscp import DSCP_TABLE


def parse_dscp(byte):

    binary = format(byte, '08b')

    dscp_bits = binary[:6]
    ecn_bits = binary[6:]

    dscp_value = int(dscp_bits, 2)
    ecn_value = int(ecn_bits, 2)

    dscp_info = DSCP_TABLE.get(

        dscp_value,

        {
            "class": "UNKNOWN",
            "usage": "UNKNOWN"
        }
    )

    return {

        "raw_hex":
            f"{byte:02X}",

        "raw_binary":
            binary,

        "breakdown": {

            "dscp": {

                "bits":
                    dscp_bits,

                "value":
                    dscp_value,

                "class":
                    dscp_info["class"],

                "usage":
                    dscp_info["usage"]
            },

            "ecn": {

                "bits":
                    ecn_bits,

                "value":
                    ecn_value
            }
        }
    }