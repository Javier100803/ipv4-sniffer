def parse_tcp_flags(data):

    raw = data[13:14]

    byte = raw[0]

    binary = format(byte, '08b')

    flags = {

        "cwr": {

            "bit":
                binary[0],

            "value":
                (byte >> 7) & 1,

            "meaning":
                "Congestion Window Reduced"
        },

        "ece": {

            "bit":
                binary[1],

            "value":
                (byte >> 6) & 1,

            "meaning":
                "ECN Echo"
        },

        "urg": {

            "bit":
                binary[2],

            "value":
                (byte >> 5) & 1,

            "meaning":
                "Urgent"
        },

        "ack": {

            "bit":
                binary[3],

            "value":
                (byte >> 4) & 1,

            "meaning":
                "Acknowledgment"
        },

        "psh": {

            "bit":
                binary[4],

            "value":
                (byte >> 3) & 1,

            "meaning":
                "Push"
        },

        "rst": {

            "bit":
                binary[5],

            "value":
                (byte >> 2) & 1,

            "meaning":
                "Reset"
        },

        "syn": {

            "bit":
                binary[6],

            "value":
                (byte >> 1) & 1,

            "meaning":
                "Synchronize"
        },

        "fin": {

            "bit":
                binary[7],

            "value":
                byte & 1,

            "meaning":
                "Finish"
        }
    }

    active = [

        name.upper()

        for name, info
        in flags.items()

        if info["value"] == 1
    ]

    return {

        "offset": 13,

        "length": 1,

        "raw_hex":
            raw.hex().upper(),

        "raw_binary":
            binary,

        "value":
            active,

        "meaning":
            "TCP Flags",

        "breakdown":
            flags
    }