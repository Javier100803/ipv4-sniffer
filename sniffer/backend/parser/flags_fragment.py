def parse_flags_fragment(data):

    value = int.from_bytes(
        data[6:8],
        "big"
    )

    flags = (value >> 13) & 0x7

    fragment_offset = value & 0x1FFF

    return {

        "offset": 6,
        "length": 2,

        "raw_hex":
            data[6:8].hex().upper(),

        "raw_binary":
            format(value, "016b"),

        "breakdown": {

            "flags": {

                "bits":
                    format(flags, "03b"),

                "df": {

                    "value":
                        (flags >> 1) & 1,

                    "meaning":
                        "Don't Fragment"
                        if ((flags >> 1) & 1)
                        else "May Fragment"
                },

                "mf": {

                    "value":
                        flags & 1,

                    "meaning":
                        "More Fragments"
                        if (flags & 1)
                        else "Last Fragment"
                }
            },

            "fragment_offset": {

                "bits":
                    format(
                        fragment_offset,
                        "013b"
                    ),

                "value":
                    fragment_offset
            }
        }
    }
