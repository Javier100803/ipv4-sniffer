def parse_flags_fragment(raw):

    value = int.from_bytes(
        raw,
        'big'
    )

    binary = format(value, '016b')

    flags_bits = binary[:3]

    fragment_offset_bits = binary[3:]

    reserved_bit = flags_bits[0]
    df_bit = flags_bits[1]
    mf_bit = flags_bits[2]

    fragment_offset_value = int(
        fragment_offset_bits,
        2
    )

    return {

        "raw_hex":

            raw.hex().upper(),

        "raw_binary":

            binary,

        "breakdown": {

            "flags": {

                "bits":
                    flags_bits,

                "reserved": {

                    "bit":
                        reserved_bit,

                    "meaning":
                        "Reserved"
                },

                "df": {

                    "bit":
                        df_bit,

                    "value":
                        int(df_bit),

                    "meaning":

                        "Do Not Fragment"

                        if df_bit == '1'

                        else

                        "Fragmentation Allowed"
                },

                "mf": {

                    "bit":
                        mf_bit,

                    "value":
                        int(mf_bit),

                    "meaning":

                        "More Fragments"

                        if mf_bit == '1'

                        else

                        "Last Fragment"
                }
            },

            "fragment_offset": {

                "bits":
                    fragment_offset_bits,

                "value":
                    fragment_offset_value
            }
        }
    }