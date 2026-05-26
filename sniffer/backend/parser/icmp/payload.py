def parse_payload(data):

    payload = data[8:]

    return {

        "offset": 8,

        "length": len(payload),

        "raw_hex":
            payload.hex().upper(),

        "raw_bytes": [

            f"{byte:02X}"

            for byte in payload
        ]
    }