import socket


def capture_packet():

    conn = socket.socket(

        socket.AF_PACKET,
        socket.SOCK_RAW,
        socket.ntohs(3)
    )

    raw_data, addr = conn.recvfrom(65535)

    return raw_data