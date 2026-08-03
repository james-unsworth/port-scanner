import struct
import socket
import sys

def checksum(data: bytes) -> int:
    total = 0
    for byte in range (0, len(data) - 1, 2):
        total += data[byte] << 8 | data[byte + 1]
    if len(data) % 2 != 0:
        remainder = data[len(data) - 1] << 8
        total += remainder

    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)

    total = total ^ 0xFFFF
    return total


def build_syn_packet(host: str, port: int) -> int:
# IP HEADER
    version = 4
    IHL = 5
    ToS = 0
    total_length = socket.htons(40) # Required for Mac (little endian), remoce for Linux.
    identification = 328
    flags_frag = 0
    TTL = 64
    protocol = 6
    ip_checksum = 0
    src_ip =  "127.0.0.1"
    dst_ip = host
    byte0 = (version << 4) | IHL

    ip_header = struct.pack('!BBHHHBBH4s4s', byte0, ToS, total_length, identification, flags_frag, TTL, protocol, ip_checksum,
                            socket.inet_aton(src_ip), socket.inet_aton(dst_ip))

    ip_checksum = checksum(ip_header)
    ip_header = struct.pack('!BBHHHBBH4s4s', byte0, ToS, total_length, identification, flags_frag, TTL, protocol, ip_checksum,
                            socket.inet_aton(src_ip), socket.inet_aton(dst_ip))


# TCP HEADER
    src_port = 55555
    dst_port = port
    seq_num = 0
    ack_num = 0
    offset = 5
    flags = 2
    window = 1024
    tcp_checksum = 0
    urg_point = 0
    offset_byte = offset << 4

    tcp_header = struct.pack('!HHIIBBHHH', src_port, dst_port, seq_num, ack_num, offset_byte, flags, window, tcp_checksum, urg_point)
    pseudo_header = struct.pack('!4s4sBBH', socket.inet_aton(src_ip), socket.inet_aton(dst_ip), 0, protocol, len(tcp_header))

    tcp_checksum = checksum(tcp_header + pseudo_header)
    tcp_header = struct.pack('!HHIIBBHHH', src_port, dst_port, seq_num, ack_num, offset_byte, flags, window, tcp_checksum, urg_point)

    packet = ip_header + tcp_header
    return packet

def syn_scan(host: str, port: int) -> str:
    packet = build_syn_packet(host, port)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW) as s:
            s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            s.settimeout(3)
            s.sendto(packet, (host, 0)) # Port always ignored
            data, addr = s.recvfrom(65535)
    except socket.timeout: 
        return "Connection timed out. Port filtered."

    except socket.error as err:
        return "Socket creation failed with error %s" %(err)

    FLAGS_OFFSET = 33 
    flags_byte = data[FLAGS_OFFSET]

    if flags_byte & 0x02:
        return "Connection established. Port open"

    elif flags_byte & 0x04:
        return "Connection refused. Port closed"

    else:
        return "Unexpected Response: %#04x" %(flags_byte)
