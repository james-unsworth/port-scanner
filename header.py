import struct
import socket

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


def ip(host: str, src_ip: str, protocol: int, total_length: int) -> bytes:
    version = 4
    IHL = 5
    ToS = 0
    total_length = socket.htons(total_length) # Required for Mac (little endian), remove for Linux.
    identification = 328
    flags_frag = 0
    TTL = 64
    ip_checksum = 0
    dst_ip = host
    byte0 = (version << 4) | IHL

    ip_header = struct.pack('!BBHHHBBH4s4s', byte0, ToS, total_length, identification, flags_frag, TTL, protocol, ip_checksum,
                            socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
    ip_checksum = checksum(ip_header)
    ip_header = struct.pack('!BBHHHBBH4s4s', byte0, ToS, total_length, identification, flags_frag, TTL, protocol, ip_checksum,
                            socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
    
    return ip_header 

def tcp(host: str, port: int, src_ip: str) -> bytes:
    src_port = 55555
    dst_port = port
    seq_num = 0
    ack_num = 0
    offset = 5
    flags = 2
    window = 1024
    protocol = 6
    tcp_checksum = 0
    dst_ip = host
    urg_point = 0
    offset_byte = offset << 4

    tcp_header = struct.pack('!HHIIBBHHH', src_port, dst_port, seq_num, ack_num, offset_byte, flags, window, tcp_checksum, urg_point)
    pseudo_header = struct.pack('!4s4sBBH', socket.inet_aton(src_ip), socket.inet_aton(dst_ip), 0, protocol, len(tcp_header))
    tcp_checksum = checksum(tcp_header + pseudo_header)
    tcp_header = struct.pack('!HHIIBBHHH', src_port, dst_port, seq_num, ack_num, offset_byte, flags, window, tcp_checksum, urg_point)

    return tcp_header

def icmp() -> bytes:
    message_type = 8
    code = 0 
    icmp_checksum = 0 
    identifier = 0 
    seq_num = 0 

    icmp_header = struct.pack('!BBHHH', message_type, code, icmp_checksum, identifier, seq_num)
    icmp_checksum = checksum(icmp_header)
    icmp_header = struct.pack('!BBHHH', message_type, code, icmp_checksum, identifier, seq_num)

    return icmp_header



