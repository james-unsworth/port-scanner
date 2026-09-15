import struct
import socket
import sys
import libpcap as pcap
import ctypes as ct
import time
import header
import scan

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


def build_syn_packet(host: str, port: int, src_ip) -> int:
    ip_header = header.ip(host, src_ip, 6, 40)
    tcp_header = header.tcp(host, port, src_ip)

    packet = ip_header + tcp_header
    return packet

def syn_scan(host: str, port: int, src_ip: str) -> str:
    handle = scan.create_handle()
    packet = build_syn_packet(host, port, src_ip)

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW) as s:
            s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            s.settimeout(3000)
            s.sendto(packet, (host, 0)) # Port always ignored

    except socket.error as err:
        return f"Socket creation failed with error %s" %(err)

    bpf = pcap.bpf_program()
    cmdbuf = f"tcp src port {port}".encode("utf-8")
    if pcap.compile(handle, ct.byref(bpf), cmdbuf, 1, 0) < 0:
        return f"{port}Packet capture error."

    pcap.setfilter(handle, ct.byref(bpf))
    hdr_ptr = ct.POINTER(pcap.pkthdr)()
    data_ptr = ct.POINTER(ct.c_ubyte)()
    
    response = 0
    timeout = time.time() + 3
    while response == 0:
        if time.time() > timeout:
            return f"{port}: Connection timed out. Port filtered."
        response = pcap.next_ex(handle, ct.byref(hdr_ptr), ct.byref(data_ptr))

    match response:
        case 1:
            data = ct.string_at(data_ptr, hdr_ptr.contents.caplen)
            FLAGS_OFFSET = 47 # Ethernet - 47, Loopback - 37
            flags_byte = data[FLAGS_OFFSET]

            if flags_byte & 0x02:
                return f"{port}: Connection established. Port open"
            elif flags_byte & 0x04:
                return f"{port}: Connection refused. Port closed"
            else:
                return f"{port}: Unexpected response: %#04x" %(flags_byte)
        case -1:
            return f"{port}: Packet capture error."
