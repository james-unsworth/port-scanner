import socket
import header
import scan
import libpcap as pcap
import ctypes as ct
import time

def icmp_scan(host: str, src_ip: str, handle: object, s: socket.socket):
    ip_header = header.ip(host, src_ip, 1, 28)
    icmp_header = header.icmp()
    packet = ip_header + icmp_header
    
    try:
        s.sendto(packet, (host, 0)) # Port always ignored
    except socket.error as err:
        return f"Packet sending failed with error %s" %(err)
 
    bpf = pcap.bpf_program()
    cmdbuf = f"icmp[icmptype] == icmp-echoreply and ip src host {host}".encode("utf-8")
    if pcap.compile(handle, ct.byref(bpf), cmdbuf, 1, 0) < 0:
        return f"{host}: Packet capture error."

    pcap.setfilter(handle, ct.byref(bpf))
    hdr_ptr = ct.POINTER(pcap.pkthdr)()
    data_ptr = ct.POINTER(ct.c_ubyte)()

    response = 0
    timeout = time.time() + 1
    while response == 0:
        if time.time() > timeout:
            return f"{host}: DOWN"
        response = pcap.next_ex(handle, ct.byref(hdr_ptr), ct.byref(data_ptr))

    if response == 1:
        return f"{host}: UP"
    else:
        return f"{host}: Packet capture error."

