import libpcap as pcap
import ctypes as ct
import socket

def create_handle():
    errbuf = ct.create_string_buffer(pcap.PCAP_ERRBUF_SIZE)
    handle = pcap.create(b'en0', errbuf)
    if not handle:
        print(f"Packet capture error: %s" %(errbuf.value.decode()))
        return None

    pcap.set_snaplen(handle, 65535)
    pcap.set_timeout(handle, 1000)
    pcap.set_immediate_mode(handle, 1)
    
    if pcap.activate(handle) < 0:
        print(f"Handle creation error.")
        return None
    
    return handle

def get_dev_ip() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    dev_ip = (s.getsockname()[0])
    s.close() 
    return dev_ip

