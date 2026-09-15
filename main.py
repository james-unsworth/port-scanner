import scan
import argparse
import concurrent.futures
import ipaddress
import socket
import threading

def scan_port(host: str, scan_type: str, socket=socket.socket, port=80):
    src_ip = scan.get_dev_ip()
    if scan_type == "tcp":
        return scan.tcp(host, port)
    elif scan_type == "syn":
        return scan.syn(host, port, src_ip)
    elif scan_type == "icmp":
        return scan.icmp(host, src_ip, local.handle, socket)

def get_thread_handle():
    local.handle = scan.create_handle()

parser = argparse.ArgumentParser()
parser.add_argument("-t", "--target", help="--target <target host>")
parser.add_argument("-p","--port", help="--port <list or range of ports>")
parser.add_argument("-s", "--scan", help="--scan <scan method> [tcp, syn, icmp]")
args = parser.parse_args()

host = args.target 
port_string = args.port 
scan_type = args.scan

range_scan = False
if port_string:
    for char in port_string:
        if char == '-':
            range_scan = True

ports = []
if range_scan:
    port_range = port_string.split('-')
    for i in range(int(port_range[0]), int(port_range[1]) + 1):
        ports.append(i)
elif port_string: 
    string_list = port_string.split(',')
    for item in string_list:
        ports.append(int(item))

if scan_type == "icmp":
    dev_ip = scan.get_dev_ip() 
    host_range = []
    for ip in ipaddress.IPv4Network(host).hosts():
        if format(ip) != dev_ip:
            host_range.append(format(ip))

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW) as s:
            s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            s.settimeout(3)
            
            local = threading.local()
            with concurrent.futures.ThreadPoolExecutor(max_workers=3, initializer=get_thread_handle) as executor:
                futures = []
                for host in host_range:
                    futures.append(executor.submit(scan_port, host=host, scan_type=scan_type, socket=s))
                for future in concurrent.futures.as_completed(futures):
                    print(future.result())

    except socket.error as err:
        print(f"Socket creation failed with error %s" %(err))


else:
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = []
        for port in ports:
            futures.append(executor.submit(scan_port, host=host, scan_type=scan_type, port=port))
        for future in concurrent.futures.as_completed(futures):
            print(future.result())

