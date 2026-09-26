import scan
import argparse
import concurrent.futures
import ipaddress
import socket
import threading

def is_range_scan(port_string: str) -> bool:
    if port_string:
        for char in port_string:
            if char == '-':
                return True
    return False

def ports_to_list(port_string: str) -> list:
    ports = []
    if is_range_scan(port_string):
        port_range = port_string.split('-')
        for i in range(int(port_range[0]), int(port_range[1]) + 1):
            ports.append(i)
    elif port_string: 
        string_list = port_string.split(',')
        for item in string_list:
            ports.append(int(item))
    return ports

def hosts_to_list(hosts: str) -> list:
    src_ip = scan.get_src_ip()
    host_range = []
    for ip in ipaddress.IPv4Network(hosts).hosts():
        if format(ip) != src_ip:
            host_range.append(format(ip))
    return host_range


def start_scan(args):
    def get_handle():
        local.handle = scan.create_handle()

    def start_syn_scan(host, port, src_ip):
        return scan.syn(host, port, local.handle, src_ip)

    def start_icmp_scan(host, src_ip):
        return scan.icmp(host, local.handle, src_ip)

    src_ip = scan.get_src_ip()

    if args.func == scan.icmp:
        local = threading.local()
        # Keep max_workers=3 to avoid congestion errors.   
        with concurrent.futures.ThreadPoolExecutor(max_workers=3, initializer=get_handle) as executor:
            futures = []
            for host in args.hosts:
                futures.append(executor.submit(start_icmp_scan, host=host, src_ip=src_ip))
            for future in concurrent.futures.as_completed(futures):
                print(future.result())
   
    elif args.func == scan.tcp:
        with concurrent.futures.ThreadPoolExecutor() as executor:
            futures = []
            for port in args.ports:
                futures.append(executor.submit(args.func, host=args.host, port=port))
            for future in concurrent.futures.as_completed(futures):
                print(future.result())

    elif args.func == scan.syn:
        local = threading.local()
        with concurrent.futures.ThreadPoolExecutor(initializer=get_handle) as executor:
            futures = []
            for port in args.ports:
                futures.append(executor.submit(start_syn_scan, host=args.host, port=port, src_ip=src_ip))
            for future in concurrent.futures.as_completed(futures):
                print(future.result())  

def main():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(required=True)

    parser_tcp = subparsers.add_parser('tcp')
    parser_tcp.add_argument('host', type=str)
    parser_tcp.add_argument('ports', type=ports_to_list)
    parser_tcp.set_defaults(func=scan.tcp)

    parser_syn = subparsers.add_parser('syn')
    parser_syn.add_argument('host', type=str)
    parser_syn.add_argument('ports', type=ports_to_list)
    parser_syn.set_defaults(func=scan.syn)

    parser_sweep = subparsers.add_parser('sweep')
    parser_sweep.add_argument('hosts', type=hosts_to_list)
    parser_sweep.set_defaults(func=scan.icmp)

    args = parser.parse_args()

    start_scan(args)

if __name__ == "__main__":
    main()
