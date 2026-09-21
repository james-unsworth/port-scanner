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

def start_scan(host: str, port_string: str, scan_type: str):
    def get_handle():
        local.handle = scan.create_handle()

    def start_syn_scan(host, port, src_ip):
        return scan.syn(host, port, local.handle, src_ip)

    def start_icmp_scan(host, src_ip):
        return scan.icmp(host, local.handle, src_ip)

    src_ip = scan.get_src_ip()

    if scan_type == "icmp":
        host_range = []
        for ip in ipaddress.IPv4Network(host).hosts():
            if format(ip) != src_ip:
                host_range.append(format(ip))

        local = threading.local()
        # Keep max_workers=3 to avoid congestion errors.   
        with concurrent.futures.ThreadPoolExecutor(max_workers=3, initializer=get_handle) as executor:
            futures = []
            for host in host_range:
                futures.append(executor.submit(start_icmp_scan, host=host, src_ip=src_ip))
            for future in concurrent.futures.as_completed(futures):
                print(future.result())
   
    else:
        ports = []
        if is_range_scan(port_string):
            port_range = port_string.split('-')
            for i in range(int(port_range[0]), int(port_range[1]) + 1):
                ports.append(i)
        elif port_string: 
            string_list = port_string.split(',')
            for item in string_list:
                ports.append(int(item))

        if scan_type == "tcp":
            with concurrent.futures.ThreadPoolExecutor() as executor:
                futures = []
                for port in ports:
                    futures.append(executor.submit(scan.tcp, host=host, port=port))
                for future in concurrent.futures.as_completed(futures):
                    print(future.result())

        elif scan_type == "syn":
            local = threading.local()
            with concurrent.futures.ThreadPoolExecutor(initializer=get_handle) as executor:
                futures = []
                for port in ports:
                    futures.append(executor.submit(start_syn_scan, host=host, port=port, src_ip=src_ip))
                for future in concurrent.futures.as_completed(futures):
                    print(future.result())  

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", help="--target <target host>")
    parser.add_argument("-p","--port", help="--port <list (1, 2, 3) or range [1-10] of ports>")
    parser.add_argument("-s", "--scan", help="--scan <scan method> [tcp, syn, icmp]")
    args = parser.parse_args()

    host = args.target 
    port_string = args.port 
    scan_type = args.scan

    start_scan(host, port_string, scan_type)


if __name__ == "__main__":
    main()
