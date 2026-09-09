import scan
import argparse
import concurrent.futures
import re

def scan_port(host: str, port: int, scan_type: str):
    if scan_type == "tcp":
        return scan.tcp(host, port)
    elif scan_type == "syn":
        return scan.syn(host, port)

parser = argparse.ArgumentParser()
parser.add_argument("-t", "--target", help="--target <target host>")
parser.add_argument("-p","--port", help="--port <list or range of ports>")
parser.add_argument("-s", "--scan", help="--scan <scan method> [tcp, syn]")
args = parser.parse_args()

host = args.target 
port_string = args.port 
scan_type = args.scan

range_scan = False
for char in port_string:
    if char == '-':
        range_scan = True

ports = []
if range_scan:
    port_range = port_string.split('-')
    for i in range(int(port_range[0]), int(port_range[1]) + 1):
        ports.append(i)
else: 
    string_list = port_string.split(',')
    for item in string_list:
        ports.append(int(item))

with concurrent.futures.ThreadPoolExecutor() as executor:
    futures = []
    for port in ports:
        futures.append(executor.submit(scan_port, host=host, port=port, scan_type=scan_type))
    for future in concurrent.futures.as_completed(futures):
        print(future.result())

