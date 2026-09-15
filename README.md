# Port Scanner

A network scanner built from scratch to learn networking internals.  IP, TCP, and ICMP headers are hand-assembled with
`struct`, checksums are computed manually, and replies are captured directly via
libpcap.

## Features

- **TCP connect scan** - standard three-way handshake via a regular socket.
- **SYN scan** - half-open scan using a raw socket with a hand-built IP + TCP header.
  Distinguishes open, closed, and filtered by parsing the captured reply
- **ICMP ping sweep** - host discovery across a CIDR range using hand-built ICMP echo
  requests.
- Replies are captured with libpcap rather than the sending socket, since macOS's
  kernel consumes inbound TCP/ICMP traffic on raw sockets.
- Concurrent scanning via a thread pool.

## Requirements

- macOS (current offsets and interface handling are macOS-specific)
- Python 3.13
- `libpcap` (Python ctypes binding)
- Root privileges (raw sockets require `sudo`)

## Installation

```bash
git clone https://github.com/james-unsworth/port-scanner.git
cd port-scanner
python3.13 -m venv .venv
source .venv/bin/activate
pip install libpcap
```

## Usage

```bash
# TCP connect scan
sudo python3 main.py -t <host> -p 80 -s tcp

# SYN scan
sudo python3 main.py -t <host> -p 80 -s syn

# ICMP ping sweep across a subnet
sudo python3 main.py -t 192.168.1.0/24 -s icmp
```

`-p` accepts a single port, a comma-separated list, or a range (e.g. `20-100`).

## Notes

- Built as a learning project - intentionally implemented at the packet level
  instead of using an existing library.
- IP addresses only - no hostname resolution yet.
- Network interface is currently hardcoded to `en0`.

## License

MIT
