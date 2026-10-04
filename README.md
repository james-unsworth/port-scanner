# Port Scanner

A network scanner built from scratch to learn networking internals. IP, TCP, and ICMP headers are hand-assembled with
`struct`, checksums are computed manually, and replies are captured directly via libpcap.

## Features

- **TCP connect scan** - standard three-way handshake via a regular socket.
- **SYN scan** - half-open scan using a raw socket with a hand-built IP + TCP header.
  Distinguishes open, closed, and filtered by parsing the captured reply.
- **ICMP ping sweep** - host discovery across a CIDR range using hand-built ICMP echo
  requests.
- **Banner grab** - connects to an open port and reads the service banner. If the
  server stays silent, sends a minimal HTTP request and returns the status line and
  `Server` header
  - Replies are captured with libpcap rather than the sending socket, since macOS's
  kernel consumes inbound TCP/ICMP traffic on raw sockets.
- Concurrent scanning via a thread pool.

## Requirements

- macOS (current offsets and interface handling are macOS-specific)
- Python 3.10
- `libpcap` (Python ctypes binding) - installed automatically below
- Root privileges for `syn` and `sweep` (raw sockets require `sudo`); `tcp` and `banner`
  use ordinary sockets

## Installation

```bash
git clone https://github.com/james-unsworth/port-scanner.git
cd port-scanner
python3.13 -m venv .venv
source .venv/bin/activate
pip install -e .
```

This installs the `portscan` command into the virtual environment.

## Usage

```bash
# TCP connect scan
portscan tcp <host> 1-1024

# SYN scan (needs root)
sudo $(which portscan) syn <host> 22,80,443

# ICMP ping sweep across a subnet (needs root)
sudo $(which portscan) sweep 192.168.1.0/24

# Banner grab
portscan banner <host> 22
```

Ports can be a single port, a comma-separated list, or a range (e.g. `20-100`).
Run `portscan --help`, or `portscan <command> --help`, for details.

`sudo portscan ...` fails with "command not found" because `sudo` does not use the
virtual environment's `PATH`; `sudo $(which portscan) ...` passes the full path instead.
`python main.py <command> ...` also works from the project folder.

## Notes

- Built as a learning project - intentionally implemented at the packet level
  instead of using an existing library.
- IP addresses only - no hostname resolution yet.
- Network interface is currently hardcoded to `en0`.
- Banner grabbing supports services that speak first (e.g. SSH) and plain HTTP. TLS
  ports are not yet supported, since the probe is sent unencrypted.

## License

MIT
