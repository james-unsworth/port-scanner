import socket

def grab_banner(host: str, port: int) -> str:
    try: 
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(3)
            s.connect((host, port))

            try:
                banner = s.recv(1024).decode(errors="replace").strip()
                if banner:
                    return f"{host}:{port}\n{banner}\n"
                return f"{host}:{port} returned nothing\n"

            except socket.timeout:
                s.sendall(f"GET / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode())
                data = s.recv(1024).decode(errors="replace").strip()
                data_lines = data.split("\r\n")
                status = data_lines[0]
                server = ""

                for line in data_lines:
                    if line.lower().startswith("server:"):
                        server = line
                
                status_str = f"{host}:{port}\n{status}\n"
                if server:
                    return status_str + server + "\n"
                return status_str + "\n"

    except socket.error as err:
        return f"{host}:{port} Socket creation failed with error %s\n" %(err)
