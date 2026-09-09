import socket

def tcp_scan(host: str, port: int):
    try: 
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(3)
            s.connect((host, port))
        return f"{port}: Connection established. Port open"

    except socket.timeout: 
        return f"{port}: Cionnection timed out. Port filtered."

    except ConnectionRefusedError:
        return f"{port}: Connection refused. Port closed"

    except socket.error as err:
        return f"{port}: Socket creation failed with error %s" %(err)

