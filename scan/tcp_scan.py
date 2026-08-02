import socket

def tcp_scan(port: int, host: str):
    try: 
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(3)
            s.connect((host, port))
        return "Connection established. Port open"

    except socket.timeout: 
        return "Connection timed out. Port filtered."

    except ConnectionRefusedError:
        return "Connection refused. Port closed"

    except socket.error as err:
        return "Socket creation failed with error %s" %(err)

