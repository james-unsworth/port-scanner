import socket

def grab_banner(host: str, port: int) -> str:
    try: 
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(3)
            s.connect((host, port))
            return s.recv(1024).decode().strip()

    except socket.error as err:
        return f"{port}: Socket creation failed with error %s" %(err)



    
