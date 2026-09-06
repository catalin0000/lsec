import socket
import ssl

def is_ssl(host: str, port: int, timeout: float = 2.0) -> bool:
    # Disable certificate verification so self-signed certs pass the handshake
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        # Step 1: Establish raw TCP connection
        raw_sock = socket.create_connection((host, port), timeout=timeout)
        
        # Step 2: Attempt TLS handshake
        with context.wrap_socket(raw_sock, server_hostname=host) as ssl_sock:
            # If wrap_socket completes without an exception, it's SSL/TLS
            return True

    except (ssl.SSLError, socket.error, TimeoutError):
        # Failed SSL handshake, connection refused, or timed out
        return False



# 
# targets = [
#     ("192.168.0.105", "389"),  # SSL -> True
#     ("192.168.0.105", 636),   # Cleartext -> False
# ]
# 
# for host, port in targets:
#     result = is_ssl(host, port)
#     print(f"{host}:{port} -> SSL: {result}")
# 
# 


