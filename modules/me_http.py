import http.client
import ssl
import socket

def is_web_service(host, port, use_ssl=False, timeout=2):
    """
    Sends an HTTP HEAD request to verify if an open port is serving HTTP/HTTPS.
    """
    try:
        if use_ssl:
            # Create an unverified SSL context to handle self-signed certificates
            context = ssl._create_unverified_context()
            conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=context)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)
        conn.request("HEAD", "/")
        response = conn.getresponse()
        conn.close()
        # Any valid HTTP status code means it's a web server
        return True
    except (http.client.HTTPException, TimeoutError, ConnectionResetError, OSError):
        return False


def is_web_service_socket(host, port, use_ssl=False, timeout=2):
    """
    Sends a raw HTTP request over a socket and checks for 'HTTP/' in the banner.
    """
    http_payload = b"HEAD / HTTP/1.1\r\nHost: " + host.encode() + b"\r\nUser-Agent: Scanner\r\nConnection: close\r\n\r\n"
    
    try:
        raw_sock = socket.create_connection((host, port), timeout=timeout)
        
        if use_ssl:
            context = ssl._create_unverified_context()
            sock = context.wrap_socket(raw_sock, server_hostname=host)
        else:
            sock = raw_sock

        sock.sendall(http_payload)
        response = sock.recv(256)  # Read just the first line/headers
        sock.close()

        # Check if the response banner starts with HTTP (e.g., HTTP/1.1 200 OK or HTTP/1.1 403 Forbidden)
        return response.startswith(b"HTTP/")
    except (socket.error, TimeoutError, ssl.SSLError):
        return False
