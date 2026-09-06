#!/usr/bin/env python3
import socket
import ssl
import sys

def quick_web_check(host, port, timeout=2):
    """Ultra-fast check using connection signatures."""
    
    # First, try to connect and detect SSL/TLS
    is_ssl = False
    try:
        # Attempt SSL handshake immediately
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as sock:
            ssl_sock = context.wrap_socket(sock, server_hostname=host)
            is_ssl = True
            # SSL succeeded - now check if it's a web server
            return check_with_ssl(host, port, ssl_sock)
    except (ssl.SSLError, socket.error):
        # Not SSL, try plain HTTP
        pass
    
    # Try plain HTTP
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            # Send minimal HTTP probe
            sock.send(b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
            response = sock.recv(512)
            if response.startswith(b'HTTP/'):
                return True, False, response.split(b'\r\n')[0].decode()
    except:
        pass
    
    return False, False, None

def check_with_ssl(host, port, ssl_sock):
    """Check SSL socket for HTTP."""
    try:
        ssl_sock.send(b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
        response = ssl_sock.recv(512)
        if response.startswith(b'HTTP/'):
            return True, True, response.split(b'\r\n')[0].decode()
    except:
        pass
    return False, False, None

# Usage
if __name__ == "__main__":
    host = sys.argv[1]
    ports = [int(p) for p in sys.argv[2:]]
    
    for port in ports:
        is_web, is_ssl, header = quick_web_check(host, port)
        if is_web:
            proto = "HTTPS" if is_ssl else "HTTP"
            print(f"✓ Port {port}: {proto} - {header}")
        else:
            print(f"✗ Port {port}: Not a web server")
