#!/usr/bin/env python3
import socket
import ssl
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

def check_web_service(host, port, timeout=3):
    """Determine if a port is running a web server and if it uses SSL."""
    results = {
        'port': port,
        'is_web': False,
        'is_ssl': False,
        'server': None,
        'status_code': None,
        'error': None
    }
    
    # Try HTTP first
    http_result = probe_http(host, port, use_ssl=False, timeout=timeout)
    if http_result['success']:
        results['is_web'] = True
        results['is_ssl'] = False
        results['server'] = http_result.get('server')
        results['status_code'] = http_result.get('status_code')
        return results
    
    # If HTTP fails, try HTTPS
    https_result = probe_http(host, port, use_ssl=True, timeout=timeout)
    if https_result['success']:
        results['is_web'] = True
        results['is_ssl'] = True
        results['server'] = https_result.get('server')
        results['status_code'] = https_result.get('status_code')
        return results
    
    # Neither worked
    results['error'] = http_result.get('error') or https_result.get('error')
    return results

def probe_http(host, port, use_ssl=False, timeout=3):
    """Probe a port with HTTP/HTTPS and parse response."""
    try:
        # Create socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        
        # Wrap with SSL if needed
        if use_ssl:
            try:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(sock, server_hostname=host)
            except ssl.SSLError:
                return {'success': False, 'error': 'SSL handshake failed'}
        
        # Send HTTP request
        request = f"GET / HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n"
        sock.send(request.encode())
        
        # Read response
        response = b''
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
                if len(response) > 8192:  # Limit response size
                    break
            except socket.timeout:
                break
        
        sock.close()
        
        # Parse response
        if not response:
            return {'success': False, 'error': 'No response'}
        
        # Check if it looks like HTTP
        response_str = response.decode('utf-8', errors='ignore')
        if not response_str.startswith(('HTTP/', 'HTTP/1.', 'HTTP/2')):
            return {'success': False, 'error': 'Not HTTP response'}
        
        # Extract status code and server header
        status_code = None
        server = None
        lines = response_str.split('\r\n')
        if lines and lines[0].startswith('HTTP/'):
            parts = lines[0].split()
            if len(parts) >= 3:
                status_code = parts[1]
        
        for line in lines:
            if line.lower().startswith('server:'):
                server = line.split(':', 1)[1].strip()
                break
        
        return {
            'success': True,
            'status_code': status_code,
            'server': server,
            'response_preview': response_str[:200]
        }
        
    except socket.timeout:
        return {'success': False, 'error': 'Timeout'}
    except socket.error as e:
        return {'success': False, 'error': str(e)}
    except Exception as e:
        return {'success': False, 'error': str(e)}

def scan_ports(host, ports, max_workers=20):
    """Scan multiple ports concurrently."""
    results = {}
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(check_web_service, host, port): port 
                   for port in ports}
        
        for future in as_completed(futures):
            port = futures[future]
            try:
                results[port] = future.result()
            except Exception as e:
                results[port] = {'port': port, 'error': str(e)}
    
    return results

# Usage
if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 web_detect.py <host> <port1> [port2 port3 ...]")
        print("Example: python3 web_detect.py example.com 80 443 8080 8443")
        sys.exit(1)
    
    host = sys.argv[1]
    ports = [int(p) for p in sys.argv[2:]]
    
    print(f"Scanning {host} on ports: {ports}")
    print("-" * 50)
    
    results = scan_ports(host, ports)
    
    for port in sorted(results.keys()):
        r = results[port]
        if r.get('is_web'):
            ssl_status = "HTTPS" if r['is_ssl'] else "HTTP"
            status = r.get('status_code', 'unknown')
            server = r.get('server', 'unknown')
            print(f"✓ Port {port}: WEB ({ssl_status}) - Status: {status} - Server: {server}")
        else:
            error = r.get('error', 'No web service detected')
            print(f"✗ Port {port}: NOT WEB - {error}")
