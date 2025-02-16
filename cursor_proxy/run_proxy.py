from http.server import HTTPServer
from sql_injection_proxy import SQLInjectionProxy
import socket
import sys
import config

def run_proxy(port=8080):
    try:
        # Set default socket timeout
        socket.setdefaulttimeout(config.CONNECT_TIMEOUT)
        
        server_address = ('', port)
        httpd = HTTPServer(server_address, SQLInjectionProxy)
        
        # Configure socket options
        httpd.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        httpd.socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        
        # Set TCP keepalive parameters
        if hasattr(socket, 'TCP_KEEPIDLE'):
            httpd.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 60)
        if hasattr(socket, 'TCP_KEEPINTVL'):
            httpd.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 10)
        if hasattr(socket, 'TCP_KEEPCNT'):
            httpd.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 5)

        print(f"Proxy server running on port {port}")
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down the proxy server...")
        httpd.server_close()
        sys.exit(0)
    except Exception as e:
        print(f"Failed to start proxy server: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    run_proxy() 