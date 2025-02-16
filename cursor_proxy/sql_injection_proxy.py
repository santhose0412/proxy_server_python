import http.server
import urllib.request
import logging
import re
import socket
import ssl
import time
import select
import shutil
from urllib.parse import urlparse, parse_qs
from urllib.error import URLError
import dns.resolver
import config

# Create a custom filter class
class FirefoxFilter(logging.Filter):
    def filter(self, record):
        return ('detectportal.firefox.com' not in record.getMessage() 
                or record.levelno > logging.DEBUG)

# Configure logging
logger = logging.getLogger('sql_injection_proxy')
logger.setLevel(logging.INFO)

# Create file handler
file_handler = logging.FileHandler('sql_injection.log')
file_handler.setLevel(logging.INFO)

# Create formatter
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)

# Add filter to file handler
file_handler.addFilter(FirefoxFilter())

# Add handler to logger
logger.addHandler(file_handler)

class SQLInjectionProxy(http.server.SimpleHTTPRequestHandler):
    timeout = 30
    max_retries = 3
    retry_delay = 1

    def resolve_dns(self, hostname):
        # First try socket's built-in resolver (uses system DNS)
        try:
            return socket.gethostbyname(hostname)
        except socket.gaierror:
            pass

        # Fallback DNS servers with shorter timeouts
        dns_servers = [
            ('8.8.8.8', 53),    # Google DNS
            ('1.1.1.1', 53),    # Cloudflare DNS
            ('208.67.222.222', 53)  # OpenDNS
        ]
        
        resolver = dns.resolver.Resolver()
        resolver.timeout = 1.0      # Shorter timeout per attempt
        resolver.lifetime = 3.0     # Total time for all attempts
        resolver.rotate = True      # Rotate through servers
        
        # Try all DNS servers at once
        resolver.nameservers = [server[0] for server in dns_servers]
        
        try:
            answers = resolver.resolve(hostname, 'A')
            for answer in answers:
                return str(answer)
        except Exception as e:
            # If parallel resolution fails, try servers one by one with minimal timeout
            for dns_server, port in dns_servers:
                try:
                    resolver.nameservers = [dns_server]
                    resolver.timeout = 0.5
                    resolver.lifetime = 1.0
                    answers = resolver.resolve(hostname, 'A')
                    for answer in answers:
                        return str(answer)
                except Exception:
                    continue
            
            # If all attempts fail, raise the last error
            logger.error(f"All DNS resolution attempts failed for {hostname}")
            raise

    def detect_sql_injection(self, query_string):
        # Enhanced SQL injection patterns
        sql_patterns = [
            r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER|EXEC|TRUNCATE)\b)",
            r"(--+)",
            r"(;+)",
            r"('|\")",
            r"(\bOR\b.*=.*)",
            r"(\bAND\b.*=.*)",
            r"(/\*.*\*/)",
            r"\b(CONCAT|CHAR|SUBSTRING|ASCII|BIN|HEX|UNHEX|BASE64)\b",
            r"\b(SLEEP|BENCHMARK|WAIT FOR DELAY)\b",
            r"\b(INFORMATION_SCHEMA|SYSUSERS|SYSOBJECTS)\b",
        ]
        
        for pattern in sql_patterns:
            if re.search(pattern, query_string, re.IGNORECASE):
                return True
        return False

    def send_request_with_retry(self, req):
        retries = 0
        while retries < self.max_retries:
            try:
                return urllib.request.urlopen(req, timeout=self.timeout)
            except (URLError, ConnectionError, socket.error) as e:
                retries += 1
                if retries == self.max_retries:
                    raise
                logger.warning(f"Request failed (attempt {retries}/{self.max_retries}): {str(e)}")
                time.sleep(self.retry_delay)

    def handle_firefox_request(self, host):
        """Handle Firefox-specific requests with empty responses"""
        if host == 'detectportal.firefox.com':
            # Cache control headers to reduce repeated requests
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.send_header('Content-Length', '0')
            self.send_header('Connection', 'close')
            self.send_header('Cache-Control', 'max-age=3600')  # Cache for 1 hour
            self.send_header('Expires', 'Thu, 01 Jan 2030 00:00:00 GMT')  # Long expiry
            self.end_headers()
            logger.debug(f"Handled Firefox portal detection request")  # Using logger instead of logging
            return True
        else:
            # Handle other Firefox-specific domains
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.send_header('Content-Length', '0')
            self.send_header('Connection', 'close')
            self.end_headers()
            logger.info(f"Handled Firefox-specific request for {host}")  # Using logger
            return True

    def do_GET(self):
        try:
            if not self.path.startswith('http'):
                self.path = f'http://{self.path}'

            parsed_url = urlparse(self.path)
            host = parsed_url.netloc.split(':')[0]

            # Handle Firefox-specific domains for GET requests
            if host in config.FIREFOX_DOMAINS:
                return self.handle_firefox_request(host)

            try:
                # Create request headers
                headers = {}
                for header, value in self.headers.items():
                    if header.lower() not in ['proxy-connection', 'connection']:
                        headers[header] = value
                headers['Host'] = parsed_url.netloc
                headers['Connection'] = 'close'

                # Create SSL context for HTTPS requests
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE

                # Make the request
                req = urllib.request.Request(
                    self.path,
                    headers=headers,
                    method='GET'
                )
                
                # Use custom opener with SSL context
                opener = urllib.request.build_opener(
                    urllib.request.HTTPSHandler(context=ctx)
                )
                
                with opener.open(req, timeout=config.CONNECT_TIMEOUT) as response:
                    # Send response status
                    self.send_response(response.status)
                    
                    # Send response headers
                    for header, value in response.getheaders():
                        if header.lower() not in ['transfer-encoding', 'content-encoding', 'connection']:
                            self.send_header(header, value)
                    self.send_header('Connection', 'close')
                    self.end_headers()

                    # Send response body
                    while True:
                        chunk = response.read(config.BUFFER_SIZE)
                        if not chunk:
                            break
                        self.wfile.write(chunk)
                    
                logger.info(f"Request processed successfully: {self.path}")

            except Exception as e:
                logger.error(f"Request failed: {self.path} - {str(e)}")
                self.send_error(502, f"Request failed: {str(e)}")

        except Exception as e:
            logger.error(f"Error processing request: {str(e)}")
            self.send_error(500, f"Internal Server Error: {str(e)}")

    def do_POST(self):
        try:
            if not self.path.startswith('http'):
                self.send_error(400, "Bad Request - URL must start with http:// or https://")
                return

            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length).decode('utf-8')
            
            if self.detect_sql_injection(post_data):
                logger.warning(f"SQL Injection attempt detected in POST data! URL: {self.path}, Data: {post_data}")
                self.send_error(403, "Forbidden - SQL Injection Detected")
                return
            
            parsed_url = urlparse(self.path)
            headers = dict(self.headers)
            headers['Host'] = parsed_url.netloc
            headers['Connection'] = 'close'
            
            req = urllib.request.Request(
                self.path,
                data=post_data.encode('utf-8'),
                headers=headers,
                method='POST'
            )
            
            try:
                response = self.send_request_with_retry(req)
                
                self.send_response(response.status)
                for header, value in response.getheaders():
                    if header.lower() not in ['transfer-encoding', 'content-encoding', 'connection']:
                        self.send_header(header, value)
                self.send_header('Connection', 'close')
                self.end_headers()

                while True:
                    chunk = response.read(8192)
                    if not chunk:
                        break
                    try:
                        self.wfile.write(chunk)
                    except (ConnectionError, BrokenPipeError):
                        return
                
                logger.info(f"POST request processed successfully: {self.path}")
                
            finally:
                if 'response' in locals():
                    response.close()
                
        except Exception as e:
            logger.error(f"Error processing POST request: {str(e)}")
            try:
                self.send_error(500, f"Internal Server Error: {str(e)}")
            except (ConnectionError, BrokenPipeError):
                pass

    def do_CONNECT(self):
        try:
            # Parse the host and port from the path
            host_port = self.path.split(':')
            host = host_port[0]
            port = int(host_port[1]) if len(host_port) > 1 else 443

            # Handle Firefox-specific domains
            if host in config.FIREFOX_DOMAINS:
                self.send_response(200, 'Connection Established')
                self.end_headers()
                return

            try:
                # Create connection to target
                dest = socket.create_connection((host, port), timeout=config.CONNECT_TIMEOUT)

                if port == 443:
                    # For HTTPS, wrap the destination socket
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    dest = context.wrap_socket(dest, server_hostname=host)

                # Send 200 Connection established
                self.send_response(200, 'Connection Established')
                self.end_headers()

                # Create bidirectional tunnel
                self.connection.setblocking(1)
                dest.setblocking(1)
                
                # Forward data between client and server
                while True:
                    try:
                        r, w, e = select.select([self.connection, dest], [], [], config.SOCKET_TIMEOUT)
                        if not r:
                            continue

                        for sock in r:
                            other = dest if sock is self.connection else self.connection
                            try:
                                data = sock.recv(config.BUFFER_SIZE)
                                if not data:
                                    return
                                other.sendall(data)
                            except (ConnectionError, socket.error, ssl.SSLError) as e:
                                return

                    except Exception as tunnel_error:
                        logger.error(f"Tunnel error for {host}:{port}: {str(tunnel_error)}")
                        return

            except Exception as e:
                logger.error(f"Connection failed to {host}:{port}: {str(e)}")
                self.send_error(504, f"Connection failed to {host}:{port}")
                return
            finally:
                try:
                    if 'dest' in locals():
                        dest.close()
                except:
                    pass

        except Exception as e:
            logger.error(f"CONNECT error for {self.path}: {str(e)}")
            self.send_error(500, f"CONNECT failed: {str(e)}")

    def handle_one_request(self):
        try:
            return super().handle_one_request()
        except ConnectionError:
            # Silently handle connection resets and broken pipes
            pass
        except Exception as e:
            logger.error(f"Error handling request: {str(e)}") 