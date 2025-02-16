from http.server import HTTPServer, BaseHTTPRequestHandler
import json

class TestServerHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        
        response = {
            'path': self.path,
            'method': 'GET',
            'headers': dict(self.headers)
        }
        self.wfile.write(json.dumps(response, indent=2).encode())

    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length).decode('utf-8')
        
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        
        response = {
            'path': self.path,
            'method': 'POST',
            'headers': dict(self.headers),
            'data': post_data
        }
        self.wfile.write(json.dumps(response, indent=2).encode())

def run_test_server(port=80):
    server_address = ('', port)
    httpd = HTTPServer(server_address, TestServerHandler)
    print(f"Test server running on port {port}")
    httpd.serve_forever()

if __name__ == "__main__":
    run_test_server() 