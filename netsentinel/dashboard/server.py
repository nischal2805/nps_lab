"""Dashboard HTTP server for NetSentinel."""
import json
import socketserver
import webbrowser
from http.server import SimpleHTTPRequestHandler
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse


class DashboardHandler(SimpleHTTPRequestHandler):
    """HTTP handler for dashboard API and static files."""
    
    def __init__(self, *args, **kwargs):
        """Initialize handler with dashboard directory as base."""
        # Set the directory to serve files from (where dashboard.html is)
        self.directory = str(Path(__file__).parent)
        super().__init__(*args, directory=self.directory, **kwargs)
    
    def end_headers(self):
        """Add CORS headers to all responses."""
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        super().end_headers()
    
    def do_GET(self):
        """Handle GET requests."""
        parsed_path = urlparse(self.path)
        path = parsed_path.path
        
        # Route: GET /api/scans - list all scans
        if path == '/api/scans':
            self._handle_list_scans()
        
        # Route: GET /api/scans/<scan-id> - get scan details
        elif path.startswith('/api/scans/'):
            scan_id = path.split('/api/scans/')[-1]
            self._handle_get_scan(scan_id)
        
        # Route: GET / - serve dashboard.html
        elif path == '/' or path == '/index.html':
            self._serve_dashboard()
        
        # All other paths: 404
        else:
            self._send_404()
    
    def _handle_list_scans(self):
        """Return list of all scans from index.json."""
        storage_path = Path.home() / '.netsentinel'
        index_file = storage_path / 'index.json'
        
        try:
            if not index_file.exists():
                # Storage directory doesn't exist yet - return empty list
                self._send_json_response([], 200)
                return
            
            with open(index_file, 'r', encoding='utf-8') as f:
                scans = json.load(f)
            
            self._send_json_response(scans, 200)
        
        except json.JSONDecodeError as e:
            error_msg = f"Malformed index.json: {str(e)}"
            self.log_error(error_msg)
            self._send_json_response({'error': error_msg}, 500)
        
        except Exception as e:
            error_msg = f"Error reading scans: {str(e)}"
            self.log_error(error_msg)
            self._send_json_response({'error': error_msg}, 500)
    
    def _handle_get_scan(self, scan_id: str):
        """Return full scan details from scans/<scan-id>.json."""
        storage_path = Path.home() / '.netsentinel'
        scan_file = storage_path / 'scans' / f'{scan_id}.json'
        
        try:
            if not scan_file.exists():
                error_msg = f"Scan not found: {scan_id}"
                self.log_error(error_msg)
                self._send_json_response({'error': error_msg}, 404)
                return
            
            with open(scan_file, 'r', encoding='utf-8') as f:
                scan_data = json.load(f)
            
            self._send_json_response(scan_data, 200)
        
        except json.JSONDecodeError as e:
            error_msg = f"Malformed scan file: {str(e)}"
            self.log_error(error_msg)
            self._send_json_response({'error': error_msg}, 500)
        
        except Exception as e:
            error_msg = f"Error reading scan: {str(e)}"
            self.log_error(error_msg)
            self._send_json_response({'error': error_msg}, 500)
    
    def _serve_dashboard(self):
        """Serve the dashboard.html file."""
        dashboard_file = Path(self.directory) / 'dashboard.html'
        
        try:
            if not dashboard_file.exists():
                error_msg = "dashboard.html not found"
                self.log_error(error_msg)
                self._send_text_response(
                    f"<h1>Error</h1><p>{error_msg}</p>",
                    404,
                    'text/html'
                )
                return
            
            with open(dashboard_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            self._send_text_response(content, 200, 'text/html')
        
        except Exception as e:
            error_msg = f"Error serving dashboard: {str(e)}"
            self.log_error(error_msg)
            self._send_text_response(
                f"<h1>Error</h1><p>{error_msg}</p>",
                500,
                'text/html'
            )
    
    def _send_json_response(self, data, status_code: int):
        """Send JSON response with proper headers."""
        json_str = json.dumps(data, indent=2)
        self._send_text_response(json_str, status_code, 'application/json')
    
    def _send_text_response(self, content: str, status_code: int, content_type: str):
        """Send text response with proper headers."""
        content_bytes = content.encode('utf-8')
        
        self.send_response(status_code)
        self.send_header('Content-Type', f'{content_type}; charset=utf-8')
        self.send_header('Content-Length', str(len(content_bytes)))
        self.end_headers()
        self.wfile.write(content_bytes)
    
    def _send_404(self):
        """Send 404 Not Found response."""
        self._send_json_response({'error': 'Not Found'}, 404)
    
    def log_message(self, format, *args):
        """Override to customize logging format."""
        # Only log errors, not every request
        pass


def start_server(port: int = 8742, open_browser: bool = True):
    """Start dashboard server and optionally open browser.
    
    Args:
        port: Port to bind to (default: 8742)
        open_browser: Whether to auto-open browser (default: True)
    """
    handler = DashboardHandler
    
    try:
        with socketserver.TCPServer(("", port), handler) as httpd:
            print(f"Dashboard running at http://localhost:{port}")
            
            if open_browser:
                webbrowser.open(f"http://localhost:{port}")
            
            httpd.serve_forever()
    
    except OSError as e:
        if e.errno == 10048:  # Windows: Address already in use
            print(f"Error: Port {port} is already in use.")
            print(f"Another NetSentinel dashboard may be running.")
        else:
            print(f"Error starting server: {e}")
    
    except KeyboardInterrupt:
        print("\nShutting down dashboard server...")


if __name__ == '__main__':
    start_server()
