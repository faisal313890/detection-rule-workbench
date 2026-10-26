"""Stateless loopback HTTP UI. All evaluation is in memory."""
import json
import os
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit
from engine import ValidationError, load_json, parse_rule, run, to_csv
from samples import get_sample

ROOT = Path(__file__).resolve().parent
MAX_REQUEST = 2 * 1024 * 1024


class WorkbenchServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address):
        if address[0] != '127.0.0.1':
            raise ValueError('The workbench must bind to 127.0.0.1.')
        super().__init__(address, Handler)


class Handler(BaseHTTPRequestHandler):
    server_version = 'DetectionRuleWorkbench/0.1'

    def setup(self):
        super().setup()
        self.connection.settimeout(15)

    def log_message(self, *args):
        pass

    def reply(self, status, data, content_type='application/json; charset=utf-8'):
        raw = data if isinstance(data, bytes) else json.dumps(data, ensure_ascii=True).encode()
        self.send_response(status)
        for key, value in {'Content-Type': content_type, 'Content-Length': str(len(raw)), 'Cache-Control': 'no-store',
            'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer', 'X-Frame-Options': 'DENY',
            'Connection': 'close', 'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"}.items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(raw)
        self.close_connection = True

    def do_GET(self):
        self.route()

    def do_POST(self):
        self.route()

    def route(self):
        hosts = {f'127.0.0.1:{self.server.server_port}', f'localhost:{self.server.server_port}'}
        origin = self.headers.get('Origin')
        if self.headers.get('Host') not in hosts or (origin is not None and origin not in {f'http://{h}' for h in hosts}) or self.headers.get('Sec-Fetch-Site') == 'cross-site':
            return self.reply(403, {'error': 'Local Host/Origin required; cross-site requests are rejected.'})
        try:
            parsed = urlsplit(self.path)
        except ValueError:
            return self.reply(400, {'error': 'Malformed path.'})
        if parsed.query or parsed.fragment or parsed.scheme or parsed.netloc:
            return self.reply(400, {'error': 'Relative paths without query parameters required.'})
        path = parsed.path
        static = {'/': ('index.html', 'text/html; charset=utf-8'), '/app.js': ('app.js', 'text/javascript; charset=utf-8'), '/style.css': ('style.css', 'text/css; charset=utf-8')}
        if self.command == 'GET' and path in static:
            filename, kind = static[path]
            return self.reply(200, (ROOT / 'static' / filename).read_bytes(), kind)
        if self.headers.get('X-Rule-Workbench') != 'local':
            return self.reply(403, {'error': 'Workbench request header required.'})
        if self.command == 'GET' and path.startswith('/api/sample/'):
            try:
                return self.reply(200, get_sample(path.removeprefix('/api/sample/')))
            except KeyError:
                return self.reply(404, {'error': 'Unknown sample.'})
        if path not in ('/api/run', '/api/validate') or self.command != 'POST':
            return self.reply(404, {'error': 'Unknown operation.'})
        if self.headers.get('Transfer-Encoding'):
            return self.reply(400, {'error': 'Transfer encoding is unsupported.'})
        try:
            length = int(self.headers.get('Content-Length', '-1'))
        except ValueError:
            length = -1
        if not 0 <= length <= MAX_REQUEST:
            return self.reply(413, {'error': 'Request must be at most 2 MiB including JSON encoding.'})
        if self.headers.get('Content-Type', '').split(';')[0].strip().lower() != 'application/json':
            return self.reply(415, {'error': 'JSON required.'})
        try:
            payload = load_json(self.rfile.read(length).decode('utf-8'))
            if path == '/api/validate':
                if not isinstance(payload, dict) or set(payload) != {'rule'}:
                    raise ValidationError('Supply rule text only.')
                rule, _, _ = parse_rule(payload['rule'])
                return self.reply(200, {'rule': rule})
            if not isinstance(payload, dict) or set(payload) != {'candidate', 'baseline', 'events', 'compare'} or type(payload['compare']) is not bool:
                raise ValidationError('Supply candidate, baseline, events and Boolean compare only.')
            if not isinstance(payload['baseline'], str):
                raise ValidationError('baseline must be text (empty is allowed when comparison is disabled).')
            report = run(payload['candidate'], payload['events'], payload['baseline'] if payload['compare'] else None)
            return self.reply(200, {'report': report, 'csv': to_csv(report)})
        except (ValidationError, UnicodeError) as exc:
            return self.reply(400, {'error': str(exc)[:500]})


def main():
    port = int(os.environ.get('RULE_WORKBENCH_PORT', '8830'))
    if not 1 <= port <= 65535:
        raise ValueError('RULE_WORKBENCH_PORT must be 1..65535')
    with WorkbenchServer(('127.0.0.1', port)) as server:
        url = f'http://127.0.0.1:{server.server_port}'
        print(f'Detection Rule Workbench: {url}\nCtrl+C stops the server. Local JSON fixtures only.')
        if os.environ.get('RULE_WORKBENCH_NO_BROWSER') != '1':
            webbrowser.open(url)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print('\nStopped.')


if __name__ == '__main__':
    main()
