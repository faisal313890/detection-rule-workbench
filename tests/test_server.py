import http.client
import json
import threading
import unittest
from contextlib import closing
from server import WorkbenchServer
from samples import get_sample


class ServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = WorkbenchServer(('127.0.0.1', 0))
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.thread.join()
        cls.server.server_close()

    def request(self, path, method='GET', body=None, headers=None):
        opts = {'X-Rule-Workbench': 'local'}
        if body is not None:
            opts['Content-Type'] = 'application/json'
        opts.update(headers or {})
        with closing(http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=5)) as connection:
            connection.request(method, path, body=body, headers=opts)
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read()

    def test_all_sample_routes(self):
        for name in ('broad', 'tuned', 'auth', 'partial', 'invalid'):
            self.assertEqual(self.request('/api/sample/' + name)[0], 200)
        self.assertEqual(self.request('/api/sample/missing')[0], 404)

    def test_real_http_evaluation(self):
        for name, expected in [('broad', 3), ('tuned', 3), ('auth', 2), ('partial', 2)]:
            with self.subTest(sample=name):
                sample = get_sample(name)
                status, _, raw = self.request('/api/run', 'POST', json.dumps(sample))
                self.assertEqual(status, 200)
                result = json.loads(raw)
                self.assertEqual(result['report']['candidate']['matches'], expected)
                self.assertIn('fixture_outcome', result['csv'])

    def test_invalid_profile_rejected_no_report(self):
        status, _, raw = self.request('/api/run', 'POST', json.dumps(get_sample('invalid')))
        self.assertEqual(status, 400)
        self.assertNotIn('report', json.loads(raw))

    def test_validate_preserves_duplicate_key_rejection(self):
        rule = get_sample('broad')['candidate'].replace('"format": "drw/1",', '"format": "drw/1", "format": "drw/1",')
        status, _, raw = self.request('/api/validate', 'POST', json.dumps({'rule': rule}))
        self.assertEqual(status, 400)
        self.assertIn('Duplicate', json.loads(raw)['error'])
        self.assertEqual(self.request('/api/validate', 'POST', json.dumps({'rule': get_sample('broad')['candidate']}))[0], 200)

    def test_outer_payload_validation(self):
        for body in ('{', '[]', '{}', '{"compare":1}', '{"large":' + '1' * 5000 + '}'):
            self.assertEqual(self.request('/api/run', 'POST', body)[0], 400)

    def test_payload_byte_and_unicode_bounds(self):
        # The server rejects an oversized declared length before reading a body.
        self.assertEqual(self.request('/api/run', 'POST', '', {'Content-Length': str(2 * 1024 * 1024 + 1)})[0], 413)
        sample = get_sample('broad')
        sample['candidate'] = '\ud800'
        self.assertEqual(self.request('/api/run', 'POST', json.dumps(sample))[0], 400)

    def test_host_origin_and_fetch_site(self):
        for headers in ({'Host': 'outside.test'}, {'Origin': 'https://outside.test'}, {'Sec-Fetch-Site': 'cross-site'}):
            self.assertEqual(self.request('/api/sample/broad', headers=headers)[0], 403)

    def test_header_and_media_type_required(self):
        self.assertEqual(self.request('/api/sample/broad', headers={'X-Rule-Workbench': ''})[0], 403)
        self.assertEqual(self.request('/api/run', 'POST', '{}', {'Content-Type': 'text/plain'})[0], 415)

    def test_static_allowlist_security_headers(self):
        for path in ('/', '/app.js', '/style.css'):
            status, headers, _ = self.request(path)
            self.assertEqual(status, 200)
            self.assertEqual(headers['Cache-Control'], 'no-store')
            self.assertIn("frame-ancestors 'none'", headers['Content-Security-Policy'])
        for path in ('/server.py', '/../engine.py', '/static/../engine.py'):
            self.assertEqual(self.request(path)[0], 404)

    def test_loopback_binding_only(self):
        with self.assertRaises(ValueError):
            WorkbenchServer(('0.0.0.0', 0))


if __name__ == '__main__':
    unittest.main()
