import base64
import importlib.util
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading
import unittest

RUNTIME = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('connect', RUNTIME / 'connect.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class FakeProxy:
    """Accept one CONNECT, record its head, answer with `reply`, then echo the tunnel upper-cased."""

    def __init__(self, reply=b'HTTP/1.1 200 Connection established\r\n\r\n'):
        self.reply = reply
        self.head = None
        self.server = socket.create_server(('127.0.0.1', 0))
        self.port = self.server.getsockname()[1]
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def serve(self):
        conn, _ = self.server.accept()
        with conn:
            data = bytearray()
            while b'\r\n\r\n' not in data:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                data.extend(chunk)
            head, _, rest = bytes(data).partition(b'\r\n\r\n')
            self.head = head.decode()
            conn.sendall(self.reply)
            if not self.reply.startswith(b'HTTP/1.1 200'):
                return
            buffered = bytearray(rest)
            while chunk := conn.recv(4096):
                buffered.extend(chunk)
            conn.sendall(bytes(buffered).upper())
            conn.shutdown(socket.SHUT_WR)

    def close(self):
        self.server.close()
        self.thread.join(timeout=5)


class ConnectRequestTests(unittest.TestCase):
    def test_request_carries_basic_credentials(self):
        address, request = module.connect_request('ssh.github.com', '443', 'http://hatchward:to%2Fken@127.0.0.1:3128')
        self.assertEqual(address, ('127.0.0.1', 3128))
        credentials = base64.b64encode(b'hatchward:to/ken').decode()
        self.assertEqual(request.decode(), 'CONNECT ssh.github.com:443 HTTP/1.1\r\nHost: ssh.github.com:443\r\n'
                         f'Proxy-Authorization: Basic {credentials}\r\n\r\n')

    def test_request_without_credentials_and_ipv6(self):
        _, request = module.connect_request('::1', '22', 'http://127.0.0.1:3128')
        self.assertEqual(request.decode(), 'CONNECT [::1]:22 HTTP/1.1\r\nHost: [::1]:22\r\n\r\n')

    def test_rejects_injection_and_bad_proxy(self):
        for host, port, proxy in (('h\r\nX: y', '22', 'http://p:1'), ('h h', '22', 'http://p:1'),
                                  ('h', '0', 'http://p:1'), ('h', '65536', 'http://p:1'), ('h', 'x', 'http://p:1'),
                                  ('h', '22', 'https://p:1'), ('h', '22', 'socks5://p:1'), ('h', '22', '')):
            with self.subTest(host=host, port=port, proxy=proxy), self.assertRaises(ValueError):
                module.connect_request(host, port, proxy)

    def test_proxy_from_env_prefers_https_proxy(self):
        self.assertEqual(module.proxy_from_env({'HTTP_PROXY': 'http://a:1', 'HTTPS_PROXY': 'http://b:1'}), 'http://b:1')
        self.assertEqual(module.proxy_from_env({'http_proxy': 'http://a:1'}), 'http://a:1')
        with self.assertRaises(ValueError):
            module.proxy_from_env({})


class ConnectProcessTests(unittest.TestCase):
    def run_connect(self, proxy, data=b'', env_proxy=None):
        env = {k: v for k, v in os.environ.items() if not k.lower().endswith('_proxy')}
        env['HTTPS_PROXY'] = env_proxy or f'http://hatchward:secret@127.0.0.1:{proxy.port}'
        return subprocess.run([sys.executable, '-I', str(RUNTIME / 'connect.py'), 'ssh.github.com', '443'],
                              input=data, capture_output=True, env=env, timeout=10)

    def test_handshake_and_relay(self):
        proxy = FakeProxy(b'HTTP/1.1 200 Connection established\r\nVia: test\r\n\r\n')
        self.addCleanup(proxy.close)
        result = self.run_connect(proxy, b'SSH-2.0-OpenSSH_9.9\r\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b'SSH-2.0-OPENSSH_9.9\r\n')
        lines = proxy.head.split('\r\n')
        self.assertEqual(lines[0], 'CONNECT ssh.github.com:443 HTTP/1.1')
        self.assertIn('Proxy-Authorization: Basic ' + base64.b64encode(b'hatchward:secret').decode(), lines)

    def test_refusal_exits_non_zero_without_leaking_credentials(self):
        proxy = FakeProxy(b'HTTP/1.1 403 Forbidden\r\n\r\n')
        self.addCleanup(proxy.close)
        result = self.run_connect(proxy)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b'')
        self.assertIn(b'403 Forbidden', result.stderr)
        self.assertNotIn(b'secret', result.stderr)

    def test_missing_proxy(self):
        env = {k: v for k, v in os.environ.items() if not k.lower().endswith('_proxy')}
        result = subprocess.run([sys.executable, '-I', str(RUNTIME / 'connect.py'), 'h', '22'],
                                capture_output=True, env=env, timeout=10)
        self.assertNotEqual(result.returncode, 0)


if __name__ == '__main__':
    unittest.main()
