import concurrent.futures
import importlib.util
import json
import os
import re
import stat
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import time
import unittest

RUNTIME = Path(__file__).resolve().parents[1]


def load_gateway():
    spec = importlib.util.spec_from_file_location('gateway', RUNTIME / 'gateway.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def receive_all(sock):
    chunks = []
    while chunk := sock.recv(65536):
        chunks.append(chunk)
    return b''.join(chunks)


def encode(kind, payload=b''):
    return kind + struct.pack('!I', len(payload)) + payload


def read_frames(stream):
    result = bytearray()
    while True:
        header = stream.read(5)
        if len(header) != 5:
            raise AssertionError('missing framed EOF')
        length = struct.unpack('!I', header[1:])[0]
        if header[:1] == b'F':
            if length:
                raise AssertionError('invalid EOF frame')
            return bytes(result)
        if header[:1] != b'D' or not 0 < length <= 65536:
            raise AssertionError('invalid data frame')
        payload = stream.read(length)
        if len(payload) != length:
            raise AssertionError('truncated payload')
        result.extend(payload)


class GatewayTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.control = self.tmp.name + '/bridge/control.sock'
        self.actions = self.tmp.name + '/actions.sock'
        self.ready = self.tmp.name + '/gateway.ready'
        self.reload_sock = self.tmp.name + '/reload.sock'
        self.endpoints = Path(self.tmp.name + '/endpoints.json')
        self.process = subprocess.Popen([sys.executable, str(RUNTIME / 'gateway.py'),
            '--control', self.control, '--actions', self.actions, '--endpoints', str(self.endpoints),
            '--port', '0', '--pending-seconds', '.3'])
        deadline = time.monotonic() + 5
        while not Path(self.ready).exists():
            if self.process.poll() is not None or time.monotonic() > deadline:
                self.fail('gateway failed startup')
            time.sleep(.01)
        self.port = int(Path(self.ready).read_text())

    def tearDown(self):
        self.process.terminate()
        self.process.wait(timeout=5)
        self.tmp.cleanup()

    def connect(self, path):
        sock = socket.socket(socket.AF_UNIX)
        sock.settimeout(5)
        self.addCleanup(sock.close)
        sock.connect(path)
        return sock

    def test_concurrent_bidirectional_exact_stream_and_halfclose(self):
        def transfer(index):
            control = self.connect(self.control)
            client = self.connect(self.actions)
            self.assertEqual(control.recv(1), b'A')
            payload = bytes(range(256)) * 5000
            def send():
                client.sendall(payload)
                client.shutdown(socket.SHUT_WR)
            with concurrent.futures.ThreadPoolExecutor(1) as pool:
                sending = pool.submit(send)
                self.assertEqual(receive_all(control), payload)
                sending.result()
            control.sendall(b'reply after EOF')
            control.shutdown(socket.SHUT_WR)
            self.assertEqual(receive_all(client), b'reply after EOF')
        with concurrent.futures.ThreadPoolExecutor(8) as pool:
            list(pool.map(transfer, range(8)))

    def test_pending_timeout_and_queue_bound(self):
        clients = []
        for _ in range(40):
            try:
                clients.append(self.connect(self.actions))
            except (ConnectionRefusedError, BlockingIOError):
                # BSD Unix sockets may reject at the bounded kernel backlog
                # before the event loop accepts and applies its pending limit;
                # Linux reports EAGAIN when the connect timeout meets a full backlog.
                pass
        self.assertTrue(clients)
        time.sleep(.6)
        for client in clients:
            self.assertEqual(client.recv(1), b'')

    def test_control_registration_bound(self):
        controls = []
        while len(controls) <= load_gateway().SLOTS:
            try:
                controls.append(self.connect(self.control))
            except ConnectionRefusedError:
                # BSD refuses at the kernel backlog (32) until the gateway accepts.
                time.sleep(.01)
        self.assertEqual(controls[-1].recv(1), b'')

    def test_channel_idle_host_eof_exits(self):
        channel = subprocess.Popen([sys.executable, str(RUNTIME / 'channel.py'),
            '--control', self.control], stdin=subprocess.PIPE, stdout=subprocess.PIPE, bufsize=0)
        out, _ = channel.communicate(timeout=3)
        self.assertEqual(channel.returncode, 0)
        self.assertEqual(out, b'')

    def spawn_channel(self):
        channel = subprocess.Popen([sys.executable, str(RUNTIME / 'channel.py'),
            '--control', self.control], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        def cleanup():
            if channel.poll() is None:
                channel.kill()
            channel.wait(timeout=3)
            channel.stdin.close()
            channel.stdout.close()
        self.addCleanup(cleanup)
        return channel

    def test_channel_stream(self):
        channel = self.spawn_channel()
        client = self.connect(self.actions)
        payload = bytes(range(256)) * 5000
        self.assertEqual(channel.stdout.read(1), b'A')
        def send_request():
            client.sendall(payload)
            client.shutdown(socket.SHUT_WR)
        with concurrent.futures.ThreadPoolExecutor(1) as pool:
            sending = pool.submit(send_request)
            self.assertEqual(read_frames(channel.stdout), payload)
            sending.result()
        # Docker's process must stay alive after directional EOF to accept reply.
        self.assertIsNone(channel.poll())
        channel.stdin.write(encode(b'D', b'response') + encode(b'F'))
        channel.stdin.flush()
        self.assertEqual(receive_all(client), b'response')
        channel.wait(timeout=3)
        self.assertEqual(channel.returncode, 0)

    def test_channel_rejects_malformed_frames(self):
        for data in (b'X' + bytes(4), encode(b'D'),
                     b'D' + struct.pack('!I', 65537), encode(b'F', b'x'),
                     encode(b'F') + encode(b'F'), encode(b'F') + encode(b'D', b'x')):
            with self.subTest(data=data):
                channel = self.spawn_channel()
                client = self.connect(self.actions)
                self.assertEqual(channel.stdout.read(1), b'A')
                channel.stdin.write(data)
                channel.stdin.flush()
                channel.wait(timeout=3)
                self.assertEqual(channel.returncode, 1)
                client.close()

    def test_channels_ready_tracks_registration_lifecycle(self):
        ready = Path(self.control).parent / 'channels.ready'
        self.assertFalse(ready.exists())
        control = self.connect(self.control)
        deadline = time.monotonic() + 2
        while not ready.exists() and time.monotonic() < deadline:
            time.sleep(.01)
        self.assertTrue(ready.exists())
        control.close()
        deadline = time.monotonic() + 2
        while ready.exists() and time.monotonic() < deadline:
            time.sleep(.01)
        self.assertFalse(ready.exists())

    def test_channel_pending_host_bytes_and_eof_cancel(self):
        channel = subprocess.Popen([sys.executable, str(RUNTIME / 'channel.py'),
            '--control', self.control], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        out, _ = channel.communicate(encode(b'D', b'unsolicited'), timeout=3)
        self.assertEqual(channel.returncode, 0)
        self.assertEqual(out, b'')

    def test_proxy_kind(self):
        control = self.connect(self.control)
        with socket.create_connection(('127.0.0.1', self.port), timeout=5) as client:
            client.sendall(b'GET')
            self.assertEqual(control.recv(1), b'P')
            self.assertEqual(control.recv(3), b'GET')

    def test_pair_backpressure_bounds_buffers(self):
        module = load_gateway()
        a, b = socket.socketpair()
        c, d = socket.socketpair()
        for sock in (a, b, c, d):
            self.addCleanup(sock.close)
            sock.setblocking(False)
        pair = module.Pair(a, c, b'P')
        while len(pair.output[1]) < module.LIMIT:
            b.send(b'x' * min(4096, module.LIMIT - len(pair.output[1])))
            pair.pump([a], [])
        self.assertEqual(len(pair.output[1]), module.LIMIT)
        reads, writes = [], []
        pair.interests(reads, writes)
        self.assertNotIn(a, reads)
        self.assertIn(c, writes)
        pair.pump([], [c])
        pair.interests(reads, writes)
        self.assertIn(a, reads)

    def test_shutdown_removes_sockets(self):
        self.write_table([{'index': 0, 'name': 'svc', 'unix': 'svc'}])
        self.assertEqual(self.reload(), b'1')
        self.process.terminate()
        self.process.wait(timeout=3)
        for path in (self.control, self.actions, self.ready, self.reload_sock, self.tmp.name + '/svc.sock'):
            self.assertFalse(Path(path).exists(), path)

    def write_table(self, endpoints):
        self.endpoints.write_text(json.dumps({'endpoints': endpoints}))

    def reload(self):
        with socket.socket(socket.AF_UNIX) as sock:
            sock.settimeout(5)
            sock.connect(self.reload_sock)
            reply = sock.recv(1)
            self.assertEqual(sock.recv(1), b'')
            return reply

    def test_reload_socket_is_public(self):
        self.assertEqual(stat.S_IMODE(os.stat(self.reload_sock).st_mode), 0o666)

    def test_reload_without_table_fails(self):
        self.assertEqual(self.reload(), b'0')
        self.endpoints.write_text('not json')
        self.assertEqual(self.reload(), b'0')

    def test_reload_binds_endpoints_idempotently(self):
        port = free_port()
        self.write_table([{'index': 5, 'name': 'svc', 'unix': 'svc'},
                          {'index': 7, 'name': 'pg', 'tcp': port, 'address': '127.0.0.1'}])
        for _ in range(3):
            self.assertEqual(self.reload(), b'1')
        unix = self.tmp.name + '/svc.sock'
        self.assertEqual(stat.S_IMODE(os.stat(unix).st_mode), 0o666)
        control = self.connect(self.control)
        client = self.connect(unix)
        client.sendall(b'hello')
        self.assertEqual(control.recv(2), b'C\x05')
        self.assertEqual(control.recv(5), b'hello')
        control.close()
        control = self.connect(self.control)
        with socket.create_connection(('127.0.0.1', port), timeout=5) as tcp:
            tcp.sendall(b'SELECT')
            self.assertEqual(control.recv(2), b'C\x07')
            self.assertEqual(control.recv(6), b'SELECT')

    def test_reload_adds_new_entries_and_refuses_changed_ones(self):
        self.write_table([{'index': 0, 'name': 'a', 'unix': 'a'}])
        self.assertEqual(self.reload(), b'1')
        self.write_table([{'index': 0, 'name': 'a', 'unix': 'a'}, {'index': 1, 'name': 'b', 'unix': 'b'}])
        self.assertEqual(self.reload(), b'1')
        self.assertTrue(Path(self.tmp.name + '/b.sock').exists())
        self.write_table([{'index': 0, 'name': 'a', 'unix': 'c'}])
        self.assertEqual(self.reload(), b'0')
        self.assertFalse(Path(self.tmp.name + '/c.sock').exists())

    def test_reload_refuses_reserved_and_invalid_listeners(self):
        for entry in ({'tcp': 3128, 'address': '127.0.0.1'}, {'tcp': self.port, 'address': '127.0.0.1'},
                      {'tcp': 1023, 'address': '127.0.0.1'}, {'tcp': 80, 'address': '127.0.0.1'},
                      {'tcp': 5432, 'address': '10.0.0.1'}, {'tcp': 5432, 'address': '0.0.0.0'},
                      {'tcp': 5432}, {'tcp': '5432', 'address': '127.0.0.1'},
                      {'unix': 'actions'}, {'unix': 'reload'}, {'unix': '../escape'}, {'unix': 'Upper'}):
            with self.subTest(entry=entry):
                self.write_table([dict(entry, index=0, name='x')])
                self.assertEqual(self.reload(), b'0')
        self.assertEqual(sorted(p.name for p in Path(self.tmp.name).glob('*.sock')), ['actions.sock', 'reload.sock'])

    def test_channel_companion_kind(self):
        self.write_table([{'index': 200, 'name': 'svc', 'unix': 'svc'}])
        self.assertEqual(self.reload(), b'1')
        channel = self.spawn_channel()
        client = self.connect(self.tmp.name + '/svc.sock')
        self.assertEqual(channel.stdout.read(2), b'C\xc8')
        client.sendall(b'ping')
        client.shutdown(socket.SHUT_WR)
        self.assertEqual(read_frames(channel.stdout), b'ping')
        channel.stdin.write(encode(b'D', b'pong') + encode(b'F'))
        channel.stdin.flush()
        self.assertEqual(receive_all(client), b'pong')
        channel.wait(timeout=3)
        self.assertEqual(channel.returncode, 0)


class ConfigureReloadTests(unittest.TestCase):
    """configure writes the table and links as root; the gateway binds them on reload."""

    def test_configure_reload_handshake_binds_linked_socket(self):
        spec = importlib.util.spec_from_file_location('configure', RUNTIME / 'configure.py')
        configure = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(configure)
        tmp = tempfile.TemporaryDirectory(dir='/tmp')
        self.addCleanup(tmp.cleanup)
        run = Path(tmp.name)
        (run / 'gateway').mkdir()
        process = subprocess.Popen([sys.executable, str(RUNTIME / 'gateway.py'),
            '--control', str(run / 'bridge/control.sock'), '--actions', str(run / 'gateway/actions.sock'),
            '--endpoints', str(run / 'endpoints.json'), '--port', '0'])
        self.addCleanup(process.wait, timeout=5)
        self.addCleanup(process.terminate)
        deadline = time.monotonic() + 5
        while not (run / 'gateway/gateway.ready').exists():
            self.assertTrue(process.poll() is None and time.monotonic() < deadline, 'gateway failed startup')
            time.sleep(.01)
        _, _, _, endpoints = configure.validate_config(
            {'endpoints': [{'index': 3, 'name': 'svc', 'listen': {'unix': 'svc'}}]}, run=run)
        configure.write_endpoints(endpoints, run=run)
        configure.reload_gateway(run / 'gateway/reload.sock', timeout=5)
        with socket.socket(socket.AF_UNIX) as control, socket.socket(socket.AF_UNIX) as client:
            control.settimeout(5)
            control.connect(str(run / 'bridge/control.sock'))
            client.connect(str(run / 'svc.sock'))  # through the root-written link
            self.assertEqual(control.recv(2), b'C\x03')


class ChannelHeaderTests(unittest.TestCase):
    def relay_header(self, header):
        spec = importlib.util.spec_from_file_location('channel', RUNTIME / 'channel.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module.header_complete(bytearray(header))

    def test_header_kinds(self):
        self.assertTrue(self.relay_header(b'P'))
        self.assertTrue(self.relay_header(b'A'))
        self.assertFalse(self.relay_header(b'C'))
        self.assertTrue(self.relay_header(b'C\x00'))
        self.assertTrue(self.relay_header(b'C\xff'))
        for header in (b'X', b'D', b'F', b'c'):
            with self.subTest(header=header), self.assertRaises(ValueError):
                self.relay_header(header)


class SlotLabelTests(unittest.TestCase):
    def test_label_advertises_gateway_slots(self):
        dockerfile = (RUNTIME.parent / 'Dockerfile').read_text()
        self.assertEqual(int(re.search(r'^ARG HATCHWARD_SLOTS=(\d+)$', dockerfile, re.M).group(1)),
                         load_gateway().SLOTS)
        self.assertIn('org.hatchward.agent.slots="${HATCHWARD_SLOTS}"', dockerfile)
        self.assertIn('org.hatchward.agent.features="declared-env,endpoints,ssh-client"', dockerfile)


if __name__ == '__main__':
    unittest.main()
