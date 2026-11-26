#!/usr/bin/env python3
"""Bounded, single-threaded assignment transport; never interprets request bytes."""
import argparse
from collections import deque
import ipaddress
import json
import os
from pathlib import Path
import re
import select
import signal
import socket
import time

LIMIT = 65536
# Host helper slots. The image advertises this number as org.hatchward.agent.slots,
# and the runner never keeps more helpers than that label (runner secrets spec §6.2).
SLOTS = 48
PENDING = 32
SOCKET_NAME = re.compile(r'[a-z][a-z0-9-]{0,31}')
RESERVED_SOCKETS = {'actions', 'reload', 'control'}
LOOPBACK = ipaddress.IPv4Network('127.0.0.0/8')


class Pair:
    def __init__(self, client, control, kind):
        self.sockets = [client, control]
        self.output = [bytearray(), bytearray(kind)]
        self.eof = [False, False]
        self.closed_write = [False, False]

    def close(self):
        for sock in self.sockets:
            sock.close()

    def interests(self, reads, writes):
        for i, sock in enumerate(self.sockets):
            if not self.eof[i] and len(self.output[1-i]) < LIMIT:
                reads.append(sock)
            if self.output[i]:
                writes.append(sock)

    def pump(self, readable, writable):
        try:
            for i, sock in enumerate(self.sockets):
                if sock in writable and self.output[i]:
                    count = sock.send(self.output[i])
                    del self.output[i][:count]
                if sock in readable and not self.eof[i]:
                    chunk = sock.recv(LIMIT - len(self.output[1-i]))
                    if chunk:
                        self.output[1-i].extend(chunk)
                    else:
                        self.eof[i] = True
            for i, sock in enumerate(self.sockets):
                if self.eof[1-i] and not self.output[i] and not self.closed_write[i]:
                    sock.shutdown(socket.SHUT_WR)
                    self.closed_write[i] = True
            return not (all(self.eof) and not any(self.output))
        except BlockingIOError:
            return True
        except OSError:
            return False


def endpoint_listeners(path, proxy_port):
    """Parse the root-written endpoint table into {index: (family, address)}; raise if invalid."""
    entries = json.loads(Path(path).read_text())['endpoints']
    if not isinstance(entries, list) or len(entries) > 255:
        raise ValueError('invalid endpoint table')
    result, seen = {}, set()
    for entry in entries:
        index = entry['index']
        if type(index) is not int or not 0 <= index <= 255 or index in result:
            raise ValueError('invalid endpoint index')
        if set(entry) == {'index', 'name', 'unix'}:
            name = entry['unix']
            if not isinstance(name, str) or not SOCKET_NAME.fullmatch(name) or name in RESERVED_SOCKETS:
                raise ValueError('invalid socket name')
            listener = (socket.AF_UNIX, name)
        elif set(entry) == {'index', 'name', 'tcp', 'address'}:
            port, address = entry['tcp'], entry['address']
            if (type(port) is not int or not 1024 <= port <= 65535 or not isinstance(address, str)
                    or str(ipaddress.IPv4Address(address)) != address
                    or ipaddress.IPv4Address(address) not in LOOPBACK
                    or (address == '127.0.0.1' and port in (3128, proxy_port))):
                raise ValueError('invalid TCP endpoint')
            listener = (socket.AF_INET, (address, port))
        else:
            raise ValueError('invalid endpoint')
        if listener in seen:
            raise ValueError('duplicate listener')
        seen.add(listener)
        result[index] = listener
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--control', default='/run/hatchward/bridge/control.sock')
    parser.add_argument('--actions', default='/run/hatchward/gateway/actions.sock')
    parser.add_argument('--endpoints', default='/run/hatchward/endpoints.json')
    parser.add_argument('--port', type=int, default=3128)
    parser.add_argument('--pending-seconds', type=float, default=15)
    args = parser.parse_args()
    bridge = Path(args.control).parent
    public = Path(args.actions).parent
    reload_path = public / 'reload.sock'
    bridge.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(bridge, 0o700)
    ready = public / 'gateway.ready'
    channels_ready = bridge / 'channels.ready'
    channels_present = False
    # Each listener's role: 'control', 'reload', or the channel header it opens.
    listeners = {}
    endpoints = {}
    unix_paths = []
    idle = deque()
    pending = deque()
    pairs = []
    running = True

    def stop(*_):
        nonlocal running
        running = False

    def listen(family, address, role, mode=None):
        sock = socket.socket(family)
        try:
            if family == socket.AF_INET:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(address)
            if mode is not None:
                unix_paths.append(Path(address))
                os.chmod(address, mode)
            sock.listen(32)
            sock.setblocking(False)
        except BaseException:
            sock.close()
            raise
        listeners[sock] = role
        return sock

    def reload():
        """Bind every endpoint the root-owned table names and is not yet bound. Idempotent."""
        try:
            table = endpoint_listeners(args.endpoints, proxy_port)
            for index, (family, address) in table.items():
                if index in endpoints:
                    if endpoints[index] != (family, address):
                        return b'0'
                    continue
                if family == socket.AF_UNIX:
                    listen(family, str(public / f'{address}.sock'), b'C' + bytes([index]), 0o666)
                else:
                    listen(family, address, b'C' + bytes([index]))
                endpoints[index] = (family, address)
            return b'1'
        except (OSError, ValueError, KeyError, TypeError, AttributeError):
            return b'0'

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        listen(socket.AF_UNIX, args.control, 'control', 0o600)
        listen(socket.AF_UNIX, args.actions, b'A', 0o666)
        listen(socket.AF_UNIX, str(reload_path), 'reload', 0o666)
        proxy = listen(socket.AF_INET, ('127.0.0.1', args.port), b'P')
        proxy_port = proxy.getsockname()[1]
        ready.write_text(str(proxy_port))
        while running:
            reads, writes = list(listeners) + list(idle), []
            for pair in pairs:
                pair.interests(reads, writes)
            readable, writable, _ = select.select(reads, writes, [], .1)
            # An idle host channel carries no bytes until assigned. EOF is cancellation.
            for sock in list(idle):
                if sock in readable:
                    idle.remove(sock)
                    sock.close()
            for listener, role in list(listeners.items()):
                if listener not in readable:
                    continue
                try:
                    sock, _ = listener.accept()
                except BlockingIOError:
                    continue
                sock.setblocking(False)
                if role == 'control':
                    if len(idle) + len(pairs) >= SLOTS:
                        sock.close()
                    else:
                        idle.append(sock)
                elif role == 'reload':
                    try:
                        sock.send(reload())
                    except OSError:
                        pass
                    sock.close()
                elif len(pending) >= PENDING:
                    sock.close()
                else:
                    pending.append((sock, role, time.monotonic() + args.pending_seconds))
            now = time.monotonic()
            while pending and pending[0][2] <= now:
                pending.popleft()[0].close()
            for pair in list(pairs):
                if not pair.pump(readable, writable):
                    pairs.remove(pair)
                    pair.close()
            while idle and pending:
                client, kind, _ = pending.popleft()
                pairs.append(Pair(client, idle.popleft(), kind))
            present = bool(idle or pairs)
            if present != channels_present:
                if present:
                    channels_ready.touch(mode=0o600)
                else:
                    channels_ready.unlink(missing_ok=True)
                channels_present = present
    finally:
        for pair in pairs:
            pair.close()
        for sock in list(idle) + [entry[0] for entry in pending] + list(listeners):
            sock.close()
        for path in [ready, channels_ready] + unix_paths:
            path.unlink(missing_ok=True)


if __name__ == '__main__':
    main()
