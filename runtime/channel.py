#!/usr/bin/env python3
"""Bounded framed host stdio channel to the private raw gateway socket.

The gateway first sends a header: P (proxy), A (actions), or C plus one endpoint
index byte (companion). It is copied to stdout before any frame.

Docker exec does not expose a subprocess stdout half-close until process exit.
Explicit D(length,payload)/F(0) frames therefore carry directional EOF. Actual
stdin EOF cancels the channel, including before assignment.
"""
import argparse
import os
import select
import socket
import struct

LIMIT = 65536
HEADER = 5
KINDS = (b'P', b'A', b'C')


def header_complete(header):
    """True once the channel header is whole; raise on an unknown kind."""
    if header[:1] not in KINDS:
        raise ValueError('unknown channel kind')
    return len(header) == (2 if header[:1] == b'C' else 1)


def frame(kind, payload=b''):
    return kind + struct.pack('!I', len(payload)) + payload


def relay(sock):
    sock.setblocking(False)
    os.set_blocking(0, False)
    os.set_blocking(1, False)
    encoded = bytearray()
    outgoing = bytearray()
    incoming = bytearray()
    header = bytearray()
    started = input_finished = peer_finished = write_closed = False
    while True:
        # Consume at most one bounded payload while the previous drains.
        if not outgoing and len(encoded) >= HEADER:
            kind = encoded[:1]
            length = struct.unpack('!I', encoded[1:HEADER])[0]
            if input_finished or kind not in (b'D', b'F') or length > LIMIT:
                return 1
            if (kind == b'F' and length != 0) or (kind == b'D' and length == 0):
                return 1
            if len(encoded) >= HEADER + length:
                del encoded[:HEADER]
                if kind == b'F':
                    input_finished = True
                else:
                    outgoing.extend(encoded[:length])
                    del encoded[:length]
                # Validate any following frame before successfully exiting.
                continue
        if input_finished and encoded:
            return 1
        if started and input_finished and not outgoing and not write_closed:
            sock.shutdown(socket.SHUT_WR)
            write_closed = True
        if peer_finished and input_finished and not outgoing and not incoming:
            return 0
        reads, writes = [], []
        capacity = LIMIT + HEADER - len(encoded) - len(outgoing)
        if capacity > 0:
            reads.append(0)
        if not peer_finished and not incoming:
            reads.append(sock)
        if outgoing and started:
            writes.append(sock)
        if incoming:
            writes.append(1)
        readable, writable, _ = select.select(reads, writes, [], None)
        # Real pipe EOF is cancellation, independently of protocol EOF.
        if 0 in readable:
            data = os.read(0, capacity)
            if not data:
                return 0
            encoded.extend(data)
        if sock in readable:
            data = sock.recv(LIMIT if started else 1)
            if not started:
                if not data:
                    return 1
                header.extend(data)
                try:
                    started = header_complete(header)
                except ValueError:
                    return 1
                if started:
                    incoming.extend(header)
            elif data:
                incoming.extend(frame(b'D', data))
            else:
                peer_finished = True
                incoming.extend(frame(b'F'))
        if sock in writable:
            count = sock.send(outgoing)
            del outgoing[:count]
        if 1 in writable:
            count = os.write(1, incoming)
            del incoming[:count]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--control', default='/run/hatchward/bridge/control.sock')
    args = parser.parse_args()
    try:
        with socket.socket(socket.AF_UNIX) as sock:
            sock.connect(args.control)
            return relay(sock)
    except (BrokenPipeError, ConnectionResetError):
        return 0
    except OSError:
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
