"""ssh ProxyCommand: open an HTTP CONNECT tunnel through $HTTPS_PROXY and relay stdio over it.

Usage: hatchward-connect HOST PORT. Runs as the agent, with no privilege.
"""
import base64
import os
import re
import select
import socket
import sys
from urllib.parse import unquote, urlsplit

LIMIT = 65536
RESPONSE_LIMIT = 16384
HOST = re.compile(r'[A-Za-z0-9.-]{1,253}|\[[0-9A-Fa-f:.]{2,45}\]|[0-9A-Fa-f:.]{2,45}')
STATUS = re.compile(rb'HTTP/1\.[01] 2[0-9][0-9][ \r]')


def proxy_from_env(environ):
    for key in ('HTTPS_PROXY', 'https_proxy', 'HTTP_PROXY', 'http_proxy'):
        if environ.get(key):
            return environ[key]
    raise ValueError('HTTPS_PROXY is not set')


def connect_request(host, port, proxy):
    """Return (proxy address, CONNECT request bytes) for host:port through the proxy URL."""
    if not HOST.fullmatch(host) or not port.isdigit() or not 1 <= int(port) <= 65535:
        raise ValueError('invalid destination')
    parsed = urlsplit(proxy)
    if parsed.scheme != 'http' or not parsed.hostname:
        raise ValueError('proxy must be an http:// URL')
    if ':' in host and not host.startswith('['):
        host = f'[{host}]'
    authority = f'{host}:{int(port)}'
    lines = [f'CONNECT {authority} HTTP/1.1', f'Host: {authority}']
    if parsed.username is not None:
        credentials = f'{unquote(parsed.username)}:{unquote(parsed.password or "")}'
        lines.append('Proxy-Authorization: Basic ' + base64.b64encode(credentials.encode()).decode())
    return (parsed.hostname, parsed.port or 80), ('\r\n'.join(lines) + '\r\n\r\n').encode()


def handshake(sock, request):
    """Send CONNECT; return any tunnel bytes that arrived with the response headers."""
    sock.sendall(request)
    response = bytearray()
    while b'\r\n\r\n' not in response:
        chunk = sock.recv(4096)
        if not chunk or len(response) + len(chunk) > RESPONSE_LIMIT:
            raise ConnectionError('proxy closed or sent an oversized response')
        response.extend(chunk)
    head, _, rest = bytes(response).partition(b'\r\n\r\n')
    if not STATUS.match(head + b'\r'):
        raise ConnectionError('proxy refused: ' + head.split(b'\r\n', 1)[0].decode(errors='replace')[:200])
    return rest


def relay(sock, stdin=0, stdout=1):
    """Copy stdin to the tunnel and the tunnel to stdout, propagating half-close."""
    reading_stdin = reading_sock = True
    while reading_sock:
        readable, _, _ = select.select([sock] + ([stdin] if reading_stdin else []), [], [])
        if stdin in readable:
            data = os.read(stdin, LIMIT)
            if data:
                sock.sendall(data)
            else:
                reading_stdin = False
                sock.shutdown(socket.SHUT_WR)
        if sock in readable:
            data = sock.recv(LIMIT)
            if data:
                write_all(stdout, data)
            else:
                reading_sock = False


def write_all(fd, data):
    view = memoryview(data)
    while view:
        view = view[os.write(fd, view):]


def main(argv=None, environ=None):
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 2:
        sys.exit('usage: hatchward-connect HOST PORT')
    try:
        address, request = connect_request(argv[0], argv[1], proxy_from_env(os.environ if environ is None else environ))
        with socket.create_connection(address, timeout=30) as sock:
            rest = handshake(sock, request)
            sock.settimeout(None)
            if rest:
                write_all(1, rest)
            relay(sock)
    except (OSError, ValueError) as error:
        sys.exit(f'hatchward-connect: {error}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
