"""Accept public trust material, sentinels, a routed repository and companion endpoints, never credentials."""
import base64
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import ssl
import struct
import subprocess
import sys
from urllib.parse import quote, urlsplit

RUN = Path('/run/hatchward')
SENTINEL = 'hatchward-proxy-managed'
# Per-secret sentinel: derived from the secret's name, not the env name it is bound to (spec §5.3).
DECLARED_SENTINEL = re.compile(r'hatchward-secret-[a-z][a-z0-9_]{1,63}')
ALLOWED = {'GH_TOKEN', 'GITHUB_TOKEN', 'ANTHROPIC_API_KEY', 'CLAUDE_CODE_OAUTH_TOKEN'}
# Real (non-sentinel) values naming the repository hatchward-run clones.
REPOSITORY_KEYS = {'AGENT_REPO', 'AGENT_BASE_BRANCH'}
REPOSITORY = re.compile(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+')
# Declared-secret and endpoint env names (runner secrets spec §5.3, §6.6).
ENV_NAME = re.compile(r'[A-Z][A-Z0-9_]{0,63}')
RESERVED_NAMES = {'PATH', 'HOME', 'USER', 'SHELL', 'NODE_OPTIONS', 'BASH_ENV', 'ENV',
                  'HTTP_PROXY', 'HTTPS_PROXY', 'NO_PROXY', 'ALL_PROXY'}
RESERVED_PREFIXES = ('LD_', 'GIT_', 'AGENT_', 'HATCHWARD_', 'ANTHROPIC_', 'CLAUDE_', 'GH_', 'GITHUB_', 'SSH_')
# Endpoint and socket names. The gateway directory already holds these sockets.
SOCKET_NAME = re.compile(r'[a-z][a-z0-9-]{0,31}')
RESERVED_SOCKETS = {'actions', 'reload', 'control'}
HOSTNAME = re.compile(r'(?=.{1,253}\Z)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*')
HOST_KEY = re.compile(r'(ssh-ed25519|ecdsa-sha2-nistp(?:256|384|521)|ssh-rsa|sk-ssh-ed25519@openssh\.com'
                      r'|sk-ecdsa-sha2-nistp256@openssh\.com) ([A-Za-z0-9+/]+={0,2})')
PROXY_PORT = 3128
LIMITS = {'declaredEnv': 16, 'endpoints': 32, 'sshHosts': 4, 'hostKeys': 8, 'env': 8}
RELOAD_TIMEOUT = 5


def valid_branch(name):
    if not isinstance(name, str) or not name or name.startswith('-'):
        return False
    result = subprocess.run(['git', 'check-ref-format', '--branch', name], cwd='/',
                            env={'PATH': os.environ.get('PATH', '/usr/bin:/bin')},
                            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return result.returncode == 0


def validate_env(env):
    credentials = {k: v for k, v in env.items() if k not in REPOSITORY_KEYS}
    if set(credentials) - ALLOWED or any(v != SENTINEL for v in credentials.values()):
        raise ValueError('only literal proxy sentinels are accepted')
    repo = env.get('AGENT_REPO')
    if 'AGENT_REPO' in env and not (isinstance(repo, str) and REPOSITORY.fullmatch(repo)):
        raise ValueError('AGENT_REPO must be owner/name')
    if 'AGENT_BASE_BRANCH' in env and ('AGENT_REPO' not in env or not valid_branch(env['AGENT_BASE_BRANCH'])):
        raise ValueError('AGENT_BASE_BRANCH must be a valid branch of AGENT_REPO')


def valid_env_name(name):
    return (isinstance(name, str) and bool(ENV_NAME.fullmatch(name))
            and name not in RESERVED_NAMES and not name.startswith(RESERVED_PREFIXES))


def bounded_list(value, key):
    if not isinstance(value, list) or len(value) > LIMITS[key]:
        raise ValueError(f'{key} must be a list of at most {LIMITS[key]} entries')
    return value


def exact_keys(value, required, optional=()):
    if not isinstance(value, dict) or not set(required) <= set(value) <= set(required) | set(optional):
        raise ValueError('unsupported entry')


def validate_declared_env(entries):
    """Each declared secret's env name carries only that secret's sentinel, one env per secret."""
    result = {}
    for entry in bounded_list(entries, 'declaredEnv'):
        exact_keys(entry, ('name', 'sentinel'))
        name, sentinel = entry['name'], entry['sentinel']
        if not valid_env_name(name) or name in result:
            raise ValueError('declared env name is reserved, invalid or duplicated')
        if not isinstance(sentinel, str) or not DECLARED_SENTINEL.fullmatch(sentinel) or sentinel in result.values():
            raise ValueError('declared env value must be a unique per-secret sentinel')
        result[name] = sentinel
    return result


def socket_path(run, name):
    return str(run / f'{name}.sock')


def validate_listen(listen):
    """Return the normalised listener: {'unix': name} or {'tcp': port, 'address': address}."""
    if isinstance(listen, dict) and set(listen) == {'unix'}:
        name = listen['unix']
        if not isinstance(name, str) or not SOCKET_NAME.fullmatch(name) or name in RESERVED_SOCKETS:
            raise ValueError('invalid socket name')
        return {'unix': name}
    exact_keys(listen, ('tcp',), ('address',))
    port, address = listen['tcp'], listen.get('address', '127.0.0.1')
    if type(port) is not int or not 1024 <= port <= 65535 or not isinstance(address, str):
        raise ValueError('endpoint port must be 1024-65535')
    try:
        parsed = ipaddress.IPv4Address(address)
    except ValueError:
        raise ValueError('endpoint address must be IPv4 loopback') from None
    if parsed not in ipaddress.IPv4Network('127.0.0.0/8') or str(parsed) != address:
        raise ValueError('endpoint address must be in 127.0.0.0/8')
    if (address, port) == ('127.0.0.1', PROXY_PORT):
        raise ValueError('endpoint must not take the proxy listener')
    return {'tcp': port, 'address': address}


def endpoint_values(listen, run):
    """The only values the runner can have generated for this endpoint's env tokens."""
    if 'unix' in listen:
        path = socket_path(run, listen['unix'])
        return {path, quote(path, safe='')}  # socket, url-host
    return {listen['address'], str(listen['tcp'])}  # address (also url-host), port


def validate_host_key(line):
    match = HOST_KEY.fullmatch(line) if isinstance(line, str) else None
    if not match:
        raise ValueError('invalid host key')
    blob = base64.b64decode(match.group(2), validate=True)
    length = struct.unpack('!I', blob[:4])[0] if len(blob) >= 4 else 0
    if blob[4:4 + length] != match.group(1).encode():
        raise ValueError('host key type does not match its blob')
    return line


def validate_ssh_hosts(entries):
    result = []
    for entry in bounded_list(entries, 'sshHosts'):
        exact_keys(entry, ('host', 'port', 'hostKeys'))
        host, port = entry['host'], entry['port']
        if not isinstance(host, str) or not HOSTNAME.fullmatch(host):
            raise ValueError('invalid SSH host')
        if type(port) is not int or not 1 <= port <= 65535:
            raise ValueError('invalid SSH port')
        keys = bounded_list(entry['hostKeys'], 'hostKeys')
        if not keys:
            raise ValueError('SSH host requires pinned host keys')
        result.append({'host': host, 'port': port, 'hostKeys': [validate_host_key(k) for k in keys]})
    return result


def validate_endpoints(entries, run=RUN):
    endpoints, indexes, names, listeners, env = [], set(), set(), set(), {}
    for entry in bounded_list(entries, 'endpoints'):
        exact_keys(entry, ('index', 'name', 'listen'), ('env', 'sshHosts'))
        index, name = entry['index'], entry['name']
        if type(index) is not int or not 0 <= index <= 255 or index in indexes:
            raise ValueError('endpoint index must be a unique byte')
        if not isinstance(name, str) or not SOCKET_NAME.fullmatch(name) or name in names:
            raise ValueError('endpoint name is invalid or duplicated')
        listen = validate_listen(entry['listen'])
        key = listen.get('unix') or (listen['address'], listen['tcp'])
        if key in listeners:
            raise ValueError('endpoints must not share a listener')
        listeners.add(key)
        indexes.add(index)
        names.add(name)
        values = endpoint_values(listen, run)
        endpoint_env = entry.get('env', {})
        if not isinstance(endpoint_env, dict) or len(endpoint_env) > LIMITS['env']:
            raise ValueError('invalid endpoint env')
        for variable, value in endpoint_env.items():
            # The built-in ssh-agent broker points SSH_AUTH_SOCK at its own socket (spec §6.5).
            agent_socket = (variable == 'SSH_AUTH_SOCK' and 'unix' in listen
                            and value == socket_path(run, listen['unix']))
            if not (agent_socket or valid_env_name(variable)) or variable in env:
                raise ValueError('endpoint env name is reserved, invalid or duplicated')
            if not isinstance(value, str) or value not in values:
                raise ValueError('endpoint env value must be generated from its own listener')
            env[variable] = value
        result = {'index': index, 'name': name, 'listen': listen}
        if 'sshHosts' in entry:
            result['sshHosts'] = validate_ssh_hosts(entry['sshHosts'])
        endpoints.append(result)
    return endpoints, env


def validate_config(value, run=RUN):
    """Return (ca, proxyUrl, workload env, endpoints)."""
    if not isinstance(value, dict) or set(value) - {'ca', 'proxyUrl', 'env', 'declaredEnv', 'endpoints'}:
        raise ValueError('unsupported configuration')
    ca, proxy, env = value.get('ca', ''), value.get('proxyUrl', ''), value.get('env', {})
    if not isinstance(ca, str) or not isinstance(proxy, str) or not isinstance(env, dict):
        raise ValueError('invalid configuration types')
    validate_env(env)
    declared = validate_declared_env(value.get('declaredEnv', []))
    endpoints, endpoint_env = validate_endpoints(value.get('endpoints', []), run)
    if set(env) & set(declared) or set(env) & set(endpoint_env) or set(declared) & set(endpoint_env):
        raise ValueError('env names must be unique')
    ssh = any(endpoint.get('sshHosts') for endpoint in endpoints)
    if bool(ca) != bool(proxy) or ((env or declared or ssh) and not proxy):
        raise ValueError('proxy and public CA must be configured together')
    if proxy:
        parsed = urlsplit(proxy)
        if (parsed.scheme != 'http' or parsed.hostname != '127.0.0.1' or parsed.port != PROXY_PORT
                or not parsed.username or parsed.path or parsed.query or parsed.fragment):
            raise ValueError('proxy must address the isolated loopback gateway')
        ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT).load_verify_locations(cadata=ca)
    return ca, proxy, {**env, **declared, **endpoint_env}, endpoints


def ssh_files(endpoints, run=RUN):
    """ssh_config and known_hosts for the pinned SSH remotes, or None without any."""
    known, blocks, ports = [], {}, {}
    for endpoint in endpoints:
        for entry in endpoint.get('sshHosts', []):
            host, port = entry['host'], entry['port']
            ports.setdefault(host, set()).add(port)
            pattern = host if port == 22 else f'[{host}]:{port}'
            known.extend(f'{pattern} {key}' for key in entry['hostKeys'])
            lines = blocks.setdefault(host, [
                f'Host {host}', f'  HostName {host}',
                '  ProxyCommand /usr/local/bin/hatchward-connect %h %p',
                f'  UserKnownHostsFile {run}/known_hosts', '  GlobalKnownHostsFile /dev/null',
                '  StrictHostKeyChecking yes', '  UpdateHostKeys no'])
            if 'unix' in endpoint['listen'] and not any('IdentityAgent' in line for line in lines):
                lines.append(f'  IdentityAgent {socket_path(run, endpoint["listen"]["unix"])}')
    if not blocks:
        return None
    for host, lines in blocks.items():
        if len(ports[host]) == 1:  # One pinned port is the default; several need `-p`.
            lines.insert(2, f'  Port {next(iter(ports[host]))}')
    return '\n\n'.join('\n'.join(lines) for lines in blocks.values()) + '\n', '\n'.join(known) + '\n'


def write_readonly(path, text):
    path.write_text(text)
    path.chmod(0o444)


def write_endpoints(endpoints, run=RUN):
    """Root-written endpoint table, agent-visible socket links and SSH configuration."""
    write_readonly(run / 'endpoints.json', json.dumps({'endpoints': [
        {'index': e['index'], 'name': e['name'], **e['listen']} for e in endpoints]}))
    for endpoint in endpoints:
        if 'unix' in endpoint['listen']:
            name = endpoint['listen']['unix']
            os.symlink(run / 'gateway' / f'{name}.sock', run / f'{name}.sock')
    files = ssh_files(endpoints, run)
    if files:
        write_readonly(run / 'ssh_config', files[0])
        write_readonly(run / 'known_hosts', files[1])


def reload_gateway(path, timeout=RELOAD_TIMEOUT):
    """Ask the gateway to bind the endpoint listeners; only an explicit `1` is success."""
    with socket.socket(socket.AF_UNIX) as sock:
        sock.settimeout(timeout)
        sock.connect(str(path))
        if sock.recv(1) != b'1':
            raise ValueError('gateway did not bind the endpoints')


def main():
    os.umask(0o077)
    if not (RUN / 'ready').is_file():
        raise ValueError('runtime not ready')
    data = sys.stdin.buffer.read(1024 * 1024 + 1)
    if len(data) > 1024 * 1024:
        raise ValueError('configuration exceeds limit')
    ca, proxy, env, endpoints = validate_config(json.loads(data), RUN)
    if proxy:
        bundle = Path('/etc/ssl/certs/ca-certificates.crt').read_text() + '\n' + ca
        (RUN / 'ca.pem').write_text(bundle)
        (RUN / 'ca.pem').chmod(0o444)
        (RUN / 'proxy-mode').touch(mode=0o444)
    if endpoints:
        write_endpoints(endpoints, RUN)
        reload_gateway(RUN / 'gateway/reload.sock')
    # Last, so a failed reload leaves no configuration for hatchward-run to start from.
    (RUN / 'config.json').write_text(json.dumps({'proxyUrl': proxy, 'env': env}))
    (RUN / 'config.json').chmod(0o444)


if __name__ == '__main__':
    try:
        main()
    except Exception:
        sys.exit('hatchward-configure: invalid or unavailable runtime configuration')
