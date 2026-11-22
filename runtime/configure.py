"""Accept public trust material, literal proxy sentinels and a routed repository, never credentials."""
import json
import os
from pathlib import Path
import re
import ssl
import subprocess
import sys
from urllib.parse import urlsplit

RUN = Path('/run/hatchward')
SENTINEL = 'hatchward-proxy-managed'
ALLOWED = {'GH_TOKEN', 'GITHUB_TOKEN', 'ANTHROPIC_API_KEY', 'CLAUDE_CODE_OAUTH_TOKEN'}
# Real (non-sentinel) values naming the repository hatchward-run clones.
REPOSITORY_KEYS = {'AGENT_REPO', 'AGENT_BASE_BRANCH'}
REPOSITORY = re.compile(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+')


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


def validate_config(value):
    if not isinstance(value, dict) or set(value) - {'ca', 'proxyUrl', 'env'}:
        raise ValueError('unsupported configuration')
    ca, proxy, env = value.get('ca', ''), value.get('proxyUrl', ''), value.get('env', {})
    if not isinstance(ca, str) or not isinstance(proxy, str) or not isinstance(env, dict):
        raise ValueError('invalid configuration types')
    validate_env(env)
    if bool(ca) != bool(proxy) or (env and not proxy):
        raise ValueError('proxy and public CA must be configured together')
    if proxy:
        parsed = urlsplit(proxy)
        if (parsed.scheme != 'http' or parsed.hostname != '127.0.0.1' or parsed.port != 3128
                or not parsed.username or parsed.path or parsed.query or parsed.fragment):
            raise ValueError('proxy must address the isolated loopback gateway')
        ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT).load_verify_locations(cadata=ca)
    return ca, proxy, env


def main():
    os.umask(0o077)
    if not (RUN / 'ready').is_file():
        raise ValueError('runtime not ready')
    data = sys.stdin.buffer.read(1024 * 1024 + 1)
    if len(data) > 1024 * 1024:
        raise ValueError('configuration exceeds limit')
    ca, proxy, env = validate_config(json.loads(data))
    if proxy:
        bundle = Path('/etc/ssl/certs/ca-certificates.crt').read_text() + '\n' + ca
        (RUN / 'ca.pem').write_text(bundle)
        (RUN / 'ca.pem').chmod(0o444)
        (RUN / 'proxy-mode').touch(mode=0o444)
    (RUN / 'config.json').write_text(json.dumps({'proxyUrl': proxy, 'env': env}))
    (RUN / 'config.json').chmod(0o444)


if __name__ == '__main__':
    try:
        main()
    except Exception:
        sys.exit('hatchward-configure: invalid or unavailable runtime configuration')
