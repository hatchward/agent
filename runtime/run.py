"""Unprivileged workload launch. All mutable files reside on the bounded volume."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from urllib.parse import urlsplit

RUN = Path('/run/hatchward')
WORKSPACE = '/workspace'


class CloneError(Exception):
    """A clone failure, already reduced to one credential-free line."""


def clone_failure(repo, stderr, returncode, proxy):
    lines = [line.strip() for line in stderr.decode(errors='replace').splitlines() if line.strip()]
    errors = [line.split(':', 1)[1].strip() for line in lines if line.startswith(('fatal:', 'error:'))]
    # git's first fatal/error line names the cause; later ones are generic advice.
    cause = errors[0] if errors else (lines or [f'git exited with status {returncode}'])[-1]
    # The proxy URL carries the gateway token; strip it and any URL userinfo.
    password = urlsplit(proxy).password if proxy else None
    for secret in filter(None, (proxy, password)):
        cause = cause.replace(secret, '[redacted]')
    cause = re.sub(r'(://)[^/@\s]+@', r'\1[redacted]@', cause)
    return CloneError(f'clone of {repo} failed: {cause[:400]}')


def clone_repository(config, env):
    """Clone the routed repository into the empty workspace, as the standard entrypoint does."""
    repo = config['env'].get('AGENT_REPO')
    if not repo:
        return
    branch = config['env'].get('AGENT_BASE_BRANCH')
    env = dict(env, GIT_TERMINAL_PROMPT='0')
    clone = ['git', 'clone', '-q', *(['--branch', branch] if branch else []), '--',
             f'https://github.com/{repo}.git', WORKSPACE]
    submodules = ['git', '-C', WORKSPACE, 'submodule', '-q', 'update', '--init', '--recursive']
    for command in (clone, submodules):
        result = subprocess.run(command, env=env, stdin=subprocess.DEVNULL, capture_output=True)
        if result.returncode:
            raise clone_failure(repo, result.stderr, result.returncode, config['proxyUrl'])


def main():
    if len(sys.argv) < 2:
        raise ValueError('image command is missing')
    config = json.loads((RUN / 'config.json').read_text())
    manifest = sys.stdin.buffer.read(16 * 1024 * 1024 + 1)
    if len(manifest) > 16 * 1024 * 1024:
        raise ValueError('manifest exceeds 16 MiB')
    json.loads(manifest)
    path = RUN / 'workload/manifest.json'
    with path.open('xb') as output:
        output.write(manifest)
    path.chmod(0o600)
    env = os.environ.copy()
    env.update(PATH='/home/agent/.local/share/mise/shims:/home/agent/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin', HOME='/home/agent', AGENT_RUN_DIR=str(RUN), AGENT_WORKSPACE='/workspace',
               CLAUDE_PROJECT_DIR='/workspace', HATCHWARD_ASSIGNMENT_ACTION_SOCKET=str(RUN / 'actions.sock'))
    env.update(config['env'])
    proxy = config['proxyUrl']
    if proxy:
        ca = str(RUN / 'ca.pem')
        for key in ('HTTP_PROXY', 'HTTPS_PROXY', 'http_proxy', 'https_proxy', 'AGENT_PROXY_URL'):
            env[key] = proxy
        env.update(NO_PROXY='localhost,127.0.0.1,::1', no_proxy='localhost,127.0.0.1,::1',
                   NODE_USE_ENV_PROXY='1', CARGO_NET_GIT_FETCH_WITH_CLI='true', CLAUDE_CODE_CERT_STORE='system')
        for key in ('AGENT_CA_FILE', 'NODE_EXTRA_CA_CERTS', 'SSL_CERT_FILE', 'CURL_CA_BUNDLE',
                    'GIT_SSL_CAINFO', 'REQUESTS_CA_BUNDLE', 'PIP_CERT', 'CARGO_HTTP_CAINFO',
                    'AWS_CA_BUNDLE', 'DENO_CERT'):
            env[key] = ca
    for key, value in [('safe.directory', '/workspace'), ('user.name', 'hatchward-agent'),
                       ('user.email', 'agent@hatchward.invalid')]:
        subprocess.run(['git', 'config', '--global', '--replace-all', key, value], env=env, check=True)
    subprocess.run(['git', 'config', '--global', 'credential.helper', '!gh auth git-credential'], env=env, check=True)
    clone_repository(config, env)
    os.chdir(WORKSPACE)
    fd = os.open('/dev/null', os.O_RDONLY)
    os.dup2(fd, 0)
    os.close(fd)
    os.execvpe(sys.argv[1], sys.argv[1:], env)


def cli():
    try:
        main()
    except CloneError as error:
        sys.exit(f'hatchward-run: {error}')
    except Exception:
        sys.exit('hatchward-run: workload preparation failed')


if __name__ == '__main__':
    cli()
