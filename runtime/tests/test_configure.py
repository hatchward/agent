import base64
import importlib.util
import json
import os
from pathlib import Path
import shutil
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import textwrap
import threading
import unittest
MODULE = Path(__file__).resolve().parents[1] / 'configure.py'
spec = importlib.util.spec_from_file_location('configure', MODULE)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

PROXY = {'proxyUrl': 'http://hatchward:token@127.0.0.1:3128', 'ca': 'certificate'}


class ConfigurationTests(unittest.TestCase):
    def test_networkless_configuration(self):
        self.assertEqual(module.validate_config({}), ('', '', {}, []))

    def test_rejects_actual_credentials_and_env_injection(self):
        for env in ({'GH_TOKEN': 'real-secret'}, {'LD_PRELOAD': '/workspace/evil.so'}, {'PATH': '/workspace'}):
            with self.assertRaises(ValueError):
                module.validate_config({'env': env})

    def test_rejects_proxy_redirection(self):
        for url in ('http://token@localhost:3128', 'https://token@127.0.0.1:3128',
                    'http://token@127.0.0.1:9999', 'http://token@127.0.0.1:3128/path'):
            with self.assertRaises(ValueError):
                module.validate_config({'proxyUrl': url, 'ca': 'invalid'})

    def test_ca_and_proxy_required_together(self):
        for value in ({'ca': 'certificate'}, {'proxyUrl': 'http://token@127.0.0.1:3128'},
                      {'env': {'GH_TOKEN': module.SENTINEL}}, {'env': {'AGENT_REPO': 'owner/name'}}):
            with self.assertRaises(ValueError):
                module.validate_config(value)


class RepositoryKeyTests(unittest.TestCase):
    def test_accepts_repository_with_and_without_branch(self):
        for env in ({'AGENT_REPO': 'hatchward/core'},
                    {'AGENT_REPO': 'Owner-1/repo_name.js', 'AGENT_BASE_BRANCH': 'develop'},
                    {'AGENT_REPO': 'o/r', 'AGENT_BASE_BRANCH': 'release/v1.2', 'GH_TOKEN': module.SENTINEL}):
            module.validate_env(env)

    def test_rejects_malformed_repository(self):
        for repo in ('', 'owner', 'owner/name/extra', 'https://github.com/o/r', 'o/r\n', 'o /r',
                     '-o/r;x', 'own$er/name', 'owner/', module.SENTINEL, 7, None, ['o/r']):
            with self.subTest(repo=repo), self.assertRaises(ValueError):
                module.validate_env({'AGENT_REPO': repo})

    def test_rejects_invalid_branch(self):
        for branch in ('', '-main', '--upload-pack=x', 'a..b', 'a b', 'main.lock', 'a~1', 'a^', 'a:b',
                       '@{-1}', 'x\n', 'feature/', 7, None):
            with self.subTest(branch=branch), self.assertRaises(ValueError):
                module.validate_env({'AGENT_REPO': 'o/r', 'AGENT_BASE_BRANCH': branch})

    def test_rejects_branch_without_repository(self):
        with self.assertRaises(ValueError):
            module.validate_env({'AGENT_BASE_BRANCH': 'main'})

    def test_repository_keys_do_not_relax_credential_rules(self):
        for env in ({'AGENT_REPO': 'o/r', 'GH_TOKEN': 'real-secret'}, {'AGENT_REPO': 'o/r', 'PATH': '/x'}):
            with self.assertRaises(ValueError):
                module.validate_env(env)


def host_key(kind=b'ssh-ed25519'):
    blob = struct.pack('!I', len(kind)) + kind + struct.pack('!I', 32) + bytes(32)
    return kind.decode() + ' ' + base64.b64encode(blob).decode()


def self_signed_ca():
    with tempfile.TemporaryDirectory() as tmp:
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
                        '-nodes', '-keyout', tmp + '/key.pem', '-out', tmp + '/ca.pem', '-days', '1',
                        '-subj', '/CN=test'], check=True, capture_output=True)
        return Path(tmp + '/ca.pem').read_text()


CA = self_signed_ca()
SSH_AGENT = {'index': 0, 'name': 'ssh-agent', 'listen': {'unix': 'ssh-agent'},
             'env': {'SSH_AUTH_SOCK': '/run/hatchward/ssh-agent.sock'},
             'sshHosts': [{'host': 'ssh.github.com', 'port': 443, 'hostKeys': [host_key()]}]}
PG = {'index': 1, 'name': 'pg', 'listen': {'tcp': 5432, 'address': '127.0.10.1'},
      'env': {'PGHOST': '127.0.10.1', 'PGPORT': '5432'}}


def config(**extra):
    return dict(PROXY, ca=CA, **extra)


class DeclaredEnvTests(unittest.TestCase):
    def test_accepts_per_secret_sentinels(self):
        _, _, env, _ = module.validate_config(config(
            env={'GH_TOKEN': module.SENTINEL},
            declaredEnv=[{'name': 'NPM_TOKEN', 'sentinel': 'hatchward-secret-npm_token'},
                         {'name': 'X2', 'sentinel': 'hatchward-secret-x2'}]))
        self.assertEqual(env, {'GH_TOKEN': module.SENTINEL, 'NPM_TOKEN': 'hatchward-secret-npm_token',
                               'X2': 'hatchward-secret-x2'})

    def test_rejects_unknown_keys(self):
        for value in ({'secrets': {}}, config(declaredEnv=[{'name': 'NPM_TOKEN',
                      'sentinel': 'hatchward-secret-npm_token', 'value': 'x'}]),
                      config(endpoints=[dict(PG, extra=1)]),
                      config(endpoints=[dict(PG, listen={'tcp': 5432, 'address': '127.0.10.1', 'x': 1})])):
            with self.subTest(value=value), self.assertRaises(ValueError):
                module.validate_config(value)

    def test_rejects_reserved_and_invalid_names(self):
        for name in ('PATH', 'HOME', 'USER', 'SHELL', 'LD_PRELOAD', 'NODE_OPTIONS', 'BASH_ENV', 'ENV',
                     'GIT_SSH_COMMAND', 'HTTP_PROXY', 'HTTPS_PROXY', 'NO_PROXY', 'ALL_PROXY', 'AGENT_REPO',
                     'HATCHWARD_X', 'ANTHROPIC_API_KEY', 'CLAUDE_X', 'GH_TOKEN', 'GITHUB_TOKEN',
                     'SSH_AUTH_SOCK', 'npm_token', 'http_proxy', '1X', '', 'A' * 65, 'A-B', 7, None):
            with self.subTest(name=name), self.assertRaises(ValueError):
                sentinel = 'hatchward-secret-' + (name.lower() if isinstance(name, str) else '')
                module.validate_config(config(declaredEnv=[{'name': name, 'sentinel': sentinel}]))

    def test_rejects_bad_sentinels(self):
        for sentinel in ('real-secret', module.SENTINEL, 'hatchward-secret-NPM_TOKEN',
                         'hatchward-secret-npm_token\n', 'hatchward-secret-', 'hatchward-secret-x',
                         'hatchward-secret-1npm', 'hatchward-secret-npm-token', 'hatchward-secret-' + 'a' * 65,
                         'prefix-hatchward-secret-npm_token', '', None, 7):
            with self.subTest(sentinel=sentinel), self.assertRaises(ValueError):
                module.validate_config(config(declaredEnv=[{'name': 'NPM_TOKEN', 'sentinel': sentinel}]))

    def test_sentinel_comes_from_secret_name_not_env_name(self):
        _, _, env, _ = module.validate_config(config(
            declaredEnv=[{'name': 'REGISTRY_TOKEN', 'sentinel': 'hatchward-secret-npm_token'}]))
        self.assertEqual(env, {'REGISTRY_TOKEN': 'hatchward-secret-npm_token'})

    def test_rejects_duplicate_sentinels(self):
        with self.assertRaises(ValueError):
            module.validate_config(config(declaredEnv=[
                {'name': 'NPM_TOKEN', 'sentinel': 'hatchward-secret-npm_token'},
                {'name': 'REGISTRY_TOKEN', 'sentinel': 'hatchward-secret-npm_token'}]))

    def test_rejects_duplicates_and_requires_proxy(self):
        entry = {'name': 'NPM_TOKEN', 'sentinel': 'hatchward-secret-npm_token'}
        for value in (config(declaredEnv=[entry, entry]), {'declaredEnv': [entry]},
                      config(declaredEnv=[{'name': 'PGHOST', 'sentinel': 'hatchward-secret-pghost'}],
                             endpoints=[PG]),
                      config(declaredEnv=[entry] * 17), config(declaredEnv={'NPM_TOKEN': 'x'})):
            with self.subTest(value=value), self.assertRaises(ValueError):
                module.validate_config(value)


class EndpointTests(unittest.TestCase):
    def test_accepts_runner_generated_env(self):
        _, _, env, endpoints = module.validate_config(config(endpoints=[SSH_AGENT, PG]))
        self.assertEqual(env, {'SSH_AUTH_SOCK': '/run/hatchward/ssh-agent.sock',
                               'PGHOST': '127.0.10.1', 'PGPORT': '5432'})
        self.assertEqual([e['listen'] for e in endpoints],
                         [{'unix': 'ssh-agent'}, {'tcp': 5432, 'address': '127.0.10.1'}])

    def test_tokens_and_default_address(self):
        endpoints = [{'index': 3, 'name': 'db', 'listen': {'tcp': 6543},
                      'env': {'DB_HOST': '127.0.0.1', 'DB_PORT': '6543'}},
                     {'index': 4, 'name': 'sock', 'listen': {'unix': 'sock'},
                      'env': {'SOCK_PATH': '/run/hatchward/sock.sock',
                              'SOCK_URL_HOST': '%2Frun%2Fhatchward%2Fsock.sock'}}]
        _, _, env, parsed = module.validate_config({'endpoints': endpoints})
        self.assertEqual(parsed[0]['listen'], {'tcp': 6543, 'address': '127.0.0.1'})
        self.assertEqual(env['SOCK_URL_HOST'], '%2Frun%2Fhatchward%2Fsock.sock')

    def test_rejects_forged_env_values(self):
        for env in ({'PGHOST': 'db.acme.example'}, {'PGHOST': '127.0.0.1'}, {'PGPORT': '5433'},
                    {'PGPORT': 5432}, {'PGHOST': '/run/hatchward/ssh-agent.sock'},
                    {'LD_PRELOAD': '127.0.10.1'}, {'NODE_OPTIONS': '5432'}, {'GIT_SSH_COMMAND': '5432'},
                    {'SSH_AUTH_SOCK': '127.0.10.1'}, {'pghost': '127.0.10.1'}):
            with self.subTest(env=env), self.assertRaises(ValueError):
                module.validate_config({'endpoints': [dict(PG, env=env)]})

    def test_ssh_auth_sock_only_names_its_own_socket(self):
        other = {'index': 2, 'name': 'other', 'listen': {'unix': 'other'},
                 'env': {'SSH_AUTH_SOCK': '/run/hatchward/ssh-agent.sock'}}
        with self.assertRaises(ValueError):
            module.validate_config({'endpoints': [dict(SSH_AGENT, env={}, sshHosts=[]), other]})

    def test_env_names_unique_across_endpoints_and_env(self):
        twin = {'index': 2, 'name': 'pg2', 'listen': {'tcp': 5432, 'address': '127.0.10.2'},
                'env': {'PGHOST': '127.0.10.2'}}
        for value in ({'endpoints': [PG, twin]},
                      config(env={'GH_TOKEN': module.SENTINEL},
                             endpoints=[dict(PG, env={'GH_TOKEN': '5432'})])):
            with self.subTest(value=value), self.assertRaises(ValueError):
                module.validate_config(value)

    def test_rejects_invalid_listeners(self):
        for listen in ({'tcp': 3128}, {'tcp': 3128, 'address': '127.0.0.1'}, {'tcp': 1023},
                       {'tcp': 22}, {'tcp': 65536}, {'tcp': '5432'}, {'tcp': True},
                       {'tcp': 5432, 'address': '0.0.0.0'}, {'tcp': 5432, 'address': '10.0.0.1'},
                       {'tcp': 5432, 'address': '::1'}, {'tcp': 5432, 'address': 'localhost'},
                       {'tcp': 5432, 'address': '127.000.0.1'}, {'unix': 'actions'}, {'unix': 'reload'},
                       {'unix': 'control'}, {'unix': '../x'}, {'unix': 'A'}, {'unix': 'a' * 33},
                       {'unix': 'x', 'tcp': 5432}, {}, 'pg'):
            with self.subTest(listen=listen), self.assertRaises(ValueError):
                module.validate_config({'endpoints': [{'index': 0, 'name': 'pg', 'listen': listen}]})

    def test_rejects_duplicate_index_name_and_listener(self):
        base = {'index': 0, 'name': 'a', 'listen': {'tcp': 5000}}
        for second in ({'index': 0, 'name': 'b', 'listen': {'tcp': 5001}},
                       {'index': 1, 'name': 'a', 'listen': {'tcp': 5001}},
                       {'index': 1, 'name': 'b', 'listen': {'tcp': 5000, 'address': '127.0.0.1'}},
                       {'index': 256, 'name': 'b', 'listen': {'tcp': 5001}},
                       {'index': -1, 'name': 'b', 'listen': {'tcp': 5001}}):
            with self.subTest(second=second), self.assertRaises(ValueError):
                module.validate_config({'endpoints': [base, second]})

    def test_rejects_invalid_ssh_hosts(self):
        bad_blob = 'ssh-ed25519 ' + base64.b64encode(struct.pack('!I', 7) + b'ssh-rsa').decode()
        for hosts in ([{'host': 'ssh.github.com', 'port': 22, 'hostKeys': []}],
                      [{'host': 'ssh.github.com', 'port': 22}],
                      [{'host': 'SSH.github.com', 'port': 22, 'hostKeys': [host_key()]}],
                      [{'host': 'a b', 'port': 22, 'hostKeys': [host_key()]}],
                      [{'host': 'x\nProxyCommand evil', 'port': 22, 'hostKeys': [host_key()]}],
                      [{'host': 'h', 'port': 0, 'hostKeys': [host_key()]}],
                      [{'host': 'h', 'port': 22, 'hostKeys': ['ssh-ed25519 AAAA\nevil']}],
                      [{'host': 'h', 'port': 22, 'hostKeys': [bad_blob]}],
                      [{'host': 'h', 'port': 22, 'hostKeys': [host_key()], 'user': 'git'}]):
            with self.subTest(hosts=hosts), self.assertRaises(ValueError):
                module.validate_config(config(endpoints=[dict(SSH_AGENT, sshHosts=hosts)]))
        with self.assertRaises(ValueError):  # SSH needs the proxy.
            module.validate_config({'endpoints': [SSH_AGENT]})


class WriteTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.run_dir = Path(self.tmp.name)
        (self.run_dir / 'gateway').mkdir()

    def test_writes_table_links_and_ssh_configuration(self):
        ssh_agent = dict(SSH_AGENT, env={'SSH_AUTH_SOCK': str(self.run_dir / 'ssh-agent.sock')},
                         sshHosts=SSH_AGENT['sshHosts'] + [
                             {'host': 'git.acme.example', 'port': 22, 'hostKeys': [host_key(), host_key()]}])
        _, _, _, endpoints = module.validate_config(config(endpoints=[ssh_agent, PG]), run=self.run_dir)
        module.write_endpoints(endpoints, run=self.run_dir)
        table = self.run_dir / 'endpoints.json'
        self.assertEqual(json.loads(table.read_text()), {'endpoints': [
            {'index': 0, 'name': 'ssh-agent', 'unix': 'ssh-agent'},
            {'index': 1, 'name': 'pg', 'tcp': 5432, 'address': '127.0.10.1'}]})
        link = self.run_dir / 'ssh-agent.sock'
        self.assertEqual(os.readlink(link), str(self.run_dir / 'gateway/ssh-agent.sock'))
        self.assertEqual(sorted(p.name for p in self.run_dir.iterdir()),
                         ['endpoints.json', 'gateway', 'known_hosts', 'ssh-agent.sock', 'ssh_config'])
        for name in ('endpoints.json', 'ssh_config', 'known_hosts'):
            self.assertEqual(stat.S_IMODE((self.run_dir / name).stat().st_mode), 0o444)
        ssh_config = (self.run_dir / 'ssh_config').read_text()
        self.assertIn('Host ssh.github.com\n  HostName ssh.github.com\n  Port 443\n'
                      '  ProxyCommand /usr/local/bin/hatchward-connect %h %p\n', ssh_config)
        self.assertIn('Host git.acme.example\n  HostName git.acme.example\n  Port 22\n', ssh_config)
        self.assertEqual(ssh_config.count('StrictHostKeyChecking yes'), 2)
        self.assertEqual(ssh_config.count(f'UserKnownHostsFile {self.run_dir}/known_hosts'), 2)
        self.assertEqual(ssh_config.count(f'IdentityAgent {self.run_dir}/ssh-agent.sock'), 2)
        self.assertEqual((self.run_dir / 'known_hosts').read_text().splitlines(), [
            f'[ssh.github.com]:443 {host_key()}', f'git.acme.example {host_key()}',
            f'git.acme.example {host_key()}'])

    def test_no_ssh_files_without_ssh_hosts(self):
        _, _, _, endpoints = module.validate_config({'endpoints': [PG]}, run=self.run_dir)
        module.write_endpoints(endpoints, run=self.run_dir)
        self.assertEqual(sorted(p.name for p in self.run_dir.iterdir()), ['endpoints.json', 'gateway'])

    def test_existing_link_is_never_replaced(self):
        (self.run_dir / 'ssh-agent.sock').symlink_to('/workspace/evil.sock')
        _, _, _, endpoints = module.validate_config({'endpoints': [dict(SSH_AGENT, env={}, sshHosts=[])]},
                                                    run=self.run_dir)
        with self.assertRaises(FileExistsError):
            module.write_endpoints(endpoints, run=self.run_dir)


class ReloadTests(unittest.TestCase):
    def serve(self, reply):
        tmp = tempfile.mkdtemp(dir='/tmp')
        self.addCleanup(shutil.rmtree, tmp)
        path = tmp + '/reload.sock'
        server = socket.socket(socket.AF_UNIX)
        self.addCleanup(server.close)
        server.bind(path)
        server.listen(1)
        accepted = []

        def respond():
            conn, _ = server.accept()
            accepted.append(conn)
            if reply is not None:
                conn.sendall(reply)
                conn.close()
        thread = threading.Thread(target=respond, daemon=True)
        thread.start()
        self.addCleanup(lambda: [c.close() for c in accepted])
        return path

    def test_success_on_one(self):
        module.reload_gateway(self.serve(b'1'), timeout=2)

    def test_failure_on_zero_other_or_close(self):
        for reply in (b'0', b'x', b''):
            with self.subTest(reply=reply), self.assertRaises(ValueError):
                module.reload_gateway(self.serve(reply), timeout=2)

    def test_timeout_without_reply(self):
        with self.assertRaises(OSError):
            module.reload_gateway(self.serve(None), timeout=.2)

    def test_missing_gateway(self):
        with self.assertRaises(OSError):
            module.reload_gateway('/nonexistent/reload.sock', timeout=.2)

    def test_main_fails_without_writing_config_when_reload_fails(self):
        script = textwrap.dedent('''
            import importlib.util, io, sys
            from pathlib import Path
            spec = importlib.util.spec_from_file_location('configure', sys.argv[1])
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            module.RUN = Path(sys.argv[2])
            module.RELOAD_TIMEOUT = .2
            module.main()
        ''')
        tmp = tempfile.mkdtemp(dir='/tmp')
        self.addCleanup(shutil.rmtree, tmp)
        run = Path(tmp)
        (run / 'gateway').mkdir()
        (run / 'ready').touch()
        data = json.dumps({'endpoints': [PG]}).encode()
        result = subprocess.run([sys.executable, '-c', script, str(MODULE), str(run)], input=data,
                                capture_output=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue((run / 'endpoints.json').exists())
        self.assertFalse((run / 'config.json').exists())
