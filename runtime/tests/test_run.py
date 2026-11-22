import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock
spec = importlib.util.spec_from_file_location('run', Path(__file__).parents[1] / 'run.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

PROXY = 'http://hatchward:gateway-secret@127.0.0.1:3128'


def git(*args, cwd=None, env=None):
    subprocess.run(['git', *args], cwd=cwd, env=env, check=True, capture_output=True)


class Fixture:
    """A local bare repository with a submodule, standing in for github.com."""

    def __init__(self, root):
        self.root = root
        home = root / 'home'
        home.mkdir()
        self.env = {'PATH': os.environ['PATH'], 'HOME': str(home), 'GIT_CONFIG_NOSYSTEM': '1',
                    'GIT_AUTHOR_NAME': 't', 'GIT_AUTHOR_EMAIL': 't@t', 'GIT_COMMITTER_NAME': 't',
                    'GIT_COMMITTER_EMAIL': 't@t'}
        git('config', '--global', 'protocol.file.allow', 'always', env=self.env)
        git('config', '--global', 'init.defaultBranch', 'main', env=self.env)
        sub = self.repo('sub', {'sub.txt': 'submodule'})
        work = root / 'work'
        git('init', '-q', str(work), env=self.env)
        (work / 'README').write_text('main')
        git('add', '.', cwd=work, env=self.env)
        git('-c', 'protocol.file.allow=always', 'submodule', '-q', 'add', sub.as_uri(), 'vendor/sub', cwd=work, env=self.env)
        git('commit', '-qm', 'main', cwd=work, env=self.env)
        git('checkout', '-qb', 'feature', cwd=work, env=self.env)
        (work / 'README').write_text('feature')
        git('commit', '-qam', 'feature', cwd=work, env=self.env)
        git('checkout', '-q', 'main', cwd=work, env=self.env)
        self.bare = root / 'repo.git'
        git('clone', '-q', '--bare', str(work), str(self.bare), env=self.env)
        # Point https://github.com/fixture/ at local paths, so no network is used.
        git('config', '--global', f'url.{root.as_uri()}/.insteadOf', 'https://github.com/fixture/', env=self.env)

    def repo(self, name, files):
        work = self.root / f'{name}-work'
        git('init', '-q', str(work), env=self.env)
        for path, content in files.items():
            (work / path).write_text(content)
        git('add', '.', cwd=work, env=self.env)
        git('commit', '-qm', name, cwd=work, env=self.env)
        bare = self.root / f'{name}.git'
        git('clone', '-q', '--bare', str(work), str(bare), env=self.env)
        return bare


class CloneTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name).resolve()
        self.fixture = Fixture(root)
        self.workspace = root / 'workspace'
        self.workspace.mkdir()
        patcher = mock.patch.object(module, 'WORKSPACE', str(self.workspace))
        patcher.start()
        self.addCleanup(patcher.stop)

    def tearDown(self):
        self.tmp.cleanup()

    def clone(self, env):
        module.clone_repository({'proxyUrl': '', 'env': env}, self.fixture.env)

    def head(self):
        out = subprocess.run(['git', '-C', str(self.workspace), 'symbolic-ref', '--short', 'HEAD'],
                             capture_output=True, text=True, check=True)
        return out.stdout.strip()

    def test_clones_remote_default_branch_with_submodules(self):
        self.clone({'AGENT_REPO': 'fixture/repo', 'GH_TOKEN': 'hatchward-proxy-managed'})
        self.assertEqual(self.head(), 'main')
        self.assertEqual((self.workspace / 'README').read_text(), 'main')
        self.assertEqual((self.workspace / 'vendor/sub/sub.txt').read_text(), 'submodule')
        origin = subprocess.run(['git', '-C', str(self.workspace), 'config', 'remote.origin.url'],
                                capture_output=True, text=True, check=True).stdout.strip()
        self.assertEqual(origin, 'https://github.com/fixture/repo.git')

    def test_clones_configured_base_branch(self):
        self.clone({'AGENT_REPO': 'fixture/repo', 'AGENT_BASE_BRANCH': 'feature'})
        self.assertEqual(self.head(), 'feature')
        self.assertEqual((self.workspace / 'README').read_text(), 'feature')
        self.assertEqual((self.workspace / 'vendor/sub/sub.txt').read_text(), 'submodule')

    def test_no_repository_means_no_git_at_all(self):
        with mock.patch.object(module.subprocess, 'run') as run:
            self.clone({'GH_TOKEN': 'hatchward-proxy-managed'})
        run.assert_not_called()
        self.assertEqual(list(self.workspace.iterdir()), [])

    def test_missing_repository_fails_with_one_line_naming_it(self):
        with self.assertRaises(module.CloneError) as caught:
            self.clone({'AGENT_REPO': 'fixture/missing'})
        message = str(caught.exception)
        self.assertTrue(message.startswith('clone of fixture/missing failed: '), message)
        self.assertIn('missing.git', message)  # the cause, not git's generic last line
        self.assertNotIn('\n', message)

    def test_missing_branch_fails_with_cause(self):
        with self.assertRaises(module.CloneError) as caught:
            self.clone({'AGENT_REPO': 'fixture/repo', 'AGENT_BASE_BRANCH': 'absent'})
        self.assertRegex(str(caught.exception), r'^clone of fixture/repo failed: .*absent')

    def test_failure_never_prints_proxy_credentials(self):
        stderr = (f'Cloning...\nwarning: via {PROXY}\nfatal: unable to access '
                  f'\'https://x-access-token:ghp_real@github.com/o/r.git/\': proxy {PROXY} '
                  f'refused, password gateway-secret\n').encode()
        message = str(module.clone_failure('o/r', stderr, 128, PROXY))
        for secret in ('gateway-secret', 'ghp_real', 'x-access-token'):
            self.assertNotIn(secret, message)
        self.assertTrue(message.startswith('clone of o/r failed: unable to access'), message)
        self.assertEqual(str(module.clone_failure('o/r', b'', 9, PROXY)),
                         'clone of o/r failed: git exited with status 9')


class MainTests(unittest.TestCase):
    """hatchward-run's own sequence, with git and exec replaced by recorders."""

    def run_main(self, env):
        with tempfile.TemporaryDirectory() as tmp:
            run = Path(tmp)
            (run / 'workload').mkdir()
            (run / 'config.json').write_text(json.dumps({'proxyUrl': PROXY, 'env': env}))
            calls = []

            def record(command, **kwargs):
                calls.append(command)
                return subprocess.CompletedProcess(command, 0, b'', b'')

            def execvpe(file, args, exec_env):
                calls.append(('exec', args, exec_env))
                raise SystemExit(0)

            stdin = mock.Mock(buffer=io.BytesIO(b'{"agent":{}}'))
            with mock.patch.object(module, 'RUN', run), mock.patch.object(module.subprocess, 'run', record), \
                    mock.patch.object(module.os, 'execvpe', execvpe), mock.patch.object(module.os, 'chdir'), \
                    mock.patch.object(module.os, 'dup2'), mock.patch.object(module.sys, 'stdin', stdin), \
                    mock.patch.object(module.sys, 'argv', ['run.py', 'agent-cmd', '--flag']), \
                    self.assertRaises(SystemExit):
                module.main()
            return calls

    def test_without_repository_only_git_config_runs(self):
        calls = self.run_main({'GH_TOKEN': 'hatchward-proxy-managed'})
        self.assertEqual([c[:3] for c in calls[:-1]], [['git', 'config', '--global']] * 4)
        self.assertEqual(calls[-1][:2], ('exec', ['agent-cmd', '--flag']))

    def test_with_repository_clones_after_git_config_and_before_exec(self):
        calls = self.run_main({'GH_TOKEN': 'hatchward-proxy-managed', 'AGENT_REPO': 'o/r',
                               'AGENT_BASE_BRANCH': 'develop'})
        self.assertEqual([c[:3] for c in calls[:4]], [['git', 'config', '--global']] * 4)
        self.assertEqual(calls[4], ['git', 'clone', '-q', '--branch', 'develop', '--',
                                    'https://github.com/o/r.git', '/workspace'])
        self.assertEqual(calls[5], ['git', '-C', '/workspace', 'submodule', '-q', 'update', '--init', '--recursive'])
        self.assertEqual(calls[6][0], 'exec')
        exec_env = calls[6][2]
        self.assertEqual(exec_env['GH_TOKEN'], 'hatchward-proxy-managed')
        self.assertEqual(exec_env['HTTPS_PROXY'], PROXY)
        self.assertNotIn('GIT_TERMINAL_PROMPT', exec_env)

    def test_clone_uses_proxy_ca_and_sentinel_without_prompting(self):
        seen = {}
        original = module.clone_repository

        def spy(config, env):
            seen.update(env)
            with mock.patch.object(module.subprocess, 'run', lambda c, **k: (seen.setdefault('clone_env', k['env']),
                                   subprocess.CompletedProcess(c, 0, b'', b''))[1]):
                original(config, env)

        with mock.patch.object(module, 'clone_repository', spy):
            self.run_main({'GH_TOKEN': 'hatchward-proxy-managed', 'AGENT_REPO': 'o/r'})
        clone_env = seen['clone_env']
        self.assertEqual(clone_env['HTTPS_PROXY'], PROXY)
        self.assertTrue(clone_env['GIT_SSL_CAINFO'].endswith('ca.pem'))
        self.assertEqual(clone_env['GH_TOKEN'], 'hatchward-proxy-managed')
        self.assertEqual(clone_env['GIT_TERMINAL_PROMPT'], '0')
        self.assertEqual(clone_env['HOME'], '/home/agent')


class ExitTests(unittest.TestCase):
    def exit_message(self, error):
        with mock.patch.object(module, 'main', side_effect=error), self.assertRaises(SystemExit) as caught:
            module.cli()
        return caught.exception.code

    def test_clone_failure_exits_with_its_own_line(self):
        # sys.exit(str) prints the string to stderr and exits with status 1.
        self.assertEqual(self.exit_message(module.CloneError('clone of o/r failed: repository not found')),
                         'hatchward-run: clone of o/r failed: repository not found')

    def test_other_failures_stay_generic(self):
        self.assertEqual(self.exit_message(RuntimeError('detail with secret')),
                         'hatchward-run: workload preparation failed')
