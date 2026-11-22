import importlib.util
from pathlib import Path
import unittest
spec = importlib.util.spec_from_file_location('configure', Path(__file__).parents[1] / 'configure.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

PROXY = {'proxyUrl': 'http://hatchward:token@127.0.0.1:3128', 'ca': 'certificate'}


class ConfigurationTests(unittest.TestCase):
    def test_networkless_configuration(self):
        self.assertEqual(module.validate_config({}), ('', '', {}))

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
