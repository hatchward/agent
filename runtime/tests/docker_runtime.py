"""Opt-in integration test: python3 runtime/tests/docker_runtime.py IMAGE."""
import io
import json
import subprocess
import sys
import tarfile
import time
import uuid

name = 'hw-runtime-test-' + uuid.uuid4().hex[:10]
image = sys.argv[1]
size_mib = int(sys.argv[2]) if len(sys.argv) > 2 else 256

def docker(*args, data=None, check=True):
    p = subprocess.run(['docker', *args], input=data, capture_output=True, timeout=120)
    if check and p.returncode:
        raise RuntimeError(p.stderr.decode(errors='replace') + p.stdout.decode(errors='replace'))
    return p

def start(name):
    """Launch an assignment container exactly as the runner does and wait for readiness."""
    docker('volume', 'create', name)
    args = ['run', '-d', '--name', name, '--network', 'none', '--read-only', '--ipc', 'none',
            '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--device', '/dev/fuse',
            '--memory', '256m', '--memory-swap', '256m', '--pids-limit', '64',
            '--mount', f'type=volume,src={name},dst=/hatchward-backing',
            '-e', f'HATCHWARD_DISK_MIB={size_mib}', '--entrypoint', '/usr/local/bin/hatchward-bootstrap']
    for cap in ['SYS_ADMIN', 'CHOWN', 'SETUID', 'SETGID', 'SETPCAP']:
        args += ['--cap-add', cap]
    docker(*args, image)
    for _ in range(60):
        if docker('exec', name, 'test', '-f', '/run/hatchward/ready', check=False).returncode == 0:
            break
        time.sleep(.25)
    else:
        raise RuntimeError(docker('logs', name).stdout.decode()+docker('logs', name).stderr.decode())


def remove(name):
    docker('rm', '-f', name, check=False)
    docker('volume', 'rm', name, check=False)


try:
    start(name)
    # Read process status in a trusted exec; all pre-existing processes must have no caps.
    audit = docker('exec', name, 'python3', '-c', '''import pathlib,os,json
out=[]
for p in pathlib.Path('/proc').glob('[0-9]*/status'):
 try:
  if p.parent.name==str(os.getpid()): continue
  data=dict(x.split(':',1) for x in p.read_text().splitlines() if ':' in x)
  assert all(int(data[k].strip(),16)==0 for k in ['CapInh','CapPrm','CapEff','CapBnd','CapAmb']),data
  assert data['NoNewPrivs'].strip()=='1'
  out.append({k:data[k].strip() for k in ['Name','Uid','CapEff','CapBnd','NoNewPrivs']})
 except FileNotFoundError: pass
print(json.dumps(out))''')
    print(audit.stdout.decode())
    # Ordinary orphan completion must be reaped without terminating the runtime.
    docker('exec', '--user', '1000:1000', name, '/usr/bin/python3', '-c',
           'import os,time; pid=os.fork(); time.sleep(.1) if pid==0 else None; os._exit(0)')
    docker('exec', name, '/usr/bin/test', '-f', '/run/hatchward/ready')
    # A hostile workload may shadow PATH tools before channel replenishment.
    docker('exec', '--user', '1000:1000', name, '/usr/bin/python3', '-c', """from pathlib import Path
folder=Path('/home/agent/.local/bin');folder.mkdir(parents=True,exist_ok=True)
for tool in ['setpriv','python3']:
 p=folder/tool
 p.write_bytes(bytes.fromhex('23212f62696e2f73680a2f62696e2f636174202f70726f632f73656c662f737461747573203e202f746d702f70726976696c656765642d706174682d70776e65640a657869742039310a'))
 p.chmod(0o755)
""")
    docker('exec', '-i', name, '/usr/local/bin/hatchward-channel', data=b'')
    assert docker('exec', name, '/usr/bin/test', '-e', '/tmp/privileged-path-pwned', check=False).returncode != 0
    docker('exec', '-i', name, 'hatchward-configure', data=b'{}')
    b=io.BytesIO()
    with tarfile.open(fileobj=b, mode='w') as tar:
        content=b'import-sentinel'
        info=tarfile.TarInfo('sentinel');info.size=len(content);tar.addfile(info,io.BytesIO(content))
    docker('exec','-i',name,'hatchward-import',data=b.getvalue())
    script='''import os,pathlib,errno,json,shutil,subprocess,socket
assert os.getuid()==1000
assert not pathlib.Path('/tmp/privileged-path-pwned').exists()
status=dict(x.split(':',1) for x in pathlib.Path('/proc/self/status').read_text().splitlines() if ':' in x)
assert all(int(status[k].strip(),16)==0 for k in ['CapInh','CapPrm','CapEff','CapBnd','CapAmb'])
assert status['NoNewPrivs'].strip()=='1'
assert len({os.stat(p).st_dev for p in ['/workspace','/home/agent','/tmp','/var/tmp','/run']})==1
control=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
try: control.connect('/run/hatchward/bridge/control.sock')
except PermissionError: pass
else: raise AssertionError('workload attached privileged host channel')
finally: control.close()
network=socket.socket();network.settimeout(1)
try: network.connect(('1.1.1.1',443))
except OSError: pass
else: raise AssertionError('direct network egress escaped isolation')
finally: network.close()
if shutil.which('claude'): subprocess.run(['claude','--version'],check=True)
assert pathlib.Path('/workspace/sentinel').read_text()=='import-sentinel'
# git creates every loose object with open(O_CREAT|O_RDWR, 0444); fuse2fs must allow it.
fd=os.open('/workspace/readonly-create',os.O_CREAT|os.O_EXCL|os.O_RDWR,0o444);os.write(fd,b'x');os.close(fd)
git=lambda *a: subprocess.run(['git','-C','/workspace/repo',*a],check=True,capture_output=True)
# O_TRUNC must truncate: a shorter rewrite (git's submodule .git file, any shell `>`) keeps no old tail.
pathlib.Path('/tmp/trunc').write_bytes(b'0123456789\\n')
fd=os.open('/tmp/trunc',os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o644);os.write(fd,b'ab\\n');os.close(fd)
assert pathlib.Path('/tmp/trunc').read_bytes()==b'ab\\n',pathlib.Path('/tmp/trunc').read_bytes()
subprocess.run(['bash','-c','echo 0123456789 > /tmp/trunc && echo ab > /tmp/trunc'],check=True)
assert pathlib.Path('/tmp/trunc').read_bytes()==b'ab\\n',pathlib.Path('/tmp/trunc').read_bytes()
subprocess.run(['git','init','-q','/workspace/repo'],check=True);pathlib.Path('/workspace/repo/f').write_text('x');git('add','f');git('commit','-qm','probe')
# fakeroot skips fuse2fs's own checks; the kernel (default_permissions) must still deny these.
for name,op in [('chmod',lambda: os.chmod('/run/hatchward/config.json',0o666)),
                ('chown',lambda: os.chown('/run/hatchward/config.json',1000,1000)),
                ('create in root dir',lambda: open('/run/hatchward/escape','x')),
                ('unlink in root dir',lambda: os.unlink('/run/hatchward/config.json'))]:
 try: op()
 except OSError: pass
 else: raise AssertionError('kernel permission check bypassed: '+name)
assert json.loads(pathlib.Path('/run/hatchward/manifest.json').read_text())=={'agent':{}}
for path in ['/hatchward-backing/quota.ext4','/run/hatchward/config.json','/run/hatchward/bridge/control.sock','/etc/escape','/dev/shm/escape','/dev/fuse']:
 try:
  with open(path,'ab') as f: f.write(b'x')
 except OSError: pass
 else: raise AssertionError('write escape '+path)
with open('/workspace/large','wb') as f:
 try:
  for _ in range(SIZE_MIB + 100): f.write(bytes(1048576))
  f.flush();os.fsync(f.fileno())
 except OSError as e: assert e.errno==errno.ENOSPC
 else: raise AssertionError('quota bypass')
try: pathlib.Path('/home/agent/overflow').write_bytes(bytes(1048576))
except OSError as e: assert e.errno==errno.ENOSPC
else: raise AssertionError('home quota bypass')
print('PASS runtime import, manifest, privileges, protected paths, git object writes, O_TRUNC, shared disk quota')'''
    result=docker('exec','-i',name,'hatchward-run','/usr/bin/python3','-c',script.replace('SIZE_MIB', str(size_mib)),data=b'{"agent":{}}')
    print(result.stdout.decode())
    docker('exec', '--user', '10002:10002', name, '/usr/bin/python3', '-c', '''import pathlib,os,signal
for p in pathlib.Path('/proc').glob('[0-9]*/cmdline'):
 try:
  if b'/usr/local/lib/hatchward/runtime/gateway.py' in p.read_bytes().split(bytes([0])):
   os.kill(int(p.parent.name),signal.SIGTERM)
 except (FileNotFoundError,PermissionError): pass
''')
    for _ in range(40):
        if docker('inspect','--format','{{.State.Running}}',name).stdout.strip()==b'false': break
        time.sleep(.1)
    else: raise AssertionError('gateway failure did not stop container')
    print('PASS orphan reaping and daemon-failure shutdown')
finally:
    remove(name)

# Routed-repository clone (AGENT_REPO). The network is off, so git's url.insteadOf
# points https://github.com/hatchward-fixture/ at a bare repository the agent builds
# under /tmp. This proves the configure keys, the clone, branch selection, a later
# agent commit, submodule initialisation and failure reporting inside the real
# sandbox, not the proxy path to github.com. The submodule needs O_TRUNC: git
# rewrites its .git file shorter, which fuse2fs before 1.47.4 corrupted.
PROXY = 'http://hatchward:gateway-token@127.0.0.1:3128'
FIXTURE = r"""set -eu
git config --global init.defaultBranch main
git config --global url.file:///tmp/fixture/.insteadOf https://github.com/hatchward-fixture/
git config --global protocol.file.allow always
[ "${MAKE_FIXTURE:-0}" = 1 ] || exit 0
cd /tmp
git init -q sub && cd sub && echo sub > SUB && git add . && git commit -qm sub
cd /tmp && git clone -q --bare --no-hardlinks sub fixture/sub.git
git init -q work && cd work && echo main > README && git add .
git submodule -q add https://github.com/hatchward-fixture/sub.git sub
git commit -qm main && git checkout -qb feature
echo feature > README && git commit -qam feature && git checkout -q main
cd /tmp && git clone -q --bare --no-hardlinks work fixture/repo.git
"""
CLONED = r"""import os,pathlib,subprocess
git=lambda *a: subprocess.run(['git',*a],capture_output=True,text=True,check=True).stdout.strip()
assert os.getcwd()=='/workspace' and os.getuid()==1000
assert pathlib.Path('README').read_text()=='feature\n'
assert git('symbolic-ref','--short','HEAD')=='feature'
assert git('rev-parse','HEAD')==git('rev-parse','origin/feature')
assert git('symbolic-ref','refs/remotes/origin/HEAD')=='refs/remotes/origin/main'
assert git('config','remote.origin.url')=='https://github.com/hatchward-fixture/repo.git'
assert git('status','--porcelain')==''
assert pathlib.Path('sub/SUB').read_text()=='sub\n'
assert pathlib.Path('sub/.git').read_text()=='gitdir: ../.git/modules/sub\n'
assert git('-C','sub','status','--porcelain')==''
assert all(p.stat().st_uid==1000 for p in pathlib.Path('/workspace').rglob('*'))
assert os.environ['AGENT_REPO']=='hatchward-fixture/repo'
git('commit','-q','--allow-empty','-m','agent commit')
print('PASS routed repository clone, base branch, submodule, agent ownership, agent commit')"""


def configure_clone(container, env):
    ca = docker('exec', container, 'openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout',
                '/dev/null', '-subj', '/CN=hatchward-test', '-days', '1', '-out', '/dev/stdout').stdout.decode()
    config = {'ca': ca, 'proxyUrl': PROXY, 'env': {'GH_TOKEN': 'hatchward-proxy-managed', **env}}
    docker('exec', '-i', container, 'hatchward-configure', data=json.dumps(config).encode())


def fixture(container, make):
    docker('exec', '--user', '1000:1000', '-e', 'HOME=/home/agent', '-e', f'MAKE_FIXTURE={int(make)}',
           '-e', 'GIT_AUTHOR_NAME=t', '-e', 'GIT_AUTHOR_EMAIL=t@t', '-e', 'GIT_COMMITTER_NAME=t',
           '-e', 'GIT_COMMITTER_EMAIL=t@t', container, 'bash', '-c', FIXTURE)


clone_name = name + '-clone'
try:
    start(clone_name)
    for bad in ({'AGENT_REPO': 'https://github.com/o/r'}, {'AGENT_REPO': 'o/r', 'AGENT_BASE_BRANCH': '-x'}):
        rejected = docker('exec', '-i', clone_name, 'hatchward-configure', check=False,
                          data=json.dumps({'env': bad}).encode())
        assert rejected.returncode != 0, bad
    fixture(clone_name, make=True)
    configure_clone(clone_name, {'AGENT_REPO': 'hatchward-fixture/repo', 'AGENT_BASE_BRANCH': 'feature'})
    assert docker('exec', clone_name, 'find', '/workspace', '-mindepth', '1').stdout == b''
    print(docker('exec', '-i', clone_name, 'hatchward-run', '/usr/bin/python3', '-c', CLONED,
                 data=b'{"agent":{}}').stdout.decode())
finally:
    remove(clone_name)

failed_name = name + '-clone-fail'
try:
    start(failed_name)
    fixture(failed_name, make=False)
    configure_clone(failed_name, {'AGENT_REPO': 'hatchward-fixture/missing'})
    failed = docker('exec', '-i', failed_name, 'hatchward-run', '/usr/bin/touch', '/workspace/command-ran',
                    data=b'{"agent":{}}', check=False)
    stderr = failed.stderr.decode()
    assert failed.returncode != 0, stderr
    assert stderr.count('\n') == 1 and stderr.startswith('hatchward-run: clone of hatchward-fixture/missing failed: '), stderr
    assert 'gateway-token' not in stderr, stderr
    assert docker('exec', failed_name, 'test', '-e', '/workspace/command-ran', check=False).returncode != 0
    print('PASS clone failure: non-zero, one credential-free stderr line, image command not run:', stderr.strip())
finally:
    remove(failed_name)

# Declared env and companion endpoints under the real privilege model: configure
# (uid 0, no capabilities) writes the table, links and SSH files into root-owned
# /run/hatchward, and the uid-10002 gateway binds the listeners on reload.sock.
HOST_KEY = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl'
ENDPOINTS = r"""import json,os,pathlib,socket,stat,subprocess
run=pathlib.Path('/run/hatchward')
assert os.environ['REGISTRY_TOKEN']=='hatchward-secret-npm_token'
assert os.environ['SSH_AUTH_SOCK']=='/run/hatchward/ssh-agent.sock'
assert os.environ['PGHOST']=='127.0.10.1' and os.environ['PGPORT']=='5432'
for name in ['endpoints.json','ssh_config','known_hosts']:
 info=(run/name).stat()
 assert info.st_uid==0 and stat.S_IMODE(info.st_mode)==0o444,(name,info)
assert os.readlink(run/'ssh-agent.sock')=='/run/hatchward/gateway/ssh-agent.sock'
assert (run/'ssh-agent.sock').lstat().st_uid==0
assert (run/'gateway/ssh-agent.sock').stat().st_uid==10002
try: (run/'endpoints.json').write_text('{}')
except OSError: pass
else: raise AssertionError('workload rewrote the endpoint table')
# Reload is public but only binds what the root-owned table names.
with socket.socket(socket.AF_UNIX) as s:
 s.settimeout(5);s.connect(str(run/'gateway/reload.sock'));assert s.recv(1)==b'1'
ssh=subprocess.run(['ssh','-G','-p','443','ssh.github.com'],capture_output=True,text=True,check=True).stdout.splitlines()
for line in ['proxycommand /usr/local/bin/hatchward-connect %h %p','stricthostkeychecking true',
             'userknownhostsfile /run/hatchward/known_hosts','identityagent /run/hatchward/ssh-agent.sock','port 443']:
 assert line in ssh,(line,ssh)
# ssh reaches the pinned host only through hatchward-connect's CONNECT, with the proxy's Basic credentials.
import threading
fake=socket.create_server(('127.0.0.2',8080));seen=[]
def serve():
 c,_=fake.accept();seen.append(c.recv(4096));c.sendall(b'HTTP/1.1 200 OK\r\n\r\nSSH-2.0-fake\r\n');c.close()
threading.Thread(target=serve,daemon=True).start()
env=dict(os.environ,HTTPS_PROXY='http://hatchward:gateway-token@127.0.0.2:8080')
result=subprocess.run(['ssh','-o','BatchMode=yes','git@ssh.github.com'],env=env,capture_output=True,text=True,timeout=20)
assert result.returncode!=0 and seen and seen[0].startswith(b'CONNECT ssh.github.com:443 HTTP/1.1\r\n'),(seen,result.stderr)
assert b'Proxy-Authorization: Basic aGF0Y2h3YXJkOmdhdGV3YXktdG9rZW4=' in seen[0],seen
s=socket.create_connection(('127.0.10.1',5432),timeout=5);s.sendall(b'q');s.close()
print('PASS declared env, endpoint table, links, ssh_config via hatchward-connect, public reload')"""

endpoints_name = name + '-endpoints'
try:
    labels = json.loads(docker('image', 'inspect', image, '--format', '{{json .Config.Labels}}').stdout)
    assert labels['org.hatchward.agent.features'] == 'declared-env,endpoints,ssh-client', labels
    assert labels['org.hatchward.agent.slots'] == '48', labels
    start(endpoints_name)
    ca = docker('exec', endpoints_name, 'openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout',
                '/dev/null', '-subj', '/CN=hatchward-test', '-days', '1', '-out', '/dev/stdout').stdout.decode()
    config = {'ca': ca, 'proxyUrl': PROXY,
              'declaredEnv': [{'name': 'REGISTRY_TOKEN', 'sentinel': 'hatchward-secret-npm_token'}],
              'endpoints': [
                  {'index': 0, 'name': 'ssh-agent', 'listen': {'unix': 'ssh-agent'},
                   'env': {'SSH_AUTH_SOCK': '/run/hatchward/ssh-agent.sock'},
                   'sshHosts': [{'host': 'ssh.github.com', 'port': 443, 'hostKeys': [HOST_KEY]}]},
                  {'index': 1, 'name': 'pg', 'listen': {'tcp': 5432, 'address': '127.0.10.1'},
                   'env': {'PGHOST': '127.0.10.1', 'PGPORT': '5432'}}]}
    forged = json.loads(json.dumps(config))
    forged['endpoints'][1]['env']['PGHOST'] = 'db.acme.example'
    assert docker('exec', '-i', endpoints_name, 'hatchward-configure', check=False,
                  data=json.dumps(forged).encode()).returncode != 0
    docker('exec', '-i', endpoints_name, 'hatchward-configure', data=json.dumps(config).encode())
    # A host helper receives `C` + the endpoint index when the agent dials the endpoint.
    helper = subprocess.Popen(['docker', 'exec', '-i', endpoints_name, '/usr/local/bin/hatchward-channel'],
                              stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    for _ in range(40):
        if docker('exec', endpoints_name, 'test', '-e', '/run/hatchward/bridge/channels.ready',
                  check=False).returncode == 0:
            break
        time.sleep(.25)
    print(docker('exec', '-i', endpoints_name, 'hatchward-run', '/usr/bin/python3', '-c', ENDPOINTS,
                 data=b'{"agent":{}}').stdout.decode())
    assert helper.stdout.read(2) == b'C\x01'
    assert helper.stdout.read(5) == b'D\x00\x00\x00\x01'
    helper.kill()
    helper.wait()
    print('PASS endpoint traffic opens a C channel with its index')
finally:
    remove(endpoints_name)
