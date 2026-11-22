#!/bin/bash
# Never resolve privileged executables through the writable agent home.
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
unset PYTHONPATH PYTHONHOME ENV BASH_ENV
# Trusted contract-3 startup. Never execute image CMD while privileged.
set -euo pipefail
set +x
umask 077
export LC_ALL=C
case "${HATCHWARD_DISK_MIB:-}" in ''|*[!0-9]*) echo 'HATCHWARD_DISK_MIB must be a positive integer' >&2; exit 1;; esac
[ "$HATCHWARD_DISK_MIB" -ge 32 ]
chmod 0600 /dev/fuse
chmod 0700 /hatchward-backing
# Assignment volumes must be fresh. Never reuse an earlier filesystem.
[ ! -e /hatchward-backing/quota.ext4 ]
truncate -s "${HATCHWARD_DISK_MIB}M" /hatchward-backing/quota.ext4
mke2fs -q -F -t ext4 -m 0 -O ^has_journal /hatchward-backing/quota.ext4
mount.fuse3 hatchward-fuse2fs#/hatchward-backing/quota.ext4 /hatchward-bounded -o allow_other,default_permissions,fakeroot,nosuid,nodev,drop_privileges &
fuse_pid=$!
for _ in $(seq 1 100); do
  mountpoint -q /hatchward-bounded && break
  kill -0 "$fuse_pid"
  sleep 0.1
done
mountpoint -q /hatchward-bounded
mkdir /hatchward-bounded/{workspace,home,tmp,run}
# Copy immutable CLI installations before hiding the image's home.
chmod 0755 /hatchward-bounded
chown 1000:1000 /hatchward-bounded/home /hatchward-bounded/workspace
/usr/bin/setpriv --reuid=1000 --regid=1000 --clear-groups --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs cp -a /home/agent/. /hatchward-bounded/home/
chmod 0755 /hatchward-bounded /hatchward-bounded/run
/usr/bin/setpriv --reuid=1000 --regid=1000 --clear-groups --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs chmod 0755 /hatchward-bounded/home /hatchward-bounded/workspace
chmod 1777 /hatchward-bounded/tmp
for mapping in workspace:/workspace home:/home/agent tmp:/tmp tmp:/var/tmp run:/run; do
  mount --bind "/hatchward-bounded/${mapping%%:*}" "${mapping#*:}"
done
mkdir -m 0755 /run/hatchward
mkdir -m 0700 /run/hatchward/bridge
mkdir -m 0755 /run/hatchward/workload
chown 1000:1000 /run/hatchward/workload
ln -s workload/manifest.json /run/hatchward/manifest.json
ln -s gateway/actions.sock /run/hatchward/actions.sock
chown 10002:10002 /run/hatchward/bridge
# Gateway needs to create actions.sock but must not own the run directory.
mkdir -m 0755 /run/hatchward/gateway
chown 10002:10002 /run/hatchward/gateway
/usr/bin/setpriv --reuid=10002 --regid=10002 --clear-groups --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs /usr/bin/python3 -I /usr/local/lib/hatchward/runtime/gateway.py &
gateway_pid=$!
# exec removes the privileged supervisor, retaining child reaping responsibility.
exec /usr/bin/setpriv --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs /usr/bin/python3 -I /usr/local/lib/hatchward/runtime/supervisor.py "$fuse_pid" "$gateway_pid"
