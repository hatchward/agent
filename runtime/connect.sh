#!/bin/sh
# ssh ProxyCommand helper; runs as the calling user with no extra privilege.
unset PYTHONPATH PYTHONHOME
exec /usr/bin/python3 -I /usr/local/lib/hatchward/runtime/connect.py "$@"
