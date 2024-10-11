#!/bin/sh

set -e
user=p2pforge

if [ -n "$DOCKER_DEBUG" ]; then
   set -x
fi

if [ `id -u` -eq 0 ]; then
    echo "Changing user to $user"
    exec su-exec "$user" "$0" $@
fi

# Only supported user can get here
p2p-forge --version

exec p2p-forge $@
