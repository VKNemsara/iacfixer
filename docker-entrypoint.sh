#!/bin/sh
set -eu

# Docker sockets commonly use a host-specific numeric group. Discover that group
# after the socket is mounted, give the unprivileged application user access, then
# drop root before running the web service.
if [ -S /var/run/docker.sock ]; then
    socket_gid="$(stat -c '%g' /var/run/docker.sock)"
    socket_group="$(getent group "${socket_gid}" | cut -d: -f1 || true)"
    if [ -z "${socket_group}" ]; then
        socket_group="docker-socket"
        groupadd -g "${socket_gid}" "${socket_group}"
    fi
    usermod -aG "${socket_group}" appuser
fi

# A named volume is mounted over this directory at runtime. Ensure the account
# used by the web service owns its Antigravity OAuth profile and CLI settings.
chown -R appuser:appuser /home/appuser

exec setpriv --reuid=appuser --regid=appuser --init-groups -- "$@"
