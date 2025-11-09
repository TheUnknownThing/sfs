#!/bin/sh
set -eu

# Ensure writable directories exist before dropping privileges
mkdir -p /data /data/storage
chown -R sfs:sfs /data /data/storage

# If no arguments or first arg looks like a flag, run the app by default
if [ "$#" -eq 0 ] || [ "${1#-}" != "$1" ]; then
  set -- /app/simple_file_server "$@"
fi

case "$1" in
  /app/simple_file_server|simple_file_server)
    exec su-exec sfs:sfs "$@"
    ;;
  *)
    exec "$@"
    ;;
esac
