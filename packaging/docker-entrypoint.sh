#!/bin/sh
# The `nextfix` command inside the image, for the container's own start and for
# `docker exec`: `nextfix scan /project`, `nextfix user add <name> --role admin`, and
# `nextfix serve`, which listens on all interfaces of the container unless told otherwise
# (NEXTFIX_HOST, NEXTFIX_PORT, or the same flags after `serve`; a later flag wins).
set -e
if [ "$1" = "serve" ]; then
  shift
  set -- serve --host "${NEXTFIX_HOST:-0.0.0.0}" --port "${NEXTFIX_PORT:-8790}" --no-open "$@"
fi
exec node /app/nextfix.cjs "$@"
