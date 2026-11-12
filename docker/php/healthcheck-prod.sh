#!/bin/sh
# SecureFlow AI — liveness of the production app container (docs/security-design.md §22 A-3).
#
# As in compose.yaml: the code is there and Laravel boots. In addition, the pool has a free worker: php-fpm's status
# page is served by a process of its own (pm.status_listen), so it still answers while every worker waits on a
# database that no longer does (threat-model R-19). Connections queued for a worker mean none is free.
# Unhealthy restarts nothing (docs/architecture.md §4.2): it is for the operator and for scripts/prod/check.sh.
set -u
test -f /var/www/html/artisan || exit 1
php /var/www/html/artisan --version > /dev/null || exit 1
status=$(SCRIPT_NAME=/fpm-status SCRIPT_FILENAME=/fpm-status REQUEST_METHOD=GET \
  cgi-fcgi -bind -connect 127.0.0.1:9001 2> /dev/null) || exit 1
printf '%s\n' "$status" | grep -q '^pool:' || exit 1
queue=$(printf '%s\n' "$status" | awk -F': *' '/^listen queue:/ { print $2 }')
[ "${queue:-1}" -eq 0 ]
