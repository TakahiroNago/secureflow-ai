#!/bin/sh
# SecureFlow AI — production entrypoint (docker/php/Dockerfile target prod).
# The configuration, route and event caches are built from the container's environment at every start, so the
# image holds no configuration and no secret. Then the service's own command runs (php-fpm, queue:work, ...).
set -eu
cd /var/www/html
php artisan config:cache --no-ansi --quiet
php artisan route:cache --no-ansi --quiet
php artisan event:cache --no-ansi --quiet
exec "$@"
