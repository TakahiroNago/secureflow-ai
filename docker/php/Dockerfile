# SecureFlow AI — PHP runtime image (php-fpm / artisan / queue worker / composer)
# Versions are pinned; see README "採用バージョン".
FROM composer:2.11.1 AS composer

FROM php:8.4.27-fpm-alpine3.24 AS base

ARG UID=1000
ARG GID=1000

# Runtime libraries + build-only dependencies for PHP extensions
RUN set -eux; \
    apk add --no-cache libpq icu-libs libzip unzip; \
    apk add --no-cache --virtual .build-deps $PHPIZE_DEPS postgresql-dev icu-dev libzip-dev linux-headers; \
    docker-php-ext-install -j"$(nproc)" pdo_pgsql intl bcmath pcntl zip opcache; \
    pecl install redis-6.3.0; \
    docker-php-ext-enable redis; \
    apk del --no-network .build-deps; \
    rm -rf /tmp/pear ~/.pearrc

COPY --from=composer /usr/bin/composer /usr/local/bin/composer
COPY docker/php/conf.d/ /usr/local/etc/php/conf.d/
COPY docker/php/php-fpm.d/zz-secureflow.conf /usr/local/etc/php-fpm.d/zz-secureflow.conf

# Non-root user matching the WSL2 host user so bind-mounted files keep sane ownership
RUN set -eux; \
    addgroup -g "${GID}" app; \
    adduser -D -u "${UID}" -G app -h /home/app app; \
    mkdir -p /var/www/html; \
    chown app:app /var/www/html

ENV COMPOSER_HOME=/home/app/.composer \
    COMPOSER_NO_INTERACTION=1

WORKDIR /var/www/html
USER app

EXPOSE 9000
CMD ["php-fpm", "--nodaemonize"]

# Development target: adds PCOV for code coverage (Phase 1+)
FROM base AS dev
USER root
RUN set -eux; \
    apk add --no-cache --virtual .build-deps $PHPIZE_DEPS; \
    pecl install pcov-1.0.12; \
    docker-php-ext-enable pcov; \
    apk del --no-network .build-deps; \
    rm -rf /tmp/pear ~/.pearrc
COPY docker/php/conf.d-dev/ /usr/local/etc/php/conf.d/
USER app

# Production target (compose.prod.yaml): the code is in the image, with no development dependency, no coverage driver
# and no bind mount. Nothing in it reads a .env file: the caches are built from the environment at every start.
FROM base AS prod
USER root
# fcgi: cgi-fcgi, with which the healthcheck reads php-fpm's status page (docker/php/healthcheck-prod.sh).
RUN apk add --no-cache fcgi
COPY docker/php/conf.d-prod/ /usr/local/etc/php/conf.d/
COPY docker/php/php-fpm.d-prod/ /usr/local/etc/php-fpm.d/
COPY --chmod=755 docker/php/entrypoint-prod.sh /usr/local/bin/secureflow-entrypoint
COPY --chmod=755 docker/php/healthcheck-prod.sh /usr/local/bin/secureflow-healthcheck
COPY --chown=app:app backend/ /var/www/html/
USER app
RUN set -eux; \
    composer install --no-dev --prefer-dist --no-progress --no-interaction --optimize-autoloader; \
    rm -rf /home/app/.composer/cache
ENTRYPOINT ["secureflow-entrypoint"]
CMD ["php-fpm", "--nodaemonize"]
