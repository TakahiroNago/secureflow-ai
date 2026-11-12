# SecureFlow AI — production web image: the built SPA and the nginx configuration in the image, no bind mount.
# Versions are pinned; see README "採用バージョン". Built by CI (.github/workflows/release.yml) and run by compose.prod.yaml.

FROM node:24.22.2-alpine3.24 AS build
WORKDIR /app
ENV npm_config_update_notifier=false npm_config_fund=false
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit
COPY frontend/ ./
RUN npm run build

FROM nginx:1.30.6-alpine3.24
COPY docker/nginx/default.conf /etc/nginx/conf.d/default.conf
COPY docker/nginx/snippets/ /etc/nginx/snippets/
# Production only: HSTS (there is TLS in front) and the client address from the load balancer's X-Forwarded-For
# (docs/security-design.md §22 A-1, A-2). The template is rendered from TRUSTED_PROXY_CIDR at start.
COPY docker/nginx/prod/security-headers.conf /etc/nginx/snippets/security-headers.conf
COPY docker/nginx/prod/templates/ /etc/nginx/templates/
COPY --from=build /app/dist/ /usr/share/nginx/html/
# The base image's Alpine packages at the state of its tag, with the fixes Alpine has published since (SCA-01: no HIGH
# with a fix ships in an image we build). Then, as the relay (docker/ai-egress): the whole process runs as the nginx
# user, not only the workers. The image's entrypoint renders the template into conf.d and nginx writes its pid and
# cache, so those are the user's; port 80 needs the ip_unprivileged_port_start sysctl of compose.prod.yaml. The "user"
# directive would only be ignored with a warning.
RUN set -eux; \
    apk upgrade --no-cache; \
    sed -i '/^user /d' /etc/nginx/nginx.conf; \
    touch /var/run/nginx.pid; \
    chown -R nginx:nginx /var/run/nginx.pid /var/cache/nginx /etc/nginx/conf.d
USER nginx
