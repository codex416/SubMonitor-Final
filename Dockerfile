FROM php:8.2-fpm-alpine

RUN apk add --no-cache sqlite libcurl \
    && mkdir -p /opt/SubMonitor/data /opt/SubMonitor/html /opt/SubMonitor/rules /etc/nginx/conf.d /etc/nginx/ssl \
    && chown -R 82:82 /opt/SubMonitor/data /opt/SubMonitor/html /opt/SubMonitor/rules /etc/nginx/conf.d \
    && chmod 775 /opt/SubMonitor/data /opt/SubMonitor/html /opt/SubMonitor/rules /etc/nginx/conf.d

WORKDIR /opt/SubMonitor
