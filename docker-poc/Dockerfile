# ThinkAdmin 安全审计复现环境
# 说明：直接复用仓库里已 `composer install` 的 vendor/，构建期不联网。
FROM php:8.3-cli

# 安装 PDO SQLite / GD（图形验证码用）等扩展
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends libsqlite3-dev libpng-dev libzip-dev unzip; \
    docker-php-ext-install pdo pdo_sqlite gd zip; \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# 复制整个项目（含已安装的 vendor、已复制的 migrations）
COPY . /app

# 入口脚本：准备 .env、建库迁移、注入模拟 AK/SK、启动内置服务器
RUN chmod +x /app/docker-poc/entrypoint.sh

EXPOSE 8099
ENTRYPOINT ["/app/docker-poc/entrypoint.sh"]
