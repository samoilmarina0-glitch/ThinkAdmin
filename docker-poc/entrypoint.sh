#!/usr/bin/env bash
# ThinkAdmin 安全审计复现环境入口脚本
set -e
cd /app

echo "[*] 准备 .env (SQLite)"
if [ ! -f .env ]; then cp .env.example .env; fi
sed -i 's/^DB_TYPE=.*/DB_TYPE=sqlite/' .env

echo "[*] 发现 ThinkPHP 服务"
php think service:discover >/dev/null 2>&1 || true

echo "[*] 准备数据库迁移文件"
mkdir -p database database/migrations
cp -f vendor/zoujingli/think-plugs-admin/stc/database/*.php database/migrations/ 2>/dev/null || true
cp -f vendor/zoujingli/think-plugs-wechat/stc/database/*.php database/migrations/ 2>/dev/null || true

# 全新建库（每次启动重置，保证确定性复现）
rm -f database/sqlite.db
touch database/sqlite.db

echo "[*] 执行数据库迁移（建表 + 种子 admin/admin）"
php think migrate:run

echo "[*] 注入模拟云存储 AK/SK 与微信密钥（模拟真实部署后台已配置的敏感数据）"
php /app/docker-poc/seed.php

echo "[*] 启动 ThinkAdmin (http://0.0.0.0:8099)"
echo "    后台登录: http://127.0.0.1:8099/admin/login/index.html  (admin / admin)"
exec php -S 0.0.0.0:8099 -t public public/router.php
