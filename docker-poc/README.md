# ThinkAdmin 安全审计 — Docker 复现环境

配套报告见仓库根 `SECURITY-AUDIT.md`。本目录提供一键复现环境与 PoC。

## 启动

```bash
# 在仓库根目录执行（需已 composer install 过 vendor/）
docker compose -f docker-poc/docker-compose.yml up --build
```

启动后：
- 后台登录：http://127.0.0.1:8099/admin/login/index.html  （默认 `admin` / `admin`）
- 入口脚本会自动：建库迁移 → 注入模拟云 AK/SK（见 `seed.php`）→ 启动服务。

> 说明：镜像直接复用仓库里已安装的 `vendor/`，构建期不需要 composer 联网。
> 若无 Docker，可等价地本地运行：
> ```bash
> cp .env.example .env && sed -i 's/^DB_TYPE=.*/DB_TYPE=sqlite/' .env
> php think service:discover
> mkdir -p database/migrations && cp vendor/zoujingli/think-plugs-*/stc/database/*.php database/migrations/
> php think migrate:run && php docker-poc/seed.php
> php -S 127.0.0.1:8099 -t public public/router.php
> ```

## PoC

### A1 — 验证码明文泄漏 + 默认超管 ⇒ 未认证读取云 AK/SK（端到端）
```bash
bash docker-poc/poc_exploit.sh http://127.0.0.1:8099
```
预期输出：泄漏的明文验证码 → `{"code":1,"info":"登录成功"}` → 逐条打印 alioss/txcos/qiniu 的 `access_key` 与 `secret_key`。

### A2 — 可预测/空 `data.jwtkey` ⇒ 未认证 PHP 对象注入（unserialize 原语）
```bash
php docker-poc/poc_deser.php
```
预期：空密钥与可预测密钥下均触发攻击者对象的 `__wakeup()`/`__destruct()`，证明 `/admin/api.plugs/script?uptoken=` 路径的 `CodeExtend::decrypt` → `unserialize` 可被伪造 token 控制。

## 文件
- `Dockerfile` / `docker-compose.yml` / `.dockerignore`
- `entrypoint.sh`：建库 + 注入模拟密钥 + 启动
- `seed.php`：模拟 AK/SK（占位假值，键名与存储类实际使用一致）
- `poc_exploit.sh` / `poc_deser.php`：PoC
