# ThinkAdmin 安全审计 — findings.md (唯一真相源)

## 目标
未认证 0-click，可泄漏 AK/SK 的漏洞。搭建 Docker 复现。

## 框架字典 (开审前建立)
- 框架: ThinkAdmin v6 (ThinkPHP 6 基座)
- 依赖: topthink/think-orm ^2|^3, zoujingli/think-library ^6.1, zoujingli/think-plugs-admin ^1.0, zoujingli/think-plugs-wechat ^1.0
- 应用层很薄 (app/)，真实逻辑在 vendor 依赖
- config/app.php: cors_on=true (全局CORS), rbac_ignore=['index'], super_user='admin'
- config/route.php: default_app=index, url_html_suffix=html

### 实际版本 (composer install 后)
- topthink/framework **v8.1.4** (ThinkPHP 8)
- topthink/think-orm v3.0.34
- zoujingli/think-library **v6.1.98**
- zoujingli/think-plugs-admin **v1.0.79**
- zoujingli/think-plugs-wechat v1.0.52
- zoujingli/wechat-developer v1.1.17

### source
- `input()`, `$this->request->get/post/param`, 路由变量
- Library.php HttpRun: 所有输入经 `xss_safe()` 过滤 (默认)
### sink (AK/SK)
- sysconf('storage.xxx') 读写; 存储类 AliossStorage/QiniuStorage/TxcosStorage/UpyunStorage 用 AK/SK
### sanitizer / 鉴权 (★可达性原语★)
- RbacAccess 中间件: rbac_ignore=['index'] 整个应用免检; 否则 AdminService::check()
- **方法默认公开**: NodeService::_parseComment 仅当方法注释含 `@auth true` 或 `@login true` 才需鉴权
- check(): `empty(isauth)` → `return !(islogin && !isLogin())`; 无注解=isauth0/islogin0 → 返回 true (公开)
- => **任何非 index 应用、无 @auth true/@login true 注解的 public 方法 = 未认证可达**
- CORS: cors_host 默认空 → 任意 Origin 回显 + Allow-Credentials:true (链条)
### n-day CVE (待补)

## 已探索入口 / 已覆盖维度
- (进行中) 代码库结构梳理

## 事实 (Fact)
- F1: 应用层 app/admin/controller 存在 Config.php (存储配置含AK/SK), File.php, api/Upload.php, api/System.php, Login.php
- F2: cors_on=true 全局开启

## 意图 (Intent) 队列
- I1: AK/SK 存储在哪？config 读取/写入接口是否需认证？
- I2: 是否有未认证接口回显存储配置 (storage-alioss/txcos/qiniu/upyun)
- I3: 鉴权中间件放行规则 (rbac_ignore, login check)
- I4: n-day: ThinkPHP6 / ThinkAdmin 已知CVE

## 未认证 0-click 端点清单 (去重, app 覆盖 vendor)
admin 应用:
- admin/index/index (@menu? 实际 Index 控制器)
- admin/login/{index,captcha,out}
- admin/api.plugs/script  → 仅回显 taDebug/taAdmin/taEditor, 无AK/SK
- admin/api.upload/index  → initUnid(false) 完全公开, 仅回显 exts/nameType
- admin/api.upload/{state,file,image,done} → initUnid(true), 需 admin登录 或 上传令牌(session) ⇒ 默认未认证被挡
wechat 应用 (插件):
- wechat/api.js/{index,sdk}
- wechat/api.login/{qrc,oauth,query}
- wechat/api.push/{geoip,index}  ← 微信消息回调, 真0-click
- wechat/api.test/{jsapi,jssdk,oauth,notify,scanOneNotify}
- wechat/api.view/{news,item,text,image,video,voice}

## 关键事实
- F3: secret 明文存 system_config 表; sysconf('') 返回整个配置数组; `|raw` 取原值. 
  => 赢condition: 未认证读 system_config = 全部 AK/SK 明文
- F4: SystemService::get() 非raw时对值做 htmlspecialchars (仅转义HTML, 不影响泄漏)
- F5: Upload::state() 的 alioss/txcos 分支回显 AK (OSSAccessKeyId / q-ak) + 签名, 但需 initUnid 通过; txcos q-ak = 腾讯SecretId(AK)
- F6: data.jwtkey 默认 = sysconf('data.jwtkey')?:md5(uniqid(rand)) 安装时随机生成 (非硬编码)

## 证伪 (falsified)
- 排序注入 layTable order("{_field_} {_order_}"): think-orm v3.0.34 Builder::parseOrder 用
  /^[\w\.]+$/ 校验字段名 + ASC/DESC 白名单 ⇒ 不可注入 (Builder.php:543-556). 且相关list端点需认证.

## Docker/本地复现环境 (已搭建)
- DB=sqlite (database/sqlite.db), 迁移已跑 (migrate:run), admin/admin (passhash=md5('admin'))
- 已插入模拟 AK/SK: storage.alioss.secret, storage.txcos.secretKey, storage.qiniu.secret_key,
  wechat.appsecret, data.jwtkey=0123...(32位) 等
- 本地服务: php -S 127.0.0.1:8099 -t public public/router.php
- 实测: index→302; admin/api.upload/index→200(未认证可达); upload/state→"未登录"(需认证);
  wechat/api.push/geoip→返回IP; plugs/script→taDebug=true(debug开)

## 证伪 (追加)
- 多语言 LFI/RCE: LoadLangPack::detect 用 /^([a-z\d\-]+)/i 只取字母数字连字符前缀(无/与.),
  且 allow_lang_list=['zh-cn'] 白名单 ⇒ langSet 不可控, 无路径穿越 (framework LoadLangPack.php)
- [Worker2] SSTI/LFI/SSRF 未认证面全部证伪:
  - View::fetch() 模板名全硬编码(think-view parseTemplate), 输入只进模板变量; think-template
    先把模板文件编译成缓存再运行时注入变量值 → 变量值永不经 parse/compiler, 无SSTI
    (Template.php fetch L222/read L250); display()从不接收输入(grep 0命中)
  - Js::index referer→getWebOauthInfo/getWebJssdkSign: 微信SDK host 硬编码 api.weixin.qq.com,
    getJsSign 从不 fetch $url ⇒ 无SSRF (wechat-developer Oauth.php/Script.php)
  - Push::_keys→MediaService::upload: $url 取自 WechatKeys/WechatNews 表(管理员设), 攻击者
    只控匹配哪个关键字, 不控URL ⇒ 无攻击者定向SSRF
  - composer audit: 依赖无已知CVE (本地缓存)
- 附带(非目标类): View::text/image/video/voice/music 反射型XSS
  (`{$content|raw}` + strip_tags允许<img> ⇒ <img src=x onerror=>) wechat/api.view/text?content=
  **实测确认**: curl wechat/api.view/text.html?content=<img src=x onerror=alert(document.domain)> 原样回显
- [Worker1] 未认证 SQLi 全部证伪:
  - xss_safe (common.php:359-364) 只删<script>和 on<word>= 事件处理器, 不碰引号/#/括号/SQL关键字
  - think-orm v3.0.34: WHERE/IN/BETWEEN 值全绑定(bindValue); WHERE字段名 parseKey strict
    /^[\w\.\*]+$/ 抛异常 (Mysql.php:411); ORDER /^[\w\.]+$/+ASC/DESC白名单
  - Push::_keys: table/field 硬编码"WechatKeys"/"keys", 攻击者只控被绑定的$value
  - View::item/news, Login用户名, FansService::set: 键名常量, 值绑定
  - 潜在弱点(不可达): think-orm MySQL parseKey 对 ->/->> JSON字段在strict正则前插值未绑定
    (Mysql.php:382-394), 但全仓无端点把HTTP输入送入标识符位(字段名) ⇒ 不可利用
  - 结论: 未认证面无可读 system_config 的 SQLi

## 发现 (confirmed / suspected)
### ★A1 [CONFIRMED][未认证,0-click,端到端已现场验证] 验证码明文泄漏 → 默认超管登录 → 云AK/SK
- 位置: app/admin/controller/Login.php:123-125 captcha(); CaptchaService.php:75 code存cache[uniqid]
- 数据流: captcha() 当 session 无 'LoginInputSessionError' 标志时, JSON 直接回显明文 code;
  JwtSession.php:77-82 会话ID由 var_session_id 请求参或cookie决定(攻击者可控) → 每次新会话无错误标志
  → code 恒泄漏; 登录动作无限流/无锁定
- 登录校验 Login.php:93: md5($user['password'] . $uniqid) === 提交password
  → 存储hash即登录共享秘密; 默认超管 admin 的 hash=md5("admin")=21232f...(公开)
  → 攻击者构造 password=md5("21232f...".uniqid) 无需明文口令
- super_user=admin → AdminService::check() 直接放行全部 → 读 config/storage 得全部 AK/SK
- 现场验证: captcha泄明文E9U6 → 登录{"code":1} → config/storage?type=alioss/txcos/qiniu 回显
  alioss_access_key/secret_key, txcos_access_key/secret_key, qiniu_access_key/secret_key 全部明文
- 前置条件: 默认口令未改(或配合下面的无限暴破弱md5口令)
- 反证排除: 唯一反自动化控制=验证码, 已被明文泄漏击穿; 无CSRF保护读取(GET); 无限流

### ★A2 [CONFIRMED原语][未认证,0-click] 可预测/空 data.jwtkey → PHP对象注入(unserialize)
- 位置: CodeExtend.php:139 decrypt()=unserialize(openssl_decrypt(..,$skey,..))
- 未认证sink: GET /admin/api.plugs/script?uptoken=<forged>  (Plugs.php:82 无@auth)
  → AdminService::withUploadUnid($token) (AdminService.php:298) → CodeExtend::decrypt($uptoken, sysconf('data.jwtkey'))
- 密钥条件: data.jwtkey 为空(全新/纯cookie会话实例, 从未触发 JwtExtend::jwtkey() 自动生成)
  或弱/可预测. 空密钥时 AES-256-CBC 用全零密钥, 确定性 → 攻击者用空密钥 encrypt(serialize(gadget)) 伪造
- 现场验证(harness): 空密钥''与可预测密钥均成功 decrypt→unserialize 触发 __wakeup/__destruct, 攻击者控对象类型/属性
- 到AK/SK: 需 POP gadget 链 [SUSPECTED]. think-orm v3.0.34 Model __destruct→save 链已移除
  (__wakeup→initialize(), Connection::__destruct→close() 均良性) ⇒ 本依赖集无现成RCE gadget, 未证实完整链
- 另一sink: jwt-token头 → JwtExtend::verify → decrypt($payload['enc']) 也 unserialize; 但 verify 内
  jwtkey() 在空密钥时先自动生成随机密钥再验签 ⇒ 此sink空密钥不可伪造(自愈); 仅 uptoken sink 空密钥可用

### 证伪(关键目标相关)
- Upload::state() 回显 txcos q-ak/alioss OSSAccessKeyId: 需 initUnid(unid>0); withUploadToken 全仓零调用
  ⇒ AdminUploadUnid 永不被设 ⇒ 未认证恒被挡"未登录". 死路.
- JWT 伪造成 admin: verify 空密钥自愈(先生成随机密钥); payload 不写入 user.id ⇒ 不成立
- A5 弱口令存储: SystemUser 口令 md5 无盐; 结合A1验证码击穿 ⇒ 任意账号在线无限暴破(弱口令可破)

### C1 [confirmed][链条元素,非0click] CORS 任意源反射 + 凭据
- 位置: vendor/zoujingli/think-library/src/Library.php register() CORS中间件
- 数据流: app.cors_on 默认true; cors_host 默认空 → `empty($hosts)` → 回显任意 Origin;
  Access-Control-Allow-Credentials: true
- 实测: Origin: https://evil.example.com 被原样回显 + Allow-Credentials:true
- 影响: 需诱导已登录管理员访问恶意页 → 恶意JS带cookie请求 admin/config/storage (GET) 读取
  AK/SK. 属 1-click, 不满足"0click未认证"目标, 仅作链条.
- 反证排除: cors_host 若配置则限制; 但默认空=全开.
