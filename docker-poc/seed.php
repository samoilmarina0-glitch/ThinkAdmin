<?php
// 注入模拟 AK/SK，模拟真实部署中管理员在后台配置过云存储 / 微信后的 system_config 状态。
// 这些值为占位假密钥，仅用于演示"读取到 system_config 即泄漏全部密钥"。
// 键名与 think-library 存储类实际使用的 sysconf 键一致 (storage.alioss_secret_key 等)。
$dbFile = __DIR__ . '/../database/sqlite.db';
$db = new PDO('sqlite:' . $dbFile);
$db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

$secrets = [
    ['storage', 'type', 'alioss'],
    // 阿里云 OSS
    ['storage', 'alioss_access_key', 'LTAI5tFAKEak1234567890AB'],
    ['storage', 'alioss_secret_key', 'FAKEsk_aliyun_SeCrEtKeY_000000000000abcd999'],
    ['storage', 'alioss_bucket', 'my-oss-bucket'],
    ['storage', 'alioss_point', 'oss-cn-hangzhou.aliyuncs.com'],
    // 腾讯云 COS
    ['storage', 'txcos_access_key', 'AKIDfake1234567890TencentSecretId00'],
    ['storage', 'txcos_secret_key', 'FAKEtxcos_SecretKey_zzzzzzzzzzzzz999'],
    ['storage', 'txcos_bucket', 'my-cos-bucket-1250000000'],
    // 七牛云
    ['storage', 'qiniu_access_key', 'FAKEqiniu_AccessKey_abcdefg12345'],
    ['storage', 'qiniu_secret_key', 'FAKEqiniu_SecretKey_zyxwvut98765'],
    // 又拍云
    ['storage', 'upyun_access_key', 'upyun_operator_fake'],
    ['storage', 'upyun_secret_key', 'FAKEupyun_password_0123456789'],
    // 微信
    ['wechat', 'appid', 'wxFAKEappid123456'],
    ['wechat', 'appsecret', 'FAKEwechatappsecret0123456789abcd'],
    ['wechat', 'token', 'faketoken123'],
    // JWT 接口密钥 (演示：此处为可预测值；全新未配置时该项为空)
    ['data', 'jwtkey', '0123456789abcdef0123456789abcdef'],
];

$exists = $db->prepare('SELECT COUNT(*) FROM system_config WHERE type=? AND name=?');
$ins = $db->prepare('INSERT INTO system_config (type,name,value) VALUES (?,?,?)');
$upd = $db->prepare('UPDATE system_config SET value=? WHERE type=? AND name=?');
foreach ($secrets as [$t, $n, $v]) {
    $exists->execute([$t, $n]);
    if ($exists->fetchColumn() > 0) {
        $upd->execute([$v, $t, $n]);
    } else {
        $ins->execute([$t, $n, $v]);
    }
}
echo "    [+] 已注入 " . count($secrets) . " 条模拟密钥，system_config 共 "
    . $db->query('SELECT COUNT(*) FROM system_config')->fetchColumn() . " 条\n";
