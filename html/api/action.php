<?php
require_once __DIR__ . '/auth.php';
require_once __DIR__ . '/v2board.php';

// 统一用容器内标准路径，确保100%能找到文件！
define('RULES_DIR',    '/opt/SubMonitor/rules/');
define('NGINX_CONF',   '/etc/nginx/conf.d/default.conf');
define('SSL_DIR',      '/etc/nginx/ssl/');
define('LOGIN_PHP',    __DIR__ . '/login.php'); 
define('ADMIN_PASSWORD_FILE', __DIR__ . '/../.admin_password');

header('Content-Type: application/json; charset=utf-8');
require_login();

// 强制设置时区为北京时间 (UTC+8)，确保获取到的证书到期时间准确
date_default_timezone_set('Asia/Shanghai');

$inputData = json_decode(file_get_contents('php://input'), true) ?? [];
$action = trim($inputData['action'] ?? $_POST['action'] ?? $_GET['action'] ?? '');
$reloadFlag = RULES_DIR . '.reload_flag';

// Log action names only. Never write request bodies, passwords or auth_data to logs.
@error_log("DEBUG_REQUEST: Method=" . $_SERVER['REQUEST_METHOD'] . " | Action=" . $action);

// 强制确保所有目录存在+可写
foreach ([RULES_DIR, SSL_DIR, dirname(NGINX_CONF), dirname(LOGIN_PHP), dirname(ADMIN_PASSWORD_FILE)] as $dir) {
    if (!is_dir($dir)) @mkdir($dir, 0777, true);
    @chmod($dir, 0777);
}

function safeWriteFile(string $filePath, string $content, bool $append = false): bool
{
    $dir = dirname($filePath);
    if (!is_dir($dir)) @mkdir($dir, 0777, true);
    @chmod($dir, 0777);
    if (file_exists($filePath)) @chmod($filePath, 0666);
    $flags = $append ? FILE_APPEND : 0;
    $result = @file_put_contents($filePath, $content, $flags);
    if ($result !== false) { @chmod($filePath, 0666); return true; }
    return false;
}


// ========================================================
// V2Board integration: credentials and user operations stay server-side.
// ========================================================
if ($action === 'v2board_get_config') {
    try {
        $c = v2b_config();
    } catch (Throwable $e) {
        $c = [];
    }
    echo json_encode([
        'status' => 'success',
        'config' => [
            'base_url' => (string)($c['base_url'] ?? ''),
            'admin_path' => (string)($c['admin_path'] ?? ''),
            'email' => (string)($c['email'] ?? ''),
            'password_set' => !empty($c['password'])
        ]
    ], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}

if ($action === 'v2board_save_config') {
    try {
        $old = v2b_config();
    } catch (Throwable $e) {
        $old = [];
    }
    try {
        v2b_save_config([
            'base_url' => $inputData['base_url'] ?? '',
            'admin_path' => $inputData['admin_path'] ?? '',
            'email' => $inputData['email'] ?? '',
            'password' => $inputData['password'] ?? ''
        ]);
        v2b_login(true);
        echo json_encode(['status'=>'success','message'=>'V2Board 连接成功，管理员身份验证通过'], JSON_UNESCAPED_UNICODE);
    } catch (Throwable $e) {
        if ($old) v2b_write_encrypted(V2B_CONFIG_FILE, $old);
        else @unlink(V2B_CONFIG_FILE);
        @unlink(V2B_SESSION_FILE);
        echo json_encode(['status'=>'error','message'=>$e->getMessage()], JSON_UNESCAPED_UNICODE);
    }
    exit;
}

if ($action === 'v2board_test') {
    try {
        v2b_api('GET', 'user/fetch', ['current' => 1, 'pageSize' => 10]);
        echo json_encode(['status'=>'success','message'=>'V2Board 登录成功，管理员接口可用'], JSON_UNESCAPED_UNICODE);
    } catch (Throwable $e) {
        echo json_encode(['status'=>'error','message'=>$e->getMessage()], JSON_UNESCAPED_UNICODE);
    }
    exit;
}

if ($action === 'v2board_set_banned') {
    $userId = (int)($inputData['user_id'] ?? 0);
    $banned = (int)($inputData['banned'] ?? -1);
    if ($userId <= 0 || !in_array($banned, [0,1], true)) {
        echo json_encode(['status'=>'error','message'=>'用户 ID 或封禁状态无效'], JSON_UNESCAPED_UNICODE);
        exit;
    }
    try {
        v2b_set_user_banned($userId, $banned === 1);
        echo json_encode(['status'=>'success','message'=>$banned ? 'V2Board 用户已封禁' : 'V2Board 用户已解封'], JSON_UNESCAPED_UNICODE);
    } catch (Throwable $e) {
        echo json_encode(['status'=>'error','message'=>$e->getMessage()], JSON_UNESCAPED_UNICODE);
    }
    exit;
}

if ($action === 'v2board_banned_list') {
    try {
        $users = v2b_banned_users();
        $list = [];
        foreach ($users as $u) {
            $list[] = [
                'id' => (int)($u['id'] ?? 0),
                'email' => (string)($u['email'] ?? ''),
                'plan_name' => (string)($u['plan_name'] ?? '无订阅'),
                'banned' => (int)($u['banned'] ?? 1)
            ];
        }
        echo json_encode(['status'=>'success','data'=>$list], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    } catch (Throwable $e) {
        echo json_encode(['status'=>'error','message'=>$e->getMessage(),'data'=>[]], JSON_UNESCAPED_UNICODE);
    }
    exit;
}

// ========================================================
// ✅ 1. 更新反代目标域名（使用按行精准定位替换，100%生效）
// ========================================================
if ($action === 'update_upstream') {
    $t = trim($inputData['target_domain'] ?? $_POST['target_domain'] ?? '');
    if (empty($t)) {
        echo json_encode(['status'=>'error','message'=>'域名不能为空'], JSON_UNESCAPED_UNICODE);
        exit;
    }
    $t = preg_replace('/^https?:\/\//i', '', $t);
    $t = rtrim($t, '/');

    if (!file_exists(NGINX_CONF)) {
        echo json_encode(['status'=>'error','message'=>'找不到Nginx配置文件：'.NGINX_CONF], JSON_UNESCAPED_UNICODE);
        exit;
    }

    // 逐行读取并精准替换 backend_url 这一行
    $lines = file(NGINX_CONF);
    $newLines = [];
    $updated = false;
    foreach ($lines as $line) {
        if (strpos($line, '$backend_url') !== false && strpos($line, 'set') !== false) {
            $newLines[] = "        set \$backend_url \"https://{$t}\";\n";
            $updated = true;
        } else {
            $newLines[] = $line;
        }
    }
    
    $c = implode('', $newLines);

    safeWriteFile(RULES_DIR . 'upstream.conf', $t);

    if (!safeWriteFile(NGINX_CONF, $c)) {
        echo json_encode(['status'=>'error','message'=>'写入配置失败，请检查权限'], JSON_UNESCAPED_UNICODE);
        exit;
    }

    @file_put_contents($reloadFlag, (string)time());

    echo json_encode(['status'=>'success','message'=>"✅ 反代域名已更新为：{$t}，配置已触发自动重载"], JSON_UNESCAPED_UNICODE);
    exit;
}

// ========================================================
// ✅ 1.1 获取当前反代目标域名
// ========================================================
if ($action === 'get_upstream') {
    $upstream = '';
    if (file_exists(RULES_DIR . 'upstream.conf')) {
        $upstream = trim(file_get_contents(RULES_DIR . 'upstream.conf'));
    } elseif (file_exists(NGINX_CONF)) {
        $confContent = file_get_contents(NGINX_CONF);
        if (preg_match('/set\s+\$backend_url\s+"https?:\/\/([^"]+)";/i', $confContent, $m)) {
            $upstream = trim($m[1]);
        } elseif (preg_match('/proxy_pass\s+https?:\/\/([^\/;\s]+)/i', $confContent, $m)) {
            $upstream = trim($m[1]);
        }
    }
    echo json_encode(['status' => 'success', 'upstream' => $upstream], JSON_UNESCAPED_UNICODE);
    exit;
}

// ========================================================
// ✅ 2. 更新域名 + 申请证书
// ========================================================
if ($action === 'apply_cert' || $action === 'update_domain') {
    $d = strtolower(trim($inputData['domain'] ?? $_POST['domain'] ?? ''));
    $d = preg_replace('/^https?:\/\//i', '', $d);
    $d = rtrim($d, '.');
    if (empty($d) || !preg_match('/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i', $d)) {
        echo json_encode(['status'=>'error','message'=>'域名不能为空'], JSON_UNESCAPED_UNICODE);
        exit;
    }
    // 提交新域名时先解除旧的域名锁，申请失败也保持 IP 可访问。
    @unlink(RULES_DIR.'.domain_locked');
    @file_put_contents(RULES_DIR.'domain_allow.conf', '');
    @file_put_contents(RULES_DIR.'domain_lock.conf', 'map $host $domain_locked { default 0; }\n');
    safeWriteFile(RULES_DIR.'domain.conf', $d);
    if (!safeWriteFile(RULES_DIR.'.cert_flag', "{$d}\n")) {
        echo json_encode(['status'=>'error','message'=>'写入证书申请标记失败'], JSON_UNESCAPED_UNICODE);
        exit;
    }
    safeWriteFile(RULES_DIR.'cert_status.json', json_encode([
        'status'=>'processing','msg'=>"🔄 域名 {$d} 已提交，后台正在申请证书..."
    ], JSON_UNESCAPED_UNICODE));
    echo json_encode(['status'=>'success','message'=>"✅ 域名 {$d} 已保存，证书申请已在后台启动"], JSON_UNESCAPED_UNICODE);
    exit;
}

// ========================================================
// ✅ 3. 获取证书状态
// ========================================================
if ($action === 'cert_status') {
    $certPath = SSL_DIR.'cert.pem';
    $requestedDomain = file_exists(RULES_DIR.'domain.conf') ? trim(file_get_contents(RULES_DIR.'domain.conf')) : '';
    $isFormal = false;

    if (file_exists($certPath) && $requestedDomain !== '') {
        $pem = @file_get_contents($certPath);
        if ($pem && preg_match('/-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----/s', $pem, $m)) {
            $certData = openssl_x509_parse($m[0]);
            if ($certData) {
                $validToTime = $certData['validTo_time_t'] ?? 0;
                $subjectCn = $certData['subject']['CN'] ?? '';
                $issuerText = json_encode($certData['issuer'] ?? [], JSON_UNESCAPED_UNICODE);
                $domainMatch = (strcasecmp($subjectCn, $requestedDomain) === 0);
                $issuerMatch = preg_match('/Let.s Encrypt|ZeroSSL|Google Trust Services|Buypass/i', $issuerText);
                $isFormal = $domainMatch && $issuerMatch && $validToTime > time();

                if ($isFormal) {
                    $daysLeft = ceil(($validToTime - time()) / 86400);
                    $rawIssuer = $certData['issuer']['CN'] ?? ($certData['issuer']['organizationName'] ?? 'ACME CA');
                    $issuer = preg_match('/YR|Let.s Encrypt/i', $rawIssuer) ? "Let's Encrypt" : $rawIssuer;
                    echo json_encode([
                        'status'=>'success',
                        'cert'=>[
                            'domain'=>$requestedDomain,
                            'issuer'=>$issuer,
                            'valid_to'=>date('Y-m-d H:i:s', $validToTime),
                            'days_left'=>$daysLeft > 0 ? $daysLeft : 0,
                            'locked'=>file_exists(RULES_DIR.'.domain_locked')
                        ]
                    ], JSON_UNESCAPED_UNICODE);
                    exit;
                }
            }
        }
    }

    $certJson = @file_get_contents(RULES_DIR.'cert_status.json');
    if ($certJson) {
        $certData = json_decode($certJson, true);
        if ($certData) {
            echo json_encode([
                'status'=>'success',
                'cert'=>null,
                'state'=>$certData['status'] ?? 'processing',
                'msg'=>$certData['msg'] ?? '证书尚未生成'
            ], JSON_UNESCAPED_UNICODE);
            exit;
        }
    }

    echo json_encode(['status'=>'success','cert'=>null,'state'=>'none','msg'=>'证书尚未生成'], JSON_UNESCAPED_UNICODE);
    exit;
}

// ========================================================
// ✅ 4. 更新黑名单（兼容所有常见命名，并格式化为标准 Nginx 语法）
// ========================================================
if ($action === 'update_blacklist' || $action === 'blacklist' || $action === 'save_blacklist') {
    $ipList = $inputData['ip_blacklist'] ?? $_POST['ip_blacklist'] ?? [];
    $uaList = $inputData['ua_blacklist'] ?? $_POST['ua_blacklist'] ?? [];
    $tokenList = $inputData['token_blacklist'] ?? $_POST['token_blacklist'] ?? [];

    $ipLines = [];
    foreach (array_filter(array_map('trim', $ipList)) as $ip) {
        if (strpos($ip, '#') === 0) continue;
        $clean = str_ireplace(['deny ', ';'], '', $ip);
        if (!empty($clean)) {
            $ipLines[] = "deny {$clean};";
        }
    }
    $ipContent = '# 禁止访问的 IP'."\n" . implode("\n", $ipLines) . "\n";

    $uaLines = [];
    foreach (array_filter(array_map('trim', $uaList)) as $ua) {
        if (strpos($ua, '#') === 0) continue;
        $clean = addslashes($ua);
        if (!empty($clean)) {
            $uaLines[] = "if (\$http_user_agent ~* \"{$clean}\") { return 403; }";
        }
    }
    $uaContent = '# 禁止访问的 UA'."\n" . implode("\n", $uaLines) . "\n";

    $tokenLines = [];
    foreach (array_filter(array_map('trim', $tokenList)) as $token) {
        if (strpos($token, '#') === 0) continue;
        $clean = addslashes($token);
        if (!empty($clean)) {
            $tokenLines[] = "if (\$arg_token = \"{$clean}\") { return 403; }";
        }
    }
    $tokenContent = '# 禁止访问的 Token'."\n" . implode("\n", $tokenLines) . "\n";

    $ok1 = safeWriteFile(RULES_DIR.'ip_blacklist.conf', $ipContent);
    $ok2 = safeWriteFile(RULES_DIR.'ua_blacklist.conf', $uaContent);
    $ok3 = safeWriteFile(RULES_DIR.'token_blacklist.conf', $tokenContent);

    @file_put_contents($reloadFlag, (string)time());

    if ($ok1 && $ok2 && $ok3) {
        echo json_encode(['status'=>'success','message'=>'✅ 黑名单已更新，配置已生效'], JSON_UNESCAPED_UNICODE);
    } else {
        echo json_encode(['status'=>'error','message'=>'⚠️ 部分文件写入失败'], JSON_UNESCAPED_UNICODE);
    }
    exit;
}

// ========================================================
// ✅ 4.1 处理快捷封禁动作 (来自日志页面的快捷封禁，动作名为 ban)
// ========================================================
if ($action === 'ban') {
    $type = trim($inputData['type'] ?? '');
    $value = trim($inputData['value'] ?? '');

    if (empty($type) || empty($value)) {
        echo json_encode(['status'=>'error','message'=>'封禁类型或值不能为空'], JSON_UNESCAPED_UNICODE);
        exit;
    }

    $fileMap = [
        'ip' => RULES_DIR . 'ip_blacklist.conf',
        'ua' => RULES_DIR . 'ua_blacklist.conf',
        'token' => RULES_DIR . 'token_blacklist.conf'
    ];

    if (!isset($fileMap[$type])) {
        echo json_encode(['status'=>'error','message'=>'非法的封禁类型'], JSON_UNESCAPED_UNICODE);
        exit;
    }

    $targetFile = $fileMap[$type];
    
    $currentContent = file_exists($targetFile) ? file_get_contents($targetFile) : '';
    $lines = array_filter(array_map('trim', explode("\n", $currentContent)));
    $lines = array_filter($lines, function($l) { return strpos($l, '#') !== 0; });

    $formattedValue = $value;
    if ($type === 'ip') {
        $clean = str_ireplace(['deny ', ';'], '', $value);
        $formattedValue = "deny {$clean};";
    } elseif ($type === 'ua') {
        $clean = addslashes($value);
        $formattedValue = "if (\$http_user_agent ~* \"{$clean}\") { return 403; }";
    } elseif ($type === 'token') {
        $clean = addslashes($value);
        $formattedValue = "if (\$arg_token = \"{$clean}\") { return 403; }";
    }

    $exists = false;
    foreach ($lines as $line) {
        if ($line === $formattedValue) {
            $exists = true;
            break;
        }
    }

    if (!$exists) {
        $lines[] = $formattedValue;
    }

    $newContent = '# 禁止访问的 ' . strtoupper($type) . "\n" . implode("\n", $lines) . "\n";
    $ok = safeWriteFile($targetFile, $newContent);

    @file_put_contents($reloadFlag, (string)time());

    if ($ok) {
        echo json_encode(['status'=>'success','message'=>"✅ 成功将 [{$value}] 加入 {$type} 黑名单"], JSON_UNESCAPED_UNICODE);
    } else {
        echo json_encode(['status'=>'error','message'=>'⚠️ 写入黑名单文件失败'], JSON_UNESCAPED_UNICODE);
    }
    exit;
}

// ========================================================
// ✅ 4.1.2 处理快捷解封动作 (动作名为 unban 或 remove_blacklist)
// ========================================================
if ($action === 'unban' || $action === 'remove_blacklist') {
    $type = trim($inputData['type'] ?? '');
    $value = trim($inputData['value'] ?? '');

    if (empty($type) || empty($value)) {
        echo json_encode(['status'=>'error','message'=>'解封类型或值不能为空'], JSON_UNESCAPED_UNICODE);
        exit;
    }

    $fileMap = [
        'ip' => RULES_DIR . 'ip_blacklist.conf',
        'ua' => RULES_DIR . 'ua_blacklist.conf',
        'token' => RULES_DIR . 'token_blacklist.conf'
    ];

    if (!isset($fileMap[$type])) {
        echo json_encode(['status'=>'error','message'=>'非法的解封类型'], JSON_UNESCAPED_UNICODE);
        exit;
    }

    $targetFile = $fileMap[$type];
    if (!file_exists($targetFile)) {
        echo json_encode(['status'=>'success','message'=>"✅ 该黑名单文件为空"], JSON_UNESCAPED_UNICODE);
        exit;
    }

    $currentContent = file_get_contents($targetFile);
    $lines = explode("\n", $currentContent);
    $newLines = [];

    foreach ($lines as $line) {
        $trimmed = trim($line);
        if (empty($trimmed) || strpos($trimmed, '#') === 0) {
            $newLines[] = $line;
            continue;
        }

        $matchFound = false;
        if ($type === 'ip') {
            $cleanVal = str_ireplace(['deny ', ';'], '', $value);
            if ($trimmed === "deny {$cleanVal};" || strpos($trimmed, $cleanVal) !== false) {
                $matchFound = true;
            }
        } elseif ($type === 'ua') {
            $cleanVal = addslashes($value);
            if ($trimmed === "if (\$http_user_agent ~* \"{$cleanVal}\") { return 403; }" || strpos($trimmed, $cleanVal) !== false) {
                $matchFound = true;
            }
        } elseif ($type === 'token') {
            $cleanVal = addslashes($value);
            if ($trimmed === "if (\$arg_token = \"{$cleanVal}\") { return 403; }" || strpos($trimmed, $cleanVal) !== false) {
                $matchFound = true;
            }
        }

        if (!$matchFound) {
            $newLines[] = $line;
        }
    }

    $newContent = implode("\n", $newLines);
    $ok = safeWriteFile($targetFile, $newContent);

    @file_put_contents($reloadFlag, (string)time());

    if ($ok) {
        echo json_encode(['status'=>'success','message'=>"✅ 成功将 [{$value}] 从 {$type} 黑名单中解封"], JSON_UNESCAPED_UNICODE);
    } else {
        echo json_encode(['status'=>'error','message'=>'⚠️ 写入黑名单文件失败'], JSON_UNESCAPED_UNICODE);
    }
    exit;
}

// ========================================================
// ✅ 4.2 补丁：获取黑名单完整列表 (对应前端 fetchBlacklistRules)
// ========================================================
if ($action === 'list') {
    $parseIpList = function($filePath) {
        if (!file_exists($filePath)) return [];
        $lines = explode("\n", file_get_contents($filePath));
        $res = [];
        foreach ($lines as $l) {
            $l = trim($l);
            if (empty($l) || strpos($l, '#') === 0) continue;
            $l = preg_replace('/^deny\s+/i', '', $l);
            $l = rtrim($l, ';');
            $res[] = trim($l, '"');
        }
        return array_filter($res);
    };

    $parseUaTokenList = function($filePath) {
        if (!file_exists($filePath)) return [];
        $lines = explode("\n", file_get_contents($filePath));
        $res = [];
        foreach ($lines as $l) {
            $l = trim($l);
            if (empty($l) || strpos($l, '#') === 0) continue;
            if (preg_match('/~*\s*"([^"]+)"/', $l, $m)) {
                $res[] = stripslashes($m[1]);
            } elseif (preg_match('/=\s*"([^"]+)"/', $l, $m)) {
                $res[] = stripslashes($m[1]);
            } else {
                $res[] = ltrim(trim($l), '# ');
            }
        }
        return array_filter($res);
    };

    echo json_encode([
        'status' => 'success',
        'code'   => 200,
        'data'   => [
            'ip'    => $parseIpList(RULES_DIR.'ip_blacklist.conf'),
            'ua'    => $parseUaTokenList(RULES_DIR.'ua_blacklist.conf'),
            'token' => $parseUaTokenList(RULES_DIR.'token_blacklist.conf'),
        ]
    ], JSON_UNESCAPED_UNICODE);
    exit;
}

// ========================================================
// ✅ 5. 读取配置
// ========================================================
if ($action === 'get_config') {
    $domain = '';
    if (file_exists(NGINX_CONF)) {
        $confContent = file_get_contents(NGINX_CONF);
        if (preg_match('/set\s+\$backend_url\s+"https?:\/\/([^"]+)";/i', $confContent, $m)) {
            $domain = trim($m[1]);
        } elseif (preg_match('/proxy_pass\s+https?:\/\/([^\/;\s]+)/i', $confContent, $m)) {
            $domain = trim($m[1]);
        }
    }

    $parseIpList = function($filePath) {
        if (!file_exists($filePath)) return [];
        $lines = explode("\n", file_get_contents($filePath));
        $res = [];
        foreach ($lines as $l) {
            $l = trim($l);
            if (empty($l) || strpos($l, '#') === 0) continue;
            $l = preg_replace('/^deny\s+/i', '', $l);
            $l = rtrim($l, ';');
            $res[] = trim($l, '"');
        }
        return array_filter($res);
    };

    $parseUaTokenList = function($filePath) {
        if (!file_exists($filePath)) return [];
        $lines = explode("\n", file_get_contents($filePath));
        $res = [];
        foreach ($lines as $l) {
            $l = trim($l);
            if (empty($l) || strpos($l, '#') === 0) continue;
            if (preg_match('/~*\s*"([^"]+)"/', $l, $m)) {
                $res[] = stripslashes($m[1]);
            } elseif (preg_match('/=\s*"([^"]+)"/', $l, $m)) {
                $res[] = stripslashes($m[1]);
            } else {
                $res[] = ltrim(trim($l), '# ');
            }
        }
        return array_filter($res);
    };

    echo json_encode([
        'status'=>'success',
        'config'=>[
            'target_domain'=>$domain,
            'ip_blacklist'=>$parseIpList(RULES_DIR.'ip_blacklist.conf'),
            'ua_blacklist'=>$parseUaTokenList(RULES_DIR.'ua_blacklist.conf'),
            'token_blacklist'=>$parseUaTokenList(RULES_DIR.'token_blacklist.conf'),
        ]
    ], JSON_UNESCAPED_UNICODE);
    exit;
}

// ========================================================
// ✅ 6. 修改密码
// ========================================================
if ($action === 'change_password') {
    $old = trim($inputData['old_password'] ?? $_POST['old_password'] ?? '');
    $new = trim($inputData['new_password'] ?? $_POST['new_password'] ?? '');
    
    $currentPassword = file_exists(ADMIN_PASSWORD_FILE) ? trim(file_get_contents(ADMIN_PASSWORD_FILE)) : '';

    if (empty($old) || empty($new)) {
        echo json_encode(['status'=>'error','message'=>'原密码与新密码不能为空'], JSON_UNESCAPED_UNICODE);
        exit;
    }
    if ($old !== $currentPassword) {
        echo json_encode(['status'=>'error','message'=>'原密码校验失败'], JSON_UNESCAPED_UNICODE);
        exit;
    }
    if (strlen($new) < 6) {
        echo json_encode(['status'=>'error','message'=>'新密码长度至少6位'], JSON_UNESCAPED_UNICODE);
        exit;
    }

    if (file_put_contents(ADMIN_PASSWORD_FILE, $new)) {
        @chmod(ADMIN_PASSWORD_FILE, 0600);
        echo json_encode(['status'=>'success','message'=>'✅ 密码修改成功！下次登录用新密码'], JSON_UNESCAPED_UNICODE);
    } else {
        echo json_encode(['status'=>'error','message'=>'❌ 写入失败：请检查目录权限'], JSON_UNESCAPED_UNICODE);
    }
    exit;
}

// ========================================================
echo json_encode(['status'=>'error','message'=>"⚠️ 未知操作：[{$action}]"], JSON_UNESCAPED_UNICODE);
