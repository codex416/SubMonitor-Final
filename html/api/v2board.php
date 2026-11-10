<?php
declare(strict_types=1);

require_once __DIR__ . '/db.php';

const V2B_CONFIG_FILE = '/opt/SubMonitor/secrets/v2board_config.enc';
const V2B_SESSION_FILE = '/opt/SubMonitor/secrets/v2board_session.enc';
const V2B_KEY_FILE = '/opt/SubMonitor/secrets/.v2board.key';

function v2b_key(): string {
    if (!is_file(V2B_KEY_FILE)) {
        $key = random_bytes(32);
        if (@file_put_contents(V2B_KEY_FILE, $key, LOCK_EX) === false) {
            throw new RuntimeException('无法创建 V2Board 配置加密密钥');
        }
        @chmod(V2B_KEY_FILE, 0600);
    }
    $key = @file_get_contents(V2B_KEY_FILE);
    if (!is_string($key) || strlen($key) !== 32) {
        throw new RuntimeException('V2Board 配置加密密钥无效');
    }
    return $key;
}

function v2b_write_encrypted(string $file, array $value): void {
    $iv = random_bytes(12);
    $tag = '';
    $plain = json_encode($value, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    $cipher = openssl_encrypt($plain, 'aes-256-gcm', v2b_key(), OPENSSL_RAW_DATA, $iv, $tag);
    if ($cipher === false) throw new RuntimeException('V2Board 配置加密失败');
    $payload = json_encode([
        'iv' => base64_encode($iv),
        'tag' => base64_encode($tag),
        'data' => base64_encode($cipher)
    ]);
    if (@file_put_contents($file, $payload, LOCK_EX) === false) {
        throw new RuntimeException('无法保存 V2Board 配置');
    }
    @chmod($file, 0600);
}

function v2b_read_encrypted(string $file): array {
    if (!is_file($file)) return [];
    $raw = @file_get_contents($file);
    $box = json_decode((string)$raw, true);
    if (!is_array($box)) return [];
    $iv = base64_decode((string)($box['iv'] ?? ''), true);
    $tag = base64_decode((string)($box['tag'] ?? ''), true);
    $cipher = base64_decode((string)($box['data'] ?? ''), true);
    if (!$iv || !$tag || $cipher === false) return [];
    $plain = openssl_decrypt($cipher, 'aes-256-gcm', v2b_key(), OPENSSL_RAW_DATA, $iv, $tag);
    if ($plain === false) return [];
    $data = json_decode($plain, true);
    return is_array($data) ? $data : [];
}

function v2b_config(): array {
    return v2b_read_encrypted(V2B_CONFIG_FILE);
}

function v2b_save_config(array $new): void {
    $old = v2b_config();
    $config = [
        'base_url' => rtrim(trim((string)($new['base_url'] ?? $old['base_url'] ?? '')), '/'),
        'admin_path' => trim(trim((string)($new['admin_path'] ?? $old['admin_path'] ?? '')), '/'),
        'email' => trim((string)($new['email'] ?? $old['email'] ?? '')),
        'password' => (string)($new['password'] ?? '')
    ];
    if ($config['password'] === '') $config['password'] = (string)($old['password'] ?? '');
    if ($config['base_url'] === '' || !filter_var($config['base_url'], FILTER_VALIDATE_URL)) {
        throw new RuntimeException('请填写正确的 V2Board 面板地址');
    }
    if ((string)(parse_url($config['base_url'], PHP_URL_SCHEME) ?? '') !== 'https') {
        throw new RuntimeException('为保护管理员密码，V2Board 面板地址必须使用 HTTPS');
    }
    if ($config['admin_path'] === '' || !preg_match('/^[A-Za-z0-9_-]{8,128}$/', $config['admin_path'])) {
        throw new RuntimeException('后台安全路径至少 8 位，只能包含字母、数字、下划线和连字符');
    }
    if ($config['email'] === '' || $config['password'] === '') {
        throw new RuntimeException('管理员邮箱和密码不能为空');
    }
    v2b_write_encrypted(V2B_CONFIG_FILE, $config);
    @unlink(V2B_SESSION_FILE);
}

function v2b_api_base(): string {
    $c = v2b_config();
    if (empty($c['base_url']) || empty($c['admin_path'])) {
        throw new RuntimeException('尚未配置 V2Board 连接信息');
    }
    return rtrim($c['base_url'], '/') . '/api/v1/' . rawurlencode($c['admin_path']);
}

function v2b_http(string $method, string $url, array $data = [], ?string $auth = null): array {
    if (!function_exists('curl_init')) throw new RuntimeException('PHP cURL 扩展未安装');
    $ch = curl_init();
    $headers = ['Accept: application/json'];
    if ($auth) $headers[] = 'Authorization: ' . $auth;
    $options = [
        CURLOPT_URL => $url,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_CONNECTTIMEOUT => 5,
        CURLOPT_TIMEOUT => 12,
        CURLOPT_HTTPHEADER => $headers,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2
    ];
    if (strtoupper($method) === 'POST') {
        $options[CURLOPT_POST] = true;
        $options[CURLOPT_POSTFIELDS] = http_build_query($data);
        $headers[] = 'Content-Type: application/x-www-form-urlencoded';
        $options[CURLOPT_HTTPHEADER] = $headers;
    }
    curl_setopt_array($ch, $options);
    $body = curl_exec($ch);
    $error = curl_error($ch);
    $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    if ($body === false) throw new RuntimeException('连接 V2Board 失败：' . $error);
    $json = json_decode((string)$body, true);
    if (!is_array($json)) throw new RuntimeException('V2Board 返回了无法识别的数据（HTTP ' . $code . '）');
    return ['http' => $code, 'json' => $json];
}

function v2b_login(bool $force = false): string {
    if (!$force) {
        $session = v2b_read_encrypted(V2B_SESSION_FILE);
        if (!empty($session['auth_data'])) return (string)$session['auth_data'];
    }
    $c = v2b_config();
    if (empty($c['email']) || empty($c['password'])) throw new RuntimeException('请先配置 V2Board 管理员账号和密码');
    $url = rtrim($c['base_url'], '/') . '/api/v1/passport/auth/login';
    $r = v2b_http('POST', $url, ['email' => $c['email'], 'password' => $c['password']]);
    $data = $r['json']['data'] ?? [];
    if ($r['http'] < 200 || $r['http'] >= 300 || empty($data['auth_data'])) {
        $message = $r['json']['message'] ?? $r['json']['msg'] ?? '登录失败，请检查账号密码、验证码或登录风控';
        throw new RuntimeException('V2Board 管理员登录失败：' . (string)$message);
    }
    if (empty($data['is_admin'])) throw new RuntimeException('该账号不是 V2Board 管理员，拒绝继续');
    v2b_write_encrypted(V2B_SESSION_FILE, ['auth_data' => $data['auth_data'], 'saved_at' => time()]);
    return (string)$data['auth_data'];
}

function v2b_api(string $method, string $path, array $data = [], bool $retry = true): array {
    $url = v2b_api_base() . '/' . ltrim($path, '/');
    if (strtoupper($method) === 'GET' && $data) $url .= '?' . http_build_query($data);
    $auth = v2b_login();
    $r = v2b_http($method, $url, strtoupper($method) === 'GET' ? [] : $data, $auth);
    if (in_array($r['http'], [401,403], true) && $retry) {
        @unlink(V2B_SESSION_FILE);
        $auth = v2b_login(true);
        $r = v2b_http($method, $url, strtoupper($method) === 'GET' ? [] : $data, $auth);
    }
    if ($r['http'] < 200 || $r['http'] >= 300 || (isset($r['json']['data']) && $r['json']['data'] === false)) {
        $message = $r['json']['message'] ?? $r['json']['msg'] ?? ('HTTP ' . $r['http']);
        throw new RuntimeException('V2Board 接口调用失败：' . (string)$message);
    }
    return $r['json'];
}

/**
 * V2Board 不同二开版本的 user/fetch 返回结构并不完全一致：
 * 有的直接返回 data 数组，有的返回 Laravel 分页对象（data.data）。
 * 只有明确拿到空列表时才判定用户不存在；结构异常必须作为查询失败处理。
 */
function v2b_extract_user_rows(array $json): array {
    if (!array_key_exists('data', $json) || !is_array($json['data'])) {
        throw new RuntimeException('V2Board user/fetch 返回结构异常');
    }
    $payload = $json['data'];
    if (array_is_list($payload)) return $payload;
    if (array_key_exists('data', $payload) && is_array($payload['data']) && array_is_list($payload['data'])) {
        return $payload['data'];
    }
    throw new RuntimeException('V2Board user/fetch 分页数据结构异常');
}

function v2b_fetch_user(string $key, string $value): ?array {
    $json = v2b_api('GET', 'user/fetch', [
        'filter' => [['key' => $key, 'condition' => '=', 'value' => $value]],
        'current' => 1,
        'pageSize' => 10
    ]);
    $rows = v2b_extract_user_rows($json);
    if (!$rows) return null;
    return is_array($rows[0] ?? null) ? $rows[0] : null;
}


function v2b_fetch_users_multi(array $tokens): array {
    $found = [];
    if (!$tokens) return $found;
    $auth = v2b_login();
    $base = v2b_api_base() . '/user/fetch';
    foreach (array_chunk($tokens, 20) as $chunk) {
        $mh = curl_multi_init();
        $handles = [];
        foreach ($chunk as $token) {
            $query = http_build_query([
                'filter' => [['key' => 'token', 'condition' => '=', 'value' => $token]],
                'current' => 1,
                'pageSize' => 10
            ]);
            $ch = curl_init($base . '?' . $query);
            curl_setopt_array($ch, [
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_CONNECTTIMEOUT => 5,
                CURLOPT_TIMEOUT => 12,
                CURLOPT_HTTPHEADER => ['Accept: application/json', 'Authorization: ' . $auth],
                CURLOPT_SSL_VERIFYPEER => true,
                CURLOPT_SSL_VERIFYHOST => 2
            ]);
            curl_multi_add_handle($mh, $ch);
            $handles[$token] = $ch;
        }
        $running = null;
        do {
            $status = curl_multi_exec($mh, $running);
            if ($running) curl_multi_select($mh, 1.0);
        } while ($running && $status === CURLM_OK);

        $unauthorized = [];
        foreach ($handles as $token => $ch) {
            $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
            $curlError = curl_error($ch);
            $body = curl_multi_getcontent($ch);
            $json = json_decode((string)$body, true);
            if (in_array($code, [401, 403], true)) {
                $unauthorized[] = $token;
            } elseif ($code >= 200 && $code < 300 && is_array($json)) {
                try {
                    $rows = v2b_extract_user_rows($json);
                    $found[$token] = (isset($rows[0]) && is_array($rows[0])) ? $rows[0] : null;
                } catch (Throwable $e) {
                    $found[$token] = ['__lookup_error' => $e->getMessage()];
                }
            } else {
                $found[$token] = ['__lookup_error' => 'V2Board Token 查询失败（HTTP ' . $code . ($curlError !== '' ? '，' . $curlError : '') . '）'];
            }
            curl_multi_remove_handle($mh, $ch);
            curl_close($ch);
        }
        curl_multi_close($mh);

        if ($unauthorized) {
            @unlink(V2B_SESSION_FILE);
            try {
                $auth = v2b_login(true);
                foreach ($unauthorized as $token) {
                    try {
                        $found[$token] = v2b_fetch_user('token', $token);
                    } catch (Throwable $e) {
                        $found[$token] = ['__lookup_error' => $e->getMessage()];
                    }
                }
            } catch (Throwable $e) {
                foreach ($unauthorized as $token) $found[$token] = ['__lookup_error' => $e->getMessage()];
            }
        }
    }
    return $found;
}

function v2b_enrich_tokens(array $tokens): array {
    $result = [];
    $validTokens = array_values(array_unique(array_filter($tokens, static fn($v) => is_string($v) && $v !== '' && $v !== '-')));
    if (!$validTokens) return $result;
    try {
        $config = v2b_config();
    } catch (Throwable $e) {
        error_log('V2Board config read failed: ' . $e->getMessage());
        foreach ($validTokens as $token) $result[$token] = ['lookup_status' => 'error'];
        return $result;
    }
    if (empty($config['base_url']) || empty($config['admin_path']) || empty($config['email']) || empty($config['password'])) {
        foreach ($validTokens as $token) $result[$token] = ['lookup_status' => 'not_configured'];
        return $result;
    }

    $db = db();
    $now = time();
    $missing = [];
    $newNotFound = false;
    // 一次读取当前页全部 Token 缓存，避免每个 Token 单独执行一条 SQLite SELECT。
    $cacheByToken = [];
    if ($validTokens) {
        $placeholders = [];
        $cacheStmt = $db->prepare('SELECT token,user_id,email,plan_name,remarks,banned,fetched_at FROM v2board_user_cache WHERE token IN (' . implode(',', array_map(static fn($i) => ':t' . $i, array_keys($validTokens))) . ')');
        foreach ($validTokens as $i => $token) {
            $name = ':t' . $i;
            $cacheStmt->bindValue($name, $token, SQLITE3_TEXT);
            $placeholders[] = $name;
        }
        $cacheResult = $cacheStmt->execute();
        while ($cacheResult && ($cacheRow = $cacheResult->fetchArray(SQLITE3_ASSOC))) {
            $cacheByToken[(string)$cacheRow['token']] = $cacheRow;
        }
    }
    foreach ($validTokens as $token) {
        $row = $cacheByToken[$token] ?? null;
        if ($row && (int)$row['user_id'] === 0) {
            // 已明确确认不存在的 Token 永久负缓存：Token 不复用，不再重复请求 V2Board。
            $result[$token] = ['lookup_status' => 'not_found'];
        } elseif ($row && (int)$row['fetched_at'] > $now - 60) {
            // 有效用户信息仍使用 60 秒缓存，过期后重新验证。
            $row['lookup_status'] = 'matched';
            $result[$token] = $row;
        } else {
            $missing[] = $token;
        }
    }

    if ($missing) {
        try {
            $users = v2b_fetch_users_multi($missing);
            $cacheWrite = $db->prepare('INSERT INTO v2board_user_cache(token,user_id,email,plan_name,remarks,banned,fetched_at) VALUES(:token,:uid,:email,:plan,:remarks,:banned,:time) ON CONFLICT(token) DO UPDATE SET user_id=excluded.user_id,email=excluded.email,plan_name=excluded.plan_name,remarks=excluded.remarks,banned=excluded.banned,fetched_at=excluded.fetched_at');
            foreach ($missing as $token) {
                // 批量查询必须为每个 Token 返回明确结果；缺少结果视为查询异常，不再追加串行单查。
                if (!array_key_exists($token, $users)) {
                    $result[$token] = ['lookup_status' => 'error'];
                    error_log('V2Board lookup returned no result entry for one token');
                    continue;
                }
                $user = $users[$token];
                if (is_array($user) && isset($user['__lookup_error'])) {
                    $result[$token] = ['lookup_status' => 'error'];
                    error_log('V2Board lookup failed for one token: ' . $user['__lookup_error']);
                    continue;
                }
                $entry = [
                    'user_id' => (int)($user['id'] ?? 0),
                    'email' => (string)($user['email'] ?? ''),
                    'plan_name' => (string)($user['plan_name'] ?? '无订阅'),
                    'remarks' => trim((string)($user['remarks'] ?? '')),
                    'banned' => (int)($user['banned'] ?? 0),
                    'fetched_at' => $now
                ];
                $cacheWrite->bindValue(':token', $token, SQLITE3_TEXT);
                $cacheWrite->bindValue(':uid', $entry['user_id'], SQLITE3_INTEGER);
                $cacheWrite->bindValue(':email', $entry['email'], SQLITE3_TEXT);
                $cacheWrite->bindValue(':plan', $entry['plan_name'], SQLITE3_TEXT);
                $cacheWrite->bindValue(':remarks', $entry['remarks'], SQLITE3_TEXT);
                $cacheWrite->bindValue(':banned', $entry['banned'], SQLITE3_INTEGER);
                $cacheWrite->bindValue(':time', $now, SQLITE3_INTEGER);
                $cacheWrite->execute();
                $cacheWrite->reset();
                if ($entry['user_id'] > 0) {
                    $entry['lookup_status'] = 'matched';
                    $result[$token] = $entry;
                } else {
                    $result[$token] = ['lookup_status' => 'not_found'];
                    $newNotFound = true;
                }
            }
            // 新增永久负缓存后，立即废弃旧分页总数和今日分析缓存，避免总数仍包含刚隐藏的日志。
            if ($newNotFound) {
                // 递增可见性版本：即使并发日志请求稍后写入旧统计缓存，也不会再被新请求使用。
                $db->exec("INSERT INTO app_meta(key,value) VALUES('logs_visibility_version','1')
                    ON CONFLICT(key) DO UPDATE SET value=CAST(COALESCE(value,'0') AS INTEGER)+1");
                $db->exec('DELETE FROM logs_stats_cache');
                $db->exec('DELETE FROM daily_analytics_cache');
            }
        } catch (Throwable $e) {
            error_log('V2Board lookup batch failed: ' . $e->getMessage());
            foreach ($missing as $token) {
                if (!isset($result[$token])) $result[$token] = ['lookup_status' => 'error'];
            }
        }
    }
    return $result;
}

function v2b_set_user_banned(int $userId, bool $banned): void {
    if ($userId <= 0) throw new RuntimeException('用户 ID 无效');
    $user = v2b_fetch_user('id', (string)$userId);
    if (!$user) throw new RuntimeException('V2Board 用户不存在');

    if ($banned) {
        v2b_api('POST', 'user/ban', [
            'filter' => [['key' => 'id', 'condition' => '=', 'value' => $userId]]
        ]);
    } else {
        // UserController::update 会重算 group_id，并可能清除 invite_user_id。
        // 为避免误改资料，先核对套餐分组，并显式保留邀请人。
        $planId = $user['plan_id'] ?? null;
        $groupId = $user['group_id'] ?? null;
        if ($planId) {
            $plans = v2b_api('GET', 'plan/fetch');
            $planRows = $plans['data'] ?? [];
            $plan = null;
            foreach ((array)$planRows as $p) {
                if ((int)($p['id'] ?? 0) === (int)$planId) { $plan = $p; break; }
            }
            if (!$plan || (string)($plan['group_id'] ?? '') !== (string)($groupId ?? '')) {
                throw new RuntimeException('该用户当前套餐分组与套餐配置不一致。为避免解封时改动用户分组，已拒绝操作。');
            }
        } elseif ($groupId !== null && $groupId !== '') {
            throw new RuntimeException('该用户没有套餐但存在独立分组。现有 V2Board 解封接口可能清空分组，已拒绝操作。');
        }

        $inviteEmail = '';
        if (!empty($user['invite_user_id'])) {
            $inviter = v2b_api('GET', 'user/getUserInfoById', ['id' => (int)$user['invite_user_id']]);
            $inviteEmail = (string)($inviter['data']['invite_user']['email'] ?? '');
            if ($inviteEmail === '') throw new RuntimeException('无法确认邀请人邮箱，为保护邀请关系已拒绝解封');
        }
        $payload = [
            'id' => $userId,
            'email' => (string)$user['email'],
            'banned' => 0,
            'is_admin' => (int)($user['is_admin'] ?? 0),
            'is_staff' => (int)($user['is_staff'] ?? 0),
        ];
        if ($planId) $payload['plan_id'] = (int)$planId;
        if ($inviteEmail !== '') $payload['invite_user_email'] = $inviteEmail;
        v2b_api('POST', 'user/update', $payload);
    }

    // Mutation endpoint returned success. Read-back is best-effort so a transient
    // lookup outage cannot turn a completed ban/unban into a misleading failure.
    try {
        $fresh = v2b_fetch_user('id', (string)$userId);
    } catch (Throwable $e) {
        $fresh = null;
        error_log('V2Board post-operation verification failed: ' . $e->getMessage());
    }
    if ($fresh && (int)($fresh['banned'] ?? -1) !== ($banned ? 1 : 0)) {
        throw new RuntimeException('V2Board 接口已返回，但重新查询的封禁状态不一致，请刷新面板确认');
    }
    $effective = $fresh ?: $user;
    $db = db();
    $email = (string)($effective['email'] ?? $user['email'] ?? '');
    $planName = (string)($effective['plan_name'] ?? $user['plan_name'] ?? '无订阅');
    $remarks = trim((string)($effective['remarks'] ?? $user['remarks'] ?? ''));
    $token = (string)($effective['token'] ?? $user['token'] ?? '');
    $stmt = $db->prepare('UPDATE v2board_user_cache SET banned=:banned,email=:email,plan_name=:plan,remarks=:remarks,fetched_at=:time WHERE user_id=:uid');
    $stmt->bindValue(':banned', $banned ? 1 : 0, SQLITE3_INTEGER);
    $stmt->bindValue(':email', $email, SQLITE3_TEXT);
    $stmt->bindValue(':plan', $planName, SQLITE3_TEXT);
    $stmt->bindValue(':remarks', $remarks, SQLITE3_TEXT);
    $stmt->bindValue(':time', time(), SQLITE3_INTEGER);
    $stmt->bindValue(':uid', $userId, SQLITE3_INTEGER);
    $stmt->execute();
    if ($token !== '') {
        $stmt = $db->prepare('INSERT INTO v2board_user_cache(token,user_id,email,plan_name,remarks,banned,fetched_at) VALUES(:token,:uid,:email,:plan,:remarks,:banned,:time) ON CONFLICT(token) DO UPDATE SET user_id=excluded.user_id,email=excluded.email,plan_name=excluded.plan_name,remarks=excluded.remarks,banned=excluded.banned,fetched_at=excluded.fetched_at');
        $stmt->bindValue(':token', $token, SQLITE3_TEXT);
        $stmt->bindValue(':uid', $userId, SQLITE3_INTEGER);
        $stmt->bindValue(':email', $email, SQLITE3_TEXT);
        $stmt->bindValue(':plan', $planName, SQLITE3_TEXT);
        $stmt->bindValue(':remarks', $remarks, SQLITE3_TEXT);
        $stmt->bindValue(':banned', $banned ? 1 : 0, SQLITE3_INTEGER);
        $stmt->bindValue(':time', time(), SQLITE3_INTEGER);
        $stmt->execute();
    }
    $stmt = $db->prepare('INSERT INTO v2board_ban_history(user_id,email,action,created_at) VALUES(:uid,:email,:action,:time)');
    $stmt->bindValue(':uid', $userId, SQLITE3_INTEGER);
    $stmt->bindValue(':email', $email, SQLITE3_TEXT);
    $stmt->bindValue(':action', $banned ? 'ban' : 'unban', SQLITE3_TEXT);
    $stmt->bindValue(':time', time(), SQLITE3_INTEGER);
    $stmt->execute();
}

function v2b_banned_users(): array {
    $all = [];
    $current = 1;
    $pageSize = 200;
    do {
        $json = v2b_api('GET', 'user/fetch', [
            'filter' => [['key' => 'banned', 'condition' => '=', 'value' => 1]],
            'current' => $current,
            'pageSize' => $pageSize,
            'sort' => 'id',
            'sort_type' => 'DESC'
        ]);
        $rows = is_array($json['data'] ?? null) ? $json['data'] : [];
        $all = array_merge($all, $rows);
        $total = (int)($json['total'] ?? count($all));
        $current++;
    } while (count($rows) === $pageSize && count($all) < $total && $current <= 100);
    return $all;
}
