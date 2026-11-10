<?php
declare(strict_types=1);

require_once __DIR__ . '/auth.php';
require_once __DIR__ . '/db.php';
require_login();
header('Content-Type: application/json; charset=utf-8');
date_default_timezone_set('Asia/Shanghai');

initDatabase();
$db = db();
$now = time();
$today = (new DateTime('today', new DateTimeZone('Asia/Shanghai')))->format('Y-m-d');
$lockPath = dirname(SUBMONITOR_DB) . '/.analytics-refresh.lock';
$lock = @fopen($lockPath, 'c');
if ($lock === false || !flock($lock, LOCK_EX)) {
    if (is_resource($lock)) fclose($lock);
    http_response_code(503);
    echo json_encode(['status' => 'error', 'message' => '分析数据正在更新'], JSON_UNESCAPED_UNICODE);
    exit;
}

try {
    $readCache = static function () use ($db, $today): ?array {
        $stmt = $db->prepare('SELECT generated_at,payload FROM daily_analytics_cache WHERE day=:day');
        $stmt->bindValue(':day', $today, SQLITE3_TEXT);
        $row = $stmt->execute()->fetchArray(SQLITE3_ASSOC);
        if (!$row) return null;
        $payload = json_decode((string)$row['payload'], true);
        return is_array($payload) ? ['generated_at' => (int)$row['generated_at'], 'payload' => $payload] : null;
    };

    $cached = $readCache();
    if ($cached && $cached['generated_at'] > $now - 10) {
        echo json_encode(['status' => 'success', 'analytics' => $cached['payload']], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        flock($lock, LOCK_UN);
        fclose($lock);
        exit;
    }

    $maxLogId = (int)($db->querySingle("SELECT COALESCE(MAX(id),0) FROM logs WHERE day='" . SQLite3::escapeString($today) . "'") ?: 0);
    // 与日志列表保持一致：已确认不存在的 Token 永久从统计中排除。
    $validToday = "l.day=:day AND NOT EXISTS (SELECT 1 FROM v2board_user_cache vnf WHERE vnf.token=l.token AND vnf.user_id=0)";
    $fetch = static function (string $sql, array $params) use ($db): array {
        $stmt = $db->prepare($sql);
        foreach ($params as $key => $value) $stmt->bindValue($key, $value, is_int($value) ? SQLITE3_INTEGER : SQLITE3_TEXT);
        $result = $stmt->execute();
        $rows = [];
        while ($result && ($row = $result->fetchArray(SQLITE3_ASSOC))) $rows[] = $row;
        return $rows;
    };
    $params = [':day' => $today];
    $topIps = $fetch("SELECT l.ip, COUNT(*) AS count, COALESCE(i.info,'') AS info FROM logs l LEFT JOIN ip_info i ON i.ip=l.ip WHERE $validToday AND l.ip <> '-' GROUP BY l.ip ORDER BY count DESC, l.ip ASC LIMIT 100", $params);
    $topTokens = $fetch("SELECT l.token, COUNT(*) AS count, MAX(l.ts) AS last_ts FROM logs l WHERE $validToday AND l.token <> '-' GROUP BY l.token ORDER BY count DESC, last_ts DESC LIMIT 100", $params);
    $susTokens = $fetch("SELECT l.token, COUNT(DISTINCT l.ip) AS ipCount FROM logs l WHERE $validToday AND l.token <> '-' AND l.ip <> '-' GROUP BY l.token HAVING COUNT(DISTINCT l.ip) > 1 ORDER BY ipCount DESC, l.token ASC LIMIT 100", $params);
    $susIps = $fetch("SELECT l.ip, COUNT(DISTINCT l.token) AS tokenCount, COALESCE(i.info,'') AS info FROM logs l LEFT JOIN ip_info i ON i.ip=l.ip WHERE $validToday AND l.ip <> '-' AND l.token <> '-' GROUP BY l.ip HAVING COUNT(DISTINCT l.token) > 1 ORDER BY tokenCount DESC, l.ip ASC LIMIT 100", $params);
    $analytics = [
        'top_ips' => array_map(static fn($r) => ['ip'=>$r['ip'], 'count'=>(int)$r['count'], 'info'=>$r['info'] !== '' ? $r['info'] : '未知地区'], $topIps),
        'top_tokens' => array_map(static fn($r) => ['token'=>$r['token'], 'count'=>(int)$r['count'], 'lastTime'=>date('Y-m-d H:i:s', (int)$r['last_ts'])], $topTokens),
        'sus_tokens' => array_map(static fn($r) => ['token'=>$r['token'], 'ipCount'=>(int)$r['ipCount']], $susTokens),
        'sus_ips' => array_map(static fn($r) => ['ip'=>$r['ip'], 'tokenCount'=>(int)$r['tokenCount'], 'info'=>$r['info'] !== '' ? $r['info'] : '未知地区'], $susIps)
    ];
    $save = $db->prepare('INSERT INTO daily_analytics_cache(day,max_log_id,generated_at,payload) VALUES(:day,:max,:time,:payload) ON CONFLICT(day) DO UPDATE SET max_log_id=excluded.max_log_id,generated_at=excluded.generated_at,payload=excluded.payload');
    $save->bindValue(':day', $today, SQLITE3_TEXT);
    $save->bindValue(':max', $maxLogId, SQLITE3_INTEGER);
    $save->bindValue(':time', $now, SQLITE3_INTEGER);
    $save->bindValue(':payload', json_encode($analytics, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES), SQLITE3_TEXT);
    $save->execute();
    echo json_encode(['status' => 'success', 'analytics' => $analytics], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
} catch (Throwable $e) {
    error_log('Daily analytics refresh failed: ' . $e->getMessage());
    http_response_code(500);
    echo json_encode(['status' => 'error', 'message' => '今日分析更新失败'], JSON_UNESCAPED_UNICODE);
} finally {
    flock($lock, LOCK_UN);
    fclose($lock);
}
