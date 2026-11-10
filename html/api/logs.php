<?php
declare(strict_types=1);

require_once __DIR__ . '/auth.php';
require_once __DIR__ . '/db.php';
require_login();
header('Content-Type: application/json; charset=utf-8');
date_default_timezone_set('Asia/Shanghai');

initDatabase();
$db = db();

$search = trim((string)($_GET['search'] ?? ''));
$startTime = trim((string)($_GET['start_time'] ?? ''));
$endTime = trim((string)($_GET['end_time'] ?? ''));
$page = max(1, (int)($_GET['page'] ?? 1));
$limit = min(5000, max(1, (int)($_GET['limit'] ?? 50))); // 移动端累计加载超过 200 条时，允许接口继续返回后续记录。

function parseFilterTime(string $value, bool $end = false): ?int {
    if ($value === '') return null;
    try {
        if (preg_match('/^\d{4}-\d{2}-\d{2}$/', $value)) {
            $value .= $end ? ' 23:59:59' : ' 00:00:00';
        }
        $dt = new DateTime($value, new DateTimeZone('Asia/Shanghai'));
        return $dt->getTimestamp();
    } catch (Throwable $e) {
        return null;
    }
}

function bindParams(SQLite3Stmt $stmt, array $params): void {
    foreach ($params as $name => $value) {
        $type = is_int($value) ? SQLITE3_INTEGER : SQLITE3_TEXT;
        $stmt->bindValue($name, $value, $type);
    }
}

function fetchRows(string $sql, array $params = []): array {
    $stmt = db()->prepare($sql);
    bindParams($stmt, $params);
    $result = $stmt->execute();
    $rows = [];
    if ($result) {
        while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
            $rows[] = $row;
        }
    }
    return $rows;
}

$conditions = [];
$params = [];
$now = time();

$startTs = parseFilterTime($startTime, false);
$endTs = parseFilterTime($endTime, true);
if ($startTs !== null) {
    $conditions[] = 'l.ts >= :start_ts';
    $params[':start_ts'] = $startTs;
}
if ($endTs !== null) {
    $conditions[] = 'l.ts <= :end_ts';
    $params[':end_ts'] = $endTs;
}

// 永久隐藏已明确确认不存在的 Token 的全部历史日志；查询异常不会写入 user_id=0，因此仍会显示。
$conditions[] = "NOT EXISTS (SELECT 1 FROM v2board_user_cache vnf WHERE vnf.token=l.token AND vnf.user_id=0)";

$ftsEnabled = (string)(dbScalar("SELECT value FROM app_meta WHERE key='fts_trigram_enabled'") ?? '0') === '1';
$useFts = $ftsEnabled && mb_strlen($search, 'UTF-8') >= 3 && !strpbrk($search, '%_\\');
if ($search !== '') {
    $escaped = str_replace(['\\', '%', '_'], ['\\\\', '\\%', '\\_'], mb_strtolower($search));
    $like = '%' . $escaped . '%';

    $remarkMap = [
        '拉取订阅' => [200],
        '伪造请求' => [400],
        '未授权请求' => [401],
        '异常用户' => [403],
        '路径错误' => [404],
        '请求过多' => [429],
        '服务异常' => [500, 502, 503],
    ];
    $remarkStatuses = [];
    foreach ($remarkMap as $remark => $statuses) {
        if (mb_stripos($remark, $search) !== false || mb_stripos($search, $remark) !== false) {
            $remarkStatuses = array_merge($remarkStatuses, $statuses);
        }
    }

    if ($useFts) {
        // FTS5 trigram 加速包含式匹配；用户资料字段规模远小于日志表，仍走本地缓存 LIKE。
        $searchSql = [
            'l.id IN (SELECT rowid FROM logs_search WHERE ip LIKE :search)',
            'l.id IN (SELECT rowid FROM logs_search WHERE token LIKE :search)',
            'l.id IN (SELECT rowid FROM logs_search WHERE ua LIKE :search)',
            'l.id IN (SELECT rowid FROM logs_search WHERE request_uri LIKE :search)',
            'l.id IN (SELECT rowid FROM logs_search WHERE day LIKE :search)',
            'i.rowid IN (SELECT rowid FROM ip_info_search WHERE info LIKE :search)',
        ];
    } else {
        $searchSql = [
            'LOWER(l.ip) LIKE :search ESCAPE \'\\\'',
            'LOWER(COALESCE(i.info, \'\')) LIKE :search ESCAPE \'\\\'',
            'LOWER(l.token) LIKE :search ESCAPE \'\\\'',
            'LOWER(l.ua) LIKE :search ESCAPE \'\\\'',
            'LOWER(l.request_uri) LIKE :search ESCAPE \'\\\'',
            'l.day LIKE :search ESCAPE \'\\\'',
        ];
    }
    $searchSql[] = 'CAST(l.status AS TEXT) LIKE :search ESCAPE \'\\\'';
    $searchSql[] = 'LOWER(COALESCE(vc.email, \'\')) LIKE :search ESCAPE \'\\\'';
    $searchSql[] = 'CAST(COALESCE(vc.user_id, 0) AS TEXT) LIKE :search ESCAPE \'\\\'';
    $searchSql[] = 'LOWER(COALESCE(vc.plan_name, \'\')) LIKE :search ESCAPE \'\\\'';
    $searchSql[] = 'LOWER(COALESCE(vc.remarks, \'\')) LIKE :search ESCAPE \'\\\'';

    if ($remarkStatuses) {
        $placeholders = [];
        foreach (array_values(array_unique($remarkStatuses)) as $i => $status) {
            $name = ':remark_' . $i;
            $placeholders[] = $name;
            $params[$name] = $status;
        }
        $searchSql[] = 'l.status IN (' . implode(',', $placeholders) . ')';
    }
    $conditions[] = '(' . implode(' OR ', $searchSql) . ')';
    $params[':search'] = $like;
}

$where = $conditions ? 'WHERE ' . implode(' AND ', $conditions) : '';
$from = 'FROM logs l LEFT JOIN ip_info i ON i.ip=l.ip LEFT JOIN v2board_user_cache vc ON vc.token=l.token';

$offset = ($page - 1) * $limit;
// 日志接口只读取 SQLite，不在首屏/翻页请求中等待 V2Board。用户信息先显示缓存，
// 随后由前端独立请求 v2board_enrich.php 更新，避免远程 API 拖慢日志列表。
$dataSql = "SELECT l.id, l.ts, l.ip, COALESCE(i.info, '') AS ip_info, l.token, l.status, l.ua,
                   COALESCE(vc.user_id,0) AS cache_user_id, COALESCE(vc.email,'') AS cache_email,
                   COALESCE(vc.plan_name,'') AS cache_plan_name, COALESCE(vc.remarks,'') AS cache_remarks,
                   COALESCE(vc.banned,0) AS cache_banned, COALESCE(vc.fetched_at,0) AS cache_fetched_at
            FROM logs l LEFT JOIN ip_info i ON i.ip=l.ip LEFT JOIN v2board_user_cache vc ON vc.token=l.token
            $where ORDER BY l.ts DESC, l.id DESC LIMIT :limit OFFSET :offset";
$dataRows = fetchRows($dataSql, array_merge($params, [':limit' => $limit, ':offset' => $offset]));

// 统计结果按筛选条件缓存 5 秒；与首页 5 秒刷新周期一致，避免每次轮询都扫描全量日志。
// 将已确认不存在 Token 的可见性版本纳入缓存键，避免并发请求在缓存清理后又写回旧总数。
$visibilityVersion = (int)(dbScalar("SELECT value FROM app_meta WHERE key='logs_visibility_version'") ?? 0);
$statsCacheKey = hash('sha256', json_encode([
    'search' => $search, 'start' => $startTime, 'end' => $endTime,
    'visibility_version' => $visibilityVersion
], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
$statsPayload = null;
$cachedStats = fetchRows('SELECT generated_at,payload FROM logs_stats_cache WHERE cache_key=:key', [':key' => $statsCacheKey]);
if ($cachedStats && (int)$cachedStats[0]['generated_at'] > $now - 5) {
    $decodedStats = json_decode((string)$cachedStats[0]['payload'], true);
    if (is_array($decodedStats)) $statsPayload = $decodedStats;
}
// 分页数据与统计缓存可能因新日志写入、Token 被确认不存在等情况短暂不同步。
// 不仅空页要重算；如果缓存总数判断当前页越界，但 SQL 实际已经取到了数据，也必须重算，
// 否则前端会误判页码越界并跳页。
$cachedTotal = $statsPayload !== null ? (int)($statsPayload['total'] ?? 0) : null;
$actualRowsThroughPage = (($page - 1) * $limit) + count($dataRows);
$pageNeedsFreshStats = (
    $page > 1 && count($dataRows) === 0
) || (
    $cachedTotal !== null && (
        $actualRowsThroughPage > $cachedTotal ||
        ($page > 1 && $page > max(1, (int)ceil($cachedTotal / $limit)))
    )
);
if ($pageNeedsFreshStats) {
    $statsPayload = null;
}
if ($statsPayload === null) {
    $stats = db()->prepare("SELECT COUNT(*) AS total, COUNT(DISTINCT l.ip) AS total_ips, SUM(CASE WHEN l.status=200 THEN 1 ELSE 0 END) AS total_success, COUNT(DISTINCT CASE WHEN l.status=200 AND l.token <> '-' THEN l.token END) AS total_success_tokens $from $where");
    bindParams($stats, $params);
    $statsRow = $stats->execute()->fetchArray(SQLITE3_ASSOC) ?: [];
    $statsPayload = [
        'total' => (int)($statsRow['total'] ?? 0),
        'total_ips' => (int)($statsRow['total_ips'] ?? 0),
        'total_success' => (int)($statsRow['total_success'] ?? 0),
        'total_success_tokens' => (int)($statsRow['total_success_tokens'] ?? 0)
    ];
    $saveStats = db()->prepare('INSERT INTO logs_stats_cache(cache_key,generated_at,payload) VALUES(:key,:time,:payload) ON CONFLICT(cache_key) DO UPDATE SET generated_at=excluded.generated_at,payload=excluded.payload');
    $saveStats->bindValue(':key', $statsCacheKey, SQLITE3_TEXT);
    $saveStats->bindValue(':time', $now, SQLITE3_INTEGER);
    $saveStats->bindValue(':payload', json_encode($statsPayload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES), SQLITE3_TEXT);
    $saveStats->execute();
    db()->exec('DELETE FROM logs_stats_cache WHERE generated_at < ' . ($now - 300));
}
$total = (int)$statsPayload['total'];
$totalIps = (int)$statsPayload['total_ips'];
$totalSuccess = (int)$statsPayload['total_success'];
$totalError = $total - $totalSuccess;
$totalSuccessTokens = (int)$statsPayload['total_success_tokens'];
$errorRate = $total > 0 ? round(($totalError / $total) * 100, 1) : 0;

$data = [];
foreach ($dataRows as $row) {
    $token = (string)$row['token'];
    $matched = (int)$row['cache_user_id'] > 0;
    $lookupStatus = $token === '-' ? 'not_applicable' : ($matched ? 'matched' : 'pending');
    $data[] = [
        'time' => date('Y-m-d H:i:s', (int)$row['ts']),
        'ip' => $row['ip'],
        'ip_info' => $row['ip_info'] !== '' ? $row['ip_info'] : '未知地区',
        'token' => $token,
        'status' => (string)$row['status'],
        'ua' => $row['ua'],
        'user_id' => $matched ? (int)$row['cache_user_id'] : null,
        'user_email' => $matched ? (string)$row['cache_email'] : '',
        'plan_name' => $matched ? (string)$row['cache_plan_name'] : '',
        'user_remark' => $matched ? (string)$row['cache_remarks'] : '',
        'user_banned' => $matched ? ((int)$row['cache_banned'] === 1) : false,
        'v2board_status' => $lookupStatus
    ];
}

// 今日分析只读取现有缓存，不在日志列表请求中执行四组全表聚合。
// 缓存过期后的重算由 analytics.php 独立完成，避免首页/翻页等待分析 SQL。
$tz = new DateTimeZone('Asia/Shanghai');
$today = (new DateTime('today', $tz))->format('Y-m-d');
$cachedAnalytics = fetchRows('SELECT payload FROM daily_analytics_cache WHERE day=:day', [':day' => $today]);
$analytics = ['top_ips' => [], 'top_tokens' => [], 'sus_tokens' => [], 'sus_ips' => []];
if ($cachedAnalytics) {
    $decoded = json_decode((string)$cachedAnalytics[0]['payload'], true);
    if (is_array($decoded)) $analytics = $decoded;
}

echo json_encode([
    'total' => $total,
    'total_ips' => $totalIps,
    'total_success' => $totalSuccess,
    'total_error' => $totalError,
    'total_success_tokens' => $totalSuccessTokens,
    'error_rate' => $errorRate,
    'analytics' => $analytics,
    'page' => $page,
    'limit' => $limit,
    'data' => $data
], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
?>
