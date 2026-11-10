<?php
declare(strict_types=1);

require_once __DIR__ . '/../html/api/db.php';

date_default_timezone_set('Asia/Shanghai');

initDatabase();

const GEO_CACHE_FILE = '/opt/SubMonitor/rules/ip_cache.json';
const GEO_BATCH_SIZE = 100;
const GEO_SLEEP_SECONDS = 5;

/**
 * 判断是否为公网 IP
 */
function isPublicIp(string $ip): bool
{
    return filter_var(
        $ip,
        FILTER_VALIDATE_IP,
        FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
    ) !== false;
}

/**
 * 判断 IP 是否为有效 IP
 */
function isValidIp(string $ip): bool
{
    return filter_var($ip, FILTER_VALIDATE_IP) !== false;
}

/**
 * 非公网 IP 的说明
 */
function classifyNonPublicIp(string $ip): string
{
    if ($ip === '127.0.0.1' || $ip === '::1') {
        return '本机地址';
    }

    return '非公网地址';
}

/**
 * 查询 IP 归属地
 */
function queryGeo(string $ip): string
{
    $url = 'http://ip-api.com/json/' .
        rawurlencode($ip) .
        '?lang=zh-CN&fields=status,message,country,regionName,city,isp,org';

    $body = false;

    if (function_exists('curl_init')) {
        $ch = curl_init($url);

        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CONNECTTIMEOUT => 2,
            CURLOPT_TIMEOUT => 4,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_USERAGENT => 'SubMonitor/2.0',
            CURLOPT_HTTPHEADER => [
                'Accept: application/json'
            ],
        ]);

        $body = curl_exec($ch);

        curl_close($ch);
    } else {
        $ctx = stream_context_create([
            'http' => [
                'timeout' => 4,
                'ignore_errors' => true,
                'header' =>
                    "Accept: application/json\r\n" .
                    "User-Agent: SubMonitor/2.0\r\n"
            ]
        ]);

        $body = @file_get_contents($url, false, $ctx);
    }

    if (!is_string($body) || $body === '') {
        return '';
    }

    $data = json_decode($body, true);

    if (
        !is_array($data) ||
        ($data['status'] ?? '') !== 'success'
    ) {
        return '';
    }

    $parts = array_filter([
        $data['country'] ?? '',
        $data['regionName'] ?? '',
        $data['city'] ?? '',
        !empty($data['isp'])
            ? '(' . $data['isp'] . ')'
            : '',
    ], static fn($value): bool =>
        trim((string)$value) !== ''
    );

    return trim(implode(' ', $parts));
}

/**
 * 读取 IP JSON 缓存
 */
function loadGeoCache(): array
{
    if (!is_file(GEO_CACHE_FILE)) {
        return [];
    }

    $json = @file_get_contents(GEO_CACHE_FILE);

    if (!is_string($json) || $json === '') {
        return [];
    }

    $cache = json_decode($json, true);

    return is_array($cache) ? $cache : [];
}

/**
 * 写入 IP JSON 缓存
 *
 * 使用临时文件 + rename，
 * 避免直接写入 JSON 时进程中断导致文件损坏。
 */
function saveGeoCache(array $cache): bool
{
    $dir = dirname(GEO_CACHE_FILE);

    if (!is_dir($dir)) {
        return false;
    }

    $json = json_encode(
        $cache,
        JSON_UNESCAPED_UNICODE |
        JSON_UNESCAPED_SLASHES |
        JSON_PRETTY_PRINT
    );

    if ($json === false) {
        error_log(
            '[SubMonitor geo] Failed to encode geo cache: ' .
            json_last_error_msg()
        );

        return false;
    }

    $tmpFile = GEO_CACHE_FILE . '.tmp';

    if (
        @file_put_contents(
            $tmpFile,
            $json,
            LOCK_EX
        ) === false
    ) {
        error_log(
            '[SubMonitor geo] Failed to write geo cache'
        );

        return false;
    }

    if (!@rename($tmpFile, GEO_CACHE_FILE)) {
        @unlink($tmpFile);

        error_log(
            '[SubMonitor geo] Failed to replace geo cache'
        );

        return false;
    }

    return true;
}

/**
 * 保存归属地到 SQLite
 */
function saveGeoToDatabase(
    string $ip,
    string $info,
    int $now
): void {
    $stmt = db()->prepare(
        'INSERT INTO ip_info(ip,info,updated_at)
         VALUES(:ip,:info,:now)
         ON CONFLICT(ip) DO UPDATE SET
            info=excluded.info,
            updated_at=excluded.updated_at'
    );

    if ($stmt === false) {
        throw new RuntimeException(
            'Failed to prepare SQLite statement'
        );
    }

    $stmt->bindValue(
        ':ip',
        $ip,
        SQLITE3_TEXT
    );

    $stmt->bindValue(
        ':info',
        $info,
        SQLITE3_TEXT
    );

    $stmt->bindValue(
        ':now',
        $now,
        SQLITE3_INTEGER
    );

    $result = $stmt->execute();

    if ($result === false) {
        throw new RuntimeException(
            'Failed to save geo info to SQLite: ' . $ip
        );
    }
}

/**
 * 获取待处理 IP
 *
 * 使用 DISTINCT，避免同一个 IP 因为存在多条日志而重复出现。
 */
function getPendingIps(): array
{
    $rows = [];

    $result = db()->query(
        "SELECT DISTINCT l.ip
         FROM logs l
         LEFT JOIN ip_info i ON i.ip = l.ip
         WHERE i.ip IS NULL
           AND l.ip <> '-'
         LIMIT " . GEO_BATCH_SIZE
    );

    if ($result === false) {
        return [];
    }

    while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
        $ip = trim((string)($row['ip'] ?? ''));

        if ($ip === '') {
            continue;
        }

        if (!isValidIp($ip)) {
            continue;
        }

        $rows[] = $ip;
    }

    return array_values(array_unique($rows));
}

/**
 * 主循环
 */
while (true) {
    try {
        $now = time();

        $cache = loadGeoCache();

        $pendingIps = getPendingIps();

        if (empty($pendingIps)) {
            sleep(GEO_SLEEP_SECONDS);
            continue;
        }

        $cacheChanged = false;

        foreach ($pendingIps as $ip) {

            /*
             * 非公网 IP：
             *
             * 不需要调用第三方 Geo API。
             * 直接写入 SQLite，避免每轮重复处理。
             */
            if (!isPublicIp($ip)) {
                $info = classifyNonPublicIp($ip);

                saveGeoToDatabase(
                    $ip,
                    $info,
                    $now
                );

                echo "[Geo] Non-public -> DB: {$ip} => {$info}\n";

                continue;
            }

            /*
             * 优先使用 JSON 缓存。
             */
            if (
                array_key_exists($ip, $cache) &&
                is_string($cache[$ip]) &&
                trim($cache[$ip]) !== ''
            ) {
                $info = trim($cache[$ip]);

                saveGeoToDatabase(
                    $ip,
                    $info,
                    $now
                );

                echo "[Geo] Cache -> DB: {$ip} => {$info}\n";

                continue;
            }

            /*
             * JSON 没有缓存，查询 API。
             */
            $info = queryGeo($ip);

            if ($info === '') {
                echo "[Geo] Query failed: {$ip}\n";
                continue;
            }

            /*
             * API 查询成功：
             *
             * 1. 写 JSON 缓存
             * 2. 写 SQLite
             */
            $cache[$ip] = $info;
            $cacheChanged = true;

            saveGeoToDatabase(
                $ip,
                $info,
                $now
            );

            echo "[Geo] API -> Cache + DB: {$ip} => {$info}\n";
        }

        /*
         * 只有 API 真正产生新缓存时，
         * 才重新写入 ip_cache.json。
         */
        if ($cacheChanged) {
            if (saveGeoCache($cache)) {
                echo "[Geo] Cache file updated.\n";
            }
        }

    } catch (Throwable $e) {
        error_log(
            '[SubMonitor geo] ' . $e->getMessage()
        );
    }

    sleep(GEO_SLEEP_SECONDS);
}
