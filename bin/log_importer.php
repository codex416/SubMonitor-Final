<?php
declare(strict_types=1);

require_once __DIR__ . '/../html/api/db.php';

date_default_timezone_set('Asia/Shanghai');

const LOG_FILE = '/opt/SubMonitor/rules/access.log';
const POLL_SECONDS = 2;

initDatabase();

/**
 * 将旧版 ip_cache.json 一次性迁移到 SQLite。
 */
function migrateIpCache(): void
{
    $marker = db()->querySingle(
        "SELECT value FROM app_meta WHERE key='ip_cache_migrated'"
    );

    if ($marker === '1') {
        return;
    }

    $file = '/opt/SubMonitor/rules/ip_cache.json';

    if (is_readable($file)) {
        $raw = @file_get_contents($file);
        $cache = is_string($raw) ? json_decode($raw, true) : null;

        if (is_array($cache)) {
            $stmt = db()->prepare(
                'INSERT INTO ip_info(ip,info,updated_at)
                 VALUES(:ip,:info,:now)
                 ON CONFLICT(ip)
                 DO UPDATE SET
                    info=excluded.info,
                    updated_at=excluded.updated_at'
            );

            foreach ($cache as $ip => $value) {
                $info = is_array($value)
                    ? ($value['info'] ?? ($value['location'] ?? ''))
                    : $value;

                $info = is_string($info) ? trim($info) : '';

                if ($info === '' || $info === '未知地区') {
                    continue;
                }

                $stmt->bindValue(':ip', (string)$ip, SQLITE3_TEXT);
                $stmt->bindValue(':info', $info, SQLITE3_TEXT);
                $stmt->bindValue(':now', time(), SQLITE3_INTEGER);
                $stmt->execute();
            }
        }
    }

    db()->exec(
        "INSERT INTO app_meta(key,value)
         VALUES('ip_cache_migrated','1')
         ON CONFLICT(key)
         DO UPDATE SET value='1'"
    );
}

migrateIpCache();

/**
 * 从 URL 中提取 token。
 */
function extractToken(string $url): string
{
    $parsed = parse_url($url);

    $path = $parsed['path'] ?? $url;
    $query = $parsed['query'] ?? '';

    if ($query !== '') {
        parse_str($query, $params);

        if (!empty($params['token'])) {
            return (string)$params['token'];
        }
    }

    if ($path !== '/' && $path !== '') {
        foreach (explode('/', trim($path, '/')) as $seg) {
            if (
                strpos($seg, '.') === false
                && strlen($seg) >= 8
                && !in_array(
                    $seg,
                    ['sub', 'api', 'static', 'admin', 'login'],
                    true
                )
            ) {
                return $seg;
            }
        }
    }

    return '-';
}

/**
 * 解析 Nginx access.log 单行日志。
 */
function parseAccessLine(string $line): ?array
{
    if (
        !preg_match(
            '/^(\S+) \S+ \S+ \[(.*?)\] "(?:GET|POST|HEAD) (\S+) HTTP\/[^"]+" (\d{3}) \d+ "([^"]*)" "([^"]*)"/',
            $line,
            $m
        )
    ) {
        return null;
    }

    $ip = $m[1];
    $timeRaw = $m[2];
    $url = $m[3];
    $status = (int)$m[4];
    $ua = $m[6];

    $parsed = parse_url($url);
    $path = $parsed['path'] ?? $url;

    /*
     * 排除：
     * - 普通 API 请求
     * - 首页
     * - index.html
     * - login.html
     * - 静态资源
     */
    if (
        (
            strpos($path, '/api/') !== false
            && strpos($path, 'cert') === false
            && strpos($path, 'domain') === false
        )
        || $path === '/'
        || $path === '/index.html'
        || $path === '/login.html'
        || preg_match(
            '/\.(js|css|ico|png|jpg|html|txt|woff)$/i',
            $path
        )
    ) {
        return null;
    }

    $dt = DateTime::createFromFormat(
        'd/M/Y:H:i:s O',
        $timeRaw
    );

    if (!$dt) {
        return null;
    }

    $dt->setTimezone(
        new DateTimeZone('Asia/Shanghai')
    );

    return [
        'ts' => $dt->getTimestamp(),
        'day' => $dt->format('Y-m-d'),
        'ip' => $ip,
        'token' => extractToken($url),
        'status' => $status,
        'ua' => $ua,
        'request_uri' => $url,
    ];
}

/**
 * 获取 importer 当前状态。
 *
 * importer_state 是全量/增量导入的唯一依据。
 */
function currentState(): array
{
    $row = db()->querySingle(
        'SELECT inode, file_size, offset
         FROM importer_state
         WHERE id=1',
        true
    );

    if (is_array($row)) {
        return $row;
    }

    return [
        'inode' => 0,
        'file_size' => 0,
        'offset' => 0,
    ];
}

/**
 * 保存 importer 状态。
 */
function saveState(
    int $inode,
    int $size,
    int $offset
): void {
    $stmt = db()->prepare(
        'UPDATE importer_state
         SET inode=:inode,
             file_size=:size,
             offset=:offset,
             updated_at=:now
         WHERE id=1'
    );

    $stmt->bindValue(
        ':inode',
        $inode,
        SQLITE3_INTEGER
    );

    $stmt->bindValue(
        ':size',
        $size,
        SQLITE3_INTEGER
    );

    $stmt->bindValue(
        ':offset',
        $offset,
        SQLITE3_INTEGER
    );

    $stmt->bindValue(
        ':now',
        time(),
        SQLITE3_INTEGER
    );

    $stmt->execute();
}

/**
 * 导入 access.log。
 *
 * importer_state 控制：
 *
 * 1. 新数据库：
 *    inode=0 / offset=0
 *    → 从 access.log 开头全量导入
 *
 * 2. access.log inode 发生变化：
 *    → 日志轮转
 *    → 从头重新导入
 *
 * 3. access.log 文件大小小于保存的 offset：
 *    → 日志被截断
 *    → 从头重新导入
 *
 * 4. inode 和 offset 都正常：
 *    → 从上次 offset 增量导入
 */
function importLog(): int
{
    if (!is_readable(LOG_FILE)) {
        return 0;
    }

    clearstatcache(true, LOG_FILE);

    $st = @stat(LOG_FILE);

    if (!$st) {
        return 0;
    }

    $inode = (int)$st['ino'];
    $size = (int)$st['size'];

    $state = currentState();

    $stateInode = (int)$state['inode'];
    $offset = (int)$state['offset'];

    /*
     * 全量导入触发条件：
     *
     * 1. 新数据库 / importer_state 尚未初始化
     * 2. 日志文件发生轮转
     * 3. 日志文件被截断
     */
    if (
        $stateInode === 0
        || $stateInode !== $inode
        || $size < $offset
    ) {
        $offset = 0;
    }

    /*
     * 没有新增日志。
     */
    if ($size <= $offset) {
        saveState(
            $inode,
            $size,
            $offset
        );

        return 0;
    }

    $fp = @fopen(LOG_FILE, 'rb');

    if (!$fp) {
        return 0;
    }

    if (fseek($fp, $offset, SEEK_SET) !== 0) {
        fclose($fp);
        return 0;
    }

    $db = db();

    $insert = $db->prepare(
        'INSERT OR IGNORE INTO logs(
            log_key,
            ts,
            day,
            ip,
            token,
            status,
            ua,
            request_uri
        )
        VALUES(
            :key,
            :ts,
            :day,
            :ip,
            :token,
            :status,
            :ua,
            :uri
        )'
    );

    $count = 0;

    /*
     * 只有完整写入数据库后才推进 offset。
     */
    $lastSafeOffset = $offset;

    $db->exec('BEGIN IMMEDIATE');

    try {
        while (($line = fgets($fp)) !== false) {
            $lineEndOffset = ftell($fp);

            /*
             * Nginx 可能正在写最后一条日志。
             * 如果最后一行没有换行符，则暂不消费。
             * 下一轮继续读取。
             */
            if (
                $lineEndOffset !== false
                && !str_ends_with($line, "\n")
            ) {
                break;
            }

            $parsed = parseAccessLine(
                rtrim($line, "\r\n")
            );

            if ($parsed !== null) {
                /*
                 * 使用：
                 *
                 * inode + 行开始位置
                 *
                 * 作为物理日志行唯一标识。
                 */
                $key = $inode . ':' . $lastSafeOffset;

                $insert->bindValue(
                    ':key',
                    $key,
                    SQLITE3_TEXT
                );

                $insert->bindValue(
                    ':ts',
                    $parsed['ts'],
                    SQLITE3_INTEGER
                );

                $insert->bindValue(
                    ':day',
                    $parsed['day'],
                    SQLITE3_TEXT
                );

                $insert->bindValue(
                    ':ip',
                    $parsed['ip'],
                    SQLITE3_TEXT
                );

                $insert->bindValue(
                    ':token',
                    $parsed['token'],
                    SQLITE3_TEXT
                );

                $insert->bindValue(
                    ':status',
                    $parsed['status'],
                    SQLITE3_INTEGER
                );

                $insert->bindValue(
                    ':ua',
                    $parsed['ua'],
                    SQLITE3_TEXT
                );

                $insert->bindValue(
                    ':uri',
                    $parsed['request_uri'],
                    SQLITE3_TEXT
                );

                $insert->execute();

                $count++;
            }

            /*
             * 当前这一行已经完整消费，
             * 可以安全推进 offset。
             */
            if ($lineEndOffset !== false) {
                $lastSafeOffset = (int)$lineEndOffset;
            }
        }

        $db->exec('COMMIT');
    } catch (Throwable $e) {
        $db->exec('ROLLBACK');

        fclose($fp);

        error_log(
            '[SubMonitor importer] ' . $e->getMessage()
        );

        return 0;
    }

    fclose($fp);

    /*
     * 只有事务成功后才保存新的 offset。
     */
    saveState(
        $inode,
        $size,
        $lastSafeOffset
    );

    return $count;
}

/**
 * 持续监控 access.log。
 */
while (true) {
    try {
        $count = importLog();

        if ($count > 0) {
            echo '[Importer] imported '
                . $count
                . " lines\n";
        }
    } catch (Throwable $e) {
        error_log(
            '[SubMonitor importer] ' . $e->getMessage()
        );
    }

    sleep(POLL_SECONDS);
}