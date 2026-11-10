<?php
declare(strict_types=1);

const SUBMONITOR_DB = '/opt/SubMonitor/data/submonitor.db';

function db(): SQLite3 {
    static $db = null;
    if ($db instanceof SQLite3) {
        return $db;
    }

    $dir = dirname(SUBMONITOR_DB);
    if (!is_dir($dir)) {
        @mkdir($dir, 0777, true);
    }

    $db = new SQLite3(SUBMONITOR_DB, SQLITE3_OPEN_READWRITE | SQLITE3_OPEN_CREATE);
    // 等待导入器或其他 PHP 请求释放 SQLite 写锁，避免并发访问立即报 database is locked。
    $db->busyTimeout(15000);
    // WAL is enabled once during database initialization; avoid changing journal mode on every request.
    $db->exec('PRAGMA synchronous=NORMAL;');
    $db->exec('PRAGMA temp_store=MEMORY;');
    $db->exec('PRAGMA cache_size=-32000;');
    $db->exec('PRAGMA mmap_size=67108864;');
    $db->exec('PRAGMA foreign_keys=ON;');
    return $db;
}

function initDatabase(): void {
    static $initialized = false;
    if ($initialized) return;

    $db = db();
    $lockPath = dirname(SUBMONITOR_DB) . '/.db-init.lock';
    $lockHandle = @fopen($lockPath, 'c');
    if ($lockHandle === false) {
        throw new RuntimeException('无法创建 SQLite 初始化锁文件，请检查 data 目录权限：' . $lockPath);
    }

    // PHP-FPM 的每个请求都有独立的 static 状态，因此必须跨进程串行化初始化。
    if (!flock($lockHandle, LOCK_EX)) {
        fclose($lockHandle);
        throw new RuntimeException('无法取得 SQLite 初始化锁，请检查文件锁及 data 目录权限');
    }

    try {
        // 锁内再次检查版本，避免多个并发请求重复执行建表、FTS 回填和索引创建。
        $metaTableExists = (int)dbScalar(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='app_meta'"
        ) > 0;
        if ($metaTableExists) {
            $schemaVersion = (string)(dbScalar("SELECT value FROM app_meta WHERE key='schema_version'") ?? '');
            if ($schemaVersion === '3') {
                $initialized = true;
                return;
            }
        }

        // WAL 模式只在初始化/升级时设置，不在每个普通请求中反复切换。
        $db->exec('PRAGMA journal_mode=WAL;');
        $db->exec(<<<SQL
CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    log_key TEXT NOT NULL UNIQUE,
    ts INTEGER NOT NULL,
    day TEXT NOT NULL,
    ip TEXT NOT NULL,
    token TEXT NOT NULL DEFAULT '-',
    status INTEGER NOT NULL,
    ua TEXT NOT NULL DEFAULT '',
    request_uri TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_logs_ts ON logs(ts DESC);
CREATE INDEX IF NOT EXISTS idx_logs_ts_id ON logs(ts DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_logs_day ON logs(day);
CREATE INDEX IF NOT EXISTS idx_logs_day_id ON logs(day, id DESC);
CREATE INDEX IF NOT EXISTS idx_logs_ip ON logs(ip);
CREATE INDEX IF NOT EXISTS idx_logs_token ON logs(token);
CREATE INDEX IF NOT EXISTS idx_logs_status_ts ON logs(status, ts);
CREATE INDEX IF NOT EXISTS idx_logs_day_ip ON logs(day, ip);
CREATE INDEX IF NOT EXISTS idx_logs_day_token ON logs(day, token);

CREATE TABLE IF NOT EXISTS ip_info (
    ip TEXT PRIMARY KEY,
    info TEXT NOT NULL DEFAULT '',
    updated_at INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS importer_state (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    inode INTEGER NOT NULL DEFAULT 0,
    file_size INTEGER NOT NULL DEFAULT 0,
    offset INTEGER NOT NULL DEFAULT 0,
    updated_at INTEGER NOT NULL DEFAULT 0
);
INSERT OR IGNORE INTO importer_state(id) VALUES (1);

CREATE TABLE IF NOT EXISTS app_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS v2board_user_cache (
    token TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL DEFAULT 0,
    email TEXT NOT NULL DEFAULT '',
    plan_name TEXT NOT NULL DEFAULT '',
    remarks TEXT NOT NULL DEFAULT '',
    banned INTEGER NOT NULL DEFAULT 0,
    fetched_at INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_v2board_user_cache_uid ON v2board_user_cache(user_id);
CREATE INDEX IF NOT EXISTS idx_v2board_user_cache_status_time ON v2board_user_cache(user_id, fetched_at);
CREATE TABLE IF NOT EXISTS v2board_ban_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    email TEXT NOT NULL DEFAULT '',
    action TEXT NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_v2board_ban_history_uid_time ON v2board_ban_history(user_id, created_at DESC);
CREATE TABLE IF NOT EXISTS daily_analytics_cache (
    day TEXT PRIMARY KEY,
    max_log_id INTEGER NOT NULL DEFAULT 0,
    generated_at INTEGER NOT NULL DEFAULT 0,
    payload TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS logs_stats_cache (
    cache_key TEXT PRIMARY KEY,
    generated_at INTEGER NOT NULL DEFAULT 0,
    payload TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_logs_stats_cache_time ON logs_stats_cache(generated_at);
SQL);
        // IP 归属地只影响展示文案，不应让每次 Geo 更新都清空今日统计缓存；统计按短 TTL 自动刷新。
        $db->exec('DROP TRIGGER IF EXISTS daily_analytics_cache_ip_ai');
        $db->exec('DROP TRIGGER IF EXISTS daily_analytics_cache_ip_au');
        $db->exec('DROP TRIGGER IF EXISTS daily_analytics_cache_ip_ad');

        // 向前兼容旧数据库：为既有 Token 缓存增加备注字段。
        $columns = [];
        $columnResult = $db->query('PRAGMA table_info(v2board_user_cache)');
        while ($columnResult && ($column = $columnResult->fetchArray(SQLITE3_ASSOC))) {
            $columns[$column['name']] = true;
        }
        if (!isset($columns['remarks'])) {
            $db->exec("ALTER TABLE v2board_user_cache ADD COLUMN remarks TEXT NOT NULL DEFAULT ''");
        }

        // SQLite FTS5 trigram 可用时启用包含式搜索；不可用时回退到原 LIKE 查询。
        $ftsEnabled = false;
        try {
            $db->exec("CREATE VIRTUAL TABLE IF NOT EXISTS logs_search USING fts5(ip, token, ua, request_uri, day, tokenize='trigram')");
            $db->exec("CREATE VIRTUAL TABLE IF NOT EXISTS ip_info_search USING fts5(info, tokenize='trigram')");
            $db->exec(<<<'FTS'
CREATE TRIGGER IF NOT EXISTS logs_search_ai AFTER INSERT ON logs BEGIN
    INSERT INTO logs_search(rowid,ip,token,ua,request_uri,day) VALUES(new.id,new.ip,new.token,new.ua,new.request_uri,new.day);
END;
CREATE TRIGGER IF NOT EXISTS logs_search_ad AFTER DELETE ON logs BEGIN
    DELETE FROM logs_search WHERE rowid=old.id;
END;
CREATE TRIGGER IF NOT EXISTS logs_search_au AFTER UPDATE ON logs BEGIN
    DELETE FROM logs_search WHERE rowid=old.id;
    INSERT INTO logs_search(rowid,ip,token,ua,request_uri,day) VALUES(new.id,new.ip,new.token,new.ua,new.request_uri,new.day);
END;
CREATE TRIGGER IF NOT EXISTS ip_info_search_ai AFTER INSERT ON ip_info BEGIN
    INSERT INTO ip_info_search(rowid,info) VALUES(new.rowid,new.info);
END;
CREATE TRIGGER IF NOT EXISTS ip_info_search_ad AFTER DELETE ON ip_info BEGIN
    DELETE FROM ip_info_search WHERE rowid=old.rowid;
END;
CREATE TRIGGER IF NOT EXISTS ip_info_search_au AFTER UPDATE ON ip_info BEGIN
    DELETE FROM ip_info_search WHERE rowid=old.rowid;
    INSERT INTO ip_info_search(rowid,info) VALUES(new.rowid,new.info);
END;
FTS);
            $ftsReady = (int)dbScalar("SELECT COUNT(*) FROM app_meta WHERE key='fts_trigram_backfilled'") === 1;
            if (!$ftsReady) {
                $db->exec("INSERT INTO logs_search(rowid,ip,token,ua,request_uri,day) SELECT l.id,l.ip,l.token,l.ua,l.request_uri,l.day FROM logs l WHERE NOT EXISTS (SELECT 1 FROM logs_search f WHERE f.rowid=l.id)");
                $db->exec("INSERT INTO ip_info_search(rowid,info) SELECT i.rowid,i.info FROM ip_info i WHERE NOT EXISTS (SELECT 1 FROM ip_info_search f WHERE f.rowid=i.rowid)");
                $db->exec("INSERT OR REPLACE INTO app_meta(key,value) VALUES('fts_trigram_backfilled','1')");
            }
            $ftsEnabled = true;
        } catch (Throwable $e) {
            // FTS 不可用时保留原 LIKE 搜索，不影响日志主表和日志导入。
            error_log('FTS5 trigram unavailable; fallback to LIKE search: ' . $e->getMessage());
        }

        $ftsValue = $ftsEnabled ? '1' : '0';
        $stmt = $db->prepare("INSERT OR REPLACE INTO app_meta(key,value) VALUES('fts_trigram_enabled',:value)");
        $stmt->bindValue(':value', $ftsValue, SQLITE3_TEXT);
        $stmt->execute();
        $db->exec("INSERT OR REPLACE INTO app_meta(key,value) VALUES('schema_version','3')");
        $initialized = true;
    } finally {
        flock($lockHandle, LOCK_UN);
        fclose($lockHandle);
    }
}

function dbScalar(string $sql, array $params = []): mixed {
    $stmt = db()->prepare($sql);
    foreach ($params as $k => $v) {
        $stmt->bindValue(is_int($k) ? $k + 1 : $k, $v, is_int($v) ? SQLITE3_INTEGER : SQLITE3_TEXT);
    }
    $result = $stmt->execute();
    $row = $result ? $result->fetchArray(SQLITE3_NUM) : false;
    return $row === false ? null : $row[0];
}
