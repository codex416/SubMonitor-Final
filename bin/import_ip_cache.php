<?php
declare(strict_types=1);

/*
 * SubMonitor
 * Import IP geo cache from rules/ip_cache.json into SQLite ip_info.
 */

require_once __DIR__ . '/../html/api/db.php';

initDatabase();

$db = db();

$cacheFile = '/opt/SubMonitor/rules/ip_cache.json';

echo "[Geo] Checking IP cache...\n";

if (!file_exists($cacheFile)) {
    echo "[Geo] ip_cache.json not found, skipping.\n";
    exit(0);
}

$json = file_get_contents($cacheFile);

if ($json === false) {
    fwrite(STDERR, "[Geo] Failed to read ip_cache.json.\n");
    exit(1);
}

/*
 * Empty cache is normal on a fresh installation.
 * Skip migration instead of treating an empty file as invalid JSON.
 */
if (trim($json) === '') {
    echo "[Geo] ip_cache.json is empty, skipping.\n";
    exit(0);
}

$cache = json_decode($json, true);

if (!is_array($cache)) {
    fwrite(
        STDERR,
        "[Geo] Invalid ip_cache.json: " . json_last_error_msg() . "\n"
    );
    exit(1);
}

$stmt = $db->prepare(
    'INSERT INTO ip_info (ip, info, updated_at)
     VALUES (:ip, :info, :updated_at)
     ON CONFLICT(ip) DO UPDATE SET
        info = excluded.info,
        updated_at = excluded.updated_at'
);

if (!$stmt) {
    fwrite(STDERR, "[Geo] Failed to prepare SQLite statement.\n");
    exit(1);
}

$now = time();

$count = 0;
$skipped = 0;

$db->exec('BEGIN IMMEDIATE');

try {
    foreach ($cache as $ip => $info) {

        // Skip invalid IP addresses.
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            $skipped++;
            continue;
        }

        // Skip empty geo information.
        if (!is_string($info) || trim($info) === '') {
            $skipped++;
            continue;
        }

        $stmt->bindValue(
            ':ip',
            $ip,
            SQLITE3_TEXT
        );

        $stmt->bindValue(
            ':info',
            trim($info),
            SQLITE3_TEXT
        );

        $stmt->bindValue(
            ':updated_at',
            $now,
            SQLITE3_INTEGER
        );

        $result = $stmt->execute();

        if ($result === false) {
            throw new RuntimeException(
                'Failed to import IP: ' . $ip
            );
        }

        $count++;
    }

    $db->exec('COMMIT');

} catch (Throwable $e) {

    $db->exec('ROLLBACK');

    fwrite(
        STDERR,
        "[Geo] Import failed: {$e->getMessage()}\n"
    );

    exit(1);
}

echo "[Geo] Imported {$count} IP geo records.\n";

if ($skipped > 0) {
    echo "[Geo] Skipped {$skipped} invalid or empty records.\n";
}

echo "[Geo] IP geo cache sync completed.\n";
