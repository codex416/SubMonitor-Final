<?php
declare(strict_types=1);

require_once __DIR__ . '/auth.php';
require_once __DIR__ . '/db.php';
require_once __DIR__ . '/v2board.php';
require_login();
header('Content-Type: application/json; charset=utf-8');

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
    http_response_code(405);
    echo json_encode(['status' => 'error', 'message' => 'Method Not Allowed'], JSON_UNESCAPED_UNICODE);
    exit;
}

$input = json_decode((string)file_get_contents('php://input'), true);
$tokens = is_array($input['tokens'] ?? null) ? $input['tokens'] : [];
$tokens = array_values(array_unique(array_filter($tokens, static function ($token) {
    return is_string($token) && $token !== '' && $token !== '-' && strlen($token) <= 512;
})));
// 单次请求限制 200 个 Token；前端会按 200 个一批连续提交，控制单次请求耗时。
$tokens = array_slice($tokens, 0, 200);

try {
    initDatabase();
    $data = [];
    foreach (array_chunk($tokens, 200) as $tokenBatch) {
        $data += v2b_enrich_tokens($tokenBatch);
    }
    echo json_encode(['status' => 'success', 'data' => $data], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
} catch (Throwable $e) {
    error_log('V2Board async enrichment failed: ' . $e->getMessage());
    http_response_code(500);
    echo json_encode(['status' => 'error', 'message' => 'V2Board 用户信息更新失败'], JSON_UNESCAPED_UNICODE);
}
