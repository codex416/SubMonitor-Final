<?php
session_start();
header('Content-Type: application/json; charset=utf-8');

define('SESSION_IDLE_EXPIRE', 7200);
define('SESSION_ABSOLUTE_EXPIRE', 604800);
define('BIND_CLIENT_INFO', false);

function isAuthorized(): bool {
    $now = time();
    $loginTime = (int)($_SESSION['login_time'] ?? 0);
    $lastActivity = (int)($_SESSION['last_activity'] ?? $loginTime);

    if (!isset($_SESSION['is_logged_in']) || $_SESSION['is_logged_in'] !== true) return false;
    if ($loginTime <= 0 || ($now - $loginTime) >= SESSION_ABSOLUTE_EXPIRE) return false;
    if (($now - $lastActivity) >= SESSION_IDLE_EXPIRE) return false;

    if (BIND_CLIENT_INFO) {
        return ($_SESSION['client_ip'] ?? '') === ($_SERVER['REMOTE_ADDR'] ?? '')
            && ($_SESSION['client_ua'] ?? '') === ($_SERVER['HTTP_USER_AGENT'] ?? '');
    }

    return true;
}

if (isAuthorized()) {
    $_SESSION['last_activity'] = time();
    $now = time();
    $idleRemain = SESSION_IDLE_EXPIRE - ($now - (int)$_SESSION['last_activity']);
    $absoluteRemain = SESSION_ABSOLUTE_EXPIRE - ($now - (int)$_SESSION['login_time']);
    $remain = max(0, min($idleRemain, $absoluteRemain));

    http_response_code(200);
    echo json_encode([
        'code' => 200,
        'msg' => '运行正常',
        'data' => [
            'system_status' => 'online',
            'is_logged_in' => true,
            'session_remain_seconds' => $remain,
            'timestamp' => time()
        ]
    ], JSON_UNESCAPED_UNICODE);
} else {
    $_SESSION = [];
    if (ini_get('session.use_cookies')) {
        $params = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000,
            $params['path'], $params['domain'],
            $params['secure'], $params['httponly']
        );
    }
    session_destroy();

    http_response_code(401);
    echo json_encode([
        'code' => 401,
        'msg' => '未登录或会话已过期',
        'data' => [
            'system_status' => 'online',
            'is_logged_in' => false
        ]
    ], JSON_UNESCAPED_UNICODE);
}
exit;
