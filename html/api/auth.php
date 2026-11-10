<?php
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

define('SESSION_IDLE_EXPIRE', 7200);
define('SESSION_ABSOLUTE_EXPIRE', 604800);
define('BIND_CLIENT_INFO', false);

function is_logged_in(): bool {
    $now = time();
    $loginTime = (int)($_SESSION['login_time'] ?? 0);
    $lastActivity = (int)($_SESSION['last_activity'] ?? $loginTime);

    if (!isset($_SESSION['is_logged_in']) || $_SESSION['is_logged_in'] !== true) {
        return false;
    }

    if ($loginTime <= 0 || ($now - $loginTime) >= SESSION_ABSOLUTE_EXPIRE) {
        return false;
    }

    if (($now - $lastActivity) >= SESSION_IDLE_EXPIRE) {
        return false;
    }

    if (BIND_CLIENT_INFO) {
        return ($_SESSION['client_ip'] ?? '') === ($_SERVER['REMOTE_ADDR'] ?? '')
            && ($_SESSION['client_ua'] ?? '') === ($_SERVER['HTTP_USER_AGENT'] ?? '');
    }

    return true;
}

function destroy_auth_session(): void {
    $_SESSION = [];
    if (ini_get('session.use_cookies')) {
        $params = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000,
            $params['path'], $params['domain'],
            $params['secure'], $params['httponly']
        );
    }
    session_destroy();
}

function require_login(): void {
    if (!is_logged_in()) {
        destroy_auth_session();
        json_return(['status' => 'error', 'code' => 401, 'message' => '请先登录或会话已过期'], 401);
    }
    $_SESSION['last_activity'] = time();
}

function json_return($data, $code = 200): void {
    http_response_code($code);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($data, JSON_UNESCAPED_UNICODE);
    exit;
}
