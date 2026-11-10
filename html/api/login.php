<?php
session_set_cookie_params(604800);
session_start();
header('Content-Type: application/json; charset=utf-8');

// 配置
define('ADMIN_PASSWORD_FILE', __DIR__ . '/../.admin_password');
define('SESSION_IDLE_EXPIRE', 7200);
define('SESSION_ABSOLUTE_EXPIRE', 604800);
define('BIND_CLIENT_INFO', false);

// 读取密码
$currentPassword = file_exists(ADMIN_PASSWORD_FILE) ? trim(file_get_contents(ADMIN_PASSWORD_FILE)) : 'admin';

// 退出登录处理
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['logout'])) {
    session_unset();
    session_destroy();
    http_response_code(200);
    echo json_encode(['code' => 200, 'msg' => '已退出登录'], JSON_UNESCAPED_UNICODE);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['password'])) {
    $inputPassword = trim($_POST['password'] ?? '');

    if ($inputPassword === '') {
        http_response_code(400);
        echo json_encode(['code' => 400, 'msg' => '请输入密码'], JSON_UNESCAPED_UNICODE);
        exit;
    }

    if ($inputPassword === $currentPassword) {
        $_SESSION['is_logged_in'] = true;
        $_SESSION['login_time'] = time();
        $_SESSION['last_activity'] = time();
        // 无论是否开启绑定，登录时都记录 IP 和 UA
        $_SESSION['client_ip'] = $_SERVER['REMOTE_ADDR'] ?? '';
        $_SESSION['client_ua'] = $_SERVER['HTTP_USER_AGENT'] ?? '';
        
        http_response_code(200);
        echo json_encode(['code' => 200, 'msg' => '登录成功'], JSON_UNESCAPED_UNICODE);
        exit;
    } else {
        http_response_code(403);
        echo json_encode(['code' => 403, 'msg' => '密码错误，请重试'], JSON_UNESCAPED_UNICODE);
        exit;
    }
}

function isAuthorized() {
    $now = time();
    $loginTime = (int)($_SESSION['login_time'] ?? 0);
    $lastActivity = (int)($_SESSION['last_activity'] ?? $loginTime);
    $baseCheck = isset($_SESSION['is_logged_in']) && $_SESSION['is_logged_in'] === true
        && $loginTime > 0
        && ($now - $loginTime) < SESSION_ABSOLUTE_EXPIRE
        && ($now - $lastActivity) < SESSION_IDLE_EXPIRE;
    if (!$baseCheck) return false;
    if (BIND_CLIENT_INFO) {
        return ($_SESSION['client_ip'] ?? '') === ($_SERVER['REMOTE_ADDR'] ?? '')
            && ($_SESSION['client_ua'] ?? '') === ($_SERVER['HTTP_USER_AGENT'] ?? '');
    }
    return true;
}

if (!isAuthorized()) {
    session_unset(); session_destroy();
    http_response_code(401);
    echo json_encode(['code' => 401, 'msg' => '未授权或会话已过期'], JSON_UNESCAPED_UNICODE);
    exit;
}
