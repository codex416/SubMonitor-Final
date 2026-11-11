<?php
session_set_cookie_params(604800);
session_start();

define('SESSION_IDLE_EXPIRE', 7200);       // 2小时无操作失效
define('SESSION_ABSOLUTE_EXPIRE', 604800); // 7天绝对过期
define('BIND_CLIENT_INFO', false);

function isAuthorized() {
    $now = time();

    $loginTime = (int)($_SESSION['login_time'] ?? 0);
    $lastActivity = (int)($_SESSION['last_activity'] ?? 0);

    $baseCheck = isset($_SESSION['is_logged_in'])
        && $_SESSION['is_logged_in'] === true
        && $loginTime > 0
        && $lastActivity > 0
        && ($now - $loginTime) < SESSION_ABSOLUTE_EXPIRE
        && ($now - $lastActivity) < SESSION_IDLE_EXPIRE;

    if (!$baseCheck) return false;

    if (BIND_CLIENT_INFO) {
        $sessionIp = $_SESSION['client_ip'] ?? $_SESSION['user_ip'] ?? '';
        $sessionUa = $_SESSION['client_ua'] ?? $_SESSION['user_ua'] ?? '';

        $currentIp = $_SERVER['REMOTE_ADDR'] ?? '';
        $currentUa = $_SERVER['HTTP_USER_AGENT'] ?? '';

        return ($sessionIp === $currentIp) && ($sessionUa === $currentUa);
    }

    return true;
}

if (!isAuthorized()) {
    $_SESSION = [];
    if (ini_get('session.use_cookies')) {
        $params = session_get_cookie_params();
        setcookie(
            session_name(),
            '',
            time() - 42000,
            $params['path'],
            $params['domain'],
            $params['secure'],
            $params['httponly']
        );
    }
    session_destroy();

    header('Location: /login.html', true, 302);
    exit;
}

// 当前页面访问视为一次有效活动，刷新2小时无操作倒计时。
// login_time 不更新，因此7天绝对过期时间不会被延长。
$_SESSION['last_activity'] = time();


// 活跃 TOKEN 趋势：从 SQLite 直接读取最近 30 天统计。
require_once __DIR__ . '/api/db.php';
initDatabase();
$tokenTrendLabels = [];
$tokenTrendValues = [];
$tokenTrendDates = [];
$trendTz = new DateTimeZone('Asia/Shanghai');
$trendToday = new DateTime('today', $trendTz);
$trendStart = clone $trendToday;
$trendStart->modify('-29 days');
for ($i = 0; $i < 30; $i++) {
    $d = clone $trendStart;
    if ($i > 0) $d->modify('+' . $i . ' day');
    $key = $d->format('Y-m-d');
    $tokenTrendDates[] = $key;
    $tokenTrendLabels[] = $d->format('n月j日');
    $tokenTrendValues[$key] = 0;
}
$trendRows = fetchTrendRows();
foreach ($trendRows as $row) {
    $day = $row['day'];
    if (isset($tokenTrendValues[$day])) $tokenTrendValues[$day] = (int)$row['count'];
}
$tokenTrendValues = array_values($tokenTrendValues);

function fetchTrendRows(): array {
    $start = (new DateTime('today', new DateTimeZone('Asia/Shanghai')))->modify('-29 days')->setTime(0,0,0)->getTimestamp();
    // 与日志列表、今日统计保持一致：永久负缓存中已确认不存在的 Token 不计入活跃趋势。
    // 只排除明确 user_id=0 的 Token；接口超时/异常不会写入该状态，因此不会误删统计。
    $stmt = db()->prepare("SELECT l.day, COUNT(DISTINCT l.token) AS count
        FROM logs l
        WHERE l.ts >= :start
          AND l.status = 200
          AND l.token <> '-'
          AND NOT EXISTS (
              SELECT 1
              FROM v2board_user_cache vnf
              WHERE vnf.token = l.token
                AND vnf.user_id = 0
          )
        GROUP BY l.day
        ORDER BY l.day ASC");
    $stmt->bindValue(':start', $start, SQLITE3_INTEGER);
    $result = $stmt->execute();
    $rows = [];
    while ($result && ($row = $result->fetchArray(SQLITE3_ASSOC))) $rows[] = $row;
    return $rows;
}
?>
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <meta name="theme-color" content="#f8fafc">
    <meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate">
    <meta http-equiv="Pragma" content="no-cache">
    <meta http-equiv="Expires" content="0">
    <title>SubMonitor - 订阅监控</title>
    
    <style>
        :root {
            --bg: #f8fafc;
            --card-bg: #ffffff;
            --border: #e2e8f0;
            --text-primary: #0f172a;
            --text-muted: #64748b;
            --primary-blue: #4f46e5;
            --primary-green: #16a34a;
            --primary-red: #dc2626;
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
        }

        html, body {
            width: 100%;
            max-width: 100vw;
            overflow-x: hidden;
        }

        body {
            background-color: var(--bg);
            background-image: radial-gradient(#e2e8f0 1.2px, transparent 1.2px);
            background-size: 18px 18px;
            color: var(--text-primary);
            padding: 16px 12px 100px 12px;
            min-height: 100vh;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            width: 100%;
            overflow: hidden;
        }

        .top-bar {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 16px;
        }

        .brand {
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .status-dot {
            width: 9px;
            height: 9px;
            background-color: #22c55e;
            border-radius: 50%;
            display: inline-block;
            box-shadow: 0 0 8px rgba(34, 197, 94, 0.6);
        }

        .brand-title {
            font-size: 1.2rem;
            font-weight: 700;
            color: #0f172a;
            letter-spacing: -0.3px;
        }

        .logout-btn {
            background: #fef2f2;
            color: var(--primary-red);
            border: 1px solid #fecaca;
            padding: 4px 10px;
            border-radius: 6px;
            font-size: 0.75rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.15s ease;
        }
        .logout-btn:hover {
            background: var(--primary-red);
            color: #ffffff;
            border-color: var(--primary-red);
        }

        .sys-control-btn {
            background: #ffffff;
            color: var(--text-primary);
            border: 1px solid var(--border);
            padding: 4px 10px;
            border-radius: 6px;
            font-size: 0.75rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.15s ease;
        }
        .sys-control-btn:hover {
            border-color: var(--primary-blue);
            color: var(--primary-blue);
            background: transparent;
        }

        .sys-btn-unified {
            width: 90px;
            height: 34px;
            padding: 0;
            font-size: 0.8rem;
            font-weight: 600;
            border-radius: 8px;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            flex-shrink: 0;
            box-sizing: border-box;
            cursor: pointer;
            transition: all 0.15s ease;
            white-space: nowrap;
        }

        .last-update {
            font-size: 0.75rem;
            color: var(--text-muted);
        }

        .analytics-grid {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 12px;
            margin-bottom: 20px;
        }

        @media (max-width: 640px) {
            .analytics-grid {
                grid-template-columns: 1fr;
            }
        }

        .analytics-card {
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 12px 14px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.02);
            display: flex;
            flex-direction: column;
            height: 320px;
        }

        .analytics-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 8px;
            padding-bottom: 8px;
            border-bottom: 1px dashed var(--border);
        }

        .analytics-title {
            font-size: 0.88rem;
            font-weight: 700;
            color: var(--text-primary);
        }

        .analytics-list {
            overflow-y: auto;
            flex: 1;
            display: flex;
            flex-direction: column;
            gap: 6px;
            padding-right: 4px;
        }

        .analytics-list::-webkit-scrollbar {
            width: 4px;
        }
        .analytics-list::-webkit-scrollbar-thumb {
            background: #cbd5e1;
            border-radius: 4px;
        }

        .analytics-item {
            display: flex;
            align-items: center;
            justify-content: space-between;
            font-size: 0.78rem;
            padding: 6px 0;
            border-bottom: 1px solid #f8fafc;
        }

        .analytics-item:last-child {
            border-bottom: none;
        }

        .item-left {
            display: flex;
            align-items: center;
            gap: 8px;
            min-width: 0;
            flex: 1;
        }

        .rank-num {
            font-size: 0.75rem;
            font-weight: 700;
            color: var(--text-muted);
            width: 28px;
            min-width: 28px;
            text-align: center;
            flex: 0 0 28px;
            font-variant-numeric: tabular-nums;
        }

        .item-main {
            display: flex;
            flex-direction: column;
            min-width: 0;
            flex: 1;
        }

        .item-title-row {
            display: flex;
            align-items: center;
            gap: 4px;
            min-width: 0;
        }

        .item-title {
            font-weight: 600;
            color: var(--text-primary);
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
            font-family: monospace;
        }

        .item-sub {
            font-size: 0.68rem;
            color: var(--text-muted);
        }

        .item-right {
            display: flex;
            align-items: center;
            gap: 6px;
            text-align: right;
            flex-shrink: 0;
            margin-left: 8px;
        }

        .count-badge {
            font-weight: 700;
            color: var(--primary-blue);
            font-size: 0.8rem;
        }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 10px;
            margin-bottom: 20px;
        }

        /* PC端统计卡片排列：第一行 总请求节点｜成功请求｜异常 / 拦截
           第二行 独立 IP 数｜独立 TOKEN｜异常率 */
        @media (min-width: 641px) {
            .stats-grid .stat-card:nth-child(1) { order: 1; }
            .stats-grid .stat-card:nth-child(2) { order: 4; }
            .stats-grid .stat-card:nth-child(3) { order: 2; }
            .stats-grid .stat-card:nth-child(4) { order: 3; }
            .stats-grid .stat-card:nth-child(5) { order: 5; }
            .stats-grid .stat-card:nth-child(6) { order: 6; }
        }

        @media (max-width: 640px) {
            .stats-grid {
                grid-template-columns: repeat(2, 1fr);
            }

            .stats-grid .stat-card {
                order: initial;
            }
        }

        .stat-card {
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 12px 14px;
            box-shadow: 0 1px 2px rgba(0,0,0,0.02);
        }

        .stat-label {
            font-size: 0.75rem;
            font-weight: 600;
            color: var(--text-muted);
            margin-bottom: 6px;
        }
        .stat-number {
            font-size: 1.4rem;
            font-weight: 700;
        }
        .stat-number.blue {
            color: var(--primary-blue);
        }
        .stat-number.green {
            color: var(--primary-green);
        }
        .stat-number.red {
            color: var(--primary-red);
        }

        .section-header {
            font-size: 1rem;
            font-weight: 700;
            color: #0f172a;
            margin-bottom: 12px;
        }

        .control-panel {
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 12px 12px 0 0;
            padding: 12px 14px;
            display: flex;
            flex-direction: column;
            gap: 10px;
            border-bottom: none;
            width: 100%;
        }

        .control-row {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            align-items: center;
            width: 100%;
        }

        .search-input {
            flex: 1;
            min-width: 180px;
            padding: 8px 12px;
            background: #f8fafc;
            border: 1px solid var(--border);
            border-radius: 8px;
            font-size: 0.82rem;
            outline: none;
            color: var(--text-primary);
        }

        .search-input:focus {
            border-color: var(--primary-blue);
            background: #fff;
        }

        .time-trigger-btn {
            background: #ffffff;
            border: 1px solid var(--border);
            padding: 6px 12px;
            border-radius: 8px;
            font-size: 0.82rem;
            color: var(--text-primary);
            cursor: pointer;
            display: inline-flex;
            align-items: center;
            gap: 6px;
            transition: all 0.15s ease;
            white-space: nowrap;
            max-width: 100%;
            overflow: hidden;
        }

        .time-trigger-btn > span:first-child {
            flex-shrink: 0;
        }

        .time-trigger-btn:hover {
            border-color: var(--primary-blue);
            background: #f0f6ff;
            color: var(--primary-blue);
        }

        .time-trigger-btn .tag {
            font-weight: 600;
            color: var(--primary-blue);
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
            min-width: 0;
        }

        .btn-group {
            display: flex;
            flex-wrap: wrap;
            gap: 6px;
            align-items: center;
            max-width: 100%;
        }

        .btn {
            background: #f1f5f9;
            border: 1px solid var(--border);
            color: var(--text-primary);
            padding: 6px 12px;
            border-radius: 8px;
            font-size: 0.82rem;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.15s ease;
            white-space: nowrap;
        }

        .btn:hover {
            background: #e2e8f0;
        }

        .btn-quick {
            background: #ffffff;
            color: var(--text-muted);
            border: 1px solid var(--border);
            font-size: 0.78rem;
            padding: 5px 10px;
            flex-shrink: 0;
        }

        .btn-quick:hover, .btn-quick.active {
            color: var(--primary-blue);
            border-color: var(--primary-blue);
            background: #f0f6ff;
        }

        .btn-ban {
            background: #fef2f2;
            color: var(--primary-red);
            border: 1px solid #fecaca;
            padding: 3px 7px;
            border-radius: 6px;
            font-size: 0.72rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.15s ease;
            white-space: nowrap;
            display: inline-flex;
            align-items: center;
            gap: 2px;
        }

        .btn-ban:hover:not(:disabled) {
            background: #dc2626;
            color: #ffffff;
            border-color: #dc2626;
        }

        /* V2Board 用户信息框：封禁后整块使用红色警示样式 */
        .v2board-user-info {
            margin-top: 6px;
            padding: 7px 8px;
            background: #f8fafc;
            border: 1px solid var(--border);
            border-radius: 7px;
            font-size: 0.74rem;
            line-height: 1.55;
            min-width: 0;
            text-align: left;
            transition: background-color 0.18s ease, border-color 0.18s ease;
        }

        .v2board-user-info .v2b-user-line {
            display: block;
            width: 100%;
            min-width: 0;
            text-align: left;
            overflow-wrap: anywhere;
        }

        /* ID 保持左侧，账户状态（正常/已封禁）靠右 */
        .v2board-user-info .v2b-user-line:first-child {
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 8px;
        }

        .v2board-user-info .v2b-user-line:first-child strong {
            min-width: 0;
            overflow-wrap: anywhere;
        }

        .v2board-user-info .v2b-user-line:first-child > span {
            flex-shrink: 0;
            margin-left: auto;
            text-align: right;
        }

        /* 封禁账户 / 解封账户按钮靠右 */
        .v2board-user-info .v2b-user-actions {
            display: flex;
            justify-content: flex-end;
            align-items: center;
            margin-top: 4px;
        }

        .v2board-user-info.is-banned {
            background: #fef2f2;
            border: 1px solid #fca5a5;
        }

        .v2board-user-info.is-banned strong,
        .v2board-user-info.is-banned .v2b-user-detail {
            color: #991b1b;
        }

        .btn-unban {
            background: #f0fdf4;
            color: var(--primary-green);
            border: 1px solid #bbf7d0;
            padding: 3px 8px;
            border-radius: 6px;
            font-size: 0.72rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.15s ease;
            white-space: nowrap;
        }

        .btn-unban:hover {
            background: #16a34a;
            color: #ffffff;
            border-color: #16a34a;
        }

        .ban-actions {
            display: flex;
            gap: 4px;
            align-items: center;
        }

        .modal-overlay {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(15, 23, 42, 0.45);
            backdrop-filter: blur(6px);
            display: none;
            align-items: center;
            justify-content: center;
            z-index: 9999;
            padding: 16px;
            overflow-y: auto;
            overscroll-behavior: contain;
            box-sizing: border-box;
        }

        /* 系统控制面板内容较长：滚动发生在弹窗内部，不再被视口高度截断。 */
        #system-control-modal {
            align-items: flex-start;
        }

        #system-control-modal .modal-card {
            display: flex;
            flex-direction: column;
            max-height: calc(100vh - 32px);
            max-height: calc(100dvh - 32px);
            margin: auto 0;
            min-height: 0;
            overflow: hidden;
        }

        #system-control-modal .modal-header,
        #system-control-modal .modal-footer {
            flex: 0 0 auto;
        }

        #system-control-modal .modal-body {
            flex: 1 1 auto;
            min-height: 0;
            overflow-y: auto;
            overflow-x: hidden;
            overscroll-behavior: contain;
            -webkit-overflow-scrolling: touch;
            padding-right: 3px;
        }

        /* V2Board 操作按钮与连接结果分行，长提示自动换行，避免互相挤压。 */
        #system-control-modal .v2b-action-row {
            display: flex;
            flex-wrap: wrap;
            align-items: center;
            gap: 8px;
            min-width: 0;
        }

        #system-control-modal .v2b-action-row .btn {
            flex: 0 0 auto;
            width: auto;
            min-width: 96px;
            height: 36px;
            padding: 0 12px;
            white-space: nowrap;
        }

        /* 覆盖全局 sys-btn-unified 的 90px 固定宽度，避免中文按钮标题被挤压。 */
        #system-control-modal .v2b-action-row .btn:first-child {
            min-width: 142px;
        }

        #system-control-modal .v2b-connection-status {
            display: block;
            flex: 1 1 100%;
            min-width: 0;
            max-width: 100%;
            margin-top: 2px;
            line-height: 1.5;
            white-space: normal;
            overflow-wrap: anywhere;
            word-break: break-word;
        }

        @media (max-width: 480px) {
            #system-control-modal {
                padding: 10px;
            }

            #system-control-modal .modal-card {
                max-height: calc(100vh - 20px);
                max-height: calc(100dvh - 20px);
                padding: 16px;
            }

            #system-control-modal .v2b-action-row .btn {
                flex: 1 1 130px;
            }
        }

        .modal-overlay.active {
            display: flex;
        }

        .modal-card {
            background: #ffffff;
            border: 1px solid var(--border);
            border-radius: 16px;
            width: 100%;
            max-width: 440px;
            padding: 20px 22px;
            box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 8px 10px -6px rgba(0, 0, 0, 0.05);
            box-sizing: border-box;
            animation: modalFadeIn 0.2s cubic-bezier(0.16, 1, 0.3, 1);
        }

        @keyframes modalFadeIn {
            from {
                opacity: 0;
                transform: scale(0.96) translateY(8px);
            }
            to {
                opacity: 1;
                transform: scale(1) translateY(0);
            }
        }

        .modal-header {
            font-size: 1.05rem;
            font-weight: 700;
            color: var(--text-primary);
            margin-bottom: 16px;
        }

        .modal-body {
            display: flex;
            flex-direction: column;
            gap: 16px;
            margin-bottom: 20px;
            width: 100%;
        }

        .input-group {
            display: flex;
            flex-direction: column;
            gap: 6px;
            width: 100%;
        }

        .input-label-row {
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .input-label {
            font-size: 0.78rem;
            font-weight: 600;
            color: var(--text-muted);
        }

        .fill-helper-btn {
            font-size: 0.72rem;
            color: var(--primary-blue);
            background: transparent;
            border: none;
            cursor: pointer;
            font-weight: 500;
        }
        .fill-helper-btn:hover {
            text-decoration: underline;
        }

        .picker-combo-row {
            display: flex;
            gap: 6px;
            align-items: center;
            width: 100%;
        }

        .date-picker-input {
            flex: 2;
            padding: 8px 10px;
            border: 1px solid var(--border);
            border-radius: 8px;
            font-size: 0.85rem;
            background: #f8fafc;
            color: var(--text-primary);
            outline: none;
            cursor: pointer;
        }

        .time-select {
            flex: 1;
            padding: 8px 4px;
            border: 1px solid var(--border);
            border-radius: 8px;
            font-size: 0.82rem;
            background: #f8fafc;
            color: var(--text-primary);
            outline: none;
            cursor: pointer;
            text-align: center;
        }

        .date-picker-input:focus, .time-select:focus {
            border-color: var(--primary-blue);
            background: #fff;
        }

        .modal-footer {
            display: flex;
            justify-content: flex-end;
            gap: 10px;
        }

        .btn-primary {
            background: var(--primary-blue);
            color: #ffffff;
            border: none;
            padding: 9px 22px;
            border-radius: 10px;
            font-size: 0.85rem;
            font-weight: 600;
            cursor: pointer;
            transition: background 0.15s ease;
        }

        .btn-primary:hover {
            background: #3730a3;
        }

        .table-card {
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 0 0 12px 12px;
            overflow: hidden;
            box-shadow: 0 1px 3px rgba(0,0,0,0.02);
            width: 100%;
        }

        .table-wrapper {
            overflow-x: auto;
            width: 100%;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            text-align: left;
            font-size: 0.85rem;
        }

        th {
            background: #f8fafc;
            padding: 12px 16px;
            color: var(--text-muted);
            font-weight: 600;
            font-size: 0.78rem;
            border-bottom: 1px solid var(--border);
            white-space: nowrap;
        }

        td {
            padding: 12px 16px;
            border-bottom: 1px solid #f1f5f9;
        }
        tr:last-child td {
            border-bottom: none;
        }
        tr:hover {
            background-color: #f8fafc;
        }

        .pill-box {
            display: inline-flex;
            align-items: center;
            gap: 4px;
            background: #f1f5f9;
            border: 1px solid #e2e8f0;
            padding: 3px 8px;
            border-radius: 6px;
            font-family: monospace;
            font-size: 0.8rem;
            max-width: 100%;
            min-width: 0;
            overflow: hidden;
            cursor: pointer;
            -webkit-tap-highlight-color: transparent;
        }

        .pill-box span {
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
            min-width: 0;
            flex: 1;
        }

        .pill-box.expanded {
            flex-wrap: wrap;
            white-space: normal;
            word-break: break-all;
        }

        .pill-box.expanded span {
            white-space: normal;
            word-break: break-all;
            overflow: visible;
            text-overflow: clip;
        }

        .btn-copy-icon {
            background: transparent;
            border: none;
            color: #64748b;
            cursor: pointer;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            padding: 2px;
            border-radius: 4px;
            flex-shrink: 0;
        }

        .btn-copy-icon:hover {
            color: var(--primary-blue);
            background: #e2e8f0;
        }
        .btn-copy-icon svg {
            width: 13px;
            height: 13px;
            stroke-width: 2;
        }

        .ip-sub {
            font-size: 0.73rem;
            color: var(--text-muted);
            margin-top: 3px;
            text-align: left;
            width: 100%;
            line-height: 1.35;
            word-break: break-all;
            overflow-wrap: anywhere;
        }

        .badge {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            min-width: 38px;
            padding: 2px 7px;
            border-radius: 10px;
            font-weight: 600;
            font-size: 0.75rem;
            font-family: monospace;
            flex-shrink: 0;
        }

        .badge-200 { background: #dcfce7; color: #15803d; }
        .badge-400 { background: #fef3c7; color: #b45309; }
        .badge-401 { background: #fee2e2; color: #991b1b; }
        .badge-403 { background: #fee2e2; color: #b91c1c; }
        .badge-404 { background: #f3e8ff; color: #6b21a8; }
        .badge-429 { background: #ffedd5; color: #c2410c; }
        .badge-500 { background: #fecdd3; color: #9f1239; }
        .badge-other { background: #e2e8f0; color: #475569; }

        .remark-text {
            font-size: 0.8rem;
            font-weight: 500;
            flex-shrink: 0;
            white-space: nowrap;
        }

        .ua-text {
            max-width: 280px;
            color: var(--text-muted);
            font-size: 0.78rem;
            word-break: break-all;
            line-height: 1.4;
        }

        .empty-state {
            padding: 40px;
            text-align: center;
            color: var(--text-muted);
            font-size: 0.85rem;
        }

        .pagination-bar {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 12px 16px;
            background: transparent;
            border-top: 0;
            font-size: 0.82rem;
            color: var(--text-muted);
        }
        .pagination-nums {
            display: flex;
            gap: 4px;
            align-items: center;
        }
        .page-btn {
            background: #ffffff;
            border: 1px solid var(--border);
            color: var(--text-primary);
            padding: 4px 10px;
            border-radius: 6px;
            font-size: 0.8rem;
            cursor: pointer;
            transition: all 0.15s ease;
        }
        .page-btn:hover:not(:disabled) {
            border-color: var(--primary-blue);
            color: var(--primary-blue);
            background: #f0f6ff;
        }
        .page-btn.active {
            background: var(--primary-blue);
            color: #ffffff;
            border-color: var(--primary-blue);
            font-weight: 600;
        }
        .page-btn:disabled {
            opacity: 0.5;
            cursor: not-allowed;
        }


        .analytics-page-ellipsis { padding: 0 2px; color: var(--text-muted); }
        @media (max-width: 640px) {
            .analytics-pagination-bar { font-size: 0.68rem; }
            .analytics-pagination-info {
                display: flex !important;
                align-items: center;
                justify-content: flex-start;
                text-align: left;
                margin-right: auto;
                flex: 0 0 auto;
            }

            .analytics-pagination-nums { gap: 3px; }
            .analytics-page-btn { min-width: 26px; padding: 3px 6px; }
        }

        .mobile-load-more-container {
            padding: 12px;
            text-align: center;
            background: transparent;
            width: 100%;
        }
        .btn-load-more {
            width: 100%;
            padding: 10px;
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 12px;
            color: var(--primary-blue);
            font-size: 0.85rem;
            font-weight: 600;
            cursor: pointer;
            box-shadow: 0 1px 2px rgba(0,0,0,0.02);
        }
        .btn-load-more:hover {
            background: #f0f6ff;
        }
        .btn-load-more:disabled {
            color: var(--text-muted);
            background: #f1f5f9;
            cursor: not-allowed;
        }

        @media (max-width: 768px) {
            .brand-title {
                cursor: pointer;
            }
            .sys-control-btn {
                display: none;
            }

            .control-panel {
                border-radius: 12px;
                margin-bottom: 12px;
                border-bottom: 1px solid var(--border);
            }

            .control-row {
                flex-direction: column;
                align-items: stretch;
            }

            .btn-group {
                overflow-x: auto;
                white-space: nowrap;
                width: 100%;
                padding-bottom: 4px;
                -webkit-overflow-scrolling: touch;
                flex-wrap: nowrap;
            }

            .time-trigger-btn {
                width: 100%;
                justify-content: space-between;
            }

            .table-card {
                background: transparent;
                border: none;
                box-shadow: none;
                overflow: hidden;
                width: 100%;
            }
            .table-wrapper {
                overflow: hidden;
                width: 100%;
            }
            
            table, tbody {
                display: block;
                width: 100%;
                box-sizing: border-box;
            }
            thead {
                display: none;
            }

            tbody {
                display: flex;
                flex-direction: column;
                gap: 12px;
                width: 100%;
            }

            tr.m-card {
                display: block !important;
                background: var(--card-bg) !important;
                border: 1px solid var(--border) !important;
                border-radius: 12px !important;
                padding: 14px !important;
                box-shadow: 0 1px 3px rgba(0,0,0,0.02) !important;
                width: 100% !important;
                box-sizing: border-box !important;
                overflow: hidden !important;
            }

            tr.m-card > td {
                display: block !important;
                width: 100% !important;
                padding: 0 !important;
                border: none !important;
                background: transparent !important;
                box-sizing: border-box !important;
                overflow: hidden !important;
            }

            .m-card-header {
                display: flex;
                justify-content: space-between;
                align-items: center;
                padding-bottom: 10px;
                border-bottom: 1px solid #f1f5f9;
                margin-bottom: 10px;
                width: 100%;
            }

            .m-time {
                font-size: 0.8rem;
                font-weight: 600;
                color: #334155;
            }
            .m-status-group {
                display: flex;
                align-items: center;
                gap: 6px;
            }

            .m-card-body {
                display: flex;
                flex-direction: column;
                gap: 10px;
                width: 100%;
            }

            .m-row {
                display: flex !important;
                justify-content: space-between !important;
                align-items: flex-start !important;
                gap: 8px !important;
                width: 100% !important;
                box-sizing: border-box !important;
            }

            .m-label {
                font-size: 0.75rem;
                font-weight: 600;
                color: var(--text-muted);
                flex-shrink: 0;
                margin-top: 3px;
            }

            .m-value {
                font-size: 0.8rem;
                display: flex !important;
                flex-direction: column !important;
                align-items: flex-end !important;
                text-align: right !important;
                min-width: 0 !important;
                max-width: 70% !important;
                box-sizing: border-box !important;
            }

            .ip-sub {
                font-size: 0.73rem;
                color: var(--text-muted);
                margin-top: 4px;
                text-align: right !important;
                width: 100% !important;
                display: block !important;
                white-space: nowrap !important;
                overflow: hidden !important;
                text-overflow: ellipsis !important;
                cursor: pointer;
            }

            .ip-sub.expanded {
                white-space: normal !important;
                word-break: break-all !important;
                overflow: visible !important;
            }

            .m-ua-box {
                margin-top: 10px;
                padding-top: 8px;
                border-top: 1px dashed #f1f5f9;
                font-size: 0.73rem;
                color: var(--text-muted);
                line-height: 1.4;
                word-break: break-all !important;
                overflow-wrap: anywhere !important;
                white-space: normal;
                display: -webkit-box;
                -webkit-line-clamp: 2;
                -webkit-box-orient: vertical;
                overflow: hidden;
                cursor: pointer;
                width: 100% !important;
                text-align: left !important;
            }

            .m-ua-box.expanded {
                display: block !important;
                overflow: visible !important;
            }
        }

        /* 手机横屏专用：监控日志列表继续使用移动端卡片布局。
           只处理日志列表，不改变四个分析卡片和PC正常宽度下的布局。 */
        @media (min-width: 769px) and (max-width: 1024px) and (orientation: landscape) and (pointer: coarse) {
            /* 时间筛选卡片与日志列表必须明确分隔。
               横屏宽度 > 768px 时不会进入 max-width:768px 的移动端规则，
               因此这里单独补上底部间距，避免首张日志卡片贴入/覆盖筛选卡片。 */
            .control-panel {
                margin-bottom: 12px !important;
                border-bottom: 1px solid var(--border) !important;
                border-radius: 12px !important;
                position: relative !important;
                z-index: 1 !important;
                box-sizing: border-box !important;
            }

            .table-card {
                margin-top: 0 !important;
                position: relative !important;
                z-index: 0 !important;
                background: transparent;
                border: none;
                box-shadow: none;
                overflow: hidden;
                width: 100%;
            }

            .table-wrapper {
                overflow: hidden;
                width: 100%;
            }

            /* 横屏时强制 table 本身脱离 table 布局，
               避免 tbody/flex 与原生 table 行高计算冲突导致卡片重叠。 */
            #desktop-table {
                display: block !important;
                width: 100% !important;
                height: auto !important;
                min-height: 0 !important;
                box-sizing: border-box !important;
                border-collapse: separate !important;
            }

            #desktop-table tbody {
                display: flex !important;
                flex-direction: column !important;
                gap: 10px !important;
                width: 100% !important;
                height: auto !important;
                min-height: 0 !important;
                box-sizing: border-box !important;
            }

            #desktop-table thead {
                display: none !important;
            }

            #desktop-table tr.m-card {
                display: block !important;
                position: relative !important;
                flex: 0 0 auto !important;
                margin-top: 0 !important;
                width: 100% !important;
                height: auto !important;
                min-height: 0 !important;
                margin: 0 !important;
                box-sizing: border-box !important;
                background: var(--card-bg) !important;
                border: 1px solid var(--border) !important;
                border-radius: 12px !important;
                padding: 12px !important;
                overflow: hidden !important;
            }

            #desktop-table tr.m-card > td {
                display: block !important;
                width: 100% !important;
                padding: 0 !important;
                border: none !important;
                background: transparent !important;
                box-sizing: border-box !important;
                overflow: hidden !important;
            }

            #desktop-table .m-card-header {
                display: flex;
                justify-content: space-between;
                align-items: center;
                gap: 10px;
                padding-bottom: 8px;
                margin-bottom: 8px;
                border-bottom: 1px solid #f1f5f9;
                width: 100%;
            }

            #desktop-table .m-time {
                font-size: 0.78rem;
                font-weight: 600;
                color: #334155;
                min-width: 0;
                overflow: hidden;
                text-overflow: ellipsis;
                white-space: nowrap;
            }

            #desktop-table .m-status-group {
                display: flex;
                align-items: center;
                gap: 5px;
                flex-shrink: 0;
                white-space: nowrap;
            }

            #desktop-table .m-card-body {
                display: flex;
                flex-direction: column;
                gap: 8px;
                width: 100%;
            }

            #desktop-table .m-row {
                display: flex !important;
                justify-content: space-between !important;
                align-items: flex-start !important;
                gap: 8px !important;
                width: 100% !important;
                box-sizing: border-box !important;
            }

            #desktop-table .m-label {
                font-size: 0.74rem;
                font-weight: 600;
                color: var(--text-muted);
                flex: 0 0 auto;
                margin-top: 3px;
            }

            #desktop-table .m-value {
                font-size: 0.79rem;
                display: flex !important;
                flex-direction: column !important;
                align-items: flex-end !important;
                text-align: right !important;
                min-width: 0 !important;
                max-width: 82% !important;
                box-sizing: border-box;
            }

            #desktop-table .m-value > div {
                max-width: 100%;
                justify-content: flex-end;
            }

            #desktop-table .pill-box {
                max-width: min(100%, 560px);
            }

            #desktop-table .ip-sub {
                font-size: 0.71rem;
                width: 100% !important;
                margin-top: 3px;
                text-align: right !important;
                white-space: nowrap !important;
                overflow: hidden !important;
                text-overflow: ellipsis !important;
            }

            #desktop-table .m-ua-box {
                margin-top: 8px;
                padding-top: 7px;
                border-top: 1px dashed #f1f5f9;
                /* 与竖屏移动端 UA 保持相同的字体比例和颜色风格 */
                font-size: 0.72rem;
                line-height: 1.35;
                color: var(--text-muted);
                word-break: break-all !important;
                overflow-wrap: anywhere !important;
                display: -webkit-box;
                -webkit-line-clamp: 2;
                -webkit-box-orient: vertical;
                overflow: hidden;
                width: 100% !important;
                text-align: left !important;
            }

            #desktop-table .m-ua-box.expanded {
                display: block !important;
                overflow: visible !important;
            }

            #pc-pagination-container {
                display: none;
            }
        }

        .toast {
            position: fixed;
            bottom: 24px;
            left: 50%;
            transform: translateX(-50%) translateY(100px);
            background: #0f172a;
            color: #fff;
            padding: 8px 18px;
            border-radius: 20px;
            font-size: 0.8rem;
            opacity: 0;
            transition: all 0.25s cubic-bezier(0.18, 0.89, 0.32, 1.28);
            pointer-events: none;
            z-index: 100001;
        }
        .toast.show {
            transform: translateX(-50%) translateY(0);
            opacity: 1;
        }

        .analytics-card {
            display: flex;
            flex-direction: column;
            min-height: 0;
        }

        .analytics-card .analytics-list {
            flex: 1 1 auto;
            min-height: 0;
        }

        .analytics-pagination-bar {
            display: flex;
            align-items: stretch;
            justify-content: space-between;
            width: 100%;
            box-sizing: border-box;
            min-height: 42px;
            margin-top: auto;
            padding: 0 10px;
            background: #f8fafc;
            border-top: 1px solid var(--border);
            color: var(--text-muted);
            font-size: 0.76rem;
            flex-shrink: 0;
        }

        .analytics-pagination-info {
            display: flex;
            align-items: center;
            white-space: nowrap;
            padding: 0 8px;
            min-width: 0;
            flex: 1 1 auto;
            overflow: hidden;
            text-overflow: ellipsis;
        }

        .analytics-pagination-nums {
            display: flex;
            align-items: stretch;
            justify-content: flex-end;
            gap: 3px;
            flex: 0 0 auto;
            min-width: 0;
        }

        .analytics-pagination-bar.compact .analytics-pagination-info {
            flex: 0 1 34%;
            max-width: 34%;
            padding: 0 4px;
        }

        .analytics-pagination-bar.compact .analytics-pagination-nums {
            flex: 0 0 auto;
            gap: 2px;
        }

        .analytics-pagination-bar.compact .analytics-page-btn {
            flex: 0 0 28px;
            width: 28px;
            min-width: 28px;
            max-width: 28px;
            padding: 0;
        }

        .analytics-page-btn {
            min-width: 32px;
            height: 30px;
            align-self: center;
            padding: 0 9px;
            border: 1px solid transparent;
            border-radius: 5px;
            background: transparent;
            color: var(--text-primary);
            font-size: 0.74rem;
            cursor: pointer;
            transition: all .15s ease;
        }

        .analytics-page-btn:hover:not(:disabled) {
            border-color: var(--primary-blue);
            color: var(--primary-blue);
            background: #f0f6ff;
        }

        .analytics-page-btn.active {
            background: var(--primary-blue);
            color: #fff;
            border-color: var(--primary-blue);
            font-weight: 600;
        }

        .analytics-page-btn:disabled {
            opacity: .45;
            cursor: not-allowed;
        }

        .analytics-page-ellipsis {
            display: flex;
            align-items: center;
            padding: 0 3px;
        }

        @media (max-width: 768px) {
            .analytics-pagination-bar {
                min-height: 40px;
                padding: 0 7px;
                font-size: 0.7rem;
            }

            .analytics-pagination-info {
                padding: 0 4px;
            }

            .analytics-page-btn {
                min-width: 29px;
                height: 28px;
                padding: 0 7px;
                font-size: 0.7rem;
            }
        }



        /* 分析卡片分页：与卡片背景无色差，左右/底部完整贴边 */
        .analytics-card {
            display: flex;
            flex-direction: column;
            min-height: 0;
            overflow: hidden;
        }

        .analytics-card .analytics-list {
            flex: 1 1 auto;
            min-height: 0;
        }

        .analytics-pagination-bar {
            display: flex;
            align-items: center;
            justify-content: space-between;
            width: calc(100% + 32px);
            min-height: 42px;
            margin: auto -16px -16px;
            padding: 0 16px;
            box-sizing: border-box;
            background: transparent;
            border: 0;
            color: var(--text-muted);
            font-size: 0.78rem;
            flex-shrink: 0;
        }

        .analytics-pagination-info {
            display: flex;
            align-items: center;
            white-space: nowrap;
            color: var(--text-muted);
        }

        .analytics-pagination-info strong {
            color: var(--text-primary);
        }

        .analytics-pagination-nums {
            display: flex;
            align-items: center;
            gap: 4px;
            min-width: 0;
            flex-shrink: 1;
            overflow: hidden;
        }

        .analytics-pagination-info {
            flex: 0 1 auto;
            min-width: 0;
            overflow: hidden;
            text-overflow: ellipsis;
        }

        /* 与监控日志列表分页按钮统一：透明底、边框、圆角、激活态 */
        .analytics-page-btn {
            min-width: 30px;
            height: 30px;
            padding: 0 9px;
            border: 1px solid var(--border);
            border-radius: 6px;
            background: transparent;
            color: var(--text-primary);
            font-size: 0.76rem;
            cursor: pointer;
            transition: all .15s ease;
        }

        .analytics-page-btn:hover:not(:disabled) {
            border-color: var(--primary-blue);
            color: var(--primary-blue);
            background: transparent;
        }

        .analytics-page-btn.active {
            background: var(--primary-blue);
            color: #fff;
            border-color: var(--primary-blue);
            font-weight: 600;
        }

        .analytics-page-btn:disabled {
            opacity: .45;
            cursor: not-allowed;
        }

        .analytics-page-ellipsis {
            display: flex;
            align-items: center;
            justify-content: center;
            min-width: 20px;
            color: var(--text-muted);
        }

        /* 移动端：四个分析卡片不出现内部滚动条 */
        @media (max-width: 768px) {
            .analytics-card {
                position: relative !important;
                overflow: hidden !important;
                height: 400px !important;
                min-height: 400px !important;
                box-sizing: border-box !important;
                display: flex !important;
                flex-direction: column !important;
                padding-bottom: 52px !important;
            }

            .analytics-card .analytics-list {
                overflow-y: auto !important;
                overflow-x: hidden !important;
                max-height: none !important;
                height: auto !important;
                flex: 1 1 auto !important;
                min-height: 0 !important;

                /* 保留触摸滑动/滚动，但隐藏可见滚动条 */
                -webkit-overflow-scrolling: touch;
                scrollbar-width: none;
                -ms-overflow-style: none;
            }

            .analytics-card .analytics-list::-webkit-scrollbar {
                width: 0;
                height: 0;
                display: none;
            }

            /* 移动端分页：只调整移动端，强制分页栏始终限制在卡片内容宽度内 */
            .analytics-pagination-bar {
                position: absolute !important;
                left: 0 !important;
                right: 0 !important;
                bottom: 0 !important;
                width: 100% !important;
                max-width: none !important;
                min-width: 0 !important;
                height: 40px !important;
                min-height: 40px !important;
                margin: 0 !important;
                justify-content: space-between !important;
                padding: 0 16px !important;
                box-sizing: border-box !important;
                align-items: center !important;
                flex: none !important;
                overflow: hidden !important;
                font-size: 0.70rem;
                z-index: 2;
            }

            .analytics-pagination-info {
                display: flex !important;
                align-items: center;
                flex: 0 1 auto;
                margin-left: 0 !important;
                min-width: 0;
                max-width: 46%;
                overflow: hidden;
                white-space: nowrap;
                text-overflow: ellipsis;
                padding: 0 4px;
            }

            .analytics-pagination-nums {
                display: flex !important;
                align-items: center;
                margin-right: 0 !important;
                justify-content: center;
                gap: 2px;
                flex: 0 1 auto;
                min-width: 0;
                max-width: 100%;
                overflow: hidden;
                white-space: nowrap;
            }

            .analytics-page-btn {
                flex: 0 0 26px;
                width: 26px;
                min-width: 26px;
                max-width: 26px;
                height: 28px;
                padding: 0;
                font-size: 0.70rem;
                box-sizing: border-box;
            }

            .analytics-page-ellipsis {
                flex: 0 0 auto;
                padding: 0 1px;
                line-height: 28px;
            }
        }

        /* 保留分析卡片滚动能力，但隐藏滚动条本身 */
        .analytics-card .analytics-list {
            scrollbar-width: none;
            -ms-overflow-style: none;
        }

        .analytics-card .analytics-list::-webkit-scrollbar {
            width: 0;
            height: 0;
            display: none;
        }

        .active-token-trend-card {
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 16px;
            margin-bottom: 16px;
            box-shadow: 0 1px 2px rgba(15, 23, 42, 0.03);
        }

        .active-token-trend-header {
            display: flex;
            align-items: baseline;
            justify-content: space-between;
            gap: 12px;
            margin-bottom: 10px;
        }

        .active-token-trend-title {
            font-size: 0.95rem;
            font-weight: 700;
            color: var(--text-primary);
        }

        .active-token-trend-subtitle {
            font-size: 0.72rem;
            color: var(--text-muted);
            white-space: nowrap;
        }

        .active-token-chart-wrap {
            position: relative;
            width: 100%;
            height: 230px;
        }

        #active-token-trend-chart {
            display: block;
            width: 100%;
            height: 100%;
        }

        @media (max-width: 768px) {
            .active-token-trend-card {
                padding: 12px;
                border-radius: 10px;
            }
            .active-token-trend-header {
                margin-bottom: 8px;
            }
            .active-token-trend-title {
                font-size: 0.88rem;
            }
            .active-token-trend-subtitle {
                font-size: 0.66rem;
            }
            .active-token-chart-wrap {
                height: 190px;
            }
        }
</style>
</head>
<body>
    <div class="container">
        <div class="top-bar">
            <div class="brand">
                <span class="status-dot"></span>
                <span class="brand-title" onclick="openSystemControlModal()">SubMonitor</span>
            </div>
            <div style="display: flex; align-items: center; gap: 8px;">
                <div class="last-update">最后更新: <span id="update-time">--:--:--</span></div>
                <button class="sys-control-btn" onclick="openSystemControlModal()">控制面板</button>
            </div>
        </div>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-label">总请求节点</div>
                <div class="stat-number" id="stat-total">0</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">独立 IP 数</div>
                <div class="stat-number blue" id="stat-ips">0</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">成功请求</div>
                <div class="stat-number green" id="stat-success">0</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">异常 / 拦截</div>
                <div class="stat-number red" id="stat-error">0</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">独立 TOKEN</div>
                <div class="stat-number green" id="stat-success-tokens">0</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">异常率</div>
                <div class="stat-number red" id="stat-error-rate">0%</div>
            </div>
        </div>

        <div class="active-token-trend-card">
            <div class="active-token-trend-header">
                <span class="active-token-trend-title">活跃 TOKEN 趋势</span>
                            </div>
            <div class="active-token-chart-wrap">
                <canvas id="active-token-trend-chart" aria-label="活跃 TOKEN 趋势图"></canvas>
            </div>
        </div>

        <div class="analytics-grid">
            <div class="analytics-card">
                <div class="analytics-header"><span class="analytics-title">今日 TOP IP</span></div>
                <div class="analytics-list" id="list-top-ip"></div>
            </div>
            <div class="analytics-card">
                <div class="analytics-header"><span class="analytics-title">今日 TOP TOKEN</span></div>
                <div class="analytics-list" id="list-top-token"></div>
            </div>
            <div class="analytics-card">
                <div class="analytics-header"><span class="analytics-title">今日可疑 TOKEN</span></div>
                <div class="analytics-list" id="list-sus-token"></div>
            </div>
            <div class="analytics-card">
                <div class="analytics-header"><span class="analytics-title">今日可疑 IP</span></div>
                <div class="analytics-list" id="list-sus-ip"></div>
            </div>
        </div>

        <div class="section-header">监控日志列表</div>

        <div class="control-panel">
            <div class="control-row">
                <input type="text" id="search" class="search-input" placeholder="搜索 IP、Token、用户、UA、请求信息" oninput="handleSearchInput()">
                <div class="btn-group">
                    <button class="btn" onclick="refreshLogData()">刷新数据</button>
                    <button class="btn" onclick="clearAllFilters()">重置所有</button>
                </div>
            </div>
            <div class="control-row">
                <button class="time-trigger-btn" onclick="openTimeModal()">
                    <span>时间范围:</span>
                    <span id="time-display-label" class="tag">全部时间</span>
                </button>
                <div class="btn-group">
                    <button class="btn btn-quick" onclick="setQuickMinutes(5)">近5分钟</button>
                    <button class="btn btn-quick" onclick="setQuickMinutes(10)">近10分钟</button>
                    <button class="btn btn-quick" onclick="setQuickMinutes(15)">近15分钟</button>
                    <button class="btn btn-quick" onclick="setQuickMinutes(20)">近20分钟</button>
                    <button class="btn btn-quick" onclick="setQuickMinutes(30)">近30分钟</button>
                    <button class="btn btn-quick" onclick="setQuickTime(1)">近1小时</button>
                    <button class="btn btn-quick" onclick="setTodayTime()">今天</button>
                    <button class="btn btn-quick" onclick="setYesterdayTime()">昨天</button>
                    <button class="btn btn-quick" onclick="setQuickDays(3)">近3天</button>
                    <button class="btn btn-quick" onclick="setQuickDays(7)">近7天</button>
                </div>
            </div>
        </div>

        <div class="table-card">
            <div class="table-wrapper">
                <table id="desktop-table">
                    <thead>
                        <tr>
                            <th>拉取时间</th>
                            <th>IP</th>
                            <th>Token</th>
                            <th>状态</th>
                            <th>备注</th>
                            <th>客户端 (User-Agent)</th>
                            <th style="text-align:center;">快速操作</th>
                        </tr>
                    </thead>
                    <tbody id="log-table"></tbody>
                </table>
            </div>
            <div id="pc-pagination-container"></div>
        </div>
        <div id="mobile-load-more-container"></div>
    </div>

    <div id="time-modal" class="modal-overlay">
        <div class="modal-card">
            <div class="modal-header">选择自定义时间段 (精确到秒)</div>
            <div class="modal-body">
                <div class="input-group">
                    <div class="input-label-row">
                        <label class="input-label">开始时间</label>
                        <button class="fill-helper-btn" onclick="fillZeroStart()">设为今日0时0分0秒</button>
                    </div>
                    <div class="picker-combo-row">
                        <input type="date" id="m-start-date" class="date-picker-input">
                        <select id="m-start-hour" class="time-select"></select>
                        <select id="m-start-minute" class="time-select"></select>
                        <select id="m-start-second" class="time-select"></select>
                    </div>
                </div>
                <div class="input-group">
                    <div class="input-label-row">
                        <label class="input-label">结束时间</label>
                        <button class="fill-helper-btn" onclick="fillNowEnd()">设为当前时间 (秒)</button>
                    </div>
                    <div class="picker-combo-row">
                        <input type="date" id="m-end-date" class="date-picker-input">
                        <select id="m-end-hour" class="time-select"></select>
                        <select id="m-end-minute" class="time-select"></select>
                        <select id="m-end-second" class="time-select"></select>
                    </div>
                </div>
            </div>
            <div class="modal-footer">
                <button class="btn" onclick="closeTimeModal()">关闭</button>
                <button class="btn-primary" onclick="confirmTimeRange()">确定应用</button>
            </div>
        </div>
    </div>

    <div id="system-control-modal" class="modal-overlay">
        <div class="modal-card" style="max-width: 580px;">
            <div class="modal-header" style="display:flex; justify-content:space-between; align-items:center;">
                <span>系统控制面板</span>
                <button class="logout-btn sys-btn-unified" onclick="handleLogout()">退出登录</button>
            </div>
            <div class="modal-body" style="gap:16px;">
                <div style="background:#f8fafc; border:1px solid var(--border); border-radius:10px; padding:12px; display:flex; justify-content:space-between; align-items:center;">
                    <div>
                        <div style="font-size:0.85rem; font-weight:700; color:var(--text-primary);">黑名单规则管理</div>
                        <div style="font-size:0.75rem; color:var(--text-muted); margin-top:2px;">添加封禁规则</div>
                    </div>
                    <button class="btn sys-btn-unified" onclick="openBlacklistModalFromSys()" style="color:var(--primary-red); border-color:#fecaca; background:#fef2f2;">黑名单</button>
                </div>

                <div style="background:#f8fafc; border:1px solid var(--border); border-radius:10px; padding:12px;">
                    <div style="font-size:0.85rem; font-weight:700; color:var(--text-primary); margin-bottom:4px;">更新反代目标域名</div>
                    <div style="font-size:0.75rem; color:var(--text-muted); margin-bottom:8px;">当前反代目标: <strong id="upstream-current-text" style="color:var(--primary-blue);">加载中...</strong></div>
                    <div style="display:flex; gap:6px;">
                        <input type="text" id="upstream-input" class="search-input" placeholder="输入新反代域名 (例: airport.example.com)">
                        <button class="btn sys-btn-unified" style="background:#0284c7; color:#ffffff; border:none;" onclick="submitUpstreamDomain()">更新反代</button>
                    </div>
                </div>

                <div style="background:#f8fafc; border:1px solid var(--border); border-radius:10px; padding:12px;">
                    <div style="font-size:0.85rem; font-weight:700; color:var(--text-primary); margin-bottom:4px;">更新域名并申请 SSL 证书</div>
                    <div style="display:flex; gap:6px; margin-bottom:8px;">
                        <input type="text" id="domain-input" class="search-input" placeholder="输入新域名 (例: sub.example.com)">
                        <button class="btn sys-btn-unified" style="background:var(--primary-blue); color:#ffffff; border:none;" onclick="submitDomainCert()">申请证书</button>
                    </div>
                    <div id="cert-status-box" style="font-size:0.78rem; padding:8px 10px; background:#fff; border:1px solid var(--border); border-radius:6px; font-family:monospace;">
                        <div style="display:flex; justify-content:space-between; align-items:center;">
                            <span>SSL证书状态：<span id="cert-status-text" style="color:var(--text-muted)">正在获取...</span></span>
                            <button class="fill-helper-btn" onclick="checkCertStatus()" style="font-size:0.75rem;">刷新</button>
                        </div>
                        <div id="cert-detail-info" style="display:none; margin-top:4px; padding-top:4px; border-top:1px dashed var(--border); line-height:1.5; font-size:0.73rem; color:var(--text-muted);"></div>
                    </div>
                </div>

                <div style="background:#f8fafc; border:1px solid var(--border); border-radius:10px; padding:12px;">
                    <div style="font-size:0.85rem; font-weight:700; color:var(--text-primary); margin-bottom:4px;">V2Board 用户管理连接</div>
                    <div style="font-size:0.73rem; color:var(--text-muted); margin-bottom:8px;">仅连接现有管理接口；管理员密码在服务器端加密保存，不会发送到浏览器日志。</div>
                    <div style="display:grid; grid-template-columns:1fr 1fr; gap:7px;">
                        <input type="text" id="v2b-url" class="search-input" placeholder="V2Board 面板地址，如 https://panel.example.com" style="min-width:0; grid-column:1 / -1;">
                        <input type="text" id="v2b-admin-path" class="search-input" placeholder="后台安全路径" style="min-width:0;">
                        <input type="email" id="v2b-email" class="search-input" placeholder="管理员邮箱" style="min-width:0;">
                        <input type="password" id="v2b-password" class="search-input" placeholder="管理员密码（留空则保留原密码）" style="min-width:0; grid-column:1 / -1;" autocomplete="new-password">
                    </div>
                    <div class="v2b-action-row" style="margin-top:8px;">
                        <button class="btn sys-btn-unified" style="background:var(--primary-blue); color:#fff; border:0;" onclick="saveV2BoardConfig()">保存并测试连接</button>
                        <button class="btn sys-btn-unified" onclick="testV2BoardConnection()">测试连接</button>
                        <span id="v2b-connection-status" class="v2b-connection-status" style="font-size:0.75rem; color:var(--text-muted);">尚未配置</span>
                    </div>
                </div>

                <div style="background:#f8fafc; border:1px solid var(--border); border-radius:10px; padding:12px;">
                    <div style="font-size:0.85rem; font-weight:700; color:var(--text-primary); margin-bottom:8px;">修改管理员密码</div>
                    <div style="display:flex; gap:6px;">
                        <input type="password" id="new-password-input" class="search-input" placeholder="输入新的管理员密码">
                        <button class="btn sys-btn-unified" style="background:var(--primary-green); color:#ffffff; border:none;" onclick="submitChangePassword()">修改密码</button>
                    </div>
                </div>
            </div>
            <div class="modal-footer">
                <button class="btn-primary sys-btn-unified" onclick="closeSystemControlModal()">关闭</button>
            </div>
        </div>
    </div>

    <div id="blacklist-modal" class="modal-overlay">
        <div class="modal-card" style="max-width: 580px;">
            <div class="modal-header" style="display:flex; justify-content:space-between; align-items:center;">
                <span>黑名单规则管理</span>
                <button class="fill-helper-btn" onclick="fetchBlacklistRules()" style="font-size:0.8rem;">刷新列表</button>
            </div>
            <div class="modal-body" style="gap:14px;">
                <div style="background:#f8fafc; border:1px solid var(--border); border-radius:10px; padding:12px;">
                    <div style="font-size:0.78rem; font-weight:600; color:var(--text-muted); margin-bottom:8px;">主动追加封禁规则</div>
                    <div style="display:flex; gap:6px; flex-wrap:wrap; align-items:center;">
                        <select id="bl-input-type" class="time-select" style="flex:0 0 85px;">
                            <option value="ip">IP 地址</option>
                            <option value="token">Token</option>
                            <option value="ua">User-Agent</option>
                        </select>
                        <input type="text" id="bl-input-value" class="search-input" style="flex:1; min-width:0;" placeholder="输入要封禁的目标 (例: 1.2.3.4 或 token_hash)" onkeydown="if(event.key==='Enter') submitManualBan()">
                        <button class="btn-primary" style="padding:6px 14px; font-size:0.8rem; flex-shrink:0; white-space:nowrap;" onclick="submitManualBan()">添加封禁</button>
                    </div>
                </div>

                <div style="display:flex; gap:6px; border-bottom:1px solid var(--border); padding-bottom:8px; overflow-x:auto;">
                    <button id="bl-tab-ip" class="btn btn-quick active" onclick="switchBlTab('ip')">IP 黑名单 (<span id="bl-count-ip">0</span>)</button>
                    <button id="bl-tab-token" class="btn btn-quick" onclick="switchBlTab('token')">Token 黑名单 (<span id="bl-count-token">0</span>)</button>
                    <button id="bl-tab-ua" class="btn btn-quick" onclick="switchBlTab('ua')">UA 黑名单 (<span id="bl-count-ua">0</span>)</button>
                    <button id="bl-tab-v2_users" class="btn btn-quick" onclick="switchBlTab('v2_users')">V2Board 用户 (<span id="bl-count-v2_users">0</span>)</button>
                </div>

                <div style="max-height: 280px; overflow-y: auto; display:flex; flex-direction:column; gap:6px; padding-right:2px;" id="bl-list-container">
                    <div style="text-align:center; padding:24px; color:var(--text-muted); font-size:0.8rem;">加载黑名单中...</div>
                </div>
            </div>
            <div class="modal-footer">
                <button class="btn" onclick="closeBlacklistModal()">关闭</button>
            </div>
        </div>
    </div>

    <div id="toast" class="toast">已复制到剪贴板</div>

    <script>
        // IP 归属地：只使用后端 logs.php 返回的 ip_info。
        // 前端不再直接请求 ipwho.is / ipapi.co，避免 CORS、429 限流以及大量重复查询。
        const ipGeoCache = Object.create(null);

        // 归属地显示标准化：去掉 country / region / city 重复，同时保留运营商。
        function normalizeIpGeo(info) {
            info = String(info || '').trim();
            if (!info) return '';
            const parts = info.split(/\s+/).filter(Boolean);
            const seen = new Set();
            const result = [];
            for (const part of parts) {
                if (!seen.has(part)) {
                    seen.add(part);
                    result.push(part);
                }
            }
            return result.join(' ');
        }

        function getGeo(ip) {
            if (!ip || ip === '-') return '-';
            return normalizeIpGeo(ipGeoCache[ip]) || '未知地区';
        }

        // 保留函数名以兼容现有渲染流程，但不再从浏览器访问第三方 IP API。
        function fetchAsyncIpGeo(ip, elements) {
            if (!ip || ip === '-') return;
            const els = Array.isArray(elements) ? elements.filter(Boolean) : [elements].filter(Boolean);
            const info = normalizeIpGeo(ipGeoCache[ip]) || '未知地区';
            els.forEach(el => el.textContent = info);
        }

        function refreshGeoForIp(ip) {
            // 归属地由后端统一查询和缓存。
            return;
        }

        document.addEventListener('DOMContentLoaded', () => {
            initializeApp();
            renderActiveTokenTrendChart();
            bindActiveTokenTrendTooltip();
        });

        function handleLogout() {
            if (!confirm('确定要退出当前管理面板吗？')) return;
            fetch('/api/login.php', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: 'logout=1'
            }).then(() => {
                window.location.href = '/login.html';
            }).catch(() => {
                window.location.href = '/login.html';
            });
        }

        let allLogs = [];
        let lockedStartTime = ''; 
        let lockedEndTime = '';   
        let currentBlData = { ip: [], token: [], ua: [], v2_users: [] };
        let activeBlTab = 'ip';
        let lastBlacklistSyncAt = 0;
        let v2EnrichRunning = false;
        let v2EnrichPending = false;
        let v2EnrichInFlightContext = '';
        let v2EnrichInFlightTokens = new Set();
        // Token 唯一且确认不存在后不会复用：当前页面会话内永久过滤该 Token，
        // 防止下一轮日志轮询把已隐藏的旧记录重新合并进列表。
        const confirmedMissingTokens = new Set();
        let analyticsRefreshRunning = false;

        let currentPcPage = 1;
        const pcPageSize = 50;
        const analyticsPageSize = 10;
        const analyticsPages = { topIp: 1, topToken: 1, susToken: 1, susIp: 1 };
        let analyticsSourceData = { topIp: [], topToken: [], susToken: [], susIp: [] };
        let mobileDisplayCount = 20;
        const mobileStep = 20;
        let searchDebounceTimer = null;

        // 监控日志列表的移动端布局：手机横屏时宽度可能超过768px，
        // 但仍应使用移动端卡片布局，避免误进入PC表格布局导致横屏显示凌乱。
        function isLogMobileLayout() {
            return window.innerWidth <= 768 ||
                (window.innerWidth <= 1024 && window.matchMedia('(pointer: coarse)').matches);
        }

        // 【交互防护】记录用户是否正与表格建立交互（鼠标悬停 / 文本选中）
        let isTableHovered = false;

        function isUserInteracting() {
            const hasSelection = window.getSelection && window.getSelection().toString().trim().length > 0;
            return isTableHovered || hasSelection;
        }

        function padZero(n) {
            return n.toString().padStart(2, '0');
        }

        function openSystemControlModal() {
            document.getElementById('system-control-modal').classList.add('active');
            fetchUpstreamDomain();
            checkCertStatus();
            loadV2BoardConfig();
        }

        function closeSystemControlModal() {
            document.getElementById('system-control-modal').classList.remove('active');
        }

        function openBlacklistModalFromSys() {
            closeSystemControlModal();
            openBlacklistModal();
        }

        async function fetchUpstreamDomain() {
            try {
                const res = await fetch('/api/action.php?action=get_upstream');
                const data = await res.json();
                if ((data.status === 'success' || data.code === 200) && data.upstream) {
                    document.getElementById('upstream-input').value = data.upstream;
                    const currentText = document.getElementById('upstream-current-text');
                    if (currentText) currentText.innerText = data.upstream;
                } else {
                    const currentText = document.getElementById('upstream-current-text');
                    if (currentText) currentText.innerText = '未设置';
                }
            } catch (e) {
                const currentText = document.getElementById('upstream-current-text');
                if (currentText) currentText.innerText = '获取失败';
            }
        }

        async function submitUpstreamDomain() {
            const input = document.getElementById('upstream-input');
            const target = input.value.trim();

            if (!target) {
                showToast('请输入有效的反代目标域名');
                return;
            }

            try {
                const res = await fetch('/api/action.php', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ action: 'update_upstream', target_domain: target })
                });
                const data = await res.json();
                if (data.status === 'success' || data.code === 200) {
                    showToast((data.message || '更新成功'));
                    fetchUpstreamDomain();
                } else {
                    showToast((data.message || '更新失败'));
                }
            } catch (err) {
                showToast('网络通信失败，请检查后端 API 服务状态');
            }
        }

        async function submitChangePassword() {
            const input = document.getElementById('new-password-input');
            const newPassword = input.value.trim();

            if (!newPassword) {
                showToast('请输入新的管理员密码');
                return;
            }

            const currentPassword = prompt('请输入当前的管理员密码：');
            if (!currentPassword) {
                showToast('必须输入当前密码才能修改');
                return;
            }

            const formData = new FormData();
            formData.append('current_password', currentPassword);
            formData.append('new_password', newPassword);

            try {
                const res = await fetch('/api/change_password.php', {
                    method: 'POST',
                    body: formData
                });
                const data = await res.json();
                showToast(data.message || '操作完成');
                if (data.code === 200 || data.status === 'success') {
                    input.value = '';
                    setTimeout(() => {
                        window.location.href = '/login.html';
                    }, 1500);
                }
            } catch (err) {
                showToast('修改密码请求失败，请检查接口');
            }
        }

        async function checkCertStatus() {
            const statusText = document.getElementById('cert-status-text');
            const detailBox = document.getElementById('cert-detail-info');
            if (statusText) statusText.innerText = '正在获取证书状态...';

            try {
                const res = await fetch('/api/action.php?action=cert_status');
                const data = await res.json();
                
                if ((data.status === 'success' || data.code === 200) && data.cert) {
                    const cert = data.cert;
                    let statusColor = 'var(--primary-green)';
                    let statusBadge = '证书生效中';
                    
                    if (cert.days_left !== undefined && cert.days_left <= 0) {
                        statusColor = 'var(--primary-red)';
                        statusBadge = '证书已过期';
                    } else if (cert.days_left !== undefined && cert.days_left <= 15) {
                        statusColor = '#b45309';
                        statusBadge = '证书即将过期';
                    }

                    statusText.innerHTML = `<strong style="color:${statusColor};">${statusBadge}</strong>`;
                    detailBox.style.display = 'block';
                    detailBox.innerHTML = `
                        <div>绑定域名：<strong style="color:var(--text-primary);">${escapeHtml(cert.domain || '-')}</strong></div>
                        <div>签发机构：${escapeHtml(cert.issuer || 'Let\'s Encrypt / ZeroSSL')} | 剩余有效期：<strong style="color:${statusColor};">${cert.days_left ?? '-'} 天</strong></div>
                        <div>到期时间：${escapeHtml(cert.valid_to || '-')}</div>
                    `;
                } else {
                    statusText.innerHTML = `<span style="color:#b45309;">未检测到有效 SSL 证书或尚未配置</span>`;
                    detailBox.style.display = 'none';
                }
            } catch (err) {
                statusText.innerHTML = `<span style="color:var(--text-muted);">暂无证书状态数据或接口待响应</span>`;
                detailBox.style.display = 'none';
            }
        }

        async function submitDomainCert() {
            const domainInput = document.getElementById('domain-input');
            const statusText = document.getElementById('cert-status-text');
            const detailBox = document.getElementById('cert-detail-info');
            const domain = domainInput.value.trim();

            if (!domain) {
                showToast('请输入有效的域名');
                return;
            }

            statusText.innerHTML = '正在提交域名配置，向 ACME/Let\'s Encrypt 申请 SSL 证书...';
            detailBox.style.display = 'block';
            detailBox.innerHTML = '<div style="color:var(--primary-blue);">[1/3] 正在验证域名 DNS 解析与端口可达性...<br>[2/3] 发起 ACME HTTP-01 验证挑战...</div>';

            try {
                const res = await fetch('/api/action.php', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ action: 'apply_cert', domain: domain })
                });
                const data = await res.json();
                if (data.status === 'success' || data.code === 200) {
                    showToast('已提交 SSL 申请，正在后台验证并签发证书...');
                    statusText.innerHTML = '<span style="color:var(--primary-blue);">正在后台申请 SSL 证书，请稍候...</span>';
                    detailBox.style.display = 'block';
                    detailBox.innerHTML = '<div>域名已保存。证书签发成功后，系统会自动切换为“仅允许绑定域名访问”模式。</div>';
                    setTimeout(checkCertStatus, 1500);
                    setTimeout(checkCertStatus, 5000);
                    setTimeout(checkCertStatus, 10000);
                } else {
                    statusText.innerHTML = `申请失败`;
                    detailBox.style.display = 'block';
                    detailBox.innerHTML = `<span style="color:var(--primary-red);">${escapeHtml(data.message || '请检查域名解析与服务配置')}</span>`;
                }
            } catch (err) {
                statusText.innerHTML = `请求出错`;
                detailBox.style.display = 'block';
                detailBox.innerHTML = `<span style="color:var(--primary-red);">网络通信失败，请检查后端 API 服务状态</span>`;
            }
        }

        function initTimeSelectOptions() {
            const hourOptions = Array.from({length: 24}, (_, i) => `<option value="${padZero(i)}">${i}时</option>`).join('');
            const minOptions = Array.from({length: 60}, (_, i) => `<option value="${padZero(i)}">${i}分</option>`).join('');
            const secOptions = Array.from({length: 60}, (_, i) => `<option value="${padZero(i)}">${i}秒</option>`).join('');

            document.getElementById('m-start-hour').innerHTML = hourOptions;
            document.getElementById('m-end-hour').innerHTML = hourOptions;
            document.getElementById('m-start-minute').innerHTML = minOptions;
            document.getElementById('m-end-minute').innerHTML = minOptions;
            document.getElementById('m-start-second').innerHTML = secOptions;
            document.getElementById('m-end-second').innerHTML = secOptions;
        }

        function escapeHtml(str) {
            if (!str) return '';
            return String(str)
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;')
                .replace(/'/g, '&#39;');
        }

        // 前后端统一使用 Asia/Shanghai，避免浏览器处于日本/其他时区时筛选边界错位。
        const APP_TIME_ZONE = 'Asia/Shanghai';

        function getTimeZoneParts(dateObj = new Date()) {
            const parts = new Intl.DateTimeFormat('en-CA', {
                timeZone: APP_TIME_ZONE,
                year: 'numeric', month: '2-digit', day: '2-digit',
                hour: '2-digit', minute: '2-digit', second: '2-digit',
                hourCycle: 'h23'
            }).formatToParts(dateObj);
            const map = {};
            parts.forEach(p => { if (p.type !== 'literal') map[p.type] = p.value; });
            return map;
        }

        function dateToYMD(dateObj) {
            const p = getTimeZoneParts(dateObj);
            return `${p.year}-${p.month}-${p.day}`;
        }

        function formatShanghaiDateTime(dateObj) {
            const p = getTimeZoneParts(dateObj);
            return `${p.year}-${p.month}-${p.day} ${p.hour}:${p.minute}:${p.second}`;
        }

        function setModalPickerValues(prefix, dateObj) {
            const p = getTimeZoneParts(dateObj);
            document.getElementById(`m-${prefix}-date`).value = `${p.year}-${p.month}-${p.day}`;
            document.getElementById(`m-${prefix}-hour`).value = p.hour;
            document.getElementById(`m-${prefix}-minute`).value = p.minute;
            document.getElementById(`m-${prefix}-second`).value = p.second;
        }

        function getModalPickerValues(prefix) {
            const date = document.getElementById(`m-${prefix}-date`).value;
            if (!date) return '';
            const hour = document.getElementById(`m-${prefix}-hour`).value || '00';
            const minute = document.getElementById(`m-${prefix}-minute`).value || '00';
            const second = document.getElementById(`m-${prefix}-second`).value || '00';
            return `${date} ${hour}:${minute}:${second}`;
        }

        function fillZeroStart() {
            const now = new Date();
            const p = getTimeZoneParts(now);
            document.getElementById('m-start-date').value = `${p.year}-${p.month}-${p.day}`;
            document.getElementById('m-start-hour').value = '00';
            document.getElementById('m-start-minute').value = '00';
            document.getElementById('m-start-second').value = '00';
        }

        function fillNowEnd() {
            setModalPickerValues('end', new Date());
        }

        function openTimeModal() {
            const now = new Date();
            const p = getTimeZoneParts(now);

            if (lockedStartTime) {
                const parts = lockedStartTime.split(' ');
                document.getElementById('m-start-date').value = parts[0];
                if (parts[1]) {
                    const tParts = parts[1].split(':');
                    document.getElementById('m-start-hour').value = tParts[0] || '00';
                    document.getElementById('m-start-minute').value = tParts[1] || '00';
                    document.getElementById('m-start-second').value = tParts[2] || '00';
                }
            } else {
                document.getElementById('m-start-date').value = `${p.year}-${p.month}-${p.day}`;
                document.getElementById('m-start-hour').value = '00';
                document.getElementById('m-start-minute').value = '00';
                document.getElementById('m-start-second').value = '00';
            }

            if (lockedEndTime) {
                const parts = lockedEndTime.split(' ');
                document.getElementById('m-end-date').value = parts[0];
                if (parts[1]) {
                    const tParts = parts[1].split(':');
                    document.getElementById('m-end-hour').value = tParts[0] || '00';
                    document.getElementById('m-end-minute').value = tParts[1] || '00';
                    document.getElementById('m-end-second').value = tParts[2] || '00';
                }
            } else {
                setModalPickerValues('end', now);
            }

            document.getElementById('time-modal').classList.add('active');
        }

        function closeTimeModal() {
            document.getElementById('time-modal').classList.remove('active');
        }

        function confirmTimeRange() {
            lockedStartTime = getModalPickerValues('start');
            lockedEndTime = getModalPickerValues('end');
            updateLabelAndFilter();
            closeTimeModal();
        }

        function clearAllFilters() {
            lockedStartTime = '';
            lockedEndTime = '';
            document.getElementById('search').value = '';
            currentPcPage = 1;
            mobileDisplayCount = 20;
            updateLabelAndFilter();
        }

        function setQuickMinutes(minutes) {
            const now = new Date();
            const past = new Date(now.getTime() - minutes * 60 * 1000);
            lockedStartTime = formatShanghaiDateTime(past);
            lockedEndTime = formatShanghaiDateTime(now);
            updateLabelAndFilter();
        }

        function setQuickTime(hours) {
            const now = new Date();
            const past = new Date(now.getTime() - hours * 60 * 60 * 1000);
            lockedStartTime = formatShanghaiDateTime(past);
            lockedEndTime = formatShanghaiDateTime(now);
            updateLabelAndFilter();
        }

        function setTodayTime() {
            const now = new Date();
            const p = getTimeZoneParts(now);
            lockedStartTime = `${p.year}-${p.month}-${p.day} 00:00:00`;
            lockedEndTime = formatShanghaiDateTime(now);
            updateLabelAndFilter();
        }

        function setYesterdayTime() {
            const now = new Date();
            const p = getTimeZoneParts(now);
            const yesterday = new Date(Date.UTC(Number(p.year), Number(p.month) - 1, Number(p.day) - 1));
            lockedStartTime = `${dateToYMD(yesterday)} 00:00:00`;
            lockedEndTime = `${dateToYMD(yesterday)} 23:59:59`;
            updateLabelAndFilter();
        }

        function setQuickDays(days) {
            const now = new Date();
            const past = new Date(now.getTime() - days * 24 * 60 * 60 * 1000);
            lockedStartTime = formatShanghaiDateTime(past);
            lockedEndTime = formatShanghaiDateTime(now);
            updateLabelAndFilter();
        }

        function updateLabelAndFilter() {
            const label = document.getElementById('time-display-label');
            if (!lockedStartTime && !lockedEndTime) {
                label.innerText = '全部时间';
            } else {
                const startStr = lockedStartTime || '最早';
                const endStr = lockedEndTime || '最晚';
                label.innerText = `${startStr} 至 ${endStr}`;
            }
            currentPcPage = 1;
            mobileDisplayCount = 20;
            invalidateLogRequestState();
            fetchData(true);
        }

        function handleSearchInput() {
            clearTimeout(searchDebounceTimer);
            searchDebounceTimer = setTimeout(() => {
                currentPcPage = 1;
                mobileDisplayCount = 20;
                invalidateLogRequestState();
                fetchData(true);
            }, 300);
        }

        function refreshLogData() {
            // 手动刷新不改变搜索、时间范围或当前页，只让当前请求上下文重新从服务端取一次。
            invalidateLogRequestState();
            fetchData(true);
            showToast('正在刷新日志数据…');
        }

        function showToast(text) {
            const toast = document.getElementById('toast');
            toast.innerText = text;
            toast.classList.add('show');
            setTimeout(() => toast.classList.remove('show'), 2000);
        }

        function copyToClipboard(text, label) {
            if (!text || text === '-') return;
            if (navigator.clipboard && window.isSecureContext) {
                navigator.clipboard.writeText(text).then(() => {
                    showToast('已复制 ' + label + ': ' + text);
                }).catch(() => fallbackCopy(text, label));
            } else {
                fallbackCopy(text, label);
            }
        }

        function fallbackCopy(text, label) {
            const textArea = document.createElement("textarea");
            textArea.value = text;
            textArea.style.position = "fixed";
            textArea.style.left = "-999999px";
            textArea.style.top = "-999999px";
            document.body.appendChild(textArea);
            textArea.focus();
            textArea.select();
            try {
                document.execCommand('copy');
                showToast('已复制 ' + label + ': ' + text);
            } catch (err) {
                showToast('复制失败');
            }
            document.body.removeChild(textArea);
        }

        function setBanButtonsForTarget(type, value, banned = true) {
            document.querySelectorAll('.btn-ban[data-ban-type]').forEach(btn => {
                if (btn.getAttribute('data-ban-type') !== type) return;
                const current = btn.getAttribute('data-ban-value') || '';
                const matched = type === 'ua'
                    ? (current === value || current.includes(value) || value.includes(current))
                    : current === value;
                if (!matched) return;
                btn.disabled = banned;
                btn.style.opacity = banned ? '0.45' : '';
                btn.style.cursor = banned ? 'not-allowed' : '';
                btn.textContent = banned ? ('已封 ' + (type === 'ip' ? 'IP' : type === 'token' ? 'Token' : 'UA')) : ('封 ' + (type === 'ip' ? 'IP' : type === 'token' ? 'Token' : 'UA'));
            });
        }

        async function banTarget(type, value, button) {
            if (!value || value === '-') return;
            const typeLabel = type === 'ip' ? 'IP' : (type === 'token' ? 'Token' : 'UA');
            if (button) {
                button.disabled = true;
                button.style.opacity = '0.45';
                button.style.cursor = 'wait';
                button.textContent = '检测中...';
            }

            // 点击时先向服务器确认最新黑名单，避免旧页面状态导致重复封禁。
            try {
                const synced = await fetchBlacklistRules(false);
                if (!synced) throw new Error('blacklist sync failed');
            } catch (e) {
                if (button) { button.disabled = false; button.style.opacity = ''; button.style.cursor = ''; button.textContent = '封 ' + typeLabel; }
                showToast('无法获取最新黑名单，已取消封禁操作');
                return;
            }

            const list = currentBlData[type] || [];
            const alreadyBanned = type === 'ua'
                ? list.some(item => item === value || value.includes(item) || item.includes(value))
                : list.includes(value);

            if (alreadyBanned) {
                showToast(`该 ${typeLabel} 已在黑名单中，无需重复封禁`);
                setBanButtonsForTarget(type, value, true);
                // 立即刷新当前按钮状态，不依赖打开黑名单窗口。
                renderTableFiltered(typeof window.__lastTotalCount === 'number' ? window.__lastTotalCount : allLogs.length);
                return;
            }

            if (!confirm(`确定要封禁该 ${typeLabel} 吗？\n${value}`)) { if (button) { button.disabled = false; button.style.opacity = ''; button.style.cursor = ''; button.textContent = '封 ' + typeLabel; } return; }

            try {
                const res = await fetch('/api/action.php', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ action: 'ban', type: type, value: value })
                });
                const data = await res.json();
                const success = data.status === 'success' || data.code === 200;

                if (success) {
                    // 【立即反馈】后端确认成功后，先立即更新本地黑名单状态并重绘按钮。
                    // 用户无需等待刷新日志或打开黑名单窗口，按钮立刻置灰。
                    if (!Array.isArray(currentBlData[type])) currentBlData[type] = [];
                    if (!currentBlData[type].includes(value)) currentBlData[type].push(value);
                    setBanButtonsForTarget(type, value, true);
                    renderTableFiltered(typeof window.__lastTotalCount === 'number' ? window.__lastTotalCount : allLogs.length);
                    showToast(`已成功封禁 ${typeLabel}: ${value}`);

                    // 【服务端校验】随后重新拉取真实黑名单，防止多页面/并发操作造成状态不一致。
                    await fetchBlacklistRules(false);
                    setBanButtonsForTarget(type, value, true);
                    renderTableFiltered(typeof window.__lastTotalCount === 'number' ? window.__lastTotalCount : allLogs.length);
                } else {
                    // 后端拒绝/提示已存在时，以服务器状态为准，并立即刷新按钮。
                    await fetchBlacklistRules(false);
                    renderTableFiltered(typeof window.__lastTotalCount === 'number' ? window.__lastTotalCount : allLogs.length);
                    showToast(data.message || '封禁失败');
                }
            } catch (e) {
                // 请求异常不能把按钮误标为已封禁，重新从服务端同步一次。
                await fetchBlacklistRules(false);
                renderTableFiltered(typeof window.__lastTotalCount === 'number' ? window.__lastTotalCount : allLogs.length);
                showToast('封禁请求失败，请检查接口');
            }
        }

        function openBlacklistModal() {
            document.getElementById('blacklist-modal').classList.add('active');
            fetchBlacklistRules();
        }

        function closeBlacklistModal() {
            document.getElementById('blacklist-modal').classList.remove('active');
        }

        async function fetchBlacklistRules(renderTableAfterSync = false, force = true) {
            if (!force && Date.now() - lastBlacklistSyncAt < 30000) return true;
            try {
                const res = await fetch('/api/action.php?action=list&_ts=' + Date.now(), { cache: 'no-store', headers: { 'Accept': 'application/json' } });
                if (!res.ok) throw new Error('HTTP ' + res.status);
                const ret = await res.json();
                if (ret.status === 'success' || ret.code === 200) {
                    const cachedV2Users = currentBlData.v2_users || [];
                    currentBlData = ret.data || ret.blacklist || ret.rules || { ip: [], token: [], ua: [] };
                    currentBlData.v2_users = cachedV2Users;
                    currentBlData.ip = Array.isArray(currentBlData.ip) ? currentBlData.ip : [];
                    currentBlData.token = Array.isArray(currentBlData.token) ? currentBlData.token : [];
                    currentBlData.ua = Array.isArray(currentBlData.ua) ? currentBlData.ua : [];
                    currentBlData.v2_users = Array.isArray(currentBlData.v2_users) ? currentBlData.v2_users : [];
                    lastBlacklistSyncAt = Date.now();
                    document.getElementById('bl-count-ip').innerText = (currentBlData.ip || []).length;
                    document.getElementById('bl-count-token').innerText = (currentBlData.token || []).length;
                    document.getElementById('bl-count-ua').innerText = (currentBlData.ua || []).length;
                    renderBlacklistTab();
                    if (renderTableAfterSync) {
                        renderTableFiltered(typeof window.__lastTotalCount === 'number' ? window.__lastTotalCount : allLogs.length);
                    }
                    return true;
                }
                throw new Error(ret.message || '黑名单接口返回异常');
            } catch (e) {
                console.error('fetchBlacklistRules:', e);
                return false;
            }
        }

        function switchBlTab(type) {
            activeBlTab = type;
            ['ip', 'token', 'ua', 'v2_users'].forEach(t => {
                const btn = document.getElementById(`bl-tab-${t}`);
                if (btn) btn.classList.toggle('active', t === type);
            });
            if (type === 'v2_users') loadV2BoardBanList();
            else renderBlacklistTab();
        }

        function renderBlacklistTab() {
            const container = document.getElementById('bl-list-container');
            const list = currentBlData[activeBlTab] || [];
            if (activeBlTab === 'v2_users') {
                if (!list.length) {
                    container.innerHTML = '<div style="text-align:center;padding:24px;color:var(--text-muted);font-size:0.8rem;">暂无 V2Board 封禁用户</div>';
                    return;
                }
                container.innerHTML = list.map(user => `
                    <div style="display:flex;justify-content:space-between;align-items:center;gap:10px;background:#f8fafc;border:1px solid var(--border);padding:9px 12px;border-radius:8px;font-size:0.8rem;">
                        <div style="min-width:0;overflow-wrap:anywhere;">
                            <div style="font-weight:700;color:var(--text-primary);">ID ${Number(user.id)} · ${escapeHtml(user.email || '')}</div>
                            <div style="font-size:0.72rem;color:var(--text-muted);margin-top:3px;">${escapeHtml(user.plan_name || '无订阅')}</div>
                        </div>
                        <button class="btn-unban" onclick="v2boardToggleBan(${Number(user.id)},0,this)">解封账户</button>
                    </div>
                `).join('');
                return;
            }
            if (list.length === 0) {
                container.innerHTML = `<div style="text-align:center; padding:24px; color:var(--text-muted); font-size:0.8rem;">暂无 ${activeBlTab.toUpperCase()} 封禁规则</div>`;
                return;
            }
            container.innerHTML = list.map(item => `
                <div style="display:flex; justify-content:space-between; align-items:center; background:#f8fafc; border:1px solid var(--border); padding:8px 12px; border-radius:8px; font-size:0.8rem;">
                    <span style="font-family:monospace; word-break:break-all; max-width:80%; font-weight:600; color:var(--text-primary);">${escapeHtml(item)}</span>
                    <button class="btn-unban" data-type="${activeBlTab}" data-value="${escapeHtml(item)}" onclick="unbanTarget(this.getAttribute('data-type'), this.getAttribute('data-value'))">解封</button>
                </div>
            `).join('');
        }

        async function submitManualBan() {
            const type = document.getElementById('bl-input-type').value;
            const value = document.getElementById('bl-input-value').value.trim();
            if (!value) {
                showToast('输入内容不能为空');
                return;
            }

            try {
                const res = await fetch('/api/action.php', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ action: 'ban', type, value })
                });
                const data = await res.json();
                showToast(data.message || '操作成功');
                if (data.status === 'success' || data.code === 200) {
                    document.getElementById('bl-input-value').value = '';
                    await fetchBlacklistRules();
                    await fetchData();
                }
            } catch (e) {
                showToast('网络请求失败');
            }
        }

        async function unbanTarget(type, value) {
            if (!confirm(`确定要解封该 ${type.toUpperCase()} 吗？\n${value}`)) return;
            try {
                const res = await fetch('/api/action.php', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ action: 'unban', type, value })
                });
                const data = await res.json();
                showToast(data.message || '操作成功');
                if (data.status === 'success' || data.code === 200) {
                    await fetchBlacklistRules();
                    await fetchData();
                }
            } catch (e) {
                showToast('网络请求失败');
            }
        }

        async function loadV2BoardConfig() {
            try {
                const res = await fetch('/api/action.php?action=v2board_get_config', { cache: 'no-store' });
                const ret = await res.json();
                if (ret.status !== 'success') throw new Error(ret.message || '读取配置失败');
                const c = ret.config || {};
                document.getElementById('v2b-url').value = c.base_url || '';
                document.getElementById('v2b-admin-path').value = c.admin_path || '';
                document.getElementById('v2b-email').value = c.email || '';
                document.getElementById('v2b-password').value = '';
                document.getElementById('v2b-password').placeholder = c.password_set ? '密码已加密保存（留空则不修改）' : 'V2Board 管理员密码';
                document.getElementById('v2b-connection-status').textContent = c.password_set ? '已保存连接配置' : '尚未配置';
            } catch (e) {
                document.getElementById('v2b-connection-status').textContent = e.message;
            }
        }

        async function saveV2BoardConfig() {
            const payload = {
                action: 'v2board_save_config',
                base_url: document.getElementById('v2b-url').value.trim(),
                admin_path: document.getElementById('v2b-admin-path').value.trim(),
                email: document.getElementById('v2b-email').value.trim(),
                password: document.getElementById('v2b-password').value
            };
            const status = document.getElementById('v2b-connection-status');
            status.textContent = '正在连接并验证管理员身份...';
            try {
                const res = await fetch('/api/action.php', {
                    method: 'POST', headers: {'Content-Type':'application/json'},
                    body: JSON.stringify(payload)
                });
                const ret = await res.json();
                status.textContent = ret.message || '连接失败';
                status.style.color = ret.status === 'success' ? '#16a34a' : '#dc2626';
                if (ret.status === 'success') {
                    document.getElementById('v2b-password').value = '';
                    await fetchData(true);
                    showToast('V2Board 连接配置已保存');
                }
            } catch (e) {
                status.textContent = '连接失败：' + e.message;
                status.style.color = '#dc2626';
            }
        }

        async function testV2BoardConnection() {
            const status = document.getElementById('v2b-connection-status');
            status.textContent = '正在测试...';
            try {
                const res = await fetch('/api/action.php', {
                    method: 'POST', headers: {'Content-Type':'application/json'},
                    body: JSON.stringify({action:'v2board_test'})
                });
                const ret = await res.json();
                status.textContent = ret.message || '测试失败';
                status.style.color = ret.status === 'success' ? '#16a34a' : '#dc2626';
            } catch (e) {
                status.textContent = '测试失败：' + e.message;
                status.style.color = '#dc2626';
            }
        }

        async function v2boardToggleBan(userId, banned, button) {
            const actionText = Number(banned) === 1 ? '封禁' : '解封';
            if (!confirm(`确定要${actionText} V2Board 用户 ID ${userId} 吗？\n此操作会作用于整个账户。`)) return;
            if (button) { button.disabled = true; button.textContent = '处理中...'; }
            try {
                const res = await fetch('/api/action.php', {
                    method: 'POST', headers: {'Content-Type':'application/json'},
                    body: JSON.stringify({action:'v2board_set_banned', user_id:Number(userId), banned:Number(banned)})
                });
                const ret = await res.json();
                if (ret.status !== 'success') throw new Error(ret.message || '操作失败');
                showToast(ret.message || '操作成功');
                await fetchBlacklistRules(false);
                await fetchData(true);
                if (activeBlTab === 'v2_users') await loadV2BoardBanList();
            } catch (e) {
                showToast(e.message || 'V2Board 操作失败');
                if (button) button.disabled = false;
            }
        }

        async function loadV2BoardBanList() {
            const container = document.getElementById('bl-list-container');
            if (container) container.innerHTML = '<div style="text-align:center;padding:20px;color:var(--text-muted);">正在读取 V2Board 封禁名单...</div>';
            try {
                const res = await fetch('/api/action.php?action=v2board_banned_list&_ts=' + Date.now(), {cache:'no-store'});
                const ret = await res.json();
                if (ret.status !== 'success') throw new Error(ret.message || '读取封禁名单失败');
                currentBlData.v2_users = Array.isArray(ret.data) ? ret.data : [];
                const count = document.getElementById('bl-count-v2_users');
                if (count) count.textContent = currentBlData.v2_users.length;
                renderBlacklistTab();
            } catch (e) {
                if (container) container.innerHTML = `<div style="text-align:center;padding:20px;color:#dc2626;">${escapeHtml(e.message)}</div>`;
            }
        }

        function renderV2BoardUserInfo(log, mobile = false) {
            if (!log || !log.user_id) {
                const message = log?.v2board_status === 'error' ? 'V2Board 查询失败' :
                    log?.v2board_status === 'not_configured' ? '尚未配置 V2Board' : '未关联 V2Board 用户';
                const color = log?.v2board_status === 'error' ? '#dc2626' : 'var(--text-muted)';
                const displayMessage = log?.v2board_status === 'pending' ? '正在更新 V2Board 用户信息…' : message;
                return `<div style="margin-top:5px;font-size:0.72rem;color:${color};">${displayMessage}</div>`;
            }
            const uid = Number(log.user_id);
            const banned = log.user_banned === true || Number(log.user_banned) === 1;
            const status = banned
                ? `<span style="color:#dc2626;font-weight:700;">已封禁</span>`
                : `<span style="color:#16a34a;font-weight:700;">正常</span>`;
            const action = banned ? 0 : 1;
            const btnClass = banned ? 'btn-unban' : 'btn-ban';
            const btnText = banned ? '解封账户' : '封禁账户';
            return `<div class="v2board-user-info${banned ? ' is-banned' : ''}">
                <div class="v2b-user-line">
                    <strong>ID：${uid}</strong>
                    ${status}
                </div>
                <div class="v2b-user-line v2b-user-detail">邮箱：${escapeHtml(log.user_email || '')}</div>
                <div class="v2b-user-line v2b-user-detail">套餐：${escapeHtml(log.plan_name || '无订阅')}</div>
                ${log.user_remark ? `<div class="v2b-user-line v2b-user-detail">备注：${escapeHtml(log.user_remark)}</div>` : ''}
                <div class="v2b-user-actions">
                    <button class="${btnClass}" onclick="v2boardToggleBan(${uid},${action},this)">${btnText}</button>
                </div>
            </div>`;
        }

        function renderCopyBtn(text, label) {
            if (!text || text === '-') return '';
            const safeText = escapeHtml(text);
            const copyIconSvg = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>`;
            return `<button class="btn-copy-icon" data-copy="${safeText}" data-label="${escapeHtml(label)}" onclick="event.stopPropagation(); copyToClipboard(this.getAttribute('data-copy'), this.getAttribute('data-label'))" title="复制 ${escapeHtml(label)}">${copyIconSvg}</button>`;
        }

        function toggleExpand(el) {
            el.classList.toggle('expanded');
        }

        function getStatusBadge(code) {
            const strCode = String(code);
            switch(strCode) {
                case '200': return `<span class="badge badge-200">${strCode}</span>`;
                case '400': return `<span class="badge badge-400">${strCode}</span>`;
                case '401': return `<span class="badge badge-401">${strCode}</span>`;
                case '403': return `<span class="badge badge-403">${strCode}</span>`;
                case '404': return `<span class="badge badge-404">${strCode}</span>`;
                case '429': return `<span class="badge badge-429">${strCode}</span>`;
                case '500':
                case '502':
                case '503': return `<span class="badge badge-500">${strCode}</span>`;
                default: return `<span class="badge badge-other">${strCode}</span>`;
            }
        }

        function getRemark(code) {
            const strCode = String(code);
            switch(strCode) {
                case '200': return '<span class="remark-text" style="color:#16a34a;">拉取订阅</span>';
                case '400': return '<span class="remark-text" style="color:#b45309;">伪造请求</span>';
                case '401': return '<span class="remark-text" style="color:#dc2626;">未授权请求</span>';
                case '403': return '<span class="remark-text" style="color:#dc2626;">异常用户</span>';
                case '404': return '<span class="remark-text" style="color:#6b21a8;">路径错误</span>';
                case '429': return '<span class="remark-text" style="color:#ea580c;">请求过多</span>';
                case '500':
                case '502':
                case '503': return '<span class="remark-text" style="color:#9f1239;">服务异常</span>';
                default: return `<span class="remark-text" style="color:var(--text-muted);">-</span>`;
            }
        }

        function renderPillBox(rawText, label) {
            if (!rawText || rawText === '-') {
                return '<span style="color:var(--text-muted)">-</span>';
            }
            const safeText = escapeHtml(rawText);
            return `<div class="pill-box" onclick="toggleExpand(this)" title="点击复制内容" style="justify-content: center;">
                <span data-copy="${safeText}" data-label="${escapeHtml(label)}" onclick="event.stopPropagation(); copyToClipboard(this.getAttribute('data-copy'), this.getAttribute('data-label'))">${safeText}</span>
            </div>`;
        }

        // 【防抖动优化】保存上一次已经渲染的数据指纹。
        // 定时刷新仍然会请求最新日志，但只有数据真正发生变化时才重绘日志列表。
        let lastLogSignature = '';
        let lastAnalyticsSignature = '';
        let lastTotalCount = null;
        let lastRenderMode = '';
        let fetchDataRunning = false;
        let fetchDataQueued = false;
        // 排队请求保留强制刷新意图，避免加载更多恰好遇到轮询时被降级成普通轮询。
        let fetchDataQueuedForce = false;
        let fetchRequestSeq = 0;
        let activeFetchContext = '';

        function getLogSignature(logs) {
            try {
                return JSON.stringify(logs || []);
            } catch (e) {
                return String(logs || '');
            }
        }

        function getAnalyticsSignature(analytics) {
            try {
                return JSON.stringify(analytics || {});
            } catch (e) {
                return String(analytics || '');
            }
        }

        function getCurrentFilterContext() {
            const isMobile = isLogMobileLayout();
            const searchVal = (document.getElementById('search')?.value || '').trim();
            return JSON.stringify({
                search: searchVal,
                start_time: lockedStartTime || '',
                end_time: lockedEndTime || '',
                page: isMobile ? 1 : currentPcPage,
                limit: isMobile ? mobileDisplayCount : pcPageSize,
                mode: isMobile ? 'mobile' : 'desktop'
            });
        }

        function invalidateLogRequestState() {
            // 任何搜索/时间/分页条件变化，都让正在途中的旧响应失效。
            fetchRequestSeq++;
            activeFetchContext = getCurrentFilterContext();
            lastLogSignature = '';
            lastTotalCount = null;
            lastRenderMode = '';
        }

        async function enrichVisibleTokens(logs, requestContext) {
            if (!Array.isArray(logs) || logs.length === 0) return;
            const tokens = [...new Set(logs.map(item => item.token).filter(token =>
                token && token !== '-' && !confirmedMissingTokens.has(token)
            ))];
            if (!tokens.length) return;
            if (v2EnrichRunning) {
                // 相同页面、相同 Token 不因每 5 秒轮询而重复排队；只有筛选变化或出现新 Token 才补查。
                if (requestContext !== v2EnrichInFlightContext || tokens.some(token => !v2EnrichInFlightTokens.has(token))) {
                    v2EnrichPending = true;
                }
                return;
            }

            v2EnrichRunning = true;
            v2EnrichInFlightContext = requestContext;
            v2EnrichInFlightTokens = new Set(tokens);
            try {
                // enrich 接口单次最多处理 200 个 Token。移动端加载更多后可能超过 200 个，
                // 这里分批顺序提交，避免后续历史卡片中的 Token 永远得不到用户信息。
                const updates = {};
                for (let offset = 0; offset < tokens.length; offset += 200) {
                    if (requestContext !== getCurrentFilterContext()) {
                        v2EnrichPending = true;
                        return;
                    }
                    const tokenBatch = tokens.slice(offset, offset + 200);
                    try {
                        const res = await fetch('/api/v2board_enrich.php', {
                            method: 'POST',
                            cache: 'no-store',
                            headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
                            body: JSON.stringify({ tokens: tokenBatch })
                        });
                        if (!res.ok) throw new Error(`HTTP ${res.status}`);
                        const ret = await res.json();
                        if (ret.status === 'success' && ret.data) Object.assign(updates, ret.data);
                    } catch (batchError) {
                        console.warn('V2Board token batch enrichment:', batchError);
                    }
                }
                if (!Object.keys(updates).length) return;

                // 不再用日志轮询序号判定异步查询过期。5 秒轮询会不断增加序号，
                // 这会让稍慢的 V2Board 结果永远无法落地；只在用户切换筛选上下文时丢弃。
                if (requestContext !== getCurrentFilterContext()) {
                    v2EnrichPending = true;
                    return;
                }

                let listChanged = false;
                let newlyMissing = false;
                const updatedLogs = [];

                for (const log of allLogs) {
                    const user = updates[log.token];
                    if (!user) {
                        updatedLogs.push(log);
                        continue;
                    }

                    if (user.lookup_status === 'not_found') {
                        if (!confirmedMissingTokens.has(log.token)) {
                            confirmedMissingTokens.add(log.token);
                            newlyMissing = true;
                        }
                        listChanged = true;
                        continue;
                    }

                    if (user.lookup_status === 'matched') {
                        const next = {
                            ...log,
                            user_id: Number(user.user_id || 0),
                            user_email: user.email || '',
                            plan_name: user.plan_name || '无订阅',
                            user_remark: user.remarks || '',
                            user_banned: Number(user.banned) === 1,
                            v2board_status: 'matched'
                        };
                        if (
                            next.user_id !== Number(log.user_id || 0) ||
                            next.user_email !== (log.user_email || '') ||
                            next.plan_name !== (log.plan_name || '') ||
                            next.user_remark !== (log.user_remark || '') ||
                            next.user_banned !== (Number(log.user_banned) === 1) ||
                            next.v2board_status !== log.v2board_status
                        ) listChanged = true;
                        updatedLogs.push(next);
                        continue;
                    }

                    const nextStatus = user.lookup_status || 'error';
                    if (log.v2board_status !== nextStatus) {
                        updatedLogs.push({ ...log, v2board_status: nextStatus });
                        listChanged = true;
                    } else {
                        updatedLogs.push(log);
                    }
                }

                if (listChanged) {
                    allLogs = updatedLogs;
                    lastLogSignature = getLogSignature(allLogs);
                    renderTableFiltered(typeof window.__lastTotalCount === 'number' ? window.__lastTotalCount : allLogs.length);
                }

                // 只有首次确认出新的不存在 Token 时才同步一次后端总数。
                // 不再每次 enrich 都重新拉整页；确认过的 Token 会被 Set 持续过滤。
                if (newlyMissing) {
                    setTimeout(() => {
                        if (requestContext === getCurrentFilterContext()) fetchData(false);
                    }, 0);
                }
            } catch (err) {
                console.warn('V2Board async enrichment:', err);
            } finally {
                v2EnrichRunning = false;
                v2EnrichInFlightContext = '';
                v2EnrichInFlightTokens.clear();
                if (v2EnrichPending) {
                    v2EnrichPending = false;
                    const latestContext = getCurrentFilterContext();
                    setTimeout(() => enrichVisibleTokens(allLogs, latestContext), 0);
                }
            }
        }

        async function refreshAnalytics(requestContext, requestSeq) {
            if (analyticsRefreshRunning) return;
            analyticsRefreshRunning = true;
            try {
                const res = await fetch('/api/analytics.php', { cache: 'no-store', headers: { 'Accept': 'application/json' } });
                if (!res.ok) throw new Error(`HTTP ${res.status}`);
                const ret = await res.json();
                if (ret.status !== 'success' || !ret.analytics) return;
                if (requestSeq !== fetchRequestSeq || requestContext !== getCurrentFilterContext()) return;
                const signature = getAnalyticsSignature(ret.analytics);
                if (signature !== lastAnalyticsSignature) {
                    renderAnalyticsCards(ret.analytics);
                    lastAnalyticsSignature = signature;
                }
            } catch (err) {
                console.warn('Daily analytics refresh:', err);
            } finally {
                analyticsRefreshRunning = false;
                if (requestSeq !== fetchRequestSeq) {
                    setTimeout(() => refreshAnalytics(getCurrentFilterContext(), fetchRequestSeq), 0);
                }
            }
        }

        async function fetchData(forceRefresh = false) {
            // 同一时刻只允许一个请求；如果期间发生了新筛选/搜索/翻页，结束后只补发最新上下文。
            if (fetchDataRunning) {
                fetchDataQueued = true;
                fetchDataQueuedForce = fetchDataQueuedForce || forceRefresh;
                return;
            }

            fetchDataRunning = true;
            const requestSeq = ++fetchRequestSeq;
            const requestContext = getCurrentFilterContext();
            activeFetchContext = requestContext;

            try {
                const isMobile = isLogMobileLayout();
                const searchVal = (document.getElementById('search')?.value || '').trim();
                // 手机端加载过更多历史记录后，5 秒轮询只取最新一屏；历史部分由前端合并保留。
                // 用户主动刷新、筛选变化或点击加载更多时，仍按完整显示数量重新取数。
                const fetchLimit = isMobile
                    ? ((!forceRefresh && allLogs.length > mobileStep) ? mobileStep : mobileDisplayCount)
                    : pcPageSize;
                const fetchPage = isMobile ? 1 : currentPcPage;

                const params = new URLSearchParams({
                    page: fetchPage,
                    limit: fetchLimit,
                    // 明确告诉后端：搜索/时间条件必须在“全部日志”上过滤后再分页。
                    scope: 'all'
                });

                if (searchVal) params.append('search', searchVal);
                if (lockedStartTime) params.append('start_time', lockedStartTime);
                if (lockedEndTime) params.append('end_time', lockedEndTime);

                const res = await fetch(`/api/logs.php?${params.toString()}`, {
                    cache: 'no-store',
                    headers: { 'Cache-Control': 'no-cache' }
                });

                if (!res.ok) throw new Error(`HTTP ${res.status}`);

                const responseData = await res.json();

                // 请求返回后再次核对：如果期间用户改过搜索、时间、页码或设备模式，
                // 这一份结果绝对不能写进页面，否则就会出现“切到有日志仍显示无日志”。
                const latestContext = getCurrentFilterContext();
                if (requestSeq !== fetchRequestSeq || requestContext !== latestContext || requestContext !== activeFetchContext) {
                    fetchDataQueued = true;
                    return;
                }

                const newLogs = (Array.isArray(responseData.data) ? responseData.data : [])
                    .filter(log => !log || !log.token || !confirmedMissingTokens.has(log.token));
                const totalCount = responseData.total !== undefined
                    ? Number(responseData.total) || 0
                    : newLogs.length;
                const analytics = responseData.analytics || {};

                // 先构造本轮最终列表，再比较签名；移动端签名必须覆盖“最新页 + 已加载历史”，
                // 否则每轮只取 20 条会与 40/60 条的旧签名不一致，造成无意义重绘。
                const mergedLogs = (isMobile && !forceRefresh && allLogs.length > 0)
                    ? mergeMobileLiveLogs(newLogs, allLogs)
                    : newLogs;
                const newLogSignature = getLogSignature(mergedLogs);
                const newAnalyticsSignature = getAnalyticsSignature(analytics);
                const renderMode = isMobile ? 'mobile' : 'desktop';
                const logsChanged = newLogSignature !== lastLogSignature;
                const analyticsChanged = newAnalyticsSignature !== lastAnalyticsSignature;
                const totalChanged = totalCount !== lastTotalCount;
                const renderModeChanged = renderMode !== lastRenderMode;

                // PC 页码只允许落在当前筛选结果范围内；筛选条件变化时已经在入口处重置为 1。
                if (!isMobile) {
                    const totalPages = Math.max(1, Math.ceil(totalCount / pcPageSize));
                    if (currentPcPage > totalPages) {
                        // 筛选结果减少时停留在最后一个有效页，避免无故跳回第一页。
                        currentPcPage = totalPages;
                        invalidateLogRequestState();
                        fetchDataQueued = true;
                        return;
                    }
                }

                // 普通实时轮询只刷新顶部最新记录，并与已加载历史记录合并。
                // 这样新日志可以实时进入列表，但不会因为重新请求 page 1 而把已加载的旧记录挤掉。
                allLogs = mergedLogs;
                window.__lastTotalCount = totalCount;

                const now = new Date();
                document.getElementById('update-time').innerText =
                    getTimeZoneParts(now).hour + ':' +
                    getTimeZoneParts(now).minute + ':' +
                    getTimeZoneParts(now).second;

                renderStats(allLogs, responseData);

                if (analyticsChanged || lastAnalyticsSignature === '') {
                    renderAnalyticsCards(analytics);
                }

                // filter context 变化时，即使新旧结果碰巧相同，也强制刷新一次表格状态。
                const contextChanged = activeFetchContext !== requestContext;
                if (forceRefresh || contextChanged || logsChanged || totalChanged || renderModeChanged || lastLogSignature === '') {
                    renderTableFiltered(totalCount);
                }

                lastLogSignature = newLogSignature;
                lastAnalyticsSignature = newAnalyticsSignature;
                lastTotalCount = totalCount;
                lastRenderMode = renderMode;
                activeFetchContext = requestContext;
                // 日志先显示；V2Board 备注和用户状态在独立请求中补齐，不阻塞首屏与翻页。
                enrichVisibleTokens(allLogs, requestContext);
                refreshAnalytics(requestContext, requestSeq);

            } catch (err) {
                console.error('fetchData error:', err);
                // 只有当前请求仍然对应当前筛选条件时，才显示错误。
                if (requestSeq === fetchRequestSeq && requestContext === getCurrentFilterContext()) {
                    if (lastLogSignature === '') {
                        document.getElementById('log-table').innerHTML =
                            '<tr><td colspan="7" class="empty-state" style="color:var(--primary-red)">获取日志失败，请检查服务状态。</td></tr>';
                    }
                }
            } finally {
                fetchDataRunning = false;
                if (fetchDataQueued) {
                    const queuedForce = fetchDataQueuedForce;
                    fetchDataQueued = false;
                    fetchDataQueuedForce = false;
                    setTimeout(() => fetchData(queuedForce), 0);
                }
            }
        }

        function renderTableFiltered(totalCount) {
            renderTable(allLogs, totalCount);
            setTimeout(() => {
                const ips = [...new Set(allLogs.map(x => x.ip).filter(ip => ip && ip !== '-'))];
                ips.forEach(refreshGeoForIp);
            }, 20);
        }

        function renderStats(logs, responseData) {
            if (responseData && responseData.total_ips !== undefined) {
                document.getElementById('stat-total').innerText = responseData.total || 0;
                document.getElementById('stat-ips').innerText = responseData.total_ips || 0;
                document.getElementById('stat-success').innerText = responseData.total_success || 0;
                document.getElementById('stat-error').innerText = responseData.total_error || 0;
                document.getElementById('stat-success-tokens').innerText = responseData.total_success_tokens || 0;
                document.getElementById('stat-error-rate').innerText = (responseData.error_rate || 0) + '%';
            } else {
                document.getElementById('stat-total').innerText = logs.length;
                const ips = new Set(logs.map(l => l.ip).filter(Boolean));
                document.getElementById('stat-ips').innerText = ips.size;
                const success = logs.filter(l => String(l.status) === '200').length;
                document.getElementById('stat-success').innerText = success;
                document.getElementById('stat-error').innerText = logs.length - success;
                const successTokens = new Set(logs.filter(l => String(l.status) === '200' && l.token && l.token !== '-').map(l => l.token));
                document.getElementById('stat-success-tokens').innerText = successTokens.size;
                document.getElementById('stat-error-rate').innerText = (logs.length ? (((logs.length - success) / logs.length) * 100).toFixed(1) : '0') + '%';
            }
        }

        const activeTokenTrendLabels = <?php echo json_encode($tokenTrendLabels, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES); ?>;
        const activeTokenTrendValues = <?php echo json_encode($tokenTrendValues, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES); ?>;

        // [折线图修复 v2026-08-19-02] X轴首尾防挤压 + 移动端数据指针竖向虚线
        function renderActiveTokenTrendChart() {
            const canvas = document.getElementById('active-token-trend-chart');
            if (!canvas) return;
            const wrap = canvas.parentElement;
            const rect = wrap.getBoundingClientRect();
            const dpr = window.devicePixelRatio || 1;
            const width = Math.max(320, Math.floor(rect.width));
            const height = Math.max(160, Math.floor(rect.height));
            canvas.width = Math.floor(width * dpr);
            canvas.height = Math.floor(height * dpr);
            canvas.style.width = width + 'px';
            canvas.style.height = height + 'px';
            canvas.style.touchAction = 'pan-y';

            const ctx = canvas.getContext('2d');
            ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
            ctx.clearRect(0, 0, width, height);

            const labels = Array.isArray(activeTokenTrendLabels) ? activeTokenTrendLabels : [];
            const values = Array.isArray(activeTokenTrendValues) ? activeTokenTrendValues.map(v => Number(v) || 0) : [];
            if (!labels.length || !values.length) return;

            const left = 42, right = 12, top = 12, bottom = 34;
            const plotW = Math.max(1, width - left - right);
            const plotH = Math.max(1, height - top - bottom);
            const maxValue = Math.max(1, ...values);
            const yStep = maxValue <= 5 ? 1 : Math.ceil(maxValue / 5);
            const yMax = Math.max(yStep * 5, maxValue);

            ctx.font = '11px -apple-system, BlinkMacSystemFont, "Segoe UI", Arial, sans-serif';
            ctx.textBaseline = 'middle';
            ctx.textAlign = 'right';
            ctx.strokeStyle = '#e2e8f0';
            ctx.fillStyle = '#64748b';
            ctx.lineWidth = 1;

            for (let i = 0; i <= 5; i++) {
                const value = yMax * i / 5;
                const y = top + plotH - (value / yMax) * plotH;
                ctx.beginPath();
                ctx.moveTo(left, y);
                ctx.lineTo(width - right, y);
                ctx.stroke();
                ctx.fillText(String(Math.round(value)), left - 7, y);
            }

            const points = values.map((value, i) => {
                const x = labels.length === 1 ? left + plotW / 2 : left + (i / (labels.length - 1)) * plotW;
                const y = top + plotH - (value / yMax) * plotH;
                return {x, y, value};
            });

            ctx.beginPath();
            points.forEach((p, i) => i ? ctx.lineTo(p.x, p.y) : ctx.moveTo(p.x, p.y));
            ctx.strokeStyle = '#16a34a';
            ctx.lineWidth = 2;
            // 转折处使用圆角连接，避免尖角像箭头一样从数据圆点外侧突出。
            ctx.lineJoin = 'round';
            ctx.lineCap = 'round';
            ctx.stroke();

            points.forEach(p => {
                ctx.beginPath();
                ctx.arc(p.x, p.y, 3, 0, Math.PI * 2);
                ctx.fillStyle = '#16a34a';
                ctx.fill();
            });

            // X 轴日期：移动端竖屏优先保证首尾日期完整显示，
            // 只有在实际文字宽度允许时才增加中间日期，避免最后一个日期被挤压。
            ctx.fillStyle = '#64748b';
            ctx.textBaseline = 'top';
            const isNarrowMobile = window.matchMedia('(max-width: 480px) and (orientation: portrait)').matches;
            const labelFontSize = isNarrowMobile ? 10 : 11;
            ctx.font = `${labelFontSize}px -apple-system, BlinkMacSystemFont, "Segoe UI", Arial, sans-serif`;
            const labelY = top + plotH + 8;
            const labelGap = isNarrowMobile ? 12 : 16;

            const labelItems = [];
            const pushLabel = (i, align) => {
                if (i < 0 || i >= labels.length) return;
                const text = String(labels[i]);
                const textWidth = ctx.measureText(text).width;
                let x = points[i].x;
                if (align === 'left') x = Math.max(left, x);
                if (align === 'right') x = Math.min(width - right, x);
                const boxLeft = align === 'left' ? x : align === 'right' ? x - textWidth : x - textWidth / 2;
                const boxRight = align === 'left' ? x + textWidth : align === 'right' ? x : x + textWidth / 2;
                labelItems.push({i, text, x, align, boxLeft, boxRight});
            };

            if (labels.length === 1) {
                pushLabel(0, 'center');
            } else {
                // 首尾标签分别向内展开，确保最后一个日期不会被 Canvas 右边缘裁掉。
                pushLabel(0, 'left');
                pushLabel(labels.length - 1, 'right');

                // 中间标签只在不与首尾标签发生碰撞时绘制。窄屏最多增加一个中间标签。
                const maxMiddle = isNarrowMobile ? 1 : (width <= 600 ? 2 : Math.floor(labels.length / 4));
                const candidates = [];
                if (maxMiddle > 0) {
                    const step = Math.max(1, Math.ceil((labels.length - 1) / (maxMiddle + 1)));
                    for (let i = step; i < labels.length - 1 && candidates.length < maxMiddle; i += step) {
                        candidates.push(i);
                    }
                }
                candidates.forEach(i => {
                    const text = String(labels[i]);
                    const textWidth = ctx.measureText(text).width;
                    const x = points[i].x;
                    const item = {i, text, x, align: 'center', boxLeft: x - textWidth / 2, boxRight: x + textWidth / 2};
                    if (labelItems.every(existing => item.boxRight + labelGap < existing.boxLeft || item.boxLeft - labelGap > existing.boxRight)) {
                        labelItems.push(item);
                    }
                });
            }

            labelItems.sort((a, b) => a.i - b.i);
            labelItems.forEach(item => {
                ctx.textAlign = item.align;
                ctx.fillText(item.text, item.x, labelY);
            });

            // 移动端数据指针：必须在每次完整重绘的最后阶段绘制，避免重绘 Canvas 后竖向虚线消失。
            // 这是最终绘制层，不参与统计数据和折线计算。
            const selectedIndex = Number.isInteger(canvas._activeTokenTrendSelectedIndex)
                ? canvas._activeTokenTrendSelectedIndex : -1;
            if (selectedIndex >= 0 && selectedIndex < points.length) {
                const selectedPoint = points[selectedIndex];
                ctx.save();
                ctx.beginPath();
                ctx.setLineDash([4, 4]);
                ctx.strokeStyle = 'rgba(100, 116, 139, 0.72)';
                ctx.lineWidth = 1;
                ctx.moveTo(selectedPoint.x, top);
                ctx.lineTo(selectedPoint.x, top + plotH);
                ctx.stroke();
                ctx.setLineDash([]);

                ctx.beginPath();
                ctx.arc(selectedPoint.x, selectedPoint.y, 5, 0, Math.PI * 2);
                ctx.fillStyle = '#ffffff';
                ctx.fill();
                ctx.beginPath();
                ctx.arc(selectedPoint.x, selectedPoint.y, 4, 0, Math.PI * 2);
                ctx.fillStyle = '#16a34a';
                ctx.fill();
                ctx.restore();
            }

            canvas._activeTokenTrendPoints = points;
            canvas._activeTokenTrendLabels = labels;
            canvas._activeTokenTrendValues = values;
            canvas._activeTokenTrendPlot = {top, plotH, width, height, dpr};
        }

        function bindActiveTokenTrendTooltip() {
            const canvas = document.getElementById('active-token-trend-chart');
            if (!canvas || canvas.dataset.tooltipBound === '1') return;
            canvas.dataset.tooltipBound = '1';

            const tip = document.createElement('div');
            tip.style.cssText = 'position:fixed;display:none;z-index:9999;padding:6px 9px;border-radius:7px;background:#0f172a;color:#fff;font-size:12px;pointer-events:none;white-space:nowrap;box-shadow:0 4px 12px rgba(0,0,0,.15);';
            document.body.appendChild(tip);

            // 统一按实际布局视口计算提示位置，确保气泡完整留在可视区域内。
            const positionTip = (clientX, clientY) => {
                const viewportWidth = document.documentElement.clientWidth || window.innerWidth;
                const viewportHeight = document.documentElement.clientHeight || window.innerHeight;
                const tipRect = tip.getBoundingClientRect();
                const tipWidth = tipRect.width || tip.offsetWidth;
                const tipHeight = tipRect.height || tip.offsetHeight;
                const left = Math.max(8, Math.min(clientX + 12, viewportWidth - tipWidth - 8));
                const top = Math.max(8, Math.min(clientY - 38, viewportHeight - tipHeight - 8));
                tip.style.left = left + 'px';
                tip.style.top = top + 'px';
            };

            canvas.addEventListener('mousemove', e => {
                const points = canvas._activeTokenTrendPoints || [];
                if (!points.length) return;
                const rect = canvas.getBoundingClientRect();
                const x = e.clientX - rect.left;
                let nearest = points[0], distance = Math.abs(x - points[0].x);
                points.forEach(p => {
                    const d = Math.abs(x - p.x);
                    if (d < distance) { distance = d; nearest = p; }
                });
                if (distance > 16) {
                    if (!canvas._activeTokenTrendTipPinned) tip.style.display = 'none';
                    return;
                }
                if (canvas._activeTokenTrendTipPinned) return;
                const idx = points.indexOf(nearest);
                tip.textContent = `${canvas._activeTokenTrendLabels[idx]}：${nearest.value} 个活跃TOKEN`;
                tip.style.display = 'block';
                positionTip(e.clientX, e.clientY);
            });
            canvas.addEventListener('mouseleave', () => {
                // 鼠标离开图表时隐藏悬浮提示。
                tip.style.display = 'none';
            });

            // 点击趋势图数据点后固定显示详细信息。
            // 移动端采用“滑动数据指针”：横向滑动选择数据点，纵向手势交给页面滚动。
            const hideTip = () => {
                tip.style.display = 'none';
                canvas._activeTokenTrendTipPinned = false;
                canvas._activeTokenTrendTouching = false;
                // 清除当前数据指针/竖向虚线，恢复基础折线图。
                canvas._activeTokenTrendSelectedIndex = -1;
                if (canvas._activeTokenTrendGuideVisible) {
                    canvas._activeTokenTrendGuideVisible = false;
                    renderActiveTokenTrendChart();
                }
            };

            const drawGuide = (point) => {
                const plot = canvas._activeTokenTrendPlot;
                if (!plot || !point) return;
                const ctx = canvas.getContext('2d');
                ctx.save();
                // 当前 canvas 已经使用 dpr 坐标变换，因此这里继续使用 CSS 像素坐标绘制。
                ctx.setTransform(plot.dpr, 0, 0, plot.dpr, 0, 0);
                ctx.beginPath();
                ctx.setLineDash([4, 4]);
                ctx.strokeStyle = 'rgba(100, 116, 139, 0.72)';
                ctx.lineWidth = 1;
                ctx.moveTo(point.x, plot.top);
                ctx.lineTo(point.x, plot.top + plot.plotH);
                ctx.stroke();
                ctx.setLineDash([]);

                // 当前数据点高亮，方便手指确认吸附到了哪一个点。
                ctx.beginPath();
                ctx.arc(point.x, point.y, 5, 0, Math.PI * 2);
                ctx.fillStyle = '#ffffff';
                ctx.fill();
                ctx.beginPath();
                ctx.arc(point.x, point.y, 4, 0, Math.PI * 2);
                ctx.fillStyle = '#16a34a';
                ctx.fill();
                ctx.restore();
                canvas._activeTokenTrendGuideVisible = true;
            };

            const showPoint = (clientX, clientY, pinned = false) => {
                const points = canvas._activeTokenTrendPoints || [];
                if (!points.length) return;
                const rect = canvas.getBoundingClientRect();
                const x = Math.max(0, Math.min(rect.width, clientX - rect.left));
                let nearest = points[0];
                let distance = Math.abs(x - points[0].x);
                points.forEach(p => {
                    const d = Math.abs(x - p.x);
                    if (d < distance) { distance = d; nearest = p; }
                });
                const idx = points.indexOf(nearest);
                tip.textContent = `${canvas._activeTokenTrendLabels[idx]}：${nearest.value} 个活跃TOKEN`;
                tip.style.display = 'block';
                positionTip(clientX, clientY);
                canvas._activeTokenTrendSelectedIndex = idx;
                canvas._activeTokenTrendTipPinned = pinned;

                // 将当前点交给完整重绘流程，由 renderActiveTokenTrendChart() 在最后一层绘制竖向虚线。
                canvas._activeTokenTrendSelectedIndex = idx;
                canvas._activeTokenTrendGuideVisible = true;
                renderActiveTokenTrendChart();
            };

            canvas.addEventListener('click', e => {
                if (window.matchMedia('(pointer: coarse)').matches) return;
                const points = canvas._activeTokenTrendPoints || [];
                if (!points.length) return;
                const rect = canvas.getBoundingClientRect();
                const x = e.clientX - rect.left;
                let nearest = points[0], distance = Math.abs(x - points[0].x);
                points.forEach(p => {
                    const d = Math.abs(x - p.x);
                    if (d < distance) { distance = d; nearest = p; }
                });
                if (distance > 20) { hideTip(); return; }
                showPoint(e.clientX, e.clientY, true);
            });

            let touchStartX = 0;
            let touchStartY = 0;
            let touchMode = null;
            canvas.addEventListener('touchstart', e => {
                if (!e.touches.length) return;
                const t = e.touches[0];
                touchStartX = t.clientX;
                touchStartY = t.clientY;
                touchMode = null;
                canvas._activeTokenTrendTouching = true;
            }, {passive: true});

            canvas.addEventListener('touchmove', e => {
                if (!e.touches.length) return;
                const t = e.touches[0];
                const dx = t.clientX - touchStartX;
                const dy = t.clientY - touchStartY;
                if (!touchMode && (Math.abs(dx) > 6 || Math.abs(dy) > 6)) {
                    touchMode = Math.abs(dx) > Math.abs(dy) ? 'horizontal' : 'vertical';
                }
                if (touchMode === 'horizontal') {
                    // 只有确定为横向手势后才阻止默认行为，页面纵向滚动不会被锁住。
                    e.preventDefault();
                    showPoint(t.clientX, t.clientY, true);
                }
            }, {passive: false});

            canvas.addEventListener('touchend', e => {
                if (touchMode === 'vertical') {
                    hideTip();
                }
                touchMode = null;
                canvas._activeTokenTrendTouching = false;
            }, {passive: true});

            canvas.addEventListener('touchcancel', hideTip, {passive: true});

            // 在其他卡片/区域开始纵向滑动时立即关闭折线图提示，避免 fixed 气泡悬停在屏幕上。
            // 不能只依赖 scroll：部分移动端浏览器在滚动开始前不会立即派发 scroll 事件。
            let outsideTouchStartX = 0;
            let outsideTouchStartY = 0;
            document.addEventListener('touchstart', e => {
                if (!e.touches.length) return;
                outsideTouchStartX = e.touches[0].clientX;
                outsideTouchStartY = e.touches[0].clientY;
            }, {passive: true, capture: true});

            document.addEventListener('touchmove', e => {
                if (!window.matchMedia('(pointer: coarse)').matches || !e.touches.length) return;
                // 折线图自身的触摸由上面的横向选点逻辑处理；这里只处理其他区域。
                if (e.target === canvas || canvas.contains(e.target)) return;
                const touch = e.touches[0];
                const dx = touch.clientX - outsideTouchStartX;
                const dy = touch.clientY - outsideTouchStartY;
                if (Math.abs(dy) > 5 && Math.abs(dy) > Math.abs(dx)) {
                    hideTip();
                }
            }, {passive: true, capture: true});

            // 捕获页面及所有嵌套滚动容器的滚动事件；不再依赖触摸状态，移动端只要发生滚动就关闭提示。
            document.addEventListener('scroll', () => {
                if (window.matchMedia('(pointer: coarse)').matches) {
                    hideTip();
                }
            }, {passive: true, capture: true});

            document.addEventListener('click', e => {
                if (e.target === canvas || canvas.contains(e.target)) return;
                hideTip();
            });
        }

        function renderAnalyticsCards(analyticsData) {
            analyticsSourceData = {
                topIp: Array.isArray(analyticsData?.top_ips) ? analyticsData.top_ips : [],
                topToken: Array.isArray(analyticsData?.top_tokens) ? analyticsData.top_tokens : [],
                susToken: Array.isArray(analyticsData?.sus_tokens) ? analyticsData.sus_tokens : [],
                susIp: Array.isArray(analyticsData?.sus_ips) ? analyticsData.sus_ips : []
            };

            Object.keys(analyticsPages).forEach(key => {
                const totalPages = Math.max(1, Math.ceil(analyticsSourceData[key].length / analyticsPageSize));
                if (analyticsPages[key] > totalPages) analyticsPages[key] = totalPages;
            });

            renderAnalyticsCardPage('topIp');
            renderAnalyticsCardPage('topToken');
            renderAnalyticsCardPage('susToken');
            renderAnalyticsCardPage('susIp');
        }

        function changeAnalyticsPage(key, page) {
            const list = analyticsSourceData[key] || [];
            const totalPages = Math.max(1, Math.ceil(list.length / analyticsPageSize));
            const nextPage = Math.min(Math.max(1, Number(page) || 1), totalPages);
            if (analyticsPages[key] === nextPage) return;
            analyticsPages[key] = nextPage;
            renderAnalyticsCardPage(key);
        }

        function renderAnalyticsPagination(key, currentPage, totalPages, totalCount) {
            let pagesHtml = '';

            // 保持原来的 PC 分页样式，只根据卡片实际宽度减少页码数量，避免卡片过窄时溢出。
            // 移动端同样采用有限页码窗口，但不改变原来的分页栏结构和按钮样式。
            const listIdMap = {
                topIp: 'list-top-ip',
                topToken: 'list-top-token',
                susToken: 'list-sus-token',
                susIp: 'list-sus-ip'
            };
            const listEl = document.getElementById(listIdMap[key]);
            const card = listEl ? listEl.closest('.analytics-card') : null;
            const cardWidth = card ? card.getBoundingClientRect().width : window.innerWidth;
            const isMobile = window.innerWidth <= 768;

            // 以卡片实际宽度判断分页是否进入紧凑模式。
            // 这样手机横屏、平板横屏以及 PC 缩小窗口时也不会继续显示“当前第 X/Y 页”并挤压页码。
            const isCompact = cardWidth < 520;

            // 根据分页栏实际可用宽度限制页码数量。
            // 关键点：页码数量必须把“上一页/下一页”和统计信息的空间一起算进去，
            // 不能只看卡片总宽度，否则卡片较窄时仍会发生横向溢出。
            let maxVisiblePages;
            if (isCompact || isMobile) {
                // 紧凑模式只显示最少的页码窗口，避免窄卡片横向挤压。
                maxVisiblePages = 3;
            } else {
                // PC 卡片越窄，页码窗口越小。
                // 3/5/7 指“数字页码”的最大数量，不包含上一页/下一页。
                maxVisiblePages = cardWidth < 430 ? 3 : (cardWidth < 600 ? 5 : 7);
            }

            const addPage = (page) => {
                pagesHtml += `<button class="analytics-page-btn ${page === currentPage ? 'active' : ''}" onclick="changeAnalyticsPage('${key}', ${page})">${page}</button>`;
            };
            const addEllipsis = () => {
                pagesHtml += '<span class="analytics-page-ellipsis">...</span>';
            };

            if (totalPages <= maxVisiblePages) {
                for (let i = 1; i <= totalPages; i++) addPage(i);
            } else if (maxVisiblePages === 3) {
                addPage(1);
                if (currentPage > 2 && currentPage < totalPages - 1) addEllipsis();
                if (currentPage !== 1 && currentPage !== totalPages) addPage(currentPage);
                if (currentPage < totalPages - 1) addEllipsis();
                addPage(totalPages);
            } else {
                const radius = maxVisiblePages === 7 ? 2 : 1;
                const middleSlots = maxVisiblePages - 2;
                let start = Math.max(2, currentPage - radius);
                let end = Math.min(totalPages - 1, currentPage + radius);

                while (end - start + 1 < middleSlots) {
                    if (start > 2) start--;
                    else if (end < totalPages - 1) end++;
                    else break;
                }

                addPage(1);
                if (start > 2) addEllipsis();
                for (let i = start; i <= end; i++) addPage(i);
                if (end < totalPages - 1) addEllipsis();
                addPage(totalPages);
            }

            const prevLabel = (isMobile || isCompact) ? '‹' : '上一页';
            const nextLabel = (isMobile || isCompact) ? '›' : '下一页';

            return `
                <div class="analytics-pagination-bar${isCompact ? ' compact' : ''}">
                    <div class="analytics-pagination-info">
                        共 <strong>${totalCount}</strong> 条记录${(isMobile || isCompact) ? '' : `，当前第 <strong>${currentPage}/${totalPages}</strong> 页`}
                    </div>
                    <div class="analytics-pagination-nums">
                        <button class="analytics-page-btn" onclick="changeAnalyticsPage('${key}', ${currentPage - 1})" ${currentPage <= 1 ? 'disabled' : ''}>${prevLabel}</button>
                        ${pagesHtml}
                        <button class="analytics-page-btn" onclick="changeAnalyticsPage('${key}', ${currentPage + 1})" ${currentPage >= totalPages ? 'disabled' : ''}>${nextLabel}</button>
                    </div>
                </div>`;
        }

        function renderAnalyticsCardPage(key) {
            const configs = {
                topIp: ['list-top-ip', item => `
                    <div class="item-left"><span class="rank-num">${item.rank}</span><div class="item-main"><div class="item-title-row"><span class="item-title">${escapeHtml(item.ip)}</span>${renderCopyBtn(item.ip, 'IP')}</div><span class="item-sub" data-geo-ip="${escapeHtml(item.ip)}">${escapeHtml(item.info && item.info !== '未知地区' ? item.info : getGeo(item.ip))}</span></div></div>
                    <div class="item-right"><span class="count-badge">${item.count}次</span></div>`],
                topToken: ['list-top-token', item => { const timeOnly = item.lastTime ? item.lastTime.split(' ')[1] : ''; return `
                    <div class="item-left"><span class="rank-num">${item.rank}</span><div class="item-main"><div class="item-title-row"><span class="item-title" title="${escapeHtml(item.token)}">${escapeHtml(item.token)}</span>${renderCopyBtn(item.token, 'Token')}</div><span class="item-sub">${timeOnly}</span></div></div>
                    <div class="item-right"><span class="count-badge">${item.count}次</span></div>`; }],
                susToken: ['list-sus-token', item => `
                    <div class="item-left"><span class="rank-num">${item.rank}</span><div class="item-main"><div class="item-title-row"><span class="item-title" title="${escapeHtml(item.token)}">${escapeHtml(item.token)}</span>${renderCopyBtn(item.token, 'Token')}</div></div></div>
                    <div class="item-right"><span class="count-badge" style="color:var(--primary-red)">${item.ipCount} 个IP</span></div>`],
                susIp: ['list-sus-ip', item => `
                    <div class="item-left"><span class="rank-num">${item.rank}</span><div class="item-main"><div class="item-title-row"><span class="item-title">${escapeHtml(item.ip)}</span>${renderCopyBtn(item.ip, 'IP')}</div><span class="item-sub" data-geo-ip="${escapeHtml(item.ip)}">${escapeHtml(item.info && item.info !== '未知地区' ? item.info : getGeo(item.ip))}</span></div></div>
                    <div class="item-right"><span class="count-badge" style="color:var(--primary-red)">${item.tokenCount} 个Token</span></div>`]
            };

            const cfg = configs[key];
            if (!cfg) return;

            const el = document.getElementById(cfg[0]);
            if (!el) return;

            const list = analyticsSourceData[key] || [];
            const totalPages = Math.max(1, Math.ceil(list.length / analyticsPageSize));
            const page = Math.min(Math.max(1, analyticsPages[key] || 1), totalPages);
            analyticsPages[key] = page;

            const start = (page - 1) * analyticsPageSize;
            const items = list.slice(start, start + analyticsPageSize);

            // 分页栏固定在四个分析卡片底部，列表本身只保留日志项。
            const card = el.closest('.analytics-card');
            if (card) {
                const oldPagination = card.querySelector('.analytics-pagination-bar');
                if (oldPagination) oldPagination.remove();
            }

            if (!items.length) {
                el.innerHTML = '<div style="color:var(--text-muted); font-size:0.75rem; text-align:center; padding:24px 0;">暂无记录</div>';
                return;
            }

            el.innerHTML = items.map((item, idx) =>
                `<div class="analytics-item">${cfg[1]({...item, rank: start + idx + 1})}</div>`
            ).join('');

            if (card) {
                card.insertAdjacentHTML(
                    'beforeend',
                    renderAnalyticsPagination(key, page, totalPages, list.length)
                );
            }

            if (key === 'topIp' || key === 'susIp') {
                setTimeout(() => el.querySelectorAll('[data-geo-ip]').forEach(node => {
                    const ip = node.getAttribute('data-geo-ip');
                    if (ip) refreshGeoForIp(ip);
                }), 20);
            }
        }

        // 【稳定渲染】只新增/移动/更新真正发生变化的行，不再每次刷新都重建整个 tbody。
        // 这样 5 秒轮询拿到新日志时，旧行的 DOM、文本选区、展开状态等都尽量保持不动。
        function getLogDomKey(log) {
            if (log && log.id !== undefined && log.id !== null) return `id:${log.id}`;
            if (log && log.log_id !== undefined && log.log_id !== null) return `log_id:${log.log_id}`;
            // 后端当前未明确提供 id 时，用日志核心字段组成稳定 key。
            return `log:${JSON.stringify([
                log && log.time || '',
                log && log.ip || '',
                log && log.token || '',
                log && log.ua || ''
            ])}`;
        }

        function mergeMobileLiveLogs(freshLogs, existingLogs) {
            const fresh = (Array.isArray(freshLogs) ? freshLogs : [])
                .filter(log => !log || !log.token || !confirmedMissingTokens.has(log.token));
            const existing = (Array.isArray(existingLogs) ? existingLogs : [])
                .filter(log => !log || !log.token || !confirmedMissingTokens.has(log.token));
            const merged = [];
            const positions = new Map();
            const freshOccurrences = new Map();
            const existingOccurrences = new Map();

            // 先放最新一屏，再把此前已加载的历史记录接在后面。
            fresh.forEach(log => {
                const base = getLogDomKey(log);
                const occurrence = freshOccurrences.get(base) || 0;
                freshOccurrences.set(base, occurrence + 1);
                const key = `${base}#${occurrence}`;
                positions.set(key, merged.length);
                merged.push(log);
            });

            existing.forEach(log => {
                const base = getLogDomKey(log);
                const occurrence = existingOccurrences.get(base) || 0;
                existingOccurrences.set(base, occurrence + 1);
                const key = `${base}#${occurrence}`;
                if (positions.has(key)) {
                    const index = positions.get(key);
                    // 使用最新日志字段，同时保留旧对象中已补齐的 V2Board 用户资料。
                    const latest = { ...log, ...merged[index] };
                    const oldLog = merged[index];
                    if (oldLog && oldLog.v2board_status === 'matched') {
                        latest.user_id = oldLog.user_id;
                        latest.user_email = oldLog.user_email;
                        latest.plan_name = oldLog.plan_name;
                        latest.user_remark = oldLog.user_remark;
                        latest.user_banned = oldLog.user_banned;
                        latest.v2board_status = oldLog.v2board_status;
                    }
                    merged[index] = latest;
                } else {
                    positions.set(key, merged.length);
                    merged.push(log);
                }
            });

            return merged;
        }

        function getLogDomSignature(log) {
            try {
                return JSON.stringify(log || {});
            } catch (e) {
                return String(log || '');
            }
        }

        function patchLogRows(tbody, logs, renderRow, emptyHtml) {
            if (!tbody) return;

            if (!logs || logs.length === 0) {
                if (tbody.dataset.emptyRendered !== '1') {
                    tbody.innerHTML = emptyHtml;
                    tbody.dataset.emptyRendered = '1';
                }
                return;
            }

            tbody.dataset.emptyRendered = '0';

            const existing = new Map();
            Array.from(tbody.children).forEach(row => {
                const key = row.getAttribute('data-log-key');
                if (key) existing.set(key, row);
            });

            const fragment = document.createDocumentFragment();
            const usedKeys = new Set();
            const keyOccurrences = new Map();

            logs.forEach(log => {
                // 没有后端唯一 ID 的历史日志可能出现完全相同的 time/ip/token/ua。
                // 给重复 key 增加出现序号，避免多条历史记录被错误合并成一行。
                const baseKey = getLogDomKey(log);
                const occurrence = keyOccurrences.get(baseKey) || 0;
                keyOccurrences.set(baseKey, occurrence + 1);
                const key = `${baseKey}#${occurrence}`;
                const signature = getLogDomSignature(log);
                let row = existing.get(key);

                if (row) {
                    usedKeys.add(key);
                    if (row.getAttribute('data-log-signature') !== signature) {
                        const wrapper = document.createElement('tbody');
                        wrapper.innerHTML = renderRow(log).trim();
                        const newRow = wrapper.firstElementChild;
                        if (newRow) {
                            newRow.setAttribute('data-log-key', key);
                            newRow.setAttribute('data-log-signature', signature);
                            row.replaceWith(newRow);
                            row = newRow;
                        }
                    }
                } else {
                    const wrapper = document.createElement('tbody');
                    wrapper.innerHTML = renderRow(log).trim();
                    row = wrapper.firstElementChild;
                    if (row) {
                        row.setAttribute('data-log-key', key);
                        row.setAttribute('data-log-signature', signature);
                    }
                }

                if (row) fragment.appendChild(row);
            });

            // 删除本次数据中已经不存在的旧行。
            Array.from(tbody.children).forEach(row => {
                const key = row.getAttribute('data-log-key');
                if (key && !usedKeys.has(key)) row.remove();
            });

            // appendChild 已经会移动已有节点，因此不会重新创建旧行。
            tbody.appendChild(fragment);
        }

        function renderTable(logs, totalCount) {
            // 使用后端返回的 ip_info 作为当前页面唯一归属地来源。
            (Array.isArray(logs) ? logs : []).forEach(l => {
                if (l && l.ip && l.ip !== '-' && l.ip_info && l.ip_info !== '未知地区') {
                    ipGeoCache[l.ip] = normalizeIpGeo(l.ip_info);
                }
            });
            const tbody = document.getElementById('log-table');
            const pcPaginationContainer = document.getElementById('pc-pagination-container');
            const mobileLoadMoreContainer = document.getElementById('mobile-load-more-container');

            const isMobile = isLogMobileLayout();
            if (logs.length === 0) {
                // PC 当前页暂时为空时，不要清空分页栏：总数可能仍有记录，
                // 保留页码让用户可以继续翻页；后续 5 秒轮询也会重新请求当前页。
                const emptyMessage = (!isMobile && Number(totalCount) > 0)
                    ? '<tr><td colspan="7" class="empty-state">当前页暂时没有日志，数据同步后会自动更新。</td></tr>'
                    : '';
                patchLogRows(tbody, [], null, emptyMessage);
                mobileLoadMoreContainer.innerHTML = '';
                if (!isMobile && Number(totalCount) > 0) {
                    const totalPages = Math.max(1, Math.ceil(Number(totalCount) / pcPageSize));
                    renderPcPaginationBar(totalPages, Number(totalCount));
                } else {
                    pcPaginationContainer.innerHTML = '';
                }
                return;
            }


            const isIpBanned = (ip) => ip && ip !== '-' && (currentBlData.ip || []).includes(ip);
            const isTokenBanned = (token) => token && token !== '-' && (currentBlData.token || []).includes(token);
            const isUaBanned = (ua) => ua && ua !== '-' && (currentBlData.ua || []).some(bannedUa => ua.includes(bannedUa));

            if (isMobile) {
                pcPaginationContainer.innerHTML = '';

                patchLogRows(tbody, logs, l => {
                    const hasUa = l.ua && l.ua !== '-';
                    const uaHtml = hasUa
                        ? `<div class="m-ua-box" onclick="toggleExpand(this)" title="点击展开/折叠完整 UA">${escapeHtml(l.ua)}</div>`
                        : '';

                    const ipBanned = isIpBanned(l.ip);
                    const tokenBanned = isTokenBanned(l.token);

                    return `
                        <tr class="m-card">
                            <td>
                                <div class="m-card-header">
                                    <div class="m-time">${escapeHtml(l.time)}</div>
                                    <div class="m-status-group">
                                        ${getStatusBadge(l.status)}
                                        ${getRemark(l.status)}
                                    </div>
                                </div>
                                <div class="m-card-body">
                                    <div class="m-row">
                                        <div class="m-label">IP</div>
                                        <div class="m-value">
                                            <div style="display:flex; align-items:center; gap:4px; flex-wrap:wrap; justify-content:flex-end;">
                                                ${renderPillBox(l.ip, 'IP')}
                                                ${l.ip && l.ip !== '-' ? (ipBanned
                                                    ? `<button class="btn-ban" style="opacity:0.5; cursor:not-allowed;" disabled>已封 IP</button>`
                                                    : `<button class="btn-ban" data-ban-type="ip" data-ban-value="${escapeHtml(l.ip)}" onclick="banTarget('ip', '${escapeHtml(l.ip)}', this)">封 IP</button>`
                                                ) : ''}
                                            </div>
                                            <div class="ip-sub" data-geo-ip="${escapeHtml(l.ip)}" onclick="toggleExpand(this)" title="点击展开/折叠完整归属地">${escapeHtml(normalizeIpGeo(l.ip_info && l.ip_info !== '未知地区' ? l.ip_info : getGeo(l.ip)))}</div>
                                        </div>
                                    </div>
                                    <div class="m-row">
                                        <div class="m-label">Token</div>
                                        <div class="m-value">
                                            <div style="display:flex; align-items:center; gap:4px; flex-wrap:wrap; justify-content:flex-end;">
                                                ${renderPillBox(l.token, 'Token')}
                                                ${l.token && l.token !== '-' ? (tokenBanned
                                                    ? `<button class="btn-ban" style="opacity:0.5; cursor:not-allowed;" disabled>已封 Token</button>`
                                                    : `<button class="btn-ban" data-ban-type="token" data-ban-value="${escapeHtml(l.token)}" onclick="banTarget('token', '${escapeHtml(l.token)}', this)">封 Token</button>`
                                                ) : ''}
                                            </div>
                                        </div>
                                    </div>
                                    <div class="m-row">
                                        <div class="m-label">V2Board</div>
                                        <div class="m-value" style="width:100%; min-width:0;">
                                            ${renderV2BoardUserInfo(l, true)}
                                        </div>
                                    </div>
                                </div>
                                ${uaHtml}
                            </td>
                        </tr>
                    `;
                }, '');

                if (logs.length < totalCount) {
                    mobileLoadMoreContainer.innerHTML = `
                        <div class="mobile-load-more-container">
                            <button class="btn-load-more" onclick="loadMoreMobileLogs(${totalCount})">加载更多 (已显示 ${logs.length} / 共 ${totalCount} 条)</button>
                        </div>
                    `;
                } else {
                    mobileLoadMoreContainer.innerHTML = `
                        <div class="mobile-load-more-container">
                            <button class="btn-load-more" disabled>已加载全部 (${totalCount}条)</button>
                        </div>
                    `;
                }

            } else {
                mobileLoadMoreContainer.innerHTML = '';

                const totalPages = Math.max(1, Math.ceil(Number(totalCount) / pcPageSize));
                // 页码越界必须由 fetchData 重新请求有效页，渲染阶段不私自改页码，
                // 避免地址栏状态、请求上下文和分页栏显示不一致。
                if (currentPcPage > totalPages) {
                    pcPaginationContainer.innerHTML = '';
                    return;
                }

                patchLogRows(tbody, logs, l => {
                    const ipBanned = isIpBanned(l.ip);
                    const tokenBanned = isTokenBanned(l.token);
                    const uaBanned = isUaBanned(l.ua);
                    const remarkHtml = getRemark(l.status);

                    return `
                        <tr>
                            <td style="color:#334155; white-space:nowrap;">${escapeHtml(l.time)}</td>
                            <td>
                                <div style="display:flex; align-items:center; gap:4px; flex-wrap:wrap;">
                                    ${renderPillBox(l.ip, 'IP')}
                                    ${ipBanned ? '<span class="badge badge-403" style="font-size:0.68rem; padding:1px 4px;">已封禁</span>' : ''}
                                </div>
                                <div class="ip-sub" data-geo-ip="${escapeHtml(l.ip)}">${escapeHtml(normalizeIpGeo(l.ip_info && l.ip_info !== '未知地区' ? l.ip_info : getGeo(l.ip)))}</div>
                            </td>
                            <td>
                                <div style="display:flex; align-items:center; gap:4px; flex-wrap:wrap;">
                                    ${renderPillBox(l.token, 'Token')}
                                    ${tokenBanned ? '<span class="badge badge-403" style="font-size:0.68rem; padding:1px 4px;">已封禁</span>' : ''}
                                </div>
                                ${renderV2BoardUserInfo(l, false)}
                            </td>
                            <td>${getStatusBadge(l.status)}</td>
                            <td>${remarkHtml}</td>
                            <td class="ua-text" title="${escapeHtml(l.ua)}">
                                ${uaBanned ? '<span style="color:#dc2626; font-weight:600; margin-right:4px;">[已封禁UA]</span>' : ''}
                                ${escapeHtml(l.ua)}
                            </td>
                            <td style="text-align:center; white-space:nowrap;">
                                <div class="ban-actions" style="justify-content:center;">
                                    ${l.ip && l.ip !== '-' ? (ipBanned
                                        ? `<button class="btn-ban" style="opacity:0.4; cursor:not-allowed;" disabled>已封 IP</button>`
                                        : `<button class="btn-ban" data-ban-type="ip" data-ban-value="${escapeHtml(l.ip)}" onclick="banTarget('ip', '${escapeHtml(l.ip)}', this)">封 IP</button>`) : ''}
                                    ${l.token && l.token !== '-' ? (tokenBanned
                                        ? `<button class="btn-ban" style="opacity:0.4; cursor:not-allowed;" disabled>已封 Token</button>`
                                        : `<button class="btn-ban" data-ban-type="token" data-ban-value="${escapeHtml(l.token)}" onclick="banTarget('token', '${escapeHtml(l.token)}', this)">封 Token</button>`) : ''}
                                </div>
                            </td>
                        </tr>
                    `;
                }, '');

                renderPcPaginationBar(totalPages, totalCount);
            }
        }

        function changePcPage(page) {
            const requestedPage = Math.max(1, Math.floor(Number(page) || 1));
            if (requestedPage === currentPcPage) return;
            currentPcPage = requestedPage;
            invalidateLogRequestState();
            fetchData(true);
        }

        function renderPcPaginationBar(totalPages, totalCount) {
            const container = document.getElementById('pc-pagination-container');
            let pagesHtml = '';
            for (let i = 1; i <= totalPages; i++) {
                if (i === 1 || i === totalPages || (i >= currentPcPage - 2 && i <= currentPcPage + 2)) {
                    pagesHtml += `<button class="page-btn ${i === currentPcPage ? 'active' : ''}" onclick="changePcPage(${i})">${i}</button>`;
                } else if (i === currentPcPage - 3 || i === currentPcPage + 3) {
                    pagesHtml += `<span style="padding:0 4px;">...</span>`;
                }
            }

            container.innerHTML = `
                <div class="pagination-bar">
                    <div>共 <strong>${totalCount}</strong> 条记录，当前第 <strong>${currentPcPage}/${totalPages}</strong> 页</div>
                    <div class="pagination-nums">
                        <button class="page-btn" onclick="changePcPage(${currentPcPage - 1})" ${currentPcPage <= 1 ? 'disabled' : ''}>上一页</button>
                        ${pagesHtml}
                        <button class="page-btn" onclick="changePcPage(${currentPcPage + 1})" ${currentPcPage >= totalPages ? 'disabled' : ''}>下一页</button>
                    </div>
                </div>
            `;
        }

        function loadMoreMobileLogs(totalCount) {
            if (mobileDisplayCount >= Number(totalCount || 0)) return;
            mobileDisplayCount = Math.min(mobileDisplayCount + mobileStep, Number(totalCount) || mobileDisplayCount + mobileStep);
            invalidateLogRequestState();
            fetchData(true);
        }

        function initializeApp() {
            initTimeSelectOptions();
            fetchBlacklistRules();
            fetchData();

            // 【交互防护】给表格/卡片绑定 mouseenter / mouseleave 事件监控
            const tableCard = document.querySelector('.table-card');
            if (tableCard) {
                tableCard.addEventListener('mouseenter', () => { isTableHovered = true; });
                tableCard.addEventListener('mouseleave', () => { isTableHovered = false; });
            }

            // 【交互防护】5秒定时器刷新时校验 isUserInteracting，选中文字或鼠标悬停时自动挂起，防止刷新抹掉内容
            setInterval(() => {
                if (!isUserInteracting()) {
                    fetchData();
                    // 后台同步最新黑名单，其他页面封禁后当前页面按钮也会自动置灰。
                    fetchBlacklistRules(false, false);
                }
            }, 5000);
        }

        window.addEventListener('resize', () => {
            renderActiveTokenTrendChart();
            if (allLogs.length > 0) {
                invalidateLogRequestState();
                fetchData(true);
            }
        });
    </script>
</body>
</html>

