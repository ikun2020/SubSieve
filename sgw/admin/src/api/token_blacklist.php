<?php
require_once __DIR__ . '/_auth.php';

$method = $_SERVER['REQUEST_METHOD'];

// GET — 列出黑名单 Token + 今日各 IP 拉取统计
if ($method === 'GET') {
    $entries = read_token_blacklist();
    if (empty($entries)) {
        json_out(['ok' => true, 'entries' => []]);
    }

    $blacklistedSet = array_flip(array_column($entries, 'token'));

    // Count today's pull attempts for each blacklisted Token. This includes blocked
    // attempts such as 403, and intentionally does not expose requester IPs here.
    $tokenPullCount = []; // token => count

    if (file_exists(LOG_FILE)) {
        $handle = fopen(LOG_FILE, 'r');
        if ($handle) {
            while (($line = fgets($handle)) !== false) {
                if (!log_line_is_today($line)) continue;
                $parsed = parse_access_log_line($line);
                if (!$parsed) continue;
                $request = $parsed['request'];
                $tok = token_from_request($request);
                if ($tok === '') continue;
                if (!isset($blacklistedSet[$tok])) continue;
                $tokenPullCount[$tok] = ($tokenPullCount[$tok] ?? 0) + 1;
            }
            fclose($handle);
        }
    }

    $result = array_map(function ($e) use ($tokenPullCount) {
        $tok   = $e['token'];
        $e['today_total'] = $tokenPullCount[$tok] ?? 0;
        return $e;
    }, $entries);

    json_out(['ok' => true, 'entries' => $result]);
}

// POST — 添加 Token 黑名单
if ($method === 'POST') {
    $body    = json_decode(file_get_contents('php://input'), true) ?? [];
    $token   = trim($body['token'] ?? '');
    $comment = trim($body['comment'] ?? '');

    if (!$token) json_err('请输入 Token');
    if (!token_blacklist_value_is_safe($token)) json_err('Token contains invalid characters');

    $entries = read_token_blacklist();
    foreach ($entries as $e) {
        if ($e['token'] === $token) json_err('该 Token 已在黑名单中');
    }

    $entries[] = ['token' => $token, 'comment' => $comment, 'added_at' => date('Y-m-d H:i')];
    if (!write_token_blacklist($entries)) json_err('写入失败，请检查文件权限');
    $reload = nginx_reload();
    json_out(['ok' => true, 'nginx_reloaded' => $reload]);
}

// PATCH — 更新备注
if ($method === 'PATCH') {
    $body    = json_decode(file_get_contents('php://input'), true) ?? [];
    $token   = trim($body['token'] ?? '');
    $comment = trim($body['comment'] ?? '');

    if (!$token) json_err('缺少 token 参数');
    if (!token_blacklist_value_is_safe($token)) json_err('Token contains invalid characters');

    $entries = read_token_blacklist();
    $found   = false;
    foreach ($entries as &$e) {
        if ($e['token'] === $token) { $e['comment'] = $comment; $found = true; break; }
    }
    unset($e);

    if (!$found) json_err('未找到该Token');
    if (!write_token_blacklist($entries)) json_err('写入失败，请检查文件权限');
    json_out(['ok' => true]);
}

// DELETE — 移除 Token 黑名单
if ($method === 'DELETE') {
    $body  = json_decode(file_get_contents('php://input'), true) ?? [];
    $token = trim($body['token'] ?? '');

    if (!$token) json_err('缺少 token 参数');
    if (!token_blacklist_value_is_safe($token)) json_err('Token contains invalid characters');

    $entries = array_values(array_filter(read_token_blacklist(), fn($e) => $e['token'] !== $token));
    if (!write_token_blacklist($entries)) json_err('写入失败，请检查文件权限');
    $reload = nginx_reload();
    json_out(['ok' => true, 'nginx_reloaded' => $reload]);
}

json_err('不支持的请求方式', 405);

// ── 读写 Token 黑名单 ────────────────────────────────────────

function read_token_blacklist(): array {
    return read_token_blacklist_entries();
}

function write_token_blacklist(array $entries): bool {
    return write_token_blacklist_files($entries);
}
