<?php
require_once __DIR__ . '/_auth.php';

$method = $_SERVER['REQUEST_METHOD'];

if ($method === 'GET') {
    json_out(['ok' => true, 'entries' => read_whitelist()]);
}

if ($method === 'POST') {
    $body = json_decode(file_get_contents('php://input'), true) ?? [];

    if (!empty($body['import_ips']) && is_array($body['import_ips'])) {
        $entries = read_whitelist();
        $existingSet = [];
        foreach ($entries as $entry) {
            $existingSet[$entry['ip']] = true;
        }

        $added = 0;
        $skipped = 0;
        $invalid = 0;
        foreach ($body['import_ips'] as $rawIp) {
            $ip = normalize_ip_cidr((string)$rawIp);
            if ($ip === null) {
                $invalid++;
                continue;
            }
            if (isset($existingSet[$ip])) {
                $skipped++;
                continue;
            }
            $entries[] = ['ip' => $ip, 'comment' => '从文件导入'];
            $existingSet[$ip] = true;
            $added++;
        }

        if ($added > 0) {
            if (!write_whitelist($entries)) {
                json_err('写入白名单文件失败，请检查文件权限');
            }
            whitelist_reload();
        }

        json_out(['ok' => true, 'added' => $added, 'skipped' => $skipped, 'invalid' => $invalid]);
    }

    $ip = normalize_ip_cidr((string)($body['ip'] ?? ''));
    $comment = safe_comment((string)($body['comment'] ?? ''));
    if ($ip === null) {
        json_err('IP 格式不合法（支持 IPv4、IPv6、CIDR）');
    }

    $entries = read_whitelist();
    foreach ($entries as $entry) {
        if ($entry['ip'] === $ip) {
            json_err('该IP已在白名单中');
        }
    }

    $entries[] = ['ip' => $ip, 'comment' => $comment];
    if (!write_whitelist($entries)) {
        json_err('写入白名单文件失败，请检查文件权限');
    }
    whitelist_reload();
    json_out(['ok' => true, 'ip' => $ip]);
}

if ($method === 'PATCH') {
    $body = json_decode(file_get_contents('php://input'), true) ?? [];
    $ip = normalize_ip_cidr((string)($body['ip'] ?? ''));
    $comment = safe_comment((string)($body['comment'] ?? ''));
    if ($ip === null) {
        json_err('IP 格式不合法（支持 IPv4、IPv6、CIDR）');
    }

    $entries = read_whitelist();
    $found = false;
    foreach ($entries as &$entry) {
        if ($entry['ip'] === $ip) {
            $entry['comment'] = $comment;
            $found = true;
            break;
        }
    }
    unset($entry);

    if (!$found) {
        json_err('未找到该IP');
    }
    if (!write_whitelist($entries)) {
        json_err('写入白名单文件失败，请检查文件权限');
    }
    whitelist_reload();
    json_out(['ok' => true]);
}

if ($method === 'DELETE') {
    $body = json_decode(file_get_contents('php://input'), true) ?? [];
    $rawIps = [];

    if (!empty($body['ips']) && is_array($body['ips'])) {
        $rawIps = $body['ips'];
    } else {
        $rawIps = [$body['ip'] ?? ''];
    }

    $toRemove = [];
    foreach ($rawIps as $rawIp) {
        $ip = normalize_ip_cidr((string)$rawIp);
        if ($ip !== null) {
            $toRemove[$ip] = true;
        }
    }
    if (!$toRemove) {
        json_err('缺少有效的 ip 参数');
    }

    $entries = array_values(array_filter(read_whitelist(), fn($entry) => !isset($toRemove[$entry['ip']])));
    if (!write_whitelist($entries)) {
        json_err('写入白名单文件失败，请检查文件权限');
    }
    whitelist_reload();
    json_out(['ok' => true]);
}

json_err('不支持的请求方式', 405);

function read_whitelist(): array {
    if (!file_exists(WHITELIST_IPS)) return [];

    $entries = [];
    $seen = [];
    foreach (file(WHITELIST_IPS, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
        $line = trim($line);
        if ($line === '' || str_starts_with($line, '#')) continue;

        $comment = '';
        if (preg_match('/^(\S+)\s+#\s*(.*)$/', $line, $m)) {
            $rawIp = $m[1];
            $comment = $m[2];
        } else {
            $rawIp = strtok($line, " \t");
        }

        $ip = normalize_ip_cidr((string)$rawIp);
        if ($ip === null || isset($seen[$ip])) continue;
        $seen[$ip] = true;
        $entries[] = ['ip' => $ip, 'comment' => safe_comment($comment)];
    }
    return $entries;
}

function write_whitelist(array $entries): bool {
    $lines = [];
    $seen = [];
    foreach ($entries as $entry) {
        if (!is_array($entry)) continue;
        $ip = normalize_ip_cidr((string)($entry['ip'] ?? ''));
        if ($ip === null || isset($seen[$ip])) continue;
        $seen[$ip] = true;

        $comment = safe_comment((string)($entry['comment'] ?? ''));
        $lines[] = $ip . ($comment !== '' ? "  # {$comment}" : '');
    }

    return file_put_contents(WHITELIST_IPS, implode("\n", $lines) . (count($lines) ? "\n" : ''), LOCK_EX) !== false;
}
