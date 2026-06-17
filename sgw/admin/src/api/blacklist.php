<?php
require_once __DIR__ . '/_auth.php';

$method = $_SERVER['REQUEST_METHOD'];

if ($method === 'GET') {
    if (!empty($_GET['cloud_cidrs'])) {
        json_out(['ok' => true, 'cidrs' => read_cloud_cidrs()]);
    }

    $idc = empty($_GET['no_idc']) ? read_idc_summary() : [];
    json_out(['ok' => true, 'entries' => read_blacklist(), 'idc_summary' => $idc]);
}

if ($method === 'POST') {
    $body = json_decode(file_get_contents('php://input'), true) ?? [];

    if (!empty($body['import_ips']) && is_array($body['import_ips'])) {
        $entries = read_blacklist();
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
            $entries[] = [
                'ip' => $ip,
                'comment' => '从文件导入',
                'added_at' => date('Y-m-d H:i'),
            ];
            $existingSet[$ip] = true;
            $added++;
        }

        $reload = false;
        if ($added > 0) {
            if (!write_blacklist($entries)) {
                json_err('写入黑名单文件失败，请检查文件权限');
            }
            $reload = nginx_reload();
        }

        json_out([
            'ok' => true,
            'added' => $added,
            'skipped' => $skipped,
            'invalid' => $invalid,
            'nginx_reloaded' => $reload,
        ]);
    }

    $ip = normalize_ip_cidr((string)($body['ip'] ?? ''));
    $comment = safe_comment((string)($body['comment'] ?? ''));
    if ($ip === null) {
        json_err('IP 格式不合法（支持 IPv4、IPv6、CIDR）');
    }

    $entries = read_blacklist();
    foreach ($entries as $entry) {
        if ($entry['ip'] === $ip) {
            json_err('该IP已在黑名单中');
        }
    }

    $entries[] = [
        'ip' => $ip,
        'comment' => $comment,
        'added_at' => date('Y-m-d H:i'),
    ];

    if (!write_blacklist($entries)) {
        json_err('写入黑名单文件失败，请检查文件权限');
    }
    $reload = nginx_reload();
    json_out(['ok' => true, 'nginx_reloaded' => $reload, 'ip' => $ip]);
}

if ($method === 'PATCH') {
    $body = json_decode(file_get_contents('php://input'), true) ?? [];
    $ip = normalize_ip_cidr((string)($body['ip'] ?? ''));
    $comment = safe_comment((string)($body['comment'] ?? ''));
    if ($ip === null) {
        json_err('IP 格式不合法（支持 IPv4、IPv6、CIDR）');
    }

    $entries = read_blacklist();
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
    if (!write_blacklist($entries)) {
        json_err('写入黑名单文件失败，请检查文件权限');
    }
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

    $entries = array_values(array_filter(read_blacklist(), fn($entry) => !isset($toRemove[$entry['ip']])));
    if (!write_blacklist($entries)) {
        json_err('写入黑名单文件失败，请检查文件权限');
    }
    $reload = nginx_reload();
    json_out(['ok' => true, 'nginx_reloaded' => $reload]);
}

json_err('不支持的请求方式', 405);

function read_blacklist(): array {
    if (!file_exists(BLACKLIST_JSON)) return [];

    $data = json_decode(file_get_contents(BLACKLIST_JSON), true);
    if (!is_array($data)) return [];

    $entries = [];
    $seen = [];
    foreach ($data as $entry) {
        if (!is_array($entry)) continue;
        $ip = normalize_ip_cidr((string)($entry['ip'] ?? ''));
        if ($ip === null || isset($seen[$ip])) continue;
        $seen[$ip] = true;
        $entries[] = [
            'ip' => $ip,
            'comment' => safe_comment((string)($entry['comment'] ?? '')),
            'added_at' => safe_comment((string)($entry['added_at'] ?? '')),
        ];
    }
    return $entries;
}

function write_blacklist(array $entries): bool {
    $clean = [];
    $seen = [];
    foreach ($entries as $entry) {
        if (!is_array($entry)) continue;
        $ip = normalize_ip_cidr((string)($entry['ip'] ?? ''));
        if ($ip === null || isset($seen[$ip])) continue;
        $seen[$ip] = true;
        $clean[] = [
            'ip' => $ip,
            'comment' => safe_comment((string)($entry['comment'] ?? '')),
            'added_at' => safe_comment((string)($entry['added_at'] ?? '')),
        ];
    }

    $r1 = file_put_contents(
        BLACKLIST_JSON,
        json_encode($clean, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE),
        LOCK_EX
    );

    $lines = ['# blacklist - generated by admin | ' . date('Y-m-d H:i:s')];
    foreach ($clean as $entry) {
        $at = $entry['added_at'];
        $comment = $entry['comment'];
        $suffix = $comment !== '' ? " # {$comment} ({$at})" : ($at !== '' ? " # {$at}" : '');
        $lines[] = "deny {$entry['ip']};{$suffix}";
    }
    $r2 = file_put_contents(BLACKLIST_CONF, implode("\n", $lines) . "\n", LOCK_EX);

    return $r1 !== false && $r2 !== false;
}

function read_cloud_cidrs(): array {
    if (!file_exists(CLOUD_GEO_CONF)) return [];

    $cidrs = [];
    foreach (file(CLOUD_GEO_CONF, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
        $line = trim($line);
        if (preg_match('/^([0-9a-fA-F:.\/]+)\s+1;$/', $line, $m)) {
            $cidr = normalize_ip_cidr($m[1]);
            if ($cidr !== null) $cidrs[] = $cidr;
        }
    }
    return $cidrs;
}

function read_idc_summary(): array {
    if (!file_exists(CLOUD_GEO_CONF)) return [];

    $summary = [];
    $current = null;
    $count = 0;

    foreach (file(CLOUD_GEO_CONF, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
        $line = trim($line);
        if (preg_match('/^# === (.+) ===$/', $line, $m)) {
            if ($current !== null && $count > 0) {
                $summary[] = ['name' => $current, 'count' => $count];
            }
            $current = $m[1];
            $count = 0;
            continue;
        }

        if ($current !== null && preg_match('/^([0-9a-fA-F:.\/]+)\s+1;$/', $line, $m)) {
            if (normalize_ip_cidr($m[1]) !== null) $count++;
        }
    }

    if ($current !== null && $count > 0) {
        $summary[] = ['name' => $current, 'count' => $count];
    }
    return $summary;
}
