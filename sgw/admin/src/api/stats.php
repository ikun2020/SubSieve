<?php
require_once __DIR__ . '/_auth.php';

$STATS_MAX_LINES = 10000;
$AUTO_TOKEN_BLACKLIST_THRESHOLD = 2;

$ips    = [];   // ip => [total,200,403,429,444]  (recent window, today only)
$tokens = [];   // token => [count, last_time]     (recent window, today only)
$badUas = [];   // ua => count (403 only, today)

$suspTokenIps = [];                 // token => {ip => true}
$suspIpTokens = [];                  // ip    => {token => true}
$tokenBlacklistedIpAttempts = [];    // token => {blacklisted ip => true}

$tokenBlacklistEntries = read_token_blacklist_entries();
$tokenBlacklist = [];
foreach ($tokenBlacklistEntries as $e) {
    $tokenBlacklist[$e['token']] = true;
}

$whitelistCidrs = stats_read_whitelist_cidrs();
$blacklistCidrs = stats_read_blacklist_cidrs();
$whitelistIndex = stats_build_cidr_index($whitelistCidrs);
$blacklistIndex = stats_build_cidr_index($blacklistCidrs);
$whitelistHitCache = [];
$blacklistHitCache = [];

foreach (stats_recent_log_lines(LOG_FILE, $STATS_MAX_LINES) as $line) {
    $parsed = parse_access_log_line($line);
    if (!$parsed) continue;

    $ip = $parsed['ip'];
    $time = $parsed['time'];
    $request = $parsed['request'];
    $status = $parsed['status'];
    $ua = $parsed['ua'];
    $tok = token_from_request($request);

    if (log_line_is_today($line)) {
        if (!isset($ips[$ip])) $ips[$ip] = ['total'=>0,'s200'=>0,'s403'=>0,'s429'=>0,'s444'=>0];
        $ips[$ip]['total']++;
        if ($status === 200) $ips[$ip]['s200']++;
        elseif ($status === 403) $ips[$ip]['s403']++;
        elseif ($status === 429) $ips[$ip]['s429']++;
        elseif ($status === 444) $ips[$ip]['s444']++;

        if ($tok !== '' && !isset($tokenBlacklist[$tok])) {
            if (!isset($tokens[$tok])) $tokens[$tok] = ['count'=>0,'last_time'=>''];
            $tokens[$tok]['count']++;
            $tokens[$tok]['last_time'] = trim(preg_replace('/^\d+\/\w+\/\d+:/', '', preg_replace('/ \+\d+$/', '', $time)));
        }

        if ($status === 403 && $ua !== '') {
            if (!isset($badUas[$ua])) $badUas[$ua] = 0;
            $badUas[$ua]++;
        }
    }

    // Suspicious analysis counts subscription attempts only. Token list counts 200/403;
    // suspicious IP list counts successful 200 pulls only.
    if (($status === 200 || $status === 403)
        && $tok !== ''
        && !isset($tokenBlacklist[$tok])
        && is_subscribe_request($request)
    ) {
        if (!isset($whitelistHitCache[$ip])) {
            $whitelistHitCache[$ip] = stats_ip_in_cidr_index($ip, $whitelistIndex);
        }
        if ($whitelistHitCache[$ip]) continue;

        $suspTokenIps[$tok][$ip] = true;

        if (!isset($blacklistHitCache[$ip])) {
            $blacklistHitCache[$ip] = stats_ip_in_cidr_index($ip, $blacklistIndex);
        }
        if ($blacklistHitCache[$ip]) {
            $tokenBlacklistedIpAttempts[$tok][$ip] = true;
        }

        if ($status === 200) {
            $suspIpTokens[$ip][$tok] = true;
        }
    }
}

$autoBannedTokens = [];
$autoBanReloaded = false;
$autoBanError = '';
$tokensToAutoBan = [];
$existingTokenSet = $tokenBlacklist;

foreach ($tokenBlacklistedIpAttempts as $tok => $ipSet) {
    if (count($ipSet) < $AUTO_TOKEN_BLACKLIST_THRESHOLD) continue;
    if (isset($existingTokenSet[$tok])) continue;
    if (!token_blacklist_value_is_safe($tok)) continue;

    $tokensToAutoBan[] = $tok;
    $existingTokenSet[$tok] = true;
}

if ($tokensToAutoBan) {
    $updatedEntries = $tokenBlacklistEntries;
    foreach ($tokensToAutoBan as $tok) {
        $updatedEntries[] = [
            'token' => $tok,
            'comment' => hex2bin('e887aae58aa8e68b89e9bb91efbc9a3220e4b8aae9bb91e5908de58d9520495020e8aebfe997ae'),
            'added_at' => date('Y-m-d H:i'),
        ];
    }

    if (write_token_blacklist_files($updatedEntries)) {
        $autoBannedTokens = $tokensToAutoBan;
        $autoBanReloaded = nginx_reload();
        foreach ($autoBannedTokens as $tok) {
            $tokenBlacklist[$tok] = true;
            unset($tokens[$tok], $suspTokenIps[$tok]);
        }
    } else {
        $autoBanError = 'write_failed';
    }
}

uasort($ips, fn($a,$b) => $b['total'] - $a['total']);
$topIps = [];
foreach (array_slice($ips, 0, 500, true) as $ip => $v) {
    $topIps[] = array_merge(['ip' => $ip], $v);
}

uasort($tokens, fn($a,$b) => $b['count'] - $a['count']);
$topTokens = [];
foreach (array_slice($tokens, 0, 500, true) as $tok => $v) {
    $topTokens[] = [
        'token'      => substr($tok, 0, 8) . '...',
        'token_full' => $tok,
        'count'      => $v['count'],
        'last_time'  => $v['last_time'],
    ];
}

arsort($badUas);
$badUaList = [];
foreach (array_slice($badUas, 0, 500, true) as $ua => $cnt) {
    $badUaList[] = ['ua' => $ua, 'count' => $cnt];
}

$SUSP_TOKEN_THRESHOLD = 3;
$suspTokenList = [];
foreach ($suspTokenIps as $tok => $ipSet) {
    $cnt = count($ipSet);
    if ($cnt >= $SUSP_TOKEN_THRESHOLD) {
        $suspTokenList[] = ['token' => $tok, 'ip_count' => $cnt, 'ips' => array_keys($ipSet)];
    }
}
usort($suspTokenList, fn($a,$b) => $b['ip_count'] - $a['ip_count']);

$SUSP_IP_THRESHOLD = 3;
$suspIpList = [];
foreach ($suspIpTokens as $ip => $tokSet) {
    $cnt = count($tokSet);
    if ($cnt >= $SUSP_IP_THRESHOLD) {
        $suspIpList[] = ['ip' => $ip, 'token_count' => $cnt];
    }
}
usort($suspIpList, fn($a,$b) => $b['token_count'] - $a['token_count']);

json_out([
    'ok'                 => true,
    'top_ips'            => $topIps,
    'top_tokens'         => $topTokens,
    'bad_uas'            => $badUaList,
    'susp_tokens'        => $suspTokenList,
    'susp_ips'           => $suspIpList,
    'auto_banned_tokens' => $autoBannedTokens,
    'auto_ban_reloaded'  => $autoBanReloaded,
    'auto_ban_error'     => $autoBanError,
    'window_lines'       => $STATS_MAX_LINES,
]);

function stats_recent_log_lines(string $path, int $maxRows): array {
    if (!file_exists($path) || $maxRows <= 0) return [];

    $handle = fopen($path, 'rb');
    if (!$handle) return [];

    clearstatcache(true, $path);
    $position = filesize($path);
    if ($position === false || $position <= 0) {
        fclose($handle);
        return [];
    }

    $chunkSize = 65536;
    $maxBytes = 16 * 1024 * 1024;
    $readBytes = 0;
    $buffer = '';
    $lines = [];

    while ($position > 0 && count($lines) <= $maxRows && $readBytes < $maxBytes) {
        $readSize = min($chunkSize, $position, $maxBytes - $readBytes);
        if ($readSize <= 0) break;
        $position -= $readSize;
        $readBytes += $readSize;
        if (fseek($handle, $position) !== 0) break;

        $chunk = fread($handle, $readSize);
        if ($chunk === false) break;

        $buffer = $chunk . $buffer;
        $parts = explode("\n", $buffer);
        $buffer = array_shift($parts);
        $lines = array_merge($parts, $lines);
    }
    fclose($handle);

    if ($buffer !== '') {
        array_unshift($lines, $buffer);
    }

    $lines = array_values(array_filter(array_map(static fn($line) => rtrim($line, "\r"), $lines), static fn($line) => $line !== ''));
    if (count($lines) > $maxRows) {
        $lines = array_slice($lines, -$maxRows);
    }
    return $lines;
}

function stats_read_whitelist_cidrs(): array {
    $cidrs = [];
    if (!file_exists(WHITELIST_IPS)) return $cidrs;

    foreach (file(WHITELIST_IPS, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
        $line = trim($line);
        if ($line === '' || str_starts_with($line, '#')) continue;
        $value = normalize_ip_cidr((string)strtok($line, " \t#"));
        if ($value !== null) $cidrs[] = $value;
    }
    return array_values(array_unique($cidrs));
}

function stats_read_blacklist_cidrs(): array {
    $cidrs = [];
    $seen = [];
    $add = function (string $value) use (&$cidrs, &$seen): void {
        $value = normalize_ip_cidr($value);
        if ($value !== null && !isset($seen[$value])) {
            $seen[$value] = true;
            $cidrs[] = $value;
        }
    };

    if (file_exists(BLACKLIST_JSON)) {
        $data = json_decode((string)file_get_contents(BLACKLIST_JSON), true);
        if (is_array($data)) {
            foreach ($data as $entry) {
                $add((string)($entry['ip'] ?? ''));
            }
        }
    }

    if (file_exists(CLOUD_GEO_CONF)) {
        foreach (file(CLOUD_GEO_CONF, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
            $line = trim($line);
            if (preg_match('/^([0-9a-fA-F:.\/]+)\s+1;$/', $line, $m)) {
                $add($m[1]);
            }
        }
    }

    return $cidrs;
}

function stats_build_cidr_index(array $cidrs): array {
    $index = [
        'v4_exact' => [],
        'v6_exact' => [],
        'v4_prefix' => [],
        'v6_prefix' => [],
    ];

    foreach ($cidrs as $cidr) {
        $cidr = normalize_ip_cidr((string)$cidr);
        if ($cidr === null) continue;

        $parts = explode('/', $cidr, 2);
        $bin = inet_pton($parts[0]);
        if ($bin === false) continue;

        $isV4 = strlen($bin) === 4;
        $maxPrefix = $isV4 ? 32 : 128;
        if (count($parts) === 1) {
            $index[$isV4 ? 'v4_exact' : 'v6_exact'][bin2hex($bin)] = true;
            continue;
        }

        $prefix = (int)$parts[1];
        if ($prefix < 0 || $prefix > $maxPrefix) continue;
        $bucket = $isV4 ? 'v4_prefix' : 'v6_prefix';
        $index[$bucket][$prefix][stats_masked_prefix_hex($bin, $prefix)] = true;
    }

    krsort($index['v4_prefix']);
    krsort($index['v6_prefix']);
    return $index;
}

function stats_ip_in_cidr_index(string $ip, array $index): bool {
    $ip = normalize_ip_cidr($ip);
    if ($ip === null || str_contains($ip, '/')) return false;

    $bin = inet_pton($ip);
    if ($bin === false) return false;

    $isV4 = strlen($bin) === 4;
    if (isset($index[$isV4 ? 'v4_exact' : 'v6_exact'][bin2hex($bin)])) {
        return true;
    }

    foreach ($index[$isV4 ? 'v4_prefix' : 'v6_prefix'] as $prefix => $keys) {
        if (isset($keys[stats_masked_prefix_hex($bin, (int)$prefix)])) {
            return true;
        }
    }
    return false;
}

function stats_masked_prefix_hex(string $bin, int $prefix): string {
    $fullBytes = intdiv($prefix, 8);
    $remainingBits = $prefix % 8;
    $out = $fullBytes > 0 ? substr($bin, 0, $fullBytes) : '';

    if ($remainingBits > 0) {
        $mask = (0xFF << (8 - $remainingBits)) & 0xFF;
        $out .= chr(ord($bin[$fullBytes]) & $mask);
    }
    return bin2hex($out);
}
