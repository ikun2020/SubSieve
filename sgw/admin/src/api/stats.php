<?php
require_once __DIR__ . '/_auth.php';

$ips    = [];   // ip => [total,200,403,429,444]  (today only)
$tokens = [];   // token => [count, last_time]     (today only)
$badUas = [];   // ua => count (403 only, today)

// 全量日志用于可疑分析
$suspTokenIps = [];  // token => {ip => true}
$suspIpTokens = [];  // ip    => {token => true}
$tokenBlacklistedIpAttempts = [];  // token => {blacklisted ip => true}
$AUTO_TOKEN_BLACKLIST_THRESHOLD = 3;

// 读取Token黑名单（用于从统计中排除）
$tokenBlacklistEntries = read_token_blacklist_entries();
$tokenBlacklist = [];
foreach ($tokenBlacklistEntries as $e) {
    $tokenBlacklist[$e['token']] = true;
}

// 读取白名单（用于排除）
$whitelistIps = [];
if (file_exists(WHITELIST_IPS)) {
    foreach (file(WHITELIST_IPS, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $wl) {
        $wl = trim($wl);
        if ($wl === '' || str_starts_with($wl, '#')) continue;
        $ip = strtok($wl, " \t#");
        $ip = normalize_ip_cidr((string)$ip);
        if ($ip !== null) $whitelistIps[] = $ip;
    }
}

$blacklistIps = [];
$blacklistSeen = [];
$addBlacklistCidr = function (string $value) use (&$blacklistIps, &$blacklistSeen): void {
    $ip = normalize_ip_cidr($value);
    if ($ip !== null && !isset($blacklistSeen[$ip])) {
        $blacklistSeen[$ip] = true;
        $blacklistIps[] = $ip;
    }
};

if (file_exists(BLACKLIST_JSON)) {
    $blData = json_decode((string)file_get_contents(BLACKLIST_JSON), true);
    if (is_array($blData)) {
        foreach ($blData as $entry) {
            $addBlacklistCidr((string)($entry['ip'] ?? ''));
        }
    }
}

if (file_exists(CLOUD_GEO_CONF)) {
    foreach (file(CLOUD_GEO_CONF, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
        $line = trim($line);
        if (preg_match('/^([0-9a-fA-F:.\/]+)\s+1;$/', $line, $m)) {
            $addBlacklistCidr($m[1]);
        }
    }
}
unset($blacklistSeen, $addBlacklistCidr);

$whitelistHitCache = [];
$blacklistHitCache = [];

if (file_exists(LOG_FILE)) {
    $handle = fopen(LOG_FILE, 'r');
    if ($handle) {
        while (($line = fgets($handle)) !== false) {
            $line = rtrim($line);
            if ($line === '') continue;

            $parsed = parse_access_log_line($line);
            if (!$parsed) continue;

            $ip = $parsed['ip'];
            $time = $parsed['time'];
            $request = $parsed['request'];
            $status = $parsed['status'];
            $ua = $parsed['ua'];

            // ── 今日统计 ──────────────────────────────────────────
            if (log_line_is_today($line)) {
                if (!isset($ips[$ip])) $ips[$ip] = ['total'=>0,'s200'=>0,'s403'=>0,'s429'=>0,'s444'=>0];
                $ips[$ip]['total']++;
                if ($status === 200) $ips[$ip]['s200']++;
                elseif ($status === 403) $ips[$ip]['s403']++;
                elseif ($status === 429) $ips[$ip]['s429']++;
                elseif ($status === 444) $ips[$ip]['s444']++;

                $tok = token_from_request($request);
                if ($tok !== '') {
                    if (!isset($tokenBlacklist[$tok])) {
                        if (!isset($tokens[$tok])) $tokens[$tok] = ['count'=>0,'last_time'=>''];
                        $tokens[$tok]['count']++;
                        $tokens[$tok]['last_time'] = trim(preg_replace('/^\d+\/\w+\/\d+:/', '', preg_replace('/ \+\d+$/', '', $time)));
                    }
                }

                if ($status === 403 && $ua !== '') {
                    if (!isset($badUas[$ua])) $badUas[$ua] = 0;
                    $badUas[$ua]++;
                }
            }

            // Suspicious analysis: token list counts 200 and 403 attempts; IP list counts successful pulls only.
            $tok = token_from_request($request);
            if (!isset($whitelistHitCache[$ip])) {
                $whitelistHitCache[$ip] = ip_in_cidr_list($ip, $whitelistIps);
            }

            if (!$whitelistHitCache[$ip]
                && is_subscribe_request($request)
                && $tok !== ''
                && !isset($tokenBlacklist[$tok])
            ) {
                if (!isset($blacklistHitCache[$ip])) {
                    $blacklistHitCache[$ip] = ip_in_cidr_list($ip, $blacklistIps);
                }
                $isBlacklistedIp = $blacklistHitCache[$ip];

                if ($status === 200 || $status === 403) {
                    $suspTokenIps[$tok][$ip] = true;
                    if ($isBlacklistedIp) {
                        $tokenBlacklistedIpAttempts[$tok][$ip] = true;
                    }
                }

                if ($status === 200) {
                    $suspIpTokens[$ip][$tok]  = true;
                }
            }
        }
        fclose($handle);
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
            'comment' => hex2bin('e887aae58aa8e68b89e9bb91efbc9a3320e4b8aae9bb91e5908de58d9520495020e8aebfe997ae'),
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

// Top IP（今日，最多返回500条，前端负责显示限制）
uasort($ips, fn($a,$b) => $b['total'] - $a['total']);
$topIps = [];
foreach (array_slice($ips, 0, 500, true) as $ip => $v) {
    $topIps[] = array_merge(['ip' => $ip], $v);
}

// Top Token（今日，最多返回500条，前端负责显示限制）
uasort($tokens, fn($a,$b) => $b['count'] - $a['count']);
$topTokens = [];
foreach (array_slice($tokens, 0, 500, true) as $tok => $v) {
    $topTokens[] = [
        'token'      => substr($tok, 0, 8) . '…',
        'token_full' => $tok,
        'count'      => $v['count'],
        'last_time'  => $v['last_time'],
    ];
}

// UA TOP（最多返回500条，前端负责显示限制）
arsort($badUas);
$badUaList = [];
foreach (array_slice($badUas, 0, 500, true) as $ua => $cnt) {
    $badUaList[] = ['ua' => $ua, 'count' => $cnt];
}

// 可疑 Token（日志周期内被 3+ 个不同IP拉取）
$SUSP_TOKEN_THRESHOLD = 3;
$suspTokenList = [];
foreach ($suspTokenIps as $tok => $ipSet) {
    $cnt = count($ipSet);
    if ($cnt >= $SUSP_TOKEN_THRESHOLD) {
        $suspTokenList[] = ['token' => $tok, 'ip_count' => $cnt, 'ips' => array_keys($ipSet)];
    }
}
usort($suspTokenList, fn($a,$b) => $b['ip_count'] - $a['ip_count']);

// 可疑 IP（日志周期内拉取了 3+ 个不同Token）
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
    'ok'          => true,
    'top_ips'     => $topIps,
    'top_tokens'  => $topTokens,
    'bad_uas'     => $badUaList,
    'susp_tokens'        => $suspTokenList,
    'susp_ips'           => $suspIpList,
    'auto_banned_tokens' => $autoBannedTokens,
    'auto_ban_reloaded'  => $autoBanReloaded,
    'auto_ban_error'     => $autoBanError,
]);
