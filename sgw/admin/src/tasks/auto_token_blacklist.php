<?php
error_reporting(E_ALL);
ini_set('display_errors', '0');

if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}

require_once dirname(__DIR__) . '/config.php';

const AUTO_TOKEN_BLACKLIST_INTERVAL_LINES = 10000;
const AUTO_TOKEN_BLACKLIST_MAX_BYTES = 16777216;
const AUTO_TOKEN_BLACKLIST_THRESHOLD = 2;
const AUTO_TOKEN_BLACKLIST_LOCK = '/tmp/subsieve_auto_token_blacklist.lock';
const AUTO_TOKEN_BLACKLIST_STATE = '/etc/nginx/subscribe/.auto_token_blacklist_state.json';

$lock = fopen(AUTO_TOKEN_BLACKLIST_LOCK, 'c');
if (!$lock || !flock($lock, LOCK_EX | LOCK_NB)) {
    exit(0);
}

$result = auto_token_blacklist_run();
if ($result['error'] !== '') {
    fwrite(STDERR, '[auto-token-blacklist] error=' . $result['error'] . PHP_EOL);
}
if ($result['added_count'] > 0) {
    echo '[auto-token-blacklist] added=' . $result['added_count']
        . ' reload=' . ($result['reloaded'] ? '1' : '0') . PHP_EOL;
}

flock($lock, LOCK_UN);
fclose($lock);

function auto_token_blacklist_run(): array {
    if (!auto_token_blacklist_log_changed()) {
        return ['added_count' => 0, 'reloaded' => false, 'error' => ''];
    }

    $tokenBlacklistEntries = read_token_blacklist_entries();
    $tokenBlacklist = [];
    foreach ($tokenBlacklistEntries as $entry) {
        $tokenBlacklist[$entry['token']] = true;
    }

    $whitelistIndex = auto_token_blacklist_build_cidr_index(auto_token_blacklist_read_whitelist_cidrs());
    $blacklistIndex = auto_token_blacklist_build_cidr_index(auto_token_blacklist_read_blacklist_cidrs());
    $whitelistHitCache = [];
    $blacklistHitCache = [];
    $tokenBlacklistedIpAttempts = [];

    foreach (auto_token_blacklist_recent_log_lines(LOG_FILE, AUTO_TOKEN_BLACKLIST_INTERVAL_LINES) as $line) {
        $parsed = parse_access_log_line($line);
        if (!$parsed) continue;

        $status = $parsed['status'];
        if ($status !== 200 && $status !== 403) continue;

        $request = $parsed['request'];
        if (!is_subscribe_request($request)) continue;

        $tok = token_from_request($request);
        if ($tok === '' || isset($tokenBlacklist[$tok])) continue;

        $ip = $parsed['ip'];
        if (!isset($whitelistHitCache[$ip])) {
            $whitelistHitCache[$ip] = auto_token_blacklist_ip_in_cidr_index($ip, $whitelistIndex);
        }
        if ($whitelistHitCache[$ip]) continue;

        if (!isset($blacklistHitCache[$ip])) {
            $blacklistHitCache[$ip] = auto_token_blacklist_ip_in_cidr_index($ip, $blacklistIndex);
        }
        if ($blacklistHitCache[$ip]) {
            $tokenBlacklistedIpAttempts[$tok][$ip] = true;
        }
    }

    $tokensToAutoBan = [];
    $existingTokenSet = $tokenBlacklist;
    foreach ($tokenBlacklistedIpAttempts as $tok => $ipSet) {
        if (count($ipSet) < AUTO_TOKEN_BLACKLIST_THRESHOLD) continue;
        if (isset($existingTokenSet[$tok])) continue;
        if (!token_blacklist_value_is_safe($tok)) continue;

        $tokensToAutoBan[] = $tok;
        $existingTokenSet[$tok] = true;
    }

    $reloaded = false;
    $error = '';
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
            $reloaded = nginx_reload();
        } else {
            $error = 'write_failed';
        }
    }

    if ($error === '') {
        auto_token_blacklist_save_log_state();
    }

    return ['added_count' => count($tokensToAutoBan), 'reloaded' => $reloaded, 'error' => $error];
}

function auto_token_blacklist_log_changed(): bool {
    $current = auto_token_blacklist_log_state();
    if ($current === null) return false;

    $previous = null;
    if (file_exists(AUTO_TOKEN_BLACKLIST_STATE)) {
        $data = json_decode((string)file_get_contents(AUTO_TOKEN_BLACKLIST_STATE), true);
        if (is_array($data)) $previous = $data;
    }

    return $previous === null
        || (string)($previous['inode'] ?? '') !== (string)$current['inode']
        || (int)($previous['size'] ?? -1) !== (int)$current['size']
        || (int)($previous['mtime'] ?? -1) !== (int)$current['mtime'];
}

function auto_token_blacklist_save_log_state(): void {
    $state = auto_token_blacklist_log_state();
    if ($state === null) return;
    @file_put_contents(AUTO_TOKEN_BLACKLIST_STATE, json_encode($state), LOCK_EX);
    @chmod(AUTO_TOKEN_BLACKLIST_STATE, 0666);
}

function auto_token_blacklist_log_state(): ?array {
    if (!file_exists(LOG_FILE)) return null;
    clearstatcache(true, LOG_FILE);
    $size = filesize(LOG_FILE);
    $mtime = filemtime(LOG_FILE);
    $inode = fileinode(LOG_FILE);
    if ($size === false || $mtime === false || $inode === false) return null;
    return ['inode' => $inode, 'size' => $size, 'mtime' => $mtime];
}

function auto_token_blacklist_recent_log_lines(string $path, int $maxRows): array {
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
    $readBytes = 0;
    $buffer = '';
    $lines = [];

    while ($position > 0 && count($lines) <= $maxRows && $readBytes < AUTO_TOKEN_BLACKLIST_MAX_BYTES) {
        $readSize = min($chunkSize, $position, AUTO_TOKEN_BLACKLIST_MAX_BYTES - $readBytes);
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

function auto_token_blacklist_read_whitelist_cidrs(): array {
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

function auto_token_blacklist_read_blacklist_cidrs(): array {
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

function auto_token_blacklist_build_cidr_index(array $cidrs): array {
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
        $index[$bucket][$prefix][auto_token_blacklist_masked_prefix_hex($bin, $prefix)] = true;
    }

    krsort($index['v4_prefix']);
    krsort($index['v6_prefix']);
    return $index;
}

function auto_token_blacklist_ip_in_cidr_index(string $ip, array $index): bool {
    $ip = normalize_ip_cidr($ip);
    if ($ip === null || str_contains($ip, '/')) return false;

    $bin = inet_pton($ip);
    if ($bin === false) return false;

    $isV4 = strlen($bin) === 4;
    if (isset($index[$isV4 ? 'v4_exact' : 'v6_exact'][bin2hex($bin)])) {
        return true;
    }

    foreach ($index[$isV4 ? 'v4_prefix' : 'v6_prefix'] as $prefix => $keys) {
        if (isset($keys[auto_token_blacklist_masked_prefix_hex($bin, (int)$prefix)])) {
            return true;
        }
    }
    return false;
}

function auto_token_blacklist_masked_prefix_hex(string $bin, int $prefix): string {
    $fullBytes = intdiv($prefix, 8);
    $remainingBits = $prefix % 8;
    $out = $fullBytes > 0 ? substr($bin, 0, $fullBytes) : '';

    if ($remainingBits > 0) {
        $mask = (0xFF << (8 - $remainingBits)) & 0xFF;
        $out .= chr(ord($bin[$fullBytes]) & $mask);
    }
    return bin2hex($out);
}