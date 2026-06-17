<?php
// =============================================================
// config.php — 从环境变量加载配置
// =============================================================

// 文件路径（共享 volume）— 先定义，以便读取 settings.json
define('LOG_FILE',          '/var/log/subscribe/access.log');
define('WHITELIST_IPS',     '/etc/nginx/subscribe/whitelist_ips.txt');
define('WHITELIST_CONF',    '/etc/nginx/subscribe/whitelist.conf');
define('BLACKLIST_JSON',    '/etc/nginx/subscribe/blacklist.json');
define('BLACKLIST_CONF',    '/etc/nginx/subscribe/blacklist.conf');
define('CLOUD_GEO_LOG',     '/var/log/subscribe/update_cloud_geo.log');
define('CLOUD_GEO_CONF',    '/etc/nginx/subscribe/cloud_geo.conf');
define('UA_BLACKLIST_JSON', '/etc/nginx/subscribe/ua_blacklist.json');
define('UA_CUSTOM_CONF',    '/etc/nginx/subscribe/ua_custom.conf');
define('UA_WHITELIST_JSON', '/etc/nginx/subscribe/ua_whitelist.json');
define('UA_WHITELIST_CONF',    '/etc/nginx/subscribe/ua_whitelist.conf');
define('TOKEN_BLACKLIST_JSON', '/etc/nginx/subscribe/token_blacklist.json');
define('SETTINGS_JSON',     '/etc/nginx/subscribe/admin_settings.json');
define('PROTECT_CONF',      '/etc/nginx/subscribe/protect.conf');
define('DEPLOY_INFO_FILE',  '/var/log/subscribe/DEPLOY_INFO.txt');

$__tz = getenv('TZ') ?: 'Asia/Shanghai';
if (!@date_default_timezone_set($__tz)) {
    date_default_timezone_set('Asia/Shanghai');
}

// 读取持久化设置（覆盖环境变量）
$_sg = [];
if (file_exists(SETTINGS_JSON)) {
    $_d = json_decode(file_get_contents(SETTINGS_JSON), true);
    if (is_array($_d)) $_sg = $_d;
}

define('ADMIN_USER',        $_sg['admin_user']      ?? (getenv('ADMIN_USER')        ?: 'admin'));
define('ADMIN_PASS',        $_sg['admin_pass']      ?? (getenv('ADMIN_PASS')        ?: ''));
define('NGINX_RELOAD_SIGNAL',     '/etc/nginx/subscribe/.reload');
define('WHITELIST_RELOAD_SIGNAL', '/etc/nginx/subscribe/.reload_whitelist');
define('GATEWAY_PORT',      (int)(getenv('GATEWAY_PORT') ?: 3333));
define('SESSION_LIFETIME',  (int)(getenv('SESSION_LIFETIME') ?: 28800)); // 8小时
// 后台访问路径前缀，留空则不校验（例如 ef9d1566 → 必须访问 /ef9d1566 才能进入后台）
define('ADMIN_SECRET_PATH', trim(trim(getenv('ADMIN_SECRET_PATH') ?: ''), '/'));

// 界面显示设置
define('SITE_TITLE', $_sg['site_title'] ?? 'SubSieve');
define('PAGE_TITLE', $_sg['page_title'] ?? 'SubSieve Admin');

// ── 辅助函数 ──────────────────────────────────────────────────

function json_out(array $data, int $code = 200): void {
    http_response_code($code);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($data, JSON_UNESCAPED_UNICODE);
    exit;
}

function json_err(string $msg, int $code = 400): void {
    json_out(['ok' => false, 'error' => $msg], $code);
}

function app_timezone(): DateTimeZone {
    static $tz = null;
    if ($tz === null) {
        $tz = new DateTimeZone(date_default_timezone_get());
    }
    return $tz;
}

function app_today_key(): string {
    return (new DateTimeImmutable('now', app_timezone()))->format('Y-m-d');
}

function app_today_label(): string {
    return (new DateTimeImmutable('now', app_timezone()))->format('d/M/Y');
}

function log_datetime(string $line): ?DateTimeImmutable {
    if (!preg_match('/\[(\d{2}\/\w{3}\/\d{4}:\d{2}:\d{2}:\d{2})(?: ([+-]\d{4}))?\]/', $line, $m)) {
        return null;
    }

    if (!empty($m[2])) {
        $dt = DateTimeImmutable::createFromFormat('!d/M/Y:H:i:s O', $m[1] . ' ' . $m[2]);
    } else {
        $dt = DateTimeImmutable::createFromFormat('!d/M/Y:H:i:s', $m[1], app_timezone());
    }

    return $dt ?: null;
}

function log_line_is_today(string $line): bool {
    $dt = log_datetime($line);
    if (!$dt) return false;
    return $dt->setTimezone(app_timezone())->format('Y-m-d') === app_today_key();
}

function normalize_path_value(string $path, string $default = '/'): string {
    $path = trim($path);
    if ($path === '') return $default;
    if (!str_starts_with($path, '/')) $path = '/' . $path;
    $path = preg_replace('#/+#', '/', $path);
    return $path === '/' ? '/' : rtrim($path, '/');
}

function current_subscribe_path(): string {
    static $path = null;
    if ($path !== null) return $path;

    $raw = '';
    if (file_exists(SETTINGS_JSON)) {
        $data = json_decode(file_get_contents(SETTINGS_JSON), true);
        if (is_array($data) && !empty($data['subscribe_path'])) {
            $raw = (string)$data['subscribe_path'];
        }
    }
    if ($raw === '' && file_exists(PROTECT_CONF)) {
        $conf = file_get_contents(PROTECT_CONF);
        if ($conf !== false && preg_match('/^location\s+\^~\s+(\S+)/m', $conf, $m)) {
            $raw = $m[1];
        }
    }
    if ($raw === '') $raw = getenv('SUBSCRIBE_PATH') ?: '/s';

    $path = normalize_path_value($raw, '/s');
    return $path;
}

function request_target_from_log(string $request): string {
    $parts = preg_split('/\s+/', trim($request));
    if (count($parts) >= 2 && preg_match('/^[A-Z]+$/', $parts[0])) {
        return $parts[1];
    }
    return $parts[0] ?? '';
}

function request_path_from_log(string $request): string {
    $target = request_target_from_log($request);
    $path = parse_url($target, PHP_URL_PATH);
    if (!is_string($path) || $path === '') {
        $path = explode('?', $target, 2)[0] ?? '';
    }
    return normalize_path_value($path, '/');
}

function subscribe_path_candidates(): array {
    return array_values(array_unique([
        current_subscribe_path(),
        '/s',
        '/api/v1/client/subscribe',
    ]));
}

function is_subscribe_request(string $request): bool {
    $path = request_path_from_log($request);
    foreach (subscribe_path_candidates() as $prefix) {
        $prefix = normalize_path_value($prefix, '/s');
        if ($path === $prefix || str_starts_with($path, $prefix . '/')) {
            return true;
        }
    }
    return false;
}

function token_from_request(string $request): string {
    if (preg_match('/[?&]token=([^&\s"]+)/i', $request, $m)) {
        return rawurldecode($m[1]);
    }

    if (!is_subscribe_request($request)) return '';

    $path = request_path_from_log($request);
    foreach (subscribe_path_candidates() as $prefix) {
        $prefix = normalize_path_value($prefix, '/s');
        if (str_starts_with($path, $prefix . '/')) {
            $rest = substr($path, strlen($prefix) + 1);
            $token = strtok($rest, '/');
            return $token ? rawurldecode($token) : '';
        }
    }

    return '';
}

function normalize_ip_cidr(string $value): ?string {
    $value = trim($value);
    if ($value === '' || preg_match('/[\s#;{}]/', $value)) {
        return null;
    }

    $parts = explode('/', $value);
    if (count($parts) > 2 || $parts[0] === '') {
        return null;
    }

    $ip = $parts[0];
    $isV4 = filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false;
    $isV6 = filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false;
    if (!$isV4 && !$isV6) {
        return null;
    }

    $ip = $isV6 ? strtolower($ip) : $ip;
    if (count($parts) === 1) {
        return $ip;
    }

    if (!preg_match('/^\d{1,3}$/', $parts[1])) {
        return null;
    }
    $prefix = (int)$parts[1];
    $maxPrefix = $isV4 ? 32 : 128;
    if ($prefix < 0 || $prefix > $maxPrefix) {
        return null;
    }

    return $ip . '/' . $prefix;
}

function ip_matches_cidr(string $ip, string $cidr): bool {
    $ip = normalize_ip_cidr($ip);
    $cidr = normalize_ip_cidr($cidr);
    if ($ip === null || $cidr === null || str_contains($ip, '/')) {
        return false;
    }

    $cidrParts = explode('/', $cidr, 2);
    $base = $cidrParts[0];
    $ipBin = inet_pton($ip);
    $baseBin = inet_pton($base);
    if ($ipBin === false || $baseBin === false || strlen($ipBin) !== strlen($baseBin)) {
        return false;
    }

    if (count($cidrParts) === 1) {
        return hash_equals($baseBin, $ipBin);
    }

    $prefix = (int)$cidrParts[1];
    $fullBytes = intdiv($prefix, 8);
    $remainingBits = $prefix % 8;

    if ($fullBytes > 0 && substr($ipBin, 0, $fullBytes) !== substr($baseBin, 0, $fullBytes)) {
        return false;
    }
    if ($remainingBits === 0) {
        return true;
    }

    $mask = (0xFF << (8 - $remainingBits)) & 0xFF;
    return (ord($ipBin[$fullBytes]) & $mask) === (ord($baseBin[$fullBytes]) & $mask);
}

function ip_in_cidr_list(string $ip, array $cidrs): bool {
    foreach ($cidrs as $cidr) {
        if (ip_matches_cidr($ip, (string)$cidr)) {
            return true;
        }
    }
    return false;
}

/**
 * 触发 gateway nginx reload
 * 向共享 volume 写入信号文件，gateway 的 watcher 检测后执行 nginx -s reload
 * 无需挂载 Docker socket，避免宿主机 root 权限暴露
 */
function nginx_reload(): bool {
    return file_put_contents(NGINX_RELOAD_SIGNAL, '1', LOCK_EX) !== false;
}

function whitelist_reload(): bool {
    return file_put_contents(WHITELIST_RELOAD_SIGNAL, '1', LOCK_EX) !== false;
}

// ── 写入 nginx 配置前的安全过滤 ────────────────────────────────
// 后台多处会把用户输入（路径、上游地址、UA、备注等）写入 nginx 配置文件，
// 若不过滤，换行 / 结构字符（{ } ; "）可篡改反代规则或注入指令。

/**
 * 校验将作为「结构性 token」直接拼入 nginx 配置的值（如订阅路径、上游地址、Host）。
 * 这些值未加引号写入配置，含换行或 nginx 结构字符（{ } ;）即可越权注入，故直接拒绝。
 * 校验不通过会输出 JSON 错误并终止请求。
 */
function safe_conf_value(string $s): string {
    $s = trim($s);
    if (preg_match('/[\r\n{};]/', $s)) {
        json_err('包含非法字符（不允许换行或 { } ; 等字符）');
    }
    return $s;
}

/**
 * 清洗将写入 nginx 配置 / 数据文件的「备注」文本，使其只能作为单行普通注释存在：
 * 移除换行（避免越行注入指令）及 # ; { } 等结构 / 注释字符，多个连续字符压缩为单空格。
 */
function safe_comment(string $s): string {
    return trim(preg_replace('/[\r\n#;{}]+/', ' ', $s));
}

/**
 * 将用户输入的 UA 关键词转为 nginx map 的「字面量」匹配模式（配合 ~* 前缀）。
 * 1) preg_quote 中和全部正则元字符，避免 . * 等生效或被构造成 ReDoS；
 * 2) 再转义 nginx 双引号字符串层的 \ 与 "，避免提前闭合字符串注入配置。
 * 调用方需保证传入的 UA 不含换行（写入前已剔除）。
 */
function nginx_ua_pattern(string $ua): string {
    $p = preg_quote($ua, '~');
    return str_replace(['\\', '"'], ['\\\\', '\\"'], $p);
}

// ── V2B 数据库接口（预留，后续填充）─────────────────────────
// TODO: 连接 V2B MySQL 查询 token 对应用户信息
// function v2b_get_user_by_token(string $token): ?array { return null; }
