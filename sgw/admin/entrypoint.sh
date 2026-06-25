#!/bin/sh
set -e

SUBSCRIBE_DIR=/etc/nginx/subscribe

# 确保目录存在且 admin 可写
mkdir -p "$SUBSCRIBE_DIR"
chmod 777 "$SUBSCRIBE_DIR"

# 确保所有可写文件存在
[ -f "$SUBSCRIBE_DIR/blacklist.json" ]    || echo "[]" > "$SUBSCRIBE_DIR/blacklist.json"
[ -f "$SUBSCRIBE_DIR/blacklist.conf" ]    || echo "# blacklist" > "$SUBSCRIBE_DIR/blacklist.conf"
[ -f "$SUBSCRIBE_DIR/ua_blacklist.json" ] || echo "[]" > "$SUBSCRIBE_DIR/ua_blacklist.json"
[ -f "$SUBSCRIBE_DIR/ua_custom.conf" ]    || printf 'map $http_user_agent $is_custom_bad_ua {\n    default 0;\n}\n' > "$SUBSCRIBE_DIR/ua_custom.conf"
[ -f "$SUBSCRIBE_DIR/whitelist_ips.txt" ] || touch "$SUBSCRIBE_DIR/whitelist_ips.txt"
[ -f "$SUBSCRIBE_DIR/admin_settings.json" ] || echo "{}" > "$SUBSCRIBE_DIR/admin_settings.json"
[ -f "$SUBSCRIBE_DIR/token_blacklist.json" ] || echo "[]" > "$SUBSCRIBE_DIR/token_blacklist.json"
if [ ! -f "$SUBSCRIBE_DIR/token_blacklist.conf" ]; then
    cat > "$SUBSCRIBE_DIR/token_blacklist.conf" <<'TOKENEOF'
map $arg_token $is_query_token_blacklisted {
    default 0;
}

map $uri $path_subscribe_token {
    default "";
    ~^/.+/([^/?]+)$ $1;
}

map $path_subscribe_token $is_path_token_blacklisted {
    default 0;
}

map "$is_query_token_blacklisted$is_path_token_blacklisted" $is_token_blacklisted {
    default 0;
    ~1 1;
}
TOKENEOF
fi

chmod 666 \
    "$SUBSCRIBE_DIR/blacklist.json" \
    "$SUBSCRIBE_DIR/blacklist.conf" \
    "$SUBSCRIBE_DIR/ua_blacklist.json" \
    "$SUBSCRIBE_DIR/ua_custom.conf" \
    "$SUBSCRIBE_DIR/whitelist_ips.txt" \
    "$SUBSCRIBE_DIR/admin_settings.json" \
    "$SUBSCRIBE_DIR/token_blacklist.json" \
    "$SUBSCRIBE_DIR/token_blacklist.conf"

php -r 'require "/var/www/html/config.php"; write_token_blacklist_files(read_token_blacklist_entries()); @file_put_contents(NGINX_RELOAD_SIGNAL, "1", LOCK_EX);' || true

# 确保日志卷目录和日志文件对 PHP-FPM(www-data) 可写
mkdir -p /var/log/subscribe
chmod 777 /var/log/subscribe
touch /var/log/subscribe/access.log
chmod 666 /var/log/subscribe/access.log

AUTO_TOKEN_BLACKLIST_INTERVAL="${AUTO_TOKEN_BLACKLIST_INTERVAL:-60}"
case "$AUTO_TOKEN_BLACKLIST_INTERVAL" in
    ''|*[!0-9]*) AUTO_TOKEN_BLACKLIST_INTERVAL=60 ;;
esac
if [ "$AUTO_TOKEN_BLACKLIST_INTERVAL" -lt 10 ]; then
    AUTO_TOKEN_BLACKLIST_INTERVAL=60
fi

(
    while true; do
        php /var/www/html/tasks/auto_token_blacklist.php >/proc/1/fd/1 2>/proc/1/fd/2 || true
        sleep "$AUTO_TOKEN_BLACKLIST_INTERVAL"
    done
) &

php-fpm -D
exec nginx -g 'daemon off;'
