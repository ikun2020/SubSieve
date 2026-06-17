#!/bin/bash
# 从 whitelist_ips.txt 生成 whitelist.conf，然后热重载 nginx
# 供 entrypoint 和 admin 后台调用

set -euo pipefail

WHITELIST_FILE="/etc/nginx/subscribe/whitelist_ips.txt"
OUTPUT="/etc/nginx/subscribe/whitelist.conf"
SKIP_NGINX_RELOAD="${SKIP_NGINX_RELOAD:-0}"

cat > "$OUTPUT" <<'EOF'
geo $whitelist_ip {
    default 0;
EOF

if [[ -f "$WHITELIST_FILE" ]]; then
    while IFS= read -r line; do
        [[ -z "$line" || "$line" =~ ^# ]] && continue
        # Extract the IP/CIDR field and keep only characters valid for IPv4/IPv6/CIDR.
        ip=$(echo "$line" | awk '{print $1}')
        [[ -z "$ip" ]] && continue
        echo "$ip" | grep -Eq '^[0-9A-Fa-f:.]+(/[0-9]{1,3})?$' || continue
        echo "    $ip 1;" >> "$OUTPUT"
    done < "$WHITELIST_FILE"
fi

echo "}" >> "$OUTPUT"

if [[ "$SKIP_NGINX_RELOAD" != "1" ]]; then
    nginx -t 2>/dev/null && nginx -s reload
fi
