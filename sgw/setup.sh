#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

ask() {
    local prompt="$1" default="$2" var="$3" val
    if [ -n "$default" ]; then
        read -r -p "$prompt [$default]: " val
        printf -v "$var" '%s' "${val:-$default}"
    else
        read -r -p "$prompt: " val
        printf -v "$var" '%s' "$val"
    fi
}

gen_random() {
    head -c 48 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9' | head -c "$1"
}

if ! command -v docker >/dev/null 2>&1; then
    echo "Docker is required. Install Docker and Docker Compose before running this script."
    exit 1
fi

if ! docker info >/dev/null 2>&1; then
    echo "Docker is installed but not running. Start Docker first."
    exit 1
fi

echo "SubSieve reverse-proxy mode setup"
echo
echo "This mode does not bind 80/443 and does not request certificates."
echo "Your host web server should reverse proxy public domains to 127.0.0.1:3333."
echo

V2B_HOST_DEFAULT=""
SUBSCRIBE_PATH_DEFAULT="/s"
GATEWAY_IMAGE_DEFAULT="ghcr.io/ikun2020/subsieve-gateway:latest"
ADMIN_IMAGE_DEFAULT="ghcr.io/ikun2020/subsieve-admin:latest"
LOCAL_BUILD_DEFAULT="0"
GATEWAY_BIND_DEFAULT="127.0.0.1"
GATEWAY_PORT_DEFAULT="3333"
ADMIN_BIND_DEFAULT="127.0.0.1"
ADMIN_PORT_DEFAULT="3334"
ADMIN_USER_DEFAULT="admin"
ADMIN_PASS_DEFAULT="$(gen_random 16)"
ADMIN_SECRET_PATH_DEFAULT="$(gen_random 12)"

if [ -f .env ]; then
    # shellcheck disable=SC1091
    set -a
    . ./.env
    set +a
    V2B_HOST_DEFAULT="${V2B_HOST:-}"
    SUBSCRIBE_PATH_DEFAULT="${SUBSCRIBE_PATH:-/s}"
    GATEWAY_IMAGE_DEFAULT="${GATEWAY_IMAGE:-ghcr.io/ikun2020/subsieve-gateway:latest}"
    ADMIN_IMAGE_DEFAULT="${ADMIN_IMAGE:-ghcr.io/ikun2020/subsieve-admin:latest}"
    LOCAL_BUILD_DEFAULT="${LOCAL_BUILD:-0}"
    GATEWAY_BIND_DEFAULT="${GATEWAY_BIND:-127.0.0.1}"
    GATEWAY_PORT_DEFAULT="${GATEWAY_PORT:-3333}"
    ADMIN_BIND_DEFAULT="${ADMIN_BIND:-127.0.0.1}"
    ADMIN_PORT_DEFAULT="${ADMIN_PORT:-3334}"
    ADMIN_USER_DEFAULT="${ADMIN_USER:-admin}"
    ADMIN_PASS_DEFAULT="${ADMIN_PASS:-$ADMIN_PASS_DEFAULT}"
    ADMIN_SECRET_PATH_DEFAULT="${ADMIN_SECRET_PATH:-$ADMIN_SECRET_PATH_DEFAULT}"
fi

ask "Upstream host, without https://, for example cdn.example.com" "$V2B_HOST_DEFAULT" V2B_HOST
V2B_HOST="${V2B_HOST#https://}"
V2B_HOST="${V2B_HOST%%/*}"
if [ -z "$V2B_HOST" ]; then
    echo "Upstream host is required."
    exit 1
fi
V2B_BACKEND="https://${V2B_HOST}"
GATEWAY_IMAGE="${GATEWAY_IMAGE_DEFAULT}"
ADMIN_IMAGE="${ADMIN_IMAGE_DEFAULT}"
LOCAL_BUILD="${LOCAL_BUILD_DEFAULT}"

ask "Subscription path exposed by this gateway" "$SUBSCRIBE_PATH_DEFAULT" SUBSCRIBE_PATH
ask "Gateway bind address" "$GATEWAY_BIND_DEFAULT" GATEWAY_BIND
ask "Gateway local port" "$GATEWAY_PORT_DEFAULT" GATEWAY_PORT
ask "Admin bind address" "$ADMIN_BIND_DEFAULT" ADMIN_BIND
ask "Admin local port" "$ADMIN_PORT_DEFAULT" ADMIN_PORT
ask "Admin username" "$ADMIN_USER_DEFAULT" ADMIN_USER
ask "Admin password" "$ADMIN_PASS_DEFAULT" ADMIN_PASS
ask "Admin secret path" "$ADMIN_SECRET_PATH_DEFAULT" ADMIN_SECRET_PATH

cat > .env <<EOF
V2B_BACKEND=${V2B_BACKEND}
V2B_HOST=${V2B_HOST}
SUBSCRIBE_PATH=${SUBSCRIBE_PATH}

GATEWAY_IMAGE=${GATEWAY_IMAGE}
ADMIN_IMAGE=${ADMIN_IMAGE}
LOCAL_BUILD=${LOCAL_BUILD}

GATEWAY_BIND=${GATEWAY_BIND}
GATEWAY_PORT=${GATEWAY_PORT}
ADMIN_BIND=${ADMIN_BIND}
ADMIN_PORT=${ADMIN_PORT}

ADMIN_USER=${ADMIN_USER}
ADMIN_PASS=${ADMIN_PASS}
ADMIN_SECRET_PATH=${ADMIN_SECRET_PATH}
GATEWAY_CONTAINER=subscribe-gateway
EOF

echo
echo ".env written."
echo "Starting containers..."
if [ "${LOCAL_BUILD}" = "1" ]; then
    docker compose up -d --build --remove-orphans
else
    docker compose pull
    docker compose up -d --remove-orphans
fi

cat > DEPLOY_INFO.txt <<EOF
SubSieve reverse-proxy mode
Generated at: $(date '+%Y-%m-%d %H:%M:%S')

Gateway:
  Local URL: http://${GATEWAY_BIND}:${GATEWAY_PORT}${SUBSCRIBE_PATH}
  Upstream:  ${V2B_BACKEND}

Admin:
  Local URL: http://${ADMIN_BIND}:${ADMIN_PORT}/${ADMIN_SECRET_PATH}
  Username:  ${ADMIN_USER}
  Password:  ${ADMIN_PASS}

Public HTTPS and certificates should be handled by your host reverse proxy.
EOF

cat DEPLOY_INFO.txt
