# Reverse Proxy Deployment

This mode runs SubSieve only on localhost and lets your host web server handle
domains, HTTPS certificates, and public ports.

## Runtime Ports

- Gateway: `127.0.0.1:3333`
- Admin: `127.0.0.1:3334`
- Default subscription path: `/s`

The containers do not bind host ports `80` or `443`, and they do not require
`ssl/cert.pem` or `ssl/key.pem`.

## GitHub Actions Image Build

The `Build Docker Images` workflow only builds and publishes Docker images to
GitHub Container Registry. It does not SSH into your server and does not need
server IP addresses or private keys.

Published images:

- `ghcr.io/ikun2020/subsieve-gateway:latest`
- `ghcr.io/ikun2020/subsieve-admin:latest`
- `ghcr.io/ikun2020/subsieve-gateway:sha-xxxxxxx`
- `ghcr.io/ikun2020/subsieve-admin:sha-xxxxxxx`

The workflow uses the automatic `GITHUB_TOKEN` with `packages: write`
permission. No custom Actions secrets are required for building images.

## Server Environment

Create `sgw/.env` manually or run `./setup.sh`:

```env
V2B_BACKEND=https://upstream.example.com
V2B_HOST=upstream.example.com
SUBSCRIBE_PATH=/s

GATEWAY_IMAGE=ghcr.io/ikun2020/subsieve-gateway:latest
ADMIN_IMAGE=ghcr.io/ikun2020/subsieve-admin:latest
LOCAL_BUILD=0

GATEWAY_BIND=127.0.0.1
GATEWAY_PORT=3333
ADMIN_BIND=127.0.0.1
ADMIN_PORT=3334

ADMIN_USER=admin
ADMIN_PASS=change-this-password
ADMIN_SECRET_PATH=change-this-secret-path
GATEWAY_CONTAINER=subscribe-gateway
```

Start or update from published images:

```bash
cd SubSieve/sgw
docker compose pull
docker compose up -d
```

If you want to rebuild locally on the server instead of pulling published
images, set `LOCAL_BUILD=1` in `.env` and run:

```bash
docker compose up -d --build
```

If GHCR packages are private, either make the packages public in GitHub or log
in on the server before `docker compose pull`.

## Host Nginx Example

Point any number of public domains to the same local gateway:

```nginx
server {
    listen 443 ssl http2;
    server_name sub-a.example.com sub-b.example.com;

    ssl_certificate     /path/to/fullchain.pem;
    ssl_certificate_key /path/to/key.pem;

    location ^~ /s {
        proxy_pass http://127.0.0.1:3333;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location / {
        return 404;
    }
}
```

Admin should normally stay private. If you need to proxy it, restrict it by IP:

```nginx
location /admin-secret-path/ {
    allow 1.2.3.4;
    deny all;
    proxy_pass http://127.0.0.1:3334;
}
```
