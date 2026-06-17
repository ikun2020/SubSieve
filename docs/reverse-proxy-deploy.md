# Reverse Proxy Deployment

This mode runs SubSieve only on localhost and lets your host web server handle
domains, HTTPS certificates, and public ports.

## Runtime Ports

- Gateway: `127.0.0.1:3333`
- Admin: `127.0.0.1:3334`
- Default subscription path: `/s`

The containers do not bind host ports `80` or `443`, and they do not require
`ssl/cert.pem` or `ssl/key.pem`.

## Server Environment

Create `sgw/.env` manually or let GitHub Actions create it:

```env
V2B_BACKEND=https://upstream.example.com
V2B_HOST=upstream.example.com
SUBSCRIBE_PATH=/s

GATEWAY_BIND=127.0.0.1
GATEWAY_PORT=3333
ADMIN_BIND=127.0.0.1
ADMIN_PORT=3334

ADMIN_USER=admin
ADMIN_PASS=change-this-password
ADMIN_SECRET_PATH=change-this-secret-path
GATEWAY_CONTAINER=subscribe-gateway
```

Start or update:

```bash
cd SubSieve/sgw
docker compose up -d --build
```

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

## GitHub Actions Secrets

Required:

- `DEPLOY_HOST`
- `DEPLOY_USER`
- `DEPLOY_SSH_KEY`
- `V2B_BACKEND`
- `V2B_HOST`
- `ADMIN_PASS`
- `ADMIN_SECRET_PATH`

Optional:

- `DEPLOY_PORT` defaults to `22`
- `DEPLOY_PATH` defaults to `~/SubSieve`
- `SUBSCRIBE_PATH` defaults to `/s`
- `GATEWAY_BIND` defaults to `127.0.0.1`
- `GATEWAY_PORT` defaults to `3333`
- `ADMIN_BIND` defaults to `127.0.0.1`
- `ADMIN_PORT` defaults to `3334`
- `ADMIN_USER` defaults to `admin`

