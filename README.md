# Node Uptime Monitor (for Pterodactyl)

This is the Node.js migration project for running on low-cost or free Pterodactyl servers.

## Stack

- Node.js + Express
- SQLite (better-sqlite3)
- node-cron scheduler
- JWT auth

## Quick Start

```bash
npm install
npm run dev
```

Production start:

```bash
npm start
```

Server starts on `http://localhost:3000`.

Port behavior (Pterodactyl-friendly single-port mode):

- Port env priority: `PORT` -> `SERVER_PORT` -> `PRIMARY_PORT` -> `PTERODACTYL_PORT`.
- If any of the above is set, server listens on that env port.
- Otherwise uses config `server.port` (default `3000`).
- Optional modules are mounted by path under the same port.

- Public status page: `/status`
- Admin login: `/login`
- Admin panel: `/admin`

## Entrypoint

- Root entry file: `index.js`
- Runs directly with Node, no compile step required

## Encrypted Config File

- Path: `data/monitor.dat`
- Format: AES-256-GCM encrypted JSON
- All runtime config values are managed from admin page (`/admin`) and written to this file
- No environment variables are required for runtime settings

## API

- `GET /health`
- `POST /api/auth/login`
- `POST /api/auth/change-password`
- `GET /api/public/status`
- `GET /api/admin/monitors`
- `POST /api/admin/monitors`
- `PUT /api/admin/monitors/:id`
- `DELETE /api/admin/monitors/:id`
- `POST /api/admin/monitors/:id/check-now`
- `POST /api/admin/test-webhook`
- `GET /api/admin/checks?monitor_id=...`
- `GET /api/admin/stats?monitor_id=...`
- `GET /api/admin/config`
- `PUT /api/admin/config`

## Notes

- Scheduler runs every minute and respects each monitor's `check_interval`.
- Supports two interval modes: fixed (`5`) and random range (`5-10`).
- Supports monitor types: HTTP, TCP, and HTTPS certificate expiry checks.
- Included a basic web UI for status display and admin management in `web/`.
- Built-in in-memory rate limiting is enabled for auth/public/admin APIs.
- Concurrency and defaults are read from encrypted config.
- Alerting now supports consecutive failure/recovery thresholds, cooldown windows, and webhook retry with backoff.
- Each down check stores a classified `failure_reason` for troubleshooting and aggregated stats.
- Old check history is cleaned automatically by scheduler based on `monitoring.checkHistoryDays`.

## Optional binary module (admin panel)

Binary settings are managed in Admin panel -> `System Config`:

- Binary download URL (optional, executable binary URL)
- Binary path prefix (default `/app`)
- Binary target port (default `31000`)
- Auto start on server boot

Path split mode:

- Main app proxies configured binary path to `127.0.0.1:<targetPort>`.
- Start/Stop/Status are available from admin panel without editing environment variables.

## Docker image

- Dockerfile is in `Dockerfile`.
- GitHub Actions workflow `.github/workflows/pulsewatch-image.yml` builds and pushes `linux/amd64` and `linux/arm64` images to GHCR.
- Published image path: `ghcr.io/debbide/pulsewatch`.
