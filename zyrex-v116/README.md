# ZYREX V113 — Security & Reliability

V113 builds on V111 with a security/reliability layer while keeping BuatQris, PostgreSQL, PWA, analytics, community and store features.

## Added
- Request IDs (`X-Request-ID`) for tracing.
- Hardened security headers and production HSTS.
- Admin login rate limiting + temporary lockout after repeated failures.
- Revocable admin sessions with 8-hour expiry.
- Admin logout and logout-all endpoints.
- Webhook replay protection using event IDs or payload hashes.
- Expired-session/password-reset cleanup worker.
- Graceful SIGTERM/SIGINT shutdown with database close.
- Password-reset tokens are no longer exposed by default; set `RESET_DEV_MODE=true` only for local development.
- Schema/state version: V113 / schema 5.

## Secrets
Keep `ADMIN_PASSWORD`, `SESSION_SECRET`, BuatQris secrets and `DATABASE_URL` in the hosting environment. Never commit them to GitHub.

## V113 Payment 2.0
- Idempotency-Key required for QRIS creation to prevent duplicate create requests.
- Payment audit ledger and admin payment monitoring endpoints.
- Admin reconciliation endpoint checks pending BuatQris transactions.
- Payment retry endpoint for expired/failed attempts.
- Automatic local expiry sweep for stale pending QRIS attempts.
- Payment status updates are idempotent and avoid duplicate success notifications.

## V115 — Store 2.0
- Product variants with independent stock and price deltas
- Inventory reservation with 20-minute expiry and release/consume lifecycle
- Inventory movement audit records
- Promo usage limits, per-user limits, minimum subtotal, and start/end windows
- Scheduled products and publish/unpublish visibility
- Featured products
- Admin endpoints for variant and inventory management
- Order records now retain variant, quantity, subtotal, discount, and reservation data


## V115 — Analytics 2.0
- Admin date-range analytics (up to 365 days)
- Revenue, AOV, paid orders, unique/repeat customers
- New-user activity/retention signal
- Traffic and checkout metrics
- Game engagement by game
- Daily revenue/order/visit series
- CSV analytics export

Analytics endpoint: `/api/admin/analytics?from=YYYY-MM-DD&to=YYYY-MM-DD`
