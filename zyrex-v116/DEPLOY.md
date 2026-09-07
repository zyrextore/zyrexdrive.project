# ZYREX V111 Deploy

## Render
1. Create/connect a PostgreSQL database.
2. Set the web service environment variable `DATABASE_URL` to the database connection string.
3. Keep all payment/admin secrets in Render Environment Variables, never in GitHub.
4. Deploy with `npm install` and `npm start`.
5. Check `/api/health` and `/api/health/database`.

If `DATABASE_URL` is absent, ZYREX continues in JSON fallback mode. For production, PostgreSQL is recommended.

### V113 payment environment
Keep all BuatQris credentials server-side. Configure `BQ_ACCOUNT_ID`, `BQ_SECRET_TOKEN`, `BQ_WEBHOOK_SECRET`, `BQ_API_URL`, `BQ_QRIS_METHOD`, `BQ_FEE_BY`, and `BQ_MODE` in the hosting provider environment. Do not commit these values.

## V114 notes
Store 2.0 requires no new environment variables. Product variants, inventory reservations, promo limits, and scheduling are persisted through the existing PostgreSQL/JSON state layer.
