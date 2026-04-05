# iLand Backend Skeleton (0.0.86)

Minimal Bun + TypeScript backend skeleton aligned to the frozen 0.0.86 app/mock seam.

## Run

1. Install dependencies:

   ```bash
   bun install
   ```

2. Copy env template:

   ```bash
   cp .env.example .env
   ```

3. Start dev server:

   ```bash
   bun run dev
   ```

## Endpoints

- `GET /health`
- `GET /health/db` (Supabase admin API connectivity check when configured)

## Notes

- Server listens on `HOST`/`PORT` (defaults: `0.0.0.0:3001`).
- Supabase is optional for startup; `/health/db` reports `not_configured` until `SUPABASE_URL` and `SUPABASE_SERVICE_ROLE_KEY` are set.
