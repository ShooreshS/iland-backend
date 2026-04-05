# iLand Backend Skeleton (0.0.86)

Minimal Bun + TypeScript backend for the first real 0.0.86 poll/vote slice.

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
- `GET /health/db`
- `GET /polls`
- `GET /polls/:id`
- `POST /polls/:id/votes`

## Temporary Viewer Resolution (Dev-Only)

Viewer-scoped endpoints currently require a dev header (default: `x-dev-viewer-id`).

- No client body/query `userId` is accepted.
- Backend resolves viewer from request header only.
- This is intentionally temporary and isolated in `src/auth/requireViewer.ts`.

Example:

```bash
curl -H "x-dev-viewer-id: <user-uuid>" http://localhost:3001/polls
```

## Vote Submission Example

```bash
curl -X POST \
  -H "content-type: application/json" \
  -H "x-dev-viewer-id: <user-uuid>" \
  -d '{"optionId":"<poll-option-uuid>"}' \
  http://localhost:3001/polls/<poll-uuid>/votes
```

## Migrations

Initial schema migration is in:

- `supabase/migrations/20260405021000_init_v086_poll_vote.sql`

Apply with Supabase CLI (after linking to hosted project):

```bash
supabase link --project-ref <YOUR_PROJECT_REF>
supabase db push
```

## Notes

- Server listens on `HOST`/`PORT` (default: `0.0.0.0:3001`).
- `/health/db` returns `not_configured` when Supabase env vars are missing.
- No seeded/demo records are inserted by backend code.
