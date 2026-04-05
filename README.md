# iLand Backend (0.0.86)

Minimal Bun + TypeScript backend for current 0.0.86 slices:

- Poll summaries/details
- Vote submission
- Draft poll create/edit/publish
- Provisional user bootstrap

## 1. Local Run (Hosted Supabase)

1. Install dependencies:

```bash
bun install
```

2. Configure env:

```bash
cp .env.example .env
```

Set at least:

- `SUPABASE_URL`
- `SUPABASE_SERVICE_ROLE_KEY`
- `SUPABASE_PROJECT_REF` (used by Supabase CLI)

3. Apply migrations to hosted Supabase:

```bash
supabase link --project-ref <YOUR_PROJECT_REF>
supabase db push
```

4. Start backend:

```bash
bun run dev
```

Server default: `0.0.0.0:3001`

## 2. Backend Smoke Checks

```bash
curl http://127.0.0.1:3001/health
curl http://127.0.0.1:3001/health/db
```

Bootstrap a provisional user:

```bash
curl -X POST http://127.0.0.1:3001/users/bootstrap
```

## 3. Endpoints In Current Slice

- `GET /health`
- `GET /health/db`
- `POST /users/bootstrap`
- `GET /polls`
- `GET /polls/:id`
- `POST /polls/:id/votes`
- `POST /polls/drafts`
- `GET /polls/drafts/:id`
- `PATCH /polls/drafts/:id`
- `GET /polls/drafts/:id/can-edit`
- `POST /polls/drafts/:id/publish`

## 4. App Integration Flags (Expo)

Set these before running the app:

- `EXPO_PUBLIC_ENABLE_BACKEND_POLL_VOTE_SLICE=true`
- `EXPO_PUBLIC_ENABLE_BACKEND_POLL_DRAFT_SLICE=true`
- `EXPO_PUBLIC_BACKEND_BASE_URL=http://<backend-host>:3001`

Notes:

- iOS simulator can usually use `http://127.0.0.1:3001`.
- Android emulator typically uses `http://10.0.2.2:3001`.
- Physical devices must use your machine LAN IP.

## 5. Temporary Viewer/Auth Bridge (Current)

- App now bootstraps a provisional backend user and stores that backend user id locally.
- Viewer-scoped backend requests use that stored id in the temporary dev header (`x-dev-viewer-id` by default).
- No client `userId` is sent in request payloads.
- This bridge is intentionally temporary until real auth/session is attached.

## 6. Minimal Test Data Path

You can test from app without seed systems:

1. Start app once (this triggers backend user bootstrap).
2. Use app poll creation flow to create/publish a poll.
3. Open poll details and submit a vote.

Optional SQL helper for fast setup:

- `supabase/dev/001_minimal_e2e_test_data.sql`

This script:

- Attaches a minimal home area to latest user
- Creates one active global poll with two options

## 7. Practical E2E From App (Immediate)

With backend running and app flags set, you can immediately test:

- Poll list loading (`GET /polls`)
- Poll details (`GET /polls/:id`)
- Draft create/edit/publish (`/polls/drafts*`)
- Vote submission (`POST /polls/:id/votes`)
- Provisional user bootstrap (`POST /users/bootstrap`)

## Notes

- No demo/seed records are auto-inserted by backend code.
- `/health/db` returns `not_configured` when Supabase env vars are missing.
- Restricted poll voting may require identity/home location data depending on poll rules.
