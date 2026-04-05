# Supabase CLI Ownership

This folder anchors Supabase CLI project ownership for the backend.

Expected usage:

- `supabase start` (optional local stack)
- `supabase db diff`
- `supabase migration new <name>`
- `supabase db push`

For hosted Supabase, keep schema changes in `supabase/migrations` and run migrations against the hosted project via CLI auth/project link.
