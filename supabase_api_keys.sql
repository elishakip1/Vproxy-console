-- Run once in the Supabase SQL editor before deploying the API.
alter table users add column if not exists api_key_hash text unique;

-- API key details shown on the API page, and each user's own score limit for API checks.
alter table users add column if not exists api_key_hint text;
alter table users add column if not exists api_key_created_at timestamptz;
alter table users add column if not exists api_key_last_used timestamptz;
alter table users add column if not exists api_max_score integer check (api_max_score between 0 and 100);
alter table users add column if not exists api_stop_after integer check (api_stop_after between 0 and 100);
