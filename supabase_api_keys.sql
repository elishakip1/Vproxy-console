-- Run once in the Supabase SQL editor before deploying the API.
alter table users add column if not exists api_key_hash text unique;
