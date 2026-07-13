-- Luv Booth — coin balance + session recap schema
-- Run this once in the Supabase SQL editor (Project → SQL Editor → New query).
-- Safe to re-run: the guards below (`if not exists`, `on conflict do nothing`)
-- mean running it twice won't error or duplicate anything.

-- ---------------------------------------------------------------------------
-- 1. Coin balance, one row per auth user
-- ---------------------------------------------------------------------------
create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  coins integer not null default 0 check (coins >= 0),
  created_at timestamptz not null default now()
);

alter table public.profiles enable row level security;

drop policy if exists "profiles_select_own" on public.profiles;
create policy "profiles_select_own"
  on public.profiles for select
  using (auth.uid() = id);

-- No client-side update policy on purpose: coin balances only ever change
-- through the spend_coin()/credit_coins() functions below (SECURITY DEFINER),
-- never through a direct client UPDATE, so a compromised client can't just
-- set its own balance to 9999.

-- Auto-create a profile (0 coins) the moment someone signs up.
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer set search_path = public
as $$
begin
  insert into public.profiles (id, coins) values (new.id, 0)
  on conflict (id) do nothing;
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute procedure public.handle_new_user();

-- Atomic spend: only succeeds if balance > 0. Returns the new balance,
-- or NULL if the user had no coins (caller should show "you're out of coins").
create or replace function public.spend_coin()
returns integer
language plpgsql
security definer set search_path = public
as $$
declare
  new_balance integer;
begin
  update public.profiles
    set coins = coins - 1
    where id = auth.uid() and coins > 0
  returning coins into new_balance;
  return new_balance;
end;
$$;

grant execute on function public.spend_coin() to authenticated;

-- Atomic credit: intended to be called ONLY by the Lemon Squeezy webhook
-- (Netlify Function, using the service_role key), never from client code —
-- that's why authenticated/anon are explicitly denied execute below.
create or replace function public.credit_coins(target_user uuid, amount integer)
returns integer
language plpgsql
security definer set search_path = public
as $$
declare
  new_balance integer;
begin
  update public.profiles
    set coins = coins + amount
    where id = target_user
  returning coins into new_balance;
  return new_balance;
end;
$$;

revoke execute on function public.credit_coins(uuid, integer) from public, anon, authenticated;
-- service_role bypasses grants entirely, so no explicit grant is needed for the webhook.

-- ---------------------------------------------------------------------------
-- 2. Session recap recordings
-- ---------------------------------------------------------------------------
create table if not exists public.recordings (
  id uuid primary key default gen_random_uuid(),
  room_code text not null,
  storage_path text not null,
  created_at timestamptz not null default now(),
  expires_at timestamptz not null default (now() + interval '7 days')
);

alter table public.recordings enable row level security;

-- The recording's id is effectively the access control (like an unlisted
-- YouTube link, shared via the QR code) rather than per-user ownership, so
-- reads are open — the app checks expires_at client-side before offering
-- playback. Anyone who has the id (from the QR/link) can look up its path.
drop policy if exists "recordings_select_any" on public.recordings;
create policy "recordings_select_any"
  on public.recordings for select
  using (true);

drop policy if exists "recordings_insert_authenticated" on public.recordings;
create policy "recordings_insert_authenticated"
  on public.recordings for insert
  to authenticated
  with check (true);

-- ---------------------------------------------------------------------------
-- 3. Storage bucket for the recap video files
-- ---------------------------------------------------------------------------
-- Public bucket + unguessable random (UUID) file names, rather than signed
-- URLs: recap clips are meant to be casually shareable via the QR code to
-- someone who never logs in at all, and a public bucket gives a permanent
-- static URL with no need to mint/refresh a signed URL on every view.
-- "Expiration" is enforced by the app (checking recordings.expires_at
-- before offering playback), not by Storage itself — the file can be swept
-- up later by a scheduled cleanup job if you want actual deletion too.
insert into storage.buckets (id, name, public)
values ('session-recaps', 'session-recaps', true)
on conflict (id) do nothing;

drop policy if exists "session_recaps_public_read" on storage.objects;
create policy "session_recaps_public_read"
  on storage.objects for select
  using (bucket_id = 'session-recaps');

drop policy if exists "session_recaps_authenticated_upload" on storage.objects;
create policy "session_recaps_authenticated_upload"
  on storage.objects for insert
  to authenticated
  with check (bucket_id = 'session-recaps');
