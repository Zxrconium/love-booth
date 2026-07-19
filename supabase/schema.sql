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
  created_at timestamptz not null default now(),
  -- Tracks the most recent spend_coin() call so refund_last_spend() can
  -- safely give back a coin if the room creation it paid for never got off
  -- the ground (camera denied, left before any photo) — see that function
  -- below for the abuse-resistant refund window.
  last_spend_at timestamptz,
  last_spend_refunded boolean not null default true
);

-- Safe to re-run against an already-deployed profiles table too (create
-- table if not exists skips the columns above if the table already exists).
alter table public.profiles add column if not exists last_spend_at timestamptz;
alter table public.profiles add column if not exists last_spend_refunded boolean not null default true;

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
-- Also stamps last_spend_at and clears last_spend_refunded, opening a
-- one-shot refund window for refund_last_spend() below.
create or replace function public.spend_coin()
returns integer
language plpgsql
security definer set search_path = public
as $$
declare
  new_balance integer;
begin
  update public.profiles
    set coins = coins - 1, last_spend_at = now(), last_spend_refunded = false
    where id = auth.uid() and coins > 0
  returning coins into new_balance;
  return new_balance;
end;
$$;

grant execute on function public.spend_coin() to authenticated;

-- Gives back the most recent spend, but only if: (a) it hasn't already been
-- refunded (one-shot — flips last_spend_refunded to true so this can't be
-- called twice for the same spend), and (b) it happened within the last 10
-- minutes (caps how long a room-creation stays "refundable", so this can't
-- be used to farm coins on old spends). Returns the new balance, or NULL if
-- there was no eligible un-refunded recent spend (safe no-op).
create or replace function public.refund_last_spend()
returns integer
language plpgsql
security definer set search_path = public
as $$
declare
  new_balance integer;
begin
  update public.profiles
    set coins = coins + 1, last_spend_refunded = true
    where id = auth.uid()
      and last_spend_refunded = false
      and last_spend_at > now() - interval '10 minutes'
  returning coins into new_balance;
  return new_balance;
end;
$$;

grant execute on function public.refund_last_spend() to authenticated;

-- Atomic, idempotent credit: intended to be called ONLY by the Lemon
-- Squeezy webhook (Supabase Edge Function, using the service_role key),
-- never from client code — that's why authenticated/anon are explicitly
-- denied execute below.
--
-- Takes the Lemon Squeezy order id and records it in processed_ls_orders
-- inside the same transaction as the credit, so a retried webhook delivery
-- for an order we've already credited is a safe no-op (the insert conflicts
-- and the exception branch just returns the current balance) rather than
-- double-crediting.
create table if not exists public.processed_ls_orders (
  order_id text primary key,
  created_at timestamptz not null default now()
);

alter table public.processed_ls_orders enable row level security;
-- No policies at all: only service_role (which bypasses RLS entirely) ever
-- touches this table, via credit_coins_for_order() below.

create or replace function public.credit_coins_for_order(p_order_id text, p_user uuid, p_amount integer)
returns integer
language plpgsql
security definer set search_path = public
as $$
declare
  new_balance integer;
begin
  insert into public.processed_ls_orders (order_id) values (p_order_id);
  update public.profiles
    set coins = coins + p_amount
    where id = p_user
  returning coins into new_balance;
  return new_balance;
exception
  when unique_violation then
    select coins into new_balance from public.profiles where id = p_user;
    return new_balance;
end;
$$;

revoke execute on function public.credit_coins_for_order(text, uuid, integer) from public, anon, authenticated;
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
-- Expiration is enforced for real: the daily cron job below (section 4)
-- deletes both the storage object and its row once expires_at has passed,
-- so the link actually goes dead rather than just being hidden by the app.
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

-- ---------------------------------------------------------------------------
-- 4. Scheduled cleanup — actually delete expired recap files, not just stop
--    offering playback, so free-tier storage doesn't quietly fill up.
-- ---------------------------------------------------------------------------
create extension if not exists pg_cron with schema extensions;
-- If this errors with a permissions message, enable "pg_cron" from the
-- Supabase dashboard under Database → Extensions instead, then re-run just
-- the block below.

create or replace function public.cleanup_expired_recordings()
returns void
language plpgsql
security definer set search_path = public
as $$
begin
  delete from storage.objects
    where bucket_id = 'session-recaps'
      and name in (select storage_path from public.recordings where expires_at < now());

  delete from public.recordings where expires_at < now();
end;
$$;

select cron.schedule(
  'cleanup-expired-recordings',
  '0 3 * * *', -- once a day at 03:00 UTC
  $$select public.cleanup_expired_recordings();$$
)
where not exists (select 1 from cron.job where jobname = 'cleanup-expired-recordings');
