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
  last_spend_refunded boolean not null default true,
  -- Server-side record of whether the room that spend paid for actually
  -- produced a photo. The client also tracks this itself (photosStartedThisRoom)
  -- to decide when to *offer* a refund in the UI, but that's just a JS
  -- variable in a page anyone can open devtools on — mark_last_spend_used()
  -- below is the real enforcement, called the moment the first photo is
  -- captured, so refund_last_spend() can refuse a refund even if the client
  -- is lying about whether the room was used.
  last_spend_used boolean not null default false
);

-- Safe to re-run against an already-deployed profiles table too (create
-- table if not exists skips the columns above if the table already exists).
alter table public.profiles add column if not exists last_spend_at timestamptz;
alter table public.profiles add column if not exists last_spend_refunded boolean not null default true;
alter table public.profiles add column if not exists last_spend_used boolean not null default false;

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
    set coins = coins - 1, last_spend_at = now(), last_spend_refunded = false, last_spend_used = false
    where id = auth.uid() and coins > 0
  returning coins into new_balance;
  return new_balance;
end;
$$;

grant execute on function public.spend_coin() to authenticated;

-- Marks the current spend as "used" — called by the client the instant the
-- first photo of a room is captured. One-directional (never flips back to
-- false) and safe to call any number of times; the only thing that matters
-- is that it lands at least once before someone tries to claim a refund.
create or replace function public.mark_last_spend_used()
returns void
language plpgsql
security definer set search_path = public
as $$
begin
  update public.profiles set last_spend_used = true where id = auth.uid();
end;
$$;

grant execute on function public.mark_last_spend_used() to authenticated;

-- Gives back the most recent spend, but only if: (a) it hasn't already been
-- refunded (one-shot — flips last_spend_refunded to true so this can't be
-- called twice for the same spend), (b) it happened within the last 10
-- minutes (caps how long a room-creation stays "refundable", so this can't
-- be used to farm coins on old spends), and (c) mark_last_spend_used() was
-- never called for it — i.e. the room never actually produced a photo.
-- (c) is what stops someone from fully using a paid room and then refunding
-- it anyway by just lying to the client about whether photos were taken —
-- the client's own "should I offer a refund" check (photosStartedThisRoom)
-- is only a JS variable, so it can't be trusted as the sole gate here.
-- Returns the new balance, or NULL if there was no eligible refund.
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
      and last_spend_used = false
      and last_spend_at > now() - interval '10 minutes'
  returning coins into new_balance;
  return new_balance;
end;
$$;

grant execute on function public.refund_last_spend() to authenticated;

-- Manual coin provisioning: coins are no longer sold through a self-serve
-- checkout. Instead, the admin-create-account Edge Function (service_role,
-- gated on the site owner's own authenticated session) creates accounts
-- with a starting coin balance already loaded, and records them here so
-- the admin panel can list "accounts I've created" without exposing the
-- full user base. No client-facing policies on purpose: only the Edge
-- Function (service_role, bypasses RLS) ever reads or writes this table.
--
-- The `email` column holds the customer-facing USERNAME, not a real email —
-- customer accounts are created and logged into by username only, with a
-- synthetic @luvbooth.local address used behind the scenes purely to
-- satisfy Supabase Auth (see the Edge Function). Kept as `email` rather
-- than renamed to avoid an unnecessary migration on an already-deployed
-- table; the column's contents (a short username) are unaffected either way.
create table if not exists public.admin_created_accounts (
  user_id uuid primary key references auth.users(id) on delete cascade,
  email text not null,
  created_at timestamptz not null default now()
);

alter table public.admin_created_accounts enable row level security;

-- Admin-only atomic top-up for an existing account's balance. Only ever
-- called from the admin-create-account Edge Function's 'add_coins' action
-- via the service-role client (never granted to authenticated/anon), same
-- trust boundary as account creation above. Mirrors the spend_coin() /
-- refund_last_spend() pattern: a single atomic UPDATE rather than a
-- read-then-write, so two top-ups landing at once can't clobber each other.
create or replace function public.admin_add_coins(target_user_id uuid, amount integer)
returns integer
language plpgsql
security definer set search_path = public
as $$
declare
  new_balance integer;
begin
  update public.profiles
    set coins = coins + amount
    where id = target_user_id
  returning coins into new_balance;
  return new_balance;
end;
$$;

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
