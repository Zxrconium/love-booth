// Lets the site owner manually provision a coin-loaded account for someone
// who paid through an outside channel (social-media DM, etc), instead of
// the old self-serve Lemon Squeezy checkout. Three actions, all gated on the
// caller being the site owner's own account:
//   { action: 'create', username, password, coins } -> creates the auth
//     user under a synthetic internal email (customers only ever see/use
//     the username — see SYNTHETIC_EMAIL_DOMAIN below), auto-confirmed so
//     the temporary password works immediately, sets their starting coin
//     balance, and records the username in admin_created_accounts so the
//     admin panel can list it later.
//   { action: 'list' } -> returns the accounts created this way, with
//     their current coin balance, for the admin panel's list view.
//   { action: 'add_coins', user_id, amount } -> tops up an existing
//     account's balance by `amount` (adds to, never overwrites).
//
// Deploy WITHOUT --no-verify-jwt (unlike the old webhook): the caller here
// really is a logged-in Supabase user, so Supabase's platform-level JWT
// check is a free first layer of defense. On top of that, this function
// independently re-verifies the caller's own session server-side (via
// admin.auth.getUser(jwt)) and compares their email against ADMIN_EMAIL —
// never trusting a client-supplied "I am the admin" claim.
//   supabase functions deploy admin-create-account --project-ref psstxmiwxosjtywxpvdz
//
// Needs the service-role key available as a secret (same secure handling
// as the old webhook secret — never in client code or the repo):
//   supabase secrets set SUPABASE_SERVICE_ROLE_KEY=xxx --project-ref psstxmiwxosjtywxpvdz
// (SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are provided automatically
// in the Edge Function runtime on Supabase's platform — no manual secrets
// step is actually required for those two, but documented here for clarity.)

import { createClient } from 'npm:@supabase/supabase-js@2';

const SUPABASE_URL = Deno.env.get('SUPABASE_URL')!;
const SERVICE_ROLE_KEY = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;
const ADMIN_EMAIL = 'zhanderjhan14@gmail.com';

// Customer accounts are created and logged into by username only — Supabase
// Auth still requires some email under the hood, so a fixed, unreachable
// domain turns "alice" into "alice@luvbooth.local" for auth purposes only;
// the admin and the customer never see this address. Must stay in sync with
// SYNTHETIC_ACCOUNT_DOMAIN in index.html (client-side login resolves the
// same suffix before calling signInWithPassword directly).
const SYNTHETIC_EMAIL_DOMAIN = 'luvbooth.local';
const USERNAME_PATTERN = /^[A-Za-z0-9._-]+$/;

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
};

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' },
  });
}

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response(null, { headers: CORS_HEADERS });
  if (req.method !== 'POST') return json({ error: 'method not allowed' }, 405);

  const admin = createClient(SUPABASE_URL, SERVICE_ROLE_KEY);

  // Re-verify the caller ourselves rather than trusting anything the
  // client claims — Supabase already checked the JWT is valid before this
  // code runs, but we still independently resolve it to a user + email.
  const authHeader = req.headers.get('Authorization') ?? '';
  const jwt = authHeader.replace(/^Bearer\s+/i, '');
  if (!jwt) return json({ error: 'not authorized' }, 401);

  const { data: callerData, error: callerError } = await admin.auth.getUser(jwt);
  if (callerError || !callerData?.user || callerData.user.email !== ADMIN_EMAIL) {
    return json({ error: 'not authorized' }, 403);
  }

  let payload: any;
  try {
    payload = await req.json();
  } catch {
    return json({ error: 'bad json' }, 400);
  }

  if (payload?.action === 'list') {
    // The email column here holds the customer-facing username (not the
    // synthetic @luvbooth.local address) — see the 'create' branch below.
    const { data: rows, error: rowsError } = await admin
      .from('admin_created_accounts')
      .select('user_id, email')
      .order('created_at', { ascending: false });
    if (rowsError) {
      console.error('admin-create-account: list error', rowsError);
      return json({ error: 'could not load accounts' }, 500);
    }

    // admin_created_accounts and profiles both reference auth.users
    // independently (no FK between the two of them), so PostgREST can't
    // auto-embed profiles:user_id(coins) here — it fails with "could not
    // find a relationship" instead of silently working. Look up balances
    // as a separate query and merge in JS.
    const userIds = (rows ?? []).map((row: any) => row.user_id);
    let coinsById: Record<string, number> = {};
    if (userIds.length) {
      const { data: profileRows, error: profilesError } = await admin
        .from('profiles')
        .select('id, coins')
        .in('id', userIds);
      if (profilesError) {
        console.error('admin-create-account: list coins lookup error', profilesError);
        return json({ error: 'could not load account balances' }, 500);
      }
      for (const p of profileRows ?? []) coinsById[p.id] = p.coins;
    }

    const accounts = (rows ?? []).map((row: any) => ({
      user_id: row.user_id,
      username: row.email,
      coins: coinsById[row.user_id] ?? 0,
    }));
    return json({ accounts });
  }

  if (payload?.action === 'create') {
    const username = String(payload?.username ?? '').trim();
    const password = String(payload?.password ?? '');
    const coins = Number(payload?.coins);

    if (!username || !password) return json({ error: 'username and password are required' }, 400);
    if (!USERNAME_PATTERN.test(username)) {
      return json({ error: 'usernames can only contain letters, numbers, dots, underscores, and hyphens' }, 400);
    }
    if (!Number.isInteger(coins) || coins < 0) return json({ error: 'coins must be a non-negative integer' }, 400);

    const email = `${username}@${SYNTHETIC_EMAIL_DOMAIN}`;
    const { data: created, error: createError } = await admin.auth.admin.createUser({
      email,
      password,
      email_confirm: true,
    });
    if (createError || !created?.user) {
      console.error('admin-create-account: createUser error', createError);
      return json({ error: (createError && createError.message) || 'could not create account' }, 500);
    }

    const userId = created.user.id;

    // handle_new_user's trigger already inserted a profiles row at 0 coins
    // by the time createUser() resolves — set the requested starting balance.
    const { error: coinsError } = await admin.from('profiles').update({ coins }).eq('id', userId);
    if (coinsError) {
      console.error('admin-create-account: setting starting coins failed', coinsError);
      return json({ error: `account created, but setting the starting balance failed: ${coinsError.message}` }, 500);
    }

    // Store the username (not the synthetic email) so the admin panel's
    // list view shows the same thing the admin typed in.
    const { error: trackError } = await admin
      .from('admin_created_accounts')
      .insert({ user_id: userId, email: username });
    if (trackError) {
      console.error('admin-create-account: tracking insert failed', trackError);
      // Not fatal to the caller — the account exists and is funded, so we
      // still report success — but silently dropping this previously made
      // "account created" and "never shows up in the list" indistinguishable
      // from the admin's side. Surface the real reason as a warning instead.
      return json({ user: { id: userId, username }, warning: `account created, but it won't show in your list yet: ${trackError.message}` });
    }

    return json({ user: { id: userId, username } });
  }

  if (payload?.action === 'add_coins') {
    const userId = String(payload?.user_id ?? '').trim();
    const amount = Number(payload?.amount);

    if (!userId) return json({ error: 'user_id is required' }, 400);
    if (!Number.isInteger(amount) || amount <= 0) {
      return json({ error: 'amount must be a positive whole number' }, 400);
    }

    // Atomic add (not a read-then-write) via the same SECURITY DEFINER
    // pattern as spend_coin()/refund_last_spend() in schema.sql — safe
    // against two top-ups landing at the same instant.
    const { data: newBalance, error: addError } = await admin.rpc('admin_add_coins', {
      target_user_id: userId,
      amount,
    });
    if (addError) {
      console.error('admin-create-account: add_coins failed', addError);
      return json({ error: `could not add coins: ${addError.message}` }, 500);
    }
    return json({ coins: newBalance });
  }

  return json({ error: 'unknown action' }, 400);
});
