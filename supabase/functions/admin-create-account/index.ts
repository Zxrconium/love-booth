// Lets the site owner manually provision a coin-loaded account for someone
// who paid through an outside channel (social-media DM, etc), instead of
// the old self-serve Lemon Squeezy checkout. Two actions, both gated on the
// caller being the site owner's own account:
//   { action: 'create', email, password, coins } -> creates the auth user
//     (auto-confirmed, so the temporary password works immediately),
//     sets their starting coin balance, and records it in
//     admin_created_accounts so the admin panel can list it later.
//   { action: 'list' } -> returns the accounts created this way, with
//     their current coin balance, for the admin panel's list view.
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
    const { data, error } = await admin
      .from('admin_created_accounts')
      .select('user_id, email, profiles:user_id(coins)')
      .order('created_at', { ascending: false });
    if (error) {
      console.error('admin-create-account: list error', error);
      return json({ error: 'could not load accounts' }, 500);
    }
    const accounts = (data ?? []).map((row: any) => ({
      email: row.email,
      coins: row.profiles?.coins ?? 0,
    }));
    return json({ accounts });
  }

  if (payload?.action === 'create') {
    const email = String(payload?.email ?? '').trim();
    const password = String(payload?.password ?? '');
    const coins = Number(payload?.coins);

    if (!email || !password) return json({ error: 'email and password are required' }, 400);
    if (!Number.isInteger(coins) || coins < 0) return json({ error: 'coins must be a non-negative integer' }, 400);

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
      return json({ error: 'account created, but setting the starting balance failed' }, 500);
    }

    const { error: trackError } = await admin
      .from('admin_created_accounts')
      .insert({ user_id: userId, email });
    if (trackError) {
      console.error('admin-create-account: tracking insert failed', trackError);
      // Not fatal to the caller — the account exists and is funded, it just
      // won't show up in the admin list view.
    }

    return json({ user: { id: userId, email } });
  }

  return json({ error: 'unknown action' }, 400);
});
