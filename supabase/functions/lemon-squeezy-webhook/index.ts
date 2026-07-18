// Receives Lemon Squeezy's order webhook and credits the purchasing user's
// coin balance via the credit_coins_for_order() RPC (SECURITY DEFINER;
// service_role — which this function has automatic access to — bypasses
// the grant restrictions that block anon/authenticated from calling it).
//
// Deploy:
//   supabase functions deploy lemon-squeezy-webhook --project-ref psstxmiwxosjtywxpvdz --no-verify-jwt
//
// --no-verify-jwt is required: Supabase Edge Functions require a Supabase
// JWT in the Authorization header by default, but Lemon Squeezy will never
// send one — it authenticates via the X-Signature header instead, which we
// verify ourselves below. Without this flag every real delivery would get
// rejected with 401 "Missing authorization header" before this code even runs.
//
// Then, once you've created the webhook in the Lemon Squeezy dashboard and
// have its signing secret:
//   supabase secrets set LEMON_SQUEEZY_WEBHOOK_SECRET=whsec_xxx --project-ref psstxmiwxosjtywxpvdz
//
// NOTE ON ACCURACY: the payload shape assumed below (meta.event_name,
// meta.custom_data.user_id, data.attributes.status, data.attributes.
// first_order_item.product_id) reflects Lemon Squeezy's documented webhook
// format. This has not been exercised against a real delivery — this
// sandbox can't reach Lemon Squeezy's API or dashboard to confirm. Log and
// check the first real payload before fully trusting this in production.

import { createClient } from 'npm:@supabase/supabase-js@2';

const WEBHOOK_SECRET = Deno.env.get('LEMON_SQUEEZY_WEBHOOK_SECRET');
const SUPABASE_URL = Deno.env.get('SUPABASE_URL')!;
const SERVICE_ROLE_KEY = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;

// Maps Lemon Squeezy PRODUCT id -> coins to credit. Real product ids, one
// coin pack per product (each assumed to have exactly one variant).
const PRODUCT_COINS: Record<string, number> = {
  '1219540': 1,
  '1219541': 3,
  '1219545': 5,
};

async function verifySignature(rawBody: string, signatureHeader: string | null): Promise<boolean> {
  if (!WEBHOOK_SECRET || !signatureHeader) return false;
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(WEBHOOK_SECRET),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const sigBytes = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(rawBody));
  const digestHex = Array.from(new Uint8Array(sigBytes)).map((b) => b.toString(16).padStart(2, '0')).join('');
  if (digestHex.length !== signatureHeader.length) return false;
  let diff = 0;
  for (let i = 0; i < digestHex.length; i++) diff |= digestHex.charCodeAt(i) ^ signatureHeader.charCodeAt(i);
  return diff === 0;
}

Deno.serve(async (req) => {
  if (req.method !== 'POST') {
    return new Response('method not allowed', { status: 405 });
  }

  const rawBody = await req.text();
  const signature = req.headers.get('X-Signature') ?? req.headers.get('x-signature');

  if (!(await verifySignature(rawBody, signature))) {
    return new Response('invalid signature', { status: 401 });
  }

  let payload: any;
  try {
    payload = JSON.parse(rawBody);
  } catch {
    return new Response('bad json', { status: 400 });
  }

  // Acknowledge (200) anything we don't act on so Lemon Squeezy doesn't
  // keep retrying an event we're intentionally ignoring.
  if (payload?.meta?.event_name !== 'order_created') {
    return new Response('ignored', { status: 200 });
  }

  const status = payload?.data?.attributes?.status;
  const orderId = payload?.data?.id;
  const productId = String(payload?.data?.attributes?.first_order_item?.product_id ?? '');
  const userId = payload?.meta?.custom_data?.user_id;

  if (status !== 'paid' || !orderId || !userId) {
    return new Response('ignored', { status: 200 });
  }

  const coins = PRODUCT_COINS[productId];
  if (!coins) {
    console.error(`lemon-squeezy-webhook: unrecognized product_id "${productId}", not crediting anything`);
    return new Response('ignored', { status: 200 });
  }

  const admin = createClient(SUPABASE_URL, SERVICE_ROLE_KEY);
  const { error } = await admin.rpc('credit_coins_for_order', {
    p_order_id: String(orderId),
    p_user: userId,
    p_amount: coins,
  });

  if (error) {
    console.error('lemon-squeezy-webhook: credit_coins_for_order error', error);
    return new Response('credit failed', { status: 500 });
  }

  return new Response('ok', { status: 200 });
});
