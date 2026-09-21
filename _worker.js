// Cloudflare Pages Worker (`_worker.js`)
// AegisChat Secured Proxy to Supabase with Admin, Invite System & Web Push Notifications

// Base64URL Helpers
function base64UrlToUint8Array(base64UrlString) {
  const padding = '='.repeat((4 - base64UrlString.length % 4) % 4);
  const base64 = (base64UrlString + padding).replace(/-/g, '+').replace(/_/g, '/');
  const rawData = atob(base64);
  const outputArray = new Uint8Array(rawData.length);
  for (let i = 0; i < rawData.length; ++i) {
    outputArray[i] = rawData.charCodeAt(i);
  }
  return outputArray;
}

function uint8ArrayToBase64Url(uint8Array) {
  let binary = '';
  for (let i = 0; i < uint8Array.length; i++) {
    binary += String.fromCharCode(uint8Array[i]);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// VAPID & HKDF Cryptographic Helpers for Web Push (RFC 8291 / RFC 8292)
async function getVapidPrivateKey(privateKeyB64Url, publicKeyB64Url) {
  if (privateKeyB64Url.startsWith('{')) {
    const jwk = JSON.parse(privateKeyB64Url);
    return await crypto.subtle.importKey(
      'jwk',
      jwk,
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['sign']
    );
  }

  const dBytes = base64UrlToUint8Array(privateKeyB64Url);
  if (dBytes.length === 32) {
    let pubJwk = {};
    if (publicKeyB64Url) {
      const pubBytes = base64UrlToUint8Array(publicKeyB64Url);
      if (pubBytes.length === 65 && pubBytes[0] === 0x04) {
        pubJwk = {
          x: uint8ArrayToBase64Url(pubBytes.subarray(1, 33)),
          y: uint8ArrayToBase64Url(pubBytes.subarray(33, 65))
        };
      }
    }
    const jwk = {
      kty: 'EC',
      crv: 'P-256',
      d: uint8ArrayToBase64Url(dBytes),
      ...pubJwk
    };
    return await crypto.subtle.importKey(
      'jwk',
      jwk,
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['sign']
    );
  }

  return await crypto.subtle.importKey(
    'pkcs8',
    dBytes.buffer,
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['sign']
  );
}

async function createVapidJwt(audience, subject, privateKeyB64Url, publicKeyB64Url) {
  const header = { alg: 'ES256', typ: 'JWT' };
  const exp = Math.floor(Date.now() / 1000) + 12 * 3600; // 12h
  const payload = {
    aud: audience,
    exp: exp,
    sub: subject || 'mailto:admin@aegischat.internal'
  };

  const enc = new TextEncoder();
  const headerB64 = uint8ArrayToBase64Url(enc.encode(JSON.stringify(header)));
  const payloadB64 = uint8ArrayToBase64Url(enc.encode(JSON.stringify(payload)));
  const unsignedToken = `${headerB64}.${payloadB64}`;

  const cryptoKey = await getVapidPrivateKey(privateKeyB64Url, publicKeyB64Url);
  const signatureBuffer = await crypto.subtle.sign(
    { name: 'ECDSA', hash: { name: 'SHA-256' } },
    cryptoKey,
    enc.encode(unsignedToken)
  );

  const signatureB64 = uint8ArrayToBase64Url(new Uint8Array(signatureBuffer));
  return `${unsignedToken}.${signatureB64}`;
}

async function hkdfExtract(salt, ikm) {
  const hmacKey = await crypto.subtle.importKey(
    'raw',
    salt.byteLength > 0 ? salt : new Uint8Array(32),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  return new Uint8Array(await crypto.subtle.sign('HMAC', hmacKey, ikm));
}

async function hkdfExpand(prk, info, length) {
  const hmacKey = await crypto.subtle.importKey(
    'raw',
    prk,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const infoWithCounter = new Uint8Array(info.byteLength + 1);
  infoWithCounter.set(info, 0);
  infoWithCounter[info.byteLength] = 1;
  const result = await crypto.subtle.sign('HMAC', hmacKey, infoWithCounter);
  return new Uint8Array(result).subarray(0, length);
}

async function encryptWebPushPayload(subscriptionKeys, payloadText) {
  if (!subscriptionKeys || !subscriptionKeys.p256dh || !subscriptionKeys.auth) {
    return null;
  }

  const userPubKeyBytes = base64UrlToUint8Array(subscriptionKeys.p256dh);
  const userAuthBytes = base64UrlToUint8Array(subscriptionKeys.auth);

  const localKeyPair = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveBits']
  );

  const localPubKeyBuffer = await crypto.subtle.exportKey('raw', localKeyPair.publicKey);
  const localPubKeyBytes = new Uint8Array(localPubKeyBuffer);

  const userPubKey = await crypto.subtle.importKey(
    'raw',
    userPubKeyBytes,
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    []
  );

  const sharedSecretBits = await crypto.subtle.deriveBits(
    { name: 'ECDH', public: userPubKey },
    localKeyPair.privateKey,
    256
  );
  const sharedSecret = new Uint8Array(sharedSecretBits);

  const prkKey = await hkdfExtract(userAuthBytes, sharedSecret);

  const enc = new TextEncoder();
  const webPushInfoLabel = enc.encode("WebPush: info\0");
  const infoKey = new Uint8Array(webPushInfoLabel.length + userPubKeyBytes.length + localPubKeyBytes.length);
  infoKey.set(webPushInfoLabel, 0);
  infoKey.set(userPubKeyBytes, webPushInfoLabel.length);
  infoKey.set(localPubKeyBytes, webPushInfoLabel.length + userPubKeyBytes.length);

  const ikm = await hkdfExpand(prkKey, infoKey, 32);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const prk = await hkdfExtract(salt, ikm);

  const cek = await hkdfExpand(prk, enc.encode("Content-Encoding: aes128gcm\0"), 16);
  const nonce = await hkdfExpand(prk, enc.encode("Content-Encoding: nonce\0"), 12);

  const payloadBytes = enc.encode(payloadText);
  const paddedPayload = new Uint8Array(payloadBytes.length + 1);
  paddedPayload.set(payloadBytes, 0);
  paddedPayload[payloadBytes.length] = 0x02;

  const aesKey = await crypto.subtle.importKey('raw', cek, { name: 'AES-GCM' }, false, ['encrypt']);
  const ciphertextBuffer = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce },
    aesKey,
    paddedPayload
  );

  const header = new Uint8Array(16 + 4 + 1 + 65);
  header.set(salt, 0);
  header[16] = 0x00;
  header[17] = 0x00;
  header[18] = 0x10;
  header[19] = 0x00;
  header[20] = 0x41;
  header.set(localPubKeyBytes, 21);

  const encryptedBody = new Uint8Array(header.length + ciphertextBuffer.byteLength);
  encryptedBody.set(header, 0);
  encryptedBody.set(new Uint8Array(ciphertextBuffer), header.length);

  return encryptedBody;
}

// Send Push Notification Helper
async function sendPushNotification(env, userId, payloadObj, cleanBaseUrl) {
  if (!env.VAPID_PUBLIC_KEY || !env.VAPID_PRIVATE_KEY || !userId) return;

  const serviceRoleKey = env.SUPABASE_SERVICE_ROLE_KEY || env.SUPABASE_ANON_KEY;
  const headers = {
    'apikey': serviceRoleKey,
    'Authorization': `Bearer ${serviceRoleKey}`
  };

  try {
    const subRes = await fetch(`${cleanBaseUrl}/rest/v1/push_subscriptions?user_id=eq.${userId}&select=*`, {
      headers
    });
    if (!subRes.ok) return;

    const subs = await subRes.json();
    if (!Array.isArray(subs) || subs.length === 0) return;

    for (const subRecord of subs) {
      const sub = subRecord.subscription;
      if (!sub || !sub.endpoint) continue;

      try {
        const endpointUrl = new URL(sub.endpoint);
        const audience = endpointUrl.origin;
        const jwt = await createVapidJwt(
          audience,
          env.VAPID_SUBJECT,
          env.VAPID_PRIVATE_KEY,
          env.VAPID_PUBLIC_KEY
        );

        const pushHeaders = {
          'Authorization': `vapid t=${jwt}, k=${env.VAPID_PUBLIC_KEY}`,
          'TTL': '86400',
          'Urgency': payloadObj.type === 'call' ? 'high' : 'normal'
        };

        let bodyData = null;
        if (sub.keys) {
          bodyData = await encryptWebPushPayload(sub.keys, JSON.stringify(payloadObj));
          if (bodyData) {
            pushHeaders['Content-Type'] = 'application/octet-stream';
            pushHeaders['Content-Encoding'] = 'aes128gcm';
          }
        }

        const pushRes = await fetch(sub.endpoint, {
          method: 'POST',
          headers: pushHeaders,
          body: bodyData
        });

        // Delete stale or expired subscriptions
        if (pushRes.status === 404 || pushRes.status === 410) {
          await fetch(`${cleanBaseUrl}/rest/v1/push_subscriptions?user_id=eq.${userId}`, {
            method: 'DELETE',
            headers
          });
        }
      } catch (err) {
        console.error("Push delivery error for endpoint:", err);
      }
    }
  } catch (err) {
    console.error("sendPushNotification error:", err);
  }
}

// Resolve user_id from 8-digit main number or burner number
async function resolveUserIdFromNumber(cleanBaseUrl, serviceRoleKey, number) {
  if (!number) return null;
  const headers = {
    'apikey': serviceRoleKey,
    'Authorization': `Bearer ${serviceRoleKey}`
  };

  try {
    const profRes = await fetch(`${cleanBaseUrl}/rest/v1/profiles?main_number=eq.${number}&select=id`, { headers });
    if (profRes.ok) {
      const profData = await profRes.json();
      if (Array.isArray(profData) && profData.length > 0) return profData[0].id;
    }

    const burnerRes = await fetch(`${cleanBaseUrl}/rest/v1/disposable_numbers?burner_number=eq.${number}&select=user_id`, { headers });
    if (burnerRes.ok) {
      const burnerData = await burnerRes.json();
      if (Array.isArray(burnerData) && burnerData.length > 0) return burnerData[0].user_id;
    }
  } catch (e) {}

  return null;
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // Only intercept requests to /api/*
    if (!url.pathname.startsWith('/api/')) {
      return env.ASSETS ? env.ASSETS.fetch(request) : fetch(request);
    }

    const supabaseUrl = env.SUPABASE_URL;
    const supabaseAnonKey = env.SUPABASE_ANON_KEY;

    // Check for missing Cloudflare Secrets
    if (!supabaseUrl || !supabaseAnonKey) {
      return new Response(
        JSON.stringify({
          error: 'Supabase Environment Secrets missing (SUPABASE_URL or SUPABASE_ANON_KEY is not configured in Cloudflare Secrets)'
        }),
        {
          status: 500,
          headers: {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Headers': '*'
          }
        }
      );
    }

    const cleanBaseUrl = supabaseUrl.replace(/\/+$/, '');

    // 1. Health Check Endpoint
    if (url.pathname === '/api/health') {
      return new Response(
        JSON.stringify({
          status: 'ok',
          message: 'Supabase backend proxy configured properly.',
          supabaseUrl: supabaseUrl,
          supabaseAnonKey: supabaseAnonKey
        }),
        {
          status: 200,
          headers: { 'Content-Type': 'application/json' }
        }
      );
    }

    // CORS preflight handling
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        status: 204,
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type, Authorization, apikey, x-client-info'
        }
      });
    }

    // 2. Realtime WebSocket Proxy (/api/realtime)
    if (url.pathname === '/api/realtime') {
      const upgradeHeader = request.headers.get('Upgrade');
      if (!upgradeHeader || upgradeHeader.toLowerCase() !== 'websocket') {
        return new Response('Expected Upgrade: websocket', { status: 426 });
      }

      const wsProtocol = cleanBaseUrl.startsWith('https') ? 'wss' : 'ws';
      const supabaseWsHost = cleanBaseUrl.replace(/^https?:\/\//, '');
      const supabaseWsUrl = `${wsProtocol}://${supabaseWsHost}/realtime/v1/websocket?apikey=${supabaseAnonKey}&vsn=1.0.0`;

      return fetch(supabaseWsUrl, {
        headers: {
          'Upgrade': 'websocket'
        }
      });
    }

    const serviceRoleKey = env.SUPABASE_SERVICE_ROLE_KEY || supabaseAnonKey;

    // Helper for Supabase REST requests
    const getSupabaseHeaders = (customAuthToken) => {
      const headers = {
        'apikey': supabaseAnonKey,
        'Content-Type': 'application/json'
      };
      if (customAuthToken) {
        headers['Authorization'] = `Bearer ${customAuthToken}`;
      } else {
        headers['Authorization'] = `Bearer ${supabaseAnonKey}`;
      }
      return headers;
    };

    // Helper for Supabase Admin / Service Role requests (bypasses RLS)
    const getServiceRoleHeaders = () => {
      return {
        'apikey': serviceRoleKey,
        'Authorization': `Bearer ${serviceRoleKey}`,
        'Content-Type': 'application/json'
      };
    };

    // Helper to verify user token and return user or null
    const verifyUserToken = async (token) => {
      if (!token) return null;
      try {
        const userRes = await fetch(`${cleanBaseUrl}/auth/v1/user`, {
          headers: getSupabaseHeaders(token)
        });
        if (!userRes.ok) return null;
        const userData = await userRes.json();
        return userData && userData.id ? userData : null;
      } catch (e) {
        return null;
      }
    };

    // Helper to verify admin token and return user profile or null
    const verifyAdminToken = async (token) => {
      const authUser = await verifyUserToken(token);
      if (!authUser) return null;

      try {
        const profRes = await fetch(`${cleanBaseUrl}/rest/v1/profiles?id=eq.${authUser.id}&select=*`, {
          headers: getSupabaseHeaders(token)
        });
        if (!profRes.ok) return null;
        const profData = await profRes.json();
        if (profData && profData.length > 0 && profData[0].is_admin && !profData[0].is_disabled) {
          return { user: authUser, profile: profData[0] };
        }
      } catch (e) {
        return null;
      }
      return null;
    };

    try {
      // 3. PUBLIC SETTINGS ENDPOINT (/api/settings/public)
      if (url.pathname === '/api/settings/public' && request.method === 'GET') {
        const res = await fetch(`${cleanBaseUrl}/rest/v1/system_settings?select=*`, {
          headers: getSupabaseHeaders()
        });
        const data = await res.json();

        let require_invite_code = false;
        let banner_config = {
          enabled: false,
          text: '',
          type: 'info', // 'info', 'warning', 'beta'
          location: 'global' // 'home', 'global'
        };
        let maintenance_mode = {
          enabled: false,
          message: 'Plattform befindet sich derzeit im Wartungsmodus.'
        };

        if (res.ok && Array.isArray(data)) {
          data.forEach(item => {
            if (item.key === 'require_invite_code') {
              require_invite_code = !!(item.value && item.value.enabled);
            }
            if (item.key === 'banner_config') {
              banner_config = item.value || banner_config;
            }
            if (item.key === 'maintenance_mode') {
              maintenance_mode = item.value || maintenance_mode;
            }
          });
        }

        return new Response(JSON.stringify({
          require_invite_code,
          banner_config,
          maintenance_mode,
          vapidPublicKey: env.VAPID_PUBLIC_KEY || null
        }), { status: 200, headers: { 'Content-Type': 'application/json' } });
      }

      // 4. VERIFY INVITE CODE (/api/invite/verify)
      if (url.pathname === '/api/invite/verify' && request.method === 'POST') {
        const body = await request.json();
        const { code } = body;

        if (!code || typeof code !== 'string') {
          return new Response(JSON.stringify({ error: 'Code ist erforderlich.' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
        }

        const cleanCode = code.trim().toUpperCase();

        // Use service role key to bypass RLS for unauthenticated users
        const inviteRes = await fetch(`${cleanBaseUrl}/rest/v1/invite_codes?code=eq.${cleanCode}&select=*`, {
          headers: getServiceRoleHeaders()
        });
        const inviteData = await inviteRes.json();

        if (!inviteRes.ok || !inviteData || inviteData.length === 0) {
          return new Response(JSON.stringify({ valid: false, error: 'Ungültiger Einladungscode.' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
        }

        const invite = inviteData[0];

        if (!invite.is_active || invite.used_count >= invite.max_uses) {
          return new Response(JSON.stringify({ valid: false, error: 'Einladungscode ist abgelaufen oder wurde bereits zu oft verwendet.' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
        }

        return new Response(JSON.stringify({ valid: true, message: 'Einladungscode erfolgreich verifiziert!' }), { status: 200, headers: { 'Content-Type': 'application/json' } });
      }

      // 5. PUSH SUBSCRIBE ENDPOINT (/api/push/subscribe)
      if (url.pathname === '/api/push/subscribe') {
        const authHeader = request.headers.get('Authorization');
        const token = authHeader ? authHeader.replace('Bearer ', '') : null;
        const authUser = await verifyUserToken(token);

        if (!token || !authUser) {
          return new Response(JSON.stringify({ error: 'Nicht autorisiert. Gültiges Token erforderlich.' }), { status: 401, headers: { 'Content-Type': 'application/json' } });
        }

        if (request.method === 'POST') {
          const body = await request.json();
          const subscription = body.subscription || body;

          if (!subscription || !subscription.endpoint) {
            return new Response(JSON.stringify({ error: 'Ungültige Subscription-Daten.' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
          }

          const upsertRes = await fetch(`${cleanBaseUrl}/rest/v1/push_subscriptions`, {
            method: 'POST',
            headers: {
              ...getSupabaseHeaders(token),
              'Prefer': 'resolution=merge-duplicates,return=representation'
            },
            body: JSON.stringify({
              user_id: authUser.id,
              subscription: subscription,
              updated_at: new Date().toISOString()
            })
          });

          const resData = await upsertRes.json();
          return new Response(JSON.stringify(resData), { status: upsertRes.status, headers: { 'Content-Type': 'application/json' } });
        }

        if (request.method === 'DELETE') {
          const delRes = await fetch(`${cleanBaseUrl}/rest/v1/push_subscriptions?user_id=eq.${authUser.id}`, {
            method: 'DELETE',
            headers: getSupabaseHeaders(token)
          });
          return new Response(null, { status: delRes.status });
        }
      }

      // 6. ADMIN SETTINGS (/api/admin/settings)
      if (url.pathname === '/api/admin/settings') {
        const authHeader = request.headers.get('Authorization');
        const token = authHeader ? authHeader.replace('Bearer ', '') : null;
        const adminCtx = await verifyAdminToken(token);

        if (!token || !adminCtx) {
          return new Response(JSON.stringify({ error: 'Zugriff verweigert. Admin-Rechte erforderlich.' }), { status: 403, headers: { 'Content-Type': 'application/json' } });
        }

        if (request.method === 'GET') {
          const res = await fetch(`${cleanBaseUrl}/rest/v1/system_settings?select=*`, {
            headers: getSupabaseHeaders(token)
          });
          const data = await res.json();
          return new Response(JSON.stringify(data), { status: res.status, headers: { 'Content-Type': 'application/json' } });
        }

        if (request.method === 'POST') {
          const body = await request.json();
          const { key, value } = body;

          if (!key || value === undefined) {
            return new Response(JSON.stringify({ error: 'key und value erforderlich.' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
          }

          const upsertRes = await fetch(`${cleanBaseUrl}/rest/v1/system_settings`, {
            method: 'POST',
            headers: {
              ...getSupabaseHeaders(token),
              'Prefer': 'resolution=merge-duplicates,return=representation'
            },
            body: JSON.stringify({ key, value })
          });

          const upsertData = await upsertRes.json();
          return new Response(JSON.stringify(upsertData), { status: upsertRes.status, headers: { 'Content-Type': 'application/json' } });
        }
      }

      // 7. ADMIN INVITES MANAGEMENT (/api/admin/invites)
      if (url.pathname === '/api/admin/invites') {
        const authHeader = request.headers.get('Authorization');
        const token = authHeader ? authHeader.replace('Bearer ', '') : null;
        const adminCtx = await verifyAdminToken(token);

        if (!token || !adminCtx) {
          return new Response(JSON.stringify({ error: 'Zugriff verweigert. Admin-Rechte erforderlich.' }), { status: 403, headers: { 'Content-Type': 'application/json' } });
        }

        if (request.method === 'GET') {
          const res = await fetch(`${cleanBaseUrl}/rest/v1/invite_codes?select=*&order=created_at.desc`, {
            headers: getServiceRoleHeaders()
          });
          const data = await res.json();
          return new Response(JSON.stringify(data), { status: res.status, headers: { 'Content-Type': 'application/json' } });
        }

        if (request.method === 'POST') {
          const body = await request.json();
          const { max_uses, code: customCode } = body;

          // Generate a random 8-character code if not provided
          const code = customCode ? customCode.trim().toUpperCase() : 'AEGIS-' + Math.random().toString(36).substring(2, 8).toUpperCase();
          const maxUsesNum = typeof max_uses === 'number' && max_uses > 0 ? max_uses : 1;

          const createRes = await fetch(`${cleanBaseUrl}/rest/v1/invite_codes`, {
            method: 'POST',
            headers: {
              ...getServiceRoleHeaders(),
              'Prefer': 'return=representation'
            },
            body: JSON.stringify({
              code: code,
              created_by: adminCtx.user.id,
              max_uses: maxUsesNum,
              used_count: 0,
              is_active: true
            })
          });

          const createData = await createRes.json();
          return new Response(JSON.stringify(createData), { status: createRes.status, headers: { 'Content-Type': 'application/json' } });
        }

        if (request.method === 'DELETE') {
          const codeToDelete = url.searchParams.get('code');
          if (!codeToDelete) {
            return new Response(JSON.stringify({ error: 'code Parameter erforderlich.' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
          }

          const delRes = await fetch(`${cleanBaseUrl}/rest/v1/invite_codes?code=eq.${codeToDelete}`, {
            method: 'DELETE',
            headers: getServiceRoleHeaders()
          });

          return new Response(null, { status: delRes.status });
        }
      }

      // 8. ADMIN STATS ENDPOINT (/api/admin/stats)
      if (url.pathname === '/api/admin/stats' && request.method === 'GET') {
        const authHeader = request.headers.get('Authorization');
        const token = authHeader ? authHeader.replace('Bearer ', '') : null;
        const adminCtx = await verifyAdminToken(token);

        if (!token || !adminCtx) {
          return new Response(JSON.stringify({ error: 'Zugriff verweigert. Admin-Rechte erforderlich.' }), { status: 403, headers: { 'Content-Type': 'application/json' } });
        }

        // Fetch counts and storage statistics using exact headers
        const [usersRes, burnersRes, msgsRes, storageListRes] = await Promise.all([
          fetch(`${cleanBaseUrl}/rest/v1/profiles?select=count`, { headers: { ...getServiceRoleHeaders(), 'Prefer': 'count=exact' } }),
          fetch(`${cleanBaseUrl}/rest/v1/disposable_numbers?select=count`, { headers: { ...getServiceRoleHeaders(), 'Prefer': 'count=exact' } }),
          fetch(`${cleanBaseUrl}/rest/v1/messages?select=count`, { headers: { ...getServiceRoleHeaders(), 'Prefer': 'count=exact' } }),
          fetch(`${cleanBaseUrl}/storage/v1/object/list/chat-attachments`, {
            method: 'POST',
            headers: getServiceRoleHeaders(),
            body: JSON.stringify({ prefix: '', limit: 10000 })
          }).catch(() => null)
        ]);

        const getCount = (res) => {
          if (!res) return 0;
          const range = res.headers.get('content-range');
          if (range && range.includes('/')) {
            return parseInt(range.split('/')[1], 10) || 0;
          }
          return 0;
        };

        let storageCount = 0;
        let storageSizeBytes = 0;

        if (storageListRes && storageListRes.ok) {
          try {
            const objects = await storageListRes.json();
            if (Array.isArray(objects)) {
              storageCount = objects.length;
              storageSizeBytes = objects.reduce((acc, obj) => {
                const sz = (obj.metadata && obj.metadata.size) || obj.size || 0;
                return acc + sz;
              }, 0);
            }
          } catch (e) {}
        }

        return new Response(JSON.stringify({
          activeUsers: getCount(usersRes),
          burnerNumbers: getCount(burnersRes),
          messageCount: getCount(msgsRes),
          storageCount: storageCount,
          storageSizeBytes: storageSizeBytes
        }), { status: 200, headers: { 'Content-Type': 'application/json' } });
      }

      // 9. ADMIN USER MANAGEMENT (/api/admin/users)
      if (url.pathname === '/api/admin/users' && request.method === 'GET') {
        const authHeader = request.headers.get('Authorization');
        const token = authHeader ? authHeader.replace('Bearer ', '') : null;
        const adminCtx = await verifyAdminToken(token);

        if (!token || !adminCtx) {
          return new Response(JSON.stringify({ error: 'Zugriff verweigert. Admin-Rechte erforderlich.' }), { status: 403, headers: { 'Content-Type': 'application/json' } });
        }

        const res = await fetch(`${cleanBaseUrl}/rest/v1/profiles?select=id,username,main_number,is_disabled,is_admin,created_at&order=created_at.desc`, {
          headers: getSupabaseHeaders(token)
        });
        const data = await res.json();
        return new Response(JSON.stringify(data), { status: res.status, headers: { 'Content-Type': 'application/json' } });
      }

      // 10. ADMIN ACCOUNT FREEZE TOGGLE (/api/admin/users/toggle-freeze)
      if (url.pathname === '/api/admin/users/toggle-freeze' && request.method === 'POST') {
        const authHeader = request.headers.get('Authorization');
        const token = authHeader ? authHeader.replace('Bearer ', '') : null;
        const adminCtx = await verifyAdminToken(token);

        if (!token || !adminCtx) {
          return new Response(JSON.stringify({ error: 'Zugriff verweigert. Admin-Rechte erforderlich.' }), { status: 403, headers: { 'Content-Type': 'application/json' } });
        }

        const body = await request.json();
        const { user_id, is_disabled } = body;

        if (!user_id || is_disabled === undefined) {
          return new Response(JSON.stringify({ error: 'user_id und is_disabled erforderlich.' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
        }

        const updateRes = await fetch(`${cleanBaseUrl}/rest/v1/profiles?id=eq.${user_id}`, {
          method: 'PATCH',
          headers: {
            ...getSupabaseHeaders(token),
            'Prefer': 'return=representation'
          },
          body: JSON.stringify({ is_disabled: is_disabled })
        });

        const updateData = await updateRes.json();
        return new Response(JSON.stringify(updateData), { status: updateRes.status, headers: { 'Content-Type': 'application/json' } });
      }

      // 11. AUTH REGISTER (/api/auth/register)
      if (url.pathname === '/api/auth/register' && request.method === 'POST') {
        const body = await request.json();
        const { username, password, main_number, encrypted_private_key, public_key, invite_code } = body;

        if (!username || !password || !main_number || !encrypted_private_key || !public_key) {
          return new Response(JSON.stringify({ error: 'Fehlende Felder für Registrierung.' }), {
            status: 400,
            headers: { 'Content-Type': 'application/json' }
          });
        }

        // Check maintenance mode
        const settingsRes = await fetch(`${cleanBaseUrl}/rest/v1/system_settings?select=*`, {
          headers: getSupabaseHeaders()
        });
        const settingsData = await settingsRes.json();

        let requireInvite = false;
        let isMaintenance = false;

        if (settingsRes.ok && Array.isArray(settingsData)) {
          settingsData.forEach(item => {
            if (item.key === 'require_invite_code') {
              requireInvite = !!(item.value && item.value.enabled);
            }
            if (item.key === 'maintenance_mode') {
              isMaintenance = !!(item.value && item.value.enabled);
            }
          });
        }

        if (isMaintenance) {
          return new Response(JSON.stringify({ error: 'Plattform befindet sich derzeit im Wartungsmodus. Registrierungen sind vorübergehend deaktiviert.' }), { status: 503, headers: { 'Content-Type': 'application/json' } });
        }

        let verifiedInviteRecord = null;

        if (requireInvite || invite_code) {
          if (!invite_code) {
            return new Response(JSON.stringify({ error: 'Einladungscode erforderlich.' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
          }

          // Verify invite code using Service Role Key
          const cleanCode = invite_code.trim().toUpperCase();
          const inviteRes = await fetch(`${cleanBaseUrl}/rest/v1/invite_codes?code=eq.${cleanCode}&select=*`, {
            headers: getServiceRoleHeaders()
          });
          const inviteData = await inviteRes.json();

          if (!inviteRes.ok || !inviteData || inviteData.length === 0 || !inviteData[0].is_active || inviteData[0].used_count >= inviteData[0].max_uses) {
            return new Response(JSON.stringify({ error: 'Ungültiger oder abgelaufener Einladungscode.' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
          }

          verifiedInviteRecord = inviteData[0];
        }

        const syntheticEmail = `${username.toLowerCase()}@aegis.internal`;
        const serviceRoleKey = env.SUPABASE_SERVICE_ROLE_KEY;

        let user = null;
        let accessToken = null;

        if (serviceRoleKey) {
          const adminRes = await fetch(`${cleanBaseUrl}/auth/v1/admin/users`, {
            method: 'POST',
            headers: {
              'apikey': serviceRoleKey,
              'Authorization': `Bearer ${serviceRoleKey}`,
              'Content-Type': 'application/json'
            },
            body: JSON.stringify({
              email: syntheticEmail,
              password: password,
              email_confirm: true,
              user_metadata: { username, main_number }
            })
          });

          const adminData = await adminRes.json();

          if (!adminRes.ok) {
            const errMsg = adminData.msg || adminData.message || adminData.error_description || adminData.error || 'Registrierung fehlgeschlagen.';
            if (errMsg.toLowerCase().includes('rate limit') || adminRes.status === 429) {
              return new Response(JSON.stringify({ error: 'Service Key fehlt oder Supabase E-Mail-Limit aktiv.' }), {
                status: 429,
                headers: { 'Content-Type': 'application/json' }
              });
            }
            return new Response(JSON.stringify({ error: errMsg }), {
              status: adminRes.status,
              headers: { 'Content-Type': 'application/json' }
            });
          }

          user = adminData.user || adminData;

          const loginRes = await fetch(`${cleanBaseUrl}/auth/v1/token?grant_type=password`, {
            method: 'POST',
            headers: getSupabaseHeaders(),
            body: JSON.stringify({
              email: syntheticEmail,
              password: password
            })
          });

          const loginData = await loginRes.json();
          if (loginRes.ok && loginData.access_token) {
            accessToken = loginData.access_token;
            if (loginData.user) {
              user = loginData.user;
            }
          }
        } else {
          const signUpRes = await fetch(`${cleanBaseUrl}/auth/v1/signup`, {
            method: 'POST',
            headers: getSupabaseHeaders(),
            body: JSON.stringify({
              email: syntheticEmail,
              password: password,
              data: { username, main_number }
            })
          });

          const signUpData = await signUpRes.json();
          if (!signUpRes.ok) {
            const errMsg = signUpData.msg || signUpData.error_description || signUpData.message || signUpData.error || 'Registrierung fehlgeschlagen.';
            if (errMsg.toLowerCase().includes('rate limit') || signUpRes.status === 429) {
              return new Response(JSON.stringify({ error: 'Service Key fehlt oder Supabase E-Mail-Limit aktiv.' }), {
                status: 429,
                headers: { 'Content-Type': 'application/json' }
              });
            }
            return new Response(JSON.stringify({ error: errMsg }), {
              status: signUpRes.status,
              headers: { 'Content-Type': 'application/json' }
            });
          }

          user = signUpData.user || signUpData;
          accessToken = signUpData.access_token;

          if (!accessToken) {
            const loginRes = await fetch(`${cleanBaseUrl}/auth/v1/token?grant_type=password`, {
              method: 'POST',
              headers: getSupabaseHeaders(),
              body: JSON.stringify({
                email: syntheticEmail,
                password: password
              })
            });

            const loginData = await loginRes.json();
            if (loginRes.ok && loginData.access_token) {
              accessToken = loginData.access_token;
              if (loginData.user) {
                user = loginData.user;
              }
            }
          }
        }

        // Insert into profiles table
        const profileRes = await fetch(`${cleanBaseUrl}/rest/v1/profiles`, {
          method: 'POST',
          headers: {
            ...getSupabaseHeaders(accessToken || serviceRoleKey),
            'Prefer': 'return=representation'
          },
          body: JSON.stringify({
            id: user.id,
            username: username,
            main_number: main_number,
            encrypted_private_key: encrypted_private_key,
            public_key: public_key,
            is_disabled: false,
            is_admin: false
          })
        });

        const profileData = await profileRes.json();
        if (!profileRes.ok) {
          return new Response(JSON.stringify({ error: profileData.message || profileData.error || 'Profil konnte nicht angelegt werden.' }), {
            status: profileRes.status,
            headers: { 'Content-Type': 'application/json' }
          });
        }

        // Increment used_count on successful registration
        if (verifiedInviteRecord) {
          const newCount = verifiedInviteRecord.used_count + 1;
          const newActive = newCount < verifiedInviteRecord.max_uses;

          await fetch(`${cleanBaseUrl}/rest/v1/invite_codes?code=eq.${verifiedInviteRecord.code}`, {
            method: 'PATCH',
            headers: {
              ...getServiceRoleHeaders(),
              'Prefer': 'return=representation'
            },
            body: JSON.stringify({
              used_count: newCount,
              is_active: newActive
            })
          });
        }

        return new Response(JSON.stringify({
          user: {
            id: user.id,
            username: username,
            main_number: main_number
          },
          profile: Array.isArray(profileData) ? profileData[0] : profileData,
          access_token: accessToken
        }), { status: 200, headers: { 'Content-Type': 'application/json' } });
      }

      // 12. AUTH LOGIN (/api/auth/login)
      if (url.pathname === '/api/auth/login' && request.method === 'POST') {
        const body = await request.json();
        const { identifier, password } = body;

        if (!identifier || !password) {
          return new Response(JSON.stringify({ error: 'Nutzername/ID und Passwort erforderlich.' }), { status: 400 });
        }

        // Check maintenance mode
        const settingsRes = await fetch(`${cleanBaseUrl}/rest/v1/system_settings?key=eq.maintenance_mode&select=*`, {
          headers: getSupabaseHeaders()
        });
        const settingsData = await settingsRes.json();
        const isMaintenance = settingsRes.ok && settingsData && settingsData.length > 0 && !!(settingsData[0].value && settingsData[0].value.enabled);

        if (isMaintenance) {
          // Resolve profile to check if user is admin before blocking
          let checkUsername = identifier;
          let profQuery = `username=eq.${encodeURIComponent(identifier)}`;
          if (/^\d{8}$/.test(identifier)) {
            profQuery = `main_number=eq.${identifier}`;
          }

          const checkProfRes = await fetch(`${cleanBaseUrl}/rest/v1/profiles?${profQuery}&select=is_admin,is_disabled`, {
            headers: getSupabaseHeaders()
          });
          const checkProfData = await checkProfRes.json();

          if (!checkProfRes.ok || !checkProfData || checkProfData.length === 0 || !checkProfData[0].is_admin) {
            return new Response(JSON.stringify({ error: 'Plattform befindet sich derzeit im Wartungsmodus. Anmeldungen sind nur für Administratoren gestattet.' }), { status: 503, headers: { 'Content-Type': 'application/json' } });
          }
        }

        let resolvedUsername = identifier;

        if (/^\d{8}$/.test(identifier)) {
          const profRes = await fetch(`${cleanBaseUrl}/rest/v1/profiles?main_number=eq.${identifier}&select=username,is_disabled`, {
            headers: getSupabaseHeaders()
          });
          const profList = await profRes.json();
          if (!profRes.ok || !profList || profList.length === 0) {
            return new Response(JSON.stringify({ error: 'Kein Profil zu dieser Haupt-ID gefunden.' }), { status: 404 });
          }
          if (profList[0].is_disabled) {
            return new Response(JSON.stringify({ error: 'Dein Konto ist derzeit deaktiviert. Bitte kontaktiere den Support oder reaktiviere es.' }), { status: 403 });
          }
          resolvedUsername = profList[0].username;
        }

        const syntheticEmail = `${resolvedUsername.toLowerCase()}@aegis.internal`;

        const tokenRes = await fetch(`${cleanBaseUrl}/auth/v1/token?grant_type=password`, {
          method: 'POST',
          headers: getSupabaseHeaders(),
          body: JSON.stringify({
            email: syntheticEmail,
            password: password
          })
        });

        const tokenData = await tokenRes.json();
        if (!tokenRes.ok) {
          return new Response(JSON.stringify({ error: tokenData.error_description || 'Anmeldung fehlgeschlagen. Bitte Zugangsdaten prüfen.' }), { status: tokenRes.status });
        }

        // Fetch User Profile
        const profileRes = await fetch(`${cleanBaseUrl}/rest/v1/profiles?id=eq.${tokenData.user.id}&select=*`, {
          headers: getSupabaseHeaders(tokenData.access_token)
        });

        const profileData = await profileRes.json();
        if (!profileRes.ok || !profileData || profileData.length === 0) {
          return new Response(JSON.stringify({ error: 'Nutzerprofil nicht gefunden.' }), { status: 404 });
        }

        if (profileData[0].is_disabled) {
          return new Response(JSON.stringify({ error: 'Dein Konto ist derzeit deaktiviert.' }), { status: 403, headers: { 'Content-Type': 'application/json' } });
        }

        return new Response(JSON.stringify({
          user: {
            id: tokenData.user.id,
            username: profileData[0].username,
            main_number: profileData[0].main_number
          },
          profile: profileData[0],
          access_token: tokenData.access_token
        }), { status: 200, headers: { 'Content-Type': 'application/json' } });
      }

      // 13. ACCOUNT DEACTIVATION (/api/auth/deactivate)
      if (url.pathname === '/api/auth/deactivate' && request.method === 'POST') {
        const authHeader = request.headers.get('Authorization');
        const token = authHeader ? authHeader.replace('Bearer ', '') : null;
        const authUser = await verifyUserToken(token);

        if (!token || !authUser) {
          return new Response(JSON.stringify({ error: 'Nicht autorisiert. Gültiges Token erforderlich.' }), { status: 401, headers: { 'Content-Type': 'application/json' } });
        }

        const body = await request.json();
        const { user_id } = body;

        if (!user_id || authUser.id !== user_id) {
          return new Response(JSON.stringify({ error: 'Keine Berechtigung für diese Aktion.' }), { status: 403, headers: { 'Content-Type': 'application/json' } });
        }

        const updateRes = await fetch(`${cleanBaseUrl}/rest/v1/profiles?id=eq.${user_id}`, {
          method: 'PATCH',
          headers: {
            ...getSupabaseHeaders(token),
            'Prefer': 'return=representation'
          },
          body: JSON.stringify({ is_disabled: true })
        });

        if (!updateRes.ok) {
          return new Response(JSON.stringify({ error: 'Konto konnte nicht deaktiviert werden.' }), { status: updateRes.status, headers: { 'Content-Type': 'application/json' } });
        }

        return new Response(JSON.stringify({ success: true, message: 'Konto erfolgreich deaktiviert.' }), { status: 200, headers: { 'Content-Type': 'application/json' } });
      }

      // 14. PERMANENT ACCOUNT DELETION ("Self-Destruct") (/api/auth/delete-account)
      if (url.pathname === '/api/auth/delete-account' && (request.method === 'POST' || request.method === 'DELETE')) {
        const authHeader = request.headers.get('Authorization');
        const token = authHeader ? authHeader.replace('Bearer ', '') : null;
        const authUser = await verifyUserToken(token);

        if (!token || !authUser) {
          return new Response(JSON.stringify({ error: 'Nicht autorisiert. Gültiges Token erforderlich.' }), { status: 401, headers: { 'Content-Type': 'application/json' } });
        }

        const body = await request.json();
        const { user_id } = body;

        if (!user_id || authUser.id !== user_id) {
          return new Response(JSON.stringify({ error: 'Keine Berechtigung für diese Aktion.' }), { status: 403, headers: { 'Content-Type': 'application/json' } });
        }

        const serviceRoleKey = env.SUPABASE_SERVICE_ROLE_KEY;

        // Delete profile (cascades disposable_numbers, user_contacts, push_subscriptions)
        const delProfRes = await fetch(`${cleanBaseUrl}/rest/v1/profiles?id=eq.${user_id}`, {
          method: 'DELETE',
          headers: getSupabaseHeaders(token || serviceRoleKey)
        });

        if (!delProfRes.ok) {
          return new Response(JSON.stringify({ error: 'Fehler beim Löschen des Profils.' }), { status: delProfRes.status, headers: { 'Content-Type': 'application/json' } });
        }

        // If serviceRoleKey is available, delete from Supabase auth admin as well
        if (serviceRoleKey) {
          await fetch(`${cleanBaseUrl}/auth/v1/admin/users/${user_id}`, {
            method: 'DELETE',
            headers: {
              'apikey': serviceRoleKey,
              'Authorization': `Bearer ${serviceRoleKey}`
            }
          });
        }

        return new Response(JSON.stringify({ success: true, message: 'Konto unwiderruflich gelöscht.' }), { status: 200, headers: { 'Content-Type': 'application/json' } });
      }

      // 15. RESOLVE PUBLIC KEY (/api/profiles/resolve)
      if (url.pathname === '/api/profiles/resolve' && request.method === 'GET') {
        const number = url.searchParams.get('number');
        if (!number) {
          return new Response(JSON.stringify({ error: 'Nummer erforderlich.' }), { status: 400 });
        }

        const profRes = await fetch(`${cleanBaseUrl}/rest/v1/profiles?main_number=eq.${number}&select=public_key,is_disabled`, {
          headers: getSupabaseHeaders()
        });
        const profData = await profRes.json();

        if (profRes.ok && profData && profData.length > 0) {
          if (profData[0].is_disabled) {
            return new Response(JSON.stringify({ error: 'Dieses Konto ist deaktiviert.' }), { status: 403 });
          }
          return new Response(JSON.stringify({
            number: number,
            public_key: profData[0].public_key,
            isBurner: false
          }), { status: 200, headers: { 'Content-Type': 'application/json' } });
        }

        const burnerRes = await fetch(`${cleanBaseUrl}/rest/v1/disposable_numbers?burner_number=eq.${number}&active=eq.true&select=user_id,expires_at,profiles(public_key,is_disabled)`, {
          headers: getSupabaseHeaders()
        });
        const burnerData = await burnerRes.json();

        if (burnerRes.ok && burnerData && burnerData.length > 0) {
          const burner = burnerData[0];
          if (burner.expires_at && new Date(burner.expires_at) <= new Date()) {
            return new Response(JSON.stringify({ error: 'Diese Einweg-Nummer ist abgelaufen.' }), { status: 410 });
          }
          if (burner.profiles && burner.profiles.is_disabled) {
            return new Response(JSON.stringify({ error: 'Inhaber-Konto ist deaktiviert.' }), { status: 403 });
          }
          if (burner.profiles && burner.profiles.public_key) {
            return new Response(JSON.stringify({
              number: number,
              public_key: burner.profiles.public_key,
              isBurner: true
            }), { status: 200, headers: { 'Content-Type': 'application/json' } });
          }
        }

        return new Response(JSON.stringify({ error: 'Nummer nicht gefunden oder inaktiv.' }), { status: 404 });
      }

      // 16. CONTACTS MANAGEMENT (/api/contacts)
      if (url.pathname === '/api/contacts') {
        const authHeader = request.headers.get('Authorization');
        const token = authHeader ? authHeader.replace('Bearer ', '') : null;

        if (request.method === 'GET') {
          const userId = url.searchParams.get('user_id');
          if (!userId) return new Response(JSON.stringify({ error: 'user_id erforderlich.' }), { status: 400 });

          const fetchRes = await fetch(`${cleanBaseUrl}/rest/v1/user_contacts?user_id=eq.${userId}&select=*`, {
            headers: getSupabaseHeaders(token)
          });
          const resData = await fetchRes.json();
          return new Response(JSON.stringify(resData), { status: fetchRes.status, headers: { 'Content-Type': 'application/json' } });
        }

        if (request.method === 'POST') {
          const body = await request.json();
          const { user_id, contact_number, nickname } = body;

          const upsertRes = await fetch(`${cleanBaseUrl}/rest/v1/user_contacts`, {
            method: 'POST',
            headers: {
              ...getSupabaseHeaders(token),
              'Prefer': 'resolution=merge-duplicates,return=representation'
            },
            body: JSON.stringify({
              user_id,
              contact_number,
              nickname
            })
          });
          const resData = await upsertRes.json();

          if (upsertRes.ok && contact_number) {
            const targetUserId = await resolveUserIdFromNumber(cleanBaseUrl, serviceRoleKey, contact_number);
            if (targetUserId) {
              ctx.waitUntil(sendPushNotification(env, targetUserId, {
                title: "AegisChat",
                body: "Neuer Kontakt hat sich verbunden",
                type: "contact"
              }, cleanBaseUrl));
            }
          }

          return new Response(JSON.stringify(resData), { status: upsertRes.status, headers: { 'Content-Type': 'application/json' } });
        }

        if (request.method === 'DELETE') {
          const userId = url.searchParams.get('user_id');
          const contactNumber = url.searchParams.get('contact_number');

          const delRes = await fetch(`${cleanBaseUrl}/rest/v1/user_contacts?user_id=eq.${userId}&contact_number=eq.${contactNumber}`, {
            method: 'DELETE',
            headers: getSupabaseHeaders(token)
          });
          return new Response(null, { status: delRes.status });
        }
      }

      // 17. BURNER NUMBERS MANAGEMENT (/api/burners)
      if (url.pathname === '/api/burners') {
        const authHeader = request.headers.get('Authorization');
        const token = authHeader ? authHeader.replace('Bearer ', '') : null;

        if (request.method === 'GET') {
          const userId = url.searchParams.get('user_id');
          const fetchRes = await fetch(`${cleanBaseUrl}/rest/v1/disposable_numbers?user_id=eq.${userId}&select=*`, {
            headers: getSupabaseHeaders(token)
          });
          const resData = await fetchRes.json();
          return new Response(JSON.stringify(resData), { status: fetchRes.status, headers: { 'Content-Type': 'application/json' } });
        }

        if (request.method === 'POST') {
          const body = await request.json();
          const insertRes = await fetch(`${cleanBaseUrl}/rest/v1/disposable_numbers`, {
            method: 'POST',
            headers: {
              ...getSupabaseHeaders(token),
              'Prefer': 'return=representation'
            },
            body: JSON.stringify(body)
          });
          const resData = await insertRes.json();
          return new Response(JSON.stringify(resData), { status: insertRes.status, headers: { 'Content-Type': 'application/json' } });
        }

        if (request.method === 'DELETE') {
          const burnerId = url.searchParams.get('id');
          const delRes = await fetch(`${cleanBaseUrl}/rest/v1/disposable_numbers?id=eq.${burnerId}`, {
            method: 'DELETE',
            headers: getSupabaseHeaders(token)
          });
          return new Response(null, { status: delRes.status });
        }
      }

      // 18. MESSAGES ENDPOINT (/api/messages)
      if (url.pathname === '/api/messages') {
        const authHeader = request.headers.get('Authorization');
        const token = authHeader ? authHeader.replace('Bearer ', '') : null;

        if (request.method === 'GET') {
          const recipientNumber = url.searchParams.get('recipient_number');
          if (!recipientNumber) {
            return new Response(JSON.stringify({ error: 'recipient_number erforderlich' }), { status: 400 });
          }
          const fetchRes = await fetch(`${cleanBaseUrl}/rest/v1/messages?recipient_number=eq.${recipientNumber}&select=*`, {
            headers: getSupabaseHeaders(token)
          });
          const resData = await fetchRes.json();
          return new Response(JSON.stringify(resData), { status: fetchRes.status, headers: { 'Content-Type': 'application/json' } });
        }

        if (request.method === 'POST') {
          const body = await request.json();
          const insertRes = await fetch(`${cleanBaseUrl}/rest/v1/messages`, {
            method: 'POST',
            headers: {
              ...getSupabaseHeaders(token),
              'Prefer': 'return=representation'
            },
            body: JSON.stringify(body)
          });
          const resData = await insertRes.json();

          if (insertRes.ok && body.recipient_number) {
            const recipientUserId = await resolveUserIdFromNumber(cleanBaseUrl, serviceRoleKey, body.recipient_number);
            if (recipientUserId) {
              const isCallMsg = body.type === 'call' || body.message_type === 'call' || body.is_call;
              const pushPayload = isCallMsg
                ? { title: "AegisChat Call", body: "Eingehender verschlüsselter Anruf...", type: "call" }
                : { title: "AegisChat", body: "Neue verschlüsselte Nachricht erhalten", type: "message" };

              ctx.waitUntil(sendPushNotification(env, recipientUserId, pushPayload, cleanBaseUrl));
            }
          }

          return new Response(JSON.stringify(resData), { status: insertRes.status, headers: { 'Content-Type': 'application/json' } });
        }

        if (request.method === 'DELETE') {
          const recipientNumber = url.searchParams.get('recipient_number');
          const msgId = url.searchParams.get('id');

          let endpoint = `${cleanBaseUrl}/rest/v1/messages`;
          if (msgId) {
            endpoint += `?id=eq.${msgId}`;
          } else if (recipientNumber) {
            endpoint += `?recipient_number=eq.${recipientNumber}`;
          } else {
            return new Response(JSON.stringify({ error: 'recipient_number oder id erforderlich' }), { status: 400 });
          }

          const delRes = await fetch(endpoint, {
            method: 'DELETE',
            headers: getSupabaseHeaders(token)
          });
          return new Response(null, { status: delRes.status });
        }
      }

      // 19. UPLOAD FILE ENDPOINT (/api/upload)
      if (url.pathname === '/api/upload' && request.method === 'POST') {
        const authHeader = request.headers.get('Authorization');
        const token = authHeader ? authHeader.replace('Bearer ', '') : null;

        const blobBuffer = await request.arrayBuffer();
        if (!blobBuffer || blobBuffer.byteLength === 0) {
          return new Response(JSON.stringify({ error: 'Keine Datei-Daten empfangen.' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
        }

        const folderParam = url.searchParams.get('folder') || url.searchParams.get('type');
        const folder = (folderParam === 'audios' || folderParam === 'voice') ? 'audios' : 'files';
        const fileUuid = crypto.randomUUID();
        const filePath = `${folder}/${fileUuid}.bin`;
        const uploadUrl = `${cleanBaseUrl}/storage/v1/object/chat-attachments/${filePath}`;

        const uploadHeaders = getServiceRoleHeaders();
        uploadHeaders['Content-Type'] = 'application/octet-stream';
        uploadHeaders['x-upsert'] = 'true';

        const uploadRes = await fetch(uploadUrl, {
          method: 'POST',
          headers: uploadHeaders,
          body: blobBuffer
        });

        if (!uploadRes.ok) {
          const errData = await uploadRes.text();
          return new Response(JSON.stringify({ error: `Upload fehlgeschlagen: ${errData}` }), { status: uploadRes.status, headers: { 'Content-Type': 'application/json' } });
        }

        const fileUrl = `/api/files/${filePath}`;
        return new Response(JSON.stringify({ file_url: fileUrl, file_id: filePath }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' }
        });
      }

      // 20. BURN FILE ENDPOINT (/api/files/burn) - Irrevocable deletion from Storage
      if (url.pathname === '/api/files/burn' && request.method === 'POST') {
        const body = await request.json().catch(() => ({}));
        const fileId = body.file_id || body.file_path;

        if (!fileId) {
          return new Response(JSON.stringify({ error: 'file_id oder file_path ist erforderlich.' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
        }

        const cleanPath = fileId.replace(/^\/+/, '').replace(/^api\/files\//, '');
        const delUrl = `${cleanBaseUrl}/storage/v1/object/chat-attachments/${cleanPath}`;

        const delRes = await fetch(delUrl, {
          method: 'DELETE',
          headers: getServiceRoleHeaders()
        });

        // Also attempt bulk delete endpoint as fallback
        if (!delRes.ok) {
          await fetch(`${cleanBaseUrl}/storage/v1/object/chat-attachments`, {
            method: 'DELETE',
            headers: getServiceRoleHeaders(),
            body: JSON.stringify({ prefixes: [cleanPath] })
          });
        }

        return new Response(JSON.stringify({ success: true, message: 'Datei dauerhaft aus Storage gelöscht (burned).' }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' }
        });
      }

      // 21. GET ENCRYPTED FILE ENDPOINT (/api/files/*)
      if (url.pathname.startsWith('/api/files/') && request.method === 'GET') {
        const fileId = url.pathname.replace('/api/files/', '');
        if (!fileId) {
          return new Response(JSON.stringify({ error: 'Datei-ID erforderlich.' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
        }

        let storageUrl = `${cleanBaseUrl}/storage/v1/object/public/chat-attachments/${fileId}`;
        let fetchRes = await fetch(storageUrl, {
          headers: getSupabaseHeaders()
        });

        if (!fetchRes.ok) {
          // Fallback to authenticated endpoint using Service Role Key
          storageUrl = `${cleanBaseUrl}/storage/v1/object/chat-attachments/${fileId}`;
          fetchRes = await fetch(storageUrl, {
            headers: getServiceRoleHeaders()
          });
        }

        if (!fetchRes.ok) {
          return new Response(JSON.stringify({ error: 'Datei nicht gefunden oder bereits gelöscht (burned).' }), { status: 404, headers: { 'Content-Type': 'application/json' } });
        }

        const fileData = await fetchRes.arrayBuffer();
        return new Response(fileData, {
          status: 200,
          headers: {
            'Content-Type': 'application/octet-stream',
            'Access-Control-Allow-Origin': '*',
            'Cache-Control': 'no-store, no-cache, must-revalidate, private'
          }
        });
      }

      return new Response(JSON.stringify({ error: 'Endpoint nicht gefunden.' }), { status: 404 });
    } catch (err) {
      return new Response(JSON.stringify({ error: err.message || 'Serverfehler im Cloudflare Worker.' }), { status: 500 });
    }
  }
};
