// Cloudflare Pages Worker (`_worker.js`)
// AegisChat Secured Proxy to Supabase

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

      // Pass-through WebSocket request to Supabase Realtime using Cloudflare fetch
      return fetch(supabaseWsUrl, {
        headers: {
          'Upgrade': 'websocket'
        }
      });
    }

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

    try {
      // 3. AUTH REGISTER (/api/auth/register)
      if (url.pathname === '/api/auth/register' && request.method === 'POST') {
        const body = await request.json();
        const { username, password, main_number, encrypted_private_key, public_key } = body;

        if (!username || !password || !main_number || !encrypted_private_key || !public_key) {
          return new Response(JSON.stringify({ error: 'Fehlende Felder für Registrierung.' }), {
            status: 400,
            headers: { 'Content-Type': 'application/json' }
          });
        }

        const syntheticEmail = `${username.toLowerCase()}@aegis.internal`;
        const serviceRoleKey = env.SUPABASE_SERVICE_ROLE_KEY;

        let user = null;
        let accessToken = null;

        if (serviceRoleKey) {
          // Admin registration via Supabase Admin API
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

          // Authenticate user to obtain access_token
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
          // Fallback to standard signup when SUPABASE_SERVICE_ROLE_KEY is missing
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

        // Step 2: Insert into profiles table
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
            public_key: public_key
          })
        });

        const profileData = await profileRes.json();
        if (!profileRes.ok) {
          return new Response(JSON.stringify({ error: profileData.message || profileData.error || 'Profil konnte nicht angelegt werden.' }), {
            status: profileRes.status,
            headers: { 'Content-Type': 'application/json' }
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

      // 4. AUTH LOGIN (/api/auth/login)
      if (url.pathname === '/api/auth/login' && request.method === 'POST') {
        const body = await request.json();
        const { identifier, password } = body;

        if (!identifier || !password) {
          return new Response(JSON.stringify({ error: 'Nutzername/ID und Passwort erforderlich.' }), { status: 400 });
        }

        let resolvedUsername = identifier;

        // Check if identifier is an 8-digit main_number
        if (/^\d{8}$/.test(identifier)) {
          const profRes = await fetch(`${cleanBaseUrl}/rest/v1/profiles?main_number=eq.${identifier}&select=username`, {
            headers: getSupabaseHeaders()
          });
          const profList = await profRes.json();
          if (!profRes.ok || !profList || profList.length === 0) {
            return new Response(JSON.stringify({ error: 'Kein Profil zu dieser Haupt-ID gefunden.' }), { status: 404 });
          }
          resolvedUsername = profList[0].username;
        }

        const syntheticEmail = `${resolvedUsername.toLowerCase()}@aegis.internal`;

        // Login via Supabase Auth
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

      // 5. RESOLVE PUBLIC KEY (/api/profiles/resolve)
      if (url.pathname === '/api/profiles/resolve' && request.method === 'GET') {
        const number = url.searchParams.get('number');
        if (!number) {
          return new Response(JSON.stringify({ error: 'Nummer erforderlich.' }), { status: 400 });
        }

        // Search profiles by main_number
        const profRes = await fetch(`${cleanBaseUrl}/rest/v1/profiles?main_number=eq.${number}&select=public_key`, {
          headers: getSupabaseHeaders()
        });
        const profData = await profRes.json();

        if (profRes.ok && profData && profData.length > 0) {
          return new Response(JSON.stringify({
            number: number,
            public_key: profData[0].public_key,
            isBurner: false
          }), { status: 200, headers: { 'Content-Type': 'application/json' } });
        }

        // Search disposable_numbers by burner_number
        const burnerRes = await fetch(`${cleanBaseUrl}/rest/v1/disposable_numbers?burner_number=eq.${number}&active=eq.true&select=user_id,expires_at,profiles(public_key)`, {
          headers: getSupabaseHeaders()
        });
        const burnerData = await burnerRes.json();

        if (burnerRes.ok && burnerData && burnerData.length > 0) {
          const burner = burnerData[0];
          if (burner.expires_at && new Date(burner.expires_at) <= new Date()) {
            return new Response(JSON.stringify({ error: 'Diese Einweg-Nummer ist abgelaufen.' }), { status: 410 });
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

      // 6. BURNER NUMBERS MANAGEMENT (/api/burners)
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

      // 7. MESSAGES ENDPOINT (/api/messages)
      if (url.pathname === '/api/messages') {
        const authHeader = request.headers.get('Authorization');
        const token = authHeader ? authHeader.replace('Bearer ', '') : null;

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
          return new Response(JSON.stringify(resData), { status: insertRes.status, headers: { 'Content-Type': 'application/json' } });
        }
      }

      return new Response(JSON.stringify({ error: 'Endpoint nicht gefunden.' }), { status: 404 });
    } catch (err) {
      return new Response(JSON.stringify({ error: err.message || 'Serverfehler im Cloudflare Worker.' }), { status: 500 });
    }
  }
};
