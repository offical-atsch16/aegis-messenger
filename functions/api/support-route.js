const corsHeaders = {
  'Content-Type': 'application/json',
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS'
};

export async function onRequestOptions() {
  return new Response(null, {
    status: 204,
    headers: corsHeaders
  });
}

export async function onRequestPost(context) {
  const { request, env } = context;

  try {
    const reqText = await request.text().catch(() => '');
    let body = {};
    if (reqText) {
      try { body = JSON.parse(reqText); } catch (e) {}
    }
    const { sender_number, encrypted_payload, message, user_id } = body;

    const supabaseUrl = env.SUPABASE_URL;
    const serviceRoleKey = env.SUPABASE_SERVICE_ROLE_KEY || env.SUPABASE_ANON_KEY;

    if (!supabaseUrl || !serviceRoleKey) {
      return new Response(JSON.stringify({ error: 'Supabase configuration missing.' }), {
        status: 500,
        headers: corsHeaders
      });
    }

    const cleanBaseUrl = supabaseUrl.replace(/\/+$/, '');
    const senderNumberClean = sender_number || '11111111';
    const msgText = message || encrypted_payload || '';

    // Verify token if present
    const authHeader = request.headers.get('Authorization');
    const token = authHeader ? authHeader.replace('Bearer ', '') : null;
    let resolvedUserId = user_id || null;

    if (token) {
      try {
        const userRes = await fetch(`${cleanBaseUrl}/auth/v1/user`, {
          headers: {
            'apikey': env.SUPABASE_ANON_KEY || serviceRoleKey,
            'Authorization': `Bearer ${token}`
          }
        });
        if (userRes.ok) {
          const userText = await userRes.text().catch(() => '');
          if (userText) {
            const userData = JSON.parse(userText);
            if (userData && userData.id) resolvedUserId = userData.id;
          }
        }
      } catch (e) {}
    }

    const insertRes = await fetch(`${cleanBaseUrl}/rest/v1/messages`, {
      method: 'POST',
      headers: {
        'apikey': serviceRoleKey,
        'Authorization': `Bearer ${serviceRoleKey}`,
        'Content-Type': 'application/json',
        'Prefer': 'return=representation'
      },
      body: JSON.stringify({
        sender_number: senderNumberClean,
        recipient_number: '11111111',
        encrypted_payload: msgText
      })
    });

    const resText = await insertRes.text().catch(() => '');
    let resData = {};
    if (resText) {
      try { resData = JSON.parse(resText); } catch (e) {}
    }

    let ticketId = null;

    // Ensure a support ticket record exists/updates for the user without error
    if (senderNumberClean && senderNumberClean !== '11111111' && senderNumberClean !== '00000000') {
      const ticketObj = {
        user_number: senderNumberClean,
        ticket_status: 'open',
        status: 'open',
        message: msgText,
        updated_at: new Date().toISOString()
      };
      if (resolvedUserId) {
        ticketObj.user_id = resolvedUserId;
      }

      const ticketRes = await fetch(`${cleanBaseUrl}/rest/v1/support_tickets`, {
        method: 'POST',
        headers: {
          'apikey': serviceRoleKey,
          'Authorization': `Bearer ${serviceRoleKey}`,
          'Content-Type': 'application/json',
          'Prefer': 'resolution=merge-duplicates,return=representation'
        },
        body: JSON.stringify(ticketObj)
      }).catch(() => null);

      if (ticketRes && ticketRes.ok) {
        const ticketText = await ticketRes.text().catch(() => '');
        if (ticketText) {
          try {
            const tData = JSON.parse(ticketText);
            if (Array.isArray(tData) && tData.length > 0) {
              ticketId = tData[0].id || tData[0].user_number;
            } else if (tData && tData.id) {
              ticketId = tData.id;
            }
          } catch (e) {}
        }
      }
    }

    return new Response(JSON.stringify({ success: true, ticketId: ticketId || senderNumberClean, data: resData }), {
      status: 200,
      headers: corsHeaders
    });
  } catch (err) {
    return new Response(JSON.stringify({ error: err.message || 'Support routing error.' }), {
      status: 500,
      headers: corsHeaders
    });
  }
}
