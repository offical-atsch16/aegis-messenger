export async function onRequestPost(context) {
  const { request, env } = context;

  try {
    const body = await request.json().catch(() => ({}));
    const { sender_number, encrypted_payload } = body;

    const supabaseUrl = env.SUPABASE_URL;
    const serviceRoleKey = env.SUPABASE_SERVICE_ROLE_KEY || env.SUPABASE_ANON_KEY;

    if (!supabaseUrl || !serviceRoleKey) {
      return new Response(JSON.stringify({ error: 'Supabase configuration missing.' }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const cleanBaseUrl = supabaseUrl.replace(/\/+$/, '');

    const senderNumberClean = sender_number || '11111111';

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
        encrypted_payload: encrypted_payload
      })
    });

    const resData = await insertRes.json();

    // Ensure a support ticket record exists/updates for the user without error
    if (senderNumberClean && senderNumberClean !== '11111111' && senderNumberClean !== '00000000') {
      await fetch(`${cleanBaseUrl}/rest/v1/support_tickets`, {
        method: 'POST',
        headers: {
          'apikey': serviceRoleKey,
          'Authorization': `Bearer ${serviceRoleKey}`,
          'Content-Type': 'application/json',
          'Prefer': 'resolution=merge-duplicates'
        },
        body: JSON.stringify({
          user_number: senderNumberClean,
          ticket_status: 'open',
          status: 'open',
          updated_at: new Date().toISOString()
        })
      }).catch(() => {});
    }

    return new Response(JSON.stringify({ success: true, data: resData }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (err) {
    return new Response(JSON.stringify({ error: err.message || 'Support routing error.' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}
