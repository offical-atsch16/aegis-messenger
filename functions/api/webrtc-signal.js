export async function onRequestPost(context) {
  const { request, env } = context;

  try {
    const body = await request.json().catch(() => ({}));
    const { sender, recipient, event, data, encrypted_payload } = body;

    if (!recipient || (!event && !encrypted_payload)) {
      return new Response(JSON.stringify({ error: 'recipient and signal payload required' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const supabaseUrl = env.SUPABASE_URL;
    const serviceRoleKey = env.SUPABASE_SERVICE_ROLE_KEY || env.SUPABASE_ANON_KEY;

    if (!supabaseUrl || !serviceRoleKey) {
      return new Response(JSON.stringify({ error: 'Supabase config missing' }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const cleanBaseUrl = supabaseUrl.replace(/\/+$/, '');

    const insertRes = await fetch(`${cleanBaseUrl}/rest/v1/messages`, {
      method: 'POST',
      headers: {
        'apikey': serviceRoleKey,
        'Authorization': `Bearer ${serviceRoleKey}`,
        'Content-Type': 'application/json',
        'Prefer': 'return=representation'
      },
      body: JSON.stringify({
        sender_number: sender,
        recipient_number: recipient,
        encrypted_payload: encrypted_payload || JSON.stringify({ type: 'call-signal', event, sender, recipient, data })
      })
    });

    const resData = await insertRes.json();
    return new Response(JSON.stringify(resData), {
      status: insertRes.status,
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (err) {
    return new Response(JSON.stringify({ error: err.message || 'Signal relay error' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}
