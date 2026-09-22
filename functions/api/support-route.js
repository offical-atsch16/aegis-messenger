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

    const insertRes = await fetch(`${cleanBaseUrl}/rest/v1/messages`, {
      method: 'POST',
      headers: {
        'apikey': serviceRoleKey,
        'Authorization': `Bearer ${serviceRoleKey}`,
        'Content-Type': 'application/json',
        'Prefer': 'return=representation'
      },
      body: JSON.stringify({
        sender_number: sender_number || '00000000',
        recipient_number: '00000000',
        encrypted_payload: encrypted_payload
      })
    });

    const resData = await insertRes.json();
    return new Response(JSON.stringify(resData), {
      status: insertRes.status,
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (err) {
    return new Response(JSON.stringify({ error: err.message || 'Support routing error.' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}
