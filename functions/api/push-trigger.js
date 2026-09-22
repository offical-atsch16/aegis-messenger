export async function onRequestPost(context) {
  const { request, env } = context;

  try {
    const body = await request.json().catch(() => ({}));
    const { user_id, title, body: msgBody, type } = body;

    if (!user_id) {
      return new Response(JSON.stringify({ error: 'user_id is required' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const payloadObj = {
      title: title || 'AegisChat',
      body: msgBody || 'Neue verschlüsselte Nachricht erhalten',
      type: type || 'message'
    };

    return new Response(JSON.stringify({ success: true, message: 'Push trigger accepted', payload: payloadObj }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (err) {
    return new Response(JSON.stringify({ error: err.message || 'Push trigger error' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}
