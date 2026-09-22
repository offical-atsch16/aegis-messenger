export async function onRequestPost(context) {
  const { request } = context;

  try {
    const body = await request.json().catch(() => ({}));
    const { username } = body;

    if (!username || typeof username !== 'string' || username.trim().length === 0) {
      return new Response(JSON.stringify({ valid: false, error: 'Dieser Profilname ist reserviert oder enthält ungültige Zeichen.' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    let normalized = username.normalize('NFKD');

    const homoglyphs = {
      'а': 'a', 'α': 'a', 'в': 'b', 'β': 'b', 'с': 'c', 'ϲ': 'c',
      'ԁ': 'd', 'е': 'e', 'ε': 'e', 'є': 'e', 'ƒ': 'f', 'ɡ': 'g',
      'н': 'h', 'і': 'i', 'ι': 'i', 'ï': 'i', 'ј': 'j', 'к': 'k',
      'κ': 'k', 'м': 'm', 'μ': 'm', 'п': 'n', 'ν': 'n', 'о': 'o',
      'ο': 'o', 'ø': 'o', 'р': 'p', 'ρ': 'p', 'г': 'r', 'ѕ': 's',
      'т': 't', 'τ': 't', 'υ': 'u', 'ω': 'w', 'х': 'x', 'χ': 'x',
      'у': 'y', 'ζ': 'z'
    };

    let mapped = '';
    for (const char of normalized.toLowerCase()) {
      mapped += homoglyphs[char] || char;
    }

    let cleaned = mapped
      .replace(/[\u200B-\u200D\uFEFF\u00A0]/g, '')
      .replace(/4/g, 'a')
      .replace(/@/g, 'a')
      .replace(/3/g, 'e')
      .replace(/1/g, 'i')
      .replace(/!/g, 'i')
      .replace(/\|/g, 'i')
      .replace(/0/g, 'o')
      .replace(/5/g, 's')
      .replace(/\$/g, 's')
      .replace(/7/g, 't')
      .replace(/\+/g, 't')
      .replace(/[^a-z0-9]/g, '');

    const blacklist = [
      "admin", "administrator", "support", "aegis", "system", "ceo", "chef", "boss",
      "official", "moderator", "mod", "root", "founder", "service", "help", "dev",
      "developer", "security", "staff", "owner"
    ];

    for (const term of blacklist) {
      if (cleaned.includes(term)) {
        return new Response(JSON.stringify({ valid: false, error: 'Dieser Profilname ist reserviert oder enthält ungültige Zeichen.' }), {
          status: 400,
          headers: { 'Content-Type': 'application/json' }
        });
      }
    }

    return new Response(JSON.stringify({ valid: true, message: 'Username ist gültig.' }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (err) {
    return new Response(JSON.stringify({ valid: false, error: err.message || 'Validierungsfehler.' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}
