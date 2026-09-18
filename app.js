// AegisChat Client Application Logic
// Zero-Secrets Cloudflare Pages Frontend with WebCrypto E2EE

// Session Storage Keys
const SESSION_KEY = 'aegis_session';
const SESSION_CHAT_PREFIX = 'aegis_chat_';

// App State
let currentUser = null; // { id, username, main_number }
let accessToken = null;
let localKeyPair = null; // { publicKey, privateKey }
let localPubKeyB64 = null;
let contacts = []; // Array of { number, isBurner, pubKeyB64, sharedKey }
let myBurnerNumbers = []; // Array of { id, burner_number, active, expires_at }
let activeContact = null;
let realtimeSocket = null;
let heartbeatTimer = null;
let html5QrScanner = null;
let audioContext = null;
let supabaseUrl = null;
let supabaseAnonKey = null;
let supabaseClient = null;
let realtimeChannel = null;

// --- UTILITY & NOTIFICATION FUNCTIONS ---

function showToast(message, isError = false) {
  const container = document.getElementById('toast-container');
  if (!container) return;
  const toast = document.createElement('div');
  toast.className = 'toast';
  if (isError) {
    toast.style.borderLeftColor = 'var(--danger)';
  }
  toast.textContent = message;
  container.appendChild(toast);
  setTimeout(() => {
    if (toast.parentNode) toast.parentNode.removeChild(toast);
  }, 4000);
}

function playSoundFeedback(type) {
  try {
    if (!audioContext) {
      audioContext = new (window.AudioContext || window.webkitAudioContext)();
    }
    if (audioContext.state === 'suspended') {
      audioContext.resume();
    }
    const osc = audioContext.createOscillator();
    const gain = audioContext.createGain();
    osc.connect(gain);
    gain.connect(audioContext.destination);

    const now = audioContext.currentTime;
    if (type === 'send') {
      osc.frequency.setValueAtTime(440, now);
      osc.frequency.exponentialRampToValueAtTime(880, now + 0.1);
      gain.gain.setValueAtTime(0.15, now);
      gain.gain.exponentialRampToValueAtTime(0.01, now + 0.1);
      osc.start(now);
      osc.stop(now + 0.1);
    } else if (type === 'receive') {
      osc.frequency.setValueAtTime(880, now);
      osc.frequency.exponentialRampToValueAtTime(587.33, now + 0.15);
      gain.gain.setValueAtTime(0.2, now);
      gain.gain.exponentialRampToValueAtTime(0.01, now + 0.15);
      osc.start(now);
      osc.stop(now + 0.15);
    }
  } catch (e) {}
}

function generate8DigitId() {
  return Math.floor(10000000 + Math.random() * 90000000).toString();
}

function escapeHtml(text) {
  return String(text)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

// --- WEBCRYPTO API: ECDH (P-256), PBKDF2 & AES-GCM ---

async function generateEcdhKeyPair() {
  return await window.crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveKey", "deriveBits"]
  );
}

async function exportPublicKey(key) {
  const exported = await window.crypto.subtle.exportKey("jwk", key);
  return btoa(JSON.stringify(exported));
}

async function importPublicKey(jwkB64) {
  const jwk = JSON.parse(atob(jwkB64));
  return await window.crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "ECDH", namedCurve: "P-256" },
    true,
    []
  );
}

async function deriveSharedAesKey(privateKey, peerPublicKey) {
  return await window.crypto.subtle.deriveKey(
    { name: "ECDH", public: peerPublicKey },
    privateKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function derivePasswordKey(password, salt) {
  const enc = new TextEncoder();
  const keyMaterial = await window.crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveKey"]
  );
  return await window.crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: salt,
      iterations: 100000,
      hash: "SHA-256"
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function encryptPrivateKey(privateKey, password) {
  const jwk = await window.crypto.subtle.exportKey("jwk", privateKey);
  const jwkString = JSON.stringify(jwk);
  const salt = window.crypto.getRandomValues(new Uint8Array(16));
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const aesKey = await derivePasswordKey(password, salt);

  const enc = new TextEncoder();
  const encryptedBuffer = await window.crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv },
    aesKey,
    enc.encode(jwkString)
  );

  return JSON.stringify({
    encryptedJwkB64: btoa(String.fromCharCode(...new Uint8Array(encryptedBuffer))),
    saltB64: btoa(String.fromCharCode(...salt)),
    ivB64: btoa(String.fromCharCode(...iv))
  });
}

async function decryptPrivateKey(encryptedDataStr, password) {
  const encryptedData = JSON.parse(encryptedDataStr);
  const salt = new Uint8Array(atob(encryptedData.saltB64).split('').map(c => c.charCodeAt(0)));
  const iv = new Uint8Array(atob(encryptedData.ivB64).split('').map(c => c.charCodeAt(0)));
  const binaryEncrypted = atob(encryptedData.encryptedJwkB64);
  const encryptedBytes = new Uint8Array(binaryEncrypted.length);
  for (let i = 0; i < binaryEncrypted.length; i++) {
    encryptedBytes[i] = binaryEncrypted.charCodeAt(i);
  }

  const aesKey = await derivePasswordKey(password, salt);
  const decryptedBuffer = await window.crypto.subtle.decrypt(
    { name: "AES-GCM", iv: iv },
    aesKey,
    encryptedBytes.buffer
  );

  const jwkString = new TextDecoder().decode(decryptedBuffer);
  const jwk = JSON.parse(jwkString);

  return await window.crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveKey", "deriveBits"]
  );
}

async function encryptPayload(text, sharedKey) {
  const enc = new TextEncoder();
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const ciphertextBuffer = await window.crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv },
    sharedKey,
    enc.encode(text)
  );

  return JSON.stringify({
    ivB64: btoa(String.fromCharCode(...iv)),
    ciphertextB64: btoa(String.fromCharCode(...new Uint8Array(ciphertextBuffer)))
  });
}

async function decryptPayload(payloadJsonStr, sharedKey) {
  const data = JSON.parse(payloadJsonStr);
  const iv = new Uint8Array(atob(data.ivB64).split('').map(c => c.charCodeAt(0)));
  const binaryCiphertext = atob(data.ciphertextB64);
  const ciphertextBytes = new Uint8Array(binaryCiphertext.length);
  for (let i = 0; i < binaryCiphertext.length; i++) {
    ciphertextBytes[i] = binaryCiphertext.charCodeAt(i);
  }

  const decryptedBuffer = await window.crypto.subtle.decrypt(
    { name: "AES-GCM", iv: iv },
    sharedKey,
    ciphertextBytes.buffer
  );

  return new TextDecoder().decode(decryptedBuffer);
}

// --- BACKEND HEALTH CHECK ---

async function checkBackendHealth() {
  try {
    const res = await fetch('/api/health');
    const data = await res.json();
    if (data.supabaseUrl) supabaseUrl = data.supabaseUrl;
    if (data.supabaseAnonKey) supabaseAnonKey = data.supabaseAnonKey;
    if (!res.ok || data.error) {
      showToast(data.error || "Fehler beim Verbinden mit dem Cloudflare Worker / Supabase.", true);
    }
  } catch (err) {
    showToast("Backend /api/health nicht erreichbar. Bitte Cloudflare Secrets prüfen.", true);
  }
}

// --- INITIALIZATION & SESSION MANAGEMENT ---

document.addEventListener('DOMContentLoaded', async () => {
  await checkBackendHealth();
  checkSessionState();
  setupEventListeners();
});

function checkSessionState() {
  const sessionStr = sessionStorage.getItem(SESSION_KEY);
  if (sessionStr) {
    try {
      const sess = JSON.parse(sessionStr);
      currentUser = sess.user;
      accessToken = sess.accessToken;
      localPubKeyB64 = sess.pubKeyB64;

      Promise.all([
        importPublicKey(sess.pubKeyB64),
        window.crypto.subtle.importKey("jwk", JSON.parse(atob(sess.privKeyJwkB64)), { name: "ECDH", namedCurve: "P-256" }, true, ["deriveKey", "deriveBits"])
      ]).then(([pubKey, privKey]) => {
        localKeyPair = { publicKey: pubKey, privateKey: privKey };
        initMainChatUI();
      }).catch(err => {
        console.error("Session restore key import error:", err);
        clearSessionData();
      });
      return;
    } catch (e) {
      clearSessionData();
    }
  }

  document.getElementById('landing-page').classList.remove('hidden');
  document.getElementById('app').classList.add('hidden');
}

async function saveSessionData() {
  if (!currentUser || !localKeyPair) return;
  const jwkPriv = await window.crypto.subtle.exportKey("jwk", localKeyPair.privateKey);
  const privKeyJwkB64 = btoa(JSON.stringify(jwkPriv));

  const sessionObj = {
    user: currentUser,
    accessToken: accessToken,
    pubKeyB64: localPubKeyB64,
    privKeyJwkB64: privKeyJwkB64
  };
  sessionStorage.setItem(SESSION_KEY, JSON.stringify(sessionObj));
}

function clearSessionData() {
  sessionStorage.clear();
  currentUser = null;
  accessToken = null;
  localKeyPair = null;
  localPubKeyB64 = null;
  contacts = [];
  myBurnerNumbers = [];
  activeContact = null;
  if (realtimeChannel && supabaseClient) {
    try { supabaseClient.removeChannel(realtimeChannel); } catch (e) {}
    realtimeChannel = null;
  }
  if (heartbeatTimer) {
    clearInterval(heartbeatTimer);
    heartbeatTimer = null;
  }
  if (realtimeSocket) {
    realtimeSocket.close();
    realtimeSocket = null;
  }
  document.getElementById('landing-page').classList.remove('hidden');
  document.getElementById('app').classList.add('hidden');
}

// --- DOM EVENT LISTENERS ---

function setupEventListeners() {
  const showRegBtn = document.getElementById('show-register-modal-btn');
  const showLoginBtn = document.getElementById('show-login-modal-btn');
  const regModal = document.getElementById('register-modal');
  const loginModal = document.getElementById('login-modal');

  showRegBtn.addEventListener('click', () => regModal.classList.remove('hidden'));
  document.getElementById('close-register-modal-btn').addEventListener('click', () => regModal.classList.add('hidden'));

  showLoginBtn.addEventListener('click', () => loginModal.classList.remove('hidden'));
  document.getElementById('close-login-modal-btn').addEventListener('click', () => loginModal.classList.add('hidden'));

  document.getElementById('submit-register-btn').addEventListener('click', handleRegistration);
  document.getElementById('submit-login-btn').addEventListener('click', handleLogin);

  document.getElementById('logout-btn').addEventListener('click', handleLogout);
  document.getElementById('mobile-logout-btn').addEventListener('click', handleLogout);

  document.getElementById('add-contact-btn').addEventListener('click', handleAddContact);
  document.getElementById('send-message-form').addEventListener('submit', handleSendMessage);

  document.getElementById('manage-burners-btn').addEventListener('click', () => {
    renderBurnerList();
    document.getElementById('burner-modal').classList.remove('hidden');
  });
  document.getElementById('close-burner-modal-btn').addEventListener('click', () => {
    document.getElementById('burner-modal').classList.add('hidden');
  });
  document.getElementById('generate-burner-btn').addEventListener('click', handleGenerateBurner);

  document.getElementById('show-qr-btn').addEventListener('click', () => {
    document.getElementById('qr-modal-title').textContent = "Haupt-ID QR-Code";
    document.getElementById('qr-modal-subtext').textContent = `Scanne diesen Code, um Nachrichten an Haupt-ID ${currentUser.main_number} zu senden.`;
    displayQrCode(currentUser.main_number);
    document.getElementById('qr-modal').classList.remove('hidden');
  });
  document.getElementById('close-qr-modal-btn').addEventListener('click', () => {
    document.getElementById('qr-modal').classList.add('hidden');
  });
  document.getElementById('copy-qr-number-btn').addEventListener('click', () => {
    const num = document.getElementById('copy-qr-number-btn').getAttribute('data-number') || currentUser.main_number;
    navigator.clipboard.writeText(num);
    showToast(`Nummer ${num} kopiert!`);
  });

  document.getElementById('scan-qr-btn').addEventListener('click', startQrScanner);
  document.getElementById('close-scanner-modal-btn').addEventListener('click', stopQrScanner);

  document.getElementById('mobile-toggle-btn').addEventListener('click', () => {
    document.getElementById('sidebar').classList.toggle('mobile-hidden');
  });
  document.getElementById('mobile-back-btn').addEventListener('click', () => {
    document.getElementById('sidebar').classList.remove('mobile-hidden');
  });
}

// --- REGISTRATION & LOGIN LOGIC ---

async function handleRegistration() {
  const username = document.getElementById('reg-username').value.trim();
  const password = document.getElementById('reg-password').value;
  const statusEl = document.getElementById('register-status');
  const submitBtn = document.getElementById('submit-register-btn');

  if (!username || !password) {
    statusEl.textContent = 'Bitte Nutzername und Passwort ausfüllen.';
    return;
  }
  if (password.length < 6) {
    statusEl.textContent = 'Das Passwort muss mindestens 6 Zeichen lang sein.';
    return;
  }

  submitBtn.disabled = true;
  statusEl.textContent = 'Generiere ECDH Schlüsselpaar & erstelle Konto...';

  try {
    const mainNumber = generate8DigitId();
    const keyPair = await generateEcdhKeyPair();
    const pubKeyB64 = await exportPublicKey(keyPair.publicKey);
    const encryptedPrivateKeyStr = await encryptPrivateKey(keyPair.privateKey, password);

    const res = await fetch('/api/auth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: username,
        password: password,
        main_number: mainNumber,
        encrypted_private_key: encryptedPrivateKeyStr,
        public_key: pubKeyB64
      })
    });

    const data = await res.json();
    if (!res.ok || data.error) {
      throw new Error(data.error || 'Registrierung fehlgeschlagen.');
    }

    currentUser = data.user;
    accessToken = data.access_token;
    localKeyPair = keyPair;
    localPubKeyB64 = pubKeyB64;

    await saveSessionData();
    document.getElementById('register-modal').classList.add('hidden');
    showToast(`Registrierung erfolgreich! Haupt-ID: ${mainNumber}`);
    initMainChatUI();
  } catch (err) {
    statusEl.textContent = `Fehler: ${err.message}`;
    showToast(err.message, true);
  } finally {
    submitBtn.disabled = false;
  }
}

async function handleLogin() {
  const identifier = document.getElementById('login-user-identifier').value.trim();
  const password = document.getElementById('login-password').value;
  const statusEl = document.getElementById('login-status');
  const submitBtn = document.getElementById('submit-login-btn');

  if (!identifier || !password) {
    statusEl.textContent = 'Bitte Nutzername/ID und Passwort eingeben.';
    return;
  }

  submitBtn.disabled = true;
  statusEl.textContent = 'Melde an und entschlüssele Private Key...';

  try {
    const res = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        identifier: identifier,
        password: password
      })
    });

    const data = await res.json();
    if (!res.ok || data.error) {
      throw new Error(data.error || 'Anmeldung fehlgeschlagen.');
    }

    const privateKey = await decryptPrivateKey(data.profile.encrypted_private_key, password);
    const publicKey = await importPublicKey(data.profile.public_key);

    currentUser = data.user;
    accessToken = data.access_token;
    localKeyPair = { publicKey, privateKey };
    localPubKeyB64 = data.profile.public_key;

    await saveSessionData();
    document.getElementById('login-modal').classList.add('hidden');
    showToast("Erfolgreich angemeldet!");
    initMainChatUI();
  } catch (err) {
    statusEl.textContent = `Fehler: ${err.message}`;
    showToast(err.message, true);
  } finally {
    submitBtn.disabled = false;
  }
}

function handleLogout() {
  clearSessionData();
  showToast("Abgemeldet & Keys aus RAM gelöscht");
  location.reload();
}

// --- MAIN CHAT INTERFACE LOGIC ---

async function initMainChatUI() {
  document.getElementById('landing-page').classList.add('hidden');
  document.getElementById('app').classList.remove('hidden');

  document.getElementById('my-avatar').textContent = currentUser.username.slice(0, 2).toUpperCase();
  document.getElementById('my-username').textContent = currentUser.username;
  document.getElementById('my-id').textContent = `ID: ${currentUser.main_number}`;

  await fetchMyBurnerNumbers();
  updateSenderDropdown();
  loadStoredContacts();
  connectRealtimeWebSocket();
}

function updateSenderDropdown() {
  const select = document.getElementById('send-as-select');
  select.innerHTML = '';

  const optMain = document.createElement('option');
  optMain.value = currentUser.main_number;
  optMain.textContent = `Haupt-ID (${currentUser.main_number})`;
  select.appendChild(optMain);

  myBurnerNumbers.filter(b => b.active).forEach(b => {
    const opt = document.createElement('option');
    opt.value = b.burner_number;
    opt.textContent = `Burner (${b.burner_number})`;
    select.appendChild(opt);
  });
}

// --- BURNER NUMBERS MANAGEMENT ---

async function fetchMyBurnerNumbers() {
  if (!currentUser) return;
  try {
    const res = await fetch(`/api/burners?user_id=${currentUser.id}`, {
      headers: accessToken ? { 'Authorization': `Bearer ${accessToken}` } : {}
    });
    if (res.ok) {
      const data = await res.json();
      const now = new Date();
      myBurnerNumbers = data.map(b => {
        if (b.expires_at && new Date(b.expires_at) <= now) {
          b.active = false;
        }
        return b;
      });
    }
  } catch (e) {
    console.error("Fetch burners error:", e);
  }
}

async function handleGenerateBurner() {
  const expiryType = document.getElementById('burner-expiry-select').value;
  let expiresAt = null;

  if (expiryType === '1h') {
    expiresAt = new Date(Date.now() + 3600 * 1000).toISOString();
  } else if (expiryType === '24h') {
    expiresAt = new Date(Date.now() + 24 * 3600 * 1000).toISOString();
  } else if (expiryType === '7d') {
    expiresAt = new Date(Date.now() + 7 * 24 * 3600 * 1000).toISOString();
  }

  const newBurnerNumber = generate8DigitId();
  const btn = document.getElementById('generate-burner-btn');
  btn.disabled = true;

  try {
    const res = await fetch('/api/burners', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(accessToken ? { 'Authorization': `Bearer ${accessToken}` } : {})
      },
      body: JSON.stringify({
        user_id: currentUser.id,
        burner_number: newBurnerNumber,
        active: true,
        expires_at: expiresAt
      })
    });

    const data = await res.json();
    if (!res.ok || data.error) {
      throw new Error(data.error || 'Erstellen der Einweg-Nummer fehlgeschlagen.');
    }

    myBurnerNumbers.push(Array.isArray(data) ? data[0] : data);
    updateSenderDropdown();
    renderBurnerList();
    showToast(`Einweg-Nummer ${newBurnerNumber} erstellt!`);
  } catch (err) {
    showToast(err.message, true);
  } finally {
    btn.disabled = false;
  }
}

function renderBurnerList() {
  const list = document.getElementById('burner-list');
  list.innerHTML = '';

  if (myBurnerNumbers.length === 0) {
    list.innerHTML = '<li style="color: var(--text-muted); font-size: 13px;">Keine Einweg-Nummern vorhanden.</li>';
    return;
  }

  myBurnerNumbers.forEach(b => {
    const li = document.createElement('li');
    li.className = 'burner-item';

    const expiryText = b.expires_at
      ? `Ablauf: ${new Date(b.expires_at).toLocaleString()}`
      : 'Kein Verfall';

    const statusBadge = b.active
      ? '<span style="color: #10b981; font-weight: 600;">Aktiv</span>'
      : '<span style="color: #ef4444; font-weight: 600;">Inaktiv / Abgelaufen</span>';

    li.innerHTML = `
      <div class="burner-info">
        <span class="burner-num">${b.burner_number}</span>
        <span class="burner-expiry">${expiryText} • ${statusBadge}</span>
      </div>
      <div class="burner-actions">
        <button class="icon-btn qr-btn" title="QR-Code"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg></button>
        <button class="icon-btn delete-btn" title="Löschen"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg></button>
      </div>
    `;

    li.querySelector('.qr-btn').addEventListener('click', () => {
      document.getElementById('qr-modal-title').textContent = "Einweg-Nummer QR-Code";
      document.getElementById('qr-modal-subtext').textContent = `Scanne diesen Code für anonymen Empfang an ${b.burner_number}.`;
      displayQrCode(b.burner_number);
      document.getElementById('qr-modal').classList.remove('hidden');
    });

    li.querySelector('.delete-btn').addEventListener('click', async () => {
      if (confirm(`Möchtest du Einweg-Nummer ${b.burner_number} wirklich löschen?`)) {
        await fetch(`/api/burners?id=${b.id}`, {
          method: 'DELETE',
          headers: accessToken ? { 'Authorization': `Bearer ${accessToken}` } : {}
        });
        myBurnerNumbers = myBurnerNumbers.filter(x => x.id !== b.id);
        updateSenderDropdown();
        renderBurnerList();
        showToast(`Einweg-Nummer ${b.burner_number} gelöscht.`);
      }
    });

    list.appendChild(li);
  });
}

// --- CONTACTS & MESSAGING LOGIC ---

async function handleAddContact() {
  const input = document.getElementById('peer-number-input');
  const number = input.value.trim();

  if (number.length !== 8 || !/^\d{8}$/.test(number)) {
    showToast('Bitte eine gültige 8-stellige ID oder Einweg-Nummer eingeben.', true);
    return;
  }

  try {
    await addOrResolveContact(number);
    input.value = '';
  } catch (err) {
    showToast(`Fehler beim Auflösen: ${err.message}`, true);
  }
}

async function addOrResolveContact(number) {
  let existing = contacts.find(c => c.number === number);
  if (existing) {
    selectContact(existing);
    return existing;
  }

  const res = await fetch(`/api/profiles/resolve?number=${number}`);
  const data = await res.json();

  if (!res.ok || data.error) {
    throw new Error(data.error || 'Nummer konnte nicht aufgelöst werden.');
  }

  const peerPubKeyObj = await importPublicKey(data.public_key);
  const sharedKey = await deriveSharedAesKey(localKeyPair.privateKey, peerPubKeyObj);

  const newContact = {
    number: data.number,
    isBurner: data.isBurner,
    pubKeyB64: data.public_key,
    sharedKey: sharedKey
  };

  contacts.push(newContact);
  saveContactsToSession();
  renderContacts();
  selectContact(newContact);
  showToast(`Chat mit ${number} gestartet.`);
  return newContact;
}

function loadStoredContacts() {
  const stored = sessionStorage.getItem('aegis_contacts');
  if (stored) {
    try {
      const arr = JSON.parse(stored);
      contacts = [];
      arr.forEach(async c => {
        try {
          const peerKey = await importPublicKey(c.pubKeyB64);
          const sharedKey = await deriveSharedAesKey(localKeyPair.privateKey, peerKey);
          contacts.push({
            number: c.number,
            isBurner: c.isBurner,
            pubKeyB64: c.pubKeyB64,
            sharedKey
          });
          renderContacts();
        } catch (e) {}
      });
    } catch (e) {}
  }
}

function saveContactsToSession() {
  const serializable = contacts.map(c => ({
    number: c.number,
    isBurner: c.isBurner,
    pubKeyB64: c.pubKeyB64
  }));
  sessionStorage.setItem('aegis_contacts', JSON.stringify(serializable));
}

function renderContacts() {
  const list = document.getElementById('contacts-list');
  list.innerHTML = '';

  if (contacts.length === 0) {
    list.innerHTML = '<li style="color: var(--text-muted); font-size: 13px; text-align: center; padding: 12px;">Noch keine Chats vorhanden.</li>';
    return;
  }

  contacts.forEach(c => {
    const li = document.createElement('li');
    li.className = `contact-item ${activeContact && activeContact.number === c.number ? 'active' : ''}`;
    const tag = c.isBurner ? '<span class="contact-type-tag">Burner</span>' : '';

    li.innerHTML = `
      <div class="avatar">${c.number.slice(0, 2)}</div>
      <div class="contact-id">${c.number}</div>
      ${tag}
    `;
    li.addEventListener('click', () => selectContact(c));
    list.appendChild(li);
  });
}

function selectContact(contact) {
  activeContact = contact;
  renderContacts();

  document.getElementById('empty-state').classList.add('hidden');
  document.getElementById('chat-header').classList.remove('hidden');
  document.getElementById('messages-container').classList.remove('hidden');
  document.getElementById('send-message-form').classList.remove('hidden');

  if (window.innerWidth <= 768) {
    document.getElementById('sidebar').classList.add('mobile-hidden');
  }

  document.getElementById('active-avatar').textContent = contact.number.slice(0, 2);
  document.getElementById('active-contact-name').textContent = `Chat ID: ${contact.number}`;

  loadAndRenderChatHistory(contact.number);
}

async function handleSendMessage(e) {
  e.preventDefault();
  const input = document.getElementById('message-input');
  const text = input.value.trim();
  if (!text || !activeContact) return;

  try {
    const senderNumber = document.getElementById('send-as-select').value || currentUser.main_number;
    const recipientNumber = activeContact.number;

    const encryptedPayloadStr = await encryptPayload(text, activeContact.sharedKey);

    const res = await fetch('/api/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(accessToken ? { 'Authorization': `Bearer ${accessToken}` } : {})
      },
      body: JSON.stringify({
        sender_number: senderNumber,
        recipient_number: recipientNumber,
        encrypted_payload: encryptedPayloadStr
      })
    });

    if (!res.ok) {
      throw new Error('Fehler beim Senden der Nachricht.');
    }

    const msgObj = {
      sender_number: senderNumber,
      recipient_number: recipientNumber,
      text: text,
      type: 'own',
      timestamp: Date.now()
    };

    appendMessageUI(msgObj);
    saveChatMessage(recipientNumber, msgObj);
    input.value = '';
    playSoundFeedback('send');
  } catch (err) {
    showToast(err.message, true);
  }
}

function getChatHistory(contactNumber) {
  const stored = sessionStorage.getItem(SESSION_CHAT_PREFIX + contactNumber);
  if (!stored) return [];
  try { return JSON.parse(stored); } catch (e) { return []; }
}

function saveChatMessage(contactNumber, msgObj) {
  const history = getChatHistory(contactNumber);
  history.push(msgObj);
  sessionStorage.setItem(SESSION_CHAT_PREFIX + contactNumber, JSON.stringify(history));
}

function loadAndRenderChatHistory(contactNumber) {
  const container = document.getElementById('messages-container');
  container.innerHTML = '';
  const history = getChatHistory(contactNumber);
  history.forEach(msg => appendMessageUI(msg));
  container.scrollTop = container.scrollHeight;
}

function appendMessageUI(msgObj) {
  const container = document.getElementById('messages-container');
  const time = new Date(msgObj.timestamp || Date.now()).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  const div = document.createElement('div');
  div.className = `msg-bubble ${msgObj.type}`;

  const senderMeta = msgObj.type === 'own' ? `An: ${msgObj.recipient_number}` : `Von: ${msgObj.sender_number}`;

  div.innerHTML = `
    <div style="font-size: 11px; opacity: 0.8; font-family: var(--font-mono); margin-bottom: 2px;">${senderMeta}</div>
    <div>${escapeHtml(msgObj.text)}</div>
    <div class="msg-meta">
      <span>${time}</span>
    </div>
  `;
  container.appendChild(div);
  container.scrollTop = container.scrollHeight;
}

// --- QR CODE & SCANNER ---

function displayQrCode(text) {
  const container = document.getElementById('qr-code-container');
  container.innerHTML = '';
  document.getElementById('copy-qr-number-btn').setAttribute('data-number', text);
  if (typeof QRCode !== 'undefined') {
    new QRCode(container, {
      text: text,
      width: 180,
      height: 180,
      colorDark: "#000000",
      colorLight: "#ffffff",
      correctLevel: QRCode.CorrectLevel.L
    });
  }
}

function startQrScanner() {
  document.getElementById('scanner-modal').classList.remove('hidden');
  if (typeof Html5Qrcode !== 'undefined') {
    html5QrScanner = new Html5Qrcode("qr-reader");
    html5QrScanner.start(
      { facingMode: "environment" },
      { fps: 10, qrbox: { width: 220, height: 220 } },
      (decodedText) => {
        document.getElementById('peer-number-input').value = decodedText.trim();
        stopQrScanner();
        showToast("QR-Code gescannt!");
      },
      () => {}
    ).catch(err => console.error("Scanner error:", err));
  }
}

function stopQrScanner() {
  document.getElementById('scanner-modal').classList.add('hidden');
  if (html5QrScanner) {
    html5QrScanner.stop().then(() => {
      html5QrScanner.clear();
      html5QrScanner = null;
    }).catch(() => {});
  }
}

// --- REALTIME MESSAGING WEBSOCKET STREAM (SUPABASE / PHOENIX PROTOCOL) ---

function getMyAllNumbers() {
  if (!currentUser) return [];
  const list = [currentUser.main_number];
  myBurnerNumbers.filter(b => b.active).forEach(b => list.push(b.burner_number));
  return list;
}

async function handleIncomingMessage(record) {
  if (!record || !record.recipient_number) return;
  const myNumbers = getMyAllNumbers();

  if (myNumbers.includes(record.recipient_number)) {
    const senderNumber = record.sender_number;
    let contact = contacts.find(c => c.number === senderNumber);

    if (!contact) {
      contact = await addOrResolveContact(senderNumber);
    }

    const decryptedText = await decryptPayload(record.encrypted_payload, contact.sharedKey);

    const msgObj = {
      sender_number: senderNumber,
      recipient_number: record.recipient_number,
      text: decryptedText,
      type: 'other',
      timestamp: record.created_at ? new Date(record.created_at).getTime() : Date.now()
    };

    saveChatMessage(senderNumber, msgObj);
    playSoundFeedback('receive');

    if (activeContact && activeContact.number === senderNumber) {
      appendMessageUI(msgObj);
    } else {
      showToast(`Neue E2EE Nachricht von ${senderNumber}!`);
    }
  }
}

function connectRealtimeWebSocket() {
  const dot = document.getElementById('realtime-status-dot');

  if (realtimeChannel) {
    try {
      if (supabaseClient) supabaseClient.removeChannel(realtimeChannel);
    } catch (e) {}
    realtimeChannel = null;
  }
  if (heartbeatTimer) {
    clearInterval(heartbeatTimer);
    heartbeatTimer = null;
  }

  // 1. Direct WebSocket Connection via Supabase JS Client (if configured)
  if (window.supabase && supabaseUrl && supabaseAnonKey) {
    try {
      if (!supabaseClient) {
        supabaseClient = window.supabase.createClient(supabaseUrl, supabaseAnonKey);
      }

      realtimeChannel = supabaseClient
        .channel('schema-db-changes')
        .on(
          'postgres_changes',
          {
            event: 'INSERT',
            schema: 'public',
            table: 'messages'
          },
          async (payload) => {
            console.log('RECEIVED REALTIME PAYLOAD:', payload);
            if (payload && payload.new) {
              try {
                await handleIncomingMessage(payload.new);
              } catch (err) {
                console.error('Error processing realtime payload:', err);
              }
            }
          }
        )
        .subscribe((status, err) => {
          console.log('REALTIME STATUS:', status, err);
          if (status === 'SUBSCRIBED') {
            if (dot) {
              dot.className = 'dot online';
              dot.title = "Realtime Verbindung aktiv (SUBSCRIBED)";
            }
          } else if (status === 'CLOSED' || status === 'CHANNEL_ERROR' || status === 'TIMED_OUT') {
            if (dot) {
              dot.className = 'dot offline';
              dot.title = `Realtime Status: ${status}`;
            }
          }
        });
      return;
    } catch (err) {
      console.error('Error creating Supabase Realtime client:', err);
    }
  }

  // 2. Fallback to HTTP Proxy / Local WebSocket server
  const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
  const wsUrl = `${protocol}//${location.host}/api/realtime`;

  try {
    realtimeSocket = new WebSocket(wsUrl);

    realtimeSocket.onopen = () => {
      console.log('REALTIME STATUS: WebSocket OPEN (Fallback)');
      if (dot) {
        dot.className = 'dot online';
        dot.title = "Realtime Verbindung aktiv";
      }

      const joinMsg = {
        topic: "realtime:public:messages",
        event: "phx_join",
        payload: {
          config: {
            postgres_changes: [
              {
                event: "INSERT",
                schema: "public",
                table: "messages"
              }
            ]
          }
        },
        ref: "1"
      };
      realtimeSocket.send(JSON.stringify(joinMsg));

      heartbeatTimer = setInterval(() => {
        if (realtimeSocket && realtimeSocket.readyState === WebSocket.OPEN) {
          realtimeSocket.send(JSON.stringify({
            topic: "phoenix",
            event: "heartbeat",
            payload: {},
            ref: "hb"
          }));
        }
      }, 25000);
    };

    realtimeSocket.onmessage = async (event) => {
      try {
        const message = JSON.parse(event.data);
        console.log('RECEIVED REALTIME PAYLOAD (WS):', message);
        const payload = message.payload || {};
        const record = payload.record || (payload.data && payload.data.record) || payload.new;

        if (record && (message.event === 'postgres_changes' || message.event === 'INSERT' || payload.type === 'INSERT')) {
          await handleIncomingMessage(record);
        }
      } catch (e) {
        console.error('Error processing WS message:', e);
      }
    };

    realtimeSocket.onerror = (err) => {
      console.log('REALTIME STATUS: CHANNEL_ERROR', err);
      if (dot) {
        dot.className = 'dot offline';
        dot.title = "Realtime Verbindung getrennt";
      }
    };

    realtimeSocket.onclose = () => {
      console.log('REALTIME STATUS: CLOSED');
      if (dot) {
        dot.className = 'dot offline';
      }
      if (heartbeatTimer) clearInterval(heartbeatTimer);
      setTimeout(connectRealtimeWebSocket, 5000);
    };
  } catch (err) {
    if (dot) dot.className = 'dot offline';
  }
}
