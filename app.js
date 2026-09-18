// AegisChat Client Application Logic with Supabase Backend & E2EE (ECDH + AES-GCM / PBKDF2 Key Wrapping)

// LOCAL STORAGE & SESSION STORAGE KEYS
const LS_SB_URL = 'aegis_sb_url';
const LS_SB_KEY = 'aegis_sb_key';
const SESSION_CHAT_PREFIX = 'aegis_chat_';

// State Variables
let supabaseClient = null;
let currentProfile = null; // { id, username, main_number, encrypted_private_key, public_key }
let decryptedKeyPair = null; // { publicKey, privateKey } (CryptoKey objects, ONLY in memory)
let myBurnerNumbers = []; // Array of disposable numbers { id, burner_number, active, expires_at }
let activeContact = null; // { number, public_key }
let contactsMap = new Map(); // number -> { number, public_key, username }
let realtimeChannel = null;
let html5QrScanner = null;
let audioContext = null;

// Fake internal domain for Supabase Auth without real emails
const DUMMY_EMAIL_DOMAIN = '@aegischat.internal';

// --- UTILITY FUNCTIONS ---

function showToast(message) {
  const container = document.getElementById('toast-container');
  if (!container) return;
  const toast = document.createElement('div');
  toast.className = 'toast';
  toast.textContent = message;
  container.appendChild(toast);
  setTimeout(() => {
    if (toast.parentNode) toast.parentNode.removeChild(toast);
  }, 3200);
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
  } catch (e) {
    // Audio context initialization error or user gesture constraint
  }
}

function generate8DigitId() {
  return Math.floor(10000000 + Math.random() * 90000000).toString();
}

function escapeHtml(text) {
  return String(text).replace(/&/g, "&amp;")
                     .replace(/</g, "&lt;")
                     .replace(/>/g, "&gt;")
                     .replace(/"/g, "&quot;")
                     .replace(/'/g, "&#039;");
}

// --- WEBCRYPTO FUNCTIONS (ECDH P-256 + AES-GCM + PBKDF2 KEY WRAPPING) ---

// Generate ECDH P-256 Key Pair for Client-Side Message Encryption
async function generateEcdhKeyPair() {
  return await window.crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveKey", "deriveBits"]
  );
}

// Export Public ECDH Key as Base64 JWK
async function exportPublicKey(publicKey) {
  const jwk = await window.crypto.subtle.exportKey("jwk", publicKey);
  return btoa(JSON.stringify(jwk));
}

// Import Public ECDH Key from Base64 JWK
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

// Derive PBKDF2 Key from User Password for Private Key Wrapping
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

// Encrypt Private Key JWK with User Password
async function wrapPrivateKey(privateKey, password) {
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

  return {
    encryptedJwkB64: btoa(String.fromCharCode(...new Uint8Array(encryptedBuffer))),
    saltB64: btoa(String.fromCharCode(...salt)),
    ivB64: btoa(String.fromCharCode(...iv))
  };
}

// Decrypt Private Key JWK with User Password
async function unwrapPrivateKey(encryptedData, password) {
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

// Derive Shared Symmetric AES-GCM Key via ECDH
async function deriveSharedAesKey(myPrivateKey, recipientPublicKey) {
  return await window.crypto.subtle.deriveKey(
    { name: "ECDH", public: recipientPublicKey },
    myPrivateKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

// Encrypt Message Text using ECDH Shared Key
async function encryptMessagePayload(text, myPrivateKey, recipientPublicKey) {
  const sharedAesKey = await deriveSharedAesKey(myPrivateKey, recipientPublicKey);
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const enc = new TextEncoder();

  const encryptedBuffer = await window.crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv },
    sharedAesKey,
    enc.encode(text)
  );

  const payloadObj = {
    iv: btoa(String.fromCharCode(...iv)),
    ciphertext: btoa(String.fromCharCode(...new Uint8Array(encryptedBuffer)))
  };

  return JSON.stringify(payloadObj);
}

// Decrypt Message Text using ECDH Shared Key
async function decryptMessagePayload(encryptedPayloadStr, myPrivateKey, senderPublicKey) {
  const payloadObj = JSON.parse(encryptedPayloadStr);
  const iv = new Uint8Array(atob(payloadObj.iv).split('').map(c => c.charCodeAt(0)));
  const binaryEncrypted = atob(payloadObj.ciphertext);
  const encryptedBytes = new Uint8Array(binaryEncrypted.length);
  for (let i = 0; i < binaryEncrypted.length; i++) {
    encryptedBytes[i] = binaryEncrypted.charCodeAt(i);
  }

  const sharedAesKey = await deriveSharedAesKey(myPrivateKey, senderPublicKey);
  const decryptedBuffer = await window.crypto.subtle.decrypt(
    { name: "AES-GCM", iv: iv },
    sharedAesKey,
    encryptedBytes.buffer
  );

  return new TextDecoder().decode(decryptedBuffer);
}

// --- SUPABASE CLIENT INITIALIZATION & CONFIG ---

function initSupabase() {
  const url = localStorage.getItem(LS_SB_URL);
  const key = localStorage.getItem(LS_SB_KEY);

  if (url && key && window.supabase) {
    try {
      supabaseClient = window.supabase.createClient(url, key);
      return true;
    } catch (e) {
      console.error("Supabase Initialization Error:", e);
    }
  }
  return false;
}

// DOM Elements
const landingPage = document.getElementById('landing-page');
const supabaseConfigBtn = document.getElementById('supabase-config-btn');
const configModal = document.getElementById('config-modal');
const closeConfigModalBtn = document.getElementById('close-config-modal-btn');
const sbUrlInput = document.getElementById('sb-url-input');
const sbKeyInput = document.getElementById('sb-key-input');
const saveConfigBtn = document.getElementById('save-config-btn');

const openRegisterBtn = document.getElementById('open-register-btn');
const registerModal = document.getElementById('register-modal');
const closeRegisterModalBtn = document.getElementById('close-register-modal-btn');
const regUsername = document.getElementById('reg-username');
const regPassword = document.getElementById('reg-password');
const submitRegisterBtn = document.getElementById('submit-register-btn');
const registerStatus = document.getElementById('register-status');

const openLoginBtn = document.getElementById('open-login-btn');
const loginModal = document.getElementById('login-modal');
const closeLoginModalBtn = document.getElementById('close-login-modal-btn');
const loginIdentifier = document.getElementById('login-identifier');
const loginPassword = document.getElementById('login-password');
const submitLoginBtn = document.getElementById('submit-login-btn');
const loginStatus = document.getElementById('login-status');

const appContainer = document.getElementById('app');
const chatScreen = document.getElementById('chat-screen');
const logoutBtn = document.getElementById('logout-btn');
const mobileLogoutBtn = document.getElementById('mobile-logout-btn');
const myAvatar = document.getElementById('my-avatar');
const myUsernameEl = document.getElementById('my-username');
const myIdEl = document.getElementById('my-id');
const wsStatusDot = document.getElementById('ws-status-dot');

const openProfileBtn = document.getElementById('open-profile-btn');
const mobileProfileBtn = document.getElementById('mobile-profile-btn');
const profileModal = document.getElementById('profile-modal');
const closeProfileModalBtn = document.getElementById('close-profile-modal-btn');
const profileMainId = document.getElementById('profile-main-id');
const qrMainIdBtn = document.getElementById('qr-main-id-btn');
const burnerTtlSelect = document.getElementById('burner-ttl-select');
const createBurnerBtn = document.getElementById('create-burner-btn');
const burnerList = document.getElementById('burner-list');

const showQrBtn = document.getElementById('show-qr-btn');
const qrModal = document.getElementById('qr-modal');
const closeQrModalBtn = document.getElementById('close-qr-modal-btn');
const qrCodeContainer = document.getElementById('qr-code-container');
const qrModalTitle = document.getElementById('qr-modal-title');
const qrModalSubtext = document.getElementById('qr-modal-subtext');
const copyQrIdBtn = document.getElementById('copy-qr-id-btn');

const peerIdInput = document.getElementById('peer-id-input');
const addContactBtn = document.getElementById('add-contact-btn');
const scanQrBtn = document.getElementById('scan-qr-btn');
const contactsList = document.getElementById('contacts-list');

const scannerModal = document.getElementById('scanner-modal');
const closeScannerModalBtn = document.getElementById('close-scanner-modal-btn');

const chatHeader = document.getElementById('chat-header');
const emptyState = document.getElementById('empty-state');
const activeAvatar = document.getElementById('active-avatar');
const activeContactName = document.getElementById('active-contact-name');
const messagesContainer = document.getElementById('messages-container');
const sendMessageForm = document.getElementById('send-message-form');
const senderNumberSelect = document.getElementById('sender-number-select');
const messageInput = document.getElementById('message-input');

const mobileToggleBtn = document.getElementById('mobile-toggle-btn');
const mobileBackBtn = document.getElementById('mobile-back-btn');
const sidebar = document.getElementById('sidebar');

document.addEventListener('DOMContentLoaded', () => {
  initSupabase();

  // Populate config fields if stored
  if (sbUrlInput) sbUrlInput.value = localStorage.getItem(LS_SB_URL) || '';
  if (sbKeyInput) sbKeyInput.value = localStorage.getItem(LS_SB_KEY) || '';

  // Config Modal handlers
  supabaseConfigBtn.addEventListener('click', () => configModal.classList.remove('hidden'));
  closeConfigModalBtn.addEventListener('click', () => configModal.classList.add('hidden'));

  saveConfigBtn.addEventListener('click', () => {
    const url = sbUrlInput.value.trim();
    const key = sbKeyInput.value.trim();
    if (!url || !key) {
      alert('Bitte sowohl Supabase URL als auch Anon Key eingeben.');
      return;
    }
    localStorage.setItem(LS_SB_URL, url);
    localStorage.setItem(LS_SB_KEY, key);
    configModal.classList.add('hidden');
    initSupabase();
    showToast("Supabase Konfiguration gespeichert!");
  });

  // Auth Modals Handlers
  openRegisterBtn.addEventListener('click', () => {
    if (!supabaseClient) {
      alert("Bitte zuerst Supabase Konfiguration eintragen!");
      configModal.classList.remove('hidden');
      return;
    }
    registerModal.classList.remove('hidden');
  });
  closeRegisterModalBtn.addEventListener('click', () => registerModal.classList.add('hidden'));

  openLoginBtn.addEventListener('click', () => {
    if (!supabaseClient) {
      alert("Bitte zuerst Supabase Konfiguration eintragen!");
      configModal.classList.remove('hidden');
      return;
    }
    loginModal.classList.remove('hidden');
  });
  closeLoginModalBtn.addEventListener('click', () => loginModal.classList.add('hidden'));

  // Registration Execution
  submitRegisterBtn.addEventListener('click', handleRegistration);

  // Login Execution
  submitLoginBtn.addEventListener('click', handleLogin);

  // Logout Handlers
  logoutBtn.addEventListener('click', handleLogout);
  if (mobileLogoutBtn) mobileLogoutBtn.addEventListener('click', handleLogout);

  // Setup UI Listeners
  setupChatListeners();
});

// --- REGISTRATION LOGIC ---

async function handleRegistration() {
  const username = regUsername.value.trim();
  const password = regPassword.value;

  if (!username || !password) {
    registerStatus.textContent = 'Bitte Username und Passwort ausfüllen.';
    return;
  }

  if (password.length < 6) {
    registerStatus.textContent = 'Das Passwort muss mindestens 6 Zeichen lang sein.';
    return;
  }

  submitRegisterBtn.disabled = true;
  registerStatus.textContent = 'Erzeuge ECDH-Schlüsselpaar & registriere bei Supabase Auth...';

  try {
    const email = `${username.toLowerCase()}${DUMMY_EMAIL_DOMAIN}`;

    // 1. Supabase Auth Signup
    const { data: authData, error: authError } = await supabaseClient.auth.signUp({
      email: email,
      password: password
    });

    if (authError) throw authError;
    if (!authData.user) throw new Error("Benutzererstellung fehlgeschlagen.");

    const userId = authData.user.id;
    const mainNumber = generate8DigitId();

    // 2. Generate Client-Side ECDH KeyPair
    const keyPair = await generateEcdhKeyPair();
    const pubKeyB64 = await exportPublicKey(keyPair.publicKey);

    // 3. Wrap Private Key using PBKDF2 + AES-GCM
    const wrappedPrivateKeyData = await wrapPrivateKey(keyPair.privateKey, password);

    // 4. Insert Profile Row in Supabase DB
    const { error: dbError } = await supabaseClient.from('profiles').insert({
      id: userId,
      username: username,
      main_number: mainNumber,
      encrypted_private_key: wrappedPrivateKeyData,
      public_key: pubKeyB64
    });

    if (dbError) throw dbError;

    registerStatus.textContent = 'Registrierung erfolgreich!';
    showToast('Konto und E2EE-Schlüssel erfolgreich erstellt!');

    // Set state
    currentProfile = {
      id: userId,
      username: username,
      main_number: mainNumber,
      encrypted_private_key: wrappedPrivateKeyData,
      public_key: pubKeyB64
    };
    decryptedKeyPair = keyPair;

    registerModal.classList.add('hidden');
    initMainChatUI();
  } catch (err) {
    console.error("Registration Error:", err);
    registerStatus.textContent = `Fehler: ${err.message || 'Registrierung fehlgeschlagen.'}`;
  } finally {
    submitRegisterBtn.disabled = false;
  }
}

// --- LOGIN LOGIC ---

async function handleLogin() {
  const identifier = loginIdentifier.value.trim();
  const password = loginPassword.value;

  if (!identifier || !password) {
    loginStatus.textContent = 'Bitte ID/Nutzername und Passwort eingeben.';
    return;
  }

  submitLoginBtn.disabled = true;
  loginStatus.textContent = 'Melde an...';

  try {
    let usernameToLogin = identifier;

    // Check if identifier is an 8-digit number -> query profiles table for corresponding username
    if (/^\d{8}$/.test(identifier)) {
      const { data: profileRow, error: pError } = await supabaseClient
        .from('profiles')
        .select('username')
        .eq('main_number', identifier)
        .maybeSingle();

      if (pError || !profileRow) {
        throw new Error('Kein Profil mit dieser 8-stelligen Haupt-ID gefunden.');
      }
      usernameToLogin = profileRow.username;
    }

    const email = `${usernameToLogin.toLowerCase()}${DUMMY_EMAIL_DOMAIN}`;

    // 1. Supabase Auth Login
    const { data: authData, error: authError } = await supabaseClient.auth.signInWithPassword({
      email: email,
      password: password
    });

    if (authError) throw authError;

    // 2. Fetch Profile Row from Supabase
    const { data: profileRow, error: profileError } = await supabaseClient
      .from('profiles')
      .select('*')
      .eq('id', authData.user.id)
      .single();

    if (profileError || !profileRow) throw new Error("Profil nicht gefunden.");

    loginStatus.textContent = 'Entschlüssele Private Key via PBKDF2...';

    // 3. Unwrap Private Key locally
    const privateKey = await unwrapPrivateKey(profileRow.encrypted_private_key, password);
    const publicKey = await importPublicKey(profileRow.public_key);

    currentProfile = profileRow;
    decryptedKeyPair = { publicKey, privateKey };

    loginStatus.textContent = 'Anmeldung erfolgreich!';
    showToast('Erfolgreich angemeldet & Private Key entschlüsselt!');

    loginModal.classList.add('hidden');
    initMainChatUI();
  } catch (err) {
    console.error("Login Error:", err);
    loginStatus.textContent = `Fehler: ${err.message || 'Anmeldung fehlgeschlagen.'}`;
  } finally {
    submitLoginBtn.disabled = false;
  }
}

function handleLogout() {
  if (supabaseClient) {
    supabaseClient.auth.signOut();
  }
  if (realtimeChannel) {
    supabaseClient.removeChannel(realtimeChannel);
    realtimeChannel = null;
  }
  currentProfile = null;
  decryptedKeyPair = null;
  myBurnerNumbers = [];
  activeContact = null;
  contactsMap.clear();

  landingPage.classList.remove('hidden');
  appContainer.classList.add('hidden');
  showToast("Erfolgreich abgemeldet.");
}

// --- MAIN CHAT & UI INITIALIZATION ---

async function initMainChatUI() {
  landingPage.classList.add('hidden');
  appContainer.classList.remove('hidden');

  myAvatar.textContent = currentProfile.username.slice(0, 2).toUpperCase();
  myUsernameEl.textContent = currentProfile.username;
  myIdEl.textContent = `Haupt-ID: ${currentProfile.main_number}`;
  profileMainId.textContent = currentProfile.main_number;

  await loadBurnerNumbers();
  updateSenderSelectOptions();
  subscribeToRealtimeMessages();
  renderContacts();
}

// --- DISPOSABLE NUMBERS (BURNER IDs) MANAGEMENT ---

async function loadBurnerNumbers() {
  if (!supabaseClient || !currentProfile) return;

  const { data, error } = await supabaseClient
    .from('disposable_numbers')
    .select('*')
    .eq('user_id', currentProfile.id)
    .eq('active', true);

  if (error) {
    console.error("Error loading burner numbers:", error);
    return;
  }

  // Filter out expired numbers
  const now = new Date();
  myBurnerNumbers = (data || []).filter(item => {
    if (item.expires_at && new Date(item.expires_at) <= now) {
      return false;
    }
    return true;
  });

  renderBurnerListUI();
  updateSenderSelectOptions();
}

function renderBurnerListUI() {
  burnerList.innerHTML = '';

  if (myBurnerNumbers.length === 0) {
    burnerList.innerHTML = '<li class="empty-burner">Keine aktiven Einweg-Nummern. Erstelle eine oben.</li>';
    return;
  }

  myBurnerNumbers.forEach(b => {
    const li = document.createElement('li');
    li.className = 'burner-item';
    const expiryText = b.expires_at ? `Verfällt: ${new Date(b.expires_at).toLocaleString()}` : 'Gültig: Unbegrenzt';

    li.innerHTML = `
      <div class="burner-details">
        <span class="burner-num mono-bold">${b.burner_number}</span>
        <span class="burner-expiry">${expiryText}</span>
      </div>
      <div class="burner-item-actions">
        <button class="btn secondary-btn small-btn qr-burner-btn" title="QR-Code anzeigen">QR</button>
        <button class="btn danger-btn small-btn del-burner-btn" title="Löschen / Inaktivieren">Löschen</button>
      </div>
    `;

    li.querySelector('.qr-burner-btn').addEventListener('click', () => {
      openQrModalForId(b.burner_number, "Einweg-Nummer (Burner ID)");
    });

    li.querySelector('.del-burner-btn').addEventListener('click', () => {
      deleteBurnerNumber(b.id);
    });

    burnerList.appendChild(li);
  });
}

async function createBurnerNumber() {
  if (!supabaseClient || !currentProfile) return;

  const ttlValue = burnerTtlSelect.value;
  let expiresAt = null;

  if (ttlValue !== 'never') {
    const now = new Date();
    if (ttlValue === '1h') now.setHours(now.getHours() + 1);
    else if (ttlValue === '24h') now.setHours(now.getHours() + 24);
    else if (ttlValue === '7d') now.setDate(now.getDate() + 7);
    expiresAt = now.toISOString();
  }

  const newBurnerNumber = generate8DigitId();

  const { error } = await supabaseClient
    .from('disposable_numbers')
    .insert({
      user_id: currentProfile.id,
      burner_number: newBurnerNumber,
      active: true,
      expires_at: expiresAt
    });

  if (error) {
    alert("Fehler beim Erstellen der Einweg-Nummer: " + error.message);
    return;
  }

  showToast(`Einweg-Nummer ${newBurnerNumber} erstellt!`);
  await loadBurnerNumbers();
}

async function deleteBurnerNumber(id) {
  if (!supabaseClient) return;

  const { error } = await supabaseClient
    .from('disposable_numbers')
    .update({ active: false })
    .eq('id', id);

  if (error) {
    alert("Fehler beim Löschen: " + error.message);
    return;
  }

  showToast("Einweg-Nummer gelöscht.");
  await loadBurnerNumbers();
}

function updateSenderSelectOptions() {
  senderNumberSelect.innerHTML = '';

  // Main ID Option
  const optMain = document.createElement('option');
  optMain.value = currentProfile.main_number;
  optMain.textContent = `Haupt-ID: ${currentProfile.main_number}`;
  senderNumberSelect.appendChild(optMain);

  // Burner ID Options
  myBurnerNumbers.forEach(b => {
    const opt = document.createElement('option');
    opt.value = b.burner_number;
    opt.textContent = `Burner: ${b.burner_number}`;
    senderNumberSelect.appendChild(opt);
  });
}

// --- CONTACT MANAGEMENT & CHAT LOOKUP ---

async function lookupAndAddContact(peerNumber) {
  if (!peerNumber || peerNumber.length !== 8) {
    alert("Bitte eine gültige 8-stellige ID eingeben.");
    return;
  }

  if (peerNumber === currentProfile.main_number || myBurnerNumbers.some(b => b.burner_number === peerNumber)) {
    alert("Du kannst nicht deine eigene ID als Kontakt hinzufügen.");
    return;
  }

  try {
    let pubKeyB64 = null;
    let label = `Kontakt ${peerNumber}`;

    // 1. Search in profiles (Main ID)
    const { data: pData } = await supabaseClient
      .from('profiles')
      .select('username, public_key')
      .eq('main_number', peerNumber)
      .maybeSingle();

    if (pData) {
      pubKeyB64 = pData.public_key;
      label = `${pData.username} (${peerNumber})`;
    } else {
      // 2. Search in disposable_numbers
      const { data: bData } = await supabaseClient
        .from('disposable_numbers')
        .select('user_id, active, expires_at')
        .eq('burner_number', peerNumber)
        .eq('active', true)
        .maybeSingle();

      if (bData) {
        // Fetch owner's public key from profiles table
        const { data: ownerProfile } = await supabaseClient
          .from('profiles')
          .select('public_key')
          .eq('id', bData.user_id)
          .maybeSingle();

        if (ownerProfile) {
          pubKeyB64 = ownerProfile.public_key;
        }
      }
    }

    if (!pubKeyB64) {
      alert("Keine aktive ID oder Public Key zu dieser Nummer gefunden.");
      return;
    }

    const importedPubKey = await importPublicKey(pubKeyB64);
    const contactObj = {
      number: peerNumber,
      publicKeyB64: pubKeyB64,
      publicKeyObject: importedPubKey,
      label: label
    };

    contactsMap.set(peerNumber, contactObj);
    renderContacts();
    selectContact(contactObj);
    showToast(`Kontakt ${peerNumber} hinzugefügt!`);
  } catch (err) {
    console.error("Lookup Contact Error:", err);
    alert("Fehler beim Abrufen der Kontaktdaten.");
  }
}

function renderContacts() {
  contactsList.innerHTML = '';

  if (contactsMap.size === 0) {
    contactsList.innerHTML = '<li class="empty-burner">Noch keine Chats vorhanden.</li>';
    return;
  }

  contactsMap.forEach(c => {
    const li = document.createElement('li');
    li.className = `contact-item ${activeContact && activeContact.number === c.number ? 'active' : ''}`;
    li.innerHTML = `
      <div class="avatar">${c.number.slice(0, 2)}</div>
      <div class="contact-id">${escapeHtml(c.label)}</div>
    `;
    li.addEventListener('click', () => selectContact(c));
    contactsList.appendChild(li);
  });
}

function selectContact(contact) {
  activeContact = contact;
  renderContacts();

  emptyState.classList.add('hidden');
  chatHeader.classList.remove('hidden');
  messagesContainer.classList.remove('hidden');
  sendMessageForm.classList.remove('hidden');

  if (window.innerWidth <= 768) {
    sidebar.classList.add('mobile-hidden');
  }

  activeAvatar.textContent = contact.number.slice(0, 2);
  activeContactName.textContent = contact.label;

  loadAndRenderChatHistory(contact.number);
}

// --- LOCAL SESSION MESSAGING & HISTORIES ---

function getChatHistory(contactNumber) {
  const stored = sessionStorage.getItem(SESSION_CHAT_PREFIX + contactNumber);
  if (!stored) return [];
  try {
    return JSON.parse(stored);
  } catch (e) {
    return [];
  }
}

function saveChatMessage(contactNumber, msgObj) {
  const history = getChatHistory(contactNumber);
  history.push(msgObj);
  sessionStorage.setItem(SESSION_CHAT_PREFIX + contactNumber, JSON.stringify(history));
}

function loadAndRenderChatHistory(contactNumber) {
  messagesContainer.innerHTML = '';
  const history = getChatHistory(contactNumber);
  history.forEach(msg => appendMessageUI(msg));
  scrollToBottom();
}

function appendMessageUI(msgObj) {
  const time = new Date(msgObj.timestamp || Date.now()).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  const div = document.createElement('div');
  div.className = `msg-bubble ${msgObj.type}`;
  const senderMeta = msgObj.senderNumber ? `<div class="msg-sender-num">An: ${msgObj.recipientNumber} | Von: ${msgObj.senderNumber}</div>` : '';

  div.innerHTML = `
    ${senderMeta}
    <div>${escapeHtml(msgObj.text)}</div>
    <div class="msg-meta">${time}</div>
  `;
  messagesContainer.appendChild(div);
  scrollToBottom();
}

function scrollToBottom() {
  messagesContainer.scrollTop = messagesContainer.scrollHeight;
}

// --- SUPABASE REALTIME & SEND MESSAGE LOGIC ---

async function sendMessage() {
  const text = messageInput.value.trim();
  const senderNum = senderNumberSelect.value;

  if (!text || !activeContact || !decryptedKeyPair) return;

  try {
    // 1. Encrypt text payload with recipient's public key via ECDH + AES-GCM
    const encryptedPayloadStr = await encryptMessagePayload(
      text,
      decryptedKeyPair.privateKey,
      activeContact.publicKeyObject
    );

    // 2. Insert into Supabase `messages` table
    const { error } = await supabaseClient
      .from('messages')
      .insert({
        sender_number: senderNum,
        recipient_number: activeContact.number,
        encrypted_payload: encryptedPayloadStr
      });

    if (error) throw error;

    // 3. Update local session history & UI
    const localMsgObj = {
      text: text,
      type: 'own',
      senderNumber: senderNum,
      recipientNumber: activeContact.number,
      timestamp: Date.now()
    };

    appendMessageUI(localMsgObj);
    saveChatMessage(activeContact.number, localMsgObj);
    messageInput.value = '';
    playSoundFeedback('send');
    showToast("Nachricht 100% E2EE verschlüsselt gesendet!");
  } catch (err) {
    console.error("Send Message Error:", err);
    alert("Fehler beim Senden der Nachricht: " + err.message);
  }
}

function subscribeToRealtimeMessages() {
  if (!supabaseClient || realtimeChannel) return;

  wsStatusDot.className = 'dot online';

  realtimeChannel = supabaseClient
    .channel('public:messages')
    .on('postgres_changes', { event: 'INSERT', schema: 'public', table: 'messages' }, async (payload) => {
      const newMsg = payload.new;
      if (!newMsg) return;

      const myNumbers = [currentProfile.main_number, ...myBurnerNumbers.map(b => b.burner_number)];

      // Check if message belongs to one of my numbers as recipient
      if (myNumbers.includes(newMsg.recipient_number)) {
        await handleIncomingMessage(newMsg);
      }
    })
    .subscribe((status) => {
      if (status === 'SUBSCRIBED') {
        wsStatusDot.className = 'dot online';
      } else {
        wsStatusDot.className = 'dot offline';
      }
    });
}

async function handleIncomingMessage(msgRow) {
  const senderNum = msgRow.sender_number;
  let senderContact = contactsMap.get(senderNum);

  // If sender is not in contact map, fetch public key
  if (!senderContact) {
    let pubKeyB64 = null;

    const { data: pData } = await supabaseClient
      .from('profiles')
      .select('public_key')
      .eq('main_number', senderNum)
      .maybeSingle();

    if (pData) {
      pubKeyB64 = pData.public_key;
    } else {
      const { data: bData } = await supabaseClient
        .from('disposable_numbers')
        .select('user_id')
        .eq('burner_number', senderNum)
        .maybeSingle();

      if (bData) {
        const { data: owner } = await supabaseClient
          .from('profiles')
          .select('public_key')
          .eq('id', bData.user_id)
          .maybeSingle();
        if (owner) pubKeyB64 = owner.public_key;
      }
    }

    if (pubKeyB64) {
      const importedPubKey = await importPublicKey(pubKeyB64);
      senderContact = {
        number: senderNum,
        publicKeyB64: pubKeyB64,
        publicKeyObject: importedPubKey,
        label: `Kontakt ${senderNum}`
      };
      contactsMap.set(senderNum, senderContact);
      renderContacts();
    }
  }

  if (!senderContact) return;

  try {
    // Decrypt payload
    const decryptedText = await decryptMessagePayload(
      msgRow.encrypted_payload,
      decryptedKeyPair.privateKey,
      senderContact.publicKeyObject
    );

    const msgObj = {
      text: decryptedText,
      type: 'other',
      senderNumber: senderNum,
      recipientNumber: msgRow.recipient_number,
      timestamp: new Date(msgRow.created_at).getTime()
    };

    saveChatMessage(senderNum, msgObj);
    playSoundFeedback('receive');

    if (activeContact && activeContact.number === senderNum) {
      appendMessageUI(msgObj);
    } else {
      showToast(`Neue verschlüsselte Nachricht von ${senderNum}`);
    }
  } catch (err) {
    console.error("Decryption Error for incoming message:", err);
  }
}

// --- EVENT LISTENERS & MODAL TRIGGERS ---

function setupChatListeners() {
  if (mobileToggleBtn) {
    mobileToggleBtn.addEventListener('click', () => sidebar.classList.toggle('mobile-hidden'));
  }

  if (mobileBackBtn) {
    mobileBackBtn.addEventListener('click', () => sidebar.classList.remove('mobile-hidden'));
  }

  // Profile / Burner ID modal
  const openProfile = () => profileModal.classList.remove('hidden');
  openProfileBtn.addEventListener('click', openProfile);
  if (mobileProfileBtn) mobileProfileBtn.addEventListener('click', openProfile);

  closeProfileModalBtn.addEventListener('click', () => profileModal.classList.add('hidden'));

  createBurnerBtn.addEventListener('click', createBurnerNumber);

  qrMainIdBtn.addEventListener('click', () => {
    openQrModalForId(currentProfile.main_number, "Haupt-ID");
  });

  // Add contact handler
  addContactBtn.addEventListener('click', () => {
    const val = peerIdInput.value.trim();
    lookupAndAddContact(val);
  });

  // QR display & camera scanning
  showQrBtn.addEventListener('click', () => {
    openQrModalForId(currentProfile.main_number, "Deine Haupt-ID");
  });

  closeQrModalBtn.addEventListener('click', () => qrModal.classList.add('hidden'));

  copyQrIdBtn.addEventListener('click', () => {
    const val = copyQrIdBtn.getAttribute('data-id');
    if (val) {
      navigator.clipboard.writeText(val);
      showToast("ID in Zwischenablage kopiert!");
    }
  });

  scanQrBtn.addEventListener('click', () => {
    scannerModal.classList.remove('hidden');
    if (typeof Html5Qrcode !== 'undefined') {
      html5QrScanner = new Html5Qrcode("qr-reader");
      html5QrScanner.start(
        { facingMode: "environment" },
        { fps: 10, qrbox: { width: 220, height: 220 } },
        (decodedText) => {
          onQrCodeScanned(decodedText);
        },
        () => {}
      ).catch(err => {
        console.error("Camera Error:", err);
        showToast("Kamera konnte nicht gestartet werden");
      });
    }
  });

  closeScannerModalBtn.addEventListener('click', stopScannerModal);

  // Send Message form
  sendMessageForm.addEventListener('submit', (e) => {
    e.preventDefault();
    sendMessage();
  });
}

function openQrModalForId(idNumber, titleLabel) {
  qrModalTitle.textContent = `QR-Code: ${titleLabel}`;
  qrModalSubtext.textContent = `Scanne diesen Code, um eine Chat-Verbindung mit der ID ${idNumber} einzurichten.`;
  copyQrIdBtn.setAttribute('data-id', idNumber);

  qrCodeContainer.innerHTML = '';
  if (typeof QRCode !== 'undefined') {
    new QRCode(qrCodeContainer, {
      text: idNumber,
      width: 180,
      height: 180,
      colorDark: "#000000",
      colorLight: "#ffffff",
      correctLevel: QRCode.CorrectLevel.L
    });
  } else {
    qrCodeContainer.textContent = idNumber;
  }

  qrModal.classList.remove('hidden');
}

function stopScannerModal() {
  if (html5QrScanner) {
    html5QrScanner.stop().then(() => {
      html5QrScanner.clear();
      html5QrScanner = null;
    }).catch(err => console.error(err));
  }
  scannerModal.classList.add('hidden');
}

function onQrCodeScanned(decodedText) {
  stopScannerModal();
  const cleaned = decodedText.trim();
  if (cleaned.length === 8 && /^\d{8}$/.test(cleaned)) {
    peerIdInput.value = cleaned;
    lookupAndAddContact(cleaned);
  } else {
    showToast("Gescannter QR-Code enthält keine 8-stellige ID.");
  }
}
