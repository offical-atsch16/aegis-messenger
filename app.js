// AegisChat Client Application Logic with Supabase Backend & WebCrypto E2EE

// STORAGE KEYS - EXCLUSIVELY SESSIONSTORAGE
const SESSION_USER = 'aegis_session_user';
const SESSION_KEYS = 'aegis_session_keys';
const SESSION_CONTACTS = 'aegis_session_contacts';
const SESSION_CHAT_PREFIX = 'aegis_chat_';
const LOCAL_SB_CONFIG = 'aegis_sb_config';

// State Variables
let supabaseClient = null;
let currentUser = null; // { id, username, main_number }
let localKeyPair = null; // CryptoKeyPair (ECDH P-256)
let localPubKeyB64 = null;
let contacts = []; // Array of { number, isBurner, pubKeyB64, pubKeyObj, sharedKey }
let myBurnerNumbers = []; // Array of { id, burner_number, active, expires_at }
let activeContact = null;
let realtimeSubscription = null;
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
    // Audio context feedback unavailable without prior interaction
  }
}

// Helper to generate 8-digit unique ID / Burner number
function generate8DigitId() {
  return Math.floor(10000000 + Math.random() * 90000000).toString();
}

// Convert username to internal synthetic email format for Supabase Auth
function usernameToEmail(username) {
  const clean = username.toLowerCase().replace(/[^a-z0-9_]/g, '');
  return `${clean}@aegischat.internal`;
}

// --- WEBCRYPTO API: ECDH (P-256) & PBKDF2 + AES-GCM ---

// Generate ECDH P-256 Key Pair for Client-Side Key Exchange
async function generateEcdhKeyPair() {
  return await window.crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveKey", "deriveBits"]
  );
}

// Export Public Key to Base64 JWK
async function exportPublicKey(key) {
  const exported = await window.crypto.subtle.exportKey("jwk", key);
  return btoa(JSON.stringify(exported));
}

// Import Public Key from Base64 JWK
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

// Derive AES-GCM Shared Symmetric Key using ECDH between local Private Key & recipient Public Key
async function deriveSharedAesKey(privateKey, peerPublicKey) {
  return await window.crypto.subtle.deriveKey(
    { name: "ECDH", public: peerPublicKey },
    privateKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

// Derive AES-GCM Key from User Password using PBKDF2 for Private Key Wrapping
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

// Encrypt Private Key (JWK) with User Password (PBKDF2 + AES-GCM)
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

// Encrypt Message payload using AES-GCM Shared Key
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

// Decrypt Message payload using AES-GCM Shared Key
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

// --- SUPABASE CLIENT INITIALIZATION & SESSION MANAGEMENT ---

function initSupabase() {
  const sbConfig = localStorage.getItem(LOCAL_SB_CONFIG);
  if (sbConfig) {
    try {
      const { url, key } = JSON.parse(sbConfig);
      if (url && key && window.supabase) {
        supabaseClient = window.supabase.createClient(url, key);
      }
    } catch (e) {
      console.error("Fehler beim Laden der Supabase Config:", e);
    }
  }
}

// DOM ELEMENTS
const landingPage = document.getElementById('landing-page');
const openConfigBtn = document.getElementById('open-config-btn');
const configModal = document.getElementById('config-modal');
const closeConfigModalBtn = document.getElementById('close-config-modal-btn');
const sbUrlInput = document.getElementById('sb-url-input');
const sbKeyInput = document.getElementById('sb-key-input');
const saveConfigBtn = document.getElementById('save-config-btn');

const showRegisterModalBtn = document.getElementById('show-register-modal-btn');
const registerModal = document.getElementById('register-modal');
const closeRegisterModalBtn = document.getElementById('close-register-modal-btn');
const regUsernameInput = document.getElementById('reg-username');
const regPasswordInput = document.getElementById('reg-password');
const submitRegisterBtn = document.getElementById('submit-register-btn');
const registerStatus = document.getElementById('register-status');

const showLoginModalBtn = document.getElementById('show-login-modal-btn');
const loginModal = document.getElementById('login-modal');
const closeLoginModalBtn = document.getElementById('close-login-modal-btn');
const loginUserIdentifierInput = document.getElementById('login-user-identifier');
const loginPasswordInput = document.getElementById('login-password');
const submitLoginBtn = document.getElementById('submit-login-btn');
const loginStatus = document.getElementById('login-status');

const appContainer = document.getElementById('app');
const chatScreen = document.getElementById('chat-screen');

const logoutBtn = document.getElementById('logout-btn');
const mobileLogoutBtn = document.getElementById('mobile-logout-btn');
const myAvatar = document.getElementById('my-avatar');
const myUsernameEl = document.getElementById('my-username');
const myIdEl = document.getElementById('my-id');
const realtimeStatusDot = document.getElementById('realtime-status-dot');

const manageBurnersBtn = document.getElementById('manage-burners-btn');
const showQrBtn = document.getElementById('show-qr-btn');

const peerNumberInput = document.getElementById('peer-number-input');
const addContactBtn = document.getElementById('add-contact-btn');
const scanQrBtn = document.getElementById('scan-qr-btn');
const contactsList = document.getElementById('contacts-list');

const scannerModal = document.getElementById('scanner-modal');
const closeScannerModalBtn = document.getElementById('close-scanner-modal-btn');

const chatHeader = document.getElementById('chat-header');
const emptyState = document.getElementById('empty-state');
const activeAvatar = document.getElementById('active-avatar');
const activeContactName = document.getElementById('active-contact-name');
const sendAsSelect = document.getElementById('send-as-select');
const messagesContainer = document.getElementById('messages-container');
const sendMessageForm = document.getElementById('send-message-form');
const senderNumberSelect = document.getElementById('sender-number-select');
const messageInput = document.getElementById('message-input');

const mobileToggleBtn = document.getElementById('mobile-toggle-btn');
const mobileBackBtn = document.getElementById('mobile-back-btn');
const sidebar = document.getElementById('sidebar');

const burnerModal = document.getElementById('burner-modal');
const closeBurnerModalBtn = document.getElementById('close-burner-modal-btn');
const burnerExpirySelect = document.getElementById('burner-expiry-select');
const generateBurnerBtn = document.getElementById('generate-burner-btn');
const burnerList = document.getElementById('burner-list');

const qrModal = document.getElementById('qr-modal');
const closeQrModalBtn = document.getElementById('close-qr-modal-btn');
const qrCodeContainer = document.getElementById('qr-code-container');
const qrModalTitle = document.getElementById('qr-modal-title');
const qrModalSubtext = document.getElementById('qr-modal-subtext');
const copyQrNumberBtn = document.getElementById('copy-qr-number-btn');

const scannerModal = document.getElementById('scanner-modal');
const closeScannerModalBtn = document.getElementById('close-scanner-modal-btn');

document.addEventListener('DOMContentLoaded', () => {
  initSupabase();
  checkSessionState();

  // Supabase Config Modal Handlers
  openConfigBtn.addEventListener('click', () => {
    const sbConfig = localStorage.getItem(LOCAL_SB_CONFIG);
    if (sbConfig) {
      try {
        const { url, key } = JSON.parse(sbConfig);
        sbUrlInput.value = url || '';
        sbKeyInput.value = key || '';
      } catch (e) {}
    }
    configModal.classList.remove('hidden');
  });

  closeConfigModalBtn.addEventListener('click', () => configModal.classList.add('hidden'));

  saveConfigBtn.addEventListener('click', () => {
    const url = sbUrlInput.value.trim();
    const key = sbKeyInput.value.trim();
    if (!url || !key) {
      alert('Bitte sowohl Supabase URL als auch Anon Key eingeben.');
      return;
    }
    localStorage.setItem(LOCAL_SB_CONFIG, JSON.stringify({ url, key }));
    initSupabase();
    configModal.classList.add('hidden');
    showToast("Supabase Konfiguration gespeichert!");
  });

  // Auth Modals Open/Close
  showRegisterModalBtn.addEventListener('click', () => {
    if (!supabaseClient) {
      alert('Bitte konfiguriere zuerst Supabase (Button "Supabase Config" oben rechts).');
      return;
    }
    registerModal.classList.remove('hidden');
  });

  closeRegisterModalBtn.addEventListener('click', () => registerModal.classList.add('hidden'));

  showLoginModalBtn.addEventListener('click', () => {
    if (!supabaseClient) {
      alert('Bitte konfiguriere zuerst Supabase (Button "Supabase Config" oben rechts).');
      return;
    }
    loginModal.classList.remove('hidden');
  });

  closeLoginModalBtn.addEventListener('click', () => loginModal.classList.add('hidden'));

  // Registration Submit Handler (Username + Password)
  submitRegisterBtn.addEventListener('click', async () => {
    const username = regUsernameInput.value.trim();
    const password = regPasswordInput.value;

    if (!username || !password) {
      registerStatus.textContent = 'Bitte Nutzername und Passwort ausfüllen.';
      return;
    }
    registerModal.classList.remove('hidden');
  });
  closeRegisterModalBtn.addEventListener('click', () => registerModal.classList.add('hidden'));

    if (password.length < 6) {
      registerStatus.textContent = 'Das Passwort muss mindestens 6 Zeichen lang sein.';
      return;
    }
    loginModal.classList.remove('hidden');
  });
  closeLoginModalBtn.addEventListener('click', () => loginModal.classList.add('hidden'));

    submitRegisterBtn.disabled = true;
    registerStatus.textContent = 'Erstelle ECDH Schlüsselpaar & Supabase Account...';

    try {
      const email = usernameToEmail(username);
      const mainNumber = generate8DigitId();

      // Step 1: Generate ECDH Keypair & Wrap Private Key
      const keyPair = await generateEcdhKeyPair();
      const pubKeyB64 = await exportPublicKey(keyPair.publicKey);
      const encryptedPrivateKeyStr = await encryptPrivateKey(keyPair.privateKey, password);

      // Step 2: Supabase Auth Sign Up
      const { data: authData, error: authErr } = await supabaseClient.auth.signUp({
        email,
        password
      });

      if (authErr) throw authErr;
      if (!authData.user) throw new Error("Benutzererstellung fehlgeschlagen.");

      // Step 3: Create Profile Record
      const { error: profileErr } = await supabaseClient
        .from('profiles')
        .insert({
          id: authData.user.id,
          username,
          main_number: mainNumber,
          encrypted_private_key: encryptedPrivateKeyStr,
          public_key: pubKeyB64
        });

      if (profileErr) throw profileErr;

      // Set State & Local Session
      currentUser = { id: authData.user.id, username, main_number: mainNumber };
      localKeyPair = keyPair;
      localPubKeyB64 = pubKeyB64;

      saveSessionData();
      registerModal.classList.add('hidden');
      initMainChatUI();
      showToast("Registrierung erfolgreich! Haupt-ID: " + mainNumber);
    } catch (e) {
      console.error(e);
      registerStatus.textContent = 'Fehler: ' + (e.message || 'Registrierung fehlgeschlagen.');
    } finally {
      submitRegisterBtn.disabled = false;
    }
  });

  // Login Submit Handler (Username / ID + Password)
  submitLoginBtn.addEventListener('click', async () => {
    const identifier = loginUserIdentifierInput.value.trim();
    const password = loginPasswordInput.value;

    if (!identifier || !password) {
      loginStatus.textContent = 'Bitte Nutzername/ID und Passwort eingeben.';
      return;
    }

    submitLoginBtn.disabled = true;
    loginStatus.textContent = 'Suche Profil & Anmelden...';

    try {
      let username = identifier;

      // If user typed an 8-digit ID, resolve username from profiles first
      if (/^\d{8}$/.test(identifier)) {
        const { data: prof, error: pErr } = await supabaseClient
          .from('profiles')
          .select('username')
          .eq('main_number', identifier)
          .single();

        if (pErr || !prof) throw new Error("Kein Profil zu dieser ID gefunden.");
        username = prof.username;
      }

      const email = usernameToEmail(username);

      // Step 1: Supabase Auth Sign In
      const { data: authData, error: authErr } = await supabaseClient.auth.signInWithPassword({
        email,
        password
      });

      if (authErr) throw authErr;

      // Step 2: Fetch Profile Data
      const { data: profile, error: profErr } = await supabaseClient
        .from('profiles')
        .select('*')
        .eq('id', authData.user.id)
        .single();

      if (profErr || !profile) throw new Error("Profil nicht gefunden.");

      // Step 3: Decrypt Private Key locally using Password
      const privateKey = await decryptPrivateKey(profile.encrypted_private_key, password);
      const publicKey = await importPublicKey(profile.public_key);

      currentUser = {
        id: profile.id,
        username: profile.username,
        main_number: profile.main_number
      };

      localKeyPair = { publicKey, privateKey };
      localPubKeyB64 = profile.public_key;

      saveSessionData();
      loginModal.classList.add('hidden');
      initMainChatUI();
      showToast("Erfolgreich angemeldet!");
    } catch (e) {
      console.error(e);
      loginStatus.textContent = 'Fehler: ' + (e.message || 'Anmeldung fehlgeschlagen.');
    } finally {
      submitLoginBtn.disabled = false;
    }
  });

  // Logout Handlers
  if (logoutBtn) logoutBtn.addEventListener('click', handleLogout);
  if (mobileLogoutBtn) mobileLogoutBtn.addEventListener('click', handleLogout);
});

function handleLogout() {
  clearSessionData();
  if (supabaseClient) {
    supabaseClient.auth.signOut().catch(() => {});
  }
  showToast("Abgemeldet & Private Key aus RAM gelöscht");
  location.reload();
}

function checkSessionState() {
  const storedUser = sessionStorage.getItem(SESSION_USER);
  const storedKeys = sessionStorage.getItem(SESSION_KEYS);

  if (storedUser && storedKeys) {
    try {
      currentUser = JSON.parse(storedUser);
      const keysObj = JSON.parse(storedKeys);

      // Re-import ECDH keys into WebCrypto memory
      Promise.all([
        importPublicKey(keysObj.pubKeyB64),
        window.crypto.subtle.importKey("jwk", JSON.parse(atob(keysObj.privKeyJwkB64)), { name: "ECDH", namedCurve: "P-256" }, true, ["deriveKey", "deriveBits"])
      ]).then(([pub, priv]) => {
        localKeyPair = { publicKey: pub, privateKey: priv };
        localPubKeyB64 = keysObj.pubKeyB64;
        initMainChatUI();
      }).catch(err => {
        clearSessionData();
      });
      return;
    } catch (e) {
      clearSessionData();
    }
  }

  landingPage.classList.remove('hidden');
  appContainer.classList.add('hidden');
}

async function saveSessionData() {
  if (!currentUser || !localKeyPair) return;

  const jwkPriv = await window.crypto.subtle.exportKey("jwk", localKeyPair.privateKey);
  const privKeyJwkB64 = btoa(JSON.stringify(jwkPriv));

  sessionStorage.setItem(SESSION_USER, JSON.stringify(currentUser));
  sessionStorage.setItem(SESSION_KEYS, JSON.stringify({
    pubKeyB64: localPubKeyB64,
    privKeyJwkB64
  }));
}

function clearSessionData() {
  sessionStorage.clear();
  currentUser = null;
  localKeyPair = null;
  localPubKeyB64 = null;
  contacts = [];
  myBurnerNumbers = [];
  activeContact = null;
  if (realtimeSubscription) {
    realtimeSubscription.unsubscribe();
    realtimeSubscription = null;
  }
}

async function initMainChatUI() {
  landingPage.classList.add('hidden');
  appContainer.classList.remove('hidden');

  myAvatar.textContent = currentUser.username.slice(0, 2).toUpperCase();
  myUsernameEl.textContent = currentUser.username;
  myIdEl.textContent = `ID: ${currentUser.main_number}`;

  await fetchMyBurnerNumbers();
  updateSenderDropdown();
  loadStoredContacts();
  setupEventListeners();
  subscribeToRealtimeMessages();
}

function updateSenderDropdown() {
  sendAsSelect.innerHTML = '';
  // Main Number Option
  const optMain = document.createElement('option');
  optMain.value = currentUser.main_number;
  optMain.textContent = `Haupt-ID (${currentUser.main_number})`;
  sendAsSelect.appendChild(optMain);

  // Active Burner Numbers
  myBurnerNumbers.filter(b => b.active).forEach(b => {
    const opt = document.createElement('option');
    opt.value = b.burner_number;
    opt.textContent = `Burner (${b.burner_number})`;
    sendAsSelect.appendChild(opt);
  });
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

  // Manage Burners Modal Open
  manageBurnersBtn.addEventListener('click', () => {
    renderBurnerList();
    burnerModal.classList.remove('hidden');
  });

  closeBurnerModalBtn.addEventListener('click', () => burnerModal.classList.add('hidden'));

  // Generate Burner ID Handler
  generateBurnerBtn.addEventListener('click', async () => {
    if (!supabaseClient || !currentUser) return;

    const expiryType = burnerExpirySelect.value;
    let expiresAt = null;

    if (expiryType === '1h') {
      expiresAt = new Date(Date.now() + 3600 * 1000).toISOString();
    } else if (expiryType === '24h') {
      expiresAt = new Date(Date.now() + 24 * 3600 * 1000).toISOString();
    } else if (expiryType === '7d') {
      expiresAt = new Date(Date.now() + 7 * 24 * 3600 * 1000).toISOString();
    }

    const newBurnerNumber = generate8DigitId();

    generateBurnerBtn.disabled = true;
    try {
      const { data, error } = await supabaseClient
        .from('disposable_numbers')
        .insert({
          user_id: currentUser.id,
          burner_number: newBurnerNumber,
          active: true,
          expires_at: expiresAt
        })
        .select()
        .single();

      if (error) throw error;

      myBurnerNumbers.push(data);
      updateSenderDropdown();
      renderBurnerList();
      showToast(`Einweg-Nummer ${newBurnerNumber} erstellt!`);
    } catch (e) {
      console.error(e);
      showToast("Fehler beim Erstellen der Einweg-Nummer");
    } finally {
      generateBurnerBtn.disabled = false;
    }
    return true;
  });

  // Show My Main QR Code Modal
  showQrBtn.addEventListener('click', () => {
    qrModalTitle.textContent = "Haupt-ID QR-Code";
    qrModalSubtext.textContent = `Scanne diesen Code, um Nachrichten an Haupt-ID ${currentUser.main_number} zu senden.`;
    displayQrCode(currentUser.main_number);
    qrModal.classList.remove('hidden');
  });

  closeQrModalBtn.addEventListener('click', () => qrModal.classList.add('hidden'));

  copyQrNumberBtn.addEventListener('click', () => {
    const num = copyQrNumberBtn.getAttribute('data-number') || currentUser.main_number;
    navigator.clipboard.writeText(num);
    showToast("Nummer " + num + " in Zwischenablage kopiert!");
  });

  // Camera Scan QR Code
  scanQrBtn.addEventListener('click', () => {
    scannerModal.classList.remove('hidden');
    if (typeof Html5Qrcode !== 'undefined') {
      html5QrScanner = new Html5Qrcode("qr-reader");
      html5QrScanner.start(
        { facingMode: "environment" },
        { fps: 10, qrbox: { width: 220, height: 220 } },
        (decodedText) => {
          peerNumberInput.value = decodedText.trim();
          stopScannerModal();
          showToast("QR-Code gescannt!");
        },
        () => {}
      ).catch(err => console.error(err));
    }
  });
}

async function createBurnerNumber() {
  if (!supabaseClient || !currentProfile) return;

  // Add Contact / Start Chat
  addContactBtn.addEventListener('click', async () => {
    const number = peerNumberInput.value.trim();
    if (number.length !== 8 || !/^\d{8}$/.test(number)) {
      alert('Bitte eine gültige 8-stellige ID oder Einweg-Nummer eingeben.');
      return;
    }

    addContactBtn.disabled = true;
    try {
      await addOrResolveContact(number);
      peerNumberInput.value = '';
    } catch (e) {
      alert("Fehler beim Auflösen des Kontakts: " + e.message);
    } finally {
      addContactBtn.disabled = false;
    }
  });

  // Send E2EE Message Handler
  sendMessageForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const text = messageInput.value.trim();
    if (!text || !activeContact) return;

    try {
      const senderNumber = sendAsSelect.value || currentUser.main_number;
      const recipientNumber = activeContact.number;

      // Encrypt payload with derived ECDH + AES-GCM key
      const encryptedPayloadStr = await encryptPayload(text, activeContact.sharedKey);

      // Insert message into Supabase
      const { error } = await supabaseClient
        .from('messages')
        .insert({
          sender_number: senderNumber,
          recipient_number: recipientNumber,
          encrypted_payload: encryptedPayloadStr
        });

      if (error) throw error;

      const msgObj = {
        sender_number: senderNumber,
        recipient_number: recipientNumber,
        text,
        type: 'own',
        timestamp: Date.now()
      };

      appendMessageUI(msgObj);
      saveChatMessage(recipientNumber, msgObj);
      messageInput.value = '';
      playSoundFeedback('send');
    } catch (err) {
      console.error(err);
      showToast("Fehler beim Senden der verschlüsselten Nachricht");
    }
  });
}

function displayQrCode(text) {
  qrCodeContainer.innerHTML = '';
  copyQrNumberBtn.setAttribute('data-number', text);
  if (typeof QRCode !== 'undefined') {
    new QRCode(qrCodeContainer, {
      text: text,
      width: 180,
      height: 180,
      colorDark: "#000000",
      colorLight: "#ffffff",
      correctLevel: QRCode.CorrectLevel.L
    });
  }
}

function stopScannerModal() {
  if (html5QrScanner) {
    html5QrScanner.stop().then(() => {
      html5QrScanner.clear();
      html5QrScanner = null;
    }).catch(err => console.error(err));
  }

  showToast(`Einweg-Nummer ${newBurnerNumber} erstellt!`);
  await loadBurnerNumbers();
}

// --- BURNER ID MANAGEMENT & SUPABASE QUERYING ---

async function fetchMyBurnerNumbers() {
  if (!supabaseClient || !currentUser) return;
  try {
    const { data, error } = await supabaseClient
      .from('disposable_numbers')
      .select('*')
      .eq('user_id', currentUser.id);

    if (!error && data) {
      // Check for expired burner numbers and auto-deactivate
      const now = new Date();
      myBurnerNumbers = data.map(b => {
        if (b.expires_at && new Date(b.expires_at) <= now) {
          b.active = false;
        }
        return b;
      });
    }
  } catch (e) {
    console.error(e);
  }
}

function renderBurnerList() {
  burnerList.innerHTML = '';
  if (myBurnerNumbers.length === 0) {
    burnerList.innerHTML = '<li style="color: var(--text-muted); font-size: 13px;">Keine Einweg-Nummern vorhanden.</li>';
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

    // QR Code for Burner ID
    li.querySelector('.qr-btn').addEventListener('click', () => {
      qrModalTitle.textContent = "Einweg-Nummer QR-Code";
      qrModalSubtext.textContent = `Scanne diesen Code für anonymen Empfang an ${b.burner_number}.`;
      displayQrCode(b.burner_number);
      qrModal.classList.remove('hidden');
    });

    // Delete/Deactivate Burner ID
    li.querySelector('.delete-btn').addEventListener('click', async () => {
      if (confirm(`Möchtest du Einweg-Nummer ${b.burner_number} wirklich löschen?`)) {
        await supabaseClient.from('disposable_numbers').delete().eq('id', b.id);
        myBurnerNumbers = myBurnerNumbers.filter(x => x.id !== b.id);
        updateSenderDropdown();
        renderBurnerList();
        showToast(`Einweg-Nummer ${b.burner_number} gelöscht.`);
      }
    });

    burnerList.appendChild(li);
  });
}

// --- CONTACT RESOLUTION & ECDH SHARED KEY COMPUTATION ---

async function addOrResolveContact(number) {
  // Check if contact already exists
  let existing = contacts.find(c => c.number === number);
  if (existing) {
    selectContact(existing);
    return existing;
  }

  // 1. Search in profiles table for main_number
  const { data: profile } = await supabaseClient
    .from('profiles')
    .select('main_number, public_key')
    .eq('main_number', number)
    .single();

  let pubKeyB64 = null;
  let isBurner = false;

  if (profile) {
    pubKeyB64 = profile.public_key;
  } else {
    // 2. Search in disposable_numbers table
    const { data: burner } = await supabaseClient
      .from('disposable_numbers')
      .select('user_id, active, expires_at, profiles(public_key)')
      .eq('burner_number', number)
      .single();

    if (!burner || !burner.active) {
      throw new Error("Nummer ist inaktiv oder existiert nicht.");
    }

    if (burner.expires_at && new Date(burner.expires_at) <= new Date()) {
      throw new Error("Diese Einweg-Nummer ist abgelaufen.");
    }

    pubKeyB64 = burner.profiles ? burner.profiles.public_key : null;
    isBurner = true;
  }

  if (!pubKeyB64) {
    throw new Error("Öffentlicher Schlüssel konnte nicht aufgelöst werden.");
  }

  // Derive Shared Symmetric Key using ECDH
  const peerPubKeyObj = await importPublicKey(pubKeyB64);
  const sharedKey = await deriveSharedAesKey(localKeyPair.privateKey, peerPubKeyObj);

  const newContact = {
    number,
    isBurner,
    pubKeyB64,
    sharedKey
  };

  contacts.push(newContact);
  saveContactsToSession();
  renderContacts();
  selectContact(newContact);
  showToast(`Chat mit ${number} gestartet.`);
  return newContact;
}

// --- CONTACTS & CHAT HISTORY LOCAL CACHING ---

function loadStoredContacts() {
  const stored = sessionStorage.getItem(SESSION_CONTACTS);
  if (stored) {
    try {
      const array = JSON.parse(stored);
      contacts = [];
      array.forEach(async c => {
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
  sessionStorage.setItem(SESSION_CONTACTS, JSON.stringify(serializable));
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

    const tag = c.isBurner ? '<span class="contact-type-tag">Burner</span>' : '';

    li.innerHTML = `
      <div class="avatar">${c.number.slice(0, 2)}</div>
      <div class="contact-id">${c.number}</div>
      ${tag}
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
  activeContactName.textContent = `Chat ID: ${contact.number}`;

  loadAndRenderChatHistory(contact.number);
}

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

  const senderMeta = msgObj.type === 'own' ? `An: ${msgObj.recipient_number}` : `Von: ${msgObj.sender_number}`;

  div.innerHTML = `
    ${senderMeta}
    <div>${escapeHtml(msgObj.text)}</div>
    <div class="msg-meta">
      <span>${senderMeta}</span>
      <span>${time}</span>
    </div>
  `;
  messagesContainer.appendChild(div);
  scrollToBottom();
}

function scrollToBottom() {
  messagesContainer.scrollTop = messagesContainer.scrollHeight;
}

function escapeHtml(text) {
  return text.replace(/&/g, "&amp;")
             .replace(/</g, "&lt;")
             .replace(/>/g, "&gt;")
             .replace(/"/g, "&quot;")
             .replace(/'/g, "&#039;");
}

// --- SUPABASE REALTIME SUBSCRIPTION FOR INCOMING E2EE MESSAGES ---

function getMyAllNumbers() {
  const list = [currentUser.main_number];
  myBurnerNumbers.filter(b => b.active).forEach(b => list.push(b.burner_number));
  return list;
}

function subscribeToRealtimeMessages() {
  if (!supabaseClient || !currentUser) return;

  realtimeSubscription = supabaseClient
    .channel('public:messages')
    .on('postgres_changes', { event: 'INSERT', schema: 'public', table: 'messages' }, async (payload) => {
      const newMsg = payload.new;
      const myNumbers = getMyAllNumbers();

      // Check if message is addressed to our main ID or any of our active Burner IDs
      if (myNumbers.includes(newMsg.recipient_number)) {
        try {
          const senderNumber = newMsg.sender_number;

          // Resolve contact if not already cached
          let contact = contacts.find(c => c.number === senderNumber);
          if (!contact) {
            contact = await addOrResolveContact(senderNumber);
          }

          // Decrypt payload locally using derived ECDH shared key
          const decryptedText = await decryptPayload(newMsg.encrypted_payload, contact.sharedKey);

          const msgObj = {
            sender_number: senderNumber,
            recipient_number: newMsg.recipient_number,
            text: decryptedText,
            type: 'other',
            timestamp: new Date(newMsg.created_at).getTime() || Date.now()
          };

          saveChatMessage(senderNumber, msgObj);
          playSoundFeedback('receive');

          if (activeContact && activeContact.number === senderNumber) {
            appendMessageUI(msgObj);
          } else {
            showToast(`Neue E2EE Nachricht an ${newMsg.recipient_number} von ${senderNumber}!`);
          }
        } catch (err) {
          console.error("Fehler beim Entschlüsseln eingehender Nachricht:", err);
        }
      }
    })
    .subscribe((status) => {
      if (status === 'SUBSCRIBED') {
        realtimeStatusDot.className = 'dot online';
      } else {
        realtimeStatusDot.className = 'dot offline';
      }
    });
}
