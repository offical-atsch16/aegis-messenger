// AegisChat Client Application Logic

// STORAGE KEYS - EXCLUSIVELY SESSIONSTORAGE
const SESSION_IDENTITY = 'aegis_session_identity';
const SESSION_CONTACTS = 'aegis_session_contacts';
const SESSION_CHAT_PREFIX = 'aegis_chat_';

// State Variables
let identity = null; // { username, id, keyPair, pubKeyB64 }
let contacts = [];   // Array of { id, username, keyB64, keyObject }
let activeContact = null;
let ws = null;
let html5QrScanner = null;

// --- UTILITY: TOAST NOTIFICATIONS ---
function showToast(message) {
  const container = document.getElementById('toast-container');
  if (!container) return;
  const toast = document.createElement('div');
  toast.className = 'toast';
  toast.textContent = message;
  container.appendChild(toast);
  setTimeout(() => {
    if (toast.parentNode) toast.parentNode.removeChild(toast);
  }, 3000);
}

// --- WEBCRYPTO FUNCTIONS ---

function generate8DigitId() {
  return Math.floor(10000000 + Math.random() * 90000000).toString();
}

// Generate RSA-OAEP 2048-bit Key Pair
async function generateKeyPair() {
  return await window.crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["encrypt", "decrypt"]
  );
}

// Export Public RSA Key as Base64 JWK
async function exportPublicKey(key) {
  const exported = await window.crypto.subtle.exportKey("jwk", key);
  return btoa(JSON.stringify(exported));
}

// Import Public RSA Key from Base64 JWK
async function importPublicKey(jwkB64) {
  const jwk = JSON.parse(atob(jwkB64));
  return await window.crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "RSA-OAEP", hash: "SHA-256" },
    true,
    ["encrypt"]
  );
}

// RSA Message Encryption
async function encryptMessage(text, publicKey) {
  const enc = new TextEncoder();
  const ciphertext = await window.crypto.subtle.encrypt(
    { name: "RSA-OAEP" },
    publicKey,
    enc.encode(text)
  );
  return btoa(String.fromCharCode(...new Uint8Array(ciphertext)));
}

// RSA Message Decryption
async function decryptMessage(encryptedB64, privateKey) {
  const binaryString = atob(encryptedB64);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  const decrypted = await window.crypto.subtle.decrypt(
    { name: "RSA-OAEP" },
    privateKey,
    bytes.buffer
  );
  return new TextDecoder().decode(decrypted);
}

// Derive AES-GCM Key from User Password using PBKDF2
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

// Encrypt Private Key (JWK JSON string) with User Password
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

  return {
    encryptedJwkB64: btoa(String.fromCharCode(...new Uint8Array(encryptedBuffer))),
    saltB64: btoa(String.fromCharCode(...salt)),
    ivB64: btoa(String.fromCharCode(...iv))
  };
}

// Decrypt Private Key (JWK) using User Password
async function decryptPrivateKey(encryptedData, password) {
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
    { name: "RSA-OAEP", hash: "SHA-256" },
    true,
    ["decrypt"]
  );
}

// Save encrypted identity into sessionStorage
function saveSessionIdentity(username, id, pubKeyB64, encryptedPrivateKeyData) {
  const payload = {
    username,
    id,
    pubKeyB64,
    encryptedPrivateKeyData
  };
  sessionStorage.setItem(SESSION_IDENTITY, JSON.stringify(payload));
}

// Read stored identity from sessionStorage
function getStoredSessionIdentity() {
  const stored = sessionStorage.getItem(SESSION_IDENTITY);
  if (!stored) return null;
  try {
    return JSON.parse(stored);
  } catch (e) {
    return null;
  }
}

// Clear all Session Storage Data
function clearSession() {
  sessionStorage.clear();
  identity = null;
  contacts = [];
  activeContact = null;
  if (ws) {
    ws.close();
    ws = null;
  }
  showToast("Session beendet");
  location.reload();
}

// UI Elements
const setupScreen = document.getElementById('setup-screen');
const unlockScreen = document.getElementById('unlock-screen');
const chatScreen = document.getElementById('chat-screen');

const usernameInput = document.getElementById('username-input');
const passwordInput = document.getElementById('password-input');
const generateKeysBtn = document.getElementById('generate-keys-btn');
const setupStatus = document.getElementById('setup-status');

const unlockPasswordInput = document.getElementById('unlock-password-input');
const unlockBtn = document.getElementById('unlock-btn');
const resetSessionBtn = document.getElementById('reset-session-btn');
const unlockStatus = document.getElementById('unlock-status');
const unlockUserTagline = document.getElementById('unlock-user-tagline');

const logoutBtn = document.getElementById('logout-btn');
const myAvatar = document.getElementById('my-avatar');
const myUsernameEl = document.getElementById('my-username');
const myIdEl = document.getElementById('my-id');
const wsStatusDot = document.getElementById('ws-status-dot');

const showQrBtn = document.getElementById('show-qr-btn');
const exportKeysBtn = document.getElementById('export-keys-btn');

const singleInviteInput = document.getElementById('single-invite-input');
const peerIdInput = document.getElementById('peer-id-input');
const peerKeyInput = document.getElementById('peer-key-input');
const addContactBtn = document.getElementById('add-contact-btn');
const scanQrBtn = document.getElementById('scan-qr-btn');
const contactsList = document.getElementById('contacts-list');

const chatHeader = document.getElementById('chat-header');
const emptyState = document.getElementById('empty-state');
const activeAvatar = document.getElementById('active-avatar');
const activeContactName = document.getElementById('active-contact-name');
const messagesContainer = document.getElementById('messages-container');
const sendMessageForm = document.getElementById('send-message-form');
const messageInput = document.getElementById('message-input');

const mobileToggleBtn = document.getElementById('mobile-toggle-btn');
const mobileBackBtn = document.getElementById('mobile-back-btn');
const sidebar = document.getElementById('sidebar');

const qrModal = document.getElementById('qr-modal');
const closeQrModalBtn = document.getElementById('close-qr-modal-btn');
const qrCodeContainer = document.getElementById('qr-code-container');
const copyQrJsonBtn = document.getElementById('copy-qr-json-btn');

const scannerModal = document.getElementById('scanner-modal');
const closeScannerModalBtn = document.getElementById('close-scanner-modal-btn');

document.addEventListener('DOMContentLoaded', () => {
  checkSessionState();

  // Setup / Registration Handler
  generateKeysBtn.addEventListener('click', async () => {
    const username = usernameInput.value.trim();
    const password = passwordInput.value;

    if (!username || !password) {
      alert('Bitte sowohl einen Namen als auch ein Passwort eingeben.');
      return;
    }

    if (password.length < 4) {
      alert('Das Passwort sollte mindestens 4 Zeichen lang sein.');
      return;
    }

    setupStatus.textContent = 'Generiere RSA-2048 Schlüsselpaar & Verschlüssele Private Key...';

    try {
      const keyPair = await generateKeyPair();
      const pubKeyB64 = await exportPublicKey(keyPair.publicKey);
      const encryptedPrivateKeyData = await encryptPrivateKey(keyPair.privateKey, password);
      const id = generate8DigitId();

      identity = {
        username,
        id,
        keyPair,
        pubKeyB64
      };

      saveSessionIdentity(username, id, pubKeyB64, encryptedPrivateKeyData);
      initMainChatUI();
      showToast("Identity & Schlüssel erfolgreich erstellt");
    } catch (e) {
      console.error(e);
      setupStatus.textContent = 'Fehler beim Erstellen der Schlüssel.';
    }
  });

  // Unlock Session Handler
  unlockBtn.addEventListener('click', async () => {
    const stored = getStoredSessionIdentity();
    if (!stored) return;

    const password = unlockPasswordInput.value;
    if (!password) {
      alert('Bitte Passwort eingeben.');
      return;
    }

    unlockStatus.textContent = 'Entschlüssele Private Key...';

    try {
      const privateKey = await decryptPrivateKey(stored.encryptedPrivateKeyData, password);
      const publicKey = await importPublicKey(stored.pubKeyB64);

      identity = {
        username: stored.username,
        id: stored.id,
        pubKeyB64: stored.pubKeyB64,
        keyPair: {
          publicKey,
          privateKey
        }
      };

      unlockScreen.classList.add('hidden');
      initMainChatUI();
      showToast("Session erfolgreich entschlüsselt");
    } catch (e) {
      console.error(e);
      unlockStatus.textContent = 'Falsches Passwort oder beschädigte Key-Daten.';
    }
  });

  resetSessionBtn.addEventListener('click', () => {
    clearSession();
  });

  if (logoutBtn) {
    logoutBtn.addEventListener('click', () => {
      clearSession();
    });
  }
});

function checkSessionState() {
  const stored = getStoredSessionIdentity();
  if (!stored) {
    setupScreen.classList.remove('hidden');
    unlockScreen.classList.add('hidden');
    chatScreen.classList.add('hidden');
  } else {
    setupScreen.classList.add('hidden');
    unlockScreen.classList.remove('hidden');
    chatScreen.classList.add('hidden');
    unlockUserTagline.textContent = `Willkommen zurück, ${stored.username}! Gib dein Passwort ein.`;
  }
}

function initMainChatUI() {
  setupScreen.classList.add('hidden');
  unlockScreen.classList.add('hidden');
  chatScreen.classList.remove('hidden');

  myAvatar.textContent = identity.username.slice(0, 2).toUpperCase();
  myUsernameEl.textContent = identity.username;
  myIdEl.textContent = `ID: ${identity.id}`;

  loadContactsFromSession();
  renderContacts();
  connectWebSocket();
  setupEventListeners();
}

function setupEventListeners() {
  // Mobile sidebar toggle
  if (mobileToggleBtn) {
    mobileToggleBtn.addEventListener('click', () => {
      sidebar.classList.toggle('mobile-hidden');
    });
  }

  if (mobileBackBtn) {
    mobileBackBtn.addEventListener('click', () => {
      sidebar.classList.remove('mobile-hidden');
    });
  }

  // Export Keys / Invite JSON
  exportKeysBtn.addEventListener('click', () => {
    if (!identity) return;
    const exportData = JSON.stringify({
      id: identity.id,
      user: identity.username,
      key: identity.pubKeyB64
    });
    
    navigator.clipboard.writeText(exportData);
    showToast("Einladungscode in Zwischenablage kopiert");
  });

  // Single Input Auto-Parser for Invites
  singleInviteInput.addEventListener('input', () => {
    const val = singleInviteInput.value.trim();
    if (!val) return;

    try {
      let parsed = null;
      if (val.startsWith('{')) {
        parsed = JSON.parse(val);
      } else {
        // Try Base64 encoded JSON
        try {
          parsed = JSON.parse(atob(val));
        } catch (err) {}
      }

      if (parsed && (parsed.id || parsed.key)) {
        if (parsed.id) peerIdInput.value = parsed.id;
        if (parsed.key) peerKeyInput.value = parsed.key;
        singleInviteInput.value = '';
        showToast("Einladungscode geparst");
      }
    } catch (e) {
      // Input is not valid JSON yet
    }
  });

  // Add Contact Handler
  addContactBtn.addEventListener('click', async () => {
    const id = peerIdInput.value.trim();
    const keyB64 = peerKeyInput.value.trim();

    if (id.length !== 8 || !keyB64) {
      alert('Bitte eine 8-stellige ID und den Public Key eingeben.');
      return;
    }

    try {
      const importedKey = await importPublicKey(keyB64);
      const existingIndex = contacts.findIndex(c => c.id === id);
      const newContact = { id, keyB64, keyObject: importedKey };

      if (existingIndex >= 0) {
        contacts[existingIndex] = newContact;
      } else {
        contacts.push(newContact);
      }

      saveContactsToSession();
      renderContacts();

      peerIdInput.value = '';
      peerKeyInput.value = '';
      singleInviteInput.value = '';
      showToast(`Kontakt ${id} gespeichert`);
    } catch (e) {
      alert('Ungültiger Key. Import fehlgeschlagen.');
    }
  });

  // Show QR Modal Handler
  showQrBtn.addEventListener('click', () => {
    if (!identity) return;
    qrCodeContainer.innerHTML = '';

    const invitePayload = JSON.stringify({
      id: identity.id,
      user: identity.username,
      key: identity.pubKeyB64
    });

    if (typeof QRCode !== 'undefined') {
      new QRCode(qrCodeContainer, {
        text: invitePayload,
        width: 180,
        height: 180,
        colorDark: "#000000",
        colorLight: "#ffffff",
        correctLevel: QRCode.CorrectLevel.L
      });
    } else {
      qrCodeContainer.textContent = "QR-Bibliothek geladen...";
    }

    qrModal.classList.remove('hidden');
  });

  closeQrModalBtn.addEventListener('click', () => {
    qrModal.classList.add('hidden');
  });

  copyQrJsonBtn.addEventListener('click', () => {
    if (!identity) return;
    const invitePayload = JSON.stringify({
      id: identity.id,
      user: identity.username,
      key: identity.pubKeyB64
    });
    navigator.clipboard.writeText(invitePayload);
    showToast("Schlüssel kopiert");
  });

  // Camera Scan QR Modal Handler
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
        (errorMessage) => {
          // Scanning in progress
        }
      ).catch(err => {
        console.error("Kamerafehler:", err);
        showToast("Kamera konnte nicht gestartet werden");
      });
    }
  });

  closeScannerModalBtn.addEventListener('click', stopScannerModal);

  // Send Message Handler
  sendMessageForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const text = messageInput.value.trim();
    if (!text || !activeContact) return;

    try {
      const ciphertextB64 = await encryptMessage(text, activeContact.keyObject);
      const msgObj = { text, type: 'own', timestamp: Date.now() };

      appendMessageUI(msgObj);
      saveChatMessage(activeContact.id, msgObj);
      messageInput.value = '';

      // Send payload over WebSocket
      if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({
          targetId: activeContact.id,
          senderId: identity.id,
          ciphertext: ciphertextB64
        }));
      } else {
        showToast("Relay nicht verbunden (Offline Modus)");
      }
    } catch (err) {
      console.error(err);
      showToast("Verschlüsselungsfehler");
    }
  });
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
  showToast("QR-Code gescannt");
  try {
    const parsed = JSON.parse(decodedText);
    if (parsed.id && parsed.key) {
      peerIdInput.value = parsed.id;
      peerKeyInput.value = parsed.key;
    }
  } catch (e) {
    peerKeyInput.value = decodedText;
  }
  stopScannerModal();
}

// --- SESSION CHAT & CONTACT STORAGE MANAGEMENT ---

function loadContactsFromSession() {
  const stored = sessionStorage.getItem(SESSION_CONTACTS);
  if (stored) {
    try {
      const serializable = JSON.parse(stored);
      contacts = [];
      for (const c of serializable) {
        importPublicKey(c.keyB64).then(keyObj => {
          contacts.push({ id: c.id, keyB64: c.keyB64, keyObject: keyObj });
          renderContacts();
        }).catch(err => console.error(err));
      }
    } catch (e) {
      console.error(e);
    }
  }
}

function saveContactsToSession() {
  const serializable = contacts.map(c => ({ id: c.id, keyB64: c.keyB64 }));
  sessionStorage.setItem(SESSION_CONTACTS, JSON.stringify(serializable));
}

function renderContacts() {
  contactsList.innerHTML = '';
  contacts.forEach(c => {
    const li = document.createElement('li');
    li.className = `contact-item ${activeContact && activeContact.id === c.id ? 'active' : ''}`;
    li.innerHTML = `
      <div class="avatar">${c.id.slice(0, 2)}</div>
      <div class="contact-id">ID: ${c.id}</div>
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

  activeAvatar.textContent = contact.id.slice(0, 2);
  activeContactName.textContent = `Chat ID: ${contact.id}`;

  loadAndRenderChatHistory(contact.id);
}

function getChatHistory(contactId) {
  const stored = sessionStorage.getItem(SESSION_CHAT_PREFIX + contactId);
  if (!stored) return [];
  try {
    return JSON.parse(stored);
  } catch (e) {
    return [];
  }
}

function saveChatMessage(contactId, msgObj) {
  const history = getChatHistory(contactId);
  history.push(msgObj);
  sessionStorage.setItem(SESSION_CHAT_PREFIX + contactId, JSON.stringify(history));
}

function loadAndRenderChatHistory(contactId) {
  messagesContainer.innerHTML = '';
  const history = getChatHistory(contactId);
  history.forEach(msg => appendMessageUI(msg));
  scrollToBottom();
}

function appendMessageUI(msgObj) {
  const time = new Date(msgObj.timestamp || Date.now()).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  const div = document.createElement('div');
  div.className = `msg-bubble ${msgObj.type}`;
  div.innerHTML = `
    <div>${escapeHtml(msgObj.text)}</div>
    <div class="msg-meta">${time}</div>
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

// --- WEBSOCKET RELAY CONNECTION ---

function connectWebSocket() {
  if (!identity) return;

  const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const wsHost = window.location.hostname || 'localhost';
  const wsUrl = `${wsProtocol}//${wsHost}:8080/ws`;

  try {
    ws = new WebSocket(wsUrl);

    ws.onopen = () => {
      wsStatusDot.className = 'dot online';
      // Register current user ID with WebSocket server
      ws.send(JSON.stringify({
        type: 'register',
        clientId: identity.id
      }));
    };

    ws.onmessage = async (event) => {
      try {
        const data = JSON.parse(event.data);
        if (data.ciphertext && data.senderId) {
          // Decrypt payload using private RSA key
          const decryptedText = await decryptMessage(data.ciphertext, identity.keyPair.privateKey);
          const msgObj = { text: decryptedText, type: 'other', timestamp: Date.now() };

          saveChatMessage(data.senderId, msgObj);

          if (activeContact && activeContact.id === data.senderId) {
            appendMessageUI(msgObj);
          } else {
            showToast(`Neue Nachricht von ${data.senderId}`);
          }
        }
      } catch (err) {
        console.error("Relay empfing ungültige oder unentschlüsselbare Nachricht:", err);
      }
    };

    ws.onerror = () => {
      wsStatusDot.className = 'dot offline';
    };

    ws.onclose = () => {
      wsStatusDot.className = 'dot offline';
      // Auto-reconnect try
      setTimeout(() => {
        if (identity) connectWebSocket();
      }, 5000);
    };
  } catch (e) {
    wsStatusDot.className = 'dot offline';
  }
}
