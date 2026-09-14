// AegisChat Client Application Logic
const STORAGE_IDENTITY = 'aegis_identity';
const STORAGE_CONTACTS = 'aegis_contacts';

let identity = null;
let contacts = [];
let activeContact = null;

function generate8DigitId() {
  return Math.floor(10000000 + Math.random() * 90000000).toString();
}

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

async function exportPublicKey(key) {
  const exported = await window.crypto.subtle.exportKey("jwk", key);
  return btoa(JSON.stringify(exported));
}

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

async function encryptMessage(text, publicKey) {
  const enc = new TextEncoder();
  const ciphertext = await window.crypto.subtle.encrypt(
    { name: "RSA-OAEP" },
    publicKey,
    enc.encode(text)
  );
  return btoa(String.fromCharCode(...new Uint8Array(ciphertext)));
}

// UI Elements
const setupScreen = document.getElementById('setup-screen');
const chatScreen = document.getElementById('chat-screen');
const usernameInput = document.getElementById('username-input');
const generateKeysBtn = document.getElementById('generate-keys-btn');
const setupStatus = document.getElementById('setup-status');

const myAvatar = document.getElementById('my-avatar');
const myUsernameEl = document.getElementById('my-username');
const myIdEl = document.getElementById('my-id');
const exportKeysBtn = document.getElementById('export-keys-btn');

const peerIdInput = document.getElementById('peer-id-input');
const peerKeyInput = document.getElementById('peer-key-input');
const addContactBtn = document.getElementById('add-contact-btn');
const contactsList = document.getElementById('contacts-list');

const chatHeader = document.getElementById('chat-header');
const emptyState = document.getElementById('empty-state');
const activeAvatar = document.getElementById('active-avatar');
const activeContactName = document.getElementById('active-contact-name');
const messagesContainer = document.getElementById('messages-container');
const sendMessageForm = document.getElementById('send-message-form');
const messageInput = document.getElementById('message-input');

document.addEventListener('DOMContentLoaded', () => {
  loadContacts();

  generateKeysBtn.addEventListener('click', async () => {
    const username = usernameInput.value.trim();
    if (!username) {
      alert('Bitte gib deinen Namen ein.');
      return;
    }

    setupStatus.textContent = 'Generiere RSA-2048 Schlüsselpaar...';
    
    const keyPair = await generateKeyPair();
    const pubKeyB64 = await exportPublicKey(keyPair.publicKey);
    const id = generate8DigitId();

    identity = { username, id, keyPair, pubKeyB64 };

    myAvatar.textContent = username.slice(0, 2).toUpperCase();
    myUsernameEl.textContent = username;
    myIdEl.textContent = `ID: ${id}`;

    setupScreen.classList.add('hidden');
    chatScreen.classList.remove('hidden');
  });

  exportKeysBtn.addEventListener('click', () => {
    if (!identity) return;
    const exportData = JSON.stringify({
      id: identity.id,
      user: identity.username,
      key: identity.pubKeyB64
    });
    
    navigator.clipboard.writeText(identity.pubKeyB64);
    alert(`Dein Public Key wurde kopiert!\n\nDeine Chat-ID: ${identity.id}`);
  });

  addContactBtn.addEventListener('click', async () => {
    const id = peerIdInput.value.trim();
    const keyB64 = peerKeyInput.value.trim();

    if (id.length !== 8 || !keyB64) {
      alert('Bitte eine 8-stellige ID und den Public Key eingeben.');
      return;
    }

    try {
      const importedKey = await importPublicKey(keyB64);
      const newContact = { id, keyB64, keyObject: importedKey };
      contacts.push(newContact);
      saveContacts();
      renderContacts();

      peerIdInput.value = '';
      peerKeyInput.value = '';
    } catch (e) {
      alert('Ungültiger Key. Import fehlgeschlagen.');
    }
  });

  sendMessageForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const text = messageInput.value.trim();
    if (!text || !activeContact) return;

    // Encrypt via Web Crypto API
    const encryptedText = await encryptMessage(text, activeContact.keyObject);
    
    appendMessage(text, 'own');
    messageInput.value = '';

    console.log("Sende verschlüsselten Payload an Peer:", {
      to: activeContact.id,
      encryptedPayload: encryptedText
    });
  });
});

function loadContacts() {
  const stored = localStorage.getItem(STORAGE_CONTACTS);
  if (stored) {
    contacts = JSON.parse(stored);
    renderContacts();
  }
}

function saveContacts() {
  const serializable = contacts.map(c => ({ id: c.id, keyB64: c.keyB64 }));
  localStorage.setItem(STORAGE_CONTACTS, JSON.stringify(serializable));
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

  activeAvatar.textContent = contact.id.slice(0, 2);
  activeContactName.textContent = `Chat ID: ${contact.id}`;
  messagesContainer.innerHTML = '';
}

function appendMessage(text, type) {
  const time = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  const div = document.createElement('div');
  div.className = `msg-bubble ${type}`;
  div.innerHTML = `
    <div>${text}</div>
    <div class="msg-meta">${time}</div>
  `;
  messagesContainer.appendChild(div);
  messagesContainer.scrollTop = messagesContainer.scrollHeight;
}
