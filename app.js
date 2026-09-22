// AegisChat Client Application Logic
// Zero-Knowledge Architecture & WebCrypto E2EE with Admin Dashboard & Invite System

// Storage Keys
const SESSION_KEY = 'aegis_session';
const SESSION_CHAT_PREFIX = 'aegis_chat_';
const LOCAL_ONBOARDED_KEY = 'aegis_onboarded_v1';

// App State
let currentUser = null; // { id, username, main_number }
let userProfile = null; // { is_admin, is_disabled, ... }
let accessToken = null;
let localKeyPair = null; // { publicKey, privateKey }
let localPubKeyB64 = null;
let contacts = []; // Array of { number, nickname, isBurner, pubKeyB64, sharedKey }
let myBurnerNumbers = []; // Array of { id, burner_number, active, expires_at }
let groups = []; // Array of { id, name, members: [number1, number2, ...] }
let activeContact = null;
let activeGroup = null;

// P2P WebRTC Full-Mesh Call State
let meshPeerConnections = new Map(); // peerNumber -> RTCPeerConnection
let meshRemoteStreams = new Map(); // peerNumber -> MediaStream
let realtimeSocket = null;
let heartbeatTimer = null;
let html5QrScanner = null;
let audioContext = null;
let supabaseUrl = null;
let supabaseAnonKey = null;
let supabaseClient = null;
let realtimeChannel = null;

// Track processed message IDs to prevent duplicate handling from WebSocket & REST
const processedMsgIds = new Set();

// Public System Settings & Invite State
let publicRequireInviteCode = false;
let verifiedInviteCode = null;

// FOUNDER & LEAD DEV VIP BADGE HELPER ("ARIEN")
function isFounder(username, number = '') {
  if (username && String(username).toLowerCase().trim() === 'arien') return true;
  return false;
}

function getFounderBadgeHtml(username, extraClass = '') {
  if (isFounder(username)) {
    return `<span class="badge-founder ${extraClass}" title="Founder & Lead Dev"><svg viewBox="0 0 24 24"><path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm-1 6h2v2h-2V7zm0 4h2v6h-2v-6z"/></svg> Founder & Lead Dev</span>`;
  }
  return '';
}
let publicBannerConfig = null;
let vapidPublicKey = null;
let swRegistration = null;

// Privacy & Chat Settings State
let activeSelfDestructTimer = 'off'; // 'off', '10s', '1m', '1h', '24h'
let typingTimeout = null;
let currentStealthMode = 'off'; // 'off', 'calculator', 'notes'

let onboardingCurrentStep = 1;
let selectedFile = null;

// Voice Recording & Media State
let mediaRecorder = null;
let audioChunks = [];
let voiceTimerInterval = null;
let recordingSeconds = 0;
let activeAudioObjectURLs = new Set();

// View Once State
let isViewOnceActive = false;

// WebRTC E2EE Audio & Video Call State
let peerConnection = null;
let localMediaStream = null;
let remoteMediaStream = null;
let currentCallType = null; // 'audio' or 'video'
let activeCallPeerNumber = null;
let isCallInitiator = false;
let callTimerInterval = null;
let callSeconds = 0;
let ringtoneOscillator = null;

// Voice Masking State & Web Audio API Processing Nodes
let isVoiceMaskActive = false;
let voiceMaskAudioCtx = null;
let voiceMaskSourceNode = null;
let voiceMaskDestinationNode = null;
let maskedAudioTrack = null;

const rtcConfig = {
  iceServers: [
    { urls: 'stun:stun.l.google.com:19302' },
    { urls: 'stun:stun1.l.google.com:19302' }
  ]
};

function formatFileSize(bytes) {
  if (!bytes || bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

async function encryptFile(file, sharedKey, onProgress) {
  const arrayBuffer = await file.arrayBuffer();
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const ciphertextBuffer = await window.crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv },
    sharedKey,
    arrayBuffer
  );

  const combinedBuffer = new Uint8Array(iv.byteLength + ciphertextBuffer.byteLength);
  combinedBuffer.set(iv, 0);
  combinedBuffer.set(new Uint8Array(ciphertextBuffer), iv.byteLength);

  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open('POST', '/api/upload?folder=files', true);
    if (accessToken) {
      xhr.setRequestHeader('Authorization', `Bearer ${accessToken}`);
    }
    xhr.setRequestHeader('Content-Type', 'application/octet-stream');

    if (xhr.upload && onProgress) {
      xhr.upload.onprogress = (e) => {
        if (e.lengthComputable) {
          onProgress(Math.round((e.loaded / e.total) * 100));
        }
      };
    }

    xhr.onload = () => {
      if (xhr.status >= 200 && xhr.status < 300) {
        try {
          const res = JSON.parse(xhr.responseText);
          resolve(res);
        } catch (e) {
          reject(new Error('Ungültige Antwort vom Server beim Upload.'));
        }
      } else {
        reject(new Error(`Upload-Fehler (${xhr.status})`));
      }
    };

    xhr.onerror = () => reject(new Error('Netzwerkfehler beim Upload.'));
    xhr.send(combinedBuffer);
  });
}

async function fetchAndDecryptFileBlob(fileUrl, sharedKey, mimeType) {
  const res = await fetch(fileUrl);
  if (!res.ok) throw new Error('Datei konnte nicht geladen werden.');
  const encryptedBuffer = await res.arrayBuffer();

  if (encryptedBuffer.byteLength < 12) {
    throw new Error('Ungültige verschlüsselte Datei.');
  }

  const iv = new Uint8Array(encryptedBuffer, 0, 12);
  const ciphertext = new Uint8Array(encryptedBuffer, 12);

  const decryptedBuffer = await window.crypto.subtle.decrypt(
    { name: "AES-GCM", iv: iv },
    sharedKey,
    ciphertext
  );

  const blob = new Blob([decryptedBuffer], { type: mimeType || 'application/octet-stream' });
  return URL.createObjectURL(blob);
}

function generateForensicSessionHash() {
  if (!currentUser) return 'AEGIS-PROTECTED-SESSION';
  const number = currentUser.main_number || '00000000';
  const now = new Date();
  const timeStr = `${now.getHours()}:${now.getMinutes() < 10 ? '0' : ''}${now.getMinutes()}`;
  return `AEGIS • ID:${number} • ${timeStr} • CONFIDENTIAL`;
}

function updateForensicWatermarks() {
  const text = generateForensicSessionHash();
  const overlays = document.querySelectorAll('.forensic-watermark-overlay');
  overlays.forEach(overlay => {
    overlay.innerHTML = '';
    for (let i = 0; i < 16; i++) {
      const span = document.createElement('span');
      span.className = 'watermark-pattern-text';
      span.textContent = text;
      overlay.appendChild(span);
    }
  });
}

function openLightbox(imgSrc, fileName) {
  const modal = document.getElementById('lightbox-modal');
  const img = document.getElementById('lightbox-img');
  const nameEl = document.getElementById('lightbox-filename');
  const dlBtn = document.getElementById('lightbox-download-btn');

  if (!modal || !img) return;
  img.src = imgSrc;
  if (nameEl) nameEl.textContent = fileName || 'Foto';
  if (dlBtn) {
    dlBtn.href = imgSrc;
    dlBtn.download = fileName || 'photo.png';
  }
  updateForensicWatermarks();
  modal.classList.remove('hidden');
}

function clearSelectedFile() {
  selectedFile = null;
  const fileInput = document.getElementById('file-input');
  if (fileInput) fileInput.value = '';
  const previewBar = document.getElementById('file-preview-bar');
  if (previewBar) previewBar.classList.add('hidden');
  const progressContainer = document.getElementById('upload-progress-container');
  if (progressContainer) progressContainer.classList.add('hidden');
  const progressBar = document.getElementById('upload-progress-bar');
  if (progressBar) progressBar.style.width = '0%';
}

async function startVoiceRecording() {
  if (!activeContact) {
    showToast("Bitte zuerst einen Kontakt auswählen.", true);
    return;
  }
  try {
    const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
    audioChunks = [];
    recordingSeconds = 0;

    let options = {};
    if (typeof MediaRecorder !== 'undefined') {
      if (MediaRecorder.isTypeSupported('audio/webm;codecs=opus')) {
        options = { mimeType: 'audio/webm;codecs=opus' };
      } else if (MediaRecorder.isTypeSupported('audio/webm')) {
        options = { mimeType: 'audio/webm' };
      } else if (MediaRecorder.isTypeSupported('audio/ogg;codecs=opus')) {
        options = { mimeType: 'audio/ogg;codecs=opus' };
      }
    }

    mediaRecorder = new MediaRecorder(stream, options);

    mediaRecorder.ondataavailable = (e) => {
      if (e.data && e.data.size > 0) {
        audioChunks.push(e.data);
      }
    };

    mediaRecorder.start();

    const micBtn = document.getElementById('mic-btn');
    if (micBtn) micBtn.classList.add('recording');

    const recBar = document.getElementById('voice-recording-bar');
    if (recBar) recBar.classList.remove('hidden');

    const timerEl = document.getElementById('recording-timer');
    if (timerEl) timerEl.textContent = '00:00';

    if (voiceTimerInterval) clearInterval(voiceTimerInterval);
    voiceTimerInterval = setInterval(() => {
      recordingSeconds++;
      const mins = String(Math.floor(recordingSeconds / 60)).padStart(2, '0');
      const secs = String(recordingSeconds % 60).padStart(2, '0');
      if (timerEl) timerEl.textContent = `${mins}:${secs}`;
    }, 1000);

  } catch (err) {
    showToast("Zugriff auf Mikrofon verweigert oder nicht unterstützt.", true);
  }
}

async function stopAndSendVoiceRecording() {
  if (!mediaRecorder || mediaRecorder.state === 'inactive') return;

  mediaRecorder.onstop = async () => {
    if (voiceTimerInterval) clearInterval(voiceTimerInterval);
    const micBtn = document.getElementById('mic-btn');
    if (micBtn) micBtn.classList.remove('recording');
    const recBar = document.getElementById('voice-recording-bar');
    if (recBar) recBar.classList.add('hidden');

    if (audioChunks.length === 0 || recordingSeconds === 0) {
      showToast("Aufnahme zu kurz.", true);
      return;
    }

    const mimeType = mediaRecorder.mimeType || 'audio/webm';
    const audioBlob = new Blob(audioChunks, { type: mimeType });
    audioChunks = [];

    if (!activeContact) return;

    try {
      showToast("Verschlüssele und sende Sprachnachricht...");
      const arrayBuffer = await audioBlob.arrayBuffer();

      const iv = window.crypto.getRandomValues(new Uint8Array(12));
      const ciphertextBuffer = await window.crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        activeContact.sharedKey,
        arrayBuffer
      );

      const combinedBuffer = new Uint8Array(iv.byteLength + ciphertextBuffer.byteLength);
      combinedBuffer.set(iv, 0);
      combinedBuffer.set(new Uint8Array(ciphertextBuffer), iv.byteLength);

      const uploadRes = await fetch('/api/upload?folder=audios', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/octet-stream',
          ...(accessToken ? { 'Authorization': `Bearer ${accessToken}` } : {})
        },
        body: combinedBuffer
      });

      if (!uploadRes.ok) {
        throw new Error('Upload der Sprachnachricht fehlgeschlagen.');
      }

      const uploadData = await uploadRes.json();
      const senderNumber = document.getElementById('send-as-select').value || currentUser.main_number;

      const voicePayloadText = JSON.stringify({
        type: 'voice',
        file_url: uploadData.file_url,
        file_id: uploadData.file_id,
        duration: recordingSeconds,
        mime_type: mimeType,
        view_once: isViewOnceActive
      });

      if (isViewOnceActive) {
        isViewOnceActive = false;
        const viewOnceBtn = document.getElementById('view-once-toggle-btn');
        if (viewOnceBtn) viewOnceBtn.classList.remove('active');
      }

      const encryptedPayloadStr = await encryptPayload(voicePayloadText, activeContact.sharedKey);

      const msgRes = await fetch('/api/messages', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(accessToken ? { 'Authorization': `Bearer ${accessToken}` } : {})
        },
        body: JSON.stringify({
          sender_number: senderNumber,
          recipient_number: activeContact.number,
          encrypted_payload: encryptedPayloadStr
        })
      });

      if (!msgRes.ok) {
        throw new Error('Fehler beim Senden der Sprachnachricht.');
      }

      let expiresAt = null;
      if (activeSelfDestructTimer === '10s') expiresAt = Date.now() + 10 * 1000;
      else if (activeSelfDestructTimer === '1m') expiresAt = Date.now() + 60 * 1000;
      else if (activeSelfDestructTimer === '1h') expiresAt = Date.now() + 3600 * 1000;
      else if (activeSelfDestructTimer === '24h') expiresAt = Date.now() + 24 * 3600 * 1000;

      const msgObj = {
        id: generate8DigitId(),
        sender_number: senderNumber,
        recipient_number: activeContact.number,
        text: voicePayloadText,
        type: 'own',
        timestamp: Date.now(),
        expiresAt: expiresAt,
        status: 'sent'
      };

      appendMessageUI(msgObj, true);
      saveChatMessage(activeContact.number, msgObj);
      playSoundFeedback('send');

      if (expiresAt) {
        scheduleSelfDestruct(msgObj.id, activeContact.number, expiresAt - Date.now());
      }
    } catch (err) {
      showToast(err.message, true);
    }
  };

  mediaRecorder.stop();
  if (mediaRecorder.stream) {
    mediaRecorder.stream.getTracks().forEach(track => track.stop());
  }
}

function cancelVoiceRecording() {
  if (voiceTimerInterval) clearInterval(voiceTimerInterval);
  if (mediaRecorder && mediaRecorder.state !== 'inactive') {
    mediaRecorder.onstop = null;
    mediaRecorder.stop();
    if (mediaRecorder.stream) {
      mediaRecorder.stream.getTracks().forEach(track => track.stop());
    }
  }
  audioChunks = [];
  const micBtn = document.getElementById('mic-btn');
  if (micBtn) micBtn.classList.remove('recording');
  const recBar = document.getElementById('voice-recording-bar');
  if (recBar) recBar.classList.add('hidden');
}


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

// --- CALL OVERLAY & WEBRTC SIGNALING LOGIC ---

function playRingtoneSound(isIncoming = false) {
  stopRingtoneSound();
  try {
    if (!audioContext) {
      audioContext = new (window.AudioContext || window.webkitAudioContext)();
    }
    if (audioContext.state === 'suspended') {
      audioContext.resume();
    }
    ringtoneOscillator = audioContext.createOscillator();
    const gain = audioContext.createGain();
    ringtoneOscillator.connect(gain);
    gain.connect(audioContext.destination);

    const now = audioContext.currentTime;
    gain.gain.setValueAtTime(0.12, now);

    if (isIncoming) {
      ringtoneOscillator.type = 'sine';
      ringtoneOscillator.frequency.setValueAtTime(440, now);
      ringtoneOscillator.frequency.setValueAtTime(880, now + 0.25);
    } else {
      ringtoneOscillator.type = 'sine';
      ringtoneOscillator.frequency.setValueAtTime(425, now);
    }
    ringtoneOscillator.start();
  } catch (e) {}
}

function stopRingtoneSound() {
  if (ringtoneOscillator) {
    try {
      ringtoneOscillator.stop();
      ringtoneOscillator.disconnect();
    } catch (e) {}
    ringtoneOscillator = null;
  }
}

function showCallModal(state) {
  const modal = document.getElementById('call-modal');
  const boxOutgoing = document.getElementById('call-state-outgoing');
  const boxIncoming = document.getElementById('call-state-incoming');
  const boxActive = document.getElementById('call-state-active');

  if (!modal) return;
  modal.classList.remove('hidden');
  boxOutgoing.classList.add('hidden');
  boxIncoming.classList.add('hidden');
  boxActive.classList.add('hidden');

  if (state === 'outgoing') boxOutgoing.classList.remove('hidden');
  else if (state === 'incoming') boxIncoming.classList.remove('hidden');
  else if (state === 'active') boxActive.classList.remove('hidden');
}

function hideCallModal() {
  stopRingtoneSound();
  if (callTimerInterval) {
    clearInterval(callTimerInterval);
    callTimerInterval = null;
  }
  callSeconds = 0;
  const modal = document.getElementById('call-modal');
  if (modal) modal.classList.add('hidden');
}

async function startE2eeCall(type) {
  if (!activeContact && !activeGroup) {
    showToast("Bitte zuerst einen Kontakt oder Gruppenraum auswählen.", true);
    return;
  }

  if (activeGroup) {
    await startMeshGroupCall(type);
    return;
  }

  currentCallType = type;
  activeCallPeerNumber = activeContact.number;
  isCallInitiator = true;

  const peerDisplayName = activeContact.nickname || activeContact.number;
  document.getElementById('call-outgoing-name').textContent = `Rufe ${peerDisplayName} an...`;
  document.getElementById('call-outgoing-subtitle').textContent = `Verschlüsselter WebRTC ${type === 'video' ? 'Video' : 'Audio'} Call`;
  document.getElementById('call-outgoing-avatar').textContent = peerDisplayName.slice(0, 2).toUpperCase();

  showCallModal('outgoing');
  playRingtoneSound(false);

  try {
    const constraints = {
      audio: true,
      video: type === 'video' ? { width: { ideal: 1280 }, height: { ideal: 720 }, facingMode: "user" } : false
    };

    localMediaStream = await navigator.mediaDevices.getUserMedia(constraints);
    setupRTCPeerConnection();

    const offer = await peerConnection.createOffer();
    await peerConnection.setLocalDescription(offer);

    await sendCallSignal('call-offer', {
      callType: type,
      sdp: offer
    });
  } catch (err) {
    showToast(`Zugriff auf Mikrofon/Kamera fehlgeschlagen: ${err.message}`, true);
    cleanupCallState();
  }
}

async function startMeshGroupCall(type) {
  if (!activeGroup) return;
  currentCallType = type;
  isCallInitiator = true;

  document.getElementById('call-outgoing-name').textContent = `Starte Gruppenanruf: ${activeGroup.name}`;
  document.getElementById('call-outgoing-subtitle').textContent = `P2P WebRTC Full-Mesh (${activeGroup.members.length + 1} Teilnehmer)`;
  document.getElementById('call-outgoing-avatar').textContent = '👥';

  showCallModal('outgoing');
  playRingtoneSound(false);

  try {
    const constraints = {
      audio: true,
      video: type === 'video' ? { width: { ideal: 1280 }, height: { ideal: 720 }, facingMode: "user" } : false
    };

    localMediaStream = await navigator.mediaDevices.getUserMedia(constraints);

    for (const memberNumber of activeGroup.members) {
      const pc = setupMeshPeerConnection(memberNumber);
      const offer = await pc.createOffer();
      await pc.setLocalDescription(offer);

      await sendDirectCallSignal('call-offer', memberNumber, {
        callType: type,
        groupId: activeGroup.id,
        sdp: offer
      });
    }

    startActiveCallUI();
    updateMeshVideoGridUI();
  } catch (err) {
    showToast(`Fehler beim Starten des Gruppenanrufs: ${err.message}`, true);
    cleanupCallState();
  }
}

function setupMeshPeerConnection(memberNumber) {
  if (meshPeerConnections.has(memberNumber)) {
    try { meshPeerConnections.get(memberNumber).close(); } catch(e) {}
  }

  const pc = new RTCPeerConnection(rtcConfig);
  meshPeerConnections.set(memberNumber, pc);

  const remoteStream = new MediaStream();
  meshRemoteStreams.set(memberNumber, remoteStream);

  if (localMediaStream) {
    const audioTrack = (isVoiceMaskActive && maskedAudioTrack) ? maskedAudioTrack : localMediaStream.getAudioTracks()[0];
    if (audioTrack) pc.addTrack(audioTrack, localMediaStream);
    localMediaStream.getVideoTracks().forEach(track => pc.addTrack(track, localMediaStream));
  }

  pc.ontrack = (event) => {
    event.streams[0].getTracks().forEach(track => remoteStream.addTrack(track));
    updateMeshVideoGridUI();
  };

  pc.onicecandidate = (event) => {
    if (event.candidate) {
      sendDirectCallSignal('call-ice-candidate', memberNumber, { candidate: event.candidate });
    }
  };

  pc.oniceconnectionstatechange = () => {
    if (pc.iceConnectionState === 'disconnected' || pc.iceConnectionState === 'failed' || pc.iceConnectionState === 'closed') {
      meshPeerConnections.delete(memberNumber);
      meshRemoteStreams.delete(memberNumber);
      updateMeshVideoGridUI();
    }
  };

  return pc;
}

async function sendDirectCallSignal(event, recipientNumber, payloadData) {
  const myNumber = document.getElementById('send-as-select').value || currentUser.main_number;
  const signalPayload = JSON.stringify({
    type: 'call-signal',
    event: event,
    sender: myNumber,
    recipient: recipientNumber,
    data: payloadData
  });

  let contact = contacts.find(c => c.number === recipientNumber);
  if (!contact) {
    try { contact = await addOrResolveContact(recipientNumber); } catch(e) {}
  }
  if (!contact || !contact.sharedKey) return;

  const encryptedPayload = await encryptPayload(signalPayload, contact.sharedKey);

  if (realtimeChannel) {
    realtimeChannel.send({
      type: 'broadcast',
      event: 'call-signal',
      payload: { encryptedPayload, recipient: recipientNumber, sender: myNumber }
    });
  }

  fetch('/api/messages', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...(accessToken ? { 'Authorization': `Bearer ${accessToken}` } : {})
    },
    body: JSON.stringify({
      sender_number: myNumber,
      recipient_number: recipientNumber,
      encrypted_payload: encryptedPayload
    })
  }).catch(() => {});
}

function updateMeshVideoGridUI() {
  const container = document.querySelector('.video-viewport-container');
  if (!container) return;

  if (meshRemoteStreams.size === 0 && !activeGroup) return;

  let grid = container.querySelector('.mesh-video-grid');
  if (!grid) {
    grid = document.createElement('div');
    grid.className = 'mesh-video-grid';
    container.appendChild(grid);
  } else {
    grid.innerHTML = '';
  }

  // Hide single call elements if group call grid is active
  const remoteVideo = document.getElementById('remote-video');
  const localVideo = document.getElementById('local-video');
  const fallbackAvatar = document.getElementById('audio-call-fallback-avatar');
  if (remoteVideo) remoteVideo.classList.add('hidden');
  if (localVideo) localVideo.classList.add('hidden');
  if (fallbackAvatar) fallbackAvatar.classList.add('hidden');

  // Add local video tile
  if (localMediaStream) {
    const tile = document.createElement('div');
    tile.className = 'mesh-video-tile';
    const v = document.createElement('video');
    v.autoplay = true;
    v.playsinline = true;
    v.muted = true;
    v.srcObject = localMediaStream;
    const label = document.createElement('span');
    label.className = 'mesh-video-label';
    label.textContent = `Du (${currentUser.username})`;
    tile.appendChild(v);
    tile.appendChild(label);
    grid.appendChild(tile);
  }

  // Add remote video tiles for mesh peers
  meshRemoteStreams.forEach((stream, memberNumber) => {
    const contact = contacts.find(c => c.number === memberNumber);
    const displayName = contact ? (contact.nickname || contact.number) : memberNumber;

    const tile = document.createElement('div');
    tile.className = 'mesh-video-tile';
    const v = document.createElement('video');
    v.autoplay = true;
    v.playsinline = true;
    v.srcObject = stream;
    const label = document.createElement('span');
    label.className = 'mesh-video-label';
    label.textContent = displayName;
    tile.appendChild(v);
    tile.appendChild(label);
    grid.appendChild(tile);
  });
}

function setupRTCPeerConnection() {
  if (peerConnection) {
    try { peerConnection.close(); } catch(e) {}
  }

  peerConnection = new RTCPeerConnection(rtcConfig);
  remoteMediaStream = new MediaStream();

  const remoteVideo = document.getElementById('remote-video');
  const localVideo = document.getElementById('local-video');
  const fallbackAvatar = document.getElementById('audio-call-fallback-avatar');

  if (remoteVideo) remoteVideo.srcObject = remoteMediaStream;

  if (localMediaStream) {
    if (localVideo) {
      if (currentCallType === 'video') {
        localVideo.srcObject = localMediaStream;
        localVideo.classList.remove('hidden');
      } else {
        localVideo.classList.add('hidden');
      }
    }

    const audioTrack = (isVoiceMaskActive && maskedAudioTrack) ? maskedAudioTrack : localMediaStream.getAudioTracks()[0];
    if (audioTrack) {
      peerConnection.addTrack(audioTrack, localMediaStream);
    }
    localMediaStream.getVideoTracks().forEach(track => {
      peerConnection.addTrack(track, localMediaStream);
    });
  }

  if (currentCallType === 'audio') {
    if (fallbackAvatar) fallbackAvatar.classList.remove('hidden');
  } else {
    if (fallbackAvatar) fallbackAvatar.classList.add('hidden');
  }

  peerConnection.ontrack = (event) => {
    event.streams[0].getTracks().forEach(track => {
      remoteMediaStream.addTrack(track);
    });
  };

  peerConnection.onicecandidate = (event) => {
    if (event.candidate && activeCallPeerNumber) {
      sendCallSignal('call-ice-candidate', { candidate: event.candidate });
    }
  };

  peerConnection.oniceconnectionstatechange = () => {
    if (peerConnection) {
      if (peerConnection.iceConnectionState === 'disconnected' || peerConnection.iceConnectionState === 'failed' || peerConnection.iceConnectionState === 'closed') {
        cleanupCallState();
      }
    }
  };
}

async function sendCallSignal(event, payloadData) {
  if (!activeCallPeerNumber) return;
  const myNumber = document.getElementById('send-as-select').value || currentUser.main_number;
  const signalPayload = JSON.stringify({
    type: 'call-signal',
    event: event,
    sender: myNumber,
    recipient: activeCallPeerNumber,
    data: payloadData
  });

  const contact = contacts.find(c => c.number === activeCallPeerNumber);
  if (!contact) return;

  const encryptedPayload = await encryptPayload(signalPayload, contact.sharedKey);

  if (realtimeChannel) {
    realtimeChannel.send({
      type: 'broadcast',
      event: 'call-signal',
      payload: { encryptedPayload, recipient: activeCallPeerNumber, sender: myNumber }
    });
  }

  fetch('/api/messages', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...(accessToken ? { 'Authorization': `Bearer ${accessToken}` } : {})
    },
    body: JSON.stringify({
      sender_number: myNumber,
      recipient_number: activeCallPeerNumber,
      encrypted_payload: encryptedPayload
    })
  }).catch(() => {});
}

async function handleIncomingCallSignal(signal) {
  const { event, sender, data } = signal;

  if (event === 'call-offer') {
    if (peerConnection && peerConnection.signalingState !== 'closed') {
      return;
    }

    activeCallPeerNumber = sender;
    currentCallType = data.callType || 'audio';
    isCallInitiator = false;

    const contact = contacts.find(c => c.number === sender);
    const displayName = contact ? (contact.nickname || contact.number) : sender;

    document.getElementById('call-incoming-name').textContent = `Eingehender ${currentCallType === 'video' ? 'Video' : 'Audio'}-Anruf`;
    document.getElementById('call-incoming-subtitle').textContent = `Von: ${displayName} (E2EE Verschlüsselt)`;
    document.getElementById('call-incoming-avatar').textContent = displayName.slice(0, 2).toUpperCase();

    showCallModal('incoming');
    playRingtoneSound(true);

    window._pendingCallOffer = data.sdp;
  } else if (event === 'call-answer') {
    if (isCallInitiator && peerConnection) {
      stopRingtoneSound();
      await peerConnection.setRemoteDescription(new RTCSessionDescription(data.sdp));
      startActiveCallUI();
    }
  } else if (event === 'call-ice-candidate') {
    if (peerConnection && data.candidate) {
      try {
        await peerConnection.addIceCandidate(new RTCIceCandidate(data.candidate));
      } catch (e) {}
    }
  } else if (event === 'call-end') {
    showToast("Anruf beendet.");
    cleanupCallState();
  }
}

async function acceptIncomingCall() {
  stopRingtoneSound();
  if (!activeCallPeerNumber || !window._pendingCallOffer) {
    cleanupCallState();
    return;
  }

  try {
    const constraints = {
      audio: true,
      video: currentCallType === 'video' ? { width: { ideal: 1280 }, height: { ideal: 720 }, facingMode: "user" } : false
    };

    localMediaStream = await navigator.mediaDevices.getUserMedia(constraints);
    setupRTCPeerConnection();

    await peerConnection.setRemoteDescription(new RTCSessionDescription(window._pendingCallOffer));
    window._pendingCallOffer = null;

    const answer = await peerConnection.createAnswer();
    await peerConnection.setLocalDescription(answer);

    await sendCallSignal('call-answer', { sdp: answer });
    startActiveCallUI();
  } catch (err) {
    showToast(`Fehler beim Annehmen des Anrufs: ${err.message}`, true);
    rejectIncomingCall();
  }
}

function rejectIncomingCall() {
  sendCallSignal('call-end', {});
  cleanupCallState();
}

function startActiveCallUI() {
  stopRingtoneSound();
  showCallModal('active');

  const contact = contacts.find(c => c.number === activeCallPeerNumber);
  const peerDisplayName = contact ? (contact.nickname || contact.number) : activeCallPeerNumber;
  const activePeerNameEl = document.getElementById('active-call-peer-name');
  const activeAvatarEl = document.getElementById('active-call-avatar');

  if (activePeerNameEl) activePeerNameEl.textContent = peerDisplayName || 'Anrufpartner';
  if (activeAvatarEl) activeAvatarEl.textContent = (peerDisplayName || 'An').slice(0, 2).toUpperCase();

  callSeconds = 0;
  const timerEl = document.getElementById('active-call-timer');
  if (timerEl) timerEl.textContent = '00:00';

  if (callTimerInterval) clearInterval(callTimerInterval);
  callTimerInterval = setInterval(() => {
    callSeconds++;
    const m = String(Math.floor(callSeconds / 60)).padStart(2, '0');
    const s = String(callSeconds % 60).padStart(2, '0');
    if (timerEl) timerEl.textContent = `${m}:${s}`;
  }, 1000);
}

function createVoiceMaskProcessedTrack(stream) {
  try {
    const rawAudioTrack = stream.getAudioTracks()[0];
    if (!rawAudioTrack) return null;

    if (!voiceMaskAudioCtx) {
      voiceMaskAudioCtx = new (window.AudioContext || window.webkitAudioContext)();
    }
    if (voiceMaskAudioCtx.state === 'suspended') {
      voiceMaskAudioCtx.resume();
    }

    voiceMaskSourceNode = voiceMaskAudioCtx.createMediaStreamSource(new MediaStream([rawAudioTrack]));
    voiceMaskDestinationNode = voiceMaskAudioCtx.createMediaStreamDestination();

    // Voice Masking Filter Chain (Pitch Shift / Pitch modification via BiquadFilters + WaveShaper)
    const lowShelf = voiceMaskAudioCtx.createBiquadFilter();
    lowShelf.type = 'lowshelf';
    lowShelf.frequency.value = 350;
    lowShelf.gain.value = 14;

    const highPass = voiceMaskAudioCtx.createBiquadFilter();
    highPass.type = 'highpass';
    highPass.frequency.value = 120;

    const peaking = voiceMaskAudioCtx.createBiquadFilter();
    peaking.type = 'peaking';
    peaking.frequency.value = 800;
    peaking.Q.value = 3.0;
    peaking.gain.value = 10;

    // Connect Web Audio processing nodes
    voiceMaskSourceNode.connect(lowShelf);
    lowShelf.connect(highPass);
    highPass.connect(peaking);
    peaking.connect(voiceMaskDestinationNode);

    maskedAudioTrack = voiceMaskDestinationNode.stream.getAudioTracks()[0];
    return maskedAudioTrack;
  } catch (err) {
    console.error("Voice masking creation error:", err);
    return null;
  }
}

async function toggleVoiceMasking(forcedState = null) {
  const newState = forcedState !== null ? forcedState : !isVoiceMaskActive;
  isVoiceMaskActive = newState;

  const maskBtn = document.getElementById('toggle-voice-mask-btn');
  const maskBadge = document.getElementById('voice-mask-status-badge');

  if (maskBtn) {
    maskBtn.classList.toggle('active', isVoiceMaskActive);
  }
  if (maskBadge) {
    maskBadge.classList.toggle('active', isVoiceMaskActive);
    maskBadge.textContent = isVoiceMaskActive ? '🎭 Voice Mask: AN' : '🎭 Voice Mask: AUS';
  }

  if (isVoiceMaskActive) {
    showToast("🎭 Voice Masking AKTIVIERT (Stimmverfremdung)");
  } else {
    showToast("🎭 Voice Masking DEAKTIVIERT");
  }

  if (peerConnection && localMediaStream) {
    const rawTrack = localMediaStream.getAudioTracks()[0];
    if (!rawTrack) return;

    if (isVoiceMaskActive && !maskedAudioTrack) {
      createVoiceMaskProcessedTrack(localMediaStream);
    }

    const trackToUse = isVoiceMaskActive ? maskedAudioTrack : rawTrack;
    if (trackToUse) {
      const sender = peerConnection.getSenders().find(s => s.track && s.track.kind === 'audio');
      if (sender) {
        try {
          await sender.replaceTrack(trackToUse);
        } catch (e) {
          console.error("Error replacing audio track for voice masking:", e);
        }
      }
    }
  }
}

function cleanupVoiceMasking() {
  isVoiceMaskActive = false;
  if (maskedAudioTrack) {
    try { maskedAudioTrack.stop(); } catch(e) {}
    maskedAudioTrack = null;
  }
  if (voiceMaskAudioCtx) {
    try { voiceMaskAudioCtx.close(); } catch(e) {}
    voiceMaskAudioCtx = null;
  }
  voiceMaskSourceNode = null;
  voiceMaskDestinationNode = null;

  const maskBtn = document.getElementById('toggle-voice-mask-btn');
  const maskBadge = document.getElementById('voice-mask-status-badge');
  if (maskBtn) maskBtn.classList.remove('active');
  if (maskBadge) {
    maskBadge.classList.remove('active');
    maskBadge.textContent = '🎭 Voice Mask: AUS';
  }
}

function cleanupCallState() {
  cleanupVoiceMasking();
  stopRingtoneSound();

  if (activeCallPeerNumber) {
    const duration = callSeconds || 0;
    const callEventObj = {
      id: generate8DigitId(),
      type: isCallInitiator ? 'own' : 'peer',
      sender_number: isCallInitiator ? (currentUser ? currentUser.main_number : 'own') : activeCallPeerNumber,
      recipient_number: isCallInitiator ? activeCallPeerNumber : (currentUser ? currentUser.main_number : 'me'),
      timestamp: Date.now(),
      text: JSON.stringify({
        type: 'call_event',
        call_type: currentCallType || 'audio',
        event: duration > 0 ? 'ended' : 'missed',
        duration: duration
      })
    };
    saveChatMessage(activeCallPeerNumber, callEventObj);
    if (activeContact && activeContact.number === activeCallPeerNumber) {
      appendMessageUI(callEventObj, true);
    }
  }
  activeCallPeerNumber = null;

  if (callTimerInterval) {
    clearInterval(callTimerInterval);
    callTimerInterval = null;
  }
  callSeconds = 0;

  if (localMediaStream) {
    localMediaStream.getTracks().forEach(track => track.stop());
    localMediaStream = null;
  }
  if (remoteMediaStream) {
    remoteMediaStream.getTracks().forEach(track => track.stop());
    remoteMediaStream = null;
  }
  if (peerConnection) {
    try { peerConnection.close(); } catch(e) {}
    peerConnection = null;
  }

  // Clean up mesh group call state
  meshPeerConnections.forEach(pc => {
    try { pc.close(); } catch(e) {}
  });
  meshPeerConnections.clear();

  meshRemoteStreams.forEach(s => {
    s.getTracks().forEach(track => track.stop());
  });
  meshRemoteStreams.clear();

  const container = document.querySelector('.video-viewport-container');
  if (container) {
    const grid = container.querySelector('.mesh-video-grid');
    if (grid) grid.remove();
  }

  const remoteVideo = document.getElementById('remote-video');
  const localVideo = document.getElementById('local-video');
  if (remoteVideo) {
    remoteVideo.srcObject = null;
    remoteVideo.classList.remove('hidden');
  }
  if (localVideo) {
    localVideo.srcObject = null;
    localVideo.classList.remove('hidden');
  }

  activeCallPeerNumber = null;
  isCallInitiator = false;
  window._pendingCallOffer = null;

  hideCallModal();
}

// --- VIEW ONCE FILE BURNING ---

async function burnViewOnceMedia(fileId, msgId, contactNumber) {
  if (!fileId) return;

  try {
    await fetch('/api/files/burn', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(accessToken ? { 'Authorization': `Bearer ${accessToken}` } : {})
      },
      body: JSON.stringify({ file_id: fileId })
    });

    if (contactNumber) {
      const history = getChatHistory(contactNumber);
      const updated = history.filter(m => m.id !== msgId);
      sessionStorage.setItem(SESSION_CHAT_PREFIX + contactNumber, JSON.stringify(updated));
    }

    showToast("🔥 View Once Medium wurde dauerhaft gelöscht.");
  } catch (err) {
    console.error("Burn View Once error:", err);
  }
}

function generate8DigitId() {
  return Math.floor(10000000 + Math.random() * 90000000).toString();
}

function escapeHtml(text) {
  return String(text || '')
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

// --- WEBCRYPTO API: ECDH (P-256), PBKDF2 & AES-GCM-256 ---

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

// --- BACKEND HEALTH & PUBLIC SETTINGS CHECK ---

async function checkBackendHealth() {
  try {
    const res = await fetch('/api/health');
    const contentType = res.headers.get('content-type');
    if (res.ok && contentType && contentType.includes('application/json')) {
      const data = await res.json();
      if (data.supabaseUrl) supabaseUrl = data.supabaseUrl;
      if (data.supabaseAnonKey) supabaseAnonKey = data.supabaseAnonKey;
    }
  } catch (err) {
    console.log("Backend offline or static mode.");
  }
}

function urlBase64ToUint8Array(base64String) {
  const base64 = base64String.trim().replace(/-/g, '+').replace(/_/g, '/');
  const padding = '='.repeat((4 - (base64.length % 4)) % 4);
  const rawData = window.atob(base64 + padding);
  const outputArray = new Uint8Array(rawData.length);
  for (let i = 0; i < rawData.length; ++i) {
    outputArray[i] = rawData.charCodeAt(i);
  }
  return outputArray;
}

function registerServiceWorker() {
  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('/sw.js')
      .then(reg => {
        swRegistration = reg;
        checkPushSubscriptionState();
      })
      .catch(err => console.error('Service Worker registration error:', err));
  }
}

function checkIosPwaNotice() {
  const isIos = /iPhone|iPad|iPod/.test(navigator.userAgent);
  const isStandalone = ('standalone' in window.navigator) && window.navigator.standalone;
  const noticeEl = document.getElementById('ios-pwa-notice');
  if (noticeEl) {
    if (isIos && !isStandalone) {
      noticeEl.classList.remove('hidden');
    } else {
      noticeEl.classList.add('hidden');
    }
  }
}

async function checkPushSubscriptionState() {
  const toggle = document.getElementById('settings-push-toggle');
  if (!toggle || !swRegistration || !swRegistration.pushManager) return;

  try {
    const sub = await swRegistration.pushManager.getSubscription();
    toggle.checked = !!sub;
  } catch (e) {
    toggle.checked = false;
  }
}

async function handleTogglePushNotifications(e) {
  const toggle = e.target;
  const isChecked = toggle.checked;

  if (!swRegistration || !swRegistration.pushManager) {
    showToast("Push-Benachrichtigungen werden von diesem Browser nicht unterstützt.", true);
    toggle.checked = false;
    return;
  }

  if (isChecked) {
    try {
      const permission = await Notification.requestPermission();
      if (permission !== 'granted') {
        showToast("Benachrichtigungs-Berechtigung verweigert.", true);
        toggle.checked = false;
        return;
      }

      if (!vapidPublicKey) {
        showToast("VAPID Key konnte nicht vom Server geladen werden.", true);
        toggle.checked = false;
        return;
      }

      const subscription = await swRegistration.pushManager.subscribe({
        userVisibleOnly: true,
        applicationServerKey: urlBase64ToUint8Array(vapidPublicKey.trim())
      });

      const res = await fetch('/api/push/subscribe', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(accessToken ? { 'Authorization': `Bearer ${accessToken}` } : {})
        },
        body: JSON.stringify({ subscription: subscription })
      });

      if (res.ok) {
        showToast("Push-Benachrichtigungen erfolgreich aktiviert!");
      } else {
        throw new Error('Speichern der Subscription fehlgeschlagen.');
      }
    } catch (err) {
      showToast(`Push-Aktivierung fehlgeschlagen: ${err.message}`, true);
      toggle.checked = false;
    }
  } else {
    try {
      const sub = await swRegistration.pushManager.getSubscription();
      if (sub) {
        await sub.unsubscribe();
      }
      await fetch('/api/push/subscribe', {
        method: 'DELETE',
        headers: accessToken ? { 'Authorization': `Bearer ${accessToken}` } : {}
      });
      showToast("Push-Benachrichtigungen deaktiviert.");
    } catch (err) {
      showToast(`Fehler beim Deaktivieren: ${err.message}`, true);
    }
  }
}

async function fetchPublicSettings() {
  try {
    const res = await fetch('/api/settings/public');
    const contentType = res.headers.get('content-type');
    if (res.ok && contentType && contentType.includes('application/json')) {
      const data = await res.json();
      publicRequireInviteCode = !!data.require_invite_code;
      publicBannerConfig = data.banner_config || null;
      if (data.vapidPublicKey) vapidPublicKey = data.vapidPublicKey;
      renderGlobalBanner();
    }
  } catch (err) {
    console.error("Fetch public settings error:", err);
  }
}

function renderGlobalBanner() {
  const bannerEl = document.getElementById('global-banner');
  if (!bannerEl) return;

  if (!publicBannerConfig || !publicBannerConfig.enabled || !publicBannerConfig.text) {
    bannerEl.classList.add('hidden');
    return;
  }

  const isHome = !currentUser;
  const isGlobal = publicBannerConfig.location === 'global';

  if (!isGlobal && !isHome) {
    bannerEl.classList.add('hidden');
    return;
  }

  bannerEl.className = `global-banner banner-type-${publicBannerConfig.type || 'info'}`;

  const badgeEl = document.getElementById('banner-badge');
  const textEl = document.getElementById('banner-text');

  if (badgeEl) {
    if (publicBannerConfig.type === 'warning') badgeEl.textContent = 'Achtung';
    else if (publicBannerConfig.type === 'beta') badgeEl.textContent = 'Beta';
    else badgeEl.textContent = 'Info';
  }

  if (textEl) {
    textEl.textContent = publicBannerConfig.text;
  }

  bannerEl.classList.remove('hidden');
}

// --- INITIALIZATION & SESSION MANAGEMENT ---

document.addEventListener('DOMContentLoaded', async () => {
  registerServiceWorker();
  await checkBackendHealth();
  await fetchPublicSettings();
  initStealthMode();
  checkSessionState();
  setupEventListeners();
  setupTabBlurProtection();

  // Check URL route for Admin Dashboard (/admin/dashboard)
  if (window.location.pathname === '/admin/dashboard') {
    openAdminDashboard();
  }
});

function initStealthMode() {
  const saved = localStorage.getItem('aegis_stealth_mode') || 'off';
  applyStealthMode(saved, false);
}

function applyStealthMode(mode, showNotification = true) {
  currentStealthMode = mode;
  localStorage.setItem('aegis_stealth_mode', mode);

  let iconLink = document.querySelector("link[rel~='icon']");
  if (!iconLink) {
    iconLink = document.createElement('link');
    iconLink.rel = 'icon';
    document.getElementsByTagName('head')[0].appendChild(iconLink);
  }

  if (mode === 'calculator') {
    document.title = "Taschenrechner";
    const calcSvg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="%2338bdf8"><rect x="4" y="2" width="16" height="20" rx="3" fill="%231e293b" stroke="%2338bdf8" stroke-width="2"/><rect x="7" y="5" width="10" height="4" rx="1" fill="%230f172a"/><circle cx="8" cy="12" r="1" fill="%2338bdf8"/><circle cx="12" cy="12" r="1" fill="%2338bdf8"/><circle cx="16" cy="12" r="1" fill="%2338bdf8"/><circle cx="8" cy="16" r="1" fill="%2338bdf8"/><circle cx="12" cy="16" r="1" fill="%2338bdf8"/><circle cx="16" cy="16" r="1" fill="%2338bdf8"/></svg>`;
    iconLink.href = 'data:image/svg+xml,' + encodeURIComponent(calcSvg);
    if (showNotification) showToast("🧮 Stealth-Modus AKTIVIERT (Taschenrechner)");
  } else if (mode === 'notes') {
    document.title = "Meine Notizen";
    const notesSvg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="%23a855f7"><rect x="4" y="2" width="16" height="20" rx="3" fill="%231e293b" stroke="%23a855f7" stroke-width="2"/><line x1="8" y1="7" x2="16" y2="7" stroke="%23a855f7" stroke-width="2"/><line x1="8" y1="11" x2="16" y2="11" stroke="%23a855f7" stroke-width="2"/><line x1="8" y1="15" x2="12" y2="15" stroke="%23a855f7" stroke-width="2"/></svg>`;
    iconLink.href = 'data:image/svg+xml,' + encodeURIComponent(notesSvg);
    if (showNotification) showToast("📝 Stealth-Modus AKTIVIERT (Meine Notizen)");
  } else {
    document.title = "AegisChat Encrypted Messenger";
    iconLink.href = "/favicon.svg";
    if (showNotification) showToast("Stealth-Modus deaktiviert");
  }

  const stealthSelect = document.getElementById('stealth-mode-select');
  if (stealthSelect) stealthSelect.value = mode;
}

async function hashPanicPassword(password) {
  const enc = new TextEncoder();
  const hashBuffer = await window.crypto.subtle.digest("SHA-256", enc.encode(password));
  return btoa(String.fromCharCode(...new Uint8Array(hashBuffer)));
}

function setupTabBlurProtection() {
  const toggleOverlay = (isBlurred) => {
    const overlay = document.getElementById('tab-blur-overlay');
    if (overlay) {
      if (currentUser && isBlurred) {
        overlay.classList.remove('hidden');
      } else {
        overlay.classList.add('hidden');
      }
    }

    // Trigger Passcode/App Lock screen on leaving app/losing focus
    if (currentUser && isBlurred) {
      lockSession();
    }
  };

  window.addEventListener('blur', () => toggleOverlay(true));
  window.addEventListener('focus', () => toggleOverlay(false));
  document.addEventListener('visibilitychange', () => {
    if (document.hidden) {
      toggleOverlay(true);
    }
  });
}

function checkSessionState() {
  const sessionStr = sessionStorage.getItem(SESSION_KEY);
  if (sessionStr) {
    try {
      const sess = JSON.parse(sessionStr);
      currentUser = sess.user;
      userProfile = sess.profile || null;
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
  renderGlobalBanner();
}

async function saveSessionData() {
  if (!currentUser || !localKeyPair) return;
  const jwkPriv = await window.crypto.subtle.exportKey("jwk", localKeyPair.privateKey);
  const privKeyJwkB64 = btoa(JSON.stringify(jwkPriv));

  const sessionObj = {
    user: currentUser,
    profile: userProfile,
    accessToken: accessToken,
    pubKeyB64: localPubKeyB64,
    privKeyJwkB64: privKeyJwkB64
  };
  sessionStorage.setItem(SESSION_KEY, JSON.stringify(sessionObj));
}

function clearSessionData() {
  sessionStorage.clear();
  currentUser = null;
  userProfile = null;
  accessToken = null;
  localKeyPair = null;
  localPubKeyB64 = null;
  contacts = [];
  myBurnerNumbers = [];
  activeContact = null;
  verifiedInviteCode = null;

  activeAudioObjectURLs.forEach(url => {
    try { URL.revokeObjectURL(url); } catch (e) {}
  });
  activeAudioObjectURLs.clear();

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
  renderGlobalBanner();
}

// --- ONBOARDING TOUR LOGIC ---

function showOnboardingTour() {
  onboardingCurrentStep = 1;
  updateOnboardingStepUI();
  document.getElementById('onboarding-modal').classList.remove('hidden');
}

function updateOnboardingStepUI() {
  for (let i = 1; i <= 3; i++) {
    const stepEl = document.getElementById(`onboarding-step-${i}`);
    const dotEl = document.getElementById(`dot-${i}`);
    if (i === onboardingCurrentStep) {
      stepEl.classList.remove('hidden');
      dotEl.classList.add('active');
    } else {
      stepEl.classList.add('hidden');
      dotEl.classList.remove('active');
    }
  }

  const prevBtn = document.getElementById('onboarding-prev-btn');
  const nextBtn = document.getElementById('onboarding-next-btn');

  prevBtn.disabled = onboardingCurrentStep === 1;
  nextBtn.textContent = onboardingCurrentStep === 3 ? 'Tour Beenden' : 'Weiter';
}

function completeOnboardingTour() {
  localStorage.setItem(LOCAL_ONBOARDED_KEY, 'true');
  document.getElementById('onboarding-modal').classList.add('hidden');
}

// --- DOM EVENT LISTENERS ---

function setupEventListeners() {
  // Call PiP toggle
  const pipBtn = document.getElementById('toggle-pip-call-btn');
  if (pipBtn) {
    pipBtn.onclick = async () => {
      const remoteVideo = document.getElementById('remote-video');
      try {
        if (document.pictureInPictureElement) {
          await document.exitPictureInPicture();
        } else if (remoteVideo && remoteVideo.srcObject && document.pictureInPictureEnabled) {
          await remoteVideo.requestPictureInPicture();
        } else {
          showNotification('Bild-im-Bild wird nicht unterstützt oder kein Video aktiv', 'error');
        }
      } catch (err) {
        console.error('PiP Error:', err);
      }
    };
  }

  // Call Fullscreen toggle
  const fullscreenBtn = document.getElementById('toggle-fullscreen-call-btn');
  if (fullscreenBtn) {
    fullscreenBtn.onclick = async () => {
      const callOverlay = document.getElementById('call-overlay');
      try {
        if (document.fullscreenElement) {
          await document.exitFullscreen();
        } else if (callOverlay) {
          await callOverlay.requestFullscreen();
        }
      } catch (err) {
        console.error('Fullscreen Error:', err);
      }
    };
  }

  const showRegBtn = document.getElementById('show-register-modal-btn');
  const showLoginBtn = document.getElementById('show-login-modal-btn');
  const regModal = document.getElementById('register-modal');
  const loginModal = document.getElementById('login-modal');

  showRegBtn.addEventListener('click', openRegisterModal);
  document.getElementById('close-register-modal-btn').addEventListener('click', () => regModal.classList.add('hidden'));
  const closeRegBtn1 = document.getElementById('close-register-modal-btn-1');
  if (closeRegBtn1) closeRegBtn1.addEventListener('click', () => regModal.classList.add('hidden'));

  showLoginBtn.addEventListener('click', () => loginModal.classList.remove('hidden'));
  document.getElementById('close-login-modal-btn').addEventListener('click', () => loginModal.classList.add('hidden'));

  document.getElementById('verify-invite-code-btn').addEventListener('click', handleVerifyInviteCode);
  document.getElementById('submit-register-btn').addEventListener('click', handleRegistration);
  document.getElementById('submit-login-btn').addEventListener('click', handleLogin);

  document.getElementById('logout-btn').addEventListener('click', handleLogout);
  document.getElementById('mobile-logout-btn').addEventListener('click', handleLogout);

  // Banner close button
  const closeBannerBtn = document.getElementById('close-banner-btn');
  if (closeBannerBtn) {
    closeBannerBtn.addEventListener('click', () => {
      const bannerEl = document.getElementById('global-banner');
      if (bannerEl) bannerEl.classList.add('hidden');
    });
  }

  // Admin Dashboard Open / Close
  const openAdminBtn = document.getElementById('open-admin-btn');
  const mobileAdminBtn = document.getElementById('mobile-admin-btn');
  if (openAdminBtn) openAdminBtn.addEventListener('click', openAdminDashboard);
  if (mobileAdminBtn) mobileAdminBtn.addEventListener('click', openAdminDashboard);

  const closeAdminBtn = document.getElementById('close-admin-modal-btn');
  if (closeAdminBtn) closeAdminBtn.addEventListener('click', closeAdminDashboard);

  // Admin Controls Listeners
  const requireInviteToggle = document.getElementById('admin-require-invite-toggle');
  if (requireInviteToggle) requireInviteToggle.addEventListener('change', handleToggleRequireInvite);

  const inviteTypeSelect = document.getElementById('admin-invite-type-select');
  if (inviteTypeSelect) {
    inviteTypeSelect.addEventListener('change', (e) => {
      const wrapper = document.getElementById('admin-invite-uses-wrapper');
      if (wrapper) {
        if (e.target.value === 'multi') wrapper.classList.remove('hidden');
        else wrapper.classList.add('hidden');
      }
    });
  }

  const generateInviteBtn = document.getElementById('admin-generate-invite-btn');
  if (generateInviteBtn) generateInviteBtn.addEventListener('click', handleAdminGenerateInvite);

  const saveBannerBtn = document.getElementById('admin-save-banner-btn');
  if (saveBannerBtn) saveBannerBtn.addEventListener('click', handleAdminSaveBanner);

  // Admin Tab Switching
  const adminTabBtns = document.querySelectorAll('.admin-tab-btn');
  adminTabBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      const tabName = btn.dataset.tab;
      switchAdminTab(tabName);
    });
  });

  // Emergency Lock / Panic Buttons
  document.getElementById('panic-lock-btn').addEventListener('click', handleEmergencyLock);
  document.getElementById('mobile-panic-btn').addEventListener('click', handleEmergencyLock);

  // Onboarding controls
  document.getElementById('onboarding-next-btn').addEventListener('click', () => {
    if (onboardingCurrentStep < 3) {
      onboardingCurrentStep++;
      updateOnboardingStepUI();
    } else {
      completeOnboardingTour();
    }
  });

  document.getElementById('onboarding-prev-btn').addEventListener('click', () => {
    if (onboardingCurrentStep > 1) {
      onboardingCurrentStep--;
      updateOnboardingStepUI();
    }
  });

  document.getElementById('skip-onboarding-btn').addEventListener('click', completeOnboardingTour);

  // Push Notifications toggle
  const pushToggle = document.getElementById('settings-push-toggle');
  if (pushToggle) pushToggle.addEventListener('change', handleTogglePushNotifications);

  // Stealth Mode Select Listener
  const stealthSelect = document.getElementById('stealth-mode-select');
  if (stealthSelect) {
    stealthSelect.addEventListener('change', (e) => applyStealthMode(e.target.value, true));
  }

  // Settings Modal controls
  document.getElementById('open-settings-btn').addEventListener('click', () => {
    if (currentUser) {
      const mainIdEl = document.getElementById('settings-main-id-display');
      const unameEl = document.getElementById('settings-username-display');
      if (mainIdEl) mainIdEl.textContent = currentUser.main_number || '--------';
      if (unameEl) unameEl.textContent = currentUser.username || '--';
    }
    if (userProfile) {
      const dnInput = document.getElementById('settings-display-name-input');
      const avInput = document.getElementById('settings-avatar-url-input');
      const shareToggle = document.getElementById('settings-share-profile-toggle');
      if (dnInput) dnInput.value = userProfile.display_name || '';
      if (avInput) avInput.value = userProfile.avatar_url || '';
      if (shareToggle) shareToggle.checked = userProfile.share_profile !== false;
    }
    checkIosPwaNotice();
    checkPushSubscriptionState();
    const stSel = document.getElementById('stealth-mode-select');
    if (stSel) stSel.value = currentStealthMode;
    document.getElementById('settings-modal').classList.remove('hidden');
  });
  document.getElementById('close-settings-modal-btn').addEventListener('click', () => {
    document.getElementById('settings-modal').classList.add('hidden');
  });

  document.getElementById('restart-onboarding-btn').addEventListener('click', () => {
    document.getElementById('settings-modal').classList.add('hidden');
    showOnboardingTour();
  });

  const saveProfileBtn = document.getElementById('save-profile-settings-btn');
  if (saveProfileBtn) saveProfileBtn.addEventListener('click', handleSaveProfileSettings);

  document.getElementById('export-keys-btn').addEventListener('click', handleExportKeysBackup);
  const savePanicBtn = document.getElementById('save-panic-password-btn');
  if (savePanicBtn) savePanicBtn.addEventListener('click', handleSavePanicPassword);
  document.getElementById('deactivate-account-btn').addEventListener('click', handleDeactivateAccount);
  document.getElementById('delete-account-btn').addEventListener('click', handleDeleteAccount);

  // Voice Recording Listeners
  const micBtn = document.getElementById('mic-btn');
  const stopRecBtn = document.getElementById('stop-recording-btn');
  const cancelRecBtn = document.getElementById('cancel-recording-btn');

  if (micBtn) micBtn.addEventListener('click', startVoiceRecording);
  if (stopRecBtn) stopRecBtn.addEventListener('click', stopAndSendVoiceRecording);
  if (cancelRecBtn) cancelRecBtn.addEventListener('click', cancelVoiceRecording);

  // Contact Prompt Bar
  document.getElementById('prompt-save-btn').addEventListener('click', handleSavePromptContact);
  document.getElementById('prompt-dismiss-btn').addEventListener('click', () => {
    document.getElementById('contact-prompt-bar').classList.add('hidden');
  });

  // Nickname Modal
  document.getElementById('active-user-clickable').addEventListener('click', openNicknameModal);
  document.getElementById('close-nickname-modal-btn').addEventListener('click', () => {
    document.getElementById('nickname-modal').classList.add('hidden');
  });
  document.getElementById('save-nickname-btn').addEventListener('click', handleSaveNickname);
  document.getElementById('delete-contact-btn').addEventListener('click', handleDeleteContact);

  // Group Room Controls
  const createGroupModalBtn = document.getElementById('create-group-modal-btn');
  const closeGroupModalBtn = document.getElementById('close-create-group-modal-btn');
  const cancelGroupBtn = document.getElementById('cancel-create-group-btn');
  const submitGroupBtn = document.getElementById('submit-create-group-btn');

  if (createGroupModalBtn) createGroupModalBtn.addEventListener('click', openCreateGroupModal);
  if (closeGroupModalBtn) closeGroupModalBtn.addEventListener('click', () => document.getElementById('create-group-modal').classList.add('hidden'));
  if (cancelGroupBtn) cancelGroupBtn.addEventListener('click', () => document.getElementById('create-group-modal').classList.add('hidden'));
  if (submitGroupBtn) submitGroupBtn.addEventListener('click', handleCreateGroup);

  // Messaging Form & Contact Addition
  document.getElementById('add-contact-btn').addEventListener('click', handleAddContact);
  document.getElementById('send-message-form').addEventListener('submit', handleSendMessage);

  // View Once Toggle Listener
  const viewOnceToggleBtn = document.getElementById('view-once-toggle-btn');
  if (viewOnceToggleBtn) {
    viewOnceToggleBtn.addEventListener('click', () => {
      isViewOnceActive = !isViewOnceActive;
      if (isViewOnceActive) {
        viewOnceToggleBtn.classList.add('active');
        showToast("View Once Modus AKTIV (Einmal-Ansicht)");
      } else {
        viewOnceToggleBtn.classList.remove('active');
        showToast("View Once Modus deaktiviert");
      }
    });
  }

  // E2EE Audio & Video Call Listeners
  const startAudioCallBtn = document.getElementById('start-audio-call-btn');
  const startVideoCallBtn = document.getElementById('start-video-call-btn');
  const cancelOutgoingCallBtn = document.getElementById('cancel-outgoing-call-btn');
  const acceptIncomingCallBtn = document.getElementById('accept-incoming-call-btn');
  const rejectIncomingCallBtn = document.getElementById('reject-incoming-call-btn');
  const endCallBtn = document.getElementById('end-call-btn');

  if (startAudioCallBtn) startAudioCallBtn.addEventListener('click', () => startE2eeCall('audio'));
  if (startVideoCallBtn) startVideoCallBtn.addEventListener('click', () => startE2eeCall('video'));
  if (cancelOutgoingCallBtn) cancelOutgoingCallBtn.addEventListener('click', rejectIncomingCall);
  if (acceptIncomingCallBtn) acceptIncomingCallBtn.addEventListener('click', acceptIncomingCall);
  if (rejectIncomingCallBtn) rejectIncomingCallBtn.addEventListener('click', rejectIncomingCall);
  if (endCallBtn) endCallBtn.addEventListener('click', rejectIncomingCall);

  // Call Audio / Camera / Voice Masking Controls
  const toggleMuteMicBtn = document.getElementById('toggle-mute-mic-btn');
  const toggleCamBtn = document.getElementById('toggle-camera-btn');
  const switchCamBtn = document.getElementById('switch-camera-btn');
  const toggleVoiceMaskBtn = document.getElementById('toggle-voice-mask-btn');

  if (toggleVoiceMaskBtn) {
    toggleVoiceMaskBtn.addEventListener('click', () => toggleVoiceMasking());
  }

  if (toggleMuteMicBtn) {
    toggleMuteMicBtn.addEventListener('click', () => {
      if (localMediaStream) {
        const audioTrack = localMediaStream.getAudioTracks()[0];
        if (audioTrack) {
          audioTrack.enabled = !audioTrack.enabled;
          toggleMuteMicBtn.classList.toggle('off', !audioTrack.enabled);
          const iconOn = toggleMuteMicBtn.querySelector('.icon-mic-on');
          const iconOff = toggleMuteMicBtn.querySelector('.icon-mic-off');
          if (iconOn && iconOff) {
            iconOn.classList.toggle('hidden', !audioTrack.enabled);
            iconOff.classList.toggle('hidden', audioTrack.enabled);
          }
        }
      }
    });
  }

  if (toggleCamBtn) {
    toggleCamBtn.addEventListener('click', () => {
      if (localMediaStream) {
        const videoTrack = localMediaStream.getVideoTracks()[0];
        if (videoTrack) {
          videoTrack.enabled = !videoTrack.enabled;
          toggleCamBtn.classList.toggle('off', !videoTrack.enabled);
          const iconOn = toggleCamBtn.querySelector('.icon-cam-on');
          const iconOff = toggleCamBtn.querySelector('.icon-cam-off');
          if (iconOn && iconOff) {
            iconOn.classList.toggle('hidden', !videoTrack.enabled);
            iconOff.classList.toggle('hidden', videoTrack.enabled);
          }
        }
      }
    });
  }

  if (switchCamBtn) {
    switchCamBtn.addEventListener('click', async () => {
      if (localMediaStream && currentCallType === 'video') {
        const currentTrack = localMediaStream.getVideoTracks()[0];
        if (currentTrack) {
          const currentFacing = currentTrack.getSettings().facingMode;
          const newFacing = currentFacing === 'user' ? 'environment' : 'user';
          currentTrack.stop();

          try {
            const newStream = await navigator.mediaDevices.getUserMedia({
              video: { facingMode: newFacing, width: { ideal: 1280 }, height: { ideal: 720 } }
            });
            const newVideoTrack = newStream.getVideoTracks()[0];
            localMediaStream.removeTrack(currentTrack);
            localMediaStream.addTrack(newVideoTrack);

            const sender = peerConnection ? peerConnection.getSenders().find(s => s.track && s.track.kind === 'video') : null;
            if (sender) sender.replaceTrack(newVideoTrack);

            const localVideo = document.getElementById('local-video');
            if (localVideo) localVideo.srcObject = localMediaStream;
          } catch (e) {}
        }
      }
    });
  }

  // File Upload Attachments & Lightbox
  const attachBtn = document.getElementById('attach-file-btn');
  const fileInput = document.getElementById('file-input');
  const cancelFileBtn = document.getElementById('cancel-file-btn');
  const closeLightboxBtn = document.getElementById('close-lightbox-btn');
  const lightboxModal = document.getElementById('lightbox-modal');

  if (attachBtn && fileInput) {
    attachBtn.addEventListener('click', () => fileInput.click());
    fileInput.addEventListener('change', (e) => {
      const file = e.target.files[0];
      if (file) {
        selectedFile = file;
        document.getElementById('file-preview-name').textContent = file.name;
        document.getElementById('file-preview-size').textContent = formatFileSize(file.size);
        document.getElementById('file-preview-bar').classList.remove('hidden');
      }
    });
  }

  if (cancelFileBtn) {
    cancelFileBtn.addEventListener('click', clearSelectedFile);
  }

  if (closeLightboxBtn && lightboxModal) {
    closeLightboxBtn.addEventListener('click', () => lightboxModal.classList.add('hidden'));
    lightboxModal.addEventListener('click', (e) => {
      if (e.target === lightboxModal) lightboxModal.classList.add('hidden');
    });
  }

  // Self Destruct Timer Selector
  document.getElementById('self-destruct-select').addEventListener('change', (e) => {
    activeSelfDestructTimer = e.target.value;
    showToast(`Nachrichten-Timer für diesen Chat: ${e.target.options[e.target.selectedIndex].text}`);
  });

  // Typing Indicator Input Trigger
  document.getElementById('message-input').addEventListener('input', handleTypingInput);

  // Burner IDs Modal
  document.getElementById('manage-burners-btn').addEventListener('click', () => {
    renderBurnerList();
    document.getElementById('burner-modal').classList.remove('hidden');
  });
  document.getElementById('close-burner-modal-btn').addEventListener('click', () => {
    document.getElementById('burner-modal').classList.add('hidden');
  });
  document.getElementById('generate-burner-btn').addEventListener('click', handleGenerateBurner);

  // QR Modals
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

  // Mobile Drawer Navigation
  document.getElementById('mobile-back-btn').addEventListener('click', () => {
    document.getElementById('sidebar').classList.remove('mobile-hidden');
  });
}

// --- REGISTRATION & INVITE CODE VERIFICATION ---

function openRegisterModal() {
  document.getElementById('register-status').textContent = '';
  document.getElementById('reg-username').value = '';
  document.getElementById('reg-password').value = '';
  document.getElementById('reg-invite-code').value = '';

  const inviteStep = document.getElementById('register-invite-step');
  const credsStep = document.getElementById('register-credentials-step');

  if (publicRequireInviteCode && !verifiedInviteCode) {
    inviteStep.classList.remove('hidden');
    credsStep.classList.add('hidden');
  } else {
    inviteStep.classList.add('hidden');
    credsStep.classList.remove('hidden');
  }

  document.getElementById('register-modal').classList.remove('hidden');
}

async function handleVerifyInviteCode() {
  const inputCode = document.getElementById('reg-invite-code').value.trim();
  const statusEl = document.getElementById('register-status');
  const verifyBtn = document.getElementById('verify-invite-code-btn');

  if (!inputCode) {
    statusEl.textContent = 'Bitte Einladungscode eingeben.';
    return;
  }

  verifyBtn.disabled = true;
  statusEl.textContent = 'Prüfe Einladungscode...';

  try {
    const res = await fetch('/api/invite/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code: inputCode })
    });

    const data = await res.json();
    if (!res.ok || !data.valid) {
      throw new Error(data.error || 'Ungültiger Einladungscode.');
    }

    verifiedInviteCode = inputCode.toUpperCase();
    statusEl.textContent = '';
    showToast("Einladungscode akzeptiert! Bitte wähle Nutzername & Passwort.");

    document.getElementById('register-invite-step').classList.add('hidden');
    document.getElementById('register-credentials-step').classList.remove('hidden');
  } catch (err) {
    statusEl.textContent = err.message;
    showToast(err.message, true);
  } finally {
    verifyBtn.disabled = false;
  }
}

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
        public_key: pubKeyB64,
        invite_code: verifiedInviteCode
      })
    });

    const data = await res.json();
    if (!res.ok || data.error) {
      throw new Error(data.error || 'Registrierung fehlgeschlagen.');
    }

    currentUser = data.user;
    userProfile = data.profile || null;
    accessToken = data.access_token;
    localKeyPair = keyPair;
    localPubKeyB64 = pubKeyB64;

    await saveSessionData();
    document.getElementById('register-modal').classList.add('hidden');
    showToast(`Registrierung erfolgreich! Haupt-ID: ${mainNumber}`);
    initMainChatUI();

    if (!localStorage.getItem(LOCAL_ONBOARDED_KEY)) {
      showOnboardingTour();
    }
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

  // Check if entered password matches Panic Password (Duress PIN)
  if (password) {
    const enteredHash = await hashPanicPassword(password);
    const storedPanicHash = localStorage.getItem('aegis_panic_hash');
    if (storedPanicHash && enteredHash === storedPanicHash) {
      // Silent complete wipe-out
      clearSessionData();
      localStorage.clear();
      statusEl.textContent = 'Anmeldung fehlgeschlagen. Bitte Zugangsdaten prüfen.';
      showToast("Anmeldung fehlgeschlagen. Bitte Zugangsdaten prüfen.", true);
      return;
    }
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
    userProfile = data.profile;
    accessToken = data.access_token;
    localKeyPair = { publicKey, privateKey };
    localPubKeyB64 = data.profile.public_key;

    await saveSessionData();
    document.getElementById('login-modal').classList.add('hidden');
    showToast("Erfolgreich angemeldet!");
    initMainChatUI();

    if (window.location.pathname === '/admin/dashboard') {
      openAdminDashboard();
    }
  } catch (err) {
    statusEl.textContent = `Fehler: ${err.message}`;
    showToast(err.message, true);
  } finally {
    submitBtn.disabled = false;
  }
}

function handleLogout() {
  cleanupTemporaryUnreadMessages();
  clearSessionData();
  showToast("Abgemeldet & Keys aus RAM gelöscht");
  location.reload();
}

function handleEmergencyLock() {
  cleanupTemporaryUnreadMessages();
  clearSessionData();
  showToast("🚨 Emergency Lock: Session & Keys unwiderruflich aus RAM gelöscht!", true);
  location.reload();
}

// --- LOCAL SEARCH & AUTO-SESSION LOCK ---

function initLocalSearch() {
  const searchInput = document.getElementById('sidebar-search-input');
  if (!searchInput) return;

  searchInput.addEventListener('input', (e) => {
    const query = e.target.value.toLowerCase().trim();
    filterSidebarAndChat(query);
  });
}

function filterSidebarAndChat(query) {
  const contactItems = document.querySelectorAll('#contacts-list .contact-item');
  contactItems.forEach(item => {
    const text = item.textContent.toLowerCase();
    if (!query || text.includes(query)) {
      item.style.display = '';
    } else {
      item.style.display = 'none';
    }
  });

  const msgBubbles = document.querySelectorAll('#messages-container .msg-bubble');
  msgBubbles.forEach(bubble => {
    const text = bubble.textContent.toLowerCase();
    if (!query || text.includes(query)) {
      bubble.style.display = '';
    } else {
      bubble.style.display = 'none';
    }
  });
}

let inactivityTimer = null;
let currentAutoLockSetting = '5m';

function resetInactivityTimer() {
  if (inactivityTimer) clearTimeout(inactivityTimer);
  const lockOverlay = document.getElementById('auto-lock-overlay');
  if (lockOverlay && !lockOverlay.classList.contains('hidden')) return;

  const sel = document.getElementById('auto-lock-timer-select');
  if (sel) currentAutoLockSetting = sel.value;

  if (currentAutoLockSetting === 'off') return;

  let ms = 5 * 60 * 1000;
  if (currentAutoLockSetting === '1m') ms = 1 * 60 * 1000;
  if (currentAutoLockSetting === '5m') ms = 5 * 60 * 1000;
  if (currentAutoLockSetting === '15m') ms = 15 * 60 * 1000;

  inactivityTimer = setTimeout(lockSession, ms);
}

function lockSession() {
  const lockOverlay = document.getElementById('auto-lock-overlay');
  if (lockOverlay) {
    lockOverlay.classList.remove('hidden');
    const pwdInput = document.getElementById('auto-lock-password-input');
    if (pwdInput) {
      pwdInput.value = '';
      pwdInput.focus();
    }
  }
}

function setupAutoLockListeners() {
  ['mousemove', 'keydown', 'touchstart', 'scroll', 'click'].forEach(evt => {
    window.addEventListener(evt, resetInactivityTimer, { passive: true });
  });

  const lockForm = document.getElementById('auto-lock-form');
  if (lockForm) {
    lockForm.addEventListener('submit', handleUnlockSession);
  }

  const sel = document.getElementById('auto-lock-timer-select');
  if (sel) {
    sel.addEventListener('change', (e) => {
      currentAutoLockSetting = e.target.value;
      resetInactivityTimer();
    });
  }
}

async function handleUnlockSession(e) {
  if (e) e.preventDefault();
  const pwdInput = document.getElementById('auto-lock-password-input');
  const pwd = pwdInput ? pwdInput.value : '';

  if (!pwd || !currentUser) {
    showToast('Bitte Passwort eingeben.', true);
    return;
  }

  try {
    const res = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ identifier: currentUser.username, password: pwd })
    });

    if (res.ok) {
      const lockOverlay = document.getElementById('auto-lock-overlay');
      if (lockOverlay) lockOverlay.classList.add('hidden');
      if (pwdInput) pwdInput.value = '';
      showToast('Session erfolgreich entsperrt 🔓');
      resetInactivityTimer();
    } else {
      showToast('Falsches Passwort!', true);
    }
  } catch (err) {
    showToast('Entsperren fehlgeschlagen.', true);
  }
}

// --- MAIN CHAT INTERFACE LOGIC ---

async function initMainChatUI() {
  document.getElementById('landing-page').classList.add('hidden');
  document.getElementById('app').classList.remove('hidden');

  document.getElementById('my-avatar').textContent = currentUser.username.slice(0, 2).toUpperCase();
  document.getElementById('my-username').innerHTML = `${escapeHtml(currentUser.username)} ${getFounderBadgeHtml(currentUser.username)}`;
  document.getElementById('my-id').textContent = `ID: ${currentUser.main_number}`;

  // Toggle Admin Button visibility
  if (userProfile && userProfile.is_admin) {
    document.getElementById('open-admin-btn').classList.remove('hidden');
    document.getElementById('mobile-admin-btn').classList.remove('hidden');
  } else {
    document.getElementById('open-admin-btn').classList.add('hidden');
    document.getElementById('mobile-admin-btn').classList.add('hidden');
  }

  renderGlobalBanner();
  updateForensicWatermarks();
  setInterval(updateForensicWatermarks, 60000); // refresh time watermark every 1m
  initLocalSearch();
  setupAutoLockListeners();
  resetInactivityTimer();
  await fetchMyBurnerNumbers();
  updateSenderDropdown();
  await loadContactsFromSupabase();
  loadGroupsFromStorage();
  connectRealtimeWebSocket();
  fetchAndProcessUnreadMessages();
  checkUrlRouteRedirect();
}

// --- GROUP CHAT & P2P FULL MESH CALL LOGIC ---

function loadGroupsFromStorage() {
  if (!currentUser) return;
  const stored = localStorage.getItem(`aegis_groups_${currentUser.id}`);
  if (stored) {
    try {
      groups = JSON.parse(stored);
    } catch (e) {
      groups = [];
    }
  }
  renderGroupsList();
}

function saveGroupsToStorage() {
  if (!currentUser) return;
  localStorage.setItem(`aegis_groups_${currentUser.id}`, JSON.stringify(groups));
}

function openCreateGroupModal() {
  const checklist = document.getElementById('group-members-checklist');
  checklist.innerHTML = '';

  if (contacts.length === 0) {
    checklist.innerHTML = '<p class="modal-subtext" style="text-align: center; padding: 12px;">Keine Kontakte vorhanden. Füge zuerst Kontakte hinzu.</p>';
  } else {
    contacts.forEach(c => {
      const row = document.createElement('label');
      row.className = 'group-member-checkbox-row';
      const displayName = c.nickname ? `${c.nickname} (${c.number})` : c.number;
      row.innerHTML = `
        <input type="checkbox" value="${c.number}">
        <span>${escapeHtml(displayName)}</span>
      `;
      checklist.appendChild(row);
    });
  }

  document.getElementById('group-name-input').value = '';
  document.getElementById('create-group-modal').classList.remove('hidden');
}

function handleCreateGroup() {
  const nameInput = document.getElementById('group-name-input').value.trim();
  if (!nameInput) {
    showToast("Bitte einen Gruppennamen eingeben.", true);
    return;
  }

  const selectedMembers = [];
  document.querySelectorAll('#group-members-checklist input[type="checkbox"]:checked').forEach(cb => {
    selectedMembers.push(cb.value);
  });

  if (selectedMembers.length === 0) {
    showToast("Bitte mindestens ein Mitglied auswählen.", true);
    return;
  }

  const groupId = 'grp-' + generate8DigitId();
  const newGroup = {
    id: groupId,
    name: nameInput,
    members: selectedMembers
  };

  groups.push(newGroup);
  saveGroupsToStorage();
  renderGroupsList();
  selectGroup(newGroup);

  document.getElementById('create-group-modal').classList.add('hidden');
  showToast(`E2EE Gruppenraum "${nameInput}" erstellt!`);
}

function renderGroupsList() {
  const list = document.getElementById('groups-list');
  if (!list) return;
  list.innerHTML = '';

  if (groups.length === 0) {
    list.innerHTML = '<li style="color: var(--text-muted); font-size: 12px; text-align: center; padding: 8px;">Keine Gruppenräume.</li>';
    return;
  }

  groups.forEach(g => {
    const li = document.createElement('li');
    li.className = `contact-item ${activeGroup && activeGroup.id === g.id ? 'active' : ''}`;
    const displayName = escapeHtml(g.name);

    li.innerHTML = `
      <div class="avatar" style="background: linear-gradient(135deg, var(--accent-pink), var(--accent));">👥</div>
      <div class="contact-details">
        <span class="contact-name">${displayName}</span>
        <span class="contact-id">${g.members.length + 1} Mitglieder</span>
      </div>
      <span class="contact-type-tag" style="background: rgba(236, 72, 153, 0.15); color: var(--accent-pink);">E2EE Mesh</span>
    `;
    li.addEventListener('click', () => selectGroup(g));
    list.appendChild(li);
  });
}

function selectGroup(group) {
  activeContact = null;
  activeGroup = group;

  renderContacts();
  renderGroupsList();

  document.getElementById('empty-state').classList.add('hidden');
  document.getElementById('chat-header').classList.remove('hidden');
  document.getElementById('messages-container').classList.remove('hidden');
  document.getElementById('send-message-form').classList.remove('hidden');

  if (window.innerWidth <= 768) {
    document.getElementById('sidebar').classList.add('mobile-hidden');
  }

  document.getElementById('active-avatar').textContent = '👥';
  document.getElementById('active-contact-name').textContent = `Gruppe: ${group.name}`;

  loadAndRenderGroupHistory(group.id);
}

function loadAndRenderGroupHistory(groupId) {
  const container = document.getElementById('messages-container');
  container.innerHTML = '';
  const stored = sessionStorage.getItem(`aegis_group_chat_${groupId}`);
  if (!stored) return;

  try {
    const history = JSON.parse(stored);
    const now = Date.now();
    history.forEach(msg => {
      if (msg.expiresAt && msg.expiresAt <= now) return;
      appendMessageUI(msg, false);
    });
    container.scrollTop = container.scrollHeight;
  } catch (e) {}
}

function saveGroupChatMessage(groupId, msgObj) {
  const key = `aegis_group_chat_${groupId}`;
  const stored = sessionStorage.getItem(key);
  let history = [];
  if (stored) {
    try { history = JSON.parse(stored); } catch (e) {}
  }
  history.push(msgObj);
  sessionStorage.setItem(key, JSON.stringify(history));
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

// --- ADMIN DASHBOARD LOGIC (/admin/dashboard) ---

async function loadAdminSupportTickets() {
  const tbody = document.getElementById('admin-support-tbody');
  if (!tbody) return;
  tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--text-secondary);">Lade Tickets...</td></tr>';

  try {
    const res = await fetchWithAuth('/api/admin/support/tickets');
    if (!res.ok) throw new Error('Tickets konnten nicht geladen werden');
    const data = await res.json();
    const tickets = Array.isArray(data) ? data : (data.tickets || []);

    if (tickets.length === 0) {
      tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--text-secondary);">Keine Support-Tickets vorhanden.</td></tr>';
      return;
    }

    tbody.innerHTML = '';
    tickets.forEach(ticket => {
      const tr = document.createElement('tr');
      const dateStr = ticket.updated_at ? new Date(ticket.updated_at).toLocaleString() : '-';
      tr.innerHTML = `
        <td><code>${escapeHtml(ticket.user_number || ticket.id)}</code></td>
        <td><span class="badge badge-secondary">${escapeHtml(ticket.ticket_status || 'open')}</span></td>
        <td>${dateStr}</td>
        <td>
          <select class="form-control form-control-sm ticket-status-select" data-ticket-id="${ticket.id}">
            <option value="open" ${ticket.ticket_status === 'open' ? 'selected' : ''}>Offen</option>
            <option value="in_progress" ${ticket.ticket_status === 'in_progress' ? 'selected' : ''}>In Bearbeitung</option>
            <option value="resolved" ${ticket.ticket_status === 'resolved' ? 'selected' : ''}>Gelöst</option>
          </select>
        </td>
        <td>
          <button class="btn btn-sm btn-primary open-support-chat-btn" data-user-number="${escapeHtml(ticket.user_number)}">Chat öffnen</button>
        </td>
      `;
      tbody.appendChild(tr);
    });

    // Add event listeners for status select
    tbody.querySelectorAll('.ticket-status-select').forEach(select => {
      select.onchange = async (e) => {
        const ticketId = e.target.dataset.ticketId;
        const newStatus = e.target.value;
        try {
          const updateRes = await fetchWithAuth('/api/admin/support/tickets', {
            method: 'PATCH',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ticket_id: ticketId, status: newStatus })
          });
          if (!updateRes.ok) throw new Error('Status-Update fehlgeschlagen');
          showNotification('Ticket-Status aktualisiert', 'success');
        } catch (err) {
          showNotification(err.message, 'error');
        }
      };
    });

    // Add event listeners for open chat
    tbody.querySelectorAll('.open-support-chat-btn').forEach(btn => {
      btn.onclick = (e) => {
        const userNum = e.target.dataset.userNumber;
        if (userNum) {
          closeModal('admin-modal');
          openDirectChat(userNum);
        }
      };
    });
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="5" style="color: var(--danger); text-align: center;">${escapeHtml(err.message)}</td></tr>`;
  }
}

function switchAdminTab(tabName) {
  const tabs = document.querySelectorAll('.admin-tab-btn');
  tabs.forEach(btn => {
    if (btn.dataset.tab === tabName) {
      btn.classList.add('active');
    } else {
      btn.classList.remove('active');
    }
  });

  const tabContents = document.querySelectorAll('.admin-tab-content');
  tabContents.forEach(content => {
    if (content.id === 'admin-tab-' + tabName) {
      content.classList.remove('hidden');
      content.classList.add('active');
    } else {
      content.classList.add('hidden');
      content.classList.remove('active');
    }
  });

  if (tabName === 'support') {
    loadAdminSupportTickets();
  }
}

async function openAdminDashboard() {
  if (!currentUser || !userProfile || !userProfile.is_admin) {
    showToast('Admin-Zugriff verweigert. Bitte melde dich mit einem Admin-Konto an.', true);
    if (!currentUser) {
      document.getElementById('login-modal').classList.remove('hidden');
    }
    return;
  }

  document.getElementById('admin-dashboard-modal').classList.remove('hidden');
  await refreshAdminDashboardData();
}

function closeAdminDashboard() {
  document.getElementById('admin-dashboard-modal').classList.add('hidden');
  if (window.location.pathname === '/admin/dashboard') {
    window.history.pushState({}, '', '/');
  }
}

async function refreshAdminDashboardData() {
  await Promise.all([
    loadAdminStats(),
    loadAdminSettings(),
    loadAdminInvites(),
    loadAdminUsers()
  ]);
}

async function loadAdminStats() {
  try {
    const res = await fetch('/api/admin/stats', {
      headers: { 'Authorization': `Bearer ${accessToken}` }
    });
    if (res.ok) {
      const data = await res.json();
      document.getElementById('admin-stat-users').textContent = data.activeUsers || 0;
      document.getElementById('admin-stat-burners').textContent = data.burnerNumbers || 0;
      document.getElementById('admin-stat-messages').textContent = data.messageCount || 0;

      const storageSizeEl = document.getElementById('admin-stat-storage-size');
      const storageFilesEl = document.getElementById('admin-stat-storage-files');
      if (storageSizeEl) storageSizeEl.textContent = formatFileSize(data.storageSizeBytes || 0);
      if (storageFilesEl) storageFilesEl.textContent = data.storageCount || 0;
    }
  } catch (e) {
    console.error("Load admin stats error:", e);
  }
}

async function loadAdminSettings() {
  try {
    const res = await fetch('/api/admin/settings', {
      headers: { 'Authorization': `Bearer ${accessToken}` }
    });
    if (res.ok) {
      const data = await res.json();
      data.forEach(item => {
        if (item.key === 'require_invite_code') {
          const toggle = document.getElementById('admin-require-invite-toggle');
          if (toggle) toggle.checked = !!(item.value && item.value.enabled);
          publicRequireInviteCode = toggle ? toggle.checked : false;
        }
        if (item.key === 'maintenance_mode') {
          const toggle = document.getElementById('admin-maintenance-toggle');
          if (toggle) toggle.checked = !!(item.value && item.value.enabled);
        }
        if (item.key === 'banner_config') {
          const cfg = item.value || {};
          publicBannerConfig = cfg;
          if (document.getElementById('admin-banner-text')) document.getElementById('admin-banner-text').value = cfg.text || '';
          if (document.getElementById('admin-banner-type')) document.getElementById('admin-banner-type').value = cfg.type || 'info';
          if (document.getElementById('admin-banner-location')) document.getElementById('admin-banner-location').value = cfg.location || 'home';
          if (document.getElementById('admin-banner-enable-toggle')) document.getElementById('admin-banner-enable-toggle').checked = !!cfg.enabled;
          renderGlobalBanner();
        }
      });
    }
  } catch (e) {
    console.error("Load admin settings error:", e);
  }
}

async function handleToggleMaintenanceMode(e) {
  const isEnabled = e.target.checked;
  try {
    const res = await fetch('/api/admin/settings', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${accessToken}`
      },
      body: JSON.stringify({
        key: 'maintenance_mode',
        value: { enabled: isEnabled, message: 'Plattform befindet sich derzeit im Wartungsmodus.' }
      })
    });
    if (res.ok) {
      showToast(`Wartungsmodus ${isEnabled ? 'aktiviert' : 'deaktiviert'}.`);
    } else {
      e.target.checked = !isEnabled;
      showToast("Fehler beim Speichern des Wartungsmodus.", true);
    }
  } catch (err) {
    e.target.checked = !isEnabled;
    showToast(err.message, true);
  }
}

async function handleSavePanicPassword() {
  const panicInput = document.getElementById('settings-panic-password');
  if (!panicInput) return;
  const panicPass = panicInput.value.trim();
  if (!panicPass) {
    showToast("Bitte ein Panik-Passwort eingeben.", true);
    return;
  }
  const panicHash = await hashPanicPassword(panicPass);
  localStorage.setItem('aegis_panic_hash', panicHash);
  panicInput.value = '';
  document.getElementById('settings-modal').classList.add('hidden');
  showToast("Panik-Passwort erfolgreich gespeichert!");
}

async function handleToggleRequireInvite(e) {
  const isEnabled = e.target.checked;
  try {
    const res = await fetch('/api/admin/settings', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${accessToken}`
      },
      body: JSON.stringify({
        key: 'require_invite_code',
        value: { enabled: isEnabled }
      })
    });
    if (res.ok) {
      publicRequireInviteCode = isEnabled;
      showToast(`Registrierungsbeschränkung ${isEnabled ? 'aktiviert' : 'deaktiviert'}.`);
    } else {
      e.target.checked = !isEnabled;
      showToast("Fehler beim Speichern der Einstellung.", true);
    }
  } catch (err) {
    e.target.checked = !isEnabled;
    showToast(err.message, true);
  }
}

async function loadAdminInvites() {
  const tbody = document.getElementById('admin-invites-tbody');
  if (!tbody) return;
  tbody.innerHTML = '<tr><td colspan="4" style="text-align:center;">Lade Einladungscodes...</td></tr>';

  try {
    const res = await fetch('/api/admin/invites', {
      headers: { 'Authorization': `Bearer ${accessToken}` }
    });
    if (res.ok) {
      const data = await res.json();
      tbody.innerHTML = '';
      if (!Array.isArray(data) || data.length === 0) {
        tbody.innerHTML = '<tr><td colspan="4" style="text-align:center; color: var(--text-muted);">Keine Invite Codes vorhanden.</td></tr>';
        return;
      }

      data.forEach(item => {
        const tr = document.createElement('tr');
        const isActive = item.is_active && item.used_count < item.max_uses;
        const statusBadge = isActive
          ? '<span class="status-badge badge-active">Aktiv</span>'
          : '<span class="status-badge badge-inactive">Inaktiv</span>';

        tr.innerHTML = `
          <td><strong>${escapeHtml(item.code)}</strong></td>
          <td>${statusBadge}</td>
          <td>${item.used_count} / ${item.max_uses}</td>
          <td>
            <button class="btn secondary-btn style-danger delete-invite-btn" style="padding: 4px 8px; font-size: 11px; width: auto;" data-code="${escapeHtml(item.code)}">Löschen</button>
          </td>
        `;

        tr.querySelector('.delete-invite-btn').addEventListener('click', () => handleDeleteInvite(item.code));
        tbody.appendChild(tr);
      });
    }
  } catch (e) {
    tbody.innerHTML = '<tr><td colspan="4" style="text-align:center; color: var(--danger);">Fehler beim Laden.</td></tr>';
  }
}

async function handleAdminGenerateInvite() {
  const type = document.getElementById('admin-invite-type-select').value;
  let maxUses = 1;

  if (type === 'multi') {
    const usesInput = parseInt(document.getElementById('admin-invite-max-uses').value, 10);
    maxUses = isNaN(usesInput) || usesInput < 1 ? 5 : usesInput;
  }

  try {
    const res = await fetch('/api/admin/invites', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${accessToken}`
      },
      body: JSON.stringify({ max_uses: maxUses })
    });

    if (res.ok) {
      const created = await res.json();
      const codeObj = Array.isArray(created) ? created[0] : created;
      showToast(`Einladungscode ${codeObj.code} generiert!`);
      loadAdminInvites();
    } else {
      showToast("Fehler beim Erstellen des Codes.", true);
    }
  } catch (err) {
    showToast(err.message, true);
  }
}

async function handleDeleteInvite(code) {
  if (confirm(`Code ${code} wirklich löschen?`)) {
    try {
      const res = await fetch(`/api/admin/invites?code=${encodeURIComponent(code)}`, {
        method: 'DELETE',
        headers: { 'Authorization': `Bearer ${accessToken}` }
      });
      if (res.ok) {
        showToast(`Code ${code} gelöscht.`);
        loadAdminInvites();
      }
    } catch (e) {
      showToast(e.message, true);
    }
  }
}

async function handleAdminSaveBanner() {
  const text = document.getElementById('admin-banner-text').value.trim();
  const type = document.getElementById('admin-banner-type').value;
  const location = document.getElementById('admin-banner-location').value;
  const enabled = document.getElementById('admin-banner-enable-toggle').checked;

  const bannerObj = { enabled, text, type, location };

  try {
    const res = await fetch('/api/admin/settings', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${accessToken}`
      },
      body: JSON.stringify({
        key: 'banner_config',
        value: bannerObj
      })
    });

    if (res.ok) {
      publicBannerConfig = bannerObj;
      renderGlobalBanner();
      showToast("Banner-Einstellungen erfolgreich gespeichert!");
    } else {
      showToast("Fehler beim Speichern der Banner-Einstellungen.", true);
    }
  } catch (err) {
    showToast(err.message, true);
  }
}

async function loadAdminUsers() {
  const tbody = document.getElementById('admin-users-tbody');
  if (!tbody) return;
  tbody.innerHTML = '<tr><td colspan="4" style="text-align:center;">Lade Benutzerliste...</td></tr>';

  try {
    const res = await fetch('/api/admin/users', {
      headers: { 'Authorization': `Bearer ${accessToken}` }
    });
    if (res.ok) {
      const data = await res.json();
      tbody.innerHTML = '';
      if (!Array.isArray(data) || data.length === 0) {
        tbody.innerHTML = '<tr><td colspan="4" style="text-align:center; color: var(--text-muted);">Keine Nutzer gefunden.</td></tr>';
        return;
      }

      data.forEach(user => {
        const tr = document.createElement('tr');
        const isFrozen = !!user.is_disabled;
        const roleBadge = user.is_admin ? '<span class="status-badge badge-admin">Admin</span>' : '<span class="status-badge badge-user">Nutzer</span>';
        const statusBadge = isFrozen
          ? '<span class="status-badge badge-inactive">Eingefroren</span>'
          : '<span class="status-badge badge-active">Aktiv</span>';

        const freezeBtnText = isFrozen ? 'Freigeben' : 'Einfrieren';
        const freezeBtnClass = isFrozen ? 'btn secondary-btn' : 'btn secondary-btn style-danger';

        const founderBadge = getFounderBadgeHtml(user.username);
        tr.innerHTML = `
          <td><strong>${escapeHtml(user.username)}</strong> ${founderBadge} ${roleBadge}</td>
          <td>${user.main_number}</td>
          <td>${statusBadge}</td>
          <td>
            ${user.id === currentUser.id ? '<span style="font-size: 11px; opacity: 0.6;">(Dein Konto)</span>' : `<button class="btn freeze-user-btn ${freezeBtnClass}" style="padding: 4px 8px; font-size: 11px; width: auto;" data-id="${user.id}" data-frozen="${isFrozen}">${freezeBtnText}</button>`}
          </td>
        `;

        const btn = tr.querySelector('.freeze-user-btn');
        if (btn) {
          btn.addEventListener('click', () => handleToggleFreezeUser(user.id, !isFrozen));
        }

        tbody.appendChild(tr);
      });
    }
  } catch (e) {
    tbody.innerHTML = '<tr><td colspan="4" style="text-align:center; color: var(--danger);">Fehler beim Laden der Nutzer.</td></tr>';
  }
}

async function handleToggleFreezeUser(userId, newDisabledState) {
  const actionText = newDisabledState ? 'einfrieren' : 'entsperren / freigeben';
  if (confirm(`Möchtest du dieses Konto wirklich ${actionText}?`)) {
    try {
      const res = await fetch('/api/admin/users/toggle-freeze', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${accessToken}`
        },
        body: JSON.stringify({
          user_id: userId,
          is_disabled: newDisabledState
        })
      });

      if (res.ok) {
        showToast(`Nutzerkonto ${newDisabledState ? 'eingefroren' : 'freigegeben'}.`);
        loadAdminUsers();
      } else {
        showToast("Fehler beim Ändern des Kontostatus.", true);
      }
    } catch (err) {
      showToast(err.message, true);
    }
  }
}

// --- CONTACT MANAGEMENT & NICKNAMES ---

async function loadContactsFromSupabase() {
  if (!currentUser) return;
  try {
    const res = await fetch(`/api/contacts?user_id=${currentUser.id}`, {
      headers: accessToken ? { 'Authorization': `Bearer ${accessToken}` } : {}
    });
    if (res.ok) {
      const dbContacts = await res.json();
      contacts = [];
      for (const item of dbContacts) {
        try {
          const resKey = await fetch(`/api/profiles/resolve?number=${item.contact_number}`);
          if (resKey.ok) {
            const keyData = await resKey.json();
            const peerKey = await importPublicKey(keyData.public_key);
            const sharedKey = await deriveSharedAesKey(localKeyPair.privateKey, peerKey);
            contacts.push({
              number: item.contact_number,
              nickname: item.nickname || null,
              isBurner: keyData.isBurner,
              pubKeyB64: keyData.public_key,
              sharedKey: sharedKey
            });
          }
        } catch (e) {
          console.error("Error restoring contact item:", e);
        }
      }
      renderContacts();
    }
  } catch (err) {
    console.error("Load contacts error:", err);
  }
}

async function saveContactToSupabase(contactNumber, nickname = null) {
  if (!currentUser) return;
  try {
    await fetch('/api/contacts', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(accessToken ? { 'Authorization': `Bearer ${accessToken}` } : {})
      },
      body: JSON.stringify({
        user_id: currentUser.id,
        contact_number: contactNumber,
        nickname: nickname
      })
    });
  } catch (err) {
    console.error("Save contact to Supabase error:", err);
  }
}

async function deleteContactFromSupabase(contactNumber) {
  if (!currentUser) return;
  try {
    await fetch(`/api/contacts?user_id=${currentUser.id}&contact_number=${contactNumber}`, {
      method: 'DELETE',
      headers: accessToken ? { 'Authorization': `Bearer ${accessToken}` } : {}
    });
  } catch (err) {
    console.error("Delete contact error:", err);
  }
}

function renderContacts() {
  const list = document.getElementById('contacts-list');
  list.innerHTML = '';

  if (contacts.length === 0) {
    list.innerHTML = '<li style="color: var(--text-muted); font-size: 13px; text-align: center; padding: 12px;">Noch keine Kontakte vorhanden.</li>';
    return;
  }

  contacts.forEach(c => {
    const li = document.createElement('li');
    li.className = `contact-item ${activeContact && activeContact.number === c.number ? 'active' : ''}`;
    const displayName = c.nickname ? escapeHtml(c.nickname) : c.number;
    const tag = c.isBurner ? '<span class="contact-type-tag">Burner</span>' : '';
    const founderBadge = getFounderBadgeHtml(c.username || c.nickname || '');

    li.innerHTML = `
      <div class="avatar">${displayName.slice(0, 2).toUpperCase()}</div>
      <div class="contact-details">
        <span class="contact-name">${displayName} ${founderBadge}</span>
        <span class="contact-id">ID: ${c.number}</span>
      </div>
      ${tag}
    `;
    li.addEventListener('click', () => selectContact(c));
    list.appendChild(li);
  });
}

async function handleAddContact() {
  const input = document.getElementById('peer-number-input');
  const rawInput = input.value.trim();

  if (!rawInput) {
    showToast('Bitte eine 8-stellige ID, Einweg-Nummer oder Nutzername eingeben.', true);
    return;
  }

  try {
    await addOrResolveContact(rawInput);
    input.value = '';
  } catch (err) {
    showToast(`Fehler beim Auflösen: ${err.message}`, true);
  }
}

async function addOrResolveContact(rawNumber) {
  let cleanNumber = String(rawNumber).trim();
  if (cleanNumber === '000000') cleanNumber = '00000000';

  let existing = contacts.find(c => c.number === cleanNumber || (c.username && c.username.toLowerCase() === cleanNumber.toLowerCase()));
  if (existing) {
    selectContact(existing);
    return existing;
  }

  const res = await fetch(`/api/profiles/resolve?number=${encodeURIComponent(cleanNumber)}`);
  const data = await res.json();

  if (!res.ok || data.error) {
    throw new Error(data.error || 'Nummer/Profil konnte nicht aufgelöst werden.');
  }

  const targetNumber = data.number || cleanNumber;
  const peerPubKeyObj = await importPublicKey(data.public_key);
  const sharedKey = await deriveSharedAesKey(localKeyPair.privateKey, peerPubKeyObj);

  const initialNickname = (data.share_profile && data.display_name) ? data.display_name : (data.isSupport ? 'Offizieller Support' : null);

  const newContact = {
    number: targetNumber,
    username: data.username || null,
    display_name: data.display_name || null,
    avatar_url: data.avatar_url || null,
    share_profile: data.share_profile,
    nickname: initialNickname,
    isBurner: !!data.isBurner,
    isSupport: !!data.isSupport,
    pubKeyB64: data.public_key,
    sharedKey: sharedKey
  };

  contacts.push(newContact);
  renderContacts();
  selectContact(newContact);

  showSavePromptBar(targetNumber);
  return newContact;
}

function checkUrlRouteRedirect() {
  const path = window.location.pathname;
  const urlParams = new URLSearchParams(window.location.search);
  const targetId = urlParams.get('id') || (path === '/support' ? '00000000' : null);

  if (targetId && currentUser) {
    const cleanId = targetId === '000000' ? '00000000' : targetId;
    addOrResolveContact(cleanId).then(contact => {
      if (contact) {
        selectContact(contact);
      }
    }).catch(() => {});
  }
}

function showSavePromptBar(number) {
  const isSaved = contacts.some(c => c.number === number && c.nickname !== undefined);
  const promptBar = document.getElementById('contact-prompt-bar');
  if (!isSaved) {
    document.getElementById('prompt-number').textContent = number;
    promptBar.classList.remove('hidden');
  } else {
    promptBar.classList.add('hidden');
  }
}

async function handleSavePromptContact() {
  if (!activeContact) return;
  await saveContactToSupabase(activeContact.number, activeContact.nickname);
  document.getElementById('contact-prompt-bar').classList.add('hidden');
  showToast(`Nummer ${activeContact.number} in Kontakten gespeichert.`);
}

function openNicknameModal() {
  if (!activeContact) return;
  document.getElementById('nickname-number-display').value = activeContact.number;
  document.getElementById('nickname-input').value = activeContact.nickname || '';
  document.getElementById('nickname-modal').classList.remove('hidden');
}

async function handleSaveNickname() {
  if (!activeContact) return;
  const newNickname = document.getElementById('nickname-input').value.trim();
  activeContact.nickname = newNickname || null;

  await saveContactToSupabase(activeContact.number, activeContact.nickname);
  renderContacts();
  selectContact(activeContact);

  document.getElementById('nickname-modal').classList.add('hidden');
  showToast('Nickname gespeichert!');
}

async function handleDeleteContact() {
  if (!activeContact) return;
  if (confirm(`Möchtest du ${activeContact.nickname || activeContact.number} wirklich aus den Kontakten entfernen?`)) {
    await deleteContactFromSupabase(activeContact.number);
    contacts = contacts.filter(c => c.number !== activeContact.number);
    activeContact = null;
    renderContacts();

    document.getElementById('empty-state').classList.remove('hidden');
    document.getElementById('chat-header').classList.add('hidden');
    document.getElementById('messages-container').classList.add('hidden');
    document.getElementById('send-message-form').classList.add('hidden');
    document.getElementById('nickname-modal').classList.add('hidden');
    showToast('Kontakt entfernt.');
  }
}

function selectContact(contact) {
  activeContact = contact;
  activeGroup = null;
  renderContacts();
  renderGroupsList();

  document.getElementById('empty-state').classList.add('hidden');
  document.getElementById('chat-header').classList.remove('hidden');
  document.getElementById('messages-container').classList.remove('hidden');
  document.getElementById('send-message-form').classList.remove('hidden');

  if (window.innerWidth <= 768) {
    document.getElementById('sidebar').classList.add('mobile-hidden');
  }

  const isSupportChat = contact.number === '00000000';
  const supportBanner = document.getElementById('support-disclaimer-banner');
  if (supportBanner) {
    if (isSupportChat) {
      supportBanner.classList.remove('hidden');
    } else {
      supportBanner.classList.add('hidden');
    }
  }

  const displayName = isSupportChat ? 'Offizieller Support (00000000)' : (contact.nickname ? `${contact.nickname} (${contact.number})` : `Chat ID: ${contact.number}`);
  const founderBadge = getFounderBadgeHtml(contact.username || contact.nickname || '');
  const supportBadge = isSupportChat ? '<span class="badge-supporter">🛡️ Support</span>' : '';

  document.getElementById('active-avatar').textContent = isSupportChat ? '🛡️' : (contact.nickname || contact.number).slice(0, 2).toUpperCase();
  document.getElementById('active-contact-name').innerHTML = `${escapeHtml(displayName)} ${supportBadge} ${founderBadge}`;

  showSavePromptBar(contact.number);
  loadAndRenderChatHistory(contact.number);
}

async function handleSendGroupMessage(text) {
  if (!activeGroup || !text) return;
  const senderNumber = document.getElementById('send-as-select').value || currentUser.main_number;

  const groupPayload = JSON.stringify({
    type: 'group_chat',
    groupId: activeGroup.id,
    groupName: activeGroup.name,
    text: text,
    sender: senderNumber
  });

  // Multi-recipient E2EE payload encryption and dispatch to all members
  for (const memberNumber of activeGroup.members) {
    let memberContact = contacts.find(c => c.number === memberNumber);
    if (!memberContact) {
      try {
        memberContact = await addOrResolveContact(memberNumber);
      } catch (e) {
        continue;
      }
    }

    if (memberContact && memberContact.sharedKey) {
      try {
        const encryptedPayloadStr = await encryptPayload(groupPayload, memberContact.sharedKey);

        await fetch('/api/messages', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            ...(accessToken ? { 'Authorization': `Bearer ${accessToken}` } : {})
          },
          body: JSON.stringify({
            sender_number: senderNumber,
            recipient_number: memberNumber,
            encrypted_payload: encryptedPayloadStr
          })
        });
      } catch (e) {
        console.error(`Error sending group message to ${memberNumber}:`, e);
      }
    }
  }

  const msgObj = {
    id: generate8DigitId(),
    sender_number: senderNumber,
    recipient_number: activeGroup.id,
    text: text,
    type: 'own',
    timestamp: Date.now()
  };

  appendMessageUI(msgObj, true);
  saveGroupChatMessage(activeGroup.id, msgObj);
  playSoundFeedback('send');
}

// --- UNREAD TEMPORARY MESSAGES ---

async function fetchAndProcessUnreadMessages() {
  const myNumbers = getMyAllNumbers();
  for (const num of myNumbers) {
    try {
      const res = await fetch(`/api/messages?recipient_number=${num}`);
      if (res.ok) {
        const msgs = await res.json();
        if (Array.isArray(msgs) && msgs.length > 0) {
          for (const record of msgs) {
            await handleIncomingMessage(record);
          }
          await fetch(`/api/messages?recipient_number=${num}`, { method: 'DELETE' });
        }
      }
    } catch (e) {
      console.error("Fetch unread messages error:", e);
    }
  }
}

async function cleanupTemporaryUnreadMessages() {
  const myNumbers = getMyAllNumbers();
  for (const num of myNumbers) {
    try {
      await fetch(`/api/messages?recipient_number=${num}`, { method: 'DELETE' });
    } catch (e) {}
  }
}

// --- ACCOUNT SETTINGS, DEACTIVATION, DELETE & BACKUP ---

async function handleSaveProfileSettings() {
  const dnInput = document.getElementById('settings-display-name-input');
  const avInput = document.getElementById('settings-avatar-url-input');
  const shareToggle = document.getElementById('settings-share-profile-toggle');

  const displayName = dnInput ? dnInput.value.trim() : '';
  const avatarUrl = avInput ? avInput.value.trim() : '';
  const shareProfile = shareToggle ? shareToggle.checked : true;

  try {
    const res = await fetch('/api/profiles/update', {
      method: 'PATCH',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${accessToken}`
      },
      body: JSON.stringify({
        display_name: displayName,
        avatar_url: avatarUrl,
        share_profile: shareProfile
      })
    });

    if (res.ok) {
      if (userProfile) {
        userProfile.display_name = displayName;
        userProfile.avatar_url = avatarUrl;
        userProfile.share_profile = shareProfile;
      }
      showToast('Profil-Einstellungen erfolgreich gespeichert!');
      if (currentUser) {
        const nameToUse = displayName || currentUser.username;
        document.getElementById('my-username').innerHTML = `${escapeHtml(nameToUse)} ${getFounderBadgeHtml(currentUser.username)}`;
        if (avatarUrl) {
          const avatarEl = document.getElementById('my-avatar');
          if (avatarEl) {
            avatarEl.innerHTML = `<img src="${escapeHtml(avatarUrl)}" style="width:100%;height:100%;border-radius:50%;object-fit:cover;">`;
          }
        }
      }
    } else {
      const err = await res.json();
      showToast(err.error || 'Fehler beim Speichern der Profil-Einstellungen.', true);
    }
  } catch (e) {
    showToast(e.message, true);
  }
}

async function handleExportKeysBackup() {
  if (!currentUser || !localKeyPair || !localPubKeyB64) return;
  try {
    const jwkPriv = await window.crypto.subtle.exportKey("jwk", localKeyPair.privateKey);

    const backupData = {
      app: "AegisChat",
      version: "2.0",
      timestamp: new Date().toISOString(),
      user: currentUser,
      publicKey: localPubKeyB64,
      privateKeyJwk: jwkPriv
    };

    const blob = new Blob([JSON.stringify(backupData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `aegischat-keys-backup-${currentUser.main_number}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);

    showToast('Schlüssel-Backup heruntergeladen!');
  } catch (err) {
    showToast(`Export-Fehler: ${err.message}`, true);
  }
}

async function handleDeactivateAccount() {
  if (!currentUser) return;
  if (confirm("Möchtest du dein Konto wirklich vorübergehend einfrieren / deaktivieren? Du wirst sofort abgemeldet.")) {
    try {
      const res = await fetch('/api/auth/deactivate', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(accessToken ? { 'Authorization': `Bearer ${accessToken}` } : {})
        },
        body: JSON.stringify({ user_id: currentUser.id })
      });

      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Deaktivierung fehlgeschlagen.');

      showToast('Konto eingefroren.');
      clearSessionData();
      location.reload();
    } catch (err) {
      showToast(err.message, true);
    }
  }
}

async function handleDeleteAccount() {
  if (!currentUser) return;
  const confirmation = prompt(`ACHTUNG: Dies löscht dein Konto (${currentUser.username}), deine Burner-IDs und alle Daten UNWIDERRUFLICH.\n\nTippe "${currentUser.username}" zur Bestätigung ein:`);

  if (confirmation === currentUser.username) {
    try {
      const res = await fetch('/api/auth/delete-account', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(accessToken ? { 'Authorization': `Bearer ${accessToken}` } : {})
        },
        body: JSON.stringify({ user_id: currentUser.id })
      });

      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Löschen fehlgeschlagen.');

      showToast('Konto unwiderruflich gelöscht.');
      clearSessionData();
      location.reload();
    } catch (err) {
      showToast(err.message, true);
    }
  } else if (confirmation !== null) {
    showToast('Bestätigung stimmte nicht überein.', true);
  }
}

// --- BURNER NUMBERS MANAGEMENT & AUTO-EXPIRY ---

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

  const now = new Date();

  myBurnerNumbers.forEach(b => {
    const li = document.createElement('li');
    li.className = 'burner-item';

    let expiryText = 'Kein Verfall';
    if (b.expires_at) {
      const expDate = new Date(b.expires_at);
      const diffMs = expDate - now;
      if (diffMs > 0) {
        const diffMins = Math.floor(diffMs / 60000);
        const hours = Math.floor(diffMins / 60);
        const mins = diffMins % 60;
        expiryText = `Ablauf in ${hours > 0 ? hours + 'h ' : ''}${mins} Min`;
      } else {
        expiryText = 'Abgelaufen';
        b.active = false;
      }
    }

    const statusBadge = b.active
      ? '<span style="color: #10b981; font-weight: 600;">Aktiv</span>'
      : '<span style="color: #ef4444; font-weight: 600;">Inaktiv / Abgelaufen</span>';

    li.innerHTML = `
      <div class="burner-info">
        <span class="burner-num">${b.burner_number}</span>
        <span class="burner-expiry">${expiryText} • ${statusBadge}</span>
      </div>
      <div class="burner-actions">
        <button class="icon-btn qr-btn" title="QR-Code"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M7 12H12V17M3.01 12H3M8.01 17H8M12.01 21H12M21.01 12H21M3 17H4.5M15.5 12H17.5M3 21H8M12 2V8M17.6 21H19.4C19.9601 21 20.2401 21 20.454 20.891C20.6422 20.7951 20.7951 20.6422 20.891 20.454C21 20.2401 21 19.9601 21 19.4V17.6C21 17.0399 21 16.7599 20.891 16.546C20.7951 16.3578 20.6422 16.2049 20.454 16.109C20.2401 16 19.9601 16 19.4 16H17.6C17.0399 16 16.7599 16 16.546 16.109C16.3578 16.2049 16.2049 16.3578 16.109 16.546C16 16.7599 16 17.0399 16 17.6V19.4C16 19.9601 16 20.2401 16.109 20.454C16.2049 20.6422 16.3578 20.7951 16.546 20.891C16.7599 21 17.0399 21 17.6 21ZM17.6 8H19.4C19.9601 8 20.2401 8 20.454 7.89101C20.6422 7.79513 20.7951 7.64215 20.891 7.45399C21 7.24008 21 6.96005 21 6.4V4.6C21 4.03995 21 3.75992 20.891 3.54601C20.7951 3.35785 20.6422 3.20487 20.454 3.10899C20.2401 3 19.9601 3 19.4 3H17.6C17.0399 3 16.7599 3 16.546 3.10899C16.3578 3.20487 16.2049 3.35785 16.109 3.54601C16 3.75992 16 4.03995 16 4.6V6.4C16 6.96005 16 7.24008 16.109 7.45399C16.2049 7.64215 16.3578 7.79513 16.546 7.89101C16.7599 8 17.0399 8 17.6 8ZM4.6 8H6.4C6.96005 8 7.24008 8 7.45399 7.89101C7.64215 7.79513 7.79513 7.64215 7.89101 7.45399C8 7.24008 8 6.96005 8 6.4V4.6C8 4.03995 8 3.75992 7.89101 3.54601C7.79513 3.35785 7.64215 3.20487 7.45399 3.10899C7.24008 3 6.96005 3 6.4 3H4.6C4.03995 3 3.75992 3 3.54601 3.10899C3.35785 3.20487 3.20487 3.35785 3.10899 3.54601C3 3.75992 3 4.03995 3 4.6V6.4C3 6.96005 3 7.24008 3.10899 7.45399C3.20487 7.64215 3.35785 7.79513 3.54601 7.89101C3.75992 8 4.03995 8 4.6 8Z" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg></button>
        <button class="icon-btn revoke-btn style-danger" title="Sofort Deaktivieren / Revoke"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg></button>
      </div>
    `;

    li.querySelector('.qr-btn').addEventListener('click', () => {
      document.getElementById('qr-modal-title').textContent = "Einweg-Nummer QR-Code";
      document.getElementById('qr-modal-subtext').textContent = `Scanne diesen Code für anonymen Empfang an ${b.burner_number}.`;
      displayQrCode(b.burner_number);
      document.getElementById('qr-modal').classList.remove('hidden');
    });

    li.querySelector('.revoke-btn').addEventListener('click', async () => {
      if (confirm(`Möchtest du Einweg-Nummer ${b.burner_number} sofort deaktivieren / löschen?`)) {
        await fetch(`/api/burners?id=${b.id}`, {
          method: 'DELETE',
          headers: accessToken ? { 'Authorization': `Bearer ${accessToken}` } : {}
        });
        myBurnerNumbers = myBurnerNumbers.filter(x => x.id !== b.id);
        updateSenderDropdown();
        renderBurnerList();
        showToast(`Einweg-Nummer ${b.burner_number} widerrufen.`);
      }
    });

    list.appendChild(li);
  });
}

// --- MESSAGING, TYPING INDICATOR & SELF-DESTRUCT TIMER ---

async function handleSendMessage(e) {
  e.preventDefault();
  const input = document.getElementById('message-input');
  const text = input.value.trim();
  if ((!text && !selectedFile) || (!activeContact && !activeGroup)) return;

  if (activeGroup) {
    await handleSendGroupMessage(text);
    input.value = '';
    return;
  }

  const progressContainer = document.getElementById('upload-progress-container');
  const progressBar = document.getElementById('upload-progress-bar');

  try {
    const senderNumber = document.getElementById('send-as-select').value || currentUser.main_number;
    const recipientNumber = activeContact.number;
    let payloadText = text;

    if (selectedFile) {
      if (progressContainer) progressContainer.classList.remove('hidden');
      if (progressBar) progressBar.style.width = '0%';

      const uploadResult = await encryptFile(selectedFile, activeContact.sharedKey, (percent) => {
        if (progressBar) progressBar.style.width = `${percent}%`;
      });

      payloadText = JSON.stringify({
        type: 'file',
        file_url: uploadResult.file_url,
        file_id: uploadResult.file_id,
        file_name: selectedFile.name,
        file_size: selectedFile.size,
        mime_type: selectedFile.type || 'application/octet-stream',
        caption: text,
        view_once: isViewOnceActive
      });

      if (isViewOnceActive) {
        isViewOnceActive = false;
        const viewOnceBtn = document.getElementById('view-once-toggle-btn');
        if (viewOnceBtn) viewOnceBtn.classList.remove('active');
      }
    }

    const encryptedPayloadStr = await encryptPayload(payloadText, activeContact.sharedKey);

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

    let expiresAt = null;
    if (activeSelfDestructTimer === '10s') expiresAt = Date.now() + 10 * 1000;
    else if (activeSelfDestructTimer === '1m') expiresAt = Date.now() + 60 * 1000;
    else if (activeSelfDestructTimer === '1h') expiresAt = Date.now() + 3600 * 1000;
    else if (activeSelfDestructTimer === '24h') expiresAt = Date.now() + 24 * 3600 * 1000;

    const msgObj = {
      id: generate8DigitId(),
      sender_number: senderNumber,
      recipient_number: recipientNumber,
      text: payloadText,
      type: 'own',
      timestamp: Date.now(),
      expiresAt: expiresAt,
      status: 'sent'
    };

    appendMessageUI(msgObj, true);
    saveChatMessage(recipientNumber, msgObj);
    input.value = '';
    clearSelectedFile();
    playSoundFeedback('send');

    if (expiresAt) {
      scheduleSelfDestruct(msgObj.id, recipientNumber, expiresAt - Date.now());
    }
  } catch (err) {
    showToast(err.message, true);
  } finally {
    if (progressContainer) progressContainer.classList.add('hidden');
    if (progressBar) progressBar.style.width = '0%';
  }
}

function handleTypingInput() {
  if (!activeContact || !supabaseClient || !realtimeChannel) return;
  if (typingTimeout) clearTimeout(typingTimeout);

  realtimeChannel.send({
    type: 'broadcast',
    event: 'typing',
    payload: { sender: currentUser.main_number, recipient: activeContact.number }
  });

  typingTimeout = setTimeout(() => {}, 2000);
}

function scheduleSelfDestruct(msgId, contactNumber, delayMs) {
  setTimeout(() => {
    const bubble = document.getElementById(`msg-${msgId}`);
    if (bubble && bubble.parentNode) {
      bubble.parentNode.removeChild(bubble);
    }
    const history = getChatHistory(contactNumber);
    const updated = history.filter(m => m.id !== msgId);
    sessionStorage.setItem(SESSION_CHAT_PREFIX + contactNumber, JSON.stringify(updated));
  }, delayMs);
}

function getChatHistory(contactNumber) {
  const stored = sessionStorage.getItem(SESSION_CHAT_PREFIX + contactNumber);
  if (!stored) return [];
  try {
    const history = JSON.parse(stored);
    const now = Date.now();
    return history.filter(m => !m.expiresAt || m.expiresAt > now);
  } catch (e) { return []; }
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
  const now = Date.now();

  history.forEach(msg => {
    if (msg.expiresAt && msg.expiresAt <= now) return;
    appendMessageUI(msg, false);

    if (msg.expiresAt) {
      scheduleSelfDestruct(msg.id, contactNumber, msg.expiresAt - now);
    }
  });
  container.scrollTop = container.scrollHeight;
}

function appendMessageUI(msgObj, isNew = false) {
  const container = document.getElementById('messages-container');
  const time = new Date(msgObj.timestamp || Date.now()).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  const div = document.createElement('div');
  div.id = `msg-${msgObj.id || Date.now()}`;
  div.className = `msg-bubble ${msgObj.type}`;

  if (isNew) {
    div.classList.add(msgObj.type === 'own' ? 'encrypting-pulse' : 'decrypting-pulse');
  }

  const contactNum = msgObj.type === 'own' ? msgObj.recipient_number : msgObj.sender_number;
  const contact = contacts.find(c => c.number === contactNum);
  let founderBadge = '';
  if (msgObj.type === 'own' && currentUser && isFounder(currentUser.username)) {
    founderBadge = getFounderBadgeHtml(currentUser.username);
  } else if (msgObj.type !== 'own' && contact && isFounder(contact.username || contact.nickname)) {
    founderBadge = getFounderBadgeHtml(contact.username || contact.nickname);
  } else if (msgObj.sender_username && isFounder(msgObj.sender_username)) {
    founderBadge = getFounderBadgeHtml(msgObj.sender_username);
  }

  const senderMeta = msgObj.type === 'own' ? `An: ${msgObj.recipient_number}` : `Von: ${msgObj.sender_number}`;
  const tickIcon = msgObj.type === 'own' ? '<span class="msg-tick" title="Verschlüsselt gesendet">✓✓</span>' : '';
  const timerBadge = msgObj.expiresAt ? '<span style="font-size: 10px; margin-right: 4px;" title="Selbstzerstörung aktiv">⏱️</span>' : '';

  let messageContentHtml = '';
  let isFileMessage = false;
  let isVoiceMessage = false;
  let isCallEvent = false;
  let fileMeta = null;
  let voiceMeta = null;
  let callEventMeta = null;

  try {
    if (msgObj.text && msgObj.text.startsWith('{')) {
      const parsed = JSON.parse(msgObj.text);
      if (parsed && parsed.type === 'file' && parsed.file_url) {
        isFileMessage = true;
        fileMeta = parsed;
      } else if (parsed && parsed.type === 'voice' && parsed.file_url) {
        isVoiceMessage = true;
        voiceMeta = parsed;
      } else if (parsed && (parsed.type === 'call_event' || parsed.type === 'call-signal' || parsed.event)) {
        isCallEvent = true;
        callEventMeta = parsed;
      }
    }
  } catch (e) {}

  if ((isFileMessage && fileMeta && fileMeta.view_once) || (isVoiceMessage && voiceMeta && voiceMeta.view_once)) {
    const meta = fileMeta || voiceMeta;
    const viewOnceCardId = `vo-${msgObj.id || Math.random().toString(36).substr(2, 9)}`;

    messageContentHtml = `
      <div id="${viewOnceCardId}">
        <div class="view-once-card" id="btn-${viewOnceCardId}">
          <div class="view-once-badge">1</div>
          <div class="view-once-text">Einmal-Medium (Klicken zum Öffnen)</div>
        </div>
      </div>
    `;

    setTimeout(() => {
      const btn = document.getElementById(`btn-${viewOnceCardId}`);
      if (btn) {
        btn.addEventListener('click', async () => {
          if (!contact || !contact.sharedKey) return;
          btn.innerHTML = `<div class="view-once-badge">...</div><div class="view-once-text">Entschlüssele Einmal-Medium...</div>`;

          try {
            const objectUrl = await fetchAndDecryptFileBlob(meta.file_url, contact.sharedKey, meta.mime_type || 'application/octet-stream');

            if (meta.type === 'file' && meta.mime_type && meta.mime_type.startsWith('image/')) {
              openLightbox(objectUrl, meta.file_name || 'Einmal-Bild');

              const closeLightboxBtn = document.getElementById('close-lightbox-btn');
              const onLightboxClose = () => {
                URL.revokeObjectURL(objectUrl);
                const targetEl = document.getElementById(viewOnceCardId);
                if (targetEl) {
                  targetEl.innerHTML = `<div class="view-once-card view-once-burned"><div class="view-once-badge">✓</div><div class="view-once-text">Geöffnet (Gespurt / Storage gelöscht)</div></div>`;
                }
                burnViewOnceMedia(meta.file_id, msgObj.id, contactNum);
                if (closeLightboxBtn) closeLightboxBtn.removeEventListener('click', onLightboxClose);
              };
              if (closeLightboxBtn) closeLightboxBtn.addEventListener('click', onLightboxClose, { once: true });
            } else {
              const audio = new Audio(objectUrl);
              showToast("🔊 Spiele Einmal-Audio ab...");
              audio.play();
              audio.onended = () => {
                URL.revokeObjectURL(objectUrl);
                const targetEl = document.getElementById(viewOnceCardId);
                if (targetEl) {
                  targetEl.innerHTML = `<div class="view-once-card view-once-burned"><div class="view-once-badge">✓</div><div class="view-once-text">Abgespielt (Gespurt / Storage gelöscht)</div></div>`;
                }
                burnViewOnceMedia(meta.file_id, msgObj.id, contactNum);
              };
            }
          } catch (err) {
            showToast("Fehler beim Öffnen des Einmal-Mediums.", true);
          }
        });
      }
    }, 50);

  } else if (isVoiceMessage && voiceMeta) {
    const voiceContainerId = `voice-${msgObj.id || Math.random().toString(36).substr(2, 9)}`;
    const formatTime = (s) => {
      const m = Math.floor(s / 60);
      const sec = Math.floor(s % 60);
      return `${m}:${sec < 10 ? '0' : ''}${sec}`;
    };

    messageContentHtml = `
      <div id="${voiceContainerId}">
        <div class="file-loading-spinner">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="animation: spin 1s linear infinite;"><path d="M21 12a9 9 0 1 1-6.219-8.56"/></svg>
          <span>Entschlüssele Sprachnachricht...</span>
        </div>
      </div>
    `;

    if (contact && contact.sharedKey) {
      fetchAndDecryptFileBlob(voiceMeta.file_url, contact.sharedKey, voiceMeta.mime_type || 'audio/webm')
        .then(objectUrl => {
          activeAudioObjectURLs.add(objectUrl);
          const targetEl = document.getElementById(voiceContainerId);
          if (!targetEl) return;

          const durFormatted = formatTime(voiceMeta.duration || 0);

          targetEl.innerHTML = `
            <div class="voice-player-card">
              <button class="voice-play-btn" id="pbtn-${msgObj.id}">▶</button>
              <div class="voice-player-info">
                <div class="voice-progress-track" id="ptrack-${msgObj.id}">
                  <div class="voice-progress-fill" id="pfill-${msgObj.id}"></div>
                </div>
                <div class="voice-time-display">
                  <span id="ptime-${msgObj.id}">0:00</span>
                  <span>${durFormatted}</span>
                </div>
              </div>
            </div>
          `;

          const audio = new Audio(objectUrl);
          const playBtn = document.getElementById(`pbtn-${msgObj.id}`);
          const fillEl = document.getElementById(`pfill-${msgObj.id}`);
          const timeEl = document.getElementById(`ptime-${msgObj.id}`);
          const trackEl = document.getElementById(`ptrack-${msgObj.id}`);

          if (playBtn) {
            playBtn.addEventListener('click', () => {
              if (audio.paused) {
                document.querySelectorAll('audio').forEach(a => { if (a !== audio) a.pause(); });
                audio.play();
                playBtn.textContent = '⏸';
              } else {
                audio.pause();
                playBtn.textContent = '▶';
              }
            });
          }

          audio.addEventListener('timeupdate', () => {
            if (audio.duration) {
              const pct = (audio.currentTime / audio.duration) * 100;
              if (fillEl) fillEl.style.width = `${pct}%`;
              if (timeEl) timeEl.textContent = formatTime(audio.currentTime);
            }
          });

          audio.addEventListener('ended', () => {
            if (playBtn) playBtn.textContent = '▶';
            if (fillEl) fillEl.style.width = '0%';
            if (timeEl) timeEl.textContent = '0:00';
          });

          if (trackEl) {
            trackEl.addEventListener('click', (e) => {
              const rect = trackEl.getBoundingClientRect();
              const clickPos = (e.clientX - rect.left) / rect.width;
              if (audio.duration) {
                audio.currentTime = clickPos * audio.duration;
              }
            });
          }

          container.scrollTop = container.scrollHeight;
        })
        .catch(err => {
          const targetEl = document.getElementById(voiceContainerId);
          if (targetEl) {
            targetEl.innerHTML = `<div class="file-loading-spinner" style="color: var(--danger);">Fehler beim Entschlüsseln der Sprachnachricht.</div>`;
          }
        });
    }
  } else if (isFileMessage && fileMeta) {
    const attachmentContainerId = `attach-${msgObj.id || Math.random().toString(36).substr(2, 9)}`;
    messageContentHtml = `
      <div id="${attachmentContainerId}">
        <div class="file-loading-spinner">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="animation: spin 1s linear infinite;"><path d="M21 12a9 9 0 1 1-6.219-8.56"/></svg>
          <span>Entschlüssele Datei...</span>
        </div>
      </div>
    `;

    if (contact && contact.sharedKey) {
      fetchAndDecryptFileBlob(fileMeta.file_url, contact.sharedKey, fileMeta.mime_type)
        .then(objectUrl => {
          const targetEl = document.getElementById(attachmentContainerId);
          if (!targetEl) return;

          if (fileMeta.mime_type && fileMeta.mime_type.startsWith('image/')) {
            targetEl.innerHTML = `
              <div class="media-card">
                <img src="${objectUrl}" class="media-card-img" alt="${escapeHtml(fileMeta.file_name)}" onclick="openLightbox('${objectUrl}', '${escapeHtml(fileMeta.file_name)}')">
              </div>
              ${fileMeta.caption ? `<div style="margin-top: 4px;">${escapeHtml(fileMeta.caption)}</div>` : ''}
            `;
          } else {
            targetEl.innerHTML = `
              <a href="${objectUrl}" download="${escapeHtml(fileMeta.file_name)}" class="file-attachment-card">
                <svg class="file-attachment-icon" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
                <div class="file-attachment-info">
                  <span class="file-attachment-name">${escapeHtml(fileMeta.file_name)}</span>
                  <span class="file-attachment-size">${formatFileSize(fileMeta.file_size)}</span>
                </div>
                <div class="file-attachment-dl-btn">
                  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                </div>
              </a>
              ${fileMeta.caption ? `<div style="margin-top: 4px;">${escapeHtml(fileMeta.caption)}</div>` : ''}
            `;
          }
          container.scrollTop = container.scrollHeight;
        })
        .catch(err => {
          const targetEl = document.getElementById(attachmentContainerId);
          if (targetEl) {
            targetEl.innerHTML = `<div class="file-loading-spinner" style="color: var(--danger);">Fehler beim Entschlüsseln der Datei.</div>`;
          }
        });
    }
  } else if (isCallEvent && callEventMeta) {
    const isVideo = callEventMeta.call_type === 'video' || callEventMeta.type === 'video';
    const icon = isVideo ? '📹' : '📞';
    const callTypeName = isVideo ? 'Videoanruf' : 'Sprachanruf';

    let statusText = '';
    let statusClass = '';

    if (callEventMeta.event === 'missed' || callEventMeta.status === 'missed') {
      statusText = `Verpasster ${callTypeName}`;
      statusClass = 'call-widget-missed';
    } else if (callEventMeta.duration) {
      const m = Math.floor(callEventMeta.duration / 60);
      const s = callEventMeta.duration % 60;
      const durFormatted = `${m < 10 ? '0' : ''}${m}:${s < 10 ? '0' : ''}${s}`;
      statusText = `${callTypeName} • ${durFormatted} Min.`;
      statusClass = 'call-widget-ended';
    } else {
      statusText = `${callTypeName} Beendet`;
      statusClass = 'call-widget-ended';
    }

    messageContentHtml = `
      <div class="call-event-card ${statusClass}">
        <div class="call-event-icon">${icon}</div>
        <div class="call-event-info">
          <span class="call-event-title">${statusText}</span>
          <span class="call-event-sub">E2EE WebRTC Encrypted</span>
        </div>
      </div>
    `;
  } else {
    let cleanText = msgObj.text || '';
    if (cleanText.startsWith('{') && cleanText.endsWith('}')) {
      try {
        const p = JSON.parse(cleanText);
        if (p && p.text) cleanText = p.text;
        else if (p && p.message) cleanText = p.message;
        else cleanText = 'Sichere Systemnachricht';
      } catch (e) {}
    }
    messageContentHtml = `<div>${escapeHtml(cleanText)}</div>`;
  }

  div.innerHTML = `
    <div style="font-size: 11px; opacity: 0.8; font-family: var(--font-mono); margin-bottom: 2px;">${senderMeta} ${founderBadge}</div>
    ${messageContentHtml}
    <div class="msg-meta">
      ${timerBadge}
      <span>${time}</span>
      ${tickIcon}
    </div>
  `;
  container.appendChild(div);
  container.scrollTop = container.scrollHeight;
}

// --- REALTIME MESSAGING WEBSOCKET STREAM ---

function getMyAllNumbers() {
  if (!currentUser) return [];
  const list = [currentUser.main_number];
  myBurnerNumbers.filter(b => b.active).forEach(b => list.push(b.burner_number));
  return list;
}

async function handleIncomingMessage(record) {
  if (!record || !record.recipient_number) return;
  if (record.id && processedMsgIds.has(record.id)) return;
  if (record.id) processedMsgIds.add(record.id);

  const myNumbers = getMyAllNumbers();

  if (myNumbers.includes(record.recipient_number)) {
    const senderNumber = record.sender_number;
    let contact = contacts.find(c => c.number === senderNumber);

    if (!contact) {
      contact = await addOrResolveContact(senderNumber);
    }

    const decryptedText = await decryptPayload(record.encrypted_payload, contact.sharedKey);

    try {
      if (decryptedText && decryptedText.startsWith('{')) {
        const parsed = JSON.parse(decryptedText);
        if (parsed && parsed.type === 'call-signal') {
          await handleIncomingCallSignal(parsed);
          if (record.id) {
            fetch(`/api/messages?id=${record.id}`, { method: 'DELETE' }).catch(() => {});
          }
          return;
        } else if (parsed && parsed.type === 'group_chat' && parsed.groupId) {
          const groupMsgObj = {
            id: record.id || generate8DigitId(),
            sender_number: senderNumber,
            recipient_number: parsed.groupId,
            text: parsed.text,
            type: 'other',
            timestamp: record.created_at ? new Date(record.created_at).getTime() : Date.now()
          };

          saveGroupChatMessage(parsed.groupId, groupMsgObj);
          playSoundFeedback('receive');

          if (activeGroup && activeGroup.id === parsed.groupId) {
            appendMessageUI(groupMsgObj, true);
          } else {
            showToast(`Neue E2EE Gruppennachricht in ${parsed.groupName || 'Gruppe'}!`);
          }

          if (record.id) {
            fetch(`/api/messages?id=${record.id}`, { method: 'DELETE' }).catch(() => {});
          }
          return;
        }
      }
    } catch (e) {}

    const msgObj = {
      id: record.id || generate8DigitId(),
      sender_number: senderNumber,
      recipient_number: record.recipient_number,
      text: decryptedText,
      type: 'other',
      timestamp: record.created_at ? new Date(record.created_at).getTime() : Date.now()
    };

    saveChatMessage(senderNumber, msgObj);
    playSoundFeedback('receive');

    if (activeContact && activeContact.number === senderNumber) {
      appendMessageUI(msgObj, true);
    } else {
      showToast(`Neue E2EE Nachricht von ${contact.nickname || senderNumber}!`);
    }

    if (record.id) {
      fetch(`/api/messages?id=${record.id}`, { method: 'DELETE' }).catch(() => {});
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

  if (window.supabase && supabaseUrl && supabaseAnonKey) {
    try {
      const clientOptions = {};
      if (accessToken) {
        clientOptions.global = {
          headers: { Authorization: `Bearer ${accessToken}` }
        };
      }
      supabaseClient = window.supabase.createClient(supabaseUrl, supabaseAnonKey, clientOptions);

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
            if (payload && payload.new) {
              try {
                await handleIncomingMessage(payload.new);
              } catch (err) {
                console.error('Error processing realtime payload:', err);
              }
            }
          }
        )
        .on('broadcast', { event: 'typing' }, (payload) => {
          if (activeContact && payload && payload.payload && payload.payload.sender === activeContact.number) {
            const typingEl = document.getElementById('typing-indicator');
            if (typingEl) {
              typingEl.classList.remove('hidden');
              setTimeout(() => typingEl.classList.add('hidden'), 2500);
            }
          }
        })
        .on('broadcast', { event: 'call-signal' }, async (payload) => {
          if (payload && payload.payload) {
            const { encryptedPayload, recipient } = payload.payload;
            const myNumbers = getMyAllNumbers();
            if (myNumbers.includes(recipient)) {
              const contact = contacts.find(c => c.number === payload.payload.sender);
              if (contact && contact.sharedKey) {
                try {
                  const decryptedSignalStr = await decryptPayload(encryptedPayload, contact.sharedKey);
                  const signalObj = JSON.parse(decryptedSignalStr);
                  if (signalObj.type === 'call-signal') {
                    await handleIncomingCallSignal(signalObj);
                  }
                } catch (e) {}
              }
            }
          }
        })
        .subscribe((status, err) => {
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

  const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
  const wsUrl = `${protocol}//${location.host}/api/realtime`;

  try {
    realtimeSocket = new WebSocket(wsUrl);

    realtimeSocket.onopen = () => {
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
      if (dot) {
        dot.className = 'dot offline';
        dot.title = "Realtime Verbindung getrennt";
      }
    };

    realtimeSocket.onclose = () => {
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
