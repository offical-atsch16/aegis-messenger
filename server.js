// AegisChat Standalone HTTP Server & Lightweight Native WebSocket Relay (No npm dependencies)
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 8080;

// HTTP Server serving static files (index.html, style.css, app.js)
const server = http.createServer((req, res) => {
  if (req.url.startsWith('/api/')) {
    res.writeHead(200, {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': '*'
    });
    if (req.url.startsWith('/api/settings/public')) {
      res.end(JSON.stringify({
        require_invite_code: false,
        banner_config: { enabled: false },
        maintenance_mode: { enabled: false }
      }));
      return;
    }
    if (req.url.startsWith('/api/auth/register')) {
      let body = '';
      req.on('data', chunk => body += chunk);
      req.on('end', () => {
        try {
          const parsed = JSON.parse(body || '{}');
          if (parsed.username && ['admin', 'support', 'system'].includes(parsed.username.toLowerCase())) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Dieser Profilname ist reserviert oder enthält ungültige Zeichen.' }));
            return;
          }
        } catch (e) {}
        const mockPrivKey = JSON.stringify({
          salt: "1234567812345678",
          iv: "123456781234",
          ciphertext: "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE"
        });
        res.end(JSON.stringify({
          user: { id: "11111111-1111-1111-1111-111111111111", username: "user123", main_number: "88888888" },
          profile: { username: "user123", main_number: "88888888", display_name: "User 123", encrypted_private_key: mockPrivKey, public_key: "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE", is_admin: false, share_profile: true },
          access_token: "mock_token"
        }));
      });
      return;
    }
    if (req.url.startsWith('/api/auth/login')) {
      res.end(JSON.stringify({
        user: { id: "11111111-1111-1111-1111-111111111111", username: "arien", main_number: "88888888" },
        profile: { username: "arien", main_number: "88888888", display_name: "Arien Founder", encrypted_private_key: null, public_key: null, is_admin: true, share_profile: true },
        access_token: "mock_token"
      }));
      return;
    }
    if (req.url.startsWith('/api/admin/support/tickets')) {
      res.end(JSON.stringify([
        {
          id: '1',
          user_number: '88888888',
          ticket_status: 'open',
          status: 'open',
          updated_at: new Date().toISOString()
        }
      ]));
      return;
    }
    if (req.url.startsWith('/api/profiles/resolve')) {
      const fallbackJwkB64 = 'eyJrZXlfb3BzIjpbXSwiZXh0Ijp0cnVlLCJrdHkiOiJFQyIsIngiOiJYc0hhR0pDQUI2MWpkZFV3MTh4Q0MxU2czanpHVmlYcURzeVZwZ0NaYWFnIiwieSI6IjgwMGRzNkNpVU83S0ticC14dEJkRDJESy1ibXFnaDVCMlNMLWs5bDhoc0kiLCJjcnYiOiJQLTI1NiJ9';
      if (req.url.includes('11111111') || req.url.includes('00000000') || req.url.includes('support') || req.url.includes('111111')) {
        res.end(JSON.stringify({
          number: '11111111',
          username: 'support',
          public_key: fallbackJwkB64,
          display_name: 'Offizieller Support',
          share_profile: true,
          isSupport: true,
          is_disabled: false,
          isBurner: false
        }));
        return;
      }
      res.end(JSON.stringify({
        number: "88888888",
        username: "arien",
        public_key: fallbackJwkB64,
        display_name: "Arien Founder",
        share_profile: true,
        isBurner: false
      }));
      return;
    }
    if (req.url.startsWith('/api/contacts') || req.url.startsWith('/api/burners') || req.url.startsWith('/api/messages')) {
      res.end(JSON.stringify([]));
      return;
    }
    res.end(JSON.stringify({ success: true }));
    return;
  }

  const reqPath = new URL(req.url, `http://${req.headers.host}`).pathname;

  let filePath = '.' + reqPath;
  if (reqPath === '/' || reqPath === '/support') {
    filePath = './index.html';
  } else if (reqPath === '/impressum' || reqPath === '/legal') {
    filePath = './public/impressum.html';
  } else if (reqPath === '/datenschutz') {
    filePath = './public/datenschutz.html';
  } else if (reqPath === '/agb') {
    filePath = './public/agb.html';
  } else if (reqPath === '/how-it-works' || reqPath === '/about') {
    filePath = './public/how-it-works.html';
  } else if (fs.existsSync('./public' + reqPath)) {
    filePath = './public' + reqPath;
  }

  const extname = String(path.extname(filePath)).toLowerCase();
  const mimeTypes = {
    '.html': 'text/html',
    '.js': 'text/javascript',
    '.css': 'text/css',
    '.json': 'application/json',
    '.png': 'image/png',
    '.jpg': 'image/jpg',
    '.gif': 'image/gif',
    '.svg': 'image/svg+xml',
  };

  const contentType = mimeTypes[extname] || 'application/octet-stream';

  fs.readFile(filePath, (error, content) => {
    if (error) {
      if (error.code === 'ENOENT') {
        fs.readFile('./index.html', (err2, fallback) => {
          if (err2) {
            res.writeHead(404, { 'Content-Type': 'text/html' });
            res.end('404 Not Found', 'utf-8');
          } else {
            res.writeHead(200, { 'Content-Type': 'text/html' });
            res.end(fallback, 'utf-8');
          }
        });
      } else {
        res.writeHead(500);
        res.end('Server Error: ' + error.code, 'utf-8');
      }
    } else {
      res.writeHead(200, { 'Content-Type': contentType });
      res.end(content, 'utf-8');
    }
  });
});

// Minimal Native WebSocket Frame Encoder/Decoder
function sendWsFrame(socket, payloadString) {
  const payloadBuffer = Buffer.from(payloadString, 'utf8');
  const length = payloadBuffer.length;
  let header;

  if (length <= 125) {
    header = Buffer.alloc(2);
    header[0] = 0x81; // Text frame, FIN bit set
    header[1] = length;
  } else if (length <= 65535) {
    header = Buffer.alloc(4);
    header[0] = 0x81;
    header[1] = 126;
    header.writeUInt16BE(length, 2);
  } else {
    header = Buffer.alloc(10);
    header[0] = 0x81;
    header[1] = 127;
    header.writeBigUInt64BE(BigInt(length), 2);
  }

  try {
    socket.write(Buffer.concat([header, payloadBuffer]));
  } catch (err) {
    console.error('Error writing WS frame:', err);
  }
}

// Map of clientId -> socket connection
const clients = new Map();

server.on('upgrade', (req, socket, head) => {
  const pathname = new URL(req.url, `http://${req.headers.host}`).pathname;
  if (pathname !== '/ws') {
    socket.destroy();
    return;
  }

  const secKey = req.headers['sec-websocket-key'];
  if (!secKey) {
    socket.destroy();
    return;
  }

  const acceptKey = crypto
    .createHash('sha1')
    .update(secKey + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11')
    .digest('base64');

  const headers = [
    'HTTP/1.1 101 Switching Protocols',
    'Upgrade: websocket',
    'Connection: Upgrade',
    `Sec-WebSocket-Accept: ${acceptKey}`,
    '\r\n'
  ];

  socket.write(headers.join('\r\n'));

  let buffer = Buffer.alloc(0);
  let registeredId = null;

  socket.on('data', (chunk) => {
    buffer = Buffer.concat([buffer, chunk]);

    while (buffer.length >= 2) {
      const secondByte = buffer[1];
      const isMasked = (secondByte & 0x80) === 0x80;
      let payloadLen = secondByte & 0x7f;
      let offset = 2;

      if (payloadLen === 126) {
        if (buffer.length < 4) return;
        payloadLen = buffer.readUInt16BE(2);
        offset = 4;
      } else if (payloadLen === 127) {
        if (buffer.length < 10) return;
        payloadLen = Number(buffer.readBigUInt64BE(2));
        offset = 10;
      }

      let masks = null;
      if (isMasked) {
        if (buffer.length < offset + 4) return;
        masks = buffer.slice(offset, offset + 4);
        offset += 4;
      }

      if (buffer.length < offset + payloadLen) return;

      const payload = buffer.slice(offset, offset + payloadLen);
      buffer = buffer.slice(offset + payloadLen);

      if (isMasked && masks) {
        for (let i = 0; i < payload.length; i++) {
          payload[i] ^= masks[i % 4];
        }
      }

      const msgStr = payload.toString('utf8');
      try {
        const data = JSON.parse(msgStr);

        // Client Registration
        if (data.type === 'register' && data.clientId) {
          registeredId = String(data.clientId);
          clients.set(registeredId, socket);
          console.log(`[Relay] Client registered: ${registeredId}`);
          continue;
        }

        // Forward Encrypted Ciphertext Payload
        if (data.targetId && data.ciphertext) {
          const targetSocket = clients.get(String(data.targetId));
          if (targetSocket && !targetSocket.destroyed) {
            sendWsFrame(targetSocket, JSON.stringify({
              senderId: data.senderId || registeredId,
              ciphertext: data.ciphertext
            }));
            console.log(`[Relay] Forwarded payload from ${registeredId} to ${data.targetId}`);
          }
        }
      } catch (err) {
        console.error('[Relay] Error parsing message JSON:', err);
      }
    }
  });

  socket.on('close', () => {
    if (registeredId && clients.get(registeredId) === socket) {
      clients.delete(registeredId);
      console.log(`[Relay] Client disconnected: ${registeredId}`);
    }
  });

  socket.on('error', () => {
    socket.destroy();
  });
});

server.listen(PORT, () => {
  console.log(`[AegisChat Server] Server and WebSocket Relay running at http://localhost:${PORT}`);
});
