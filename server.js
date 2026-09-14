// AegisChat Standalone HTTP Server & Lightweight Native WebSocket Relay (No npm dependencies)
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 8080;

// HTTP Server serving static files (index.html, style.css, app.js)
const server = http.createServer((req, res) => {
  let filePath = '.' + req.url;
  if (filePath === './') {
    filePath = './index.html';
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
        res.writeHead(404, { 'Content-Type': 'text/html' });
        res.end('404 Not Found', 'utf-8');
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
