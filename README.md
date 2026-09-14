# AegisChat - Self-Hosted E2EE Web Messenger

AegisChat ist ein minimalistischer, moderner und komplett unbeschränkter Open-Source Web-Messenger mit Ende-zu-Ende-Verschlüsselung (RSA-OAEP 2048-Bit via WebCrypto API).

## Features
- **Zero Server-Side State:** Keine Datenbanken, keine Registrierungsserwer.
- **8-Digit Unique ID System:** Jeder Client erzeugt eine eigene 8-stellige ID.
- **Moderne UI:** Glassmorphism Dark Mode Design.
- **WebCrypto Native:** RSA-OAEP Key-Generation direkt im Browser.

## How to Run
Einfach die Dateien in jedem beliebigen Webserver (Nginx, Caddy, Apache, Proxmox Docker Container, Python Server) bereitstellen:

```bash
python3 -m http.server 8080
```
Öffne anschließend `http://localhost:8080` im Browser.
