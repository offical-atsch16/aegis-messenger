# AegisChat - E2EE Web Messenger mit Supabase & Burner IDs

AegisChat ist ein minimalistischer, moderner und quelloffener Web-Messenger mit 100% clientseitiger Ende-zu-Ende-Verschlüsselung (ECDH P-256 & AES-GCM via WebCrypto API) und Supabase als Backend für Authentifizierung, Kontaktdatenbank und Realtime-Messaging.

## Features
- **100% Anonyme Auth via Supabase:** Nutzername + Passwort. Keine E-Mails oder Telefonnummern verlangt.
- **Feste 8-Stellige Haupt-ID:** Automatische Zuweisung einer eindeutigen Haupt-ID bei Registrierung.
- **Temporäre Einweg-Nummern (Burner IDs):** Erstelle beliebige Burner IDs mit optionalem Ablaufdatum (1h, 24h, 7d, unbegrenzt). Eingehende Nachrichten werden empfangen, ohne dass die Gegenpartei deine echte Haupt-ID sieht.
- **Key Wrapping & Key Protection:** Private Keys werden NIE unverschlüsselt übertragen oder gespeichert. Lokale PBKDF2 (100.000 Iterationen) + AES-GCM Verschlüsselung des Private Keys clientseitig.
- **Supabase Realtime Messaging:** Nachrichtenübertragung via Supabase Realtime WebSockets.
- **QR-Code Support:** Einfaches Teilen und Scannen der IDs per Kamera oder Bild.
- **Branding Footer:** "Made with ❤️ by official-atsch16" (Link zu https://github.com/official-atsch16).

## Supabase Database Setup

1. Erstelle ein neues Projekt auf [Supabase](https://supabase.com).
2. Gehe in deinem Supabase Dashboard zum **SQL Editor**.
3. Führe den Inhalt der Datei `schema.sql` aus.
4. Aktiviere in Supabase unter **Database > Realtime** die Echtzeitübertragung für die Tabelle `messages`.
5. Öffne AegisChat im Browser, klicke auf **Supabase Config** und trage deine **Supabase Project URL** und deinen **Anon Key** ein.

## Lokaler Aufruf / Deployment

Da AegisChat eine reine Frontend-Anwendung ist (mit optionalem lokalen HTTP-Server), kann sie einfach mit Node.js gestartet werden:

```bash
node server.js
```
Öffne anschließend `http://localhost:8080` im Browser.
