# Aegis Chat

Aegis Chat ist eine auf maximale Privatsphäre ausgelegte Kommunikationsplattform. Das System arbeitet nach dem Minimal-Data-Prinzip: Keine Nachrichten werden dauerhaft auf Servern verbleibend gespeichert, Metadaten werden minimiert und alle Chat-Inhalte sind durchgehend Ende-zu-Ende verschlüsselt.

---

## 🔒 Sicherheitskonzept im Detail

### 1. Ablauf der Ende-zu-Ende-Verschlüsselung (E2EE)

Der Klartext sowie die privaten Schlüssel verlassen zu keinem Zeitpunkt das Endgerät. Der Server verarbeitet ausschließlich unlesbaren Geheimtext (Ciphertext).
* Zero-Knowledge-Prinzip: Nachrichten, Sprachnachrichten und Anhänge werden direkt auf dem Endgerät des Absenders verschlüsselt und erst auf dem Gerät des Empfängers wieder entschlüsselt.
 * Client-Side Key Generation: Die kryptografischen Schlüsselpaare werden lokal im Browser/Gerät generiert. Private Keys verbleiben ausschließlich im lokalen Speicher des Nutzers.
 * Unlesbarkeit für Dritte: Der Server fungiert als reiner Relais-Knotenpunkt. Weder Betreiber noch Dritte haben Zugriff auf den Klartext der übertragenen Daten.

```text
[ Absender (Gerät A) ]                                [ Server / Relais ]                               [ Empfänger (Gerät B) ]
         │                                                      │                                                  │
 1. Generiert Nachricht (Klartext)                              │                                                  │
         │                                                      │                                                  │
 2. Liest Öffentlichen Schlüssel von B ─────────────────────────┼─────────────────────────────────────────► Liest Öffentlichen Schlüssel
         │                                                      │                                                  │
 3. Verschlüsselt lokal:                                        │                                                  │
    Klartext + Public Key B                                     │                                                  │
    └─► Erzeugt Ciphertext                                      │                                                  │
         │                                                      │                                                  │
 4. Sendet Ciphertext ─────────────────────────────────────────►│                                                  │
                                                                │ 5. Leitet Ciphertext weiter                      │
                                                                ├─────────────────────────────────────────────────►│
                                                                                                                   │
                                                                                                           6. Empfängt Ciphertext
                                                                                                                   │
                                                                                                           7. Entschlüsselt lokal:
                                                                                                              Ciphertext + Private Key B
                                                                                                              └─► Liest Klartext




```

### 2. Tägliche Datenbereinigung (Automatischer 23:59 Wipe)
Unabhängig vom Onlinestatus der Beteiligten wird die Datenbank täglich um 23:59 Uhr (Europe/Berlin) bereinigt.

```
  [ Aktiver Chat-Betrieb ]
          │
          ▼
  23:50 Uhr: Lokale Warnmeldung im Client ("Nachrichten werden um 23:59 Uhr gelöscht")
          │
          ▼
  23:59 Uhr: Automatischer Purge-Befehl
          │
          ├───────────────────────────┐
          ▼                           ▼
[ Server-Datenbank ]         [ Lokaler Client-Cache ]
  └─► Nachrichten löschen      └─► UI-State zurücksetzen
```

 * Ephemerer Chatverlauf: Um 23:59 Uhr werden ausnahmslos alle ausgetauschten Nachrichten und Medien serverseitig unwiderruflich gelöscht.
 * Keine Server-Backups: Es existieren keine verdeckten Backups oder Historien gelöschter Chatverläufe.

### 3. Sichere Direktverbindungen (WebRTC Audio/Video)
 * Verschlüsselte Anrufe: Sprach- und Videoanrufe werden über abhörsichere, verschlüsselte Peer-to-Peer-Protokolle (DTLS/SRTP) direkt zwischen den Teilnehmern aufgebaut.
 * Keine Medienaufzeichnung: Während eines Anrufs fließen Audiodaten direkt zwischen den Geräten und werden zu keinem Zeitpunkt zwischengespeichert oder aufgezeichnet.
### 4. Einmalmedien (View-Once) & Selbstzerstörung
 * Medien können als Einmalmedium gesendet werden. Nach dem ersten Öffnen durch den Empfänger wird der Inhalt sofort auf den Clients und dem Relais gelöscht.
### 5. Anonymität & Metadaten-Minimalismus
 * Keine Pflicht zur Angabe persönlicher Klarnamen oder Verknüpfung mit Telefonnummern.
 * Minimale Protokollierung von Verbindungsdaten zur Reduzierung digitaler Fußabdrücke.
### 🚀 Kernfunktionen
 * Abhörsichere Chats: Text- und Sprachnachrichten mit E2EE.
 * P2P Audio- & Videoanrufe: Direktverbindung in HD-Qualität.
 * View-Once Medien: Bilder & Videos, die nach dem Betrachten verschwinden.
 * Automatischer Mitternachts-Reset: Täglicher Wipe aller Chathistorien um 23:59 Uhr.
 * Push-Benachrichtigungen: Benachrichtigungen über eingehende Anrufe und Nachrichten bei geschlossener App.

### 📄 Lizenz
Dieses Projekt ist unter der Open-Source-Lizenz veröffentlicht.

