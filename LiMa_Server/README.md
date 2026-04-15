# LiMa Server – Flask Authentifizierungs-Backend

Flask-basierter Server für das **LiMa (Lernen im Makerspace)**-System. Verwaltet Bridge-Geräte (ESP32), Benutzer und Maschinenfreischaltungen. Stellt eine REST-API für die ESP32-Firmware und ein Admin-Dashboard bereit.

## Funktionsübersicht

### Bridge-Verwaltung
- **Geräteregistrierung**: ESP32 meldet sich per MAC-Adresse an, erhält einen Token
- **Heartbeat**: Periodischer Statusbericht (Unlock-Status, Config-Sync, Sensor-Rohwerte, Idle-Strom in mV)
- **Bridge-Konfiguration**: Maschinenname, Standort, Idle-Strom, Sound, OTP-Pflicht, Freischaltzeit, Info-URL

### Benutzer-Authentifizierung
- **NFC-Karte**: UID-basierte Identifikation (8 oder 14 Hex-Zeichen)
- **Login**: E-Mail + Passwort (lokal oder OpenID-Forward)
- **OTP (2FA)**:
  - **TOTP**: Authenticator-App (Google Authenticator, etc.)
  - **Mail-OTP**: 6-stelliger Code per simulierter E-Mail (5 Min. gültig)
- **Karten-Registrierung**: Benutzer kann NFC-Karte selbst mit seinem Konto verknüpfen

### Maschinenfreischaltung
- Zeitlich befristete Freischaltung (User-spezifisch → Bridge-Konfiguration → 30 Min. Default)
- Freischaltdauer: 1–1440 Minuten (beide Ebenen gecappt)
- Jede Freischaltung wird im Audit-Log protokolliert (User, Methode, Maschine, Zeitpunkt)
- Status-Tracking über Heartbeat (locked/unlocked + verbleibende Minuten)

### Idle-Strom-Messung
- Die Bridge misst per ADS1115 den Leerlaufstrom und sendet `idle_current_mV` im Heartbeat
- Der Server speichert den Wert in `bridge_config.idle_current` (überschreibt Admin-Wert)
- Admin kann den Schwellwert manuell setzen; beim nächsten Config-Sync wird er zur Bridge übertragen

### Admin-Dashboard
- Einseiten-HTML-App mit JavaScript (keine externen Frameworks)
- Echtzeit-Verwaltung: Benutzer, Clients, Bridge-Konfigurationen
- Tabellen mit farbcodierten Statusanzeigen (Heartbeat, Freigabe)
- OTP-Setup/Entfernung mit QR-Code-Anzeige
- Unlock-Log und Mail-OTP-Log
- OTA-Firmware-Upload (.bin) mit automatischer Versionskennung aus dem Binary

## API-Endpunkte

### Bridge → Server (von der ESP32-Firmware aufgerufen)

| Methode | Endpunkt | Beschreibung |
|---------|----------|-------------|
| POST | `/api/hsd/setup` | Erstregistrierung (MAC → Token) |
| POST | `/api/hsd/heartbeat` | Statusbericht + Config-Sync + Idle-Strom |
| POST | `/api/hsd/nfc` | NFC-UID-Authentifizierung |
| POST | `/api/hsd/login` | E-Mail/Passwort-Login |
| POST | `/api/hsd/login/otp` | OTP-Verifikation nach Login |
| POST | `/api/hsd/pin` | OTP-Verifikation nach NFC |
| POST | `/api/hsd/register_card` | NFC-Karte registrieren |
| POST | `/api/hsd/ping` | Token-Validierung |
| GET | `/api/hsd/ota/check` | Prüft ob neue Firmware verfügbar |
| GET | `/api/hsd/ota/firmware` | Liefert Firmware-Binary |

### Admin-Dashboard

| Methode | Endpunkt | Beschreibung |
|---------|----------|-------------|
| GET | `/` | Dashboard (HTML) |
| GET | `/api/admin/users` | Alle Benutzer |
| POST | `/api/admin/users/save` | Benutzer anlegen/bearbeiten |
| POST | `/api/admin/users/delete` | Benutzer löschen |
| GET | `/api/admin/clients` | Alle Clients |
| POST | `/api/admin/clients/save` | Client bearbeiten |
| GET | `/api/admin/bridge_config` | Bridge-Konfigurationen |
| POST | `/api/admin/bridge_config/save` | Bridge-Konfiguration speichern |
| POST | `/api/admin/bridge_config/delete` | Bridge-Konfiguration löschen |
| GET | `/api/admin/unlock_log` | Freischaltungs-Protokoll |
| GET | `/api/admin/mail` | Mail-OTP-Log |
| POST | `/api/admin/mail/send` | Mail-OTP manuell auslösen |
| POST | `/api/admin/totp/setup` | TOTP-Secret generieren |
| POST | `/api/admin/totp/confirm` | TOTP mit Code bestätigen |
| POST | `/api/admin/totp/remove` | TOTP entfernen |
| POST | `/api/admin/ota/upload` | Firmware hochladen |
| GET | `/api/admin/ota/info` | Aktuelle Firmware-Info |

## Authentifizierungsfluss

```
NFC-Karte anlegen                    Login-Formular
       │                                   │
       ▼                                   ▼
  POST /nfc                          POST /login
  {token, uid}                       {token, email, password}
       │                                   │
       ▼                                   ▼
  UID → User-Lookup                  Passwort prüfen
       │                             (lokal oder OpenID)
       ▼                                   │
  ┌─── OTP erforderlich? ◄────────────────┘
  │         │
  │ nein    │ ja
  │         ▼
  │    {valid:true, pin_required:true}
  │    → ESP zeigt PIN-Eingabe
  │         │
  │         ▼
  │    POST /pin oder /login/otp {token, pin/otp}
  │    → TOTP oder Mail-OTP prüfen
  │         │
  ▼         ▼
  {valid:true, unlock_duration:N}
  → ESP aktiviert Freischaltung für N Minuten
```

## Bridge-Konfiguration (Felder & Limits)

| Feld | Typ | Beschreibung | Limit |
|------|-----|-------------|-------|
| `machine_name` | Text | Anzeigename der Maschine | 63 Zeichen |
| `location` | Text | Standort der Maschine | 63 Zeichen |
| `idle_current` | Float | Idle-Strom-Schwellwert / Messwert (mV) | – |
| `info_url` | Text | URL für QR-Code auf der Startseite | 127 Zeichen |
| `unlock_duration` | Int | Standard-Freischaltdauer in Minuten | 1–1440 |
| `otp_required` | Bool | Zweiter Faktor nach NFC/Login | – |
| `sound_enabled` | Bool | Akustisches Feedback | – |
| `idle_detection_enabled` | Bool | Idle-Erkennung per Stromsensor | – |
| `auto_ota` | Bool | Automatisches Firmware-Update | – |

## Datenbanken

### lima_clients.db
| Tabelle | Beschreibung |
|---------|-------------|
| `clients` | Bridge-Tokens, MAC, OTP-Status, User-Binding |
| `bridge_config` | Maschinenkonfiguration, Heartbeat-Status, ADS1115/PCF-Rohwerte |

### lima_users.db
| Tabelle | Beschreibung |
|---------|-------------|
| `users` | E-Mail, Name, Passwort-Hash, NFC-UID, OTP-Secret, individuelle Freischaltdauer |
| `mail_otp_log` | Protokoll aller generierten Mail-OTPs |
| `unlock_log` | Audit-Log: Wer hat wann welche Maschine freigeschaltet |

## Sicherheit

- **Passwort-Hashing**: PBKDF2-SHA256 mit 120.000 Iterationen und zufälligem Salt
- **Token**: 24 Byte `secrets.token_urlsafe` (192 Bit Entropie)
- **OTP-Codes**: 6-stellig, SHA-256-gehasht gespeichert, zeitlich begrenzt, einmalig verwendbar
- **Timing-safe**: `secrets.compare_digest` für alle sensitiven Vergleiche
- **Eingabelimits**: Alle Felder serverseitig auf ESP32-Puffergröße gecappt
- **UNIQUE-Constraints**: NFC-UIDs und E-Mails sind eindeutig pro Benutzer

## Installation & Start

```bash
# Abhängigkeiten
pip install flask pyotp qrcode[pil]

# Server starten
cd LiMa_Server
python server.py
# → http://localhost:5555
```

### Umgebungsvariablen
| Variable | Beschreibung |
|----------|-------------|
| `OPENID_FORWARD_URL` | Optional: URL für OpenID-Authentifizierungs-Delegation |

## Projektstruktur

```
LiMa_Server/
├── server.py           # Gesamter Server (API + Dashboard + DB-Init)
├── lima_clients.db     # Client/Bridge-Datenbank (auto-erstellt)
├── lima_users.db       # Benutzer-Datenbank (auto-erstellt)
└── ota_firmware/       # OTA-Verzeichnis (auto-erstellt)
    ├── firmware.bin    # Aktuelle Firmware
    └── version.txt     # Versionsnummer der gespeicherten Firmware
```

## Funktionsübersicht

### Bridge-Verwaltung
- **Geräteregistrierung**: ESP32 meldet sich per MAC-Adresse an, erhält einen Token
- **Heartbeat**: Periodischer Statusbericht (Unlock-Status, Config-Sync)
- **Bridge-Konfiguration**: Maschinenname, Standort, Idle-Strom, Sound, OTP-Pflicht, Freischaltzeit, Info-URL

### Benutzer-Authentifizierung
- **NFC-Karte**: UID-basierte Identifikation (8 oder 14 Hex-Zeichen)
- **Login**: E-Mail + Passwort (lokal oder OpenID-Forward)
- **OTP (2FA)**:
  - **TOTP**: Authenticator-App (Google Authenticator, etc.)
  - **Mail-OTP**: 6-stelliger Code per simulierter E-Mail (5 Min. gültig)
- **Karten-Registrierung**: Benutzer kann NFC-Karte selbst mit seinem Konto verknüpfen

### Maschinenfreischaltung
- Zeitlich befristete Freischaltung (User-spezifisch → Bridge-Konfiguration → 30 Min. Default)
- Jede Freischaltung wird im Audit-Log protokolliert (User, Methode, Maschine, Zeitpunkt)
- Status-Tracking über Heartbeat (locked/unlocked + verbleibende Minuten)

### Admin-Dashboard
- Einseiten-HTML-App mit JavaScript (keine externen Frameworks)
- Echtzeit-Verwaltung: Benutzer, Clients, Bridge-Konfigurationen
- Tabellen mit farbcodierten Statusanzeigen (Heartbeat, Freigabe)
- OTP-Setup/Entfernung mit QR-Code-Anzeige
- Unlock-Log und Mail-OTP-Log

## API-Endpunkte

### Bridge → Server (von der ESP32-Firmware aufgerufen)

| Methode | Endpunkt | Beschreibung |
|---------|----------|-------------|
| POST | `/api/hsd/setup` | Erstregistrierung (MAC → Token) |
| POST | `/api/hsd/heartbeat` | Statusbericht + Config-Sync |
| POST | `/api/hsd/nfc` | NFC-UID-Authentifizierung |
| POST | `/api/hsd/login` | E-Mail/Passwort-Login |
| POST | `/api/hsd/pin` | OTP-Verifikation (TOTP/Mail) |
| POST | `/api/hsd/register_card` | NFC-Karte registrieren |
| POST | `/api/hsd/ping` | Token-Validierung |

### Admin-Dashboard

| Methode | Endpunkt | Beschreibung |
|---------|----------|-------------|
| GET | `/` | Dashboard (HTML) |
| GET | `/api/admin/users` | Alle Benutzer |
| POST | `/api/admin/users/save` | Benutzer anlegen/bearbeiten |
| POST | `/api/admin/users/delete` | Benutzer löschen |
| GET | `/api/admin/clients` | Alle Clients |
| POST | `/api/admin/clients/save` | Client bearbeiten |
| GET | `/api/admin/bridge_config` | Bridge-Konfigurationen |
| POST | `/api/admin/bridge_config/save` | Bridge-Konfiguration speichern |
| GET | `/api/admin/unlock_log` | Freischaltungs-Protokoll |
| GET | `/api/admin/mail` | Mail-OTP-Log |
| POST | `/api/admin/totp/setup` | TOTP-Secret generieren |
| POST | `/api/admin/totp/confirm` | TOTP mit Code bestätigen |
| POST | `/api/admin/totp/remove` | TOTP entfernen |

## Authentifizierungsfluss

```
NFC-Karte anlegen                    Login-Formular
       │                                   │
       ▼                                   ▼
  POST /nfc                          POST /login
  {token, uid}                       {token, email, password}
       │                                   │
       ▼                                   ▼
  UID → User-Lookup                  Passwort prüfen
       │                             (lokal oder OpenID)
       ▼                                   │
  ┌─── OTP erforderlich? ◄────────────────┘
  │         │
  │ nein    │ ja
  │         ▼
  │    {valid:true, pin_required:true}
  │    → ESP zeigt PIN-Eingabe
  │         │
  │         ▼
  │    POST /pin {token, pin}
  │    → TOTP oder Mail-OTP prüfen
  │         │
  ▼         ▼
  {valid:true, unlock_duration:N}
  → ESP aktiviert Freischaltung für N Minuten
```

## Datenbanken

### lima_clients.db
| Tabelle | Beschreibung |
|---------|-------------|
| `clients` | Bridge-Tokens, MAC, OTP-Status, User-Binding |
| `bridge_config` | Maschinenkonfiguration je MAC-Adresse |

### lima_users.db
| Tabelle | Beschreibung |
|---------|-------------|
| `users` | E-Mail, Name, Passwort-Hash, NFC-UID, OTP-Secret |
| `mail_otp_log` | Protokoll aller generierten Mail-OTPs |
| `unlock_log` | Audit-Log: Wer hat wann welche Maschine freigeschaltet |

## Sicherheit

- **Passwort-Hashing**: PBKDF2-SHA256 mit 120.000 Iterationen und zufälligem Salt
- **Token**: 24 Byte `secrets.token_urlsafe` (192 Bit Entropie)
- **OTP-Codes**: 6-stellig, SHA-256-gehasht gespeichert, zeitlich begrenzt
- **TLS**: HTTPS-Only (selbstsigniertes Zertifikat für Entwicklung)
- **UNIQUE-Constraints**: NFC-UIDs und E-Mails sind eindeutig pro Benutzer
- **Timing-safe Vergleiche**: `secrets.compare_digest` für sensitive Werte

## Installation & Start

```bash
# Abhängigkeiten
pip install flask pyotp qrcode

# TLS-Zertifikat (wird beim ersten Start automatisch generiert falls fehlend)
# Oder manuell: openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.crt -days 365 -nodes

# Server starten
cd LiMa_Server
python server.py
# → https://localhost:5555
```

### Umgebungsvariablen
| Variable | Beschreibung |
|----------|-------------|
| `OPENID_FORWARD_URL` | Optional: URL für OpenID-Authentifizierung |

## Projektstruktur

```
LiMa_Server/
├── server.py           # Gesamter Server (API + Dashboard + DB)
├── server.crt          # TLS-Zertifikat (auto-generiert)
├── server.key          # TLS-Schlüssel (auto-generiert)
├── lima_clients.db     # Client/Bridge-Datenbank (auto-erstellt)
└── lima_users.db       # Benutzer-Datenbank (auto-erstellt)
```
