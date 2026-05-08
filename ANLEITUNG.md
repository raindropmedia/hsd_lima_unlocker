# LiMa – Lernen im Makerspace: Systemübersicht & Anleitung

Das **LiMa-System** ermöglicht die gesicherte, zeitlich befristete Freischaltung von Werkzeugmaschinen im Makerspace der HSD (Hochschule Düsseldorf). Zugang erhalten nur authentifizierte Benutzer – per NFC-Karte oder Login mit optionalem Zweifaktor.

---

## Systemarchitektur

```
┌─────────────────────────────────┐        ┌──────────────────────────────┐
│        LiMa Bridge              │        │        LiMa Server            │
│  Waveshare ESP32-S3 Touch LCD 4 │  HTTPS │  Python / Flask               │
│                                 │◄──────►│  lima.hsd.pub                 │
│  • Touchscreen-GUI (LVGL 9)     │        │                               │
│  • NFC-Karte (PN532, I2C 0x54)  │        │  • REST-API für Bridges       │
│  • Relais / LED (PCF8574T)      │        │  • SQLite-Datenbanken         │
│  • Strommessung (ADS1115)       │        │  • Admin-Dashboard (Web)      │
│  • WLAN (WPA2-PSK / EAP)        │        │  • OTA-Firmware-Server        │
│  • SuperUser-Direktfreischaltung│        │  • Reservierungsverwaltung    │
└─────────────────────────────────┘        └──────────────────────────────┘
                │
                │ steuert
                ▼
      ┌─────────────────┐
      │    Maschine      │
      │  Relais + LEDs   │
      └─────────────────┘
```

---

## Schnellstart

### Voraussetzungen
- ESP-IDF v5.5.3 (für Bridge-Firmware)
- Python 3.9+ mit Flask, pyotp, qrcode (für Server)

### Server starten
```bash
cd LiMa_Server
pip install flask pyotp "qrcode[pil]"
python server.py
# Admin-Dashboard: http://localhost:5555  (Standard-Passwort: L1Ma, überschreibbar via LIMA_ADMIN_PASSWORD)
```

### Bridge flashen
```bash
cd LiMa_Bridge
idf.py set-target esp32s3
idf.py build
idf.py -p /dev/ttyUSB0 flash monitor
```

---

## Ersteinrichtung einer neuen Bridge

1. **Bridge einschalten** → WLAN-Konfigurationsmodal erscheint automatisch (oder PWRKEY drücken)
2. **WLAN konfigurieren**: SSID scannen, Passwort eingeben, „Verbinden" tippen
   - WPA2-PSK (Heimnetz) oder WPA2-Enterprise (eduroam/802.1x) wählbar
3. **Bridge registriert sich** automatisch beim Server (MAC → Token)
4. **Server-Admin** öffnet Dashboard → Bridge-Konfiguration → Maschine konfigurieren:
   - Maschinenname, Standort, Info-URL
   - Freischaltdauer (Min.), OTP-Pflicht, Auto-OTA, Idle-Strom, Idle-Shutdown-Delay
5. **Bridge synchronisiert** Konfiguration beim nächsten Heartbeat (max. 5 Min.; unkonfiguriert: 1 Min.)
6. **Maschinenname und QR-Code** erscheinen auf der Bridge-Startseite

---

## Benutzer anlegen & Karte registrieren

### Im Admin-Dashboard
1. **Users** → Neuer Benutzer → E-Mail, Anzeigename, Passwort eintragen → Speichern
2. Optional: TOTP-Authenticator unter „TOTP einrichten" konfigurieren
3. Optional: **SuperUser**-Flag setzen → NFC-UID dieses Benutzers schaltet ohne Server-Roundtrip direkt frei

### Karte per Bridge registrieren
1. Benutzer meldet sich per Login an der Bridge an (E-Mail + Passwort)
2. Nach erfolgreicher Authentifizierung erscheint „Karte jetzt registrieren"-Button
3. NFC-Karte ans Lesegerät halten → Karte ist dem Konto zugeordnet
4. Ab sofort reicht die Karte zur Authentifizierung

---

## Authentifizierungsablauf

### Variante A: NFC-Karte
```
Karte anlegen → Bridge prüft lokal gegen SuperUser-UIDs
    │
    ├── SuperUser-Treffer → Maschine sofort freigeschaltet ✓ (kein Server nötig)
    │
    └── kein SuperUser → Bridge sendet UID an Server
            │
            ├── OTP nicht erforderlich → Maschine sofort freigeschaltet ✓
            │
            └── OTP erforderlich:
                    TOTP → PIN-Eingabe (Authenticator-App)
                    Mail-OTP → 6-stelliger Code (5 Min. gültig)
                            → PIN-Eingabe → Maschine freigeschaltet ✓
```

### Variante B: Login (E-Mail + Passwort)
```
Login-Button → E-Mail + Passwort eingeben → Server prüft
    │
    ├── OTP nicht erforderlich → Maschine sofort freigeschaltet ✓
    │
    └── OTP erforderlich → gleich wie NFC-Variante oben (TOTP / Mail-OTP)
```

---

## Maschinenfreischaltung

| Zustand | LED | Anzeige |
|---------|-----|---------|
| Gesperrt | Rot | Statusindikator Rot |
| Freigeschaltet | Grün | Statusindikator Grün + Timer |
| Ablauf < 2 Min. | Gelb blinkend | Countdown sichtbar |

- **Timer verlängern**: Auf den Statusindikator tippen (setzt auf Originalzeit zurück)
- **Manuell sperren**: „Zugang entziehen"-Button auf der Startseite
- **Freischaltdauer**: Vom Server vorgegeben (User-Einstellung hat Vorrang vor Bridge-Einstellung, 1–1440 Min.)

### Idle-basiertes Abschalten
Wenn Idle-Erkennung aktiviert ist, schaltet das Relais automatisch ab, sobald nach Timer-Ablauf der gemessene Strom dauerhaft unter die Idle-Schwelle fällt:

1. Freischalt-Timer läuft ab → Relay bleibt noch aktiv (`idle_shutdown_delay_s` Sekunden)
2. Gemessener Strom-RMS bleibt unter `idle_current` (konfigurierbar im Dashboard)
3. Nach Ablauf der Wartezeit → Relais trennt, Anzeige wechselt auf gesperrt

---

## Reservierungen

Maschinenzeiten können im Admin-Dashboard reserviert werden:

1. **Dashboard → Reservierungen** → Neue Reservierung → Bridge wählen, Name, Start, Ende eintragen
2. Bridge zeigt die nächste anstehende Reservierung (innerhalb der nächsten 24 h) als **Banner auf der Startseite** an (aus Heartbeat-Antwort)
3. Laufende Reservierungen erscheinen ebenfalls im Banner

---

## Strommessung & Kalibrierung

### Kontinuierliche Messung
Die Bridge misst fortlaufend den Strom am Maschinenausgang über ADS1115 (RMS, 128 Samples) und überträgt den aktuellen Wert bei jedem Heartbeat zum Server.

### Idle-Strom einmalig messen
1. **PWRKEY** → Board-Status-Modal → Tab **„Bridge"** → „Idle-Strom messen"
2. Messung (~75 ms, 5 Werte, Trimmed Mean)
3. Ergebnis im NVS und beim nächsten Heartbeat auf dem Server gespeichert
4. Admin kann den Wert im Dashboard überschreiben

### Nullpunkt-Kalibrierung
Wenn der Stromsensor einen Offset hat (Anzeige ≠ 0 A bei abgezogenem Gerät):

1. **PWRKEY** → Tab **„Kalibrierung"** → „Nullpunkt kalibrieren"
2. Aktueller Messwert wird als neuer Nullpunkt gespeichert (NVS-Key `zero_cal_mv`, unabhängig von Config-Versionierung)
3. Alle folgenden RMS-Messungen werden relativ zu diesem Nullpunkt berechnet

---

## OTA-Firmware-Update

### Manuell (Admin)
1. Dashboard → OTA-Bereich → `.bin`-Datei hochladen
2. Versionsnummer wird automatisch aus dem Binary gelesen (alternativ manuell eintragen)
3. Bridge bemerkt neue Version beim nächsten OTA-Check und flasht

### Automatisch (auto_ota)
- In der Bridge-Konfiguration `auto_ota` aktivieren
- Bridge prüft nach jedem Heartbeat, ob eine neue Version verfügbar ist
- Bei neuer Version: Automatischer Download und Flash ohne Nutzerinteraktion

---

## Netzwerk & WLAN

Die WLAN-Konfiguration erfolgt vollständig über den Touchscreen:

1. **PWRKEY** → Board-Status-Modal → Tab „Netzwerk" → „WLAN Konfiguration"
2. **Netz scannen** oder SSID manuell eingeben
3. Passwort eingeben
4. **WPA2-Enterprise (EAP)**: Schalter aktivieren → Äußere Identität (`anonymous@…`) und Benutzername eingeben (eduroam-kompatibel)
5. Optional: Statische IP, Gateway, DNS eingeben
6. **„Verbinden"** tippen

Konfiguration wird im NVS gespeichert und übersteht Neustarts.

---

## Bridge-Status einsehen

**PWRKEY** (GPIO 16) → Board-Status-Modal zeigt vier Tabs:

| Tab | Inhalt |
|-----|--------|
| **Netzwerk** | IP-Adresse, SSID, Signal, MAC, Server-Token, WLAN-Konfiguration |
| **Bridge** | Maschinenname, Standort, Config-Version, Idle-Strom-Messung |
| **System** | Firmware-Version, Heap, OTA-Status, Debug-Log-Schalter, OTA-Trigger |
| **Kalibrierung** | Aktueller Nullpunkt, Nullpunkt-Kalibrierung, Live-Strom-Anzeige |

---

## Server-API-Endpunkte (Übersicht)

### Bridge → Server
| Endpunkt | Methode | Funktion |
|----------|---------|----------|
| `/api/hsd/setup` | POST | Erstregistrierung (MAC → Token) |
| `/api/hsd/heartbeat` | POST | Statusbericht + Config-Sync + Reservierung |
| `/api/hsd/nfc` | POST | NFC-UID-Authentifizierung |
| `/api/hsd/login` | POST | E-Mail/Passwort-Login |
| `/api/hsd/login/otp` | POST | OTP-Verifizierung nach Login |
| `/api/hsd/pin` | POST | OTP-Verifizierung nach NFC |
| `/api/hsd/register_card` | POST | NFC-Karte mit Benutzer verknüpfen |
| `/api/hsd/ota/check` | GET | Prüfen ob neue Firmware verfügbar |
| `/api/hsd/ota/firmware` | GET | Firmware-Binary herunterladen |

### Admin-Dashboard
| Endpunkt | Funktion |
|----------|----------|
| `GET /` | Admin-Dashboard (HTML) |
| `GET/POST /api/admin/users/*` | Benutzerverwaltung |
| `GET/POST /api/admin/bridge_config/*` | Bridge-Konfiguration |
| `GET/POST /api/admin/reservations/*` | Reservierungsverwaltung |
| `GET/POST /api/admin/ota/*` | OTA-Firmware hochladen/abfragen |
| `GET/POST /api/admin/totp/*` | TOTP-Setup für Benutzer |
| `GET /api/admin/unlock_log` | Freischaltungs-Protokoll |
| `GET /api/admin/mail` | Mail-OTP-Log |

---

## SuperUser-Konzept

Benutzer mit gesetztem **SuperUser-Flag** (im Admin-Dashboard) werden vom Server per Heartbeat als Liste von NFC-UIDs an alle Bridges übertragen (`superuser_uids`-Feld in der Konfiguration, max. 32 Einträge).

- Legt eine solche NFC-Karte an, erkennt die Bridge den Treffer **lokal** und schaltet sofort frei – **ohne Netzwerkzugriff**
- Nützlich für Notfall-/Admin-Zugang auch bei Serverausfall
- Die Freischaltdauer richtet sich nach der Bridge-Konfiguration des Servers

---

## Datenbankstruktur (Server)

| Datenbank | Tabellen | Inhalt |
|-----------|----------|--------|
| `lima_clients.db` | `clients`, `bridge_config`, `reservations` | Bridge-Tokens, Konfiguration, Reservierungen |
| `lima_users.db` | `users`, `mail_otp_log`, `unlock_log` | Benutzer, NFC-UIDs, TOTP-Secrets, OTP-Logs, Freischaltprotokoll |

---

## Projektverzeichnisse

```
hsd_lima_unlocker/
├── LiMa_Bridge/        # ESP32-S3 Firmware (ESP-IDF v5.5.3, C, LVGL 9)
│   └── README.md       # Technische Firmware-Dokumentation
├── LiMa_Server/        # Flask-Server (Python)
│   └── README.md       # Technische Server-Dokumentation
└── ANLEITUNG.md        # Diese Datei
```
