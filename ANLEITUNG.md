# LiMa – Lernen im Makerspace: Systemübersicht & Anleitung

Das **LiMa-System** ermöglicht die gesicherte, zeitlich befristete Freischaltung von Werkzeugmaschinen im Makerspace der HSD (Hochschule Düsseldorf). Zugang erhalten nur authentifizierte Benutzer – per NFC-Karte oder Login mit optionalem Zweifaktor.

---

## Systemarchitektur

```
┌─────────────────────────────────┐        ┌──────────────────────────────┐
│        LiMa Bridge              │        │        LiMa Server            │
│  Waveshare ESP32-S3 Touch LCD 4 │  HTTPS │  Python / Flask               │
│                                 │◄──────►│  lima.hsd.pub                 │
│  • Touchscreen-GUI (LVGL)       │        │                               │
│  • NFC-Karte (PN532)            │        │  • REST-API für Bridges       │
│  • Relais / LED (PCF8574T)      │        │  • SQLite-Datenbanken         │
│  • Strommessung (ADS1115)       │        │  • Admin-Dashboard (Web)      │
│  • WLAN (WPA2/EAP)              │        │  • OTA-Firmware-Server        │
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
# Admin-Dashboard: http://localhost:5555
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
3. **Bridge registriert sich** automatisch beim Server (MAC → Token)
4. **Server-Admin** öffnet Dashboard → Bridge-Konfiguration → Maschine konfigurieren:
   - Maschinenname, Standort, Info-URL
   - Freischaltdauer (Min.), OTP-Pflicht, Auto-OTA
5. **Bridge synchronisiert** Konfiguration beim nächsten Heartbeat (max. 1 Min.)
6. **Maschinenname und QR-Code** erscheinen auf der Bridge-Startseite

---

## Benutzer anlegen & Karte registrieren

### Im Admin-Dashboard
1. **Users** → Neuer Benutzer → E-Mail, Anzeigename, Passwort eintragen → Speichern
2. Optional: TOTP-Authenticator unter „TOTP einrichten" konfigurieren

### Karte per Bridge registrieren
1. Benutzer meldet sich per Login an der Bridge an (E-Mail + Passwort)
2. Nach erfolgreicher Authentifizierung erscheint „Karte jetzt registrieren"-Button
3. NFC-Karte ans Lesegerät halten → Karte ist dem Konto zugeordnet
4. Ab sofort reicht die Karte zur Authentifizierung

---

## Authentifizierungsablauf

### Variante A: NFC-Karte
```
Karte anlegen → Bridge sendet UID → Server prüft
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
    └── OTP erforderlich → gleich wie NFC-Variante oben
```

---

## Maschinenfreischaltung

| Zustand | LED | Anzeige |
|---------|-----|---------|
| Gesperrt | Rot | Statusindikator Rot |
| Freigeschaltet | Grün | Statusindikator Grün + Timer |
| Ablauf < 2 Min. | Grün blinkend | Countdown sichtbar |

- **Timer verlängern**: Auf den Statusindikator tippen (setzt auf Originalzeit zurück)
- **Manuell sperren**: „Zugang entziehen"-Button auf der Startseite
- **Freischaltdauer**: Wird vom Server vorgegeben (User-Einstellung hat Vorrang vor Bridge-Einstellung)

---

## Idle-Strom messen

Mit dem integrierten ADS1115-ADC kann der Leerlaufstrom der Maschine gemessen werden:

1. **PWRKEY** drücken → Board-Status-Modal öffnet sich
2. Tab **„Bridge"** wählen
3. **„Idle-Strom messen"** tippen
4. Messung läuft (~75 ms, 5 Messungen, Trimmed Mean)
5. Ergebnis wird angezeigt, im NVS gespeichert und beim nächsten Heartbeat zum Server übertragen
6. **Server-Admin** kann den Wert in der Bridge-Konfiguration auch manuell überschreiben

---

## OTA-Firmware-Update

### Manuell (Admin)
1. Dashboard → OTA-Bereich → `.bin`-Datei hochladen
2. Versionsnummer wird automatisch aus dem Binary gelesen
3. Bridge bemerkt neue Version beim nächsten OTA-Check und flasht

### Automatisch (auto_ota)
- In der Bridge-Konfiguration `auto_ota` aktivieren
- Bridge prüft nach jedem Heartbeat ob eine neue Version verfügbar ist
- Bei neuer Version: Automatischer Download und Flash ohne Nutzerinteraktion

---

## Netzwerk & WLAN

Die WLAN-Konfiguration erfolgt vollständig über den Touchscreen:

1. **PWRKEY** drücken → Board-Status-Modal → Tab „Netzwerk" → „WLAN Konfiguration"
2. **Netz scannen** oder SSID manuell eingeben
3. Passwort eingeben (WPA2-PSK oder Enterprise/EAP)
4. Optional: Statische IP, Gateway, DNS eingeben
5. **„Verbinden"** tippen

Konfiguration wird im NVS gespeichert und übersteht Neustarts.

---

## Bridge-Status einsehen

**PWRKEY** → Board-Status-Modal zeigt drei Tabs:

| Tab | Inhalt |
|-----|--------|
| **Netzwerk** | IP-Adresse, SSID, Signal, MAC, Server-Token |
| **Bridge** | Maschinenname, Standort, Config-Version, Idle-Strom-Messung |
| **System** | Firmware-Version, Heap, OTA-Status, Debug-Log-Schalter |

---

## Projektverzeichnisse

```
hsd_lima_unlocker/
├── LiMa_Bridge/        # ESP32-S3 Firmware (ESP-IDF, C, LVGL)
│   └── README.md       # Technische Firmware-Dokumentation
├── LiMa_Server/        # Flask-Server (Python)
│   └── README.md       # Technische Server-Dokumentation
└── ANLEITUNG.md        # Diese Datei
```
