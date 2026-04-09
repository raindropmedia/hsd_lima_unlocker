# LiMa Bridge – ESP32-S3 Firmware

Firmware für das **LiMa (Lernen im Makerspace) Bridge**-Gerät, das auf einem **Waveshare ESP32-S3 Touch LCD 4** (480×480 Touchscreen) läuft. Es dient als NFC-basiertes Authentifizierungsterminal für Maschinenfreischaltungen an der HSD (Hochschule Düsseldorf).

## Funktionsübersicht

### Authentifizierung
- **NFC-Karte**: PN532-Reader (I2C-Bridge) liest die UID und prüft sie gegen den Server
- **Login**: E-Mail/Passwort-Eingabe über Touchscreen-GUI
- **OTP**: Zweiter Faktor via TOTP (Authenticator-App) oder Mail-OTP (6-stelliger Code)
- **Karten-Registrierung**: Nach erfolgreichem Login kann eine neue NFC-Karte mit dem Benutzerkonto verknüpft werden

### Maschinenfreischaltung
- Zeitlich befristete Freischaltung (Dauer vom Server konfigurierbar)
- Visuelle Statusanzeige: Grün (aktiv), Gelb blinkend (<2 Min.), Rot (gesperrt)
- Freischaltung manuell widerrufbar über Touchscreen
- Timer-Reset per Tap auf den Statusindikator

### Kommunikation
- HTTPS-Verbindung zum LiMa Server (TLS, selbstsigniertes Zertifikat)
- Periodischer Heartbeat (5 Min. konfiguriert / 1 Min. unkonfiguriert)
- Bridge-Konfiguration wird vom Server synchronisiert
- Sofortiger Heartbeat bei Statusänderungen (Freischaltung/Sperrung)

### GUI (LVGL 9)
- **Startseite**: Maschinenname, Standort, QR-Code (Info-URL), Status, NFC-UID, Login-/Revoke-Button
- **PIN-Eingabe**: 6-stelliges Num-Pad für OTP-Codes
- **Ergebnisseite**: Erfolg/Fehler-Anzeige mit Auto-Return (60s) und Karten-Registrierungsoption
- **Modals**: Login-Formular, WLAN-Konfiguration (Scan + manuelle IP), Debug-Overlay

### Hardware
- **WLAN**: WPA2-PSK, DHCP oder statische IP, GUI-basierte Konfiguration
- **Buzzer**: Akustisches Feedback (1× Info, 2× Erfolg, 3× Fehler) über IO-Expander
- **PWRKEY**: Hardware-Button (GPIO 16) öffnet das WLAN-Konfigurationsmodal

## Architektur

```
┌─────────────────────────────────────────────────────┐
│                    app_main()                        │
│  NVS laden → Display init → GUI erstellen → Tasks   │
└──────────────────┬──────────────────┬───────────────┘
                   │                  │
    ┌──────────────▼──────┐  ┌───────▼────────────┐
    │   Auth-Worker-Task  │  │   NFC-Task (Core 0) │
    │      (Core 1)       │  │   PN532 I2C-Polling  │
    │                     │  │                      │
    │  Request-Queue ◄────┼──┤  UID erkannt →       │
    │  ↓                  │  │  AUTH_SRC_NFC oder    │
    │  HTTPS POST an      │  │  AUTH_SRC_REGISTER   │
    │  LiMa Server        │  └──────────────────────┘
    │  ↓                  │
    │  Response-Queue ──► │──► Auth-Result-Timer (LVGL)
    │                     │    ↓
    └─────────────────────┘    show_result_page() /
                               show_view(PIN) /
                               activate_unlock()
```

### Task-Verteilung
| Task | Core | Funktion |
|------|------|----------|
| LVGL (Display) | 1 | GUI-Rendering, Timer-Callbacks |
| Auth-Worker | 1 | HTTPS-Requests, JSON-Parsing |
| NFC-Polling | 0 | PN532-Kommunikation, UID-Erkennung |

### Datenfluss (Authentifizierung)
1. NFC-Karte wird erkannt → `auth_request_t` mit UID in Request-Queue
2. Auth-Worker sendet HTTPS POST an `/api/hsd/nfc`
3. Server prüft UID → Antwort mit `valid`, `pin_required`, `unlock_duration`
4. Auth-Result-Timer wertet Antwort aus:
   - Direkt freigeschaltet → `activate_unlock()` + Ergebnisseite
   - OTP erforderlich → PIN-Eingabeseite
   - Abgelehnt → Fehlermeldung

## Konfiguration

### Build-Einstellungen (`main.c`)
| Define | Default | Beschreibung |
|--------|---------|-------------|
| `ENABLE_NFC` | `0` | `1` = echter PN532, `0` = Sim-Buttons |
| `AUTH_URL_*` | `192.168.0.241:5555` | Server-Endpunkte |
| `DEV_TLS_INSECURE` | `1` | TLS-Zertifikatsprüfung überspringen |
| `HEARTBEAT_INTERVAL_MS` | `300000` (5min) | Heartbeat-Intervall |
| `AUTH_HTTP_RETRY_COUNT` | `2` | HTTP-Retry bei Timeout |

### NVS-Namespaces
| Namespace | Inhalt |
|-----------|--------|
| `wifi_cfg` | SSID, Passwort, IP-Konfiguration |
| `auth_cfg` | Server-Token, MAC-Adresse |
| `bridge_cfg` | Maschinenname, Standort, Config-Version |

## Build

```bash
# ESP-IDF v5.5.3 erforderlich
idf.py set-target esp32s3
idf.py build
idf.py flash monitor
```

## Projektstruktur

```
LiMa_Bridge/
├── main/
│   ├── main.c              # Gesamte Firmware (GUI, NFC, Auth, WLAN)
│   ├── CMakeLists.txt       # Build-Konfiguration
│   └── idf_component.yml   # ESP-IDF Komponenten-Abhängigkeiten
├── managed_components/      # Automatisch verwaltete Abhängigkeiten
│   ├── lvgl__lvgl/          # LVGL 9 Grafikbibliothek
│   ├── waveshare__esp32_s3_touch_lcd_4/  # BSP für Display
│   ├── espressif__esp_lcd_touch_gt911/   # Touch-Controller
│   └── ...
├── partitions.csv           # Flash-Partitionstabelle
├── sdkconfig                # ESP-IDF Konfiguration
└── CMakeLists.txt           # Projekt-CMake
```
