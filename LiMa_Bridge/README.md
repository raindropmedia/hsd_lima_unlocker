# LiMa Bridge – ESP32-S3 Firmware

**Version 1.0.3**

Firmware für das **LiMa (Lernen im Makerspace) Bridge**-Gerät, das auf einem **Waveshare ESP32-S3 Touch LCD 4** (480×480 Touchscreen) läuft. Es dient als NFC-basiertes Authentifizierungsterminal für Maschinenfreischaltungen an der HSD (Hochschule Düsseldorf).

## Funktionsübersicht

### Authentifizierung
- **NFC-Karte**: PN532-Reader (I2C) liest die UID und prüft sie gegen den Server
- **Login**: E-Mail/Passwort-Eingabe über Touchscreen-GUI
- **OTP**: Zweiter Faktor via TOTP (Authenticator-App) oder Mail-OTP (6-stelliger Code)
- **Karten-Registrierung**: Nach erfolgreichem Login kann eine neue NFC-Karte mit dem Benutzerkonto verknüpft werden

### Maschinenfreischaltung
- Zeitlich befristete Freischaltung (Dauer vom Server konfigurierbar, 1–1440 Min.)
- Visuelle Statusanzeige: Grün (aktiv), Gelb blinkend (<2 Min.), Rot (gesperrt)
- Freischaltung manuell widerrufbar über Touchscreen
- Timer-Reset per Tap auf den Statusindikator

### Kommunikation
- HTTPS-Verbindung zum LiMa Server (`lima.hsd.pub`) mit Let's-Encrypt-Zertifikat
- Periodischer Heartbeat (5 Min. konfiguriert / 1 Min. unkonfiguriert)
- Bridge-Konfiguration (Name, Standort, Idle-Strom, OTP-Pflicht etc.) wird vom Server synchronisiert (Config-Versioning)
- Sofortiger Heartbeat nach Idle-Strommessung oder Statusänderungen
- OTA-Firmware-Updates (manuell und automatisch per `auto_ota`-Flag)

### Sensorik & Peripherie
- **ADS1115** (I2C, 0x48): 16-Bit ADC, 4 Kanäle – Strommessung am Maschinenausgang
- **PCF8574T** (I2C, 0x20): 8-Bit I/O-Expander – Rote/Grüne LED, Relais (P0–P3), digitale Eingänge (P4–P7)
- **Idle-Strom-Messung**: 5-fach Messung mit Trimmed Mean, Ergebnis in mV, wird per Heartbeat zum Server übertragen und im NVS persistent gespeichert

### GUI (LVGL 9)
- **Startseite**: Maschinenname, Standort, QR-Code (Info-URL), Freischalt-Status, NFC-UID, Login-/Revoke-Button
- **PIN-Eingabe**: 6-stelliges Num-Pad für OTP-Codes
- **Ergebnisseite**: Erfolg/Fehler-Anzeige mit Auto-Return (60 s) und Karten-Registrierungsoption
- **Board-Status-Modal** (PWRKEY): Tab-basierte Übersicht – Netzwerk, Bridge, System/Debug; enthält WLAN-Konfiguration und Idle-Strom-Messung
- **Login-Modal**: E-Mail/Passwort-Formular mit WLAN-Keyboard
- **Debug-Overlay**: Schalter für Log-Label, OTA-Trigger-Button

### Netzwerk
- **WLAN**: WPA2-PSK, WPA2-Enterprise (EAP), DHCP oder statische IP
- Konfiguration vollständig über Touchscreen-GUI (Netzwerk-Scan, manuelle Eingabe)
- **PWRKEY** (GPIO 16): Hardware-Button öffnet das Board-Status-Modal

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

    Idle-Strom-Messung (bei Bedarf):
    measure_idle_current_event_cb → idle_measure_task (Core 1)
      → ADS1115 ch0, 5× Single-Shot → Trimmed Mean → mV
      → s_bridge_cfg.idle_current (NVS) + Heartbeat-Payload
```

### Task-Verteilung
| Task | Core | Funktion |
|------|------|----------|
| LVGL / Display | 1 | GUI-Rendering, Timer-Callbacks |
| Auth-Worker | 1 | HTTPS-Requests, JSON-Parsing, Config-Sync |
| NFC-Polling | 0 | PN532-Kommunikation, UID-Erkennung |
| Idle-Measure (einmalig) | 1 | ADS1115-Messung, NVS-Speicherung |
| OTA-Task (einmalig) | 1 | Firmware-Download und Flash |

### Datenfluss (Authentifizierung)
1. NFC-Karte erkannt → `auth_request_t` mit UID in Request-Queue
2. Auth-Worker → HTTPS POST `/api/hsd/nfc`
3. Server antwortet mit `valid`, `pin_required`, `unlock_duration`
4. Auth-Result-Timer:
   - Direkt freigeschaltet → `activate_unlock()` + Ergebnisseite
   - OTP erforderlich → PIN-Eingabeseite
   - Abgelehnt → Fehlermeldung

### Datenfluss (Idle-Strom)
1. Nutzer tippt „Idle-Strom messen" im Bridge-Tab
2. `idle_measure_task` misst 5× ADS1115 ch0, berechnet Trimmed Mean
3. Ergebnis → `s_bridge_cfg.idle_current` (NVS-Persist) + `s_idle_current_measured_mV`
4. Nächster Heartbeat enthält `"idle_current_mV": <Wert>`
5. Server speichert Wert in `bridge_config.idle_current`
6. Beim Config-Sync (Admin-Änderung) überschreibt Server-Wert den lokalen Wert

## Konfiguration

### Build-Einstellungen (`main.c`)
| Define | Wert | Beschreibung |
|--------|------|-------------|
| `ENABLE_NFC` | `1` | `1` = echter PN532, `0` = Sim-Buttons |
| `AUTH_URL_*` | `lima.hsd.pub` | Server-Endpunkte (HTTPS) |
| `DEV_TLS_INSECURE` | `0` | `0` = echte TLS-Prüfung (Let's Encrypt) |
| `HEARTBEAT_INTERVAL_MS` | `300000` (5 Min.) | Heartbeat-Intervall konfiguriert |
| `HEARTBEAT_INTERVAL_UNCONFIGURED_MS` | `60000` (1 Min.) | Heartbeat-Intervall unkonfiguriert |
| `AUTH_HTTP_RETRY_COUNT` | `2` | Retries bei HTTP-Timeout |
| `IDLE_MEASURE_SAMPLES` | `5` | ADS1115-Messwiederholungen (Trimmed Mean) |

### NVS-Namespaces
| Namespace | Version | Inhalt |
|-----------|---------|--------|
| `wifi_cfg` | 2 | SSID, Passwort, IP-Konfiguration, EAP |
| `auth_cfg` | 1 | Server-Token, MAC-Adresse |
| `bridge_cfg` | 2 | Maschinenname, Standort, Idle-Strom, Config-Version |

## Build

```bash
# ESP-IDF v5.5.3 erforderlich
idf.py set-target esp32s3
idf.py build
idf.py -p /dev/ttyUSB0 flash monitor
```

### Abhängigkeiten (managed_components)
| Komponente | Funktion |
|-----------|---------|
| `lvgl__lvgl` | LVGL 9 Grafikbibliothek |
| `waveshare__esp32_s3_touch_lcd_4` | BSP für Waveshare-Display |
| `espressif__esp_lcd_touch_gt911` | GT911 Touch-Controller |
| `espressif__esp_lvgl_port` | LVGL/BSP-Integration |
| `espressif__esp_io_expander` | CH32V003 I/O-Expander |

## Projektstruktur

```
LiMa_Bridge/
├── main/
│   ├── main.c              # Gesamte Firmware (GUI, NFC, Auth, WLAN, Sensoren)
│   ├── CMakeLists.txt      # Build-Konfiguration
│   └── idf_component.yml  # ESP-IDF Komponenten-Abhängigkeiten
├── managed_components/     # Automatisch verwaltete Abhängigkeiten
├── partitions.csv          # Flash-Partitionstabelle (OTA + NVS)
├── sdkconfig               # ESP-IDF Konfiguration
└── CMakeLists.txt          # Projekt-CMake (Version: PROJECT_VER)
```
