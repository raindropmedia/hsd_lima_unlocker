# LiMa Bridge – ESP32-S3 Firmware

**Version 1.0.8** – spricht mit dem **LiMa Server** (`LiMa_Server`, Doku: `LiMa_Server docs/SERVER.md`) über fünf Endpunkte, siehe [Server-API](#server-api). Offene Punkte stehen unter [Bekannte Probleme](#bekannte-probleme--work-in-progress).

Firmware für das **LiMa (Lernen im Makerspace) Bridge**-Gerät, das auf einem **Waveshare ESP32-S3 Touch LCD 4** (480×480 Touchscreen) läuft. Es dient als NFC-basiertes Authentifizierungsterminal für Maschinenfreischaltungen an der HSD (Hochschule Düsseldorf).

## Funktionsübersicht

### Authentifizierung
- **NFC-Karte / Button**: PN532-Reader (I2C, Adresse 0x54) liest die UID, oder der Start-Button löst die Authentifizierung über die MAC-Adresse aus
- **SuperUser**: Bis zu 32 NFC-UIDs können serverseitig als SuperUser hinterlegt werden – diese schalten die Maschine direkt ohne Netzwerk-Roundtrip frei
- **Activation-Flow**: Karte/Button → Gerät fragt `POST /activations` mit `card_id`, `device_id` und **`resource_id`** an → Server liefert eine Freigabe-URL (+ Ablaufzeit) → Bridge zeigt QR-Code/URL an, Nutzer meldet sich im Browser an (Microsoft Entra ID) → Bridge pollt `GET /activations/decision/<code>` alle 1,5 s bis Freigabe (200), Ablehnung (403) oder Ablauf (404)
- **Karten-Registrierung**: Weiterhin im Code vorhanden, aber vom Start-Button aus aktuell nicht mehr erreichbar (siehe unten)

> ⚠️ Der frühere Login-/OTP-Flow (E-Mail/Passwort-Modal, TOTP/Mail-OTP, direkte NFC-Prüfung gegen `/api/hsd/nfc`) ist im Code noch vorhanden, aber **nicht mehr über die GUI erreichbar**.

### Maschinenfreischaltung
- Zeitlich befristete Freischaltung: Die Dauer ist die **Restzeit der Buchung** (`remaining_ms` aus der Freigabe-Antwort, begrenzt auf 1–1440 Min.). Fehlt der Wert, gilt die konfigurierte `unlock_duration`
- Visuelle Statusanzeige: Grün (aktiv), Gelb blinkend (<2 Min.), Rot (gesperrt)
- Freischaltung manuell widerrufbar über Touchscreen
- Timer-Reset per Tap auf den Statusindikator
- **Idle-basiertes Abschalten**: Wenn nach Timer-Ablauf der gemessene Strom unter die konfigurierte Idle-Schwelle fällt und dort bleibt (Wartezeit `idle_shutdown_delay_s`), schaltet das Relais automatisch ab

### Kommunikation
- **Server-Endpunkte** (`AUTH_URL_*`): HTTPS zu `lima.intern.hs-duesseldorf.de`, authentifiziert per festem Bearer-Token (`BRIDGE_API_TOKEN`) – siehe [Server-API](#server-api)
- **OTA-Endpunkte** (`OTA_URL_CHECK`/`OTA_URL_FIRMWARE`) weiterhin HTTPS zu `lima.hsd.pub` mit Let's-Encrypt-Zertifikat
- Periodischer Heartbeat (5 Min. konfiguriert / 1 Min. unkonfiguriert)
- Bridge-Konfiguration (Name, Standort, Info-URL, **Anny-Ressourcen-ID**, Idle-Strom, OTP-Pflicht, SuperUser-UIDs usw.) wird vom Server synchronisiert (Config-Hash als `config_version`)
- Button **„Konfiguration abrufen"** im Bridge-Tab stößt sofort einen Heartbeat an (liefert wartende Konfiguration bzw. löst den Voll-Upload aus), ohne das Intervall abzuwarten
- Nach jedem erfolgreichen Heartbeat holt die Bridge die Buchungen der Ressource über `GET /bookings/{Ressourcen-ID}`; die laufende bzw. nächste Buchung erscheint als Banner auf der Startseite (rechts neben dem QR-Code, unter „NFC UID:"). Voraussetzung: gesetzte `resource_id` und SNTP-Sync
- WLAN-Modem-Sleep ist abgeschaltet (`WIFI_PS_NONE`), damit der TLS-Handshake nicht durch Beacon-Wartezeiten ausgebremst wird
- OTA-Firmware-Updates (manuell über GUI und automatisch per `auto_ota`-Flag)

### Sensorik & Peripherie
- **ADS1115** (I2C, 0x48): 16-Bit ADC, 4 Kanäle – kontinuierliche Strommessung am Maschinenausgang (RMS über 128 Samples)
- **MCS1806**: Stromsensor ±20A, Empfindlichkeit 66 mV/A, Ruhespannung 1650 mV (VCC/2 bei 3,3 V)
- **Kalibrierter Nullpunkt**: Einmalige Nullpunkt-Kalibrierung über GUI, Ergebnis persistent in NVS (`zero_cal_mv`), unabhängig von der Config-Versionierung
- **Idle-Strom-Messung**: Einmalige Messung über GUI speichert den gemessenen Strom-Ruhewert im NVS und überträgt ihn per Heartbeat zum Server
- **PCF8574T** (I2C, 0x20): 8-Bit I/O-Expander – Rote/Grüne LED, Relais (P0–P3), digitale Eingänge (P4–P7)

### GUI (LVGL 9)
- **Startseite**: Maschinenname, Standort, QR-Code (Info-URL, 134 px), Freischalt-Status, NFC-UID, darunter Reservierungs-Banner, Authentifizieren-/Revoke-Button
- **Activation-Overlay**: QR-Code + URL + Hinweistext, erscheint während des Activation-Pollings
- **PIN-Eingabe**: 6-stelliges Num-Pad für OTP-Codes (Code vorhanden, im aktuellen Flow nicht mehr angesteuert)
- **Ergebnisseite**: Erfolg/Fehler-Anzeige mit Auto-Return (60 s) und Karten-Registrierungsoption
- **Board-Status-Modal** (PWRKEY): Tab-basierte Übersicht – Netzwerk, Bridge (inkl. Ressourcen-ID und „Konfiguration abrufen"), System/Debug, Kalibrierung; enthält WLAN-Konfiguration, Idle-Strom-Messung und Nullpunkt-Kalibrierung
- **Login-Modal**: E-Mail/Passwort-Formular mit WLAN-Keyboard (Code vorhanden, aktuell nicht mehr aus der GUI erreichbar)
- **Debug-Overlay**: Schalter für Log-Label, OTA-Trigger-Button

### Netzwerk
- **WLAN**: WPA2-PSK, WPA2-Enterprise (EAP), DHCP oder statische IP
- Konfiguration vollständig über Touchscreen-GUI (Netzwerk-Scan, manuelle Eingabe)
- **PWRKEY** (GPIO 16): Hardware-Button öffnet das Board-Status-Modal

## Server-API

Alle Endpunkte verlangen `Authorization: Bearer <BRIDGE_API_TOKEN>`.

| Methode | Endpunkt | Zweck |
|---|---|---|
| POST | `/activations` | Body: `card_id`, `device_id`, `resource_id`. Antwort 201 mit `url` + `expiresAt` |
| GET | `/activations/decision/{code}` | Long-Poll (bis 25 s). 200 `{remaining_ms, booking_id}`, 403 mit Grund, 202 noch offen, 404 Sitzung weg |
| POST | `/heartbeat` | `device_id`, `fw_version`, `config_version`, `telemetry`. Antwort: `{}`, `{configuration_request:true}` oder `{configuration:{…}}` |
| POST | `/heartbeat/configuration` | Voll-Upload auf `configuration_request`: Manifest (als JSON-String) + aktuelle Konfiguration |
| GET | `/bookings/{Ressourcen-ID}` | `{bookings:[{booking_id, booking_number, resource_name, service_name, starts_in_ms, ends_in_ms}]}`, max. 5, nach Beginn sortiert. 404 bei nicht numerischer ID, 502 wenn Anny nicht erreichbar |

Die `resource_id` ist die Anny-ID der Ressource und wird im Dashboard pro Bridge als Konfigurationsfeld gesetzt. Ohne sie lehnt der Server `/activations` mit 400 ab.

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
    │  POST /activations   │  │  AUTH_SRC_REGISTER   │
    │  ↓                  │  └──────────────────────┘
    │  Response-Queue ──► │──► Auth-Result-Timer (LVGL)
    │                     │    ↓
    └─────────────────────┘    Activation-Overlay (QR/URL)
                               ↓
                               activation_poll_timer_cb
                               (GET /activations/decision/<code>)
                               ↓
                               activate_unlock() / show_result_page()

    Strom-Messung (kontinuierlich, Core 0):
    current_measure_task → ADS1115 ch0, kontinuierlicher Modus
      → 128 Samples → RMS → s_current_rms_a [A]
      → Idle-Erkennung: s_unlock_idle_pending + s_idle_below_since_us

    Idle-Strom-Messung (einmalig, auf Anfrage aus GUI):
    measure_idle_btn → idle_measure_task (Core 1)
      → s_bridge_cfg.idle_current (NVS) + Heartbeat-Payload

    Nullpunkt-Kalibrierung (einmalig, auf Anfrage aus GUI):
    calibrate_zero_btn → zero_cal_save() → NVS "zero_cal_mv"
      → s_current_zero_mv (globaler Nullpunkt für RMS-Berechnung)
```

### Task-Verteilung
| Task | Core | Funktion |
|------|------|----------|
| LVGL / Display | 1 | GUI-Rendering, Timer-Callbacks |
| Auth-Worker | 1 | HTTPS-Requests, JSON-Parsing, Config-Sync |
| NFC-Polling | 0 | PN532-Kommunikation, UID-Erkennung |
| Strom-Messung | 0 | Kontinuierliche ADS1115-RMS-Messung, Idle-Erkennung |
| Idle-Measure (einmalig) | 1 | ADS1115-Einzelmessung, NVS-Speicherung |
| Auto-OTA (einmalig) | 1 | Firmware-Download und Flash |

### Datenfluss (Authentifizierung)
1. NFC-Karte erkannt (oder Start-Button gedrückt) → `auth_request_t` (UID bzw. MAC) in Request-Queue
2. Auth-Worker prüft zuerst lokal gegen `superuser_uids` – direktes Unlock ohne Server möglich
3. Sonst POST an `/activations` (`card_id`/`device_id`/`resource_id`)
4. Server antwortet mit einer Freigabe-`url` (+ optional `expiresAt`)
5. Bridge zeigt Activation-Overlay (QR-Code + URL) und startet `activation_poll_timer_cb` (alle 1,5 s)
6. Polling gegen `/activations/decision/<code>`:
   - `200` → `activate_unlock()` für die Restzeit (`remaining_ms`) + Erfolgsseite
   - `403` → Ergebnisseite mit Fehlermeldung vom Server
   - `404` → „Session abgelaufen"
   - `≥500` → Statustext „Serverfehler bei Freigabe", Polling läuft weiter bis Ablauf

### Datenfluss (Idle-Erkennung)
1. `current_measure_task` misst kontinuierlich ADS1115 ch0 (RMS, 128 Samples)
2. Nach Ablauf des Freischalt-Timers: `s_unlock_idle_pending = true`, Relais bleibt aktiv
3. Strom bleibt unter `s_bridge_cfg.idle_current` → `s_idle_below_since_us` gesetzt
4. Nach `idle_shutdown_delay_s` Sekunden kontinuierlich unter Schwelle → Relais abschalten

### Datenfluss (Idle-Strom-Messung)
1. Nutzer tippt „Idle-Strom messen" im Bridge-Tab
2. `idle_measure_task` misst ADS1115 ch0, speichert in `s_bridge_cfg.idle_current` (NVS) + `s_idle_current_measured_mV`
3. Nächster Heartbeat enthält `"idle_current_mV": <Wert>`
4. Server speichert Wert in `bridge_config.idle_current`
5. Beim Config-Sync (Admin-Änderung) überschreibt Server-Wert den lokalen Wert

## Konfiguration

### Build-Einstellungen (`main.c`)
| Define | Wert | Beschreibung |
|--------|------|-------------|
| `ENABLE_NFC` | `1` | `1` = echter PN532, `0` = Sim-Buttons |
| `AUTH_URL_ACTIVATIONS` / `_ACTIVATION_DECISION` / `_HEARTBEAT` / `_BOOKINGS` / `_CONFIGURATION` | `https://lima.intern.hs-duesseldorf.de/...` | Server-Endpunkte (HTTPS). Die Dev-Variante `https://10.50.55.55:8080/...` steht auskommentiert daneben |
| `BRIDGE_API_TOKEN` | fest im Quellcode | Gemeinsamer Bearer-Token für alle Bridges (ersetzt den früheren Server-generierten Pro-Gerät-Token) |
| `OTA_URL_*` | `lima.hsd.pub` | OTA-Endpunkte (HTTPS, unverändert) |
| `DEV_TLS_INSECURE` | `0` | `0` = echte TLS-Prüfung (Let's Encrypt); wirkt nur für HTTPS-URLs |
| `HEARTBEAT_INTERVAL_MS` | `300000` (5 Min.) | Heartbeat-Intervall konfiguriert |
| `HEARTBEAT_INTERVAL_UNCONFIGURED_MS` | `60000` (1 Min.) | Heartbeat-Intervall unkonfiguriert |
| `AUTH_HTTP_RETRY_COUNT` | `2` | Retries bei HTTP-Timeout |
| `CURRENT_RMS_SAMPLES` | `128` | Samples pro RMS-Berechnung (kontinuierliche Strommessung) |
| `MCS1806_SENSITIVITY_MV_A` | `66.0` | Empfindlichkeit Stromsensor [mV/A] |
| `MCS1806_OFFSET_MV` | `1650.0` | Ruhespannung Stromsensor bei 0A [mV] |
| `SUPERUSER_MAX` | `32` | Max. SuperUser-UIDs pro Bridge |
| `PN532_I2C_ADDR` | `0x54` | I2C-Adresse des PN532 |

### NVS-Namespaces
| Namespace | Version | Inhalt |
|-----------|---------|--------|
| `wifi_cfg` | 2 | SSID, Passwort, IP-Konfiguration, EAP |
| `auth_cfg` | 1 | Server-Token, MAC-Adresse |
| `bridge_cfg` | 8 | Maschinenname, Standort, Info-URL, Ressourcen-ID, Idle-Strom, SuperUser-UIDs, Config-Hash, Idle-Shutdown-Delay (Versionswechsel verwirft die gespeicherte Konfiguration, sie kommt per Heartbeat neu) |
| `bridge_cfg` / `zero_cal_mv` | – | Kalibrierter Nullpunkt des Stromsensors [mV] (versionierungsunabhängig) |

## Bekannte Probleme / Work in Progress

- **Langsame TLS-Verbindungen**: Neue HTTPS-Verbindungen brauchen im Testbetrieb 8–12 s und laufen teils in den 8-s-Timeout (`ESP_ERR_HTTP_CONNECT`); der Server selbst antwortet in ~50 ms. Die Zertifikatskette ist groß (~5,4 KB, RSA 4096). Ursache noch nicht bestätigt – Modem-Sleep ist abgeschaltet, vor jedem Heartbeat wird `[WIFI] RSSI=…` geloggt. Der Auth-Busy-Timeout (12 s) ist kürzer als ein langsamer Heartbeat samt Upload.
- **Fest codierter, geteilter API-Token**: `BRIDGE_API_TOKEN` steht im Klartext im Quellcode und gilt für alle Bridges gleichermaßen (kein Pro-Gerät-Token). Landet der Token in einem öffentlichen Repo oder wird eine Bridge kompromittiert, sind potenziell alle Geräte betroffen.
- **Login-/PIN-Flow ist tote GUI-Logik**: `login_open_event_cb` öffnet das Login-Modal nicht mehr, sondern löst direkt eine Activation über die MAC-Adresse aus. Modal, E-Mail/Passwort-Eingabe und PIN-Screen existieren weiterhin im Code, sind aber nicht mehr erreichbar.
- **Ausführliches Secret-Logging**: Mehrere `ESP_LOGI`-Aufrufe schreiben komplette Server-Antworten, Token-Header und den Bearer-Token im Klartext ins Log (z. B. „Setup success, token stored: %s").
- **Buchungsliste direkt nach dem Boot leer**: Solange SNTP nicht synchron ist, überspringt die Bridge den Abruf (die Banner-Zeiten brauchen die Uhr); der nächste Heartbeat holt ihn nach.

### Bereits behoben
- ~~`POST /activations` ohne `resource_id` (Server antwortet 400)~~ → `resource_id` ist Konfigurationsfeld und wird mitgeschickt.
- ~~Reservierung aus der Heartbeat-Antwort (`res_name`/`res_start`/`res_end`)~~ → ersetzt durch `GET /bookings/{Ressourcen-ID}`.
- ~~Freigabedauer aus `end_date` der Freigabe-Antwort~~ → `remaining_ms`.
- ~~`response_is_true()` fiel bei leerer/uneindeutiger Server-Antwort „offen" (autorisiert) statt „geschlossen" (abgelehnt) aus~~ → Default wieder auf `false` gesetzt; nur noch explizite Erfolgs-Marker (`result:true`, `valid:true`, `url`-Feld usw.) gelten als Freigabe.
- ~~Fester Platzhalter-Device-ID (`s_device_id`) für alle Bridges identisch~~ → wird in `app_main()` deterministisch aus der Geräte-MAC-Adresse abgeleitet (ohne Doppelpunkte, klein geschrieben).
- ~~OTA-Check (`ota_task`/`auto_ota_task`) hängte den nie befüllten `s_auth_cfg.token` an die URL~~ → nutzt jetzt wie die restlichen Endpunkte `auth_active_token()` (`BRIDGE_API_TOKEN`).
- ~~Unversionierte Altlasten (`main/main.c.bak`, `.DS_Store`)~~ → lokal entfernt (waren bereits über `.gitignore` ausgeschlossen).

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
