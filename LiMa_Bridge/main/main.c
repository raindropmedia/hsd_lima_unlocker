/*
 * LiMa Bridge – ESP32-S3 Firmware für das HSD-Freischaltungssystem
 *
 * Dieses Programm läuft auf einem Waveshare ESP32-S3 Touch LCD 4 (480x480)
 * und stellt ein NFC-basiertes Authentifizierungssystem für Maschinen in der
 * HSD (Hochschule Düsseldorf) bereit. Es kommuniziert über HTTPS mit einem
 * Flask-Server (LiMa Server), um Benutzer per NFC-Karte oder Login zu
 * authentifizieren und Maschinen zeitlich befristet freizuschalten.
 *
 * Hauptfunktionen:
 *   - NFC-Kartenleser (PN532 direkt via I2C, Adresse 0x54) zur Benutzeridentifikation
 *   - LVGL-basierte Touchscreen-GUI mit Start-, PIN- und Ergebnis-Ansichten
 *   - WLAN-Konfiguration über GUI-Modal mit Scan-Funktion
 *   - HTTPS-Kommunikation mit dem LiMa Server (Setup, Heartbeat, Auth)
 *   - Zeitlich befristete Maschinenfreischaltung mit visueller Statusanzeige
 *   - OTP-Unterstützung (TOTP / Mail-OTP) als zweiter Faktor
 *   - NFC-Karten-Selbstregistrierung nach erfolgreichem Login
 *   - Akustisches Feedback über Buzzer (IO-Expander)
 *   - Bridge-Konfiguration wird vom Server verwaltet und per Heartbeat synchronisiert
 */
#include <stdbool.h>
#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "sdkconfig.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "esp_check.h"
#include "esp_crt_bundle.h"
#include "esp_err.h"
#include "esp_event.h"
#include "esp_http_client.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "esp_eap_client.h"
#include "esp_mac.h"
#include "lvgl.h"
#include "bsp/esp-bsp.h"
#include "bsp/display.h"
#include "driver/i2c_master.h"
#include "lwip/ip4_addr.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "esp_heap_caps.h"
#include "esp_lcd_panel_rgb.h"
#include "driver/gpio.h"
#include "esp_https_ota.h"
#include "esp_ota_ops.h"

/* ════════════════════════════════════════════════════════════════════════════
 * Build-Konfiguration: ENABLE_NFC steuert, ob echter NFC-Betrieb (PN532)
 * oder simulierte NFC-Buttons auf dem Touchscreen verwendet werden.
 * ════════════════════════════════════════════════════════════════════════════ */
#define ENABLE_NFC 1

/* APP_VERSION wird per target_compile_definitions aus PROJECT_VER (root CMakeLists.txt) gesetzt */

#if ENABLE_NFC
#define PN532_I2C_ADDR        0x54
#define PN532_UID_MAX_LEN     10
/* PN532 Protokoll-Konstanten */
#define PN532_HOSTTOPN532     0xD4u
#define PN532_CMD_SAMCONFIGURATION    0x14u
#define PN532_CMD_INLISTPASSIVETARGET 0x4Au
#endif

#define LVGL_TASK_CORE_ID 1
#if ENABLE_NFC
#define NFC_TASK_CORE_ID 0
#endif
#define AUTH_TASK_CORE_ID 1

#define WIFI_NAMESPACE "wifi_cfg"
#define WIFI_CFG_VERSION 2
#define AUTH_NAMESPACE "auth_cfg"
#define AUTH_CFG_VERSION 1

#define PWRKEY_GPIO GPIO_NUM_16

#define BRIDGE_CFG_NAMESPACE "bridge_cfg"
#define BRIDGE_CFG_VERSION 2
#define HEARTBEAT_INTERVAL_MS (5 * 60 * 1000)
#define HEARTBEAT_INTERVAL_UNCONFIGURED_MS (1 * 60 * 1000)

/* Server-Endpunkte – alle Authentifizierungs-URLs zeigen auf den LiMa Server */
#define AUTH_URL_SETUP         "https://lima.hsd.pub/api/hsd/setup"
#define AUTH_URL_NFC            "https://lima.hsd.pub/api/hsd/nfc"
#define AUTH_URL_LOGIN          "https://lima.hsd.pub/api/hsd/login"
#define AUTH_URL_PIN            "https://lima.hsd.pub/api/hsd/pin"
#define AUTH_URL_HEARTBEAT      "https://lima.hsd.pub/api/hsd/heartbeat"
#define AUTH_URL_REGISTER_CARD  "https://lima.hsd.pub/api/hsd/register_card"
#define OTA_URL_CHECK           "https://lima.hsd.pub/api/hsd/ota/check"
#define OTA_URL_FIRMWARE        "https://lima.hsd.pub/api/hsd/ota/firmware"
#define DEV_TLS_INSECURE 0      /* Let's Encrypt: echte Zertifikatspruefung aktiv */
#define AUTH_HTTP_RETRY_COUNT 2
#define AUTH_HTTP_RETRY_DELAY_MS 250

#define AUTH_REQ_QUEUE_LEN 4
#define AUTH_RES_QUEUE_LEN 4
#define AUTH_BUSY_TIMEOUT_MS 12000
#define SETUP_RETRY_INTERVAL_MS 15000
#if ENABLE_NFC
#define NFC_POLL_IDLE_MS 1000
#define NFC_POLL_PAUSED_MS 250
#define NFC_POLL_AFTER_CARD_MS 1500
#define PN532_SCAN_FAIL_REINIT_THRESHOLD 6
#define PN532_RECOVERY_DELAY_MS 200
#define PN532_I2C_SCL_SPEED_HZ 100000
#define PN532_I2C_RX_TIMEOUT_MS 120      /* Timeout fuer echte Daten-Frames (ACK, Response) */
#define PN532_STATUS_POLL_TIMEOUT_MS 15  /* Kurzer Timeout fuer Status-Byte-Polls (kein Clock-stretch) */
#define PN532_WAIT_READY_INTERVAL_MS 30  /* Abstand zwischen Status-Polls – laesst GT911 Bus-Zeit */
#define PN532_ACK_TIMEOUT_MS  150
#define PN532_CMD_TIMEOUT_MS  600
#define PN532_SCAN_TIMEOUT_MS 660        /* >600ms PN532-interner RF-Scan + Puffer */
#endif

/* Externe Sensorik: ADS1115 (16-Bit-ADC, 4 Kanaele) + PCF8574T (8-Bit-I/O-Expander) */
#define ADS1115_I2C_ADDR        0x48    /* ADDR-Pin auf GND */
#define PCF8574_I2C_ADDR        0x20    /* A0-A2 auf GND    */
#define ADS1115_I2C_SCL_SPEED_HZ 400000
#define PCF8574_I2C_SCL_SPEED_HZ 400000

/* PCF8574T Pin-Belegung: P0-P3 Ausgaenge (active LOW), P4-P7 Eingaenge */
#define PCF_PIN_LED_RED    0u    /* P0: Rote LED    (active LOW: 0=an, 1=aus) */
#define PCF_PIN_LED_GREEN  1u    /* P1: Gruene LED  (active LOW) */
#define PCF_PIN_RELAY      2u    /* P2: Relais      (active LOW) */
#define PCF_OUTPUT_MASK    0x0Fu /* P0-P3: Ausgaenge; HIGH=aus, LOW=an */
#define PCF_INPUT_MASK     0xF0u /* P4-P7: Eingaenge; immer 1 schreiben */

static const char *TAG = "HSD_APP";
extern const char server_cert_pem_start[] asm("_binary_server_cert_pem_start");
extern const char server_cert_pem_end[] asm("_binary_server_cert_pem_end");

/* ════════════════════════════════════════════════════════════════════════════
 * Datenstrukturen: NVS-persistierte Konfigurationen und Auth-Nachrichten
 * ════════════════════════════════════════════════════════════════════════════ */

/* WLAN-Konfiguration – wird im NVS gespeichert (DHCP oder statische IP) */
typedef struct {
    uint32_t version;
    uint8_t dhcp_enabled;
    char ssid[33];
    char password[65];
    char ip[16];
    char gateway[16];
    char netmask[16];
    char dns[16];           /* Optionaler DNS-Server (leer = Router/DHCP-DNS) */
    uint8_t eap_enabled;    /* 1 = WPA2-Enterprise (802.1x), 0 = PSK/Open */
    char eap_identity[64];  /* Aeussere Identitaet (z.B. anonymous@eduroam.example.com) */
    char eap_username[64];  /* Innere Identitaet / Username (z.B. user@eduroam.example.com) */
} wifi_store_t;

/* GUI-Ansichten: Start (NFC/Login), PIN-Eingabe, Ergebnis (Erfolg/Fehler) */
typedef enum {
    APP_VIEW_START = 0,
    APP_VIEW_PIN,
    APP_VIEW_RESULT,
} app_view_t;

/* Auth-Quellen: bestimmt, welcher Server-Endpunkt angesprochen wird */
typedef enum {
    AUTH_SRC_SETUP = 0,         /* Erstregistrierung des Geräts (MAC → Token) */
    AUTH_SRC_HEARTBEAT,         /* Periodischer Statusbericht an Server */
    AUTH_SRC_NFC,               /* NFC-Karten-Authentifizierung */
    AUTH_SRC_LOGIN,             /* E-Mail/Passwort-Login über GUI */
    AUTH_SRC_PIN,               /* OTP/PIN-Eingabe (zweiter Faktor) */
    AUTH_SRC_REGISTER_CARD,     /* NFC-Karte mit Benutzer verknüpfen */
} auth_source_t;

/* Auth-Request: wird in die Request-Queue eingereiht (value_a/b je nach Quelle) */
typedef struct {
    auth_source_t source;
    char value_a[96];   /* z.B. MAC, UID, E-Mail oder PIN */
    char value_b[96];   /* z.B. Passwort (nur bei LOGIN) */
} auth_request_t;

typedef struct {
    auth_source_t source;
    bool success;
    bool pin_required;
    int http_status;
    uint32_t unlock_duration_min;
    char token[96];
} auth_result_t;

typedef struct {
    uint32_t version;
    char token[96];
    char mac[18];
} auth_store_t;

typedef struct {
    uint32_t version;
    char machine_name[64];
    char location[64];
    char info_url[128];
    float idle_current;
    uint8_t sound_enabled;
    uint8_t idle_detection_enabled;
    uint8_t otp_required;
    uint8_t auto_ota;           /* 1 = automatisch updaten wenn neue Version verfuegbar */
    uint32_t unlock_duration_min;
    uint32_t config_version;
} bridge_cfg_t;

/* Alle LVGL UI-Handles – zentral verwaltet für Zugriff aus Callbacks */
typedef struct {
    lv_obj_t *machine_name_label;
    lv_obj_t *location_label;
    lv_obj_t *qr_code;
    lv_obj_t *status_label;
    lv_obj_t *nfc_uid_label;
    lv_obj_t *start_container;
    lv_obj_t *pin_container;
    lv_obj_t *result_container;
    lv_obj_t *pin_ta;
    lv_obj_t *pin_pad;
    lv_obj_t *result_icon_label;
    lv_obj_t *result_text_label;
    lv_obj_t *login_modal;
    lv_obj_t *login_email_ta;
    lv_obj_t *login_password_ta;
    lv_obj_t *wifi_cfg_modal;
    lv_obj_t *wifi_cfg_page;
    lv_obj_t *wifi_status_page;
    lv_obj_t *wifi_ssid_dropdown;
    lv_obj_t *wifi_password_ta;
    lv_obj_t *wifi_dhcp_sw;
    lv_obj_t *wifi_eap_sw;         /* Toggle: WPA2-Enterprise aktivieren */
    lv_obj_t *wifi_eap_cont;       /* Container fuer Enterprise-Felder (hidden bei PSK) */
    lv_obj_t *wifi_eap_identity_ta;/* Aeussere Identitaet (anonymous@...) */
    lv_obj_t *wifi_eap_username_ta;/* Innere Identitaet / Username */
    lv_obj_t *wifi_static_ip_cont;
    lv_obj_t *wifi_ip_ta;
    lv_obj_t *wifi_gateway_ta;
    lv_obj_t *wifi_netmask_ta;
    lv_obj_t *wifi_dns_ta;
    lv_obj_t *wifi_cfg_status_label;
    lv_obj_t *status_info_label;
    lv_obj_t *status_net_label;
    lv_obj_t *status_bridge_label;
    lv_obj_t *status_system_label;
    lv_obj_t *status_tab_net;
    lv_obj_t *status_tab_bridge;
    lv_obj_t *status_tab_system;
    lv_obj_t *tab_net_btn;
    lv_obj_t *tab_bridge_btn;
    lv_obj_t *tab_sys_btn;
    lv_obj_t *unlock_indicator;
    lv_obj_t *unlock_text_label;
    lv_obj_t *login_btn;
    lv_obj_t *revoke_unlock_btn;
    lv_obj_t *register_card_btn;
    lv_obj_t *keyboard;
    lv_obj_t *ota_status_label;
    lv_obj_t *ota_btn;
    lv_obj_t *measure_idle_btn;
} ui_handles_t;

typedef struct {
    char *response;
    size_t response_size;
    size_t response_len;
    char *token;
    size_t token_size;
} http_capture_t;

/* ════════════════════════════════════════════════════════════════════════════
 * Globaler Zustand: NVS-Konfigurationen, FreeRTOS-Queues, UI und Flags
 * ════════════════════════════════════════════════════════════════════════════ */

#if ENABLE_NFC
static i2c_master_dev_handle_t s_pn532_dev = NULL;
#endif
static i2c_master_dev_handle_t s_ads1115_dev = NULL;  /* ADS1115 – 16-Bit ADC            */
static i2c_master_dev_handle_t s_pcf8574_dev = NULL;  /* PCF8574T – 8-Bit I/O-Expander   */
static volatile int16_t s_ads_raw[4] = {0, 0, 0, 0};  /* Letzter Messwert je Kanal (raw) */
static volatile uint8_t s_pcf_input  = 0xFF;           /* Letzter gelesener Portbyte (P4-P7) */
static volatile uint8_t s_pcf_output = 0x0F;           /* Ausgangszustand P0-P3 (active LOW, init=alle aus) */
static wifi_store_t s_wifi_cfg = {
    .version = WIFI_CFG_VERSION,
    .dhcp_enabled = 1,
};
static auth_store_t s_auth_cfg = {
    .version = AUTH_CFG_VERSION,
};
static bridge_cfg_t s_bridge_cfg = {
    .version = BRIDGE_CFG_VERSION,
};
static volatile bool s_bridge_cfg_updated = false;
static volatile int64_t s_last_heartbeat_us = 0;
static volatile int64_t s_unlock_until_us = 0;      /* Freischaltung gültig bis (Mikrosekunden, 0=gesperrt) */
static volatile uint32_t s_unlock_duration_orig_min = 0; /* Originalwert für Timer-Reset */
static esp_netif_t *s_wifi_netif = NULL;
static esp_event_handler_instance_t s_wifi_evt_instance = NULL;
static esp_event_handler_instance_t s_ip_evt_instance = NULL;

/* Auth-Queues: Request-Queue (UI → Worker) und Response-Queue (Worker → UI-Timer) */
static QueueHandle_t s_auth_req_queue = NULL;
static QueueHandle_t s_auth_res_queue = NULL;
static ui_handles_t s_ui = {0};
static volatile bool s_auth_busy = false;
static volatile int64_t s_auth_busy_since_us = 0;
static volatile bool s_wifi_has_ip = false;
static volatile bool s_wifi_scan_in_progress = false;  /* Scan laeuft: Reconnect-Loop pausieren */
static volatile bool s_auto_ota_in_progress = false;   /* Auto-OTA-Task laeuft bereits */
static volatile int64_t s_setup_last_attempt_us = 0;
static bool s_setup_log_verbose = true;
static volatile app_view_t s_current_view = APP_VIEW_START;
static volatile bool s_pause_nfc_polling = false;       /* NFC-Polling pausiert (z.B. während Modals) */
static volatile bool s_reset_nfc_uid_requested = false;  /* Letzte UID vergessen, neue Karte akzeptieren */
static volatile uint32_t s_vsync_count = 0;
static lv_obj_t *s_debug_label = NULL;
static volatile bool s_pwrkey_pressed = false;
static char s_wifi_scan_options[1024] = "";
static esp_io_expander_handle_t s_io_expander = NULL;
static lv_timer_t *s_auto_return_timer = NULL;           /* 60s Auto-Rückkehr zum Startbildschirm */
static volatile bool s_register_card_mode = false;       /* NFC-Task liest Karte für Registrierung */
static volatile bool s_offer_card_registration = false;  /* Registrierungs-Button auf Ergebnisseite zeigen */
static volatile bool s_auth_origin_login = false;        /* PIN-Flow kam von Login (nicht NFC) */
static volatile float s_idle_current_measured_mV = -1.0f; /* <0 = noch nicht gemessen */

static void set_label_text_color(lv_obj_t *label, const char *text, lv_color_t color);
static void set_status_text(const char *text, lv_color_t color);
static void set_nfc_uid_text(const char *text, lv_color_t color);
static bool enqueue_auth_request(const auth_request_t *req);
static bool enqueue_setup_request_if_needed(void);
static bool enqueue_token_check_request_if_needed(void);
static void activate_unlock(uint32_t server_duration_min);

/* ════════════════════════════════════════════════════════════════════════════
 * Buzzer: Akustisches Feedback über IO-Expander (1× = Info, 2× = Erfolg, 3× = Fehler)
 * ════════════════════════════════════════════════════════════════════════════ */

/* Akustisches Signal über IO-Expander: count × 80ms Beep */
static void beep(int count)
{
    if (!s_bridge_cfg.sound_enabled || !s_io_expander) {
        return;
    }
    for (int i = 0; i < count; i++) {
        esp_io_expander_set_level(s_io_expander, BSP_BEE_EN, 1);
        vTaskDelay(pdMS_TO_TICKS(80));
        esp_io_expander_set_level(s_io_expander, BSP_BEE_EN, 0);
        if (i + 1 < count) {
            vTaskDelay(pdMS_TO_TICKS(100));
        }
    }
}

/* ISR: PWRKEY-Tastendruck (GPIO 16, Flanke → LOW) setzt Flag für Timer */
static void IRAM_ATTR pwrkey_isr_handler(void *arg)
{
    (void)arg;
    s_pwrkey_pressed = true;
}

/* I2C-Bus scannen und gefundene Geräteadressen loggen (Debug) */
static void i2c_scan_log(void)
{
    esp_err_t err = bsp_i2c_init();
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "I2C scan skipped, init failed: %s", esp_err_to_name(err));
        return;
    }

    i2c_master_bus_handle_t i2c_bus = bsp_i2c_get_handle();
    if (i2c_bus == NULL) {
        ESP_LOGW(TAG, "I2C scan skipped, bus handle is NULL");
        return;
    }

    uint8_t found_count = 0;
    ESP_LOGI(TAG, "I2C scan start (7-bit addresses 0x03..0x77)");
    for (uint8_t addr = 0x03; addr <= 0x77; addr++) {
        if (i2c_master_probe(i2c_bus, addr, 10) == ESP_OK) {
            ESP_LOGI(TAG, "I2C device found at 0x%02X", addr);
            found_count++;
        }
    }

    ESP_LOGI(TAG, "I2C scan done, devices found: %u", (unsigned int)found_count);
}

/* HTTP-Event-Handler: Fängt Response-Body und X-Bridge-Token Header ab */
static esp_err_t http_capture_event_handler(esp_http_client_event_t *evt)
{
    http_capture_t *cap = (http_capture_t *)evt->user_data;
    if (cap == NULL) {
        return ESP_OK;
    }

    if ((evt->event_id == HTTP_EVENT_ON_DATA) && (evt->data != NULL) && (evt->data_len > 0) && (cap->response != NULL) && (cap->response_size > 1)) {
        size_t remaining = (cap->response_size - 1) - cap->response_len;
        size_t copy_len = evt->data_len < remaining ? (size_t)evt->data_len : remaining;
        if (copy_len > 0) {
            memcpy(cap->response + cap->response_len, evt->data, copy_len);
            cap->response_len += copy_len;
            cap->response[cap->response_len] = '\0';
        }
    }

    if ((evt->event_id == HTTP_EVENT_ON_HEADER) && (evt->header_key != NULL) && (evt->header_value != NULL) && (cap->token != NULL) && (cap->token_size > 1)) {
        if (strcasecmp(evt->header_key, "X-Bridge-Token") == 0) {
            strncpy(cap->token, evt->header_value, cap->token_size - 1);
            cap->token[cap->token_size - 1] = '\0';
        }
    }

    return ESP_OK;
}

/* Auth-Busy-Flag setzen/zurücksetzen mit Zeitstempel für Timeout-Erkennung */
static void set_auth_busy(bool busy)
{
    s_auth_busy = busy;
    s_auth_busy_since_us = busy ? esp_timer_get_time() : 0;
}

/* ════════════════════════════════════════════════════════════════════════════
 * NVS-Persistierung: WLAN-, Auth- und Bridge-Konfigurationen werden im
 * Non-Volatile Storage des ESP32 gespeichert und beim Boot geladen.
 * ════════════════════════════════════════════════════════════════════════════ */

/* WLAN-Konfiguration im NVS speichern */
static esp_err_t wifi_cfg_save(const wifi_store_t *cfg)
{
    nvs_handle_t nvs = 0;
    ESP_RETURN_ON_ERROR(nvs_open(WIFI_NAMESPACE, NVS_READWRITE, &nvs), TAG, "NVS open write failed");
    ESP_RETURN_ON_ERROR(nvs_set_blob(nvs, "store", cfg, sizeof(*cfg)), TAG, "NVS write failed");
    ESP_RETURN_ON_ERROR(nvs_commit(nvs), TAG, "NVS commit failed");
    nvs_close(nvs);
    return ESP_OK;
}

/* Auth-Konfiguration auf Standardwerte zurücksetzen */
static void auth_cfg_set_defaults(auth_store_t *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    cfg->version = AUTH_CFG_VERSION;
}

/* Auth-Konfiguration (Token + MAC) im NVS speichern */
static esp_err_t auth_cfg_save(const auth_store_t *cfg)
{
    nvs_handle_t nvs = 0;
    ESP_RETURN_ON_ERROR(nvs_open(AUTH_NAMESPACE, NVS_READWRITE, &nvs), TAG, "NVS auth open write failed");
    ESP_RETURN_ON_ERROR(nvs_set_blob(nvs, "store", cfg, sizeof(*cfg)), TAG, "NVS auth write failed");
    ESP_RETURN_ON_ERROR(nvs_commit(nvs), TAG, "NVS auth commit failed");
    nvs_close(nvs);
    return ESP_OK;
}

/* Auth-Konfiguration aus NVS laden, bei Fehler Defaults setzen */
static esp_err_t auth_cfg_load(auth_store_t *cfg)
{
    nvs_handle_t nvs = 0;
    auth_store_t loaded = {0};
    size_t len = sizeof(loaded);

    auth_cfg_set_defaults(cfg);

    esp_err_t err = nvs_open(AUTH_NAMESPACE, NVS_READONLY, &nvs);
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        return ESP_OK;
    }
    ESP_RETURN_ON_ERROR(err, TAG, "NVS auth open failed");

    err = nvs_get_blob(nvs, "store", &loaded, &len);
    nvs_close(nvs);

    if ((err == ESP_OK) && (len == sizeof(loaded)) && (loaded.version == AUTH_CFG_VERSION)) {
        *cfg = loaded;
    }

    return ESP_OK;
}

/* Bridge-Konfiguration auf Standardwerte zurücksetzen */
static void bridge_cfg_set_defaults(bridge_cfg_t *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    cfg->version = BRIDGE_CFG_VERSION;
}

/* Bridge-Konfiguration im NVS speichern */
static esp_err_t bridge_cfg_save(const bridge_cfg_t *cfg)
{
    nvs_handle_t nvs = 0;
    ESP_RETURN_ON_ERROR(nvs_open(BRIDGE_CFG_NAMESPACE, NVS_READWRITE, &nvs), TAG, "NVS bridge open write failed");
    ESP_RETURN_ON_ERROR(nvs_set_blob(nvs, "store", cfg, sizeof(*cfg)), TAG, "NVS bridge write failed");
    ESP_RETURN_ON_ERROR(nvs_commit(nvs), TAG, "NVS bridge commit failed");
    nvs_close(nvs);
    return ESP_OK;
}

/* Bridge-Konfiguration aus NVS laden, bei Fehler Defaults setzen */
static esp_err_t bridge_cfg_load(bridge_cfg_t *cfg)
{
    nvs_handle_t nvs = 0;
    bridge_cfg_t loaded = {0};
    size_t len = sizeof(loaded);

    bridge_cfg_set_defaults(cfg);

    esp_err_t err = nvs_open(BRIDGE_CFG_NAMESPACE, NVS_READONLY, &nvs);
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        return ESP_OK;
    }
    ESP_RETURN_ON_ERROR(err, TAG, "NVS bridge open failed");

    err = nvs_get_blob(nvs, "store", &loaded, &len);
    nvs_close(nvs);

    if ((err == ESP_OK) && (len == sizeof(loaded)) && (loaded.version == BRIDGE_CFG_VERSION)) {
        *cfg = loaded;
    }

    return ESP_OK;
}

/* Prüft ob ein gültiger Server-Token vorhanden ist */
static bool auth_has_token(void)
{
    return s_auth_cfg.token[0] != '\0';
}

/* MAC-Adresse als formatierte Zeichenkette (XX:XX:XX:XX:XX:XX) in Buffer schreiben */
static esp_err_t get_device_mac_text(char *buffer, size_t buffer_size)
{
    uint8_t mac[6] = {0};

    ESP_RETURN_ON_FALSE((buffer != NULL) && (buffer_size >= 18), ESP_ERR_INVALID_ARG, TAG, "MAC buffer invalid");
    ESP_RETURN_ON_ERROR(esp_read_mac(mac, ESP_MAC_WIFI_STA), TAG, "read MAC failed");

    snprintf(buffer, buffer_size, "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return ESP_OK;
}

/* Statustext im WLAN-Modal setzen und einfärben */
static void set_wifi_cfg_status_text(const char *text, lv_color_t color)
{
    if (s_ui.wifi_cfg_status_label && bsp_display_lock(30)) {
        set_label_text_color(s_ui.wifi_cfg_status_label, text, color);
        bsp_display_unlock();
    }
}

/* WLAN-Dropdown mit Liste verfügbarer Netze befüllen */
static void wifi_set_dropdown_options(const char *options)
{
    if (s_ui.wifi_ssid_dropdown && bsp_display_lock(50)) {
        lv_dropdown_set_options(s_ui.wifi_ssid_dropdown, options);
        bsp_display_unlock();
    }
}

/* WLAN-Konfiguration auf Standardwerte zurücksetzen */
static void wifi_cfg_set_defaults(wifi_store_t *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    cfg->version = WIFI_CFG_VERSION;
    cfg->dhcp_enabled = 1;
}

/* WLAN-Konfiguration aus NVS laden, bei Fehler Defaults setzen */
static esp_err_t wifi_cfg_load(wifi_store_t *cfg)
{
    nvs_handle_t nvs = 0;
    wifi_store_t loaded = {0};
    size_t len = sizeof(loaded);

    wifi_cfg_set_defaults(cfg);

    esp_err_t err = nvs_open(WIFI_NAMESPACE, NVS_READONLY, &nvs);
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        return ESP_OK;
    }
    ESP_RETURN_ON_ERROR(err, TAG, "NVS open failed");

    err = nvs_get_blob(nvs, "store", &loaded, &len);
    nvs_close(nvs);

    if ((err == ESP_OK) && (len == sizeof(loaded)) && (loaded.version == WIFI_CFG_VERSION)) {
        *cfg = loaded;
    }

    return ESP_OK;
}

/* IPv4-Adresse aus Text parsen (für statische IP-Konfiguration) */
static bool parse_ipv4(const char *text, ip4_addr_t *out)
{
    if ((text == NULL) || (text[0] == '\0')) {
        return false;
    }
    return ip4addr_aton(text, out) == 1;
}

/* ════════════════════════════════════════════════════════════════════════════
 * WLAN: Initialisierung, Event-Handling, Scan und statische/DHCP-Konfiguration
 * ════════════════════════════════════════════════════════════════════════════ */

/* WLAN-Verbindung mit gespeicherter Konfiguration herstellen (DHCP/statisch) */
static esp_err_t wifi_connect_from_cfg(const wifi_store_t *cfg)
{
    wifi_config_t wifi_cfg = {0};
    size_t ssid_len = strnlen(cfg->ssid, sizeof(cfg->ssid));

    if (ssid_len == 0) {
        return ESP_ERR_INVALID_ARG;
    }

    memcpy(wifi_cfg.sta.ssid, cfg->ssid, ssid_len);

    if (cfg->eap_enabled) {
        /* WPA2-Enterprise (PEAP/MSCHAPv2) – typisch fuer Eduroam */
        wifi_cfg.sta.threshold.authmode = WIFI_AUTH_WPA2_ENTERPRISE;
        wifi_cfg.sta.pmf_cfg.capable = true;
        wifi_cfg.sta.pmf_cfg.required = false;

        /* Zertifikatspruefung deaktivieren (kein CA-Zertifikat eingebettet) */
        esp_eap_client_set_disable_time_check(true);

        /* Aeussere Identitaet (wird im unverschluesselten EAP-Teil gesendet) */
        if (cfg->eap_identity[0] != '\0') {
            esp_eap_client_set_identity((const unsigned char *)cfg->eap_identity,
                                        (int)strlen(cfg->eap_identity));
        } else {
            esp_eap_client_clear_identity();
        }

        /* Innere Identitaet und Passwort (im verschluesselten TLS-Tunnel) */
        esp_eap_client_set_username((const unsigned char *)cfg->eap_username,
                                    (int)strlen(cfg->eap_username));
        esp_eap_client_set_password((const unsigned char *)cfg->password,
                                    (int)strlen(cfg->password));
    } else {
        /* PSK oder offenes Netzwerk */
        memcpy(wifi_cfg.sta.password, cfg->password, strnlen(cfg->password, sizeof(cfg->password)));
        /* Bei leerem Passwort: offenes Netzwerk erlauben (OPEN), sonst WPA2 erzwingen */
        wifi_cfg.sta.threshold.authmode = (cfg->password[0] != '\0') ? WIFI_AUTH_WPA2_PSK : WIFI_AUTH_OPEN;
        wifi_cfg.sta.pmf_cfg.capable = true;
        wifi_cfg.sta.pmf_cfg.required = false;
        esp_wifi_sta_enterprise_disable();
    }

    if (cfg->dhcp_enabled) {
        esp_err_t err = esp_netif_dhcpc_start(s_wifi_netif);
        if ((err != ESP_OK) && (err != ESP_ERR_ESP_NETIF_DHCP_ALREADY_STARTED)) {
            return err;
        }
    } else {
        ip4_addr_t ip = {0};
        ip4_addr_t gw = {0};
        ip4_addr_t mask = {0};

        if (!parse_ipv4(cfg->ip, &ip) || !parse_ipv4(cfg->gateway, &gw) || !parse_ipv4(cfg->netmask, &mask)) {
            return ESP_ERR_INVALID_ARG;
        }

        esp_err_t err = esp_netif_dhcpc_stop(s_wifi_netif);
        if ((err != ESP_OK) && (err != ESP_ERR_ESP_NETIF_DHCP_ALREADY_STOPPED)) {
            return err;
        }

        esp_netif_ip_info_t ip_info = {
            .ip.addr = ip.addr,
            .gw.addr = gw.addr,
            .netmask.addr = mask.addr,
        };
        ESP_RETURN_ON_ERROR(esp_netif_set_ip_info(s_wifi_netif, &ip_info), TAG, "Set static IP failed");

        /* Optionalen DNS-Server setzen (leer = Standard beibehalten) */
        if (cfg->dns[0] != '\0') {
            ip4_addr_t dns_addr = {0};
            if (parse_ipv4(cfg->dns, &dns_addr)) {
                esp_netif_dns_info_t dns_info = { .ip = { .u_addr.ip4.addr = dns_addr.addr, .type = IPADDR_TYPE_V4 } };
                esp_netif_set_dns_info(s_wifi_netif, ESP_NETIF_DNS_MAIN, &dns_info);
            }
        }
    }

    /* STA in IDLE bringen bevor set_config: verhindert "sta is connecting, cannot set config" */
    esp_wifi_disconnect();
    ESP_RETURN_ON_ERROR(esp_wifi_set_config(WIFI_IF_STA, &wifi_cfg), TAG, "WiFi set config failed");
    if (cfg->eap_enabled) {
        ESP_RETURN_ON_ERROR(esp_wifi_sta_enterprise_enable(), TAG, "Enterprise enable failed");
    }
    return esp_wifi_connect();
}

/* WLAN-Events: Disconnect-Retry, Got-IP, Scan-Done verarbeiten */
static void wifi_event_handler(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data)
{
    LV_UNUSED(arg);

    if ((event_base == WIFI_EVENT) && (event_id == WIFI_EVENT_STA_DISCONNECTED)) {
        s_wifi_has_ip = false;
        set_status_text("WLAN getrennt", lv_color_hex(0xFCA5A5));
        /* Nicht reconnecten wenn ein Scan laeuft – sonst "STA is connecting, scan not allowed" */
        if ((s_wifi_cfg.ssid[0] != '\0') && !s_wifi_scan_in_progress) {
            esp_wifi_connect();
        }
    }

    if ((event_base == IP_EVENT) && (event_id == IP_EVENT_STA_GOT_IP)) {
        ip_event_got_ip_t *evt = (ip_event_got_ip_t *)event_data;
        char ip_text[32] = "WLAN verbunden";
        s_wifi_has_ip = true;
        s_setup_last_attempt_us = 0;
        snprintf(ip_text, sizeof(ip_text), "WLAN " IPSTR, IP2STR(&evt->ip_info.ip));
        set_status_text(ip_text, lv_color_hex(0x86EFAC));
        if (!enqueue_token_check_request_if_needed()) {
            enqueue_setup_request_if_needed();
        }
    }

    if ((event_base == WIFI_EVENT) && (event_id == WIFI_EVENT_SCAN_DONE)) {
        uint16_t ap_count = 0;
        wifi_ap_record_t *ap_records = NULL;

        if (esp_wifi_scan_get_ap_num(&ap_count) != ESP_OK) {
            s_wifi_scan_in_progress = false;
            if (s_wifi_cfg.ssid[0] != '\0') { wifi_connect_from_cfg(&s_wifi_cfg); }
            set_wifi_cfg_status_text("Scan fehlgeschlagen", lv_color_hex(0xFCA5A5));
            return;
        }

        if (ap_count == 0) {
            strncpy(s_wifi_scan_options, "Kein Netzwerk gefunden", sizeof(s_wifi_scan_options) - 1);
            s_wifi_scan_options[sizeof(s_wifi_scan_options) - 1] = '\0';
            wifi_set_dropdown_options(s_wifi_scan_options);
            s_wifi_scan_in_progress = false;
            if (s_wifi_cfg.ssid[0] != '\0') { wifi_connect_from_cfg(&s_wifi_cfg); }
            set_wifi_cfg_status_text("Kein Netzwerk gefunden", lv_color_hex(0xFCA5A5));
            return;
        }

        if (ap_count > 30) {
            ap_count = 30;
        }

        ap_records = calloc(ap_count, sizeof(wifi_ap_record_t));
        if (ap_records == NULL) {
            s_wifi_scan_in_progress = false;
            if (s_wifi_cfg.ssid[0] != '\0') { wifi_connect_from_cfg(&s_wifi_cfg); }
            set_wifi_cfg_status_text("Zu wenig RAM fuer Scan", lv_color_hex(0xFCA5A5));
            return;
        }

        if (esp_wifi_scan_get_ap_records(&ap_count, ap_records) != ESP_OK) {
            free(ap_records);
            s_wifi_scan_in_progress = false;
            if (s_wifi_cfg.ssid[0] != '\0') { wifi_connect_from_cfg(&s_wifi_cfg); }
            set_wifi_cfg_status_text("AP-Liste Fehler", lv_color_hex(0xFCA5A5));
            return;
        }

        s_wifi_scan_options[0] = '\0';
        for (uint16_t i = 0; i < ap_count; i++) {
            const char *ssid = (const char *)ap_records[i].ssid;
            if (ssid[0] == '\0') {
                continue;
            }

            if (s_wifi_scan_options[0] != '\0') {
                strncat(s_wifi_scan_options, "\n", sizeof(s_wifi_scan_options) - strlen(s_wifi_scan_options) - 1);
            }
            strncat(s_wifi_scan_options, ssid, sizeof(s_wifi_scan_options) - strlen(s_wifi_scan_options) - 1);
        }

        if (s_wifi_scan_options[0] == '\0') {
            strncpy(s_wifi_scan_options, "Kein Netzwerk gefunden", sizeof(s_wifi_scan_options) - 1);
            s_wifi_scan_options[sizeof(s_wifi_scan_options) - 1] = '\0';
        }

        free(ap_records);
        wifi_set_dropdown_options(s_wifi_scan_options);
        set_wifi_cfg_status_text("Scan abgeschlossen", lv_color_hex(0x86EFAC));
        /* Scan abgeschlossen: Flag loeschen und Verbindung neu aufbauen */
        s_wifi_scan_in_progress = false;
        if (s_wifi_cfg.ssid[0] != '\0') {
            wifi_connect_from_cfg(&s_wifi_cfg);
        }
    }
}

/* WLAN im STA-Modus initialisieren und erste Verbindung starten */
static esp_err_t wifi_init_sta(void)
{
    ESP_RETURN_ON_ERROR(esp_netif_init(), TAG, "esp_netif init failed");

    esp_err_t err = esp_event_loop_create_default();
    if ((err != ESP_OK) && (err != ESP_ERR_INVALID_STATE)) {
        return err;
    }

    s_wifi_netif = esp_netif_create_default_wifi_sta();
    ESP_RETURN_ON_FALSE(s_wifi_netif != NULL, ESP_FAIL, TAG, "create default wifi sta failed");

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_RETURN_ON_ERROR(esp_wifi_init(&cfg), TAG, "esp_wifi_init failed");
    ESP_RETURN_ON_ERROR(esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL, &s_wifi_evt_instance), TAG, "register WIFI handler failed");
    ESP_RETURN_ON_ERROR(esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &wifi_event_handler, NULL, &s_ip_evt_instance), TAG, "register IP handler failed");
    ESP_RETURN_ON_ERROR(esp_wifi_set_storage(WIFI_STORAGE_RAM), TAG, "wifi storage failed");
    ESP_RETURN_ON_ERROR(esp_wifi_set_mode(WIFI_MODE_STA), TAG, "wifi mode set failed");
    ESP_RETURN_ON_ERROR(esp_wifi_start(), TAG, "wifi start failed");

    if (s_wifi_cfg.ssid[0] == '\0') {
        set_status_text("WLAN nicht konfiguriert", lv_color_hex(0xFDE68A));
        return ESP_OK;
    }

    return wifi_connect_from_cfg(&s_wifi_cfg);
}

/* Setup-Request (Erstregistrierung) einreihen, falls noch kein Token vorhanden */
static bool enqueue_setup_request_if_needed(void)
{
    auth_request_t req = {0};

    if (auth_has_token() || s_auth_busy || (s_auth_req_queue == NULL)) {
        return false;
    }

    if (s_auth_cfg.mac[0] == '\0') {
        if (get_device_mac_text(s_auth_cfg.mac, sizeof(s_auth_cfg.mac)) != ESP_OK) {
            set_status_text("MAC Lesen fehlgeschlagen", lv_color_hex(0xFCA5A5));
            return false;
        }
        auth_cfg_save(&s_auth_cfg);
    }

    req.source = AUTH_SRC_SETUP;
    strncpy(req.value_a, s_auth_cfg.mac, sizeof(req.value_a) - 1);
    if (!enqueue_auth_request(&req)) {
        set_status_text("Setup Queue voll", lv_color_hex(0xFCA5A5));
        return false;
    }

    set_auth_busy(true);
    s_setup_last_attempt_us = esp_timer_get_time();
    set_status_text("Geraet wird registriert...", lv_color_hex(0xFDE68A));
    return true;
}

/* Heartbeat-Request einreihen zur periodischen Token-Validierung */
static bool enqueue_token_check_request_if_needed(void)
{
    auth_request_t req = {0};

    if (!auth_has_token() || s_auth_busy || (s_auth_req_queue == NULL)) {
        return false;
    }

    req.source = AUTH_SRC_HEARTBEAT;
    if (!enqueue_auth_request(&req)) {
        return false;
    }

    set_auth_busy(true);
    set_status_text("Token wird geprueft...", lv_color_hex(0x93C5FD));
    return true;
}

/* Label-Text und Farbe setzen (ohne Display-Lock, Aufrufer muss locken) */
static void set_label_text_color(lv_obj_t *label, const char *text, lv_color_t color)
{
    if (!label) {
        return;
    }
    lv_label_set_text(label, text);
    lv_obj_set_style_text_color(label, color, 0);
}

/* Haupt-Statustext auf Startseite setzen (mit Display-Lock) */
static void set_status_text(const char *text, lv_color_t color)
{
    if (s_ui.status_label && bsp_display_lock(30)) {
        set_label_text_color(s_ui.status_label, text, color);
        bsp_display_unlock();
    }
}

/* NFC-UID-Anzeigetext setzen (mit Display-Lock) */
static void set_nfc_uid_text(const char *text, lv_color_t color)
{
    if (s_ui.nfc_uid_label && bsp_display_lock(30)) {
        set_label_text_color(s_ui.nfc_uid_label, text, color);
        bsp_display_unlock();
    }
}

/* ════════════════════════════════════════════════════════════════════════════
 * View-Management: Wechsel zwischen Start-, PIN- und Ergebnis-Ansicht.
 * show_result_page() zeigt Erfolg/Fehler und startet 60s Auto-Return-Timer.
 * ════════════════════════════════════════════════════════════════════════════ */

/* Zwischen Start-, PIN- und Ergebnis-Ansicht umschalten */
static void show_view(app_view_t view)
{
    s_current_view = view;
    if (!bsp_display_lock(100)) {
        return;
    }

    if (s_ui.start_container) {
        if (view == APP_VIEW_START) {
            lv_obj_clear_flag(s_ui.start_container, LV_OBJ_FLAG_HIDDEN);
        } else {
            lv_obj_add_flag(s_ui.start_container, LV_OBJ_FLAG_HIDDEN);
        }
    }

    if (s_ui.pin_container) {
        if (view == APP_VIEW_PIN) {
            if (s_ui.pin_ta) {
                lv_textarea_set_text(s_ui.pin_ta, "");
            }
            lv_obj_clear_flag(s_ui.pin_container, LV_OBJ_FLAG_HIDDEN);
        } else {
            lv_obj_add_flag(s_ui.pin_container, LV_OBJ_FLAG_HIDDEN);
        }
    }

    if (s_ui.result_container) {
        if (view == APP_VIEW_RESULT) {
            lv_obj_clear_flag(s_ui.result_container, LV_OBJ_FLAG_HIDDEN);
        } else {
            lv_obj_add_flag(s_ui.result_container, LV_OBJ_FLAG_HIDDEN);
        }
    }

    bsp_display_unlock();
}

/* Timer-Callback: Nach 60s automatisch zum Startbildschirm zurückkehren */
static void auto_return_timer_cb(lv_timer_t *timer)
{
    LV_UNUSED(timer);
    s_auto_return_timer = NULL;
    s_register_card_mode = false;
    s_offer_card_registration = false;
    if (s_current_view != APP_VIEW_START) {
        s_pause_nfc_polling = false;
        s_reset_nfc_uid_requested = true;
        show_view(APP_VIEW_START);
        set_nfc_uid_text("NFC UID: -", lv_color_hex(0x86EFAC));
        set_status_text("Bitte HSD Karte anlegen", lv_color_hex(0x93C5FD));
    }
}

/* Erfolgs-/Fehlerseite anzeigen und Auto-Return-Timer starten */
static void show_result_page(bool granted, const char *text)
{
    if (!bsp_display_lock(100)) {
        return;
    }

    if (granted) {
        set_label_text_color(s_ui.result_icon_label, LV_SYMBOL_OK, lv_color_hex(0x22C55E));
        set_label_text_color(s_ui.result_text_label, text, lv_color_hex(0x86EFAC));
    } else {
        set_label_text_color(s_ui.result_icon_label, LV_SYMBOL_CLOSE, lv_color_hex(0xEF4444));
        set_label_text_color(s_ui.result_text_label, text, lv_color_hex(0xFCA5A5));
    }

    if (s_ui.register_card_btn) {
        if (granted && s_offer_card_registration) {
            lv_obj_clear_flag(s_ui.register_card_btn, LV_OBJ_FLAG_HIDDEN);
        } else {
            lv_obj_add_flag(s_ui.register_card_btn, LV_OBJ_FLAG_HIDDEN);
        }
    }

    bsp_display_unlock();
    show_view(APP_VIEW_RESULT);

    /* Auto-return to start screen after 60 seconds */
    if (s_auto_return_timer) {
        lv_timer_del(s_auto_return_timer);
    }
    s_auto_return_timer = lv_timer_create(auto_return_timer_cb, 60000, NULL);
    lv_timer_set_repeat_count(s_auto_return_timer, 1);
}

/* Auth-Request in die FreeRTOS-Queue einreihen */
static bool enqueue_auth_request(const auth_request_t *req)
{
    if (!s_auth_req_queue) {
        return false;
    }
    return xQueueSend(s_auth_req_queue, req, 0) == pdTRUE;
}

/* Prüft ob Server-Antwort ein positives Ergebnis ("valid":true usw.) enthält */
static bool response_is_true(const char *resp)
{
    const char *pos = NULL;

    if ((resp == NULL) || (resp[0] == '\0')) {
        return false;
    }

    if (strstr(resp, "\"result\":true") || strstr(resp, "\"allowed\":true") || strstr(resp, "\"success\":true") || strstr(resp, "\"valid\":true")) {
        return true;
    }

    if ((strcmp(resp, "true") == 0) || (strcmp(resp, "{\"result\":true}") == 0) || (strcmp(resp, "{\"valid\":true}") == 0)) {
        return true;
    }

    pos = strstr(resp, "\"valid\"");
    if (pos != NULL) {
        pos = strchr(pos, ':');
        if (pos != NULL) {
            pos++;
            while ((*pos != '\0') && isspace((unsigned char)*pos)) {
                pos++;
            }
            if (strncmp(pos, "true", 4) == 0) {
                return true;
            }
        }
    }

    return false;
}

/* ════════════════════════════════════════════════════════════════════════════
 * JSON-Parsing: Leichtgewichtige Parser für Server-Antworten ohne externe
 * JSON-Bibliothek – extrahiert Strings, Bools, Floats und Ints aus Antworten.
 * ════════════════════════════════════════════════════════════════════════════ */

/* String-Wert aus JSON-Antwort anhand des Schlüssels extrahieren */
static bool extract_json_string(const char *resp, const char *key, char *out, size_t out_size)
{
    char needle[40] = {0};
    const char *start = NULL;
    const char *cursor = NULL;
    const char *end = NULL;
    size_t len = 0;

    if ((resp == NULL) || (key == NULL) || (out == NULL) || (out_size < 2)) {
        return false;
    }

    snprintf(needle, sizeof(needle), "\"%s\"", key);
    start = strstr(resp, needle);
    if (start == NULL) {
        return false;
    }

    cursor = start + strlen(needle);
    cursor = strchr(cursor, ':');
    if (cursor == NULL) {
        return false;
    }

    cursor++;
    while ((*cursor != '\0') && isspace((unsigned char)*cursor)) {
        cursor++;
    }
    if (*cursor != '"') {
        return false;
    }

    start = cursor + 1;
    end = strchr(start, '"');
    if (end == NULL) {
        return false;
    }

    len = (size_t)(end - start);
    if (len >= out_size) {
        len = out_size - 1;
    }

    memcpy(out, start, len);
    out[len] = '\0';
    return len > 0;
}

/* Boolean-Wert aus JSON-Antwort extrahieren (true/false) */
static bool extract_json_bool(const char *resp, const char *key)
{
    char needle[40] = {0};
    const char *pos = NULL;

    if ((resp == NULL) || (key == NULL)) {
        return false;
    }

    snprintf(needle, sizeof(needle), "\"%s\"", key);
    pos = strstr(resp, needle);
    if (pos == NULL) {
        return false;
    }

    pos = strchr(pos + strlen(needle), ':');
    if (pos == NULL) {
        return false;
    }

    pos++;
    while ((*pos != '\0') && isspace((unsigned char)*pos)) {
        pos++;
    }
    return strncmp(pos, "true", 4) == 0;
}

/* Float-Wert aus JSON-Antwort extrahieren, mit Fallback-Wert */
static float extract_json_float(const char *resp, const char *key, float fallback)
{
    char needle[40] = {0};
    const char *pos = NULL;

    if ((resp == NULL) || (key == NULL)) {
        return fallback;
    }

    snprintf(needle, sizeof(needle), "\"%s\"", key);
    pos = strstr(resp, needle);
    if (pos == NULL) {
        return fallback;
    }

    pos = strchr(pos + strlen(needle), ':');
    if (pos == NULL) {
        return fallback;
    }

    pos++;
    while ((*pos != '\0') && isspace((unsigned char)*pos)) {
        pos++;
    }

    char *end = NULL;
    float val = strtof(pos, &end);
    if (end == pos) {
        return fallback;
    }
    return val;
}

/* Integer-Wert aus JSON-Antwort extrahieren, mit Fallback-Wert */
static int extract_json_int(const char *resp, const char *key, int fallback)
{
    char needle[40] = {0};
    const char *pos = NULL;

    if ((resp == NULL) || (key == NULL)) {
        return fallback;
    }

    snprintf(needle, sizeof(needle), "\"%s\"", key);
    pos = strstr(resp, needle);
    if (pos == NULL) {
        return fallback;
    }

    pos = strchr(pos + strlen(needle), ':');
    if (pos == NULL) {
        return fallback;
    }

    pos++;
    while ((*pos != '\0') && isspace((unsigned char)*pos)) {
        pos++;
    }

    char *end = NULL;
    long val = strtol(pos, &end, 10);
    if (end == pos) {
        return fallback;
    }
    return (int)val;
}

/* Bridge-Konfiguration (Maschinenname, Standort etc.) aus Server-JSON parsen */
static void parse_bridge_config_from_response(const char *resp)
{
    if ((resp == NULL) || (resp[0] == '\0')) {
        return;
    }

    /* Look for "config" object in response */
    const char *cfg_start = strstr(resp, "\"config\"");
    if (cfg_start == NULL) {
        return;
    }

    extract_json_string(resp, "machine_name", s_bridge_cfg.machine_name, sizeof(s_bridge_cfg.machine_name));
    extract_json_string(resp, "location", s_bridge_cfg.location, sizeof(s_bridge_cfg.location));
    extract_json_string(resp, "info_url", s_bridge_cfg.info_url, sizeof(s_bridge_cfg.info_url));
    s_bridge_cfg.idle_current = extract_json_float(resp, "idle_current", 0.0f);
    s_bridge_cfg.sound_enabled = extract_json_bool(resp, "sound_enabled") ? 1 : 0;
    s_bridge_cfg.idle_detection_enabled = extract_json_bool(resp, "idle_detection_enabled") ? 1 : 0;
    s_bridge_cfg.otp_required = extract_json_bool(resp, "otp_required") ? 1 : 0;
    s_bridge_cfg.unlock_duration_min = (uint32_t)extract_json_int(resp, "unlock_duration", 30);
    s_bridge_cfg.config_version = (uint32_t)extract_json_int(resp, "config_version", 0);
    s_bridge_cfg.auto_ota = extract_json_bool(resp, "auto_ota") ? 1 : 0;

    /* Server-seitiger idle_current ueberschreibt auch den lokalen Messwert,
     * damit der Admin-Wert persistent als naechste Heartbeat-Payload genutzt wird. */
    if (s_bridge_cfg.idle_current > 0.0f) {
        s_idle_current_measured_mV = s_bridge_cfg.idle_current;
    }

    s_bridge_cfg_updated = true;
    ESP_LOGI(TAG, "Bridge config parsed: name=%s loc=%s url=%s idle=%.2f sound=%d idle_det=%d ver=%lu",
             s_bridge_cfg.machine_name, s_bridge_cfg.location, s_bridge_cfg.info_url,
             s_bridge_cfg.idle_current, s_bridge_cfg.sound_enabled,
             s_bridge_cfg.idle_detection_enabled, (unsigned long)s_bridge_cfg.config_version);
}

/* ════════════════════════════════════════════════════════════════════════════
 * HTTPS-Client: Sendet JSON-POST-Requests an den LiMa Server.
 * Fängt Response-Body und X-Bridge-Token-Header ab. Unterstützt Retry.
 * ════════════════════════════════════════════════════════════════════════════ */

/* HTTPS POST mit JSON-Payload an LiMa Server; liest Response + Token-Header */
static esp_err_t https_post_json(const char *url, const char *payload, int *http_status, bool *ok, char *response_out, size_t response_out_size, char *token_out, size_t token_out_size)
{
    char response[512] = {0};
    http_capture_t capture = {
        .response = response,
        .response_size = sizeof(response),
        .response_len = 0,
        .token = token_out,
        .token_size = token_out_size,
    };
    esp_err_t err = ESP_OK;
    if (http_status) {
        *http_status = 0;
    }
    if (ok) {
        *ok = false;
    }

    esp_http_client_config_t cfg = {
        .url = url,
        .method = HTTP_METHOD_POST,
        .transport_type = HTTP_TRANSPORT_OVER_SSL,
        .timeout_ms = 8000,
        .crt_bundle_attach = esp_crt_bundle_attach,  /* Let's Encrypt via ESP-IDF Mozilla-Bundle */
        .event_handler = http_capture_event_handler,
        .user_data = &capture,
    };

    esp_http_client_handle_t client = esp_http_client_init(&cfg);
    if (client == NULL) {
        ESP_LOGW(TAG, "HTTP client init failed (soft fail)");
        return ESP_OK;
    }

    err = esp_http_client_set_header(client, "Content-Type", "application/json");
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "set header failed (soft fail): %s", esp_err_to_name(err));
        esp_http_client_cleanup(client);
        return ESP_OK;
    }

    err = esp_http_client_set_post_field(client, payload, (int)strlen(payload));
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "set post failed (soft fail): %s", esp_err_to_name(err));
        esp_http_client_cleanup(client);
        return ESP_OK;
    }

    err = esp_http_client_perform(client);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "HTTP perform failed (soft fail): %s", esp_err_to_name(err));
        esp_http_client_cleanup(client);
        return ESP_OK;
    }

    if (http_status) {
        *http_status = esp_http_client_get_status_code(client);
    }
    ESP_LOGI(TAG, "HTTP read bytes=%u content_length=%lld", (unsigned)capture.response_len, (long long)esp_http_client_get_content_length(client));

    if (ok && http_status) {
        *ok = ((*http_status >= 200) && (*http_status < 300) && response_is_true(response));
    }
    if ((response_out != NULL) && (response_out_size > 0)) {
        strncpy(response_out, response, response_out_size - 1);
        response_out[response_out_size - 1] = '\0';
    }
    esp_http_client_cleanup(client);
    return ESP_OK;
}

/* ════════════════════════════════════════════════════════════════════════════
 * Auth-Worker-Task: Läuft als FreeRTOS-Task, empfängt Auth-Requests aus der
 * Queue, baut JSON-Payloads, führt HTTPS-Calls aus und schickt Ergebnisse
 * zurück in die Response-Queue. Wird vom LVGL-Timer ausgewertet.
 *
 * Request-Routing nach auth_source_t:
 *   SETUP           → /api/hsd/setup          (MAC → Token)
 *   HEARTBEAT       → /api/hsd/heartbeat      (Status + Config-Sync)
 *   NFC             → /api/hsd/nfc            (UID-Prüfung)
 *   LOGIN           → /api/hsd/login          (E-Mail + Passwort)
 *   PIN             → /api/hsd/pin            (OTP-Code)
 *   REGISTER_CARD   → /api/hsd/register_card  (UID verknüpfen)
 * ════════════════════════════════════════════════════════════════════════════ */

/* Vorwaertsdeklaration – Definitionen weiter unten in der Sensor-Sektion */
static void sensors_read(void);
static void pcf8574_set_outputs(uint8_t outputs);
static int16_t ads1115_read_channel(uint8_t ch);

static void auth_worker_task(void *arg)
{
    LV_UNUSED(arg);
    auth_request_t req = {0};
    auth_result_t res = {0};
    ESP_LOGI(TAG, "auth_worker started on core %d", (int)xPortGetCoreID());

    while (1) {
        if (xQueueReceive(s_auth_req_queue, &req, portMAX_DELAY) != pdTRUE) {
            continue;
        }

        char payload[512] = {0};
        char response[512] = {0};
        const char *url = AUTH_URL_NFC;

        res.source = req.source;
        res.success = false;
        res.pin_required = false;
        res.http_status = 0;
        res.unlock_duration_min = 0;
        res.token[0] = '\0';

        if (req.source == AUTH_SRC_SETUP) {
            snprintf(payload, sizeof(payload), "{\"mac\":\"%s\",\"fw_version\":\"" APP_VERSION "\"}", req.value_a);
            url = AUTH_URL_SETUP;
        } else if (req.source == AUTH_SRC_HEARTBEAT) {
            int64_t until = s_unlock_until_us;
            int64_t now_us = esp_timer_get_time();
            bool unlocked = (until > 0) && (until > now_us);
            int remaining_min = unlocked ? (int)((until - now_us) / 60000000) : 0;
            sensors_read();  /* ADS1115 + PCF8574T vor Payload lesen (~62 ms) */
            char idle_part[48] = "";
            if (s_idle_current_measured_mV >= 0.0f) {
                snprintf(idle_part, sizeof(idle_part), ",\"idle_current_mV\":%.3f", s_idle_current_measured_mV);
            }
            snprintf(payload, sizeof(payload),
                     "{\"token\":\"%s\",\"config_version\":%lu,\"unlock_status\":\"%s\",\"unlock_remaining_min\":%d,\"fw_version\":\"" APP_VERSION "\",\"ads\":[%d,%d,%d,%d],\"pcf\":%u%s}",
                     s_auth_cfg.token, (unsigned long)s_bridge_cfg.config_version,
                     unlocked ? "unlocked" : "locked", remaining_min,
                     (int)s_ads_raw[0], (int)s_ads_raw[1], (int)s_ads_raw[2], (int)s_ads_raw[3],
                     (unsigned)s_pcf_input, idle_part);
            url = AUTH_URL_HEARTBEAT;
        } else if (req.source == AUTH_SRC_NFC) {
            snprintf(payload, sizeof(payload), "{\"token\":\"%s\",\"uid\":\"%s\"}", s_auth_cfg.token, req.value_a);
            url = AUTH_URL_NFC;
        } else if (req.source == AUTH_SRC_LOGIN) {
            snprintf(payload, sizeof(payload), "{\"token\":\"%s\",\"email\":\"%s\",\"password\":\"%s\"}", s_auth_cfg.token, req.value_a, req.value_b);
            url = AUTH_URL_LOGIN;
        } else if (req.source == AUTH_SRC_REGISTER_CARD) {
            snprintf(payload, sizeof(payload), "{\"token\":\"%s\",\"uid\":\"%s\"}", s_auth_cfg.token, req.value_a);
            url = AUTH_URL_REGISTER_CARD;
        } else {
            snprintf(payload, sizeof(payload), "{\"token\":\"%s\",\"pin\":\"%s\"}", s_auth_cfg.token, req.value_a);
            url = AUTH_URL_PIN;
        }

        bool ok = false;
        esp_err_t err = ESP_OK;
        for (int attempt = 0; attempt <= AUTH_HTTP_RETRY_COUNT; attempt++) {
            response[0] = '\0';
            err = https_post_json(url, payload, &res.http_status, &ok, response, sizeof(response), res.token, sizeof(res.token));
            res.success = (err == ESP_OK) && ok;

            if ((req.source == AUTH_SRC_SETUP) && (s_setup_log_verbose || !ok)) {
                ESP_LOGI(TAG, "Setup attempt=%d status=%d ok=%d response=%s token_hdr=%s", attempt, res.http_status, (int)ok, response, res.token);
            }

            if ((req.source == AUTH_SRC_SETUP) && res.success) {
                if ((res.token[0] == '\0') && !extract_json_string(response, "token", res.token, sizeof(res.token))) {
                    ESP_LOGW(TAG, "Setup response without token: %s", response);
                    res.success = false;
                }
                if (res.success) {
                    if (extract_json_bool(response, "configured")) {
                        parse_bridge_config_from_response(response);
                    } else if (s_bridge_cfg.config_version > 0) {
                        ESP_LOGW(TAG, "Server reports unconfigured, clearing local config");
                        bridge_cfg_set_defaults(&s_bridge_cfg);
                        s_bridge_cfg_updated = true;
                    }
                }
            }
            if ((req.source == AUTH_SRC_HEARTBEAT) && res.success) {
                if (extract_json_bool(response, "config_changed")) {
                    parse_bridge_config_from_response(response);
                }
            }
            if (((req.source == AUTH_SRC_NFC) || (req.source == AUTH_SRC_LOGIN)) && res.success) {
                res.pin_required = extract_json_bool(response, "pin_required");
            }
            if (res.success) {
                int dur = extract_json_int(response, "unlock_duration", 0);
                if (dur > 0) {
                    res.unlock_duration_min = (uint32_t)dur;
                }
            }
            if (res.success || (res.http_status > 0)) {
                break;
            }

            if (attempt < AUTH_HTTP_RETRY_COUNT) {
                ESP_LOGW(TAG, "HTTP retry %d/%d (server unreachable)", attempt + 1, AUTH_HTTP_RETRY_COUNT);
                vTaskDelay(pdMS_TO_TICKS(AUTH_HTTP_RETRY_DELAY_MS));
            }
        }

        if (err != ESP_OK) {
            ESP_LOGW(TAG, "HTTPS request ended with error: %s", esp_err_to_name(err));
            res.success = false;
        }

        if (xQueueSend(s_auth_res_queue, &res, 0) != pdTRUE) {
            ESP_LOGW(TAG, "Auth result queue full, clearing busy state");
            set_auth_busy(false);
        }
    }
}

/* Maschinenname, Standort und QR-Code in der GUI aktualisieren */
static void update_machine_info_ui(void)
{
    if (s_ui.machine_name_label) {
        if (s_bridge_cfg.machine_name[0]) {
            lv_label_set_text(s_ui.machine_name_label, s_bridge_cfg.machine_name);
            lv_obj_clear_flag(s_ui.machine_name_label, LV_OBJ_FLAG_HIDDEN);
        } else {
            lv_obj_add_flag(s_ui.machine_name_label, LV_OBJ_FLAG_HIDDEN);
        }
    }
    if (s_ui.location_label) {
        if (s_bridge_cfg.location[0]) {
            lv_label_set_text(s_ui.location_label, s_bridge_cfg.location);
            lv_obj_clear_flag(s_ui.location_label, LV_OBJ_FLAG_HIDDEN);
        } else {
            lv_obj_add_flag(s_ui.location_label, LV_OBJ_FLAG_HIDDEN);
        }
    }
#if LV_USE_QRCODE
    if (s_ui.qr_code) {
        if (s_bridge_cfg.info_url[0]) {
            lv_qrcode_update(s_ui.qr_code, s_bridge_cfg.info_url, strlen(s_bridge_cfg.info_url));
            lv_obj_clear_flag(s_ui.qr_code, LV_OBJ_FLAG_HIDDEN);
        } else {
            lv_obj_add_flag(s_ui.qr_code, LV_OBJ_FLAG_HIDDEN);
        }
    }
#endif
}

/* ════════════════════════════════════════════════════════════════════════════
 * Auth-Result-Timer: LVGL-Timer (100ms), liest Ergebnisse aus der Response-Queue
 * und reagiert je nach Quelle: Token speichern, Freischaltung aktivieren,
 * PIN-Seite zeigen, Ergebnis anzeigen, Kartenregistrierung bestätigen.
 * Läuft im LVGL-Kontext (Core 1) – darf UI-Elemente direkt ändern.
 * ════════════════════════════════════════════════════════════════════════════ */

/* Vorwaertsdeklaration (Definition weiter unten, nach OTA-Sektion) */
static void auto_ota_task(void *arg);

static void auth_result_timer_cb(lv_timer_t *timer)
{
    LV_UNUSED(timer);
    auth_result_t res = {0};

    while (xQueueReceive(s_auth_res_queue, &res, 0) == pdTRUE) {
        set_auth_busy(false);
        bool server_unreachable = (res.http_status <= 0);

        /* Save bridge config if updated by worker task */
        if (s_bridge_cfg_updated) {
            s_bridge_cfg_updated = false;
            bridge_cfg_save(&s_bridge_cfg);
            update_machine_info_ui();
            ESP_LOGI(TAG, "Bridge config saved to NVS (ver=%lu)", (unsigned long)s_bridge_cfg.config_version);
        }

        if (res.source == AUTH_SRC_SETUP) {
            if (res.success && (res.token[0] != '\0')) {
                strncpy(s_auth_cfg.token, res.token, sizeof(s_auth_cfg.token) - 1);
                s_auth_cfg.token[sizeof(s_auth_cfg.token) - 1] = '\0';
                auth_cfg_save(&s_auth_cfg);
                s_setup_log_verbose = false;
                ESP_LOGI(TAG, "Setup success, token stored: %s", s_auth_cfg.token);
                if (s_bridge_cfg.config_version > 0) {
                    set_status_text("Geraet registriert", lv_color_hex(0x86EFAC));
                } else {
                    set_status_text("Registriert, unkonfiguriert", lv_color_hex(0xFDE68A));
                }
                if (s_bridge_cfg.auto_ota && !s_auto_ota_in_progress) {
                    s_auto_ota_in_progress = true;
                    xTaskCreatePinnedToCore(auto_ota_task, "auto_ota", 8192, NULL, 4, NULL, AUTH_TASK_CORE_ID);
                }
            } else if (server_unreachable) {
                ESP_LOGW(TAG, "Setup failed: server unreachable (http_status=%d)", res.http_status);
                set_status_text("Setup Server nicht erreichbar", lv_color_hex(0xFCA5A5));
            } else {
                ESP_LOGW(TAG, "Setup failed: token missing or valid=false (http_status=%d)", res.http_status);
                set_status_text("Setup fehlgeschlagen", lv_color_hex(0xFCA5A5));
            }
            continue;
        }

        if (res.source == AUTH_SRC_HEARTBEAT) {
            if (res.success) {
                if (s_bridge_cfg.config_version > 0) {
                    ESP_LOGI(TAG, "Heartbeat OK (konfiguriert)");
                    set_status_text("Token gueltig", lv_color_hex(0x86EFAC));
                } else {
                    ESP_LOGI(TAG, "Heartbeat OK (unkonfiguriert)");
                    set_status_text("Registriert, unkonfiguriert", lv_color_hex(0xFDE68A));
                }
                if (s_bridge_cfg.auto_ota && !s_auto_ota_in_progress) {
                    s_auto_ota_in_progress = true;
                    xTaskCreatePinnedToCore(auto_ota_task, "auto_ota", 8192, NULL, 4, NULL, AUTH_TASK_CORE_ID);
                }
            } else if ((res.http_status >= 400) && (res.http_status < 500)) {
                ESP_LOGW(TAG, "Stored token invalid (http_status=%d), re-registering", res.http_status);
                s_auth_cfg.token[0] = '\0';
                auth_cfg_save(&s_auth_cfg);
                s_setup_log_verbose = true;
                s_setup_last_attempt_us = 0;
                set_status_text("Token ungueltig, registriere neu...", lv_color_hex(0xFCA5A5));
                enqueue_setup_request_if_needed();
            } else if (server_unreachable) {
                ESP_LOGW(TAG, "Heartbeat: server unreachable");
                set_status_text("Server nicht erreichbar", lv_color_hex(0xFCA5A5));
            } else {
                ESP_LOGW(TAG, "Heartbeat failed (http_status=%d)", res.http_status);
            }
            continue;
        }

        if (res.source == AUTH_SRC_REGISTER_CARD) {
            s_register_card_mode = false;
            if (res.success) {
                beep(2);
                show_result_page(true, "Karte registriert");
            } else if (server_unreachable) {
                show_result_page(false, "Server nicht erreichbar");
            } else {
                beep(3);
                show_result_page(false, "Registrierung fehlgeschlagen");
            }
            continue;
        }

        if (res.source == AUTH_SRC_PIN) {
            if (res.success) {
                beep(2);
                activate_unlock(res.unlock_duration_min);
                s_offer_card_registration = s_auth_origin_login;
                show_result_page(true, "Freigeschaltet");
            } else if (server_unreachable) {
                show_result_page(false, "Server nicht erreichbar");
            } else {
                beep(3);
                show_result_page(false, "Falsche Eingabe");
            }
            continue;
        }

        if (res.success) {
            if (res.pin_required) {
                s_auth_origin_login = (res.source == AUTH_SRC_LOGIN);
                beep(1);
                show_view(APP_VIEW_PIN);
                set_status_text("Code eingeben", lv_color_hex(0x93C5FD));
            } else {
                beep(2);
                activate_unlock(res.unlock_duration_min);
                s_offer_card_registration = (res.source == AUTH_SRC_LOGIN);
                show_result_page(true, "Freigeschaltet");
            }
        } else if (server_unreachable) {
            show_result_page(false, "Server nicht erreichbar");
        } else {
            beep(3);
            show_result_page(false, "Verweigert");
        }
    }
}

/* Tastatur-Event: Ready/Cancel → Tastatur ausblenden */
static void keyboard_event_cb(lv_event_t *event)
{
    lv_event_code_t code = lv_event_get_code(event);
    if ((code == LV_EVENT_READY) || (code == LV_EVENT_CANCEL)) {
        lv_keyboard_set_textarea(s_ui.keyboard, NULL);
        lv_obj_add_flag(s_ui.keyboard, LV_OBJ_FLAG_HIDDEN);
    }
}

/* Textarea-Fokus → Tastatur ein-/ausblenden */
static void textarea_focus_event_cb(lv_event_t *event)
{
    lv_event_code_t code = lv_event_get_code(event);
    lv_obj_t *ta = lv_event_get_target(event);

    if (code == LV_EVENT_FOCUSED) {
        lv_keyboard_set_textarea(s_ui.keyboard, ta);
        lv_obj_clear_flag(s_ui.keyboard, LV_OBJ_FLAG_HIDDEN);
    } else if (code == LV_EVENT_DEFOCUSED) {
        lv_keyboard_set_textarea(s_ui.keyboard, NULL);
        lv_obj_add_flag(s_ui.keyboard, LV_OBJ_FLAG_HIDDEN);
    }
}

/* Auge-Button: Passwort-Sichtbarkeit umschalten.
 * user_data des Events zeigt auf das zugehoerige lv_textarea. */
static void pwd_toggle_event_cb(lv_event_t *event)
{
    lv_obj_t *btn = lv_event_get_target(event);
    lv_obj_t *ta  = (lv_obj_t *)lv_event_get_user_data(event);
    if (ta == NULL) {
        return;
    }
    bool hidden = lv_textarea_get_password_mode(ta);
    lv_textarea_set_password_mode(ta, !hidden);
    /* Symbol je nach Zustand aktualisieren */
    lv_obj_t *lbl = lv_obj_get_child(btn, 0);
    if (lbl) {
        lv_label_set_text(lbl, hidden ? LV_SYMBOL_EYE_CLOSE : LV_SYMBOL_EYE_OPEN);
    }
}

/* Zurück-Button: zum Startbildschirm, Timer und Flags zurücksetzen */
static void back_to_start_event_cb(lv_event_t *event)
{
    LV_UNUSED(event);
    /* Cancel auto-return timer if user navigates manually */
    if (s_auto_return_timer) {
        lv_timer_del(s_auto_return_timer);
        s_auto_return_timer = NULL;
    }
    s_register_card_mode = false;
    s_offer_card_registration = false;
    s_pause_nfc_polling = false;
    s_reset_nfc_uid_requested = true;
    show_view(APP_VIEW_START);
    set_nfc_uid_text("NFC UID: -", lv_color_hex(0x86EFAC));
    set_status_text("Bitte HSD Karte anlegen", lv_color_hex(0x93C5FD));
}

/* PIN-Code (6-stellig) an Server zur OTP-Prüfung senden */
static void pin_submit_event_cb(lv_event_t *event)
{
    LV_UNUSED(event);

    if (s_auth_busy) {
        return;
    }

    if (!auth_has_token()) {
        set_status_text("Geraet noch nicht registriert", lv_color_hex(0xFCA5A5));
        return;
    }

    const char *pin = lv_textarea_get_text(s_ui.pin_ta);
    if (strlen(pin) != 6) {
        set_status_text("Code muss 6-stellig sein", lv_color_hex(0xFCA5A5));
        return;
    }

    auth_request_t req = {
        .source = AUTH_SRC_PIN,
    };
    strncpy(req.value_a, pin, sizeof(req.value_a) - 1);

    if (!enqueue_auth_request(&req)) {
        set_status_text("Queue voll", lv_color_hex(0xFCA5A5));
        return;
    }

    set_auth_busy(true);
    set_status_text("Code wird geprueft...", lv_color_hex(0xFDE68A));
}

/* Numpad-Tasten verarbeiten: Ziffern, Löschen (CLR), OK → Submit */
static void pin_pad_event_cb(lv_event_t *event)
{
    lv_obj_t *obj = lv_event_get_target(event);
    const char *txt = lv_buttonmatrix_get_button_text(obj, lv_buttonmatrix_get_selected_button(obj));

    if ((txt == NULL) || (s_ui.pin_ta == NULL)) {
        return;
    }

    if (strcmp(txt, LV_SYMBOL_BACKSPACE) == 0) {
        lv_textarea_delete_char(s_ui.pin_ta);
        return;
    }

    if (strcmp(txt, "CLR") == 0) {
        lv_textarea_set_text(s_ui.pin_ta, "");
        return;
    }

    if (strcmp(txt, "OK") == 0) {
        pin_submit_event_cb(NULL);
        return;
    }

    if ((strlen(txt) == 1) && (txt[0] >= '0') && (txt[0] <= '9')) {
        lv_textarea_add_text(s_ui.pin_ta, txt);
    }
}

/* ════════════════════════════════════════════════════════════════════════════
 * NFC-Karten-Registrierung: Nach erfolgreichem Login wird dem Benutzer
 * angeboten, eine NFC-Karte mit seinem Konto zu verknüpfen.
 * Button-Klick → NFC-Polling aktivieren → UID einlesen → Server-Request.
 * ════════════════════════════════════════════════════════════════════════════ */

static void register_card_event_cb(lv_event_t *event)
{
    LV_UNUSED(event);
    if (s_auth_busy || !auth_has_token()) {
        return;
    }
    s_offer_card_registration = false;
    /* Hide the register button and update text */
    if (bsp_display_lock(100)) {
        lv_obj_add_flag(s_ui.register_card_btn, LV_OBJ_FLAG_HIDDEN);
        set_label_text_color(s_ui.result_icon_label, LV_SYMBOL_REFRESH, lv_color_hex(0xFDE68A));
        set_label_text_color(s_ui.result_text_label, "Bitte Karte anlegen...", lv_color_hex(0xFDE68A));
        bsp_display_unlock();
    }
    /* Cancel auto-return timer while waiting for card */
    if (s_auto_return_timer) {
        lv_timer_del(s_auto_return_timer);
        s_auto_return_timer = NULL;
    }
#if ENABLE_NFC
    s_register_card_mode = true;
    s_reset_nfc_uid_requested = true;
    s_pause_nfc_polling = false;
#else
    /* Simulation: directly enqueue with a simulated UID */
    static const char *sim_reg_uid = "AABBCCDD";
    auth_request_t req = { .source = AUTH_SRC_REGISTER_CARD };
    strncpy(req.value_a, sim_reg_uid, sizeof(req.value_a) - 1);
    if (enqueue_auth_request(&req)) {
        set_auth_busy(true);
        if (bsp_display_lock(100)) {
            set_label_text_color(s_ui.result_text_label, "Karte wird registriert...", lv_color_hex(0xFDE68A));
            bsp_display_unlock();
        }
    }
#endif
}

/* Login-Modal öffnen und NFC-Polling pausieren */
static void login_open_event_cb(lv_event_t *event)
{
    LV_UNUSED(event);
    s_pause_nfc_polling = true;
    if (!bsp_display_lock(100)) {
        return;
    }
    lv_obj_clear_flag(s_ui.login_modal, LV_OBJ_FLAG_HIDDEN);
    bsp_display_unlock();
}

#if !ENABLE_NFC
/* NFC-Simulation: Sendet vorgegebene UID als Auth-Request (Testmodus) */
static void sim_nfc_event_cb(lv_event_t *event)
{
    const char *uid = (const char *)lv_event_get_user_data(event);
    if (!uid || s_auth_busy || !auth_has_token()) {
        if (!auth_has_token()) {
            set_status_text("Geraet noch nicht registriert", lv_color_hex(0xFCA5A5));
        }
        return;
    }

    auth_request_t req = { .source = AUTH_SRC_NFC };
    strncpy(req.value_a, uid, sizeof(req.value_a) - 1);
    if (!enqueue_auth_request(&req)) {
        set_status_text("Queue voll", lv_color_hex(0xFCA5A5));
        return;
    }
    set_auth_busy(true);
    char msg[64];
    snprintf(msg, sizeof(msg), "NFC Sim: %s", uid);
    set_status_text(msg, lv_color_hex(0xFDE68A));
}
#endif

/* Login-Modal schließen, Tastatur ausblenden, NFC-Polling fortsetzen */
static void login_close_event_cb(lv_event_t *event)
{
    LV_UNUSED(event);
    s_pause_nfc_polling = false;
    if (!bsp_display_lock(100)) {
        return;
    }
    lv_obj_add_flag(s_ui.login_modal, LV_OBJ_FLAG_HIDDEN);
    lv_obj_add_flag(s_ui.keyboard, LV_OBJ_FLAG_HIDDEN);
    lv_keyboard_set_textarea(s_ui.keyboard, NULL);
    bsp_display_unlock();
}

/* Login-Daten (E-Mail + Passwort) an Server senden */
static void login_submit_event_cb(lv_event_t *event)
{
    LV_UNUSED(event);

    if (s_auth_busy) {
        return;
    }

    if (!auth_has_token()) {
        set_status_text("Geraet noch nicht registriert", lv_color_hex(0xFCA5A5));
        return;
    }

    const char *email = lv_textarea_get_text(s_ui.login_email_ta);
    const char *password = lv_textarea_get_text(s_ui.login_password_ta);

    if ((strlen(email) == 0) || (strlen(password) == 0)) {
        set_status_text("Login Daten fehlen", lv_color_hex(0xFCA5A5));
        return;
    }

    auth_request_t req = {
        .source = AUTH_SRC_LOGIN,
    };
    strncpy(req.value_a, email, sizeof(req.value_a) - 1);
    strncpy(req.value_b, password, sizeof(req.value_b) - 1);

    if (!enqueue_auth_request(&req)) {
        set_status_text("Queue voll", lv_color_hex(0xFCA5A5));
        return;
    }

    set_auth_busy(true);
    set_status_text("Login wird geprueft...", lv_color_hex(0xFDE68A));
    login_close_event_cb(NULL);
}

/* WLAN-Konfigurationsmodal schließen */
static void wifi_cfg_close_event_cb(lv_event_t *event)
{
    LV_UNUSED(event);
    s_pause_nfc_polling = false;
    if (!bsp_display_lock(100)) {
        return;
    }

    lv_obj_add_flag(s_ui.wifi_cfg_modal, LV_OBJ_FLAG_HIDDEN);
    lv_obj_add_flag(s_ui.keyboard, LV_OBJ_FLAG_HIDDEN);
    lv_keyboard_set_textarea(s_ui.keyboard, NULL);
    if (s_ui.unlock_indicator) {
        lv_obj_clear_flag(s_ui.unlock_indicator, LV_OBJ_FLAG_HIDDEN);
    }

    bsp_display_unlock();
}

/* WLAN-Scan starten (asynchron, Ergebnis kommt über Event) */
static void wifi_scan_event_cb(lv_event_t *event)
{
    LV_UNUSED(event);

    wifi_scan_config_t scan_cfg = {
        .show_hidden = false,
    };

    set_wifi_cfg_status_text("Scanne WLAN...", lv_color_hex(0xFDE68A));

    /* Verbindungsversuch abbrechen bevor Scan startet.
     * STA darf nicht gleichzeitig verbinden und scannen. */
    s_wifi_scan_in_progress = true;
    esp_wifi_disconnect();
    /* Kurz warten damit DISCONNECTED-Event verarbeitet wird */
    vTaskDelay(pdMS_TO_TICKS(100));

    esp_err_t err = esp_wifi_scan_start(&scan_cfg, false);
    if (err != ESP_OK) {
        s_wifi_scan_in_progress = false;
        /* Verbindung wiederherstellen falls Scan nicht startete */
        if (s_wifi_cfg.ssid[0] != '\0') {
            wifi_connect_from_cfg(&s_wifi_cfg);
        }
        set_wifi_cfg_status_text("Scan Start Fehler", lv_color_hex(0xFCA5A5));
    }
}

/* ════════════════════════════════════════════════════════════════════════════
 * OTA: Firmware-Update über den LiMa-Server per HTTPS
 * ════════════════════════════════════════════════════════════════════════════ */

/* Hilfsfunktion: OTA-Statuslabel setzen (Display-Lock intern) */
static void set_ota_status_text(const char *text, lv_color_t color)
{
    if (s_ui.ota_status_label && bsp_display_lock(50)) {
        lv_label_set_text(s_ui.ota_status_label, text);
        lv_obj_set_style_text_color(s_ui.ota_status_label, color, 0);
        bsp_display_unlock();
    }
}

/* OTA-Worker-Task: Lädt Firmware vom Server und flasht sie */
static void ota_task(void *arg)
{
    (void)arg;
    ESP_LOGI(TAG, "OTA task started, fetching firmware from %s", OTA_URL_FIRMWARE);
    set_ota_status_text("Firmware wird heruntergeladen...", lv_color_hex(0xFDE68A));

    char url_with_token[256] = {0};
    snprintf(url_with_token, sizeof(url_with_token), "%s?token=%s", OTA_URL_FIRMWARE, s_auth_cfg.token);

    esp_http_client_config_t http_cfg = {
        .url = url_with_token,
        .crt_bundle_attach = esp_crt_bundle_attach,  /* Let's Encrypt via ESP-IDF Mozilla-Bundle */
        .timeout_ms = 60000,
        .keep_alive_enable = true,
        .buffer_size = 4096,
        .buffer_size_tx = 1024,
    };

    esp_https_ota_config_t ota_cfg = {
        .http_config = &http_cfg,
    };

    esp_err_t err = esp_https_ota(&ota_cfg);
    if (err == ESP_OK) {
        ESP_LOGI(TAG, "OTA success, rebooting...");
        set_ota_status_text("Update OK - Neustart...", lv_color_hex(0x86EFAC));
        vTaskDelay(pdMS_TO_TICKS(2000));
        esp_restart();
    } else {
        ESP_LOGE(TAG, "OTA failed: %s", esp_err_to_name(err));
        set_ota_status_text("Update fehlgeschlagen!", lv_color_hex(0xFCA5A5));
        if (s_ui.ota_btn && bsp_display_lock(50)) {
            lv_obj_clear_flag(s_ui.ota_btn, LV_OBJ_FLAG_HIDDEN);
            bsp_display_unlock();
        }
    }
    vTaskDelete(NULL);
}

/* OTA-Check: Prüft beim Server ob eine neue Firmware verfügbar ist */
static void ota_check_event_cb(lv_event_t *event)
{
    LV_UNUSED(event);

    if (!s_wifi_has_ip) {
        set_ota_status_text("Kein WLAN", lv_color_hex(0xFCA5A5));
        return;
    }
    if (!auth_has_token()) {
        set_ota_status_text("Kein Token", lv_color_hex(0xFCA5A5));
        return;
    }

    set_ota_status_text("Prüfe Server...", lv_color_hex(0xFDE68A));
    if (s_ui.ota_btn && bsp_display_lock(50)) {
        lv_obj_add_flag(s_ui.ota_btn, LV_OBJ_FLAG_HIDDEN);
        bsp_display_unlock();
    }

    /* Prüfe ob neue Version verfügbar */
    char url[256] = {0};
    snprintf(url, sizeof(url), "%s?token=%s&version=%s", OTA_URL_CHECK, s_auth_cfg.token, APP_VERSION);

    char response_buf[256] = {0};
    http_capture_t cap = {
        .response = response_buf,
        .response_size = sizeof(response_buf),
        .response_len = 0,
        .token = NULL,
        .token_size = 0,
    };

    esp_http_client_config_t http_cfg = {
        .url = url,
        .crt_bundle_attach = esp_crt_bundle_attach,  /* Let's Encrypt via ESP-IDF Mozilla-Bundle */
        .timeout_ms = 10000,
        .event_handler = http_capture_event_handler,
        .user_data = &cap,
    };

    esp_http_client_handle_t client = esp_http_client_init(&http_cfg);
    if (!client) {
        set_ota_status_text("HTTP-Fehler", lv_color_hex(0xFCA5A5));
        if (s_ui.ota_btn && bsp_display_lock(50)) {
            lv_obj_clear_flag(s_ui.ota_btn, LV_OBJ_FLAG_HIDDEN);
            bsp_display_unlock();
        }
        return;
    }

    esp_err_t err = esp_http_client_perform(client);
    int status_code = esp_http_client_get_status_code(client);
    esp_http_client_cleanup(client);

    if ((err != ESP_OK) || (status_code != 200)) {
        set_ota_status_text("Server nicht erreichbar", lv_color_hex(0xFCA5A5));
        if (s_ui.ota_btn && bsp_display_lock(50)) {
            lv_obj_clear_flag(s_ui.ota_btn, LV_OBJ_FLAG_HIDDEN);
            bsp_display_unlock();
        }
        return;
    }

    /* JSON-Antwort prüfen: {"available": true, "version": "x.y.z"} */
    bool update_available = extract_json_bool(response_buf, "available");
    if (!update_available) {
        char server_version[32] = {0};
        extract_json_string(response_buf, "version", server_version, sizeof(server_version));
        char msg[64] = {0};
        if (server_version[0]) {
            snprintf(msg, sizeof(msg), "Aktuell (v%s)", server_version);
        } else {
            snprintf(msg, sizeof(msg), "Aktuell (v" APP_VERSION ")");
        }
        set_ota_status_text(msg, lv_color_hex(0x86EFAC));
        if (s_ui.ota_btn && bsp_display_lock(50)) {
            lv_obj_clear_flag(s_ui.ota_btn, LV_OBJ_FLAG_HIDDEN);
            bsp_display_unlock();
        }
        return;
    }

    /* Neue Version vorhanden – OTA-Task starten */
    char ver_msg[64] = {0};
    char new_ver[32] = {0};
    extract_json_string(response_buf, "version", new_ver, sizeof(new_ver));
    if (new_ver[0]) {
        snprintf(ver_msg, sizeof(ver_msg), "Update auf v%s...", new_ver);
    } else {
        snprintf(ver_msg, sizeof(ver_msg), "Update wird gestartet...");
    }
    set_ota_status_text(ver_msg, lv_color_hex(0xFDE68A));

    BaseType_t ota_ok = xTaskCreatePinnedToCore(ota_task, "ota_task", 8192, NULL, 4, NULL, AUTH_TASK_CORE_ID);
    if (ota_ok != pdPASS) {
        ESP_LOGE(TAG, "OTA task creation failed");
        set_ota_status_text("Task-Fehler", lv_color_hex(0xFCA5A5));
        if (s_ui.ota_btn && bsp_display_lock(50)) {
            lv_obj_clear_flag(s_ui.ota_btn, LV_OBJ_FLAG_HIDDEN);
            bsp_display_unlock();
        }
    }
}

/* Auto-OTA-Task: Wird nach Heartbeat/Setup gestartet wenn auto_ota konfiguriert.
 * Prueft Server auf neue Firmware und flasht automatisch. */
static void auto_ota_task(void *arg)
{
    (void)arg;
    ESP_LOGI(TAG, "Auto-OTA check started");

    if (!s_wifi_has_ip || !auth_has_token()) {
        s_auto_ota_in_progress = false;
        vTaskDelete(NULL);
        return;
    }

    char url[256] = {0};
    snprintf(url, sizeof(url), "%s?token=%s&version=%s", OTA_URL_CHECK, s_auth_cfg.token, APP_VERSION);

    char response_buf[256] = {0};
    http_capture_t cap = {
        .response = response_buf,
        .response_size = sizeof(response_buf),
        .response_len = 0,
        .token = NULL,
        .token_size = 0,
    };

    esp_http_client_config_t http_cfg = {
        .url = url,
        .crt_bundle_attach = esp_crt_bundle_attach,  /* Let's Encrypt via ESP-IDF Mozilla-Bundle */
        .timeout_ms = 10000,
        .event_handler = http_capture_event_handler,
        .user_data = &cap,
    };

    esp_http_client_handle_t client = esp_http_client_init(&http_cfg);
    if (!client) {
        s_auto_ota_in_progress = false;
        vTaskDelete(NULL);
        return;
    }

    esp_err_t err = esp_http_client_perform(client);
    int status_code = esp_http_client_get_status_code(client);
    esp_http_client_cleanup(client);

    if ((err != ESP_OK) || (status_code != 200)) {
        ESP_LOGW(TAG, "Auto-OTA: server not reachable (err=%d status=%d)", (int)err, status_code);
        s_auto_ota_in_progress = false;
        vTaskDelete(NULL);
        return;
    }

    bool update_available = extract_json_bool(response_buf, "available");
    if (!update_available) {
        char server_ver[32] = {0};
        extract_json_string(response_buf, "version", server_ver, sizeof(server_ver));
        ESP_LOGI(TAG, "Auto-OTA: firmware up to date (server=%s cur=" APP_VERSION ")", server_ver);
        s_auto_ota_in_progress = false;
        vTaskDelete(NULL);
        return;
    }

    char new_ver[32] = {0};
    extract_json_string(response_buf, "version", new_ver, sizeof(new_ver));
    ESP_LOGI(TAG, "Auto-OTA: update available v%s, downloading...", new_ver);
    set_ota_status_text("Auto-Update wird heruntergeladen...", lv_color_hex(0xFDE68A));

    char url_fw[256] = {0};
    snprintf(url_fw, sizeof(url_fw), "%s?token=%s", OTA_URL_FIRMWARE, s_auth_cfg.token);

    esp_http_client_config_t fw_cfg = {
        .url = url_fw,
        .crt_bundle_attach = esp_crt_bundle_attach,  /* Let's Encrypt via ESP-IDF Mozilla-Bundle */
        .timeout_ms = 60000,
        .keep_alive_enable = true,
        .buffer_size = 4096,
        .buffer_size_tx = 1024,
    };

    esp_https_ota_config_t ota_cfg = { .http_config = &fw_cfg };
    esp_err_t ota_err = esp_https_ota(&ota_cfg);
    if (ota_err == ESP_OK) {
        ESP_LOGI(TAG, "Auto-OTA success, rebooting...");
        set_ota_status_text("Auto-Update OK - Neustart...", lv_color_hex(0x86EFAC));
        vTaskDelay(pdMS_TO_TICKS(2000));
        esp_restart();
    } else {
        ESP_LOGE(TAG, "Auto-OTA failed: %s", esp_err_to_name(ota_err));
        set_ota_status_text("Auto-Update fehlgeschlagen!", lv_color_hex(0xFCA5A5));
        s_auto_ota_in_progress = false;
    }
    vTaskDelete(NULL);
}

/* DHCP-Schalter: statische IP-Felder ein-/ausblenden */
static void wifi_dhcp_toggle_event_cb(lv_event_t *event)
{
    LV_UNUSED(event);
    if (!s_ui.wifi_static_ip_cont) {
        return;
    }
    bool dhcp = lv_obj_has_state(s_ui.wifi_dhcp_sw, LV_STATE_CHECKED);
    if (dhcp) {
        lv_obj_add_flag(s_ui.wifi_static_ip_cont, LV_OBJ_FLAG_HIDDEN);
    } else {
        lv_obj_clear_flag(s_ui.wifi_static_ip_cont, LV_OBJ_FLAG_HIDDEN);
    }
}

/* Enterprise-Schalter: Identity/Username-Felder und Passwort-Label ein-/ausblenden */
static void wifi_eap_toggle_event_cb(lv_event_t *event)
{
    LV_UNUSED(event);
    if (!s_ui.wifi_eap_cont) {
        return;
    }
    bool eap = lv_obj_has_state(s_ui.wifi_eap_sw, LV_STATE_CHECKED);
    if (eap) {
        lv_obj_clear_flag(s_ui.wifi_eap_cont, LV_OBJ_FLAG_HIDDEN);
    } else {
        lv_obj_add_flag(s_ui.wifi_eap_cont, LV_OBJ_FLAG_HIDDEN);
    }
}

/* WLAN-Konfiguration speichern und Verbindung herstellen */
static void wifi_cfg_save_connect_event_cb(lv_event_t *event)
{
    LV_UNUSED(event);

    char selected_ssid[33] = {0};
    lv_dropdown_get_selected_str(s_ui.wifi_ssid_dropdown, selected_ssid, sizeof(selected_ssid));

    if ((selected_ssid[0] == '\0') || (strcmp(selected_ssid, "Kein Netzwerk gefunden") == 0)) {
        set_wifi_cfg_status_text("SSID auswaehlen", lv_color_hex(0xFCA5A5));
        return;
    }

    strncpy(s_wifi_cfg.ssid, selected_ssid, sizeof(s_wifi_cfg.ssid) - 1);
    s_wifi_cfg.ssid[sizeof(s_wifi_cfg.ssid) - 1] = '\0';

    strncpy(s_wifi_cfg.password, lv_textarea_get_text(s_ui.wifi_password_ta), sizeof(s_wifi_cfg.password) - 1);
    s_wifi_cfg.password[sizeof(s_wifi_cfg.password) - 1] = '\0';

    /* WPA2-Enterprise (802.1x) */
    bool eap = lv_obj_has_state(s_ui.wifi_eap_sw, LV_STATE_CHECKED);
    s_wifi_cfg.eap_enabled = eap ? 1 : 0;
    if (eap) {
        if (s_wifi_cfg.password[0] == '\0') {
            set_wifi_cfg_status_text("Passwort fuer Enterprise benoetigt", lv_color_hex(0xFCA5A5));
            return;
        }
        const char *identity_text = lv_textarea_get_text(s_ui.wifi_eap_identity_ta);
        const char *username_text = lv_textarea_get_text(s_ui.wifi_eap_username_ta);
        if (username_text[0] == '\0') {
            set_wifi_cfg_status_text("Username benoetigt", lv_color_hex(0xFCA5A5));
            return;
        }
        strncpy(s_wifi_cfg.eap_identity, identity_text, sizeof(s_wifi_cfg.eap_identity) - 1);
        s_wifi_cfg.eap_identity[sizeof(s_wifi_cfg.eap_identity) - 1] = '\0';
        strncpy(s_wifi_cfg.eap_username, username_text, sizeof(s_wifi_cfg.eap_username) - 1);
        s_wifi_cfg.eap_username[sizeof(s_wifi_cfg.eap_username) - 1] = '\0';
    } else {
        s_wifi_cfg.eap_identity[0] = '\0';
        s_wifi_cfg.eap_username[0] = '\0';
    }

    /* DHCP / statische IP */
    bool dhcp = lv_obj_has_state(s_ui.wifi_dhcp_sw, LV_STATE_CHECKED);
    s_wifi_cfg.dhcp_enabled = dhcp ? 1 : 0;
    if (!dhcp) {
        const char *ip_text = lv_textarea_get_text(s_ui.wifi_ip_ta);
        const char *gw_text = lv_textarea_get_text(s_ui.wifi_gateway_ta);
        const char *nm_text = lv_textarea_get_text(s_ui.wifi_netmask_ta);

        ip4_addr_t tmp = {0};
        if (!parse_ipv4(ip_text, &tmp) || !parse_ipv4(gw_text, &tmp) || !parse_ipv4(nm_text, &tmp)) {
            set_wifi_cfg_status_text("Ungueltige IP-Adresse", lv_color_hex(0xFCA5A5));
            return;
        }

        strncpy(s_wifi_cfg.ip, ip_text, sizeof(s_wifi_cfg.ip) - 1);
        s_wifi_cfg.ip[sizeof(s_wifi_cfg.ip) - 1] = '\0';
        strncpy(s_wifi_cfg.gateway, gw_text, sizeof(s_wifi_cfg.gateway) - 1);
        s_wifi_cfg.gateway[sizeof(s_wifi_cfg.gateway) - 1] = '\0';
        strncpy(s_wifi_cfg.netmask, nm_text, sizeof(s_wifi_cfg.netmask) - 1);
        s_wifi_cfg.netmask[sizeof(s_wifi_cfg.netmask) - 1] = '\0';

        /* DNS: optional, leer ist erlaubt; falls angegeben muss IP gueltig sein */
        const char *dns_text = lv_textarea_get_text(s_ui.wifi_dns_ta);
        if (dns_text[0] != '\0') {
            ip4_addr_t dns_tmp = {0};
            if (!parse_ipv4(dns_text, &dns_tmp)) {
                set_wifi_cfg_status_text("Ungueltige DNS-Adresse", lv_color_hex(0xFCA5A5));
                return;
            }
            strncpy(s_wifi_cfg.dns, dns_text, sizeof(s_wifi_cfg.dns) - 1);
            s_wifi_cfg.dns[sizeof(s_wifi_cfg.dns) - 1] = '\0';
        } else {
            s_wifi_cfg.dns[0] = '\0';
        }
    }

    esp_err_t err = wifi_cfg_save(&s_wifi_cfg);
    if (err != ESP_OK) {
        set_wifi_cfg_status_text("Speichern fehlgeschlagen", lv_color_hex(0xFCA5A5));
        return;
    }

    err = wifi_connect_from_cfg(&s_wifi_cfg);
    if (err != ESP_OK) {
        set_wifi_cfg_status_text("Verbinden fehlgeschlagen", lv_color_hex(0xFCA5A5));
        return;
    }

    set_wifi_cfg_status_text("Verbinde...", lv_color_hex(0xFDE68A));
    set_status_text("WLAN verbindet...", lv_color_hex(0xFDE68A));
}

/* Status-Seiten (Netzwerk/Bridge/System) mit aktuellen Werten füllen */
static void status_update_info(void)
{
    char buf[384] = {0};
    char mac_buf[18] = "??";
    get_device_mac_text(mac_buf, sizeof(mac_buf));

    /* --- Network tab --- */
    if (s_ui.status_net_label) {
        esp_netif_ip_info_t ip_info = {0};
        char ip_str[16] = "-";
        char gw_str[16] = "-";
        char mask_str[16] = "-";
        char dns_str[16] = "-";
        if (s_wifi_netif && (esp_netif_get_ip_info(s_wifi_netif, &ip_info) == ESP_OK) && ip_info.ip.addr) {
            snprintf(ip_str, sizeof(ip_str), IPSTR, IP2STR(&ip_info.ip));
            snprintf(gw_str, sizeof(gw_str), IPSTR, IP2STR(&ip_info.gw));
            snprintf(mask_str, sizeof(mask_str), IPSTR, IP2STR(&ip_info.netmask));
        }
        esp_netif_dns_info_t dns_info = {0};
        if (s_wifi_netif && (esp_netif_get_dns_info(s_wifi_netif, ESP_NETIF_DNS_MAIN, &dns_info) == ESP_OK)
            && dns_info.ip.u_addr.ip4.addr != 0) {
            snprintf(dns_str, sizeof(dns_str), IPSTR, IP2STR(&dns_info.ip.u_addr.ip4));
        }
        snprintf(buf, sizeof(buf),
                 "MAC: %s\n"
                 "SSID: %s\n"
                 "DHCP: %s\n"
                 "IP: %s\n"
                 "Gateway: %s\n"
                 "Netmask: %s\n"
                 "DNS: %s\n"
                 "WLAN: %s\n"
                 "Token: %s",
                 mac_buf,
                 s_wifi_cfg.ssid[0] ? s_wifi_cfg.ssid : "-",
                 s_wifi_cfg.dhcp_enabled ? "Ja" : "Nein",
                 ip_str, gw_str, mask_str, dns_str,
                 s_wifi_has_ip ? "Verbunden" : "Getrennt",
                 auth_has_token() ? "Vorhanden" : "Fehlt");
        lv_label_set_text(s_ui.status_net_label, buf);
    }

    /* --- Bridge config tab --- */
    if (s_ui.status_bridge_label) {
        int64_t until = s_unlock_until_us;
        int64_t now_us = esp_timer_get_time();
        bool unlocked = (until > 0) && (until > now_us);
        char unlock_str[32];
        if (unlocked) {
            int remaining_sec = (int)((until - now_us) / 1000000);
            snprintf(unlock_str, sizeof(unlock_str), "Aktiv (%d:%02d)", remaining_sec / 60, remaining_sec % 60);
        } else {
            snprintf(unlock_str, sizeof(unlock_str), "Gesperrt");
        }

        snprintf(buf, sizeof(buf),
                 "Status: %s\n"
                 "Maschine: %s\n"
                 "Standort: %s\n"
                 "Info URL: %s\n"
                 "Idle Strom: %.2f A\n"
                 "Sound: %s\n"
                 "Idle-Erkennung: %s\n"
                 "Freischaltung: %s\n"
                 "Config Version: %lu",
                 s_bridge_cfg.config_version > 0 ? "Konfiguriert" : "Unkonfiguriert",
                 s_bridge_cfg.machine_name[0] ? s_bridge_cfg.machine_name : "-",
                 s_bridge_cfg.location[0] ? s_bridge_cfg.location : "-",
                 s_bridge_cfg.info_url[0] ? s_bridge_cfg.info_url : "-",
                 s_bridge_cfg.idle_current,
                 s_bridge_cfg.sound_enabled ? "An" : "Aus",
                 s_bridge_cfg.idle_detection_enabled ? "An" : "Aus",
                 unlock_str,
                 (unsigned long)s_bridge_cfg.config_version);
        lv_label_set_text(s_ui.status_bridge_label, buf);
    }

    /* --- System tab --- */
    if (s_ui.status_system_label) {
        int64_t uptime_s = esp_timer_get_time() / 1000000;
        int hours = (int)(uptime_s / 3600);
        int mins = (int)((uptime_s % 3600) / 60);
        int secs = (int)(uptime_s % 60);
        size_t psram_free = heap_caps_get_free_size(MALLOC_CAP_SPIRAM) / 1024;
        size_t sram_free = heap_caps_get_free_size(MALLOC_CAP_INTERNAL) / 1024;

        snprintf(buf, sizeof(buf),
                 "Firmware: " APP_VERSION "\n"
                 "Build: " __DATE__ " " __TIME__ "\n"
                 "PSRAM frei: %u KB\n"
                 "SRAM frei: %u KB\n"
                 "Uptime: %02d:%02d:%02d",
                 (unsigned)psram_free, (unsigned)sram_free,
                 hours, mins, secs);
        lv_label_set_text(s_ui.status_system_label, buf);
    }
}

/* Status-Seite im WLAN-Modal anzeigen */
static void wifi_cfg_show_status_page(lv_event_t *event)
{
    LV_UNUSED(event);
    if (!bsp_display_lock(100)) {
        return;
    }
    status_update_info();
    if (s_ui.wifi_cfg_page) {
        lv_obj_add_flag(s_ui.wifi_cfg_page, LV_OBJ_FLAG_HIDDEN);
    }
    if (s_ui.wifi_status_page) {
        lv_obj_clear_flag(s_ui.wifi_status_page, LV_OBJ_FLAG_HIDDEN);
    }
    bsp_display_unlock();
}

/* WLAN-Konfigurationsseite im Modal anzeigen */
static void wifi_cfg_show_wifi_page(lv_event_t *event)
{
    LV_UNUSED(event);
    if (!bsp_display_lock(100)) {
        return;
    }
    if (s_ui.wifi_status_page) {
        lv_obj_add_flag(s_ui.wifi_status_page, LV_OBJ_FLAG_HIDDEN);
    }
    if (s_ui.wifi_cfg_page) {
        lv_obj_clear_flag(s_ui.wifi_cfg_page, LV_OBJ_FLAG_HIDDEN);
    }
    bsp_display_unlock();
}

/* Status-Tab umschalten (0=Netzwerk, 1=Bridge, 2=System) */
static void status_show_tab(int tab)
{
    lv_color_t active_bg = lv_color_hex(0x2563EB);
    lv_color_t inactive_bg = lv_color_hex(0x374151);

    if (s_ui.status_tab_net) {
        if (tab == 0) {
            lv_obj_clear_flag(s_ui.status_tab_net, LV_OBJ_FLAG_HIDDEN);
        } else {
            lv_obj_add_flag(s_ui.status_tab_net, LV_OBJ_FLAG_HIDDEN);
        }
    }
    if (s_ui.status_tab_bridge) {
        if (tab == 1) {
            lv_obj_clear_flag(s_ui.status_tab_bridge, LV_OBJ_FLAG_HIDDEN);
        } else {
            lv_obj_add_flag(s_ui.status_tab_bridge, LV_OBJ_FLAG_HIDDEN);
        }
    }
    if (s_ui.status_tab_system) {
        if (tab == 2) {
            lv_obj_clear_flag(s_ui.status_tab_system, LV_OBJ_FLAG_HIDDEN);
        } else {
            lv_obj_add_flag(s_ui.status_tab_system, LV_OBJ_FLAG_HIDDEN);
        }
    }

    if (s_ui.tab_net_btn) {
        lv_obj_set_style_bg_color(s_ui.tab_net_btn, (tab == 0) ? active_bg : inactive_bg, 0);
    }
    if (s_ui.tab_bridge_btn) {
        lv_obj_set_style_bg_color(s_ui.tab_bridge_btn, (tab == 1) ? active_bg : inactive_bg, 0);
    }
    if (s_ui.tab_sys_btn) {
        lv_obj_set_style_bg_color(s_ui.tab_sys_btn, (tab == 2) ? active_bg : inactive_bg, 0);
    }
}

/* Tab-Callback: Netzwerk-Tab aktivieren */
static void status_tab_net_cb(lv_event_t *event)
{
    LV_UNUSED(event);
    status_show_tab(0);
}

/* Tab-Callback: Bridge-Tab aktivieren */
static void status_tab_bridge_cb(lv_event_t *event)
{
    LV_UNUSED(event);
    status_show_tab(1);
}

/* Tab-Callback: System-Tab aktivieren */
static void status_tab_system_cb(lv_event_t *event)
{
    LV_UNUSED(event);
    status_show_tab(2);
}

/* Debug-Overlay ein-/ausschalten per Switch */
static void debug_overlay_toggle_event_cb(lv_event_t *event)
{
    lv_obj_t *sw = lv_event_get_target(event);
    bool checked = lv_obj_has_state(sw, LV_STATE_CHECKED);
    if (s_debug_label) {
        if (checked) {
            lv_obj_clear_flag(s_debug_label, LV_OBJ_FLAG_HIDDEN);
        } else {
            lv_obj_add_flag(s_debug_label, LV_OBJ_FLAG_HIDDEN);
        }
    }
}

/* LVGL-Timer: Periodischen Heartbeat an Server senden */
static void heartbeat_timer_cb(lv_timer_t *timer)
{
    (void)timer;

    if (!auth_has_token() || !s_wifi_has_ip || s_auth_busy) {
        return;
    }

    int64_t now_us = esp_timer_get_time();
    int64_t interval_ms = (s_bridge_cfg.config_version > 0) ? HEARTBEAT_INTERVAL_MS : HEARTBEAT_INTERVAL_UNCONFIGURED_MS;
    if ((s_last_heartbeat_us != 0) && ((now_us - s_last_heartbeat_us) < (interval_ms * 1000))) {
        return;
    }

    auth_request_t req = {
        .source = AUTH_SRC_HEARTBEAT,
    };

    if (enqueue_auth_request(&req)) {
        set_auth_busy(true);
        s_last_heartbeat_us = now_us;
        ESP_LOGI(TAG, "Heartbeat request enqueued");
    }
}

/* LVGL-Timer: PWRKEY-Tastendruck verarbeiten → WLAN-Modal öffnen */
static void pwrkey_timer_cb(lv_timer_t *timer)
{
    (void)timer;

    if (s_pwrkey_pressed) {
        s_pwrkey_pressed = false;
        s_pause_nfc_polling = true;
        if (bsp_display_lock(100)) {
            status_update_info();
            if (s_ui.wifi_cfg_page) {
                lv_obj_add_flag(s_ui.wifi_cfg_page, LV_OBJ_FLAG_HIDDEN);
            }
            if (s_ui.wifi_status_page) {
                lv_obj_clear_flag(s_ui.wifi_status_page, LV_OBJ_FLAG_HIDDEN);
            }
            if (s_ui.wifi_cfg_modal) {
                lv_obj_clear_flag(s_ui.wifi_cfg_modal, LV_OBJ_FLAG_HIDDEN);
            }
            if (s_ui.unlock_indicator) {
                lv_obj_add_flag(s_ui.unlock_indicator, LV_OBJ_FLAG_HIDDEN);
            }
            bsp_display_unlock();
        }
    }
}

/* Einheitlichen blauen Primary-Button erstellen (Hilfsfunktion) */
static lv_obj_t *create_primary_button(lv_obj_t *parent, const char *text)
{
    lv_obj_t *btn = lv_button_create(parent);
    lv_obj_set_width(btn, lv_pct(100));
    lv_obj_set_height(btn, 56);
    lv_obj_set_style_radius(btn, 18, 0);
    lv_obj_set_style_border_width(btn, 0, 0);
    lv_obj_set_style_bg_color(btn, lv_color_hex(0x2563EB), 0);

    lv_obj_t *label = lv_label_create(btn);
    lv_label_set_text(label, text);
    lv_obj_set_style_text_color(label, lv_color_hex(0xEFF6FF), 0);
    lv_obj_center(label);

    return btn;
}

/* ISR-Callback: VSync-Zähler für FPS-Berechnung im Debug-Overlay */
static bool IRAM_ATTR vsync_event_cb(esp_lcd_panel_handle_t panel,
                                     const esp_lcd_rgb_panel_event_data_t *edata,
                                     void *user_ctx)
{
    (void)panel; (void)edata; (void)user_ctx;
    s_vsync_count++;
    return false;
}

/* Debug-Overlay-Text aktualisieren: FPS, PSRAM, SRAM */
static void debug_overlay_timer_cb(lv_timer_t *timer)
{
    (void)timer;
    static uint32_t last_vsync = 0;
    uint32_t cur = s_vsync_count;
    uint32_t fps = cur - last_vsync;
    last_vsync = cur;

    size_t psram_free = heap_caps_get_free_size(MALLOC_CAP_SPIRAM) / 1024;
    size_t sram_free  = heap_caps_get_free_size(MALLOC_CAP_INTERNAL) / 1024;

    if (s_debug_label) {
        char buf[72];
        snprintf(buf, sizeof(buf), "VSync:%uHz  PSRAM:%uKB  SRAM:%uKB",
                 (unsigned)fps, (unsigned)psram_free, (unsigned)sram_free);
        lv_label_set_text(s_debug_label, buf);
    }
}

/* ════════════════════════════════════════════════════════════════════════════
 * Freischaltung: Zeitlich befristeter Unlock mit visueller Statusanzeige.
 * - activate_unlock(): Setzt Timer, erzwingt sofortigen Heartbeat
 * - unlock_timer_cb(): 1s-LVGL-Timer, aktualisiert Anzeige (grün/gelb/rot)
 * - revoke_unlock_event_cb(): Manuelles Aufheben der Freischaltung
 * ════════════════════════════════════════════════════════════════════════════ */

/* Freischaltung aktivieren mit Zeitlimit (Minuten), sofortigen Heartbeat erzwingen */
static void activate_unlock(uint32_t server_duration_min)
{
    uint32_t dur = server_duration_min;
    if (dur == 0) {
        dur = s_bridge_cfg.unlock_duration_min;
    }
    if (dur == 0) {
        dur = 30;
    }
    s_unlock_duration_orig_min = dur;
    s_unlock_until_us = esp_timer_get_time() + (int64_t)dur * 60 * 1000000;
    ESP_LOGI(TAG, "Unlock activated for %lu min", (unsigned long)dur);

    /* Force immediate heartbeat so server sees the unlock status right away */
    s_last_heartbeat_us = 0;
}

/* Tap auf Statusindikator → Unlock-Timer zurücksetzen */
static void unlock_indicator_click_cb(lv_event_t *event)
{
    LV_UNUSED(event);
    if (s_unlock_until_us > 0) {
        /* Reset timer to original duration */
        uint32_t dur = s_unlock_duration_orig_min;
        if (dur == 0) {
            dur = 30;
        }
        s_unlock_until_us = esp_timer_get_time() + (int64_t)dur * 60 * 1000000;
        ESP_LOGI(TAG, "Unlock timer reset to %lu min", (unsigned long)dur);
    }
}

/* 1s-Timer: Unlock-Anzeige aktualisieren (grün/gelb/rot + Countdown) */
static void unlock_timer_cb(lv_timer_t *timer)
{
    LV_UNUSED(timer);
    if (!s_ui.unlock_indicator) {
        return;
    }
    /* Modal offen: Indikator nicht anzeigen, Zustand nicht verändern */
    if (s_ui.wifi_cfg_modal && !lv_obj_has_flag(s_ui.wifi_cfg_modal, LV_OBJ_FLAG_HIDDEN)) {
        lv_obj_add_flag(s_ui.unlock_indicator, LV_OBJ_FLAG_HIDDEN);
        return;
    }

    int64_t now_us = esp_timer_get_time();
    int64_t until = s_unlock_until_us;

    if (until <= 0) {
        /* Not unlocked — red */
        lv_obj_set_style_bg_color(s_ui.unlock_indicator, lv_color_hex(0xEF4444), 0);
        lv_obj_clear_flag(s_ui.unlock_indicator, LV_OBJ_FLAG_HIDDEN);
        if (s_ui.unlock_text_label) {
            lv_label_set_text(s_ui.unlock_text_label, LV_SYMBOL_CLOSE " Gesperrt");
        }
        if (s_ui.revoke_unlock_btn) {
            lv_obj_add_flag(s_ui.revoke_unlock_btn, LV_OBJ_FLAG_HIDDEN);
        }
        if (s_ui.login_btn) {
            lv_obj_clear_flag(s_ui.login_btn, LV_OBJ_FLAG_HIDDEN);
        }
        /* PCF: Rote LED an wenn verbunden+angemeldet, sonst alles aus */
        pcf8574_set_outputs((s_wifi_has_ip && auth_has_token())
            ? (uint8_t)(PCF_OUTPUT_MASK & ~(1u << PCF_PIN_LED_RED))
            : PCF_OUTPUT_MASK);
        return;
    }

    int64_t remaining_us = until - now_us;
    if (remaining_us <= 0) {
        /* Expired — reset to locked */
        s_unlock_until_us = 0;
        lv_obj_set_style_bg_color(s_ui.unlock_indicator, lv_color_hex(0xEF4444), 0);
        lv_obj_clear_flag(s_ui.unlock_indicator, LV_OBJ_FLAG_HIDDEN);
        if (s_ui.unlock_text_label) {
            lv_label_set_text(s_ui.unlock_text_label, LV_SYMBOL_CLOSE " Gesperrt");
        }
        ESP_LOGI(TAG, "Unlock expired");
        /* Force immediate heartbeat so server sees the status change */
        s_last_heartbeat_us = 0;
        if (s_ui.revoke_unlock_btn) {
            lv_obj_add_flag(s_ui.revoke_unlock_btn, LV_OBJ_FLAG_HIDDEN);
        }
        if (s_ui.login_btn) {
            lv_obj_clear_flag(s_ui.login_btn, LV_OBJ_FLAG_HIDDEN);
        }
        /* PCF: Rote LED an wenn verbunden+angemeldet, sonst alles aus */
        pcf8574_set_outputs((s_wifi_has_ip && auth_has_token())
            ? (uint8_t)(PCF_OUTPUT_MASK & ~(1u << PCF_PIN_LED_RED))
            : PCF_OUTPUT_MASK);
        return;
    }

    int remaining_sec = (int)(remaining_us / 1000000);
    int mins = remaining_sec / 60;
    int secs = remaining_sec % 60;
    char time_buf[32];
    snprintf(time_buf, sizeof(time_buf), LV_SYMBOL_OK " %d:%02d", mins, secs);

    int64_t two_min_us = (int64_t)2 * 60 * 1000000;
    if (remaining_us < two_min_us) {
        /* Less than 2 min — yellow, blink */
        static bool blink_on = true;
        blink_on = !blink_on;
        lv_obj_set_style_bg_color(s_ui.unlock_indicator, lv_color_hex(0xEAB308), 0);
        if (blink_on) {
            lv_obj_clear_flag(s_ui.unlock_indicator, LV_OBJ_FLAG_HIDDEN);
        } else {
            lv_obj_add_flag(s_ui.unlock_indicator, LV_OBJ_FLAG_HIDDEN);
        }
        /* PCF: Gruene LED blinkt im Gleichlauf; Relais bleibt permanent aktiv */
        pcf8574_set_outputs(blink_on
            ? (uint8_t)(PCF_OUTPUT_MASK & ~((1u << PCF_PIN_LED_GREEN) | (1u << PCF_PIN_RELAY)))
            : (uint8_t)(PCF_OUTPUT_MASK & ~(1u << PCF_PIN_RELAY)));
    } else {
        /* Unlocked — green */
        lv_obj_set_style_bg_color(s_ui.unlock_indicator, lv_color_hex(0x22C55E), 0);
        lv_obj_clear_flag(s_ui.unlock_indicator, LV_OBJ_FLAG_HIDDEN);
        /* PCF: Gruene LED an, Relais aktiv */
        pcf8574_set_outputs((uint8_t)(PCF_OUTPUT_MASK & ~((1u << PCF_PIN_LED_GREEN) | (1u << PCF_PIN_RELAY))));
    }
    if (s_ui.unlock_text_label) {
        lv_label_set_text(s_ui.unlock_text_label, time_buf);
    }
    if (s_ui.revoke_unlock_btn) {
        lv_obj_clear_flag(s_ui.revoke_unlock_btn, LV_OBJ_FLAG_HIDDEN);
    }
    if (s_ui.login_btn) {
        lv_obj_add_flag(s_ui.login_btn, LV_OBJ_FLAG_HIDDEN);
    }
}

/* Freischaltung manuell aufheben (Revoke-Button) */
static void revoke_unlock_event_cb(lv_event_t *event)
{
    LV_UNUSED(event);
    s_unlock_until_us = 0;
    ESP_LOGI(TAG, "Unlock revoked by user");
    s_last_heartbeat_us = 0;
}

/* Idle-Strom messen via ADS1115 (Kanal 0).
 * Fuehrt IDLE_MEASURE_SAMPLES Single-Shot-Messungen durch, sortiert die Werte
 * und bildet einen Trimmed-Mean (ohne kleinstes und groesstes Ergebnis).
 * Rueckgabe: Durchschnitts-Spannung in mV (1 LSB = ADS_LSB_uV µV, PGA ±2.048 V).
 * Negativer Rueckgabewert = ADS1115 nicht verfuegbar. */
#define IDLE_MEASURE_SAMPLES   5
#define ADS_LSB_uV             62.5f  /* 2048 mV / 32768 LSB */
static float measure_idle_current_mV(void)
{
    if (s_ads1115_dev == NULL) {
        return -1.0f;
    }
    int32_t readings[IDLE_MEASURE_SAMPLES];
    for (int i = 0; i < IDLE_MEASURE_SAMPLES; i++) {
        readings[i] = (int32_t)ads1115_read_channel(0);
        /* ads1115_read_channel enthaelt bereits ~15 ms Wartezeit */
    }
    /* Insertion-Sort aufsteigend */
    for (int i = 1; i < IDLE_MEASURE_SAMPLES; i++) {
        int32_t key = readings[i];
        int j = i - 1;
        while ((j >= 0) && (readings[j] > key)) {
            readings[j + 1] = readings[j];
            j--;
        }
        readings[j + 1] = key;
    }
    /* Trimmed Mean: erstes (min) und letztes (max) verwerfen */
    int32_t sum = 0;
    for (int i = 1; i < (IDLE_MEASURE_SAMPLES - 1); i++) {
        sum += readings[i];
    }
    float avg_raw = (float)sum / (float)(IDLE_MEASURE_SAMPLES - 2);
    return avg_raw * ADS_LSB_uV / 1000.0f;  /* µV → mV */
}

/* Hintergrund-Task fuer Idle-Strommessung: laeuft ausserhalb des LVGL-Tasks
 * (Gesamtdauer ~5 × 15 ms = 75 ms), aktualisiert UI und loest Heartbeat aus. */
static void idle_measure_task(void *arg)
{
    (void)arg;
    float mV = measure_idle_current_mV();
    s_idle_current_measured_mV = mV;
    ESP_LOGI(TAG, "Idle current measured: %.3f mV (ADS1115 ch0)", mV);
    /* Persistent speichern: Wert in Bridge-Config schreiben und NVS-Save triggern */
    if (mV >= 0.0f) {
        s_bridge_cfg.idle_current = mV;
        s_bridge_cfg_updated = true;
    }

    char msg[72];
    lv_color_t col;
    if (mV < 0.0f) {
        snprintf(msg, sizeof(msg), "Messung fehlgeschlagen (ADS1115)");
        col = lv_color_hex(0xFCA5A5);
    } else {
        snprintf(msg, sizeof(msg), "Idle: %.2f mV  (wird uebermittelt)", mV);
        col = lv_color_hex(0x86EFAC);
    }
    if (s_ui.status_bridge_label && bsp_display_lock(100)) {
        lv_label_set_text(s_ui.status_bridge_label, msg);
        lv_obj_set_style_text_color(s_ui.status_bridge_label, col, 0);
        bsp_display_unlock();
    }
    /* Heartbeat sofort auslösen, damit der Messwert zum Server uebertragen wird */
    if (mV >= 0.0f) {
        s_last_heartbeat_us = 0;
    }
    vTaskDelete(NULL);
}

/* Button-Callback: startet Idle-Strommessung als Hintergrund-Task */
static void measure_idle_current_event_cb(lv_event_t *event)
{
    LV_UNUSED(event);
    if (s_ui.status_bridge_label && bsp_display_lock(50)) {
        lv_label_set_text(s_ui.status_bridge_label, "Idle-Strom wird gemessen...");
        lv_obj_set_style_text_color(s_ui.status_bridge_label, lv_color_hex(0xFDE68A), 0);
        bsp_display_unlock();
    }
    BaseType_t ok = xTaskCreatePinnedToCore(idle_measure_task, "idle_meas", 4096, NULL, 3, NULL, AUTH_TASK_CORE_ID);
    if (ok != pdPASS) {
        ESP_LOGE(TAG, "idle_measure_task creation failed");
        if (s_ui.status_bridge_label && bsp_display_lock(50)) {
            lv_label_set_text(s_ui.status_bridge_label, "Task-Fehler");
            lv_obj_set_style_text_color(s_ui.status_bridge_label, lv_color_hex(0xFCA5A5), 0);
            bsp_display_unlock();
        }
    }
}

/* ════════════════════════════════════════════════════════════════════════════
 * GUI-Erstellung: Baut alle LVGL-Objekte auf – drei Hauptansichten:
 *   1. start_container: Maschineninfo, QR-Code, Status, Login/Revoke-Buttons
 *   2. pin_container: PIN-Eingabe mit Num-Pad
 *   3. result_container: Erfolgs-/Fehlermeldung mit Rückkehr- und
 *      Karten-Registrierungs-Button
 * Plus: Login-Modal, WLAN-Konfigurationsmodal, Debug-Overlay, Keyboard
 * ════════════════════════════════════════════════════════════════════════════ */

static void create_ui(void)
{
    lv_obj_t *screen = lv_screen_active();
    lv_obj_set_style_bg_color(screen, lv_color_hex(0x0B1220), 0);
    lv_obj_set_style_bg_grad_color(screen, lv_color_hex(0x111827), 0);
    lv_obj_set_style_bg_grad_dir(screen, LV_GRAD_DIR_VER, 0);
    lv_obj_set_scrollbar_mode(screen, LV_SCROLLBAR_MODE_OFF);
    lv_obj_clear_flag(screen, LV_OBJ_FLAG_SCROLLABLE);

    s_ui.start_container = lv_obj_create(screen);
    lv_obj_set_size(s_ui.start_container, lv_pct(100), lv_pct(100));
    lv_obj_set_style_bg_opa(s_ui.start_container, LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_width(s_ui.start_container, 0, 0);
    lv_obj_set_style_pad_all(s_ui.start_container, 24, 0);
    lv_obj_set_style_pad_row(s_ui.start_container, 14, 0);
    lv_obj_set_layout(s_ui.start_container, LV_LAYOUT_FLEX);
    lv_obj_set_flex_flow(s_ui.start_container, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_scrollbar_mode(s_ui.start_container, LV_SCROLLBAR_MODE_OFF);
    lv_obj_clear_flag(s_ui.start_container, LV_OBJ_FLAG_SCROLLABLE);

    /* Machine name (large) */
    s_ui.machine_name_label = lv_label_create(s_ui.start_container);
    lv_label_set_text(s_ui.machine_name_label, "");
    lv_obj_set_style_text_font(s_ui.machine_name_label, &lv_font_montserrat_20, 0);
    lv_obj_set_style_text_color(s_ui.machine_name_label, lv_color_hex(0xF9FAFB), 0);
    lv_obj_add_flag(s_ui.machine_name_label, LV_OBJ_FLAG_HIDDEN);

    /* Location */
    s_ui.location_label = lv_label_create(s_ui.start_container);
    lv_label_set_text(s_ui.location_label, "");
    lv_obj_set_style_text_color(s_ui.location_label, lv_color_hex(0xCBD5E1), 0);
    lv_obj_add_flag(s_ui.location_label, LV_OBJ_FLAG_HIDDEN);

    /* QR code */
#if LV_USE_QRCODE
    s_ui.qr_code = lv_qrcode_create(s_ui.start_container);
    lv_qrcode_set_size(s_ui.qr_code, 120);
    lv_qrcode_set_dark_color(s_ui.qr_code, lv_color_hex(0x000000));
    lv_qrcode_set_light_color(s_ui.qr_code, lv_color_hex(0xFFFFFF));
    lv_obj_set_style_border_color(s_ui.qr_code, lv_color_hex(0xFFFFFF), 0);
    lv_obj_set_style_border_width(s_ui.qr_code, 4, 0);
    lv_obj_add_flag(s_ui.qr_code, LV_OBJ_FLAG_HIDDEN);
#endif

    lv_obj_t *title = lv_label_create(s_ui.start_container);
    lv_label_set_text(title, "Bitte HSD Karte anlegen");
    lv_obj_set_style_text_font(title, &lv_font_montserrat_20, 0);
    lv_obj_set_style_text_color(title, lv_color_hex(0xF9FAFB), 0);

    lv_obj_t *hint = lv_label_create(s_ui.start_container);
    lv_label_set_text(hint, "oder HSD Login verwenden.");
    lv_obj_set_style_text_color(hint, lv_color_hex(0xCBD5E1), 0);

    s_ui.status_label = lv_label_create(s_ui.start_container);
    lv_label_set_text(s_ui.status_label, "Bitte HSD Karte anlegen");
    lv_obj_set_style_text_color(s_ui.status_label, lv_color_hex(0x93C5FD), 0);

#if ENABLE_NFC
    s_ui.nfc_uid_label = lv_label_create(s_ui.start_container);
    lv_label_set_text(s_ui.nfc_uid_label, "NFC UID: -");
    lv_obj_set_style_text_color(s_ui.nfc_uid_label, lv_color_hex(0x86EFAC), 0);
#endif

    s_ui.login_btn = create_primary_button(s_ui.start_container, "HSD Login");
    lv_obj_add_event_cb(s_ui.login_btn, login_open_event_cb, LV_EVENT_CLICKED, NULL);

    /* Revoke button — same position, hidden by default, replaces login btn when unlocked */
    s_ui.revoke_unlock_btn = lv_button_create(s_ui.start_container);
    lv_obj_set_width(s_ui.revoke_unlock_btn, lv_pct(100));
    lv_obj_set_height(s_ui.revoke_unlock_btn, 56);
    lv_obj_set_style_bg_color(s_ui.revoke_unlock_btn, lv_color_hex(0xDC2626), 0);
    lv_obj_set_style_bg_color(s_ui.revoke_unlock_btn, lv_color_hex(0xB91C1C), LV_STATE_PRESSED);
    lv_obj_set_style_radius(s_ui.revoke_unlock_btn, 18, 0);
    lv_obj_add_flag(s_ui.revoke_unlock_btn, LV_OBJ_FLAG_HIDDEN);
    lv_obj_add_event_cb(s_ui.revoke_unlock_btn, revoke_unlock_event_cb, LV_EVENT_CLICKED, NULL);
    lv_obj_t *revoke_label = lv_label_create(s_ui.revoke_unlock_btn);
    lv_label_set_text(revoke_label, LV_SYMBOL_CLOSE " Freischaltung aufheben");
    lv_obj_set_style_text_color(revoke_label, lv_color_hex(0xFFFFFF), 0);
    lv_obj_center(revoke_label);

#if !ENABLE_NFC
    /* NFC simulation buttons */
    static const char *sim_uid_lars  = "044F3E6A174F80";
    static const char *sim_uid_ben   = "11223344";
    static const char *sim_uid_hsd = "AABBCCDD";

    lv_obj_t *sim_row = lv_obj_create(s_ui.start_container);
    lv_obj_set_width(sim_row, lv_pct(100));
    lv_obj_set_height(sim_row, LV_SIZE_CONTENT);
    lv_obj_set_style_bg_opa(sim_row, LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_width(sim_row, 0, 0);
    lv_obj_set_style_pad_all(sim_row, 0, 0);
    lv_obj_set_style_pad_column(sim_row, 8, 0);
    lv_obj_set_layout(sim_row, LV_LAYOUT_FLEX);
    lv_obj_set_flex_flow(sim_row, LV_FLEX_FLOW_ROW);

    lv_obj_t *sim_btn1 = create_primary_button(sim_row, "Lars");
    lv_obj_set_flex_grow(sim_btn1, 1);
    lv_obj_set_style_bg_color(sim_btn1, lv_color_hex(0x6366F1), 0);
    lv_obj_add_event_cb(sim_btn1, sim_nfc_event_cb, LV_EVENT_CLICKED, (void *)sim_uid_lars);

    lv_obj_t *sim_btn2 = create_primary_button(sim_row, "Ben");
    lv_obj_set_flex_grow(sim_btn2, 1);
    lv_obj_set_style_bg_color(sim_btn2, lv_color_hex(0x6366F1), 0);
    lv_obj_add_event_cb(sim_btn2, sim_nfc_event_cb, LV_EVENT_CLICKED, (void *)sim_uid_ben);

    lv_obj_t *sim_btn3 = create_primary_button(sim_row, "HSD");
    lv_obj_set_flex_grow(sim_btn3, 1);
    lv_obj_set_style_bg_color(sim_btn3, lv_color_hex(0x6366F1), 0);
    lv_obj_add_event_cb(sim_btn3, sim_nfc_event_cb, LV_EVENT_CLICKED, (void *)sim_uid_hsd);
#endif

    s_ui.pin_container = lv_obj_create(screen);
    lv_obj_set_size(s_ui.pin_container, lv_pct(100), lv_pct(100));
    lv_obj_set_style_bg_opa(s_ui.pin_container, LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_width(s_ui.pin_container, 0, 0);
    lv_obj_set_style_pad_all(s_ui.pin_container, 24, 0);
    lv_obj_set_style_pad_row(s_ui.pin_container, 14, 0);
    lv_obj_set_layout(s_ui.pin_container, LV_LAYOUT_FLEX);
    lv_obj_set_flex_flow(s_ui.pin_container, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_scrollbar_mode(s_ui.pin_container, LV_SCROLLBAR_MODE_OFF);
    lv_obj_clear_flag(s_ui.pin_container, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_add_flag(s_ui.pin_container, LV_OBJ_FLAG_HIDDEN);

    lv_obj_t *pin_title = lv_label_create(s_ui.pin_container);
    lv_label_set_text(pin_title, "6-stelligen Code eingeben");
    lv_obj_set_style_text_font(pin_title, &lv_font_montserrat_20, 0);
    lv_obj_set_style_text_color(pin_title, lv_color_hex(0xF9FAFB), 0);

    s_ui.pin_ta = lv_textarea_create(s_ui.pin_container);
    lv_obj_set_width(s_ui.pin_ta, lv_pct(100));
    lv_obj_set_height(s_ui.pin_ta, 86);
    lv_textarea_set_one_line(s_ui.pin_ta, true);
    lv_textarea_set_accepted_chars(s_ui.pin_ta, "0123456789");
    lv_textarea_set_max_length(s_ui.pin_ta, 6);
    lv_textarea_set_placeholder_text(s_ui.pin_ta, "123456");
    lv_textarea_set_password_mode(s_ui.pin_ta, false);
    lv_obj_set_style_text_font(s_ui.pin_ta, &lv_font_montserrat_20, 0);
    lv_obj_set_style_text_align(s_ui.pin_ta, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_set_style_pad_top(s_ui.pin_ta, 26, 0);
    lv_obj_set_style_radius(s_ui.pin_ta, 18, 0);
    lv_obj_clear_flag(s_ui.pin_ta, LV_OBJ_FLAG_CLICK_FOCUSABLE);

    static const char *pin_map[] = {
        "1", "2", "3", "\n",
        "4", "5", "6", "\n",
        "7", "8", "9", "\n",
        "CLR", "0", LV_SYMBOL_BACKSPACE, ""
    };

    s_ui.pin_pad = lv_buttonmatrix_create(s_ui.pin_container);
    lv_buttonmatrix_set_map(s_ui.pin_pad, pin_map);
    lv_obj_set_width(s_ui.pin_pad, lv_pct(100));
    lv_obj_set_height(s_ui.pin_pad, 250);
    lv_obj_set_style_radius(s_ui.pin_pad, 14, 0);
    lv_obj_set_style_pad_gap(s_ui.pin_pad, 8, 0);
    lv_obj_set_style_text_font(s_ui.pin_pad, &lv_font_montserrat_20, 0);
    lv_obj_add_event_cb(s_ui.pin_pad, pin_pad_event_cb, LV_EVENT_VALUE_CHANGED, NULL);

    lv_obj_t *pin_btn_row = lv_obj_create(s_ui.pin_container);
    lv_obj_set_width(pin_btn_row, lv_pct(100));
    lv_obj_set_height(pin_btn_row, LV_SIZE_CONTENT);
    lv_obj_set_layout(pin_btn_row, LV_LAYOUT_FLEX);
    lv_obj_set_flex_flow(pin_btn_row, LV_FLEX_FLOW_ROW);
    lv_obj_set_style_pad_column(pin_btn_row, 10, 0);
    lv_obj_set_style_pad_all(pin_btn_row, 0, 0);
    lv_obj_set_style_bg_opa(pin_btn_row, LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_width(pin_btn_row, 0, 0);

    lv_obj_t *pin_back_btn = create_primary_button(pin_btn_row, "Zurueck");
    lv_obj_set_flex_grow(pin_back_btn, 1);
    lv_obj_set_style_bg_color(pin_back_btn, lv_color_hex(0x374151), 0);
    lv_obj_add_event_cb(pin_back_btn, back_to_start_event_cb, LV_EVENT_CLICKED, NULL);

    lv_obj_t *pin_submit_btn = create_primary_button(pin_btn_row, "Code pruefen");
    lv_obj_set_flex_grow(pin_submit_btn, 1);
    lv_obj_add_event_cb(pin_submit_btn, pin_submit_event_cb, LV_EVENT_CLICKED, NULL);
    lv_obj_add_event_cb(pin_back_btn, back_to_start_event_cb, LV_EVENT_CLICKED, NULL);

    s_ui.result_container = lv_obj_create(screen);
    lv_obj_set_size(s_ui.result_container, lv_pct(100), lv_pct(100));
    lv_obj_set_style_bg_opa(s_ui.result_container, LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_width(s_ui.result_container, 0, 0);
    lv_obj_set_style_pad_all(s_ui.result_container, 24, 0);
    lv_obj_set_style_pad_row(s_ui.result_container, 18, 0);
    lv_obj_set_layout(s_ui.result_container, LV_LAYOUT_FLEX);
    lv_obj_set_flex_flow(s_ui.result_container, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_flex_align(s_ui.result_container, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    lv_obj_set_scrollbar_mode(s_ui.result_container, LV_SCROLLBAR_MODE_OFF);
    lv_obj_clear_flag(s_ui.result_container, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_add_flag(s_ui.result_container, LV_OBJ_FLAG_HIDDEN);

    s_ui.result_icon_label = lv_label_create(s_ui.result_container);
    lv_label_set_text(s_ui.result_icon_label, LV_SYMBOL_OK);
    lv_obj_set_style_text_font(s_ui.result_icon_label, &lv_font_montserrat_20, 0);

    s_ui.result_text_label = lv_label_create(s_ui.result_container);
    lv_label_set_text(s_ui.result_text_label, "Freigeschaltet");
    lv_obj_set_style_text_font(s_ui.result_text_label, &lv_font_montserrat_20, 0);

    lv_obj_t *result_back_btn = create_primary_button(s_ui.result_container, "Zurueck");
    lv_obj_set_style_bg_color(result_back_btn, lv_color_hex(0x374151), 0);
    lv_obj_add_event_cb(result_back_btn, back_to_start_event_cb, LV_EVENT_CLICKED, NULL);

    s_ui.register_card_btn = lv_button_create(s_ui.result_container);
    lv_obj_set_width(s_ui.register_card_btn, lv_pct(100));
    lv_obj_set_height(s_ui.register_card_btn, 56);
    lv_obj_set_style_bg_color(s_ui.register_card_btn, lv_color_hex(0x2563EB), 0);
    lv_obj_set_style_bg_color(s_ui.register_card_btn, lv_color_hex(0x1D4ED8), LV_STATE_PRESSED);
    lv_obj_set_style_radius(s_ui.register_card_btn, 18, 0);
    lv_obj_add_flag(s_ui.register_card_btn, LV_OBJ_FLAG_HIDDEN);
    lv_obj_add_event_cb(s_ui.register_card_btn, register_card_event_cb, LV_EVENT_CLICKED, NULL);
    lv_obj_t *reg_card_label = lv_label_create(s_ui.register_card_btn);
    lv_label_set_text(reg_card_label, LV_SYMBOL_PLUS " Karte registrieren");
    lv_obj_set_style_text_color(reg_card_label, lv_color_hex(0xFFFFFF), 0);
    lv_obj_center(reg_card_label);

    s_ui.login_modal = lv_obj_create(screen);
    lv_obj_set_size(s_ui.login_modal, lv_pct(88), LV_SIZE_CONTENT);
    lv_obj_align(s_ui.login_modal, LV_ALIGN_CENTER, 0, -20);
    lv_obj_set_style_bg_color(s_ui.login_modal, lv_color_hex(0x111827), 0);
    lv_obj_set_style_radius(s_ui.login_modal, 18, 0);
    lv_obj_set_style_pad_all(s_ui.login_modal, 16, 0);
    lv_obj_set_style_pad_row(s_ui.login_modal, 10, 0);
    lv_obj_set_layout(s_ui.login_modal, LV_LAYOUT_FLEX);
    lv_obj_set_flex_flow(s_ui.login_modal, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_scrollbar_mode(s_ui.login_modal, LV_SCROLLBAR_MODE_OFF);
    lv_obj_clear_flag(s_ui.login_modal, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_add_flag(s_ui.login_modal, LV_OBJ_FLAG_HIDDEN);

    lv_obj_t *login_title = lv_label_create(s_ui.login_modal);
    lv_label_set_text(login_title, "HSD Login");
    lv_obj_set_style_text_font(login_title, &lv_font_montserrat_20, 0);
    lv_obj_set_style_text_color(login_title, lv_color_hex(0xF9FAFB), 0);

    s_ui.login_email_ta = lv_textarea_create(s_ui.login_modal);
    lv_obj_set_width(s_ui.login_email_ta, lv_pct(100));
    lv_textarea_set_one_line(s_ui.login_email_ta, true);
    lv_textarea_set_placeholder_text(s_ui.login_email_ta, "Email");
    lv_obj_add_event_cb(s_ui.login_email_ta, textarea_focus_event_cb, LV_EVENT_FOCUSED, NULL);
    lv_obj_add_event_cb(s_ui.login_email_ta, textarea_focus_event_cb, LV_EVENT_DEFOCUSED, NULL);

    /* Login-Passwortfeld mit Sichtbarkeits-Toggle */
    lv_obj_t *login_pwd_row = lv_obj_create(s_ui.login_modal);
    lv_obj_set_width(login_pwd_row, lv_pct(100));
    lv_obj_set_height(login_pwd_row, LV_SIZE_CONTENT);
    lv_obj_set_style_bg_opa(login_pwd_row, LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_width(login_pwd_row, 0, 0);
    lv_obj_set_style_pad_all(login_pwd_row, 0, 0);
    lv_obj_set_style_pad_column(login_pwd_row, 6, 0);
    lv_obj_set_layout(login_pwd_row, LV_LAYOUT_FLEX);
    lv_obj_set_flex_flow(login_pwd_row, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(login_pwd_row, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);

    s_ui.login_password_ta = lv_textarea_create(login_pwd_row);
    lv_obj_set_flex_grow(s_ui.login_password_ta, 1);
    lv_textarea_set_one_line(s_ui.login_password_ta, true);
    lv_textarea_set_password_mode(s_ui.login_password_ta, true);
    lv_textarea_set_placeholder_text(s_ui.login_password_ta, "Passwort");
    lv_obj_add_event_cb(s_ui.login_password_ta, textarea_focus_event_cb, LV_EVENT_FOCUSED, NULL);
    lv_obj_add_event_cb(s_ui.login_password_ta, textarea_focus_event_cb, LV_EVENT_DEFOCUSED, NULL);

    lv_obj_t *login_pwd_eye = lv_button_create(login_pwd_row);
    lv_obj_set_size(login_pwd_eye, 48, 48);
    lv_obj_set_style_radius(login_pwd_eye, 12, 0);
    lv_obj_set_style_border_width(login_pwd_eye, 0, 0);
    lv_obj_set_style_bg_color(login_pwd_eye, lv_color_hex(0x374151), 0);
    lv_obj_t *login_pwd_eye_lbl = lv_label_create(login_pwd_eye);
    lv_label_set_text(login_pwd_eye_lbl, LV_SYMBOL_EYE_OPEN);
    lv_obj_set_style_text_color(login_pwd_eye_lbl, lv_color_hex(0xD1D5DB), 0);
    lv_obj_center(login_pwd_eye_lbl);
    lv_obj_add_event_cb(login_pwd_eye, pwd_toggle_event_cb, LV_EVENT_CLICKED, s_ui.login_password_ta);

    lv_obj_t *login_submit_btn = create_primary_button(s_ui.login_modal, "Login");
    lv_obj_add_event_cb(login_submit_btn, login_submit_event_cb, LV_EVENT_CLICKED, NULL);

    lv_obj_t *login_close_btn = create_primary_button(s_ui.login_modal, "Schliessen");
    lv_obj_set_style_bg_color(login_close_btn, lv_color_hex(0x374151), 0);
    lv_obj_add_event_cb(login_close_btn, login_close_event_cb, LV_EVENT_CLICKED, NULL);

    s_ui.wifi_cfg_modal = lv_obj_create(screen);
    lv_obj_set_size(s_ui.wifi_cfg_modal, lv_pct(88), lv_pct(90));
    lv_obj_align(s_ui.wifi_cfg_modal, LV_ALIGN_CENTER, 0, -20);
    lv_obj_set_style_bg_color(s_ui.wifi_cfg_modal, lv_color_hex(0x111827), 0);
    lv_obj_set_style_radius(s_ui.wifi_cfg_modal, 18, 0);
    lv_obj_set_style_pad_all(s_ui.wifi_cfg_modal, 16, 0);
    lv_obj_set_style_pad_row(s_ui.wifi_cfg_modal, 0, 0);
    lv_obj_set_layout(s_ui.wifi_cfg_modal, LV_LAYOUT_FLEX);
    lv_obj_set_flex_flow(s_ui.wifi_cfg_modal, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_scrollbar_mode(s_ui.wifi_cfg_modal, LV_SCROLLBAR_MODE_OFF);
    lv_obj_clear_flag(s_ui.wifi_cfg_modal, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_add_flag(s_ui.wifi_cfg_modal, LV_OBJ_FLAG_HIDDEN);

    /* --- WLAN config page --- */
    s_ui.wifi_cfg_page = lv_obj_create(s_ui.wifi_cfg_modal);
    lv_obj_set_width(s_ui.wifi_cfg_page, lv_pct(100));
    lv_obj_set_height(s_ui.wifi_cfg_page, 0);
    lv_obj_set_flex_grow(s_ui.wifi_cfg_page, 1);
    lv_obj_set_style_bg_opa(s_ui.wifi_cfg_page, LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_width(s_ui.wifi_cfg_page, 0, 0);
    lv_obj_set_style_pad_all(s_ui.wifi_cfg_page, 0, 0);
    lv_obj_set_style_pad_row(s_ui.wifi_cfg_page, 10, 0);
    lv_obj_set_layout(s_ui.wifi_cfg_page, LV_LAYOUT_FLEX);
    lv_obj_set_flex_flow(s_ui.wifi_cfg_page, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_scrollbar_mode(s_ui.wifi_cfg_page, LV_SCROLLBAR_MODE_AUTO);
    lv_obj_add_flag(s_ui.wifi_cfg_page, LV_OBJ_FLAG_SCROLLABLE);

    lv_obj_t *wifi_title = lv_label_create(s_ui.wifi_cfg_page);
    lv_label_set_text(wifi_title, "WLAN Konfiguration");
    lv_obj_set_style_text_font(wifi_title, &lv_font_montserrat_20, 0);
    lv_obj_set_style_text_color(wifi_title, lv_color_hex(0xF9FAFB), 0);

    s_ui.wifi_cfg_status_label = lv_label_create(s_ui.wifi_cfg_page);
    lv_label_set_text(s_ui.wifi_cfg_status_label, "SSID scannen und auswaehlen");
    lv_obj_set_style_text_color(s_ui.wifi_cfg_status_label, lv_color_hex(0x93C5FD), 0);

    s_ui.wifi_ssid_dropdown = lv_dropdown_create(s_ui.wifi_cfg_page);
    lv_obj_set_width(s_ui.wifi_ssid_dropdown, lv_pct(100));
    lv_dropdown_set_options(s_ui.wifi_ssid_dropdown, "Kein Netzwerk gefunden");

    lv_obj_t *wifi_scan_btn = create_primary_button(s_ui.wifi_cfg_page, "WLAN Scan");
    lv_obj_add_event_cb(wifi_scan_btn, wifi_scan_event_cb, LV_EVENT_CLICKED, NULL);

    /* WLAN-Passwortfeld mit Sichtbarkeits-Toggle */
    lv_obj_t *wifi_pwd_row = lv_obj_create(s_ui.wifi_cfg_page);
    lv_obj_set_width(wifi_pwd_row, lv_pct(100));
    lv_obj_set_height(wifi_pwd_row, LV_SIZE_CONTENT);
    lv_obj_set_style_bg_opa(wifi_pwd_row, LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_width(wifi_pwd_row, 0, 0);
    lv_obj_set_style_pad_all(wifi_pwd_row, 0, 0);
    lv_obj_set_style_pad_column(wifi_pwd_row, 6, 0);
    lv_obj_set_layout(wifi_pwd_row, LV_LAYOUT_FLEX);
    lv_obj_set_flex_flow(wifi_pwd_row, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(wifi_pwd_row, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);

    s_ui.wifi_password_ta = lv_textarea_create(wifi_pwd_row);
    lv_obj_set_flex_grow(s_ui.wifi_password_ta, 1);
    lv_textarea_set_one_line(s_ui.wifi_password_ta, true);
    lv_textarea_set_password_mode(s_ui.wifi_password_ta, true);
    lv_textarea_set_placeholder_text(s_ui.wifi_password_ta, "Passwort");
    lv_textarea_set_text(s_ui.wifi_password_ta, s_wifi_cfg.password[0] ? s_wifi_cfg.password : "");
    lv_obj_add_event_cb(s_ui.wifi_password_ta, textarea_focus_event_cb, LV_EVENT_FOCUSED, NULL);
    lv_obj_add_event_cb(s_ui.wifi_password_ta, textarea_focus_event_cb, LV_EVENT_DEFOCUSED, NULL);

    lv_obj_t *wifi_pwd_eye = lv_button_create(wifi_pwd_row);
    lv_obj_set_size(wifi_pwd_eye, 48, 48);
    lv_obj_set_style_radius(wifi_pwd_eye, 12, 0);
    lv_obj_set_style_border_width(wifi_pwd_eye, 0, 0);
    lv_obj_set_style_bg_color(wifi_pwd_eye, lv_color_hex(0x374151), 0);
    lv_obj_t *wifi_pwd_eye_lbl = lv_label_create(wifi_pwd_eye);
    lv_label_set_text(wifi_pwd_eye_lbl, LV_SYMBOL_EYE_OPEN);
    lv_obj_set_style_text_color(wifi_pwd_eye_lbl, lv_color_hex(0xD1D5DB), 0);
    lv_obj_center(wifi_pwd_eye_lbl);
    lv_obj_add_event_cb(wifi_pwd_eye, pwd_toggle_event_cb, LV_EVENT_CLICKED, s_ui.wifi_password_ta);

    /* --- Enterprise (802.1x) toggle row --- */
    lv_obj_t *eap_row = lv_obj_create(s_ui.wifi_cfg_page);
    lv_obj_set_width(eap_row, lv_pct(100));
    lv_obj_set_height(eap_row, LV_SIZE_CONTENT);
    lv_obj_set_style_bg_opa(eap_row, LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_width(eap_row, 0, 0);
    lv_obj_set_style_pad_all(eap_row, 0, 0);
    lv_obj_set_style_pad_column(eap_row, 8, 0);
    lv_obj_set_layout(eap_row, LV_LAYOUT_FLEX);
    lv_obj_set_flex_flow(eap_row, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(eap_row, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);

    lv_obj_t *eap_label = lv_label_create(eap_row);
    lv_label_set_text(eap_label, "802.1x (Eduroam)");
    lv_obj_set_style_text_color(eap_label, lv_color_hex(0xD1D5DB), 0);
    lv_obj_set_flex_grow(eap_label, 1);

    s_ui.wifi_eap_sw = lv_switch_create(eap_row);
    lv_obj_set_style_bg_color(s_ui.wifi_eap_sw, lv_color_hex(0x2563EB), LV_PART_INDICATOR | LV_STATE_CHECKED);
    if (s_wifi_cfg.eap_enabled) {
        lv_obj_add_state(s_ui.wifi_eap_sw, LV_STATE_CHECKED);
    }
    lv_obj_add_event_cb(s_ui.wifi_eap_sw, wifi_eap_toggle_event_cb, LV_EVENT_VALUE_CHANGED, NULL);

    /* Container fuer EAP-spezifische Felder */
    s_ui.wifi_eap_cont = lv_obj_create(s_ui.wifi_cfg_page);
    lv_obj_set_width(s_ui.wifi_eap_cont, lv_pct(100));
    lv_obj_set_height(s_ui.wifi_eap_cont, LV_SIZE_CONTENT);
    lv_obj_set_style_bg_opa(s_ui.wifi_eap_cont, LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_width(s_ui.wifi_eap_cont, 0, 0);
    lv_obj_set_style_pad_all(s_ui.wifi_eap_cont, 0, 0);
    lv_obj_set_style_pad_row(s_ui.wifi_eap_cont, 6, 0);
    lv_obj_set_layout(s_ui.wifi_eap_cont, LV_LAYOUT_FLEX);
    lv_obj_set_flex_flow(s_ui.wifi_eap_cont, LV_FLEX_FLOW_COLUMN);
    if (!s_wifi_cfg.eap_enabled) {
        lv_obj_add_flag(s_ui.wifi_eap_cont, LV_OBJ_FLAG_HIDDEN);
    }

    s_ui.wifi_eap_identity_ta = lv_textarea_create(s_ui.wifi_eap_cont);
    lv_obj_set_width(s_ui.wifi_eap_identity_ta, lv_pct(100));
    lv_textarea_set_one_line(s_ui.wifi_eap_identity_ta, true);
    lv_textarea_set_placeholder_text(s_ui.wifi_eap_identity_ta, "Aeussere Identitaet (z.B. anonymous@hsd.de)");
    lv_textarea_set_text(s_ui.wifi_eap_identity_ta, s_wifi_cfg.eap_identity[0] ? s_wifi_cfg.eap_identity : "");
    lv_obj_add_event_cb(s_ui.wifi_eap_identity_ta, textarea_focus_event_cb, LV_EVENT_FOCUSED, NULL);
    lv_obj_add_event_cb(s_ui.wifi_eap_identity_ta, textarea_focus_event_cb, LV_EVENT_DEFOCUSED, NULL);

    s_ui.wifi_eap_username_ta = lv_textarea_create(s_ui.wifi_eap_cont);
    lv_obj_set_width(s_ui.wifi_eap_username_ta, lv_pct(100));
    lv_textarea_set_one_line(s_ui.wifi_eap_username_ta, true);
    lv_textarea_set_placeholder_text(s_ui.wifi_eap_username_ta, "Username (z.B. user@hsd.de)");
    lv_textarea_set_text(s_ui.wifi_eap_username_ta, s_wifi_cfg.eap_username[0] ? s_wifi_cfg.eap_username : "");
    lv_obj_add_event_cb(s_ui.wifi_eap_username_ta, textarea_focus_event_cb, LV_EVENT_FOCUSED, NULL);
    lv_obj_add_event_cb(s_ui.wifi_eap_username_ta, textarea_focus_event_cb, LV_EVENT_DEFOCUSED, NULL);
    lv_obj_t *dhcp_row = lv_obj_create(s_ui.wifi_cfg_page);
    lv_obj_set_width(dhcp_row, lv_pct(100));
    lv_obj_set_height(dhcp_row, LV_SIZE_CONTENT);
    lv_obj_set_style_bg_opa(dhcp_row, LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_width(dhcp_row, 0, 0);
    lv_obj_set_style_pad_all(dhcp_row, 0, 0);
    lv_obj_set_style_pad_column(dhcp_row, 8, 0);
    lv_obj_set_layout(dhcp_row, LV_LAYOUT_FLEX);
    lv_obj_set_flex_flow(dhcp_row, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(dhcp_row, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);

    lv_obj_t *dhcp_label = lv_label_create(dhcp_row);
    lv_label_set_text(dhcp_label, "DHCP");
    lv_obj_set_style_text_color(dhcp_label, lv_color_hex(0xD1D5DB), 0);
    lv_obj_set_flex_grow(dhcp_label, 1);

    s_ui.wifi_dhcp_sw = lv_switch_create(dhcp_row);
    lv_obj_set_style_bg_color(s_ui.wifi_dhcp_sw, lv_color_hex(0x2563EB), LV_PART_INDICATOR | LV_STATE_CHECKED);
    if (s_wifi_cfg.dhcp_enabled) {
        lv_obj_add_state(s_ui.wifi_dhcp_sw, LV_STATE_CHECKED);
    }
    lv_obj_add_event_cb(s_ui.wifi_dhcp_sw, wifi_dhcp_toggle_event_cb, LV_EVENT_VALUE_CHANGED, NULL);

    /* --- Static IP container (hidden when DHCP active) --- */
    s_ui.wifi_static_ip_cont = lv_obj_create(s_ui.wifi_cfg_page);
    lv_obj_set_width(s_ui.wifi_static_ip_cont, lv_pct(100));
    lv_obj_set_height(s_ui.wifi_static_ip_cont, LV_SIZE_CONTENT);
    lv_obj_set_style_bg_opa(s_ui.wifi_static_ip_cont, LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_width(s_ui.wifi_static_ip_cont, 0, 0);
    lv_obj_set_style_pad_all(s_ui.wifi_static_ip_cont, 0, 0);
    lv_obj_set_style_pad_row(s_ui.wifi_static_ip_cont, 6, 0);
    lv_obj_set_layout(s_ui.wifi_static_ip_cont, LV_LAYOUT_FLEX);
    lv_obj_set_flex_flow(s_ui.wifi_static_ip_cont, LV_FLEX_FLOW_COLUMN);
    if (s_wifi_cfg.dhcp_enabled) {
        lv_obj_add_flag(s_ui.wifi_static_ip_cont, LV_OBJ_FLAG_HIDDEN);
    }

    s_ui.wifi_ip_ta = lv_textarea_create(s_ui.wifi_static_ip_cont);
    lv_obj_set_width(s_ui.wifi_ip_ta, lv_pct(100));
    lv_textarea_set_one_line(s_ui.wifi_ip_ta, true);
    lv_textarea_set_placeholder_text(s_ui.wifi_ip_ta, "IP-Adresse (z.B. 192.168.1.100)");
    lv_textarea_set_text(s_ui.wifi_ip_ta, s_wifi_cfg.ip[0] ? s_wifi_cfg.ip : "");
    lv_obj_add_event_cb(s_ui.wifi_ip_ta, textarea_focus_event_cb, LV_EVENT_FOCUSED, NULL);
    lv_obj_add_event_cb(s_ui.wifi_ip_ta, textarea_focus_event_cb, LV_EVENT_DEFOCUSED, NULL);

    s_ui.wifi_gateway_ta = lv_textarea_create(s_ui.wifi_static_ip_cont);
    lv_obj_set_width(s_ui.wifi_gateway_ta, lv_pct(100));
    lv_textarea_set_one_line(s_ui.wifi_gateway_ta, true);
    lv_textarea_set_placeholder_text(s_ui.wifi_gateway_ta, "Gateway (z.B. 192.168.1.1)");
    lv_textarea_set_text(s_ui.wifi_gateway_ta, s_wifi_cfg.gateway[0] ? s_wifi_cfg.gateway : "");
    lv_obj_add_event_cb(s_ui.wifi_gateway_ta, textarea_focus_event_cb, LV_EVENT_FOCUSED, NULL);
    lv_obj_add_event_cb(s_ui.wifi_gateway_ta, textarea_focus_event_cb, LV_EVENT_DEFOCUSED, NULL);

    s_ui.wifi_netmask_ta = lv_textarea_create(s_ui.wifi_static_ip_cont);
    lv_obj_set_width(s_ui.wifi_netmask_ta, lv_pct(100));
    lv_textarea_set_one_line(s_ui.wifi_netmask_ta, true);
    lv_textarea_set_placeholder_text(s_ui.wifi_netmask_ta, "Subnetzmaske (z.B. 255.255.255.0)");
    lv_textarea_set_text(s_ui.wifi_netmask_ta, s_wifi_cfg.netmask[0] ? s_wifi_cfg.netmask : "");
    lv_obj_add_event_cb(s_ui.wifi_netmask_ta, textarea_focus_event_cb, LV_EVENT_FOCUSED, NULL);
    lv_obj_add_event_cb(s_ui.wifi_netmask_ta, textarea_focus_event_cb, LV_EVENT_DEFOCUSED, NULL);

    s_ui.wifi_dns_ta = lv_textarea_create(s_ui.wifi_static_ip_cont);
    lv_obj_set_width(s_ui.wifi_dns_ta, lv_pct(100));
    lv_textarea_set_one_line(s_ui.wifi_dns_ta, true);
    lv_textarea_set_placeholder_text(s_ui.wifi_dns_ta, "DNS-Server (z.B. 8.8.8.8, optional)");
    lv_textarea_set_text(s_ui.wifi_dns_ta, s_wifi_cfg.dns[0] ? s_wifi_cfg.dns : "");
    lv_obj_add_event_cb(s_ui.wifi_dns_ta, textarea_focus_event_cb, LV_EVENT_FOCUSED, NULL);
    lv_obj_add_event_cb(s_ui.wifi_dns_ta, textarea_focus_event_cb, LV_EVENT_DEFOCUSED, NULL);

    lv_obj_t *wifi_apply_btn = create_primary_button(s_ui.wifi_cfg_page, "Speichern & Verbinden");
    lv_obj_add_event_cb(wifi_apply_btn, wifi_cfg_save_connect_event_cb, LV_EVENT_CLICKED, NULL);

    lv_obj_t *wifi_to_status_btn = create_primary_button(s_ui.wifi_cfg_page, "Board Status");
    lv_obj_set_style_bg_color(wifi_to_status_btn, lv_color_hex(0x374151), 0);
    lv_obj_add_event_cb(wifi_to_status_btn, wifi_cfg_show_status_page, LV_EVENT_CLICKED, NULL);

    /* --- Board status page (inside same modal) --- */
    s_ui.wifi_status_page = lv_obj_create(s_ui.wifi_cfg_modal);
    lv_obj_set_width(s_ui.wifi_status_page, lv_pct(100));
    lv_obj_set_height(s_ui.wifi_status_page, 0);
    lv_obj_set_flex_grow(s_ui.wifi_status_page, 1);
    lv_obj_set_style_bg_opa(s_ui.wifi_status_page, LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_width(s_ui.wifi_status_page, 0, 0);
    lv_obj_set_style_pad_all(s_ui.wifi_status_page, 0, 0);
    lv_obj_set_style_pad_row(s_ui.wifi_status_page, 8, 0);
    lv_obj_set_layout(s_ui.wifi_status_page, LV_LAYOUT_FLEX);
    lv_obj_set_flex_flow(s_ui.wifi_status_page, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_scrollbar_mode(s_ui.wifi_status_page, LV_SCROLLBAR_MODE_OFF);
    lv_obj_clear_flag(s_ui.wifi_status_page, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_add_flag(s_ui.wifi_status_page, LV_OBJ_FLAG_HIDDEN);

    lv_obj_t *status_title = lv_label_create(s_ui.wifi_status_page);
    lv_label_set_text(status_title, "Board Status");
    lv_obj_set_style_text_font(status_title, &lv_font_montserrat_20, 0);
    lv_obj_set_style_text_color(status_title, lv_color_hex(0xF9FAFB), 0);

    /* Sub-tab button row */
    lv_obj_t *tab_row = lv_obj_create(s_ui.wifi_status_page);
    lv_obj_set_width(tab_row, lv_pct(100));
    lv_obj_set_height(tab_row, LV_SIZE_CONTENT);
    lv_obj_set_style_bg_opa(tab_row, LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_width(tab_row, 0, 0);
    lv_obj_set_style_pad_all(tab_row, 0, 0);
    lv_obj_set_style_pad_column(tab_row, 6, 0);
    lv_obj_set_layout(tab_row, LV_LAYOUT_FLEX);
    lv_obj_set_flex_flow(tab_row, LV_FLEX_FLOW_ROW);

    s_ui.tab_net_btn = lv_button_create(tab_row);
    lv_obj_set_flex_grow(s_ui.tab_net_btn, 1);
    lv_obj_set_height(s_ui.tab_net_btn, 36);
    lv_obj_set_style_radius(s_ui.tab_net_btn, 10, 0);
    lv_obj_set_style_bg_color(s_ui.tab_net_btn, lv_color_hex(0x2563EB), 0);
    lv_obj_t *tab_net_lbl = lv_label_create(s_ui.tab_net_btn);
    lv_label_set_text(tab_net_lbl, "Netzwerk");
    lv_obj_set_style_text_color(tab_net_lbl, lv_color_hex(0xEFF6FF), 0);
    lv_obj_center(tab_net_lbl);
    lv_obj_add_event_cb(s_ui.tab_net_btn, status_tab_net_cb, LV_EVENT_CLICKED, NULL);

    s_ui.tab_bridge_btn = lv_button_create(tab_row);
    lv_obj_set_flex_grow(s_ui.tab_bridge_btn, 1);
    lv_obj_set_height(s_ui.tab_bridge_btn, 36);
    lv_obj_set_style_radius(s_ui.tab_bridge_btn, 10, 0);
    lv_obj_set_style_bg_color(s_ui.tab_bridge_btn, lv_color_hex(0x374151), 0);
    lv_obj_t *tab_bridge_lbl = lv_label_create(s_ui.tab_bridge_btn);
    lv_label_set_text(tab_bridge_lbl, "Bridge");
    lv_obj_set_style_text_color(tab_bridge_lbl, lv_color_hex(0xEFF6FF), 0);
    lv_obj_center(tab_bridge_lbl);
    lv_obj_add_event_cb(s_ui.tab_bridge_btn, status_tab_bridge_cb, LV_EVENT_CLICKED, NULL);

    s_ui.tab_sys_btn = lv_button_create(tab_row);
    lv_obj_set_flex_grow(s_ui.tab_sys_btn, 1);
    lv_obj_set_height(s_ui.tab_sys_btn, 36);
    lv_obj_set_style_radius(s_ui.tab_sys_btn, 10, 0);
    lv_obj_set_style_bg_color(s_ui.tab_sys_btn, lv_color_hex(0x374151), 0);
    lv_obj_t *tab_sys_lbl = lv_label_create(s_ui.tab_sys_btn);
    lv_label_set_text(tab_sys_lbl, "System");
    lv_obj_set_style_text_color(tab_sys_lbl, lv_color_hex(0xEFF6FF), 0);
    lv_obj_center(tab_sys_lbl);
    lv_obj_add_event_cb(s_ui.tab_sys_btn, status_tab_system_cb, LV_EVENT_CLICKED, NULL);

    /* Scrollbarer Inhaltsbereich fuer Tab-Content – Title und Tab-Leiste bleiben oben fixiert */
    lv_obj_t *tab_scroll_area = lv_obj_create(s_ui.wifi_status_page);
    lv_obj_set_width(tab_scroll_area, lv_pct(100));
    lv_obj_set_height(tab_scroll_area, 0);
    lv_obj_set_flex_grow(tab_scroll_area, 1);
    lv_obj_set_style_bg_opa(tab_scroll_area, LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_width(tab_scroll_area, 0, 0);
    lv_obj_set_style_pad_all(tab_scroll_area, 0, 0);
    lv_obj_set_layout(tab_scroll_area, LV_LAYOUT_FLEX);
    lv_obj_set_flex_flow(tab_scroll_area, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_scrollbar_mode(tab_scroll_area, LV_SCROLLBAR_MODE_AUTO);
    lv_obj_add_flag(tab_scroll_area, LV_OBJ_FLAG_SCROLLABLE);

    /* --- Network sub-tab --- */
    s_ui.status_tab_net = lv_obj_create(tab_scroll_area);
    lv_obj_set_width(s_ui.status_tab_net, lv_pct(100));
    lv_obj_set_height(s_ui.status_tab_net, LV_SIZE_CONTENT);
    lv_obj_set_style_bg_opa(s_ui.status_tab_net, LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_width(s_ui.status_tab_net, 0, 0);
    lv_obj_set_style_pad_all(s_ui.status_tab_net, 0, 0);
    lv_obj_set_style_pad_row(s_ui.status_tab_net, 10, 0);
    lv_obj_set_layout(s_ui.status_tab_net, LV_LAYOUT_FLEX);
    lv_obj_set_flex_flow(s_ui.status_tab_net, LV_FLEX_FLOW_COLUMN);

    s_ui.status_net_label = lv_label_create(s_ui.status_tab_net);
    lv_label_set_text(s_ui.status_net_label, "Lade...");
    lv_obj_set_width(s_ui.status_net_label, lv_pct(100));
    lv_obj_set_style_text_color(s_ui.status_net_label, lv_color_hex(0xCBD5E1), 0);

    lv_obj_t *net_to_wifi_btn = create_primary_button(s_ui.status_tab_net, "WLAN Konfiguration");
    lv_obj_set_style_bg_color(net_to_wifi_btn, lv_color_hex(0x374151), 0);
    lv_obj_add_event_cb(net_to_wifi_btn, wifi_cfg_show_wifi_page, LV_EVENT_CLICKED, NULL);

    /* --- Bridge sub-tab --- */
    s_ui.status_tab_bridge = lv_obj_create(tab_scroll_area);
    lv_obj_set_width(s_ui.status_tab_bridge, lv_pct(100));
    lv_obj_set_height(s_ui.status_tab_bridge, LV_SIZE_CONTENT);
    lv_obj_set_style_bg_opa(s_ui.status_tab_bridge, LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_width(s_ui.status_tab_bridge, 0, 0);
    lv_obj_set_style_pad_all(s_ui.status_tab_bridge, 0, 0);
    lv_obj_set_style_pad_row(s_ui.status_tab_bridge, 10, 0);
    lv_obj_set_layout(s_ui.status_tab_bridge, LV_LAYOUT_FLEX);
    lv_obj_set_flex_flow(s_ui.status_tab_bridge, LV_FLEX_FLOW_COLUMN);
    lv_obj_add_flag(s_ui.status_tab_bridge, LV_OBJ_FLAG_HIDDEN);

    s_ui.status_bridge_label = lv_label_create(s_ui.status_tab_bridge);
    lv_label_set_text(s_ui.status_bridge_label, "Lade...");
    lv_obj_set_width(s_ui.status_bridge_label, lv_pct(100));
    lv_obj_set_style_text_color(s_ui.status_bridge_label, lv_color_hex(0xCBD5E1), 0);

    s_ui.measure_idle_btn = create_primary_button(s_ui.status_tab_bridge, LV_SYMBOL_CHARGE " Idle-Strom messen");
    lv_obj_set_style_bg_color(s_ui.measure_idle_btn, lv_color_hex(0x0F766E), 0);
    lv_obj_add_event_cb(s_ui.measure_idle_btn, measure_idle_current_event_cb, LV_EVENT_CLICKED, NULL);

    /* --- System sub-tab --- */
    s_ui.status_tab_system = lv_obj_create(tab_scroll_area);
    lv_obj_set_width(s_ui.status_tab_system, lv_pct(100));
    lv_obj_set_height(s_ui.status_tab_system, LV_SIZE_CONTENT);
    lv_obj_set_style_bg_opa(s_ui.status_tab_system, LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_width(s_ui.status_tab_system, 0, 0);
    lv_obj_set_style_pad_all(s_ui.status_tab_system, 0, 0);
    lv_obj_set_style_pad_row(s_ui.status_tab_system, 10, 0);
    lv_obj_set_layout(s_ui.status_tab_system, LV_LAYOUT_FLEX);
    lv_obj_set_flex_flow(s_ui.status_tab_system, LV_FLEX_FLOW_COLUMN);
    lv_obj_add_flag(s_ui.status_tab_system, LV_OBJ_FLAG_HIDDEN);

    s_ui.status_system_label = lv_label_create(s_ui.status_tab_system);
    lv_label_set_text(s_ui.status_system_label, "Lade...");
    lv_obj_set_width(s_ui.status_system_label, lv_pct(100));
    lv_obj_set_style_text_color(s_ui.status_system_label, lv_color_hex(0xCBD5E1), 0);

    /* Debug overlay toggle row */
    lv_obj_t *debug_row = lv_obj_create(s_ui.status_tab_system);
    lv_obj_set_width(debug_row, lv_pct(100));
    lv_obj_set_height(debug_row, LV_SIZE_CONTENT);
    lv_obj_set_style_bg_opa(debug_row, LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_width(debug_row, 0, 0);
    lv_obj_set_style_pad_all(debug_row, 0, 0);
    lv_obj_set_layout(debug_row, LV_LAYOUT_FLEX);
    lv_obj_set_flex_flow(debug_row, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(debug_row, LV_FLEX_ALIGN_SPACE_BETWEEN, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);

    lv_obj_t *debug_lbl = lv_label_create(debug_row);
    lv_label_set_text(debug_lbl, "Performance Overlay");
    lv_obj_set_style_text_color(debug_lbl, lv_color_hex(0xCBD5E1), 0);

    lv_obj_t *debug_sw = lv_switch_create(debug_row);
    lv_obj_add_event_cb(debug_sw, debug_overlay_toggle_event_cb, LV_EVENT_VALUE_CHANGED, NULL);

    /* OTA-Update-Bereich im System-Tab */
    lv_obj_t *ota_sep = lv_label_create(s_ui.status_tab_system);
    lv_label_set_text(ota_sep, "-- Firmware Update --");
    lv_obj_set_style_text_color(ota_sep, lv_color_hex(0x6B7280), 0);
    lv_obj_set_width(ota_sep, lv_pct(100));

    s_ui.ota_status_label = lv_label_create(s_ui.status_tab_system);
    lv_label_set_text(s_ui.ota_status_label, "v" APP_VERSION " - Auf Update pruefen");
    lv_obj_set_style_text_color(s_ui.ota_status_label, lv_color_hex(0x93C5FD), 0);
    lv_obj_set_width(s_ui.ota_status_label, lv_pct(100));

    s_ui.ota_btn = create_primary_button(s_ui.status_tab_system, LV_SYMBOL_REFRESH " Firmware Update");
    lv_obj_set_style_bg_color(s_ui.ota_btn, lv_color_hex(0x0F766E), 0);
    lv_obj_add_event_cb(s_ui.ota_btn, ota_check_event_cb, LV_EVENT_CLICKED, NULL);

    /* Schliessen-Button immer am unteren Rand des Modals (ausserhalb beider Pages) */
    lv_obj_t *modal_close_btn = create_primary_button(s_ui.wifi_cfg_modal, "Schliessen");
    lv_obj_set_style_bg_color(modal_close_btn, lv_color_hex(0x374151), 0);
    lv_obj_set_style_margin_top(modal_close_btn, 8, 0);
    lv_obj_add_event_cb(modal_close_btn, wifi_cfg_close_event_cb, LV_EVENT_CLICKED, NULL);

    s_ui.keyboard = lv_keyboard_create(screen);
    lv_obj_set_size(s_ui.keyboard, lv_pct(100), lv_pct(40));
    lv_obj_align(s_ui.keyboard, LV_ALIGN_BOTTOM_MID, 0, 0);
    lv_obj_add_flag(s_ui.keyboard, LV_OBJ_FLAG_HIDDEN);
    lv_obj_add_event_cb(s_ui.keyboard, keyboard_event_cb, LV_EVENT_ALL, NULL);

    /* Unlock status indicator (top-right) */
    s_ui.unlock_indicator = lv_obj_create(screen);
    lv_obj_set_size(s_ui.unlock_indicator, 150, 44);
    lv_obj_align(s_ui.unlock_indicator, LV_ALIGN_TOP_RIGHT, -12, 12);
    lv_obj_set_style_radius(s_ui.unlock_indicator, 8, 0);
    lv_obj_set_style_bg_color(s_ui.unlock_indicator, lv_color_hex(0xEF4444), 0);
    lv_obj_set_style_bg_opa(s_ui.unlock_indicator, LV_OPA_COVER, 0);
    lv_obj_set_style_border_width(s_ui.unlock_indicator, 0, 0);
    lv_obj_set_style_pad_all(s_ui.unlock_indicator, 0, 0);
    lv_obj_clear_flag(s_ui.unlock_indicator, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_add_flag(s_ui.unlock_indicator, LV_OBJ_FLAG_CLICKABLE);
    lv_obj_add_event_cb(s_ui.unlock_indicator, unlock_indicator_click_cb, LV_EVENT_CLICKED, NULL);

    s_ui.unlock_text_label = lv_label_create(s_ui.unlock_indicator);
    lv_label_set_text(s_ui.unlock_text_label, LV_SYMBOL_CLOSE " Gesperrt");
    lv_obj_set_style_text_color(s_ui.unlock_text_label, lv_color_hex(0xFFFFFF), 0);
    lv_obj_center(s_ui.unlock_text_label);

    lv_timer_create(auth_result_timer_cb, 120, NULL);
    lv_timer_create(pwrkey_timer_cb, 200, NULL);
    lv_timer_create(heartbeat_timer_cb, 30000, NULL);
    lv_timer_create(unlock_timer_cb, 500, NULL);

    s_debug_label = lv_label_create(screen);
    lv_obj_set_style_text_color(s_debug_label, lv_color_hex(0x374151), 0);
    lv_label_set_text(s_debug_label, "VSync:--Hz  PSRAM:--KB  SRAM:--KB");
    lv_obj_align(s_debug_label, LV_ALIGN_BOTTOM_LEFT, 8, -10);
    lv_obj_add_flag(s_debug_label, LV_OBJ_FLAG_HIDDEN);
    lv_timer_create(debug_overlay_timer_cb, 1000, NULL);
}

#if ENABLE_NFC
/* ════════════════════════════════════════════════════════════════════════════
 * PN532 Direkt-I2C-Kommunikation (Adresse 0x54)
 * Standard PN532 Framing: Preamble, Start-Code, LEN/LCS, TFI, Data, DCS, Postamble
 * Kein Bridge-Chip, kein Zwischenprotokoll.
 * ════════════════════════════════════════════════════════════════════════════ */

/* Baut ein PN532-I2C-Frame und sendet es an den Chip */
static esp_err_t pn532_write_frame(const uint8_t *cmd, size_t cmd_len)
{
    if ((cmd_len + 8u) > 32u) {
        return ESP_ERR_INVALID_SIZE;
    }
    uint8_t frame[32];
    size_t idx = 0;
    frame[idx++] = 0x00u; /* Preamble */
    frame[idx++] = 0x00u; /* Start Code 1 */
    frame[idx++] = 0xFFu; /* Start Code 2 */
    uint8_t len = (uint8_t)(cmd_len + 1u); /* LEN = TFI + data */
    frame[idx++] = len;
    frame[idx++] = (uint8_t)(0x100u - len); /* LCS */
    frame[idx++] = PN532_HOSTTOPN532;       /* TFI: Host -> PN532 */
    uint8_t dcs = PN532_HOSTTOPN532;
    for (size_t i = 0; i < cmd_len; i++) {
        frame[idx++] = cmd[i];
        dcs += cmd[i];
    }
    frame[idx++] = (uint8_t)(0x100u - dcs); /* DCS */
    frame[idx++] = 0x00u; /* Postamble */
    return i2c_master_transmit(s_pn532_dev, frame, idx, PN532_I2C_RX_TIMEOUT_MS);
}

/* Wartet bis PN532 Daten bereitstellt (Statusbyte bit0 = 1) */
static esp_err_t pn532_wait_ready(int timeout_ms)
{
    uint8_t status = 0;
    int elapsed = 0;
    while (elapsed < timeout_ms) {
        /* Kurzer Timeout: Status-Byte ist sofort verfuegbar wenn bereit,
         * kein Clock-Stretching erwartet → schnell freigeben fuer GT911 */
        esp_err_t err = i2c_master_receive(s_pn532_dev, &status, 1, PN532_STATUS_POLL_TIMEOUT_MS);
        if ((err == ESP_OK) && (status & 0x01u)) {
            return ESP_OK;
        }
        /* Laengeres Intervall: GT911 bekommt genug Bus-Fenster zwischen Polls */
        vTaskDelay(pdMS_TO_TICKS(PN532_WAIT_READY_INTERVAL_MS));
        elapsed += PN532_WAIT_READY_INTERVAL_MS;
    }
    return ESP_ERR_TIMEOUT;
}

/* Liest PN532-Antwortframe; gibt Nutzlast (ohne TFI+CMD) zurueck.
 * Layout: [status][0x00][0x00][0xFF][LEN][LCS][TFI=0xD5][CMD+1][data...][DCS][0x00] */
static esp_err_t pn532_read_response(uint8_t *buf, size_t buf_len, size_t *out_len)
{
    uint8_t tmp[64] = {0};
    size_t read_sz = buf_len + 10u;
    if (read_sz > sizeof(tmp)) {
        read_sz = sizeof(tmp);
    }
    esp_err_t err = i2c_master_receive(s_pn532_dev, tmp, read_sz, PN532_I2C_RX_TIMEOUT_MS);
    if (err != ESP_OK) {
        return err;
    }
    /* tmp[0]=status, tmp[3]=0xFF markiert gültigen Frame-Start */
    if ((read_sz < 9u) || (tmp[3] != 0xFFu)) {
        return ESP_ERR_INVALID_RESPONSE;
    }
    uint8_t frame_len = tmp[4]; /* TFI + CMD + Payload */
    size_t data_len = (frame_len >= 2u) ? (size_t)(frame_len - 2u) : 0u;
    if (out_len) {
        *out_len = data_len;
    }
    if (data_len > buf_len) {
        data_len = buf_len;
    }
    if (data_len > 0u) {
        memcpy(buf, &tmp[8], data_len);
    }
    return ESP_OK;
}

/* Wakeup: schickt Dummy-Bytes um PN532 aus Power-Down zu holen */
static void pn532_wakeup(void)
{
    uint8_t wake[16];
    memset(wake, 0x55, sizeof(wake));
    i2c_master_transmit(s_pn532_dev, wake, sizeof(wake), PN532_I2C_RX_TIMEOUT_MS);
    vTaskDelay(pdMS_TO_TICKS(10));
}

/* SAMConfiguration: Normalmodus, kein IRQ */
static esp_err_t pn532_sam_config(void)
{
    /* Cmd=0x14, Normalmodus, Timeout=0x14 (20x50ms=1s), no IRQ */
    const uint8_t cmd[] = { PN532_CMD_SAMCONFIGURATION, 0x01u, 0x14u, 0x00u };
    esp_err_t err = pn532_write_frame(cmd, sizeof(cmd));
    if (err != ESP_OK) {
        return err;
    }
    vTaskDelay(pdMS_TO_TICKS(10)); /* PN532 parst Command, bevor erstem Status-Poll */
    err = pn532_wait_ready(PN532_ACK_TIMEOUT_MS);
    if (err != ESP_OK) {
        return err;
    }
    uint8_t ack[7] = {0};
    i2c_master_receive(s_pn532_dev, ack, sizeof(ack), PN532_I2C_RX_TIMEOUT_MS);
    err = pn532_wait_ready(PN532_CMD_TIMEOUT_MS);
    if (err != ESP_OK) {
        return err;
    }
    uint8_t resp[4] = {0};
    size_t resp_len = 0;
    return pn532_read_response(resp, sizeof(resp), &resp_len);
}

/* InListPassiveTarget: Sucht eine ISO14443A-Karte (106 kbps).
 * Blockiert bis zu PN532_SCAN_TIMEOUT_MS. uid_len=0 wenn keine Karte. */
static esp_err_t pn532_list_passive_target(uint8_t *uid_out, uint8_t *uid_len_out)
{
    *uid_len_out = 0;
    /* MaxTg=1, BrTy=0x00 = 106kbps ISO14443A */
    const uint8_t cmd[] = { PN532_CMD_INLISTPASSIVETARGET, 0x01u, 0x00u };
    esp_err_t err = pn532_write_frame(cmd, sizeof(cmd));
    if (err != ESP_OK) {
        return err;
    }
    vTaskDelay(pdMS_TO_TICKS(10)); /* PN532 parst Command, bevor erstem Status-Poll */
    /* Warten auf ACK vom PN532 */
    err = pn532_wait_ready(PN532_ACK_TIMEOUT_MS);
    if (err != ESP_OK) {
        return ESP_ERR_TIMEOUT;
    }
    uint8_t ack[7] = {0};
    i2c_master_receive(s_pn532_dev, ack, sizeof(ack), PN532_I2C_RX_TIMEOUT_MS);
    /* Warten auf Scan-Ergebnis (Karte gefunden oder interner Timeout) */
    err = pn532_wait_ready(PN532_SCAN_TIMEOUT_MS);
    if (err == ESP_ERR_TIMEOUT) {
        return ESP_OK; /* Keine Karte – kein Fehler */
    }
    if (err != ESP_OK) {
        return err;
    }
    /* Antwort: [0]=NbTg [1]=Tg [2]=ATQA_H [3]=ATQA_L [4]=SAK [5]=NFCIDLen [6..]=NFCID */
    uint8_t resp[24] = {0};
    size_t resp_len = 0;
    err = pn532_read_response(resp, sizeof(resp), &resp_len);
    if (err != ESP_OK) {
        return err;
    }
    if ((resp_len < 6u) || (resp[0] == 0u)) {
        return ESP_OK; /* Kein Target */
    }
    uint8_t nfcid_len = resp[5];
    if ((nfcid_len == 0u) || (nfcid_len > PN532_UID_MAX_LEN) ||
        ((size_t)(6u + nfcid_len) > resp_len)) {
        return ESP_OK;
    }
    memcpy(uid_out, &resp[6], nfcid_len);
    *uid_len_out = nfcid_len;
    return ESP_OK;
}

/* PN532 I2C-Geraet vom Bus entfernen */
static esp_err_t pn532_deinit(void)
{
    if (s_pn532_dev != NULL) {
        esp_err_t err = i2c_master_bus_rm_device(s_pn532_dev);
        s_pn532_dev = NULL;
        return err;
    }
    return ESP_OK;
}

/* PN532 initialisieren: I2C-Bus, Adresse 0x54, Wakeup, SAMConfiguration */
static esp_err_t pn532_init(void)
{
    if (s_pn532_dev != NULL) {
        return ESP_OK;
    }

    ESP_RETURN_ON_ERROR(bsp_i2c_init(), TAG, "I2C init failed");

    i2c_master_bus_handle_t i2c_bus = bsp_i2c_get_handle();
    ESP_RETURN_ON_FALSE(i2c_bus != NULL, ESP_ERR_INVALID_STATE, TAG, "I2C bus not ready");

    i2c_device_config_t dev_cfg = {
        .dev_addr_length = I2C_ADDR_BIT_LEN_7,
        .device_address = PN532_I2C_ADDR,
        .scl_speed_hz = PN532_I2C_SCL_SPEED_HZ,
    };

    esp_err_t err = i2c_master_bus_add_device(i2c_bus, &dev_cfg, &s_pn532_dev);
    if (err != ESP_OK) {
        return err;
    }

    vTaskDelay(pdMS_TO_TICKS(10));
    pn532_wakeup();

    err = pn532_sam_config();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "PN532 SAMConfiguration failed: %s", esp_err_to_name(err));
        i2c_master_bus_rm_device(s_pn532_dev);
        s_pn532_dev = NULL;
        return err;
    }

    ESP_LOGI(TAG, "PN532 direkt initialisiert auf Adresse 0x%02X", PN532_I2C_ADDR);
    return ESP_OK;
}

/* PN532 neu initialisieren nach Kommunikationsfehlern */
static esp_err_t pn532_recover(void)
{
    esp_err_t err = pn532_deinit();
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "PN532 deinit failed: %s", esp_err_to_name(err));
    }
    /* Physischen I2C-Bus zuruecksetzen: loest haengende SDA/SCL (9 Dummy-Clocks) */
    i2c_master_bus_handle_t i2c_bus = bsp_i2c_get_handle();
    if (i2c_bus != NULL) {
        esp_err_t reset_err = i2c_master_bus_reset(i2c_bus);
        if (reset_err != ESP_OK) {
            ESP_LOGW(TAG, "I2C bus reset failed: %s", esp_err_to_name(reset_err));
        } else {
            ESP_LOGI(TAG, "I2C bus reset OK");
        }
    }
    vTaskDelay(pdMS_TO_TICKS(PN532_RECOVERY_DELAY_MS));
    return pn532_init();
}
#endif /* ENABLE_NFC */

/* ════════════════════════════════════════════════════════════════════════════
 * ADS1115 + PCF8574T – Sensor-Treiber
 *
 * ADS1115 (0x48): 16-Bit-ADC, 4 Single-Ended-Kanaele, PGA=±2.048 V, 128 SPS
 *   Konfigurationsregister (0x01) wird pro Kanal mit Single-Shot-Befehl beschrieben.
 *   Konversionsregister (0x00) wird nach ~15 ms gelesen.
 *   Spannungsaufloesung: 1 LSB = 62.5 µV  →  mV = raw * 2048 / 32768
 *
 * PCF8574T (0x20): Quasi-bidirektionale I/Os.
 *   Input:  0xFF schreiben (Port-Latch HIGH), dann 1 Byte lesen.
 *   Output: Gewuenschten Byte-Wert direkt schreiben.
 * ════════════════════════════════════════════════════════════════════════════ */

static esp_err_t sensors_init(void)
{
    ESP_RETURN_ON_ERROR(bsp_i2c_init(), TAG, "sensors: I2C init failed");
    i2c_master_bus_handle_t bus = bsp_i2c_get_handle();
    ESP_RETURN_ON_FALSE(bus != NULL, ESP_ERR_INVALID_STATE, TAG, "sensors: I2C bus null");

    /* ADS1115 */
    if (s_ads1115_dev == NULL) {
        i2c_device_config_t ads_cfg = {
            .dev_addr_length  = I2C_ADDR_BIT_LEN_7,
            .device_address   = ADS1115_I2C_ADDR,
            .scl_speed_hz     = ADS1115_I2C_SCL_SPEED_HZ,
        };
        esp_err_t e = i2c_master_bus_add_device(bus, &ads_cfg, &s_ads1115_dev);
        if (e == ESP_OK) {
            ESP_LOGI(TAG, "ADS1115 init OK (0x%02X)", ADS1115_I2C_ADDR);
        } else {
            ESP_LOGW(TAG, "ADS1115 not found at 0x%02X: %s", ADS1115_I2C_ADDR, esp_err_to_name(e));
            s_ads1115_dev = NULL;
        }
    }

    /* PCF8574T */
    if (s_pcf8574_dev == NULL) {
        i2c_device_config_t pcf_cfg = {
            .dev_addr_length  = I2C_ADDR_BIT_LEN_7,
            .device_address   = PCF8574_I2C_ADDR,
            .scl_speed_hz     = PCF8574_I2C_SCL_SPEED_HZ,
        };
        esp_err_t e = i2c_master_bus_add_device(bus, &pcf_cfg, &s_pcf8574_dev);
        if (e == ESP_OK) {
            ESP_LOGI(TAG, "PCF8574T init OK (0x%02X)", PCF8574_I2C_ADDR);
            /* Ausgaenge initialisieren: alle aus (active LOW = 1), Eingaenge auf 1 */
            uint8_t pcf_init = PCF_OUTPUT_MASK | PCF_INPUT_MASK;
            i2c_master_transmit(s_pcf8574_dev, &pcf_init, 1, pdMS_TO_TICKS(20));
            s_pcf_output = PCF_OUTPUT_MASK;
        } else {
            ESP_LOGW(TAG, "PCF8574T not found at 0x%02X: %s", PCF8574_I2C_ADDR, esp_err_to_name(e));
            s_pcf8574_dev = NULL;
        }
    }

    return ESP_OK;
}

/* Einen ADS1115-Kanal (0-3) einmalig im Single-Shot-Modus messen.
 * Config MSB-Werte fuer AIN0-GND (0xC5), AIN1-GND (0xD5), AIN2-GND (0xE5), AIN3-GND (0xF5):
 *   OS=1, MUX=1xx, PGA=010(±2.048V), MODE=1, DR=100(128SPS), COMP_QUE=11(disabled)  */
static int16_t ads1115_read_channel(uint8_t ch)
{
    if (s_ads1115_dev == NULL || ch > 3) {
        return 0;
    }
    static const uint8_t mux_msb[4] = {0xC5, 0xD5, 0xE5, 0xF5};

    /* Konfigurationsregister schreiben → Konversion starten */
    uint8_t cfg[3] = {0x01, mux_msb[ch], 0x83};
    esp_err_t e = i2c_master_transmit(s_ads1115_dev, cfg, sizeof(cfg), pdMS_TO_TICKS(50));
    if (e != ESP_OK) {
        return 0;
    }

    vTaskDelay(pdMS_TO_TICKS(15)); /* 128 SPS → ~7.8 ms; 15 ms Sicherheitsmarge */

    /* Auf Konversionsregister zeigen */
    uint8_t reg = 0x00;
    e = i2c_master_transmit(s_ads1115_dev, &reg, 1, pdMS_TO_TICKS(50));
    if (e != ESP_OK) {
        return 0;
    }

    /* 16-Bit-Ergebnis lesen */
    uint8_t buf[2] = {0};
    e = i2c_master_receive(s_ads1115_dev, buf, sizeof(buf), pdMS_TO_TICKS(50));
    if (e != ESP_OK) {
        return 0;
    }
    return (int16_t)((uint16_t)(buf[0] << 8) | buf[1]);
}

/* PCF8574T: gewuenschten Ausgangszustand schreiben (0=LOW, 1=HIGH/Input-floating) */
static void pcf8574_write(uint8_t val)
{
    if (s_pcf8574_dev == NULL) {
        return;
    }
    i2c_master_transmit(s_pcf8574_dev, &val, 1, pdMS_TO_TICKS(20));
}

/* Ausgangszustand P0-P3 setzen und senden; P4-P7 bleiben Eingaenge (1).
 * active LOW: bit=0 → aktiv (LED/Relais an), bit=1 → inaktiv. */
static void pcf8574_set_outputs(uint8_t outputs)
{
    s_pcf_output = outputs & PCF_OUTPUT_MASK;
    pcf8574_write(s_pcf_output | PCF_INPUT_MASK);
}

/* Alle Sensoren lesen und in globale Cache-Variablen schreiben.
 * Dauer: ~4 × 15 ms (ADS) + 2 ms (PCF) ≈ 62 ms → nur im Auth-Worker aufrufen. */
static void sensors_read(void)
{
    if (s_ads1115_dev != NULL) {
        for (int ch = 0; ch < 4; ch++) {
            s_ads_raw[ch] = ads1115_read_channel((uint8_t)ch);
        }
    }
    if (s_pcf8574_dev != NULL) {
        /* Ausgaenge beibehalten, Eingaenge (P4-P7) fuer Lesevorgang auf 1 setzen */
        pcf8574_write(s_pcf_output | PCF_INPUT_MASK);
        vTaskDelay(pdMS_TO_TICKS(2));
        uint8_t val = 0xFF;
        esp_err_t e = i2c_master_receive(s_pcf8574_dev, &val, 1, pdMS_TO_TICKS(20));
        if (e == ESP_OK) {
            s_pcf_input = val & PCF_INPUT_MASK;  /* nur Eingangsbits (P4-P7) speichern */
        }
    }
}

#if ENABLE_NFC
/* ════════════════════════════════════════════════════════════════════════════
 * NFC-Task: Core 0, kommuniziert direkt mit PN532 via I2C (Adresse 0x54).
 * Scannt per InListPassiveTarget, formatiert die UID und schickt Auth-Requests.
 * Zwei Modi:
 *   - Normal:   AUTH_SRC_NFC          → Karte zur Authentifizierung
 *   - Register: AUTH_SRC_REGISTER_CARD → Karte mit Benutzer verknuepfen
 * Polling pausiert bei: Modals offen, Auth laeuft, nicht-Start-View
 * (ausser im Register-Card-Modus).
 * ════════════════════════════════════════════════════════════════════════════ */

static void nfc_task(void *arg)
{
    LV_UNUSED(arg);
    char uid_text[40] = {0};
    char last_uid_text[40] = "";
    uint32_t scan_fail_streak = 0;
    ESP_LOGI(TAG, "nfc_task started on core %d", (int)xPortGetCoreID());

    esp_err_t err = pn532_init();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "PN532 init failed: %s", esp_err_to_name(err));
        set_status_text("NFC Fehler", lv_color_hex(0xFCA5A5));
        vTaskDelete(NULL);
        return;
    }

    while (1) {
        if (!auth_has_token() && s_wifi_has_ip && !s_auth_busy) {
            int64_t now_us = esp_timer_get_time();
            if ((s_setup_last_attempt_us == 0) || ((now_us - s_setup_last_attempt_us) >= ((int64_t)SETUP_RETRY_INTERVAL_MS * 1000))) {
                enqueue_setup_request_if_needed();
            }
        }

        if (s_reset_nfc_uid_requested) {
            last_uid_text[0] = '\0';
            s_reset_nfc_uid_requested = false;
        }

        if (s_auth_busy && (s_auth_busy_since_us > 0)) {
            int64_t busy_ms = (esp_timer_get_time() - s_auth_busy_since_us) / 1000;
            if (busy_ms > AUTH_BUSY_TIMEOUT_MS) {
                ESP_LOGW(TAG, "Auth busy timeout (%lld ms), force clear", (long long)busy_ms);
                set_auth_busy(false);
                set_status_text("Server Timeout, erneut versuchen", lv_color_hex(0xFCA5A5));
            }
        }

        if (((s_current_view != APP_VIEW_START) && !s_register_card_mode) || s_auth_busy || s_pause_nfc_polling) {
            vTaskDelay(pdMS_TO_TICKS(NFC_POLL_PAUSED_MS));
            continue;
        }

        /* PN532 nach Karte scannen (blockiert bis zu PN532_SCAN_TIMEOUT_MS) */
        uint8_t uid_buf[PN532_UID_MAX_LEN] = {0};
        uint8_t uid_len = 0;
        err = pn532_list_passive_target(uid_buf, &uid_len);

        if (err != ESP_OK) {
            scan_fail_streak++;
            if ((scan_fail_streak <= 3u) || (scan_fail_streak % 10u == 0u)) {
                ESP_LOGW(TAG, "PN532 scan error (%lu): %s", (unsigned long)scan_fail_streak, esp_err_to_name(err));
            }
            if (scan_fail_streak >= PN532_SCAN_FAIL_REINIT_THRESHOLD) {
                ESP_LOGW(TAG, "PN532 recovering after %lu errors", (unsigned long)scan_fail_streak);
                set_status_text("NFC wird neu gestartet...", lv_color_hex(0xFDE68A));
                esp_err_t recover_err = pn532_recover();
                if (recover_err != ESP_OK) {
                    ESP_LOGE(TAG, "PN532 recovery failed: %s", esp_err_to_name(recover_err));
                    set_status_text("NFC Fehler", lv_color_hex(0xFCA5A5));
                } else {
                    scan_fail_streak = 0;
                }
            }
            vTaskDelay(pdMS_TO_TICKS(NFC_POLL_AFTER_CARD_MS));
            continue;
        }

        scan_fail_streak = 0;

        if (uid_len == 0u) {
            /* Keine Karte im Feld */
            if (last_uid_text[0] != '\0') {
                last_uid_text[0] = '\0';
                set_nfc_uid_text("NFC UID: -", lv_color_hex(0x86EFAC));
            }
            /* Kein extra Delay: pn532_list_passive_target hat bereits bis zu
             * PN532_SCAN_TIMEOUT_MS gewartet, kurze Pause fuer anderen Task */
            vTaskDelay(pdMS_TO_TICKS(20));
            continue;
        }

        /* UID als Hex-String formatieren (mit ':' als Trennzeichen) */
        int written = 0;
        uid_text[0] = '\0';
        for (uint8_t i = 0; (i < uid_len) && (written >= 0) && (written < (int)sizeof(uid_text)); i++) {
            written += snprintf(&uid_text[written], sizeof(uid_text) - (size_t)written, "%02X", uid_buf[i]);
            if (i + 1 < uid_len) {
                written += snprintf(&uid_text[written], sizeof(uid_text) - (size_t)written, ":");
            }
        }

        /* Gleiche Karte noch im Feld – nicht erneut authentifizieren */
        if (strcmp(uid_text, last_uid_text) == 0) {
            vTaskDelay(pdMS_TO_TICKS(NFC_POLL_IDLE_MS));
            continue;
        }

        /* Neue Karte erkannt */
        char label_text[56] = {0};
        snprintf(label_text, sizeof(label_text), "NFC UID: %s", uid_text);
        set_nfc_uid_text(label_text, lv_color_hex(0x86EFAC));
        strncpy(last_uid_text, uid_text, sizeof(last_uid_text) - 1);
        last_uid_text[sizeof(last_uid_text) - 1] = '\0';

        if (!auth_has_token()) {
            set_status_text("Warte auf Geraete-Setup", lv_color_hex(0xFDE68A));
            vTaskDelay(pdMS_TO_TICKS(NFC_POLL_AFTER_CARD_MS));
            continue;
        }

        auth_request_t req = {
            .source = s_register_card_mode ? AUTH_SRC_REGISTER_CARD : AUTH_SRC_NFC,
        };
        /* Doppelpunkte entfernen (Server erwartet reinen Hex-String) */
        {
            size_t j = 0;
            for (size_t i = 0; (uid_text[i] != '\0') && (j < sizeof(req.value_a) - 1u); i++) {
                if (uid_text[i] != ':') {
                    req.value_a[j++] = uid_text[i];
                }
            }
            req.value_a[j] = '\0';
        }

        if (enqueue_auth_request(&req)) {
            set_auth_busy(true);
            if (s_register_card_mode) {
                s_register_card_mode = false;
                if (s_ui.result_text_label && bsp_display_lock(30)) {
                    set_label_text_color(s_ui.result_text_label, "Karte wird registriert...", lv_color_hex(0xFDE68A));
                    bsp_display_unlock();
                }
            } else {
                set_status_text("Karte wird geprueft...", lv_color_hex(0xFDE68A));
            }
        }

        vTaskDelay(pdMS_TO_TICKS(NFC_POLL_AFTER_CARD_MS));
    }
}
#endif /* ENABLE_NFC */

/* ════════════════════════════════════════════════════════════════════════════
 * app_main(): Einstiegspunkt – initialisiert Hardware, lädt Konfigurationen,
 * erstellt GUI und startet die FreeRTOS-Tasks (Auth-Worker, NFC-Polling).
 *
 * Boot-Reihenfolge:
 *   1. NVS init + I2C scan
 *   2. PWRKEY-ISR (GPIO 16) für WLAN-Modal per Hardware-Button
 *   3. WLAN/Auth/Bridge-Konfiguration aus NVS laden
 *   4. Display + IO-Expander initialisieren, VSync-Callback registrieren
 *   5. LVGL-UI erstellen
 *   6. Auth-Queue + Worker-Task starten
 *   7. WLAN verbinden (löst Setup/Heartbeat aus)
 *   8. NFC-Task starten (wenn ENABLE_NFC=1)
 * ════════════════════════════════════════════════════════════════════════════ */

void app_main(void)
{
    ESP_LOGI(TAG, "Core config: LVGL=%d AUTH=%d", LVGL_TASK_CORE_ID, AUTH_TASK_CORE_ID);
    esp_err_t err = nvs_flash_init();
    if ((err == ESP_ERR_NVS_NO_FREE_PAGES) || (err == ESP_ERR_NVS_NEW_VERSION_FOUND)) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    ESP_ERROR_CHECK(err);

    i2c_scan_log();
    sensors_init();  /* ADS1115 + PCF8574T initialisieren */

    /* PWRKEY (SYS_OUT) on GPIO 16: goes LOW when BAT_PWR button is pressed */
    {
        gpio_config_t io_conf = {
            .pin_bit_mask = (1ULL << PWRKEY_GPIO),
            .mode = GPIO_MODE_INPUT,
            .pull_up_en = GPIO_PULLUP_ENABLE,
            .pull_down_en = GPIO_PULLDOWN_DISABLE,
            .intr_type = GPIO_INTR_NEGEDGE,
        };
        ESP_ERROR_CHECK(gpio_config(&io_conf));
        ESP_ERROR_CHECK(gpio_install_isr_service(0));
        ESP_ERROR_CHECK(gpio_isr_handler_add(PWRKEY_GPIO, pwrkey_isr_handler, NULL));
        ESP_LOGI(TAG, "PWRKEY ISR installed on GPIO %d", PWRKEY_GPIO);
    }

    ESP_ERROR_CHECK(wifi_cfg_load(&s_wifi_cfg));
    ESP_ERROR_CHECK(auth_cfg_load(&s_auth_cfg));
    ESP_ERROR_CHECK(bridge_cfg_load(&s_bridge_cfg));
    /* Gespeicherten Messwert nach Neustart wiederherstellen */
    if (s_bridge_cfg.idle_current > 0.0f) {
        s_idle_current_measured_mV = s_bridge_cfg.idle_current;
    }
    if (s_auth_cfg.mac[0] == '\0') {
        if (get_device_mac_text(s_auth_cfg.mac, sizeof(s_auth_cfg.mac)) == ESP_OK) {
            auth_cfg_save(&s_auth_cfg);
        }
    }

    bsp_display_cfg_t display_cfg = {
        .lvgl_port_cfg = ESP_LVGL_PORT_INIT_CONFIG(),
    };
    display_cfg.lvgl_port_cfg.task_affinity = LVGL_TASK_CORE_ID;
    bsp_display_start_with_config(&display_cfg);

    s_io_expander = bsp_io_expander_init();
    if (!s_io_expander) {
        ESP_LOGW(TAG, "IO expander init failed, buzzer disabled");
    }

    {
        esp_lcd_panel_handle_t panel = bsp_get_panel_handle();
        if (panel) {
            const esp_lcd_rgb_panel_event_callbacks_t panel_cbs = {
                .on_vsync = vsync_event_cb,
            };
            esp_lcd_rgb_panel_register_event_callbacks(panel, &panel_cbs, NULL);
        }
    }

    bsp_display_lock(0);
    create_ui();
    update_machine_info_ui();
    bsp_display_unlock();

    s_auth_req_queue = xQueueCreate(AUTH_REQ_QUEUE_LEN, sizeof(auth_request_t));
    s_auth_res_queue = xQueueCreate(AUTH_RES_QUEUE_LEN, sizeof(auth_result_t));
    ESP_ERROR_CHECK(s_auth_req_queue != NULL ? ESP_OK : ESP_FAIL);
    ESP_ERROR_CHECK(s_auth_res_queue != NULL ? ESP_OK : ESP_FAIL);

    BaseType_t auth_task_ok = xTaskCreatePinnedToCore(auth_worker_task, "auth_worker", 8192, NULL, 5, NULL, AUTH_TASK_CORE_ID);
    if (auth_task_ok != pdPASS) {
        ESP_LOGE(TAG, "Auth worker start failed");
    }

    err = wifi_init_sta();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "WiFi init failed: %s", esp_err_to_name(err));
        set_status_text("WLAN Init Fehler", lv_color_hex(0xFCA5A5));
    }

#if ENABLE_NFC
    BaseType_t nfc_task_ok = xTaskCreatePinnedToCore(nfc_task, "nfc_task", 6144, NULL, 1, NULL, NFC_TASK_CORE_ID);
    if (nfc_task_ok != pdPASS) {
        ESP_LOGE(TAG, "NFC task start failed");
    }
#endif
}
