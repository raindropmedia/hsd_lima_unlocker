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

#define PN532_I2C_ADDR_BRIDGE 0x25
#define PN532_TFI_HOST_TO_PN532 0xD4
#define PN532_TFI_PN532_TO_HOST 0xD5
#define PN532_CMD_SAMCONFIGURATION 0x14
#define PN532_CMD_INLISTPASSIVETARGET 0x4A
#define PN532_CMD_INRELEASE 0x52

#define LVGL_TASK_CORE_ID 1
#define NFC_TASK_CORE_ID 0
#define AUTH_TASK_CORE_ID 1

#define AUTH_REQUIRE_PIN_AFTER_AUTH 1
#define WIFI_NAMESPACE "wifi_cfg"
#define WIFI_CFG_VERSION 1
#define AUTH_NAMESPACE "auth_cfg"
#define AUTH_CFG_VERSION 1

#define AUTH_URL_SETUP "https://192.168.0.241:5555/api/hsd/setup"
#define AUTH_URL_PING "https://192.168.0.241:5555/api/hsd/ping"
#define AUTH_URL_NFC "https://192.168.0.241:5555/api/hsd/nfc"
#define AUTH_URL_LOGIN "https://192.168.0.241:5555/api/hsd/login"
#define AUTH_URL_PIN "https://192.168.0.241:5555/api/hsd/pin"
#define DEV_TLS_INSECURE 1
#define AUTH_HTTP_RETRY_COUNT 2
#define AUTH_HTTP_RETRY_DELAY_MS 250

#define AUTH_REQ_QUEUE_LEN 4
#define AUTH_RES_QUEUE_LEN 4
#define AUTH_BUSY_TIMEOUT_MS 12000
#define SETUP_RETRY_INTERVAL_MS 15000
#define NFC_POLL_IDLE_MS 700
#define NFC_POLL_PAUSED_MS 250
#define NFC_POLL_AFTER_CARD_MS 1200
#define PN532_SCAN_FAIL_REINIT_THRESHOLD 6
#define PN532_RECOVERY_DELAY_MS 200
#define PN532_READY_TIMEOUT_MS 400
#define PN532_SAM_RETRY_COUNT 2
#define PN532_I2C_SCL_SPEED_HZ 50000
#define PN532_I2C_TX_TIMEOUT_MS 200
#define PN532_I2C_RX_TIMEOUT_MS 250
#define PN532_I2C_STATUS_RX_TIMEOUT_MS 80

static const char *TAG = "HSD_APP";
extern const char server_cert_pem_start[] asm("_binary_server_cert_pem_start");
extern const char server_cert_pem_end[] asm("_binary_server_cert_pem_end");

typedef struct {
    uint32_t version;
    uint8_t dhcp_enabled;
    char ssid[33];
    char password[65];
    char ip[16];
    char gateway[16];
    char netmask[16];
} wifi_store_t;

typedef enum {
    APP_VIEW_START = 0,
    APP_VIEW_PIN,
    APP_VIEW_RESULT,
} app_view_t;

typedef enum {
    AUTH_SRC_SETUP = 0,
    AUTH_SRC_TOKEN_CHECK,
    AUTH_SRC_NFC,
    AUTH_SRC_LOGIN,
    AUTH_SRC_PIN,
} auth_source_t;

typedef struct {
    auth_source_t source;
    char value_a[96];
    char value_b[96];
} auth_request_t;

typedef struct {
    auth_source_t source;
    bool success;
    int http_status;
    char token[96];
} auth_result_t;

typedef struct {
    uint32_t version;
    char token[96];
    char mac[18];
} auth_store_t;

typedef struct {
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
    lv_obj_t *wifi_ssid_dropdown;
    lv_obj_t *wifi_password_ta;
    lv_obj_t *wifi_cfg_status_label;
    lv_obj_t *keyboard;
} ui_handles_t;

typedef struct {
    char *response;
    size_t response_size;
    size_t response_len;
    char *token;
    size_t token_size;
} http_capture_t;

static i2c_master_dev_handle_t s_pn532_dev = NULL;
static uint16_t s_pn532_addr = 0;
static wifi_store_t s_wifi_cfg = {
    .version = WIFI_CFG_VERSION,
    .dhcp_enabled = 1,
};
static auth_store_t s_auth_cfg = {
    .version = AUTH_CFG_VERSION,
};
static esp_netif_t *s_wifi_netif = NULL;
static esp_event_handler_instance_t s_wifi_evt_instance = NULL;
static esp_event_handler_instance_t s_ip_evt_instance = NULL;

static QueueHandle_t s_auth_req_queue = NULL;
static QueueHandle_t s_auth_res_queue = NULL;
static ui_handles_t s_ui = {0};
static volatile bool s_auth_busy = false;
static volatile int64_t s_auth_busy_since_us = 0;
static volatile bool s_wifi_has_ip = false;
static volatile int64_t s_setup_last_attempt_us = 0;
static bool s_setup_log_verbose = true;
static volatile app_view_t s_current_view = APP_VIEW_START;
static volatile bool s_pause_nfc_polling = false;
static volatile bool s_reset_nfc_uid_requested = false;
static volatile uint32_t s_vsync_count = 0;
static lv_obj_t *s_debug_label = NULL;
static uint8_t s_cfg_click_count = 0;
static int64_t s_cfg_click_window_start_us = 0;
static char s_wifi_scan_options[1024] = "";

static void set_label_text_color(lv_obj_t *label, const char *text, lv_color_t color);
static void set_status_text(const char *text, lv_color_t color);
static void set_nfc_uid_text(const char *text, lv_color_t color);
static bool enqueue_auth_request(const auth_request_t *req);
static bool enqueue_setup_request_if_needed(void);
static bool enqueue_token_check_request_if_needed(void);

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

static void set_auth_busy(bool busy)
{
    s_auth_busy = busy;
    s_auth_busy_since_us = busy ? esp_timer_get_time() : 0;
}

static esp_err_t wifi_cfg_save(const wifi_store_t *cfg)
{
    nvs_handle_t nvs = 0;
    ESP_RETURN_ON_ERROR(nvs_open(WIFI_NAMESPACE, NVS_READWRITE, &nvs), TAG, "NVS open write failed");
    ESP_RETURN_ON_ERROR(nvs_set_blob(nvs, "store", cfg, sizeof(*cfg)), TAG, "NVS write failed");
    ESP_RETURN_ON_ERROR(nvs_commit(nvs), TAG, "NVS commit failed");
    nvs_close(nvs);
    return ESP_OK;
}

static void auth_cfg_set_defaults(auth_store_t *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    cfg->version = AUTH_CFG_VERSION;
}

static esp_err_t auth_cfg_save(const auth_store_t *cfg)
{
    nvs_handle_t nvs = 0;
    ESP_RETURN_ON_ERROR(nvs_open(AUTH_NAMESPACE, NVS_READWRITE, &nvs), TAG, "NVS auth open write failed");
    ESP_RETURN_ON_ERROR(nvs_set_blob(nvs, "store", cfg, sizeof(*cfg)), TAG, "NVS auth write failed");
    ESP_RETURN_ON_ERROR(nvs_commit(nvs), TAG, "NVS auth commit failed");
    nvs_close(nvs);
    return ESP_OK;
}

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

static bool auth_has_token(void)
{
    return s_auth_cfg.token[0] != '\0';
}

static esp_err_t get_device_mac_text(char *buffer, size_t buffer_size)
{
    uint8_t mac[6] = {0};

    ESP_RETURN_ON_FALSE((buffer != NULL) && (buffer_size >= 18), ESP_ERR_INVALID_ARG, TAG, "MAC buffer invalid");
    ESP_RETURN_ON_ERROR(esp_read_mac(mac, ESP_MAC_WIFI_STA), TAG, "read MAC failed");

    snprintf(buffer, buffer_size, "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return ESP_OK;
}

static void set_wifi_cfg_status_text(const char *text, lv_color_t color)
{
    if (s_ui.wifi_cfg_status_label && bsp_display_lock(30)) {
        set_label_text_color(s_ui.wifi_cfg_status_label, text, color);
        bsp_display_unlock();
    }
}

static void wifi_set_dropdown_options(const char *options)
{
    if (s_ui.wifi_ssid_dropdown && bsp_display_lock(50)) {
        lv_dropdown_set_options(s_ui.wifi_ssid_dropdown, options);
        bsp_display_unlock();
    }
}

static void wifi_cfg_set_defaults(wifi_store_t *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    cfg->version = WIFI_CFG_VERSION;
    cfg->dhcp_enabled = 1;
}

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

static bool parse_ipv4(const char *text, ip4_addr_t *out)
{
    if ((text == NULL) || (text[0] == '\0')) {
        return false;
    }
    return ip4addr_aton(text, out) == 1;
}

static esp_err_t wifi_connect_from_cfg(const wifi_store_t *cfg)
{
    wifi_config_t wifi_cfg = {0};
    size_t ssid_len = strnlen(cfg->ssid, sizeof(cfg->ssid));

    if (ssid_len == 0) {
        return ESP_ERR_INVALID_ARG;
    }

    memcpy(wifi_cfg.sta.ssid, cfg->ssid, ssid_len);
    memcpy(wifi_cfg.sta.password, cfg->password, strnlen(cfg->password, sizeof(cfg->password)));
    wifi_cfg.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;
    wifi_cfg.sta.pmf_cfg.capable = true;
    wifi_cfg.sta.pmf_cfg.required = false;

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
    }

    ESP_RETURN_ON_ERROR(esp_wifi_set_config(WIFI_IF_STA, &wifi_cfg), TAG, "WiFi set config failed");
    return esp_wifi_connect();
}

static void wifi_event_handler(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data)
{
    LV_UNUSED(arg);

    if ((event_base == WIFI_EVENT) && (event_id == WIFI_EVENT_STA_DISCONNECTED)) {
        s_wifi_has_ip = false;
        set_status_text("WLAN getrennt", lv_color_hex(0xFCA5A5));
        if (s_wifi_cfg.ssid[0] != '\0') {
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
            set_wifi_cfg_status_text("Scan fehlgeschlagen", lv_color_hex(0xFCA5A5));
            return;
        }

        if (ap_count == 0) {
            strncpy(s_wifi_scan_options, "Kein Netzwerk gefunden", sizeof(s_wifi_scan_options) - 1);
            s_wifi_scan_options[sizeof(s_wifi_scan_options) - 1] = '\0';
            wifi_set_dropdown_options(s_wifi_scan_options);
            set_wifi_cfg_status_text("Kein Netzwerk gefunden", lv_color_hex(0xFCA5A5));
            return;
        }

        if (ap_count > 30) {
            ap_count = 30;
        }

        ap_records = calloc(ap_count, sizeof(wifi_ap_record_t));
        if (ap_records == NULL) {
            set_wifi_cfg_status_text("Zu wenig RAM fuer Scan", lv_color_hex(0xFCA5A5));
            return;
        }

        if (esp_wifi_scan_get_ap_records(&ap_count, ap_records) != ESP_OK) {
            free(ap_records);
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
    }
}

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

static bool enqueue_token_check_request_if_needed(void)
{
    auth_request_t req = {0};

    if (!auth_has_token() || s_auth_busy || (s_auth_req_queue == NULL)) {
        return false;
    }

    req.source = AUTH_SRC_TOKEN_CHECK;
    if (!enqueue_auth_request(&req)) {
        return false;
    }

    set_auth_busy(true);
    set_status_text("Token wird geprueft...", lv_color_hex(0x93C5FD));
    return true;
}

static void set_label_text_color(lv_obj_t *label, const char *text, lv_color_t color)
{
    if (!label) {
        return;
    }
    lv_label_set_text(label, text);
    lv_obj_set_style_text_color(label, color, 0);
}

static void set_status_text(const char *text, lv_color_t color)
{
    if (s_ui.status_label && bsp_display_lock(30)) {
        set_label_text_color(s_ui.status_label, text, color);
        bsp_display_unlock();
    }
}

static void set_nfc_uid_text(const char *text, lv_color_t color)
{
    if (s_ui.nfc_uid_label && bsp_display_lock(30)) {
        set_label_text_color(s_ui.nfc_uid_label, text, color);
        bsp_display_unlock();
    }
}

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

    bsp_display_unlock();
    show_view(APP_VIEW_RESULT);
}

static bool enqueue_auth_request(const auth_request_t *req)
{
    if (!s_auth_req_queue) {
        return false;
    }
    return xQueueSend(s_auth_req_queue, req, 0) == pdTRUE;
}

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

static esp_err_t https_post_json(const char *url, const char *payload, int *http_status, bool *ok, char *response_out, size_t response_out_size, char *token_out, size_t token_out_size)
{
    char response[256] = {0};
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
        .cert_pem = server_cert_pem_start,
        .event_handler = http_capture_event_handler,
        .user_data = &capture,
    #if DEV_TLS_INSECURE
        .skip_cert_common_name_check = true,
    #endif
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

        char payload[256] = {0};
        char response[256] = {0};
        const char *url = AUTH_URL_NFC;

        res.source = req.source;
        res.success = false;
        res.http_status = 0;
        res.token[0] = '\0';

        if (req.source == AUTH_SRC_SETUP) {
            snprintf(payload, sizeof(payload), "{\"mac\":\"%s\"}", req.value_a);
            url = AUTH_URL_SETUP;
        } else if (req.source == AUTH_SRC_TOKEN_CHECK) {
            snprintf(payload, sizeof(payload), "{\"token\":\"%s\"}", s_auth_cfg.token);
            url = AUTH_URL_PING;
        } else if (req.source == AUTH_SRC_NFC) {
            snprintf(payload, sizeof(payload), "{\"token\":\"%s\",\"uid\":\"%s\"}", s_auth_cfg.token, req.value_a);
            url = AUTH_URL_NFC;
        } else if (req.source == AUTH_SRC_LOGIN) {
            snprintf(payload, sizeof(payload), "{\"token\":\"%s\",\"email\":\"%s\",\"password\":\"%s\"}", s_auth_cfg.token, req.value_a, req.value_b);
            url = AUTH_URL_LOGIN;
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

static void auth_result_timer_cb(lv_timer_t *timer)
{
    LV_UNUSED(timer);
    auth_result_t res = {0};

    while (xQueueReceive(s_auth_res_queue, &res, 0) == pdTRUE) {
        set_auth_busy(false);
        bool server_unreachable = (res.http_status <= 0);

        if (res.source == AUTH_SRC_SETUP) {
            if (res.success && (res.token[0] != '\0')) {
                strncpy(s_auth_cfg.token, res.token, sizeof(s_auth_cfg.token) - 1);
                s_auth_cfg.token[sizeof(s_auth_cfg.token) - 1] = '\0';
                auth_cfg_save(&s_auth_cfg);
                s_setup_log_verbose = false;
                ESP_LOGI(TAG, "Setup success, token stored: %s", s_auth_cfg.token);
                set_status_text("Geraet registriert", lv_color_hex(0x86EFAC));
            } else if (server_unreachable) {
                ESP_LOGW(TAG, "Setup failed: server unreachable (http_status=%d)", res.http_status);
                set_status_text("Setup Server nicht erreichbar", lv_color_hex(0xFCA5A5));
            } else {
                ESP_LOGW(TAG, "Setup failed: token missing or valid=false (http_status=%d)", res.http_status);
                set_status_text("Setup fehlgeschlagen", lv_color_hex(0xFCA5A5));
            }
            continue;
        }

        if (res.source == AUTH_SRC_TOKEN_CHECK) {
            if (res.success) {
                set_status_text("Token gueltig", lv_color_hex(0x86EFAC));
            } else if ((res.http_status >= 400) && (res.http_status < 500)) {
                ESP_LOGW(TAG, "Stored token invalid (http_status=%d), re-registering", res.http_status);
                s_auth_cfg.token[0] = '\0';
                auth_cfg_save(&s_auth_cfg);
                s_setup_log_verbose = true;
                s_setup_last_attempt_us = 0;
                set_status_text("Token ungueltig, registriere neu...", lv_color_hex(0xFCA5A5));
                enqueue_setup_request_if_needed();
            } else if (server_unreachable) {
                set_status_text("Tokencheck Server nicht erreichbar", lv_color_hex(0xFCA5A5));
            }
            continue;
        }

        if (res.source == AUTH_SRC_PIN) {
            if (res.success) {
                show_result_page(true, "Freigeschaltet");
            } else if (server_unreachable) {
                show_result_page(false, "Server nicht erreichbar");
            } else {
                show_result_page(false, "Falsche Eingabe");
            }
            continue;
        }

        if (res.success) {
#if AUTH_REQUIRE_PIN_AFTER_AUTH
            show_view(APP_VIEW_PIN);
            set_status_text("PIN eingeben", lv_color_hex(0x93C5FD));
#else
            show_result_page(true, "Freigeschaltet");
#endif
        } else if (server_unreachable) {
            show_result_page(false, "Server nicht erreichbar");
        } else {
            show_result_page(false, "Verweigert");
        }
    }
}

static void keyboard_event_cb(lv_event_t *event)
{
    lv_event_code_t code = lv_event_get_code(event);
    if ((code == LV_EVENT_READY) || (code == LV_EVENT_CANCEL)) {
        lv_keyboard_set_textarea(s_ui.keyboard, NULL);
        lv_obj_add_flag(s_ui.keyboard, LV_OBJ_FLAG_HIDDEN);
    }
}

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

static void back_to_start_event_cb(lv_event_t *event)
{
    LV_UNUSED(event);
    s_pause_nfc_polling = false;
    s_reset_nfc_uid_requested = true;
    show_view(APP_VIEW_START);
    set_nfc_uid_text("NFC UID: -", lv_color_hex(0x86EFAC));
    set_status_text("Bitte HSD Karte anlegen", lv_color_hex(0x93C5FD));
}

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
    if (strlen(pin) != 4) {
        set_status_text("PIN muss 4-stellig sein", lv_color_hex(0xFCA5A5));
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
    set_status_text("PIN wird geprueft...", lv_color_hex(0xFDE68A));
}

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

static void wifi_cfg_open_event_cb(lv_event_t *event)
{
    LV_UNUSED(event);
    int64_t now = esp_timer_get_time();

    if ((now - s_cfg_click_window_start_us) > 900000) {
        s_cfg_click_count = 0;
        s_cfg_click_window_start_us = now;
    }

    s_cfg_click_count++;

    if (s_cfg_click_count >= 3) {
        s_cfg_click_count = 0;
        s_pause_nfc_polling = true;
        if (!bsp_display_lock(100)) {
            return;
        }

        if (s_ui.wifi_cfg_modal) {
            lv_obj_clear_flag(s_ui.wifi_cfg_modal, LV_OBJ_FLAG_HIDDEN);
            lv_textarea_set_text(s_ui.wifi_password_ta, s_wifi_cfg.password);
        }

        bsp_display_unlock();
        set_wifi_cfg_status_text("WLAN Konfiguration", lv_color_hex(0x93C5FD));
    }
}

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

    bsp_display_unlock();
}

static void wifi_scan_event_cb(lv_event_t *event)
{
    LV_UNUSED(event);

    wifi_scan_config_t scan_cfg = {
        .show_hidden = false,
    };

    set_wifi_cfg_status_text("Scanne WLAN...", lv_color_hex(0xFDE68A));
    esp_err_t err = esp_wifi_scan_start(&scan_cfg, false);
    if (err != ESP_OK) {
        set_wifi_cfg_status_text("Scan Start Fehler", lv_color_hex(0xFCA5A5));
    }
}

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

static bool IRAM_ATTR vsync_event_cb(esp_lcd_panel_handle_t panel,
                                     const esp_lcd_rgb_panel_event_data_t *edata,
                                     void *user_ctx)
{
    (void)panel; (void)edata; (void)user_ctx;
    s_vsync_count++;
    return false;
}

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

    lv_obj_t *title = lv_label_create(s_ui.start_container);
    lv_label_set_text(title, "Bitte HSD Karte anlegen");
    lv_obj_set_style_text_font(title, &lv_font_montserrat_20, 0);
    lv_obj_set_style_text_color(title, lv_color_hex(0xF9FAFB), 0);

    lv_obj_t *hint = lv_label_create(s_ui.start_container);
    lv_label_set_text(hint, "NFC Karte anhalten oder HSD Login verwenden.");
    lv_obj_set_style_text_color(hint, lv_color_hex(0xCBD5E1), 0);

    s_ui.status_label = lv_label_create(s_ui.start_container);
    lv_label_set_text(s_ui.status_label, "Bitte HSD Karte anlegen");
    lv_obj_set_style_text_color(s_ui.status_label, lv_color_hex(0x93C5FD), 0);

    s_ui.nfc_uid_label = lv_label_create(s_ui.start_container);
    lv_label_set_text(s_ui.nfc_uid_label, "NFC UID: -");
    lv_obj_set_style_text_color(s_ui.nfc_uid_label, lv_color_hex(0x86EFAC), 0);

    lv_obj_t *login_btn = create_primary_button(s_ui.start_container, "HSD Login");
    lv_obj_add_event_cb(login_btn, login_open_event_cb, LV_EVENT_CLICKED, NULL);

    lv_obj_t *cfg_secret_btn = lv_button_create(screen);
    lv_obj_set_size(cfg_secret_btn, 44, 44);
    lv_obj_align(cfg_secret_btn, LV_ALIGN_BOTTOM_RIGHT, -14, -14);
    lv_obj_set_style_radius(cfg_secret_btn, 22, 0);
    lv_obj_set_style_bg_color(cfg_secret_btn, lv_color_hex(0x1F2937), 0);
    lv_obj_set_style_bg_opa(cfg_secret_btn, LV_OPA_40, 0);
    lv_obj_set_style_border_width(cfg_secret_btn, 0, 0);
    lv_obj_add_event_cb(cfg_secret_btn, wifi_cfg_open_event_cb, LV_EVENT_CLICKED, NULL);

    lv_obj_t *cfg_icon = lv_label_create(cfg_secret_btn);
    lv_label_set_text(cfg_icon, LV_SYMBOL_SETTINGS);
    lv_obj_set_style_text_color(cfg_icon, lv_color_hex(0x93C5FD), 0);
    lv_obj_center(cfg_icon);

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
    lv_label_set_text(pin_title, "4-stelligen Code eingeben");
    lv_obj_set_style_text_font(pin_title, &lv_font_montserrat_20, 0);
    lv_obj_set_style_text_color(pin_title, lv_color_hex(0xF9FAFB), 0);

    s_ui.pin_ta = lv_textarea_create(s_ui.pin_container);
    lv_obj_set_width(s_ui.pin_ta, lv_pct(100));
    lv_obj_set_height(s_ui.pin_ta, 86);
    lv_textarea_set_one_line(s_ui.pin_ta, true);
    lv_textarea_set_accepted_chars(s_ui.pin_ta, "0123456789");
    lv_textarea_set_max_length(s_ui.pin_ta, 4);
    lv_textarea_set_placeholder_text(s_ui.pin_ta, "1234");
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
        "CLR", "0", LV_SYMBOL_BACKSPACE, "OK", ""
    };

    s_ui.pin_pad = lv_buttonmatrix_create(s_ui.pin_container);
    lv_buttonmatrix_set_map(s_ui.pin_pad, pin_map);
    lv_obj_set_width(s_ui.pin_pad, lv_pct(100));
    lv_obj_set_height(s_ui.pin_pad, 250);
    lv_obj_set_style_radius(s_ui.pin_pad, 14, 0);
    lv_obj_set_style_pad_gap(s_ui.pin_pad, 8, 0);
    lv_obj_set_style_text_font(s_ui.pin_pad, &lv_font_montserrat_20, 0);
    lv_obj_add_event_cb(s_ui.pin_pad, pin_pad_event_cb, LV_EVENT_VALUE_CHANGED, NULL);

    lv_obj_t *pin_submit_btn = create_primary_button(s_ui.pin_container, "Code pruefen");
    lv_obj_add_event_cb(pin_submit_btn, pin_submit_event_cb, LV_EVENT_CLICKED, NULL);

    lv_obj_t *pin_back_btn = create_primary_button(s_ui.pin_container, "Zurueck");
    lv_obj_set_style_bg_color(pin_back_btn, lv_color_hex(0x374151), 0);
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

    s_ui.login_password_ta = lv_textarea_create(s_ui.login_modal);
    lv_obj_set_width(s_ui.login_password_ta, lv_pct(100));
    lv_textarea_set_one_line(s_ui.login_password_ta, true);
    lv_textarea_set_password_mode(s_ui.login_password_ta, true);
    lv_textarea_set_placeholder_text(s_ui.login_password_ta, "Passwort");
    lv_obj_add_event_cb(s_ui.login_password_ta, textarea_focus_event_cb, LV_EVENT_FOCUSED, NULL);
    lv_obj_add_event_cb(s_ui.login_password_ta, textarea_focus_event_cb, LV_EVENT_DEFOCUSED, NULL);

    lv_obj_t *login_submit_btn = create_primary_button(s_ui.login_modal, "Login");
    lv_obj_add_event_cb(login_submit_btn, login_submit_event_cb, LV_EVENT_CLICKED, NULL);

    lv_obj_t *login_close_btn = create_primary_button(s_ui.login_modal, "Schliessen");
    lv_obj_set_style_bg_color(login_close_btn, lv_color_hex(0x374151), 0);
    lv_obj_add_event_cb(login_close_btn, login_close_event_cb, LV_EVENT_CLICKED, NULL);

    s_ui.wifi_cfg_modal = lv_obj_create(screen);
    lv_obj_set_size(s_ui.wifi_cfg_modal, lv_pct(88), LV_SIZE_CONTENT);
    lv_obj_align(s_ui.wifi_cfg_modal, LV_ALIGN_CENTER, 0, -20);
    lv_obj_set_style_bg_color(s_ui.wifi_cfg_modal, lv_color_hex(0x111827), 0);
    lv_obj_set_style_radius(s_ui.wifi_cfg_modal, 18, 0);
    lv_obj_set_style_pad_all(s_ui.wifi_cfg_modal, 16, 0);
    lv_obj_set_style_pad_row(s_ui.wifi_cfg_modal, 10, 0);
    lv_obj_set_layout(s_ui.wifi_cfg_modal, LV_LAYOUT_FLEX);
    lv_obj_set_flex_flow(s_ui.wifi_cfg_modal, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_scrollbar_mode(s_ui.wifi_cfg_modal, LV_SCROLLBAR_MODE_OFF);
    lv_obj_clear_flag(s_ui.wifi_cfg_modal, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_add_flag(s_ui.wifi_cfg_modal, LV_OBJ_FLAG_HIDDEN);

    lv_obj_t *wifi_title = lv_label_create(s_ui.wifi_cfg_modal);
    lv_label_set_text(wifi_title, "WLAN Konfiguration");
    lv_obj_set_style_text_font(wifi_title, &lv_font_montserrat_20, 0);
    lv_obj_set_style_text_color(wifi_title, lv_color_hex(0xF9FAFB), 0);

    s_ui.wifi_cfg_status_label = lv_label_create(s_ui.wifi_cfg_modal);
    lv_label_set_text(s_ui.wifi_cfg_status_label, "SSID scannen und auswaehlen");
    lv_obj_set_style_text_color(s_ui.wifi_cfg_status_label, lv_color_hex(0x93C5FD), 0);

    s_ui.wifi_ssid_dropdown = lv_dropdown_create(s_ui.wifi_cfg_modal);
    lv_obj_set_width(s_ui.wifi_ssid_dropdown, lv_pct(100));
    lv_dropdown_set_options(s_ui.wifi_ssid_dropdown, "Kein Netzwerk gefunden");

    lv_obj_t *wifi_scan_btn = create_primary_button(s_ui.wifi_cfg_modal, "WLAN Scan");
    lv_obj_add_event_cb(wifi_scan_btn, wifi_scan_event_cb, LV_EVENT_CLICKED, NULL);

    s_ui.wifi_password_ta = lv_textarea_create(s_ui.wifi_cfg_modal);
    lv_obj_set_width(s_ui.wifi_password_ta, lv_pct(100));
    lv_textarea_set_one_line(s_ui.wifi_password_ta, true);
    lv_textarea_set_password_mode(s_ui.wifi_password_ta, true);
    lv_textarea_set_placeholder_text(s_ui.wifi_password_ta, "Passwort");
    lv_obj_add_event_cb(s_ui.wifi_password_ta, textarea_focus_event_cb, LV_EVENT_FOCUSED, NULL);
    lv_obj_add_event_cb(s_ui.wifi_password_ta, textarea_focus_event_cb, LV_EVENT_DEFOCUSED, NULL);

    lv_obj_t *wifi_apply_btn = create_primary_button(s_ui.wifi_cfg_modal, "Speichern & Verbinden");
    lv_obj_add_event_cb(wifi_apply_btn, wifi_cfg_save_connect_event_cb, LV_EVENT_CLICKED, NULL);

    lv_obj_t *wifi_close_btn = create_primary_button(s_ui.wifi_cfg_modal, "Schliessen");
    lv_obj_set_style_bg_color(wifi_close_btn, lv_color_hex(0x374151), 0);
    lv_obj_add_event_cb(wifi_close_btn, wifi_cfg_close_event_cb, LV_EVENT_CLICKED, NULL);

    s_ui.keyboard = lv_keyboard_create(screen);
    lv_obj_set_size(s_ui.keyboard, lv_pct(100), lv_pct(40));
    lv_obj_align(s_ui.keyboard, LV_ALIGN_BOTTOM_MID, 0, 0);
    lv_obj_add_flag(s_ui.keyboard, LV_OBJ_FLAG_HIDDEN);
    lv_obj_add_event_cb(s_ui.keyboard, keyboard_event_cb, LV_EVENT_ALL, NULL);

    lv_timer_create(auth_result_timer_cb, 120, NULL);

    s_debug_label = lv_label_create(screen);
    lv_obj_set_style_text_color(s_debug_label, lv_color_hex(0x374151), 0);
    lv_label_set_text(s_debug_label, "VSync:--Hz  PSRAM:--KB  SRAM:--KB");
    lv_obj_align(s_debug_label, LV_ALIGN_BOTTOM_LEFT, 8, -10);
    lv_timer_create(debug_overlay_timer_cb, 1000, NULL);
}

static esp_err_t pn532_wait_ready(uint32_t timeout_ms)
{
    uint8_t status = 0;
    TickType_t start = xTaskGetTickCount();
    uint8_t ready_streak = 0;

    while ((xTaskGetTickCount() - start) < pdMS_TO_TICKS(timeout_ms)) {
        esp_err_t err = i2c_master_receive(s_pn532_dev, &status, sizeof(status), PN532_I2C_STATUS_RX_TIMEOUT_MS);
        if ((err == ESP_OK) && (status == 0x01)) {
            ready_streak++;
            if (ready_streak >= 2) {
                return ESP_OK;
            }
        } else {
            ready_streak = 0;
        }
        vTaskDelay(pdMS_TO_TICKS(5));
    }

    return ESP_ERR_TIMEOUT;
}

static esp_err_t pn532_write_command(uint8_t cmd, const uint8_t *data, size_t data_len)
{
    uint8_t frame[48];
    size_t frame_len = data_len + 2;
    size_t tx_len = frame_len + 8;
    uint8_t sum = PN532_TFI_HOST_TO_PN532 + cmd;

    if (data_len > 32) {
        return ESP_ERR_INVALID_SIZE;
    }

    frame[0] = 0x00;
    frame[1] = 0x00;
    frame[2] = 0x00;
    frame[3] = 0xFF;
    frame[4] = (uint8_t)frame_len;
    frame[5] = (uint8_t)(~frame_len + 1);
    frame[6] = PN532_TFI_HOST_TO_PN532;
    frame[7] = cmd;

    for (size_t i = 0; i < data_len; i++) {
        frame[8 + i] = data[i];
        sum += data[i];
    }

    frame[8 + data_len] = (uint8_t)(~sum + 1);
    frame[9 + data_len] = 0x00;

    return i2c_master_transmit(s_pn532_dev, frame, tx_len, PN532_I2C_TX_TIMEOUT_MS);
}

static esp_err_t pn532_read_ack(void)
{
    uint8_t ack[7] = {0};

    ESP_RETURN_ON_ERROR(pn532_wait_ready(PN532_READY_TIMEOUT_MS), TAG, "PN532 ACK timeout");
    ESP_RETURN_ON_ERROR(i2c_master_receive(s_pn532_dev, ack, sizeof(ack), PN532_I2C_RX_TIMEOUT_MS), TAG, "PN532 ACK read failed");

    if ((ack[0] != 0x01) || (ack[1] != 0x00) || (ack[2] != 0x00) ||
        (ack[3] != 0xFF) || (ack[4] != 0x00) || (ack[5] != 0xFF) || (ack[6] != 0x00)) {
        return ESP_ERR_INVALID_RESPONSE;
    }

    return ESP_OK;
}

static esp_err_t pn532_read_response(uint8_t expected_cmd, uint8_t *payload, size_t payload_max, size_t *payload_len)
{
    uint8_t rx[48] = {0};
    size_t offset = 0;
    uint8_t frame_len = 0;

    ESP_RETURN_ON_ERROR(pn532_wait_ready(PN532_READY_TIMEOUT_MS), TAG, "PN532 response timeout");
    ESP_RETURN_ON_ERROR(i2c_master_receive(s_pn532_dev, rx, sizeof(rx), PN532_I2C_RX_TIMEOUT_MS), TAG, "PN532 response read failed");

    if (rx[0] == 0x01) {
        offset = 1;
    }

    if ((rx[offset + 0] != 0x00) || (rx[offset + 1] != 0x00) || (rx[offset + 2] != 0xFF)) {
        return ESP_ERR_INVALID_RESPONSE;
    }

    frame_len = rx[offset + 3];
    if ((uint8_t)(frame_len + rx[offset + 4]) != 0x00) {
        return ESP_ERR_INVALID_CRC;
    }

    if ((frame_len < 2) || (rx[offset + 5] != PN532_TFI_PN532_TO_HOST) || (rx[offset + 6] != (expected_cmd + 1))) {
        return ESP_ERR_INVALID_RESPONSE;
    }

    *payload_len = frame_len - 2;
    if (*payload_len > payload_max) {
        return ESP_ERR_INVALID_SIZE;
    }

    memcpy(payload, &rx[offset + 7], *payload_len);
    return ESP_OK;
}

static esp_err_t pn532_sam_configuration(void)
{
    const uint8_t sam_cfg[] = {0x01, 0x14, 0x01};
    esp_err_t last_err = ESP_FAIL;

    for (int attempt = 1; attempt <= PN532_SAM_RETRY_COUNT; attempt++) {
        last_err = pn532_write_command(PN532_CMD_SAMCONFIGURATION, sam_cfg, sizeof(sam_cfg));
        if (last_err != ESP_OK) {
            ESP_LOGW(TAG, "PN532 SAM cmd failed (attempt %d/%d): %s", attempt, PN532_SAM_RETRY_COUNT, esp_err_to_name(last_err));
            vTaskDelay(pdMS_TO_TICKS(20));
            continue;
        }

        last_err = pn532_read_ack();
        if (last_err != ESP_OK) {
            ESP_LOGW(TAG, "PN532 SAM ack failed (attempt %d/%d): %s", attempt, PN532_SAM_RETRY_COUNT, esp_err_to_name(last_err));
            vTaskDelay(pdMS_TO_TICKS(20));
            continue;
        }

        uint8_t payload[8] = {0};
        size_t payload_len = 0;
        last_err = pn532_read_response(PN532_CMD_SAMCONFIGURATION, payload, sizeof(payload), &payload_len);
        if (last_err == ESP_OK) {
            return ESP_OK;
        }

        ESP_LOGW(TAG, "PN532 SAM response failed (attempt %d/%d): %s", attempt, PN532_SAM_RETRY_COUNT, esp_err_to_name(last_err));
        vTaskDelay(pdMS_TO_TICKS(20));
    }

    return last_err;
}

static esp_err_t pn532_deinit(void)
{
    if (s_pn532_dev != NULL) {
        esp_err_t err = i2c_master_bus_rm_device(s_pn532_dev);
        s_pn532_dev = NULL;
        return err;
    }
    return ESP_OK;
}

static esp_err_t pn532_read_passive_uid(uint8_t *uid, size_t uid_max, size_t *uid_len)
{
    const uint8_t in_list[] = {0x01, 0x00};
    uint8_t payload[32] = {0};
    size_t payload_len = 0;

    ESP_RETURN_ON_ERROR(pn532_write_command(PN532_CMD_INLISTPASSIVETARGET, in_list, sizeof(in_list)), TAG, "PN532 scan cmd failed");
    ESP_RETURN_ON_ERROR(pn532_read_ack(), TAG, "PN532 scan ack failed");
    ESP_RETURN_ON_ERROR(pn532_read_response(PN532_CMD_INLISTPASSIVETARGET, payload, sizeof(payload), &payload_len), TAG, "PN532 scan response failed");

    if ((payload_len < 7) || (payload[0] == 0x00)) {
        return ESP_ERR_NOT_FOUND;
    }

    *uid_len = payload[5];
    if ((*uid_len == 0) || (*uid_len > uid_max) || ((6 + *uid_len) > payload_len)) {
        return ESP_ERR_INVALID_SIZE;
    }

    memcpy(uid, &payload[6], *uid_len);
    return ESP_OK;
}

static esp_err_t pn532_release_target(uint8_t tg)
{
    uint8_t payload[8] = {0};
    size_t payload_len = 0;

    ESP_RETURN_ON_ERROR(pn532_write_command(PN532_CMD_INRELEASE, &tg, 1), TAG, "PN532 release cmd failed");
    ESP_RETURN_ON_ERROR(pn532_read_ack(), TAG, "PN532 release ack failed");
    return pn532_read_response(PN532_CMD_INRELEASE, payload, sizeof(payload), &payload_len);
}

static esp_err_t pn532_init(void)
{
    if (s_pn532_dev != NULL) {
        return pn532_sam_configuration();
    }

    ESP_RETURN_ON_ERROR(bsp_i2c_init(), TAG, "I2C init failed");

    i2c_master_bus_handle_t i2c_bus = bsp_i2c_get_handle();
    esp_err_t last_err = ESP_ERR_NOT_FOUND;
    i2c_device_config_t dev_cfg = {
        .dev_addr_length = I2C_ADDR_BIT_LEN_7,
        .device_address = PN532_I2C_ADDR_BRIDGE,
        .scl_speed_hz = PN532_I2C_SCL_SPEED_HZ,
    };

    ESP_RETURN_ON_FALSE(i2c_bus != NULL, ESP_ERR_INVALID_STATE, TAG, "I2C bus not ready");

    esp_err_t add_err = i2c_master_bus_add_device(i2c_bus, &dev_cfg, &s_pn532_dev);
    if (add_err != ESP_OK) {
        return add_err;
    }

    vTaskDelay(pdMS_TO_TICKS(80));
    esp_err_t sam_err = pn532_sam_configuration();
    if (sam_err == ESP_OK) {
        s_pn532_addr = PN532_I2C_ADDR_BRIDGE;
        ESP_LOGI(TAG, "PN532 I2C address selected: 0x%02X", (unsigned int)s_pn532_addr);
        return ESP_OK;
    }

    ESP_LOGW(TAG, "PN532 handshake failed at 0x%02X: %s", PN532_I2C_ADDR_BRIDGE, esp_err_to_name(sam_err));
    i2c_master_bus_rm_device(s_pn532_dev);
    s_pn532_dev = NULL;
    last_err = sam_err;

    ESP_LOGE(TAG, "PN532 not found on I2C at required bridge address 0x%02X", PN532_I2C_ADDR_BRIDGE);
    return last_err;
}

static esp_err_t pn532_recover(void)
{
    esp_err_t err = pn532_deinit();
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "PN532 remove device failed: %s", esp_err_to_name(err));
    }
    vTaskDelay(pdMS_TO_TICKS(PN532_RECOVERY_DELAY_MS));
    return pn532_init();
}

static void nfc_task(void *arg)
{
    LV_UNUSED(arg);
    uint8_t uid[10] = {0};
    size_t uid_len = 0;
    char uid_text[40] = {0};
    char last_uid_text[40] = "";
    uint32_t scan_fail_streak = 0;
    ESP_LOGI(TAG, "nfc_task started on core %d", (int)xPortGetCoreID());

    esp_err_t err = pn532_init();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "PN532 init failed: %s", esp_err_to_name(err));
        set_status_text("PN532 Fehler", lv_color_hex(0xFCA5A5));
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

        if ((s_current_view != APP_VIEW_START) || s_auth_busy || s_pause_nfc_polling) {
            vTaskDelay(pdMS_TO_TICKS(NFC_POLL_PAUSED_MS));
            continue;
        }

        uint32_t next_poll_ms = NFC_POLL_IDLE_MS;
        err = pn532_read_passive_uid(uid, sizeof(uid), &uid_len);
        if (err == ESP_OK) {
            scan_fail_streak = 0;
            pn532_release_target(0x01);

            int written = 0;
            uid_text[0] = '\0';
            for (size_t i = 0; (i < uid_len) && (written > -1) && (written < (int)sizeof(uid_text)); i++) {
                written += snprintf(&uid_text[written], sizeof(uid_text) - (size_t)written, "%02X", uid[i]);
                if (i + 1 < uid_len) {
                    written += snprintf(&uid_text[written], sizeof(uid_text) - (size_t)written, ":");
                }
            }

            if (strcmp(uid_text, last_uid_text) != 0) {
                char label_text[56] = {0};
                snprintf(label_text, sizeof(label_text), "NFC UID: %s", uid_text);
                set_nfc_uid_text(label_text, lv_color_hex(0x86EFAC));
                strncpy(last_uid_text, uid_text, sizeof(last_uid_text) - 1);
                last_uid_text[sizeof(last_uid_text) - 1] = '\0';
            }

            if (!auth_has_token()) {
                set_status_text("Warte auf Geraete-Setup", lv_color_hex(0xFDE68A));
                next_poll_ms = NFC_POLL_AFTER_CARD_MS;
                continue;
            }

            auth_request_t req = {
                .source = AUTH_SRC_NFC,
            };
            strncpy(req.value_a, uid_text, sizeof(req.value_a) - 1);

            if (enqueue_auth_request(&req)) {
                set_auth_busy(true);
                set_status_text("Karte wird geprueft...", lv_color_hex(0xFDE68A));
            }

            next_poll_ms = NFC_POLL_AFTER_CARD_MS;
        } else if (err != ESP_ERR_NOT_FOUND) {
            scan_fail_streak++;
            if ((scan_fail_streak <= 3) || (scan_fail_streak % 10 == 0)) {
                ESP_LOGW(TAG, "PN532 scan error (%lu): %s", (unsigned long)scan_fail_streak, esp_err_to_name(err));
            }

            if (scan_fail_streak >= PN532_SCAN_FAIL_REINIT_THRESHOLD) {
                ESP_LOGW(TAG, "PN532 recovering after %lu consecutive scan failures", (unsigned long)scan_fail_streak);
                set_status_text("NFC wird neu gestartet...", lv_color_hex(0xFDE68A));
                esp_err_t recover_err = pn532_recover();
                if (recover_err != ESP_OK) {
                    ESP_LOGE(TAG, "PN532 recovery failed: %s", esp_err_to_name(recover_err));
                    set_status_text("PN532 Fehler", lv_color_hex(0xFCA5A5));
                } else {
                    scan_fail_streak = 0;
                }
                next_poll_ms = NFC_POLL_AFTER_CARD_MS;
            }
        }

        vTaskDelay(pdMS_TO_TICKS(next_poll_ms));
    }
}

void app_main(void)
{
    ESP_LOGI(TAG, "Core config: LVGL=%d AUTH=%d NFC=%d", LVGL_TASK_CORE_ID, AUTH_TASK_CORE_ID, NFC_TASK_CORE_ID);
    esp_err_t err = nvs_flash_init();
    if ((err == ESP_ERR_NVS_NO_FREE_PAGES) || (err == ESP_ERR_NVS_NEW_VERSION_FOUND)) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    ESP_ERROR_CHECK(err);

    i2c_scan_log();

    ESP_ERROR_CHECK(wifi_cfg_load(&s_wifi_cfg));
    ESP_ERROR_CHECK(auth_cfg_load(&s_auth_cfg));
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
    bsp_display_unlock();

    s_auth_req_queue = xQueueCreate(AUTH_REQ_QUEUE_LEN, sizeof(auth_request_t));
    s_auth_res_queue = xQueueCreate(AUTH_RES_QUEUE_LEN, sizeof(auth_result_t));
    ESP_ERROR_CHECK(s_auth_req_queue != NULL ? ESP_OK : ESP_FAIL);
    ESP_ERROR_CHECK(s_auth_res_queue != NULL ? ESP_OK : ESP_FAIL);

    BaseType_t auth_task_ok = xTaskCreatePinnedToCore(auth_worker_task, "auth_worker", 6144, NULL, 5, NULL, AUTH_TASK_CORE_ID);
    if (auth_task_ok != pdPASS) {
        ESP_LOGE(TAG, "Auth worker start failed");
    }

    err = wifi_init_sta();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "WiFi init failed: %s", esp_err_to_name(err));
        set_status_text("WLAN Init Fehler", lv_color_hex(0xFCA5A5));
    }

    BaseType_t nfc_task_ok = xTaskCreatePinnedToCore(nfc_task, "nfc_task", 4096, NULL, 5, NULL, NFC_TASK_CORE_ID);
    if (nfc_task_ok != pdPASS) {
        ESP_LOGE(TAG, "NFC task start failed");
    }
}
