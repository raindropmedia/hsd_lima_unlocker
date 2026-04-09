#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "esp_log.h"
#include "esp_err.h"
#include "esp_check.h"
#include "driver/i2c_slave.h"
#include "driver/gpio.h"
#include "driver/rmt_common.h"
#include "driver/rmt_encoder.h"
#include "driver/rmt_tx.h"
#include "esp32c3/rom/ets_sys.h"

#define TAG "PN532_BRIDGE"

/*
 * Upstream bus: host board (master) -> bridge ESP32 (slave)
 * Downstream bus: bridge ESP32 (soft-I2C master) -> PN532 (slave)
 *
 * Runtime model:
 * - PN532 is polled continuously in the background.
 * - Latest UID state is stored in RAM.
 * - Each upstream I2C read returns one fixed 16-byte status/UID packet.
 * - No upstream command forwarding to PN532 is used.
 *
 * Default pins avoid the ESP32-C3 USB (GPIO18/19), UART0 (GPIO20/21),
 * the onboard LED on GPIO8 and flash-connected pins (GPIO12-17).
 */
#define UPSTREAM_SDA_GPIO          6
#define UPSTREAM_SCL_GPIO          7
#define DOWNSTREAM_SDA_GPIO        4
#define DOWNSTREAM_SCL_GPIO        5
#define PN532_RESET_GPIO           10
#define DEVKIT_LED_GPIO            8

#define UPSTREAM_SLAVE_ADDR        0x25
#define DOWNSTREAM_PN532_ADDR      0x24

#define I2C_TIMEOUT_MS             50
#define LED_OFF_TIMEOUT_MS         50
#define PN532_PROBE_RETRIES        8
#define PN532_PROBE_DELAY_MS       25
#define BOOT_ERROR_BLINK_COUNT     4
#define BOOT_ERROR_BLINK_MS        120
#define BOOT_RETRY_DELAY_MS        1000

#define PN532_STATUS_READ_LEN      1
#define PN532_ACK_READ_LEN         7
#define PN532_RESPONSE_READ_LEN    48
#define PN532_FW_CMD_LEN           9
#define PN532_FW_RESP_READ_LEN     14

#define BRIDGE_PKT_MAGIC           0xB1
#define BRIDGE_STATUS_CARD_PRESENT 0x01
#define BRIDGE_STATUS_NEW_UID      0x02
#define BRIDGE_PKT_LEN             16
#define BRIDGE_PKT_UID_OFFSET      4
#define BRIDGE_UID_MAX_LEN         10
#define BRIDGE_NFC_POLL_MS         120
#define BRIDGE_CARD_LOST_POLLS     2

#define PN532_READY_STATUS         0x01
#define PN532_WAIT_READY_RETRIES   40
#define PN532_WAIT_READY_DELAY_MS  10
#define PN532_SCAN_READY_RETRIES   120
#define PN532_RESET_LOW_MS         10
#define PN532_RESET_BOOT_WAIT_MS   40

#define SOFT_I2C_HALF_PERIOD_US    5
#define SOFT_I2C_SCL_WAIT_US       1500

/* Internal pull-ups are weak; external 2.2k-4.7k to 3V3 are recommended for stable I2C. */
#define DOWNSTREAM_INTERNAL_PULLUPS 1

_Static_assert(BRIDGE_PKT_LEN >= (BRIDGE_PKT_UID_OFFSET + BRIDGE_UID_MAX_LEN), "Bridge packet too small for max UID length");

typedef enum {
    EV_UPSTREAM_REQUEST = 0,
} bridge_event_type_t;

typedef struct {
    bridge_event_type_t type;
} bridge_event_t;

typedef struct {
    QueueHandle_t ev_queue;
    i2c_slave_dev_handle_t slave_dev;
} bridge_ctx_t;

typedef struct {
    uint8_t uid[BRIDGE_UID_MAX_LEN];
    uint8_t uid_len;
    uint8_t seq;
    bool valid;
    bool new_uid;
} bridge_uid_state_t;

typedef struct {
    rmt_channel_handle_t tx_channel;
    rmt_encoder_handle_t bytes_encoder;
    uint8_t current_grb[3];
    bool ready;
} devkit_led_ctx_t;

static bridge_ctx_t s_ctx = {0};
static devkit_led_ctx_t s_led = {0};
static bridge_uid_state_t s_uid_state = {0};
static portMUX_TYPE s_uid_mux = portMUX_INITIALIZER_UNLOCKED;

static esp_err_t pn532_wait_ready_custom(uint32_t retries, uint32_t delay_ms);

static inline void soft_i2c_delay(void)
{
    esp_rom_delay_us(SOFT_I2C_HALF_PERIOD_US);
}

static inline void soft_i2c_sda_set(bool high)
{
    gpio_set_level(DOWNSTREAM_SDA_GPIO, high ? 1 : 0);
}

static inline void soft_i2c_scl_set(bool high)
{
    gpio_set_level(DOWNSTREAM_SCL_GPIO, high ? 1 : 0);
}

static inline bool soft_i2c_sda_read(void)
{
    return gpio_get_level(DOWNSTREAM_SDA_GPIO) != 0;
}

static inline bool soft_i2c_scl_read(void)
{
    return gpio_get_level(DOWNSTREAM_SCL_GPIO) != 0;
}

static bool soft_i2c_wait_scl_high(uint32_t timeout_us)
{
    while (timeout_us-- > 0) {
        if (soft_i2c_scl_read()) {
            return true;
        }
        esp_rom_delay_us(1);
    }
    return false;
}

static void soft_i2c_start(void)
{
    soft_i2c_sda_set(true);
    soft_i2c_scl_set(true);
    soft_i2c_delay();
    soft_i2c_sda_set(false);
    soft_i2c_delay();
    soft_i2c_scl_set(false);
    soft_i2c_delay();
}

static void soft_i2c_stop(void)
{
    soft_i2c_sda_set(false);
    soft_i2c_delay();
    soft_i2c_scl_set(true);
    soft_i2c_delay();
    soft_i2c_sda_set(true);
    soft_i2c_delay();
}

static bool soft_i2c_write_byte(uint8_t data)
{
    for (int bit = 7; bit >= 0; --bit) {
        soft_i2c_sda_set(((data >> bit) & 0x01u) != 0u);
        soft_i2c_delay();
        soft_i2c_scl_set(true);
        if (!soft_i2c_wait_scl_high(SOFT_I2C_SCL_WAIT_US)) {
            soft_i2c_scl_set(false);
            return false;
        }
        soft_i2c_delay();
        soft_i2c_scl_set(false);
        soft_i2c_delay();
    }

    soft_i2c_sda_set(true);
    soft_i2c_delay();
    soft_i2c_scl_set(true);
    if (!soft_i2c_wait_scl_high(SOFT_I2C_SCL_WAIT_US)) {
        soft_i2c_scl_set(false);
        return false;
    }
    soft_i2c_delay();
    bool ack = !soft_i2c_sda_read();
    soft_i2c_scl_set(false);
    soft_i2c_delay();
    return ack;
}

static bool soft_i2c_read_byte(bool ack, uint8_t *out)
{
    uint8_t data = 0;
    soft_i2c_sda_set(true);

    for (int bit = 7; bit >= 0; --bit) {
        soft_i2c_scl_set(true);
        if (!soft_i2c_wait_scl_high(SOFT_I2C_SCL_WAIT_US)) {
            soft_i2c_scl_set(false);
            return false;
        }
        soft_i2c_delay();
        if (soft_i2c_sda_read()) {
            data |= (uint8_t)(1u << bit);
        }
        soft_i2c_scl_set(false);
        soft_i2c_delay();
    }

    soft_i2c_sda_set(ack ? false : true);
    soft_i2c_delay();
    soft_i2c_scl_set(true);
    soft_i2c_delay();
    soft_i2c_scl_set(false);
    soft_i2c_delay();
    soft_i2c_sda_set(true);
    *out = data;
    return true;
}

static esp_err_t soft_i2c_init(void)
{
    const gpio_pullup_t pullup_cfg = DOWNSTREAM_INTERNAL_PULLUPS ? GPIO_PULLUP_ENABLE : GPIO_PULLUP_DISABLE;

    const gpio_config_t io_cfg = {
        .pin_bit_mask = (1ULL << DOWNSTREAM_SDA_GPIO) | (1ULL << DOWNSTREAM_SCL_GPIO),
        .mode = GPIO_MODE_INPUT_OUTPUT_OD,
        .pull_up_en = pullup_cfg,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type = GPIO_INTR_DISABLE,
    };
    ESP_RETURN_ON_ERROR(gpio_config(&io_cfg), TAG, "soft i2c gpio config failed");
    soft_i2c_sda_set(true);
    soft_i2c_scl_set(true);
    return ESP_OK;
}

static esp_err_t pn532_reset_pulse(void)
{
    const gpio_config_t rst_cfg = {
        .pin_bit_mask = (1ULL << PN532_RESET_GPIO),
        .mode = GPIO_MODE_OUTPUT,
        .pull_up_en = GPIO_PULLUP_DISABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type = GPIO_INTR_DISABLE,
    };
    ESP_RETURN_ON_ERROR(gpio_config(&rst_cfg), TAG, "pn532 reset gpio config failed");

    gpio_set_level(PN532_RESET_GPIO, 0);
    vTaskDelay(pdMS_TO_TICKS(PN532_RESET_LOW_MS));
    gpio_set_level(PN532_RESET_GPIO, 1);
    vTaskDelay(pdMS_TO_TICKS(PN532_RESET_BOOT_WAIT_MS));

    ESP_LOGI(TAG, "PN532 Reset-Puls ausgefuehrt auf GPIO%d", PN532_RESET_GPIO);
    return ESP_OK;
}

static bool soft_i2c_bus_idle(void)
{
    soft_i2c_sda_set(true);
    soft_i2c_scl_set(true);
    soft_i2c_delay();
    return soft_i2c_sda_read() && soft_i2c_scl_read();
}

static bool soft_i2c_bus_recover(void)
{
    soft_i2c_sda_set(true);
    soft_i2c_scl_set(true);
    soft_i2c_delay();

    for (int i = 0; i < 9; ++i) {
        if (soft_i2c_bus_idle()) {
            return true;
        }
        soft_i2c_scl_set(false);
        soft_i2c_delay();
        soft_i2c_scl_set(true);
        soft_i2c_delay();
    }

    soft_i2c_stop();
    return soft_i2c_bus_idle();
}

static esp_err_t devkit_led_set_grb(uint8_t green, uint8_t red, uint8_t blue)
{
    if (!s_led.ready) {
        return ESP_ERR_INVALID_STATE;
    }

    if (s_led.current_grb[0] == green && s_led.current_grb[1] == red && s_led.current_grb[2] == blue) {
        return ESP_OK;
    }

    uint8_t led_grb[3] = {green, red, blue};

    const rmt_transmit_config_t tx_config = {
        .loop_count = 0,
        .flags.eot_level = 0,
    };

    esp_err_t err = rmt_transmit(s_led.tx_channel, s_led.bytes_encoder, led_grb, sizeof(led_grb), &tx_config);
    if (err != ESP_OK) {
        return err;
    }

    err = rmt_tx_wait_all_done(s_led.tx_channel, LED_OFF_TIMEOUT_MS);
    if (err != ESP_OK) {
        return err;
    }

    memcpy(s_led.current_grb, led_grb, sizeof(led_grb));
    return ESP_OK;
}

static void devkit_led_show_boot_error_pattern(void)
{
    for (int i = 0; i < BOOT_ERROR_BLINK_COUNT; ++i) {
        (void)devkit_led_set_grb(0x00, 0x18, 0x00);
        vTaskDelay(pdMS_TO_TICKS(BOOT_ERROR_BLINK_MS));
        (void)devkit_led_set_grb(0x00, 0x00, 0x00);
        vTaskDelay(pdMS_TO_TICKS(BOOT_ERROR_BLINK_MS));
    }

    (void)devkit_led_set_grb(0x00, 0x18, 0x00);
}

static esp_err_t devkit_led_init(void)
{
    if (s_led.ready) {
        return ESP_OK;
    }

    memset(s_led.current_grb, 0xFF, sizeof(s_led.current_grb));

    const rmt_tx_channel_config_t tx_cfg = {
        .gpio_num = DEVKIT_LED_GPIO,
        .clk_src = RMT_CLK_SRC_DEFAULT,
        .resolution_hz = 10000000,
        .mem_block_symbols = 64,
        .trans_queue_depth = 1,
        .intr_priority = 0,
        .flags.init_level = 0,
    };
    ESP_RETURN_ON_ERROR(rmt_new_tx_channel(&tx_cfg, &s_led.tx_channel), TAG, "led tx channel init failed");

    const rmt_bytes_encoder_config_t enc_cfg = {
        .bit0 = {
            .level0 = 1,
            .duration0 = 3,
            .level1 = 0,
            .duration1 = 9,
        },
        .bit1 = {
            .level0 = 1,
            .duration0 = 9,
            .level1 = 0,
            .duration1 = 3,
        },
        .flags.msb_first = 1,
    };

    esp_err_t err = rmt_new_bytes_encoder(&enc_cfg, &s_led.bytes_encoder);
    if (err != ESP_OK) {
        (void)rmt_del_channel(s_led.tx_channel);
        s_led.tx_channel = NULL;
        return err;
    }

    err = rmt_enable(s_led.tx_channel);
    if (err != ESP_OK) {
        (void)rmt_del_encoder(s_led.bytes_encoder);
        (void)rmt_del_channel(s_led.tx_channel);
        s_led.bytes_encoder = NULL;
        s_led.tx_channel = NULL;
        return err;
    }

    s_led.ready = true;
    ESP_RETURN_ON_ERROR(devkit_led_set_grb(0x04, 0x04, 0x04), TAG, "devkit led boot state failed");
    return ESP_OK;
}

static esp_err_t pn532_write(const uint8_t *data, size_t len)
{
    if (len == 0) {
        return ESP_OK;
    }

    soft_i2c_start();
    if (!soft_i2c_write_byte((uint8_t)(DOWNSTREAM_PN532_ADDR << 1))) {
        soft_i2c_stop();
        return ESP_ERR_TIMEOUT;
    }

    for (size_t i = 0; i < len; i++) {
        if (!soft_i2c_write_byte(data[i])) {
            soft_i2c_stop();
            return ESP_ERR_TIMEOUT;
        }
    }

    soft_i2c_stop();
    return ESP_OK;
}

static esp_err_t pn532_read(uint8_t *out, size_t len)
{
    if (len == 0) {
        return ESP_OK;
    }

    soft_i2c_start();
    if (!soft_i2c_write_byte((uint8_t)((DOWNSTREAM_PN532_ADDR << 1) | 0x01u))) {
        soft_i2c_stop();
        return ESP_ERR_TIMEOUT;
    }

    for (size_t i = 0; i < len; i++) {
        if (!soft_i2c_read_byte(i < (len - 1), &out[i])) {
            soft_i2c_stop();
            return ESP_ERR_TIMEOUT;
        }
    }

    soft_i2c_stop();
    return ESP_OK;
}

static bool downstream_i2c_address_responds(uint8_t addr7)
{
    soft_i2c_start();
    bool ack = soft_i2c_write_byte((uint8_t)(addr7 << 1));
    soft_i2c_stop();
    return ack;
}

static void downstream_i2c_scan(void)
{
    bool any_found = false;

    ESP_LOGI(TAG, "Downstream I2C-Scan startet (SDA=%d, SCL=%d)", DOWNSTREAM_SDA_GPIO, DOWNSTREAM_SCL_GPIO);

    if (!soft_i2c_bus_idle()) {
        ESP_LOGW(TAG, "Downstream I2C-Leitung nicht idle (SDA=%d, SCL=%d), versuche Bus-Recovery", soft_i2c_sda_read(), soft_i2c_scl_read());
        if (!soft_i2c_bus_recover()) {
            ESP_LOGE(TAG, "Downstream I2C-Bus bleibt blockiert (SDA=%d, SCL=%d), Scan abgebrochen", soft_i2c_sda_read(), soft_i2c_scl_read());
            return;
        }
    }

    for (uint8_t addr = 0x03; addr <= 0x77; ++addr) {
        if (!downstream_i2c_address_responds(addr)) {
            continue;
        }

        any_found = true;
        if (addr == DOWNSTREAM_PN532_ADDR) {
            ESP_LOGI(TAG, "Downstream I2C gefunden: 0x%02X (PN532 erwartet)", addr);
        } else {
            ESP_LOGI(TAG, "Downstream I2C gefunden: 0x%02X", addr);
        }
    }

    if (!any_found) {
        ESP_LOGW(TAG, "Downstream I2C-Scan: kein Geraet gefunden");
    }
}

static esp_err_t pn532_wait_ready(void)
{
    return pn532_wait_ready_custom(PN532_WAIT_READY_RETRIES, PN532_WAIT_READY_DELAY_MS);
}

static esp_err_t pn532_wait_ready_custom(uint32_t retries, uint32_t delay_ms)
{
    uint8_t status = 0x00;
    esp_err_t last_err = ESP_FAIL;

    for (uint32_t i = 0; i < retries; ++i) {
        last_err = pn532_read(&status, PN532_STATUS_READ_LEN);
        if (last_err == ESP_OK && status == PN532_READY_STATUS) {
            return ESP_OK;
        }
        vTaskDelay(pdMS_TO_TICKS(delay_ms));
    }

    return (last_err == ESP_OK) ? ESP_ERR_TIMEOUT : last_err;
}

static esp_err_t pn532_probe(void)
{
    static const uint8_t fw_cmd[PN532_FW_CMD_LEN] = {
        0x00, 0x00, 0xFF, 0x02, 0xFE, 0xD4, 0x02, 0x2A, 0x00
    };
    static const uint8_t ack_pattern[6] = {0x00, 0x00, 0xFF, 0x00, 0xFF, 0x00};

    uint8_t ack_buf[PN532_ACK_READ_LEN] = {0};
    uint8_t resp_buf[PN532_FW_RESP_READ_LEN] = {0};
    esp_err_t last_err = ESP_FAIL;

    for (int attempt = 1; attempt <= PN532_PROBE_RETRIES; ++attempt) {
        last_err = pn532_write(fw_cmd, sizeof(fw_cmd));
        if (last_err != ESP_OK) {
            ESP_LOGW(TAG, "PN532 Probe-Write fehlgeschlagen (Versuch %d/%d): %s", attempt, PN532_PROBE_RETRIES, esp_err_to_name(last_err));
            vTaskDelay(pdMS_TO_TICKS(PN532_PROBE_DELAY_MS));
            continue;
        }

        last_err = pn532_wait_ready();
        if (last_err != ESP_OK) {
            ESP_LOGW(TAG, "PN532 wurde nicht ready nach Command (Versuch %d/%d): %s", attempt, PN532_PROBE_RETRIES, esp_err_to_name(last_err));
            vTaskDelay(pdMS_TO_TICKS(PN532_PROBE_DELAY_MS));
            continue;
        }

        last_err = pn532_read(ack_buf, sizeof(ack_buf));
        if (last_err != ESP_OK) {
            ESP_LOGW(TAG, "PN532 ACK-Read fehlgeschlagen (Versuch %d/%d): %s", attempt, PN532_PROBE_RETRIES, esp_err_to_name(last_err));
            vTaskDelay(pdMS_TO_TICKS(PN532_PROBE_DELAY_MS));
            continue;
        }

        if (ack_buf[0] != PN532_READY_STATUS || memcmp(&ack_buf[1], ack_pattern, sizeof(ack_pattern)) != 0) {
            last_err = ESP_ERR_INVALID_RESPONSE;
            ESP_LOGW(TAG, "PN532 ACK ungueltig (Versuch %d/%d)", attempt, PN532_PROBE_RETRIES);
            vTaskDelay(pdMS_TO_TICKS(PN532_PROBE_DELAY_MS));
            continue;
        }

        last_err = pn532_wait_ready();
        if (last_err != ESP_OK) {
            ESP_LOGW(TAG, "PN532 wurde nicht ready fuer Antwort (Versuch %d/%d): %s", attempt, PN532_PROBE_RETRIES, esp_err_to_name(last_err));
            vTaskDelay(pdMS_TO_TICKS(PN532_PROBE_DELAY_MS));
            continue;
        }

        last_err = pn532_read(resp_buf, sizeof(resp_buf));
        if (last_err == ESP_OK &&
            resp_buf[0] == PN532_READY_STATUS &&
            resp_buf[1] == 0x00 && resp_buf[2] == 0x00 && resp_buf[3] == 0xFF &&
            resp_buf[6] == 0xD5 && resp_buf[7] == 0x03) {
            ESP_LOGI(TAG, "PN532 erreichbar (FW IC=0x%02X VER=0x%02X REV=0x%02X, Versuch %d/%d)",
                     resp_buf[8], resp_buf[9], resp_buf[10], attempt, PN532_PROBE_RETRIES);
            return ESP_OK;
        }

        if (last_err == ESP_OK) {
            last_err = ESP_ERR_INVALID_RESPONSE;
            ESP_LOGW(TAG, "PN532 Antwort ungueltig (Versuch %d/%d)", attempt, PN532_PROBE_RETRIES);
        } else {
            ESP_LOGW(TAG, "PN532 Response-Read fehlgeschlagen (Versuch %d/%d): %s", attempt, PN532_PROBE_RETRIES, esp_err_to_name(last_err));
        }
        vTaskDelay(pdMS_TO_TICKS(PN532_PROBE_DELAY_MS));
    }

    return last_err;
}

static esp_err_t pn532_write_command(uint8_t cmd, const uint8_t *data, size_t data_len)
{
    uint8_t frame[48];
    size_t frame_len = data_len + 2;
    size_t tx_len = frame_len + 8;
    uint8_t sum = 0xD4 + cmd;

    if (data_len > 32) {
        return ESP_ERR_INVALID_SIZE;
    }

    frame[0] = 0x00;
    frame[1] = 0x00;
    frame[2] = 0x00;
    frame[3] = 0xFF;
    frame[4] = (uint8_t)frame_len;
    frame[5] = (uint8_t)(~frame_len + 1);
    frame[6] = 0xD4;
    frame[7] = cmd;

    for (size_t i = 0; i < data_len; i++) {
        frame[8 + i] = data[i];
        sum += data[i];
    }

    frame[8 + data_len] = (uint8_t)(~sum + 1);
    frame[9 + data_len] = 0x00;

    return pn532_write(frame, tx_len);
}

static esp_err_t pn532_read_ack(void)
{
    uint8_t ack[PN532_ACK_READ_LEN] = {0};
    static const uint8_t ack_pattern[6] = {0x00, 0x00, 0xFF, 0x00, 0xFF, 0x00};

    ESP_RETURN_ON_ERROR(pn532_wait_ready(), TAG, "PN532 ACK timeout");
    ESP_RETURN_ON_ERROR(pn532_read(ack, sizeof(ack)), TAG, "PN532 ACK read failed");

    if ((ack[0] != PN532_READY_STATUS) || (memcmp(&ack[1], ack_pattern, sizeof(ack_pattern)) != 0)) {
        return ESP_ERR_INVALID_RESPONSE;
    }

    return ESP_OK;
}

static esp_err_t pn532_read_response_with_wait(uint8_t expected_cmd, uint8_t *payload, size_t payload_max,
                                               size_t *payload_len, uint32_t ready_retries)
{
    uint8_t rx[48] = {0};
    size_t offset = 0;

    ESP_RETURN_ON_ERROR(pn532_wait_ready_custom(ready_retries, PN532_WAIT_READY_DELAY_MS), TAG, "PN532 response timeout");
    ESP_RETURN_ON_ERROR(pn532_read(rx, sizeof(rx)), TAG, "PN532 response read failed");

    if (rx[0] == PN532_READY_STATUS) {
        offset = 1;
    }

    if ((rx[offset + 0] != 0x00) || (rx[offset + 1] != 0x00) || (rx[offset + 2] != 0xFF)) {
        return ESP_ERR_INVALID_RESPONSE;
    }

    uint8_t frame_len = rx[offset + 3];
    if ((uint8_t)(frame_len + rx[offset + 4]) != 0x00) {
        return ESP_ERR_INVALID_CRC;
    }

    if ((frame_len < 2) || (rx[offset + 5] != 0xD5) || (rx[offset + 6] != (expected_cmd + 1))) {
        return ESP_ERR_INVALID_RESPONSE;
    }

    *payload_len = frame_len - 2;
    if (*payload_len > payload_max) {
        return ESP_ERR_INVALID_SIZE;
    }

    memcpy(payload, &rx[offset + 7], *payload_len);
    return ESP_OK;
}

static esp_err_t pn532_read_response(uint8_t expected_cmd, uint8_t *payload, size_t payload_max, size_t *payload_len)
{
    return pn532_read_response_with_wait(expected_cmd, payload, payload_max, payload_len, PN532_WAIT_READY_RETRIES);
}

static esp_err_t pn532_release_target(uint8_t target_number)
{
    uint8_t payload[2] = {target_number, 0x00};
    uint8_t response[4] = {0};
    size_t response_len = 0;

    ESP_RETURN_ON_ERROR(pn532_write_command(0x52, payload, 1), TAG, "PN532 release cmd failed");
    ESP_RETURN_ON_ERROR(pn532_read_ack(), TAG, "PN532 release ack failed");
    ESP_RETURN_ON_ERROR(pn532_read_response(0x52, response, sizeof(response), &response_len), TAG, "PN532 release response failed");
    return ESP_OK;
}

static esp_err_t pn532_sam_configuration(void)
{
    const uint8_t sam_cfg[] = {0x01, 0x14, 0x01};
    uint8_t payload[8] = {0};
    size_t payload_len = 0;

    ESP_RETURN_ON_ERROR(pn532_write_command(0x14, sam_cfg, sizeof(sam_cfg)), TAG, "PN532 SAM cmd failed");
    ESP_RETURN_ON_ERROR(pn532_read_ack(), TAG, "PN532 SAM ack failed");
    return pn532_read_response(0x14, payload, sizeof(payload), &payload_len);
}

static esp_err_t pn532_read_passive_uid(uint8_t *uid, size_t uid_max, size_t *uid_len)
{
    const uint8_t in_list[] = {0x01, 0x00};
    uint8_t payload[32] = {0};
    size_t payload_len = 0;
    uint8_t target_number = 0;

    ESP_RETURN_ON_ERROR(pn532_write_command(0x4A, in_list, sizeof(in_list)), TAG, "PN532 scan cmd failed");
    ESP_RETURN_ON_ERROR(pn532_read_ack(), TAG, "PN532 scan ack failed");
    ESP_RETURN_ON_ERROR(pn532_read_response_with_wait(0x4A, payload, sizeof(payload), &payload_len, PN532_SCAN_READY_RETRIES), TAG, "PN532 scan response failed");

    if ((payload_len < 7) || (payload[0] == 0x00)) {
        return ESP_ERR_NOT_FOUND;
    }

    target_number = payload[1];

    *uid_len = payload[5];
    if ((*uid_len == 0) || (*uid_len > BRIDGE_UID_MAX_LEN)) {
        return ESP_ERR_NOT_SUPPORTED;
    }

    if ((*uid_len > uid_max) || ((6 + *uid_len) > payload_len)) {
        return ESP_ERR_INVALID_SIZE;
    }

    memcpy(uid, &payload[6], *uid_len);
    (void)pn532_release_target(target_number);
    return ESP_OK;
}

static void clear_uid_state(void)
{
    portENTER_CRITICAL(&s_uid_mux);
    memset(s_uid_state.uid, 0, sizeof(s_uid_state.uid));
    s_uid_state.uid_len = 0;
    s_uid_state.valid = false;
    s_uid_state.new_uid = false;
    portEXIT_CRITICAL(&s_uid_mux);
}

static void nfc_poll_task(void *arg)
{
    (void)arg;
    uint8_t uid[BRIDGE_UID_MAX_LEN] = {0};
    size_t uid_len = 0;
    uint8_t last_uid[BRIDGE_UID_MAX_LEN] = {0};
    uint8_t last_uid_len = 0;
    uint8_t missing_polls = 0;

    ESP_LOGI(TAG, "Bridge NFC poll task gestartet");

    while (1) {
        esp_err_t err = pn532_read_passive_uid(uid, sizeof(uid), &uid_len);
        if (err == ESP_OK) {
            missing_polls = 0;
            bool changed = (uid_len != last_uid_len) || (memcmp(uid, last_uid, uid_len) != 0);
            if (changed) {
                memcpy(last_uid, uid, uid_len);
                last_uid_len = (uint8_t)uid_len;

                portENTER_CRITICAL(&s_uid_mux);
                memcpy(s_uid_state.uid, uid, uid_len);
                s_uid_state.uid_len = (uint8_t)uid_len;
                s_uid_state.valid = true;
                s_uid_state.new_uid = true;
                s_uid_state.seq++;
                uint8_t seq = s_uid_state.seq;
                portEXIT_CRITICAL(&s_uid_mux);

                ESP_LOGI(TAG, "Neue UID erkannt (len=%u, seq=%u)", (unsigned int)uid_len, (unsigned int)seq);
            }
        } else if ((err == ESP_ERR_NOT_FOUND) || (err == ESP_ERR_TIMEOUT)) {
            if (last_uid_len > 0) {
                missing_polls++;
                if (missing_polls >= BRIDGE_CARD_LOST_POLLS) {
                    memset(last_uid, 0, sizeof(last_uid));
                    last_uid_len = 0;
                    clear_uid_state();
                    missing_polls = 0;
                    ESP_LOGI(TAG, "Karte entfernt");
                }
            }
        } else {
            ESP_LOGW(TAG, "Bridge UID poll Fehler: %s", esp_err_to_name(err));
            vTaskDelay(pdMS_TO_TICKS(40));
        }

        vTaskDelay(pdMS_TO_TICKS(BRIDGE_NFC_POLL_MS));
    }
}

static bool slave_on_request(i2c_slave_dev_handle_t i2c_slave, const i2c_slave_request_event_data_t *evt_data, void *arg)
{
    (void)i2c_slave;
    (void)evt_data;
    bridge_ctx_t *ctx = (bridge_ctx_t *)arg;
    BaseType_t hp_wakeup = pdFALSE;

    bridge_event_t ev = {
        .type = EV_UPSTREAM_REQUEST,
    };
    xQueueSendFromISR(ctx->ev_queue, &ev, &hp_wakeup);
    return hp_wakeup == pdTRUE;
}

static esp_err_t bridge_init(bridge_ctx_t *ctx)
{
    esp_err_t err = ESP_OK;

    ESP_RETURN_ON_ERROR(devkit_led_init(), TAG, "devkit led init failed");
    ESP_RETURN_ON_ERROR(pn532_reset_pulse(), TAG, "pn532 reset pulse failed");
    ESP_RETURN_ON_ERROR(soft_i2c_init(), TAG, "downstream soft i2c init failed");

    ESP_LOGI(TAG, "Downstream I2C Pull-ups auf GPIO%d/GPIO%d: %s", DOWNSTREAM_SDA_GPIO, DOWNSTREAM_SCL_GPIO,
             DOWNSTREAM_INTERNAL_PULLUPS ? "intern aktiv (schwach)" : "intern aus (externe Pull-ups noetig)");

    downstream_i2c_scan();

    err = pn532_probe();
    if (err != ESP_OK) {
        devkit_led_show_boot_error_pattern();
        return err;
    }

    i2c_slave_config_t slave_cfg = {
        .i2c_port = I2C_NUM_0,
        .sda_io_num = UPSTREAM_SDA_GPIO,
        .scl_io_num = UPSTREAM_SCL_GPIO,
        .clk_source = I2C_CLK_SRC_DEFAULT,
        .send_buf_depth = 512,
        .receive_buf_depth = 512,
        .slave_addr = UPSTREAM_SLAVE_ADDR,
        .addr_bit_len = I2C_ADDR_BIT_LEN_7,
        .intr_priority = 0,
        .flags.enable_internal_pullup = 1,
    };
    ESP_RETURN_ON_ERROR(i2c_new_slave_device(&slave_cfg, &ctx->slave_dev), TAG, "slave init failed");

    i2c_slave_event_callbacks_t cbs = {
        .on_request = slave_on_request,
    };
    ESP_RETURN_ON_ERROR(i2c_slave_register_event_callbacks(ctx->slave_dev, &cbs, ctx), TAG, "callback register failed");

    ctx->ev_queue = xQueueCreate(16, sizeof(bridge_event_t));
    if (ctx->ev_queue == NULL) {
        return ESP_ERR_NO_MEM;
    }

    err = pn532_sam_configuration();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "PN532 SAM init fehlgeschlagen: %s", esp_err_to_name(err));
        devkit_led_show_boot_error_pattern();
        return err;
    }

    uint8_t init_pkt[BRIDGE_PKT_LEN] = {0};
    init_pkt[0] = BRIDGE_PKT_MAGIC;
    {
        uint32_t written = 0;
        (void)i2c_slave_write(ctx->slave_dev, init_pkt, BRIDGE_PKT_LEN, &written, 100);
    }

    BaseType_t poll_ok = xTaskCreatePinnedToCore(nfc_poll_task, "bridge_nfc_poll", 4096, NULL, 5, NULL, 0);
    if (poll_ok != pdPASS) {
        return ESP_ERR_NO_MEM;
    }

    (void)devkit_led_set_grb(0x00, 0x00, 0x10);

    ESP_LOGI(TAG, "Bridge ready: host addr=0x%02X -> pn532 addr=0x%02X", UPSTREAM_SLAVE_ADDR, DOWNSTREAM_PN532_ADDR);
    ESP_LOGI(TAG, "Upstream pins SDA=%d SCL=%d, Downstream pins SDA=%d SCL=%d", UPSTREAM_SDA_GPIO, UPSTREAM_SCL_GPIO, DOWNSTREAM_SDA_GPIO, DOWNSTREAM_SCL_GPIO);

    return ESP_OK;
}

void app_main(void)
{
    esp_err_t init_err = ESP_FAIL;
    while ((init_err = bridge_init(&s_ctx)) != ESP_OK) {
        ESP_LOGE(TAG, "Bridge init fehlgeschlagen: %s. Neuer Versuch in %d ms", esp_err_to_name(init_err), BOOT_RETRY_DELAY_MS);
        vTaskDelay(pdMS_TO_TICKS(BOOT_RETRY_DELAY_MS));
    }

    uint8_t tx_buf[BRIDGE_PKT_LEN] = {0};

    while (1) {
        bridge_event_t ev = {0};
        if (xQueueReceive(s_ctx.ev_queue, &ev, portMAX_DELAY) != pdTRUE) {
            continue;
        }

        if (ev.type == EV_UPSTREAM_REQUEST) {
            uint32_t written = 0;
            bridge_uid_state_t snap = {0};

            portENTER_CRITICAL(&s_uid_mux);
            snap = s_uid_state;
            s_uid_state.new_uid = false;
            portEXIT_CRITICAL(&s_uid_mux);

            memset(tx_buf, 0, sizeof(tx_buf));
            tx_buf[0] = BRIDGE_PKT_MAGIC;
            if (snap.valid) {
                tx_buf[1] |= BRIDGE_STATUS_CARD_PRESENT;
            }
            if (snap.new_uid) {
                tx_buf[1] |= BRIDGE_STATUS_NEW_UID;
            }
            tx_buf[2] = snap.uid_len;
            tx_buf[3] = snap.seq;
            if (snap.valid && (snap.uid_len > 0) && (snap.uid_len <= BRIDGE_UID_MAX_LEN)) {
                memcpy(&tx_buf[BRIDGE_PKT_UID_OFFSET], snap.uid, snap.uid_len);
            }

            (void)i2c_slave_write(s_ctx.slave_dev, tx_buf, BRIDGE_PKT_LEN, &written, I2C_TIMEOUT_MS);
        }
    }
}
