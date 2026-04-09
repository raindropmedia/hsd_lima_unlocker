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
 * Upstream bus: Waveshare board (master) -> bridge ESP32 (slave)
 * Downstream bus: bridge ESP32 (master) -> PN532 (slave)
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

#define I2C_CLK_HZ                 100000
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
#define UPSTREAM_STATUS_REPLY_LEN  1
#define PN532_FW_CMD_LEN           9
#define PN532_FW_RESP_READ_LEN     14

#define PN532_READY_STATUS         0x01
#define PN532_WAIT_READY_RETRIES   40
#define PN532_WAIT_READY_DELAY_MS  10
#define PN532_RESET_LOW_MS         10
#define PN532_RESET_BOOT_WAIT_MS   40

#define SOFT_I2C_HALF_PERIOD_US    5
#define DOWNSTREAM_HW_I2C_TEST_MODE 0
#define DIAG_RETRY_DELAY_MS        1000
#define SOFT_I2C_SCL_WAIT_US       1500

#if DOWNSTREAM_HW_I2C_TEST_MODE
#include "driver/i2c.h"
#endif

/* Internal pull-ups are weak; external 2.2k-4.7k to 3V3 are recommended for stable I2C. */
#define DOWNSTREAM_INTERNAL_PULLUPS 1

#define RX_BUF_MAX                 300
#define TX_BUF_MAX                 300

typedef enum {
    BRIDGE_PHASE_STATUS = 0,
    BRIDGE_PHASE_ACK,
    BRIDGE_PHASE_RESPONSE,
} bridge_phase_t;

typedef enum {
    EV_UPSTREAM_RX = 0,
    EV_UPSTREAM_REQUEST,
} bridge_event_type_t;

typedef struct {
    bridge_event_type_t type;
    uint16_t len;
} bridge_event_t;

typedef struct {
    QueueHandle_t ev_queue;
    i2c_slave_dev_handle_t slave_dev;
    volatile bridge_phase_t phase;
    uint8_t rx_shadow[RX_BUF_MAX];
} bridge_ctx_t;

typedef struct {
    rmt_channel_handle_t tx_channel;
    rmt_encoder_handle_t bytes_encoder;
    uint8_t current_grb[3];
    bool ready;
} devkit_led_ctx_t;

static bridge_ctx_t s_ctx = {0};
static devkit_led_ctx_t s_led = {0};
#if DOWNSTREAM_HW_I2C_TEST_MODE
static bool s_downstream_hw_i2c_ready = false;
#endif

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

#if DOWNSTREAM_HW_I2C_TEST_MODE
static esp_err_t downstream_hw_i2c_init(void)
{
    if (s_downstream_hw_i2c_ready) {
        return ESP_OK;
    }

    const i2c_config_t cfg = {
        .mode = I2C_MODE_MASTER,
        .sda_io_num = DOWNSTREAM_SDA_GPIO,
        .scl_io_num = DOWNSTREAM_SCL_GPIO,
        .sda_pullup_en = DOWNSTREAM_INTERNAL_PULLUPS ? GPIO_PULLUP_ENABLE : GPIO_PULLUP_DISABLE,
        .scl_pullup_en = DOWNSTREAM_INTERNAL_PULLUPS ? GPIO_PULLUP_ENABLE : GPIO_PULLUP_DISABLE,
        .master.clk_speed = I2C_CLK_HZ,
        .clk_flags = 0,
    };

    ESP_RETURN_ON_ERROR(i2c_param_config(I2C_NUM_0, &cfg), TAG, "downstream hw i2c param config failed");

    esp_err_t err = i2c_driver_install(I2C_NUM_0, I2C_MODE_MASTER, 0, 0, 0);
    if (err == ESP_ERR_INVALID_STATE) {
        err = ESP_OK;
    }
    ESP_RETURN_ON_ERROR(err, TAG, "downstream hw i2c driver install failed");

    s_downstream_hw_i2c_ready = true;
    return ESP_OK;
}
#endif

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

static esp_err_t devkit_led_apply_phase(bridge_phase_t phase)
{
    switch (phase) {
    case BRIDGE_PHASE_STATUS:
        return devkit_led_set_grb(0x00, 0x00, 0x10);
    case BRIDGE_PHASE_ACK:
        return devkit_led_set_grb(0x10, 0x08, 0x00);
    case BRIDGE_PHASE_RESPONSE:
        return devkit_led_set_grb(0x08, 0x00, 0x00);
    default:
        return devkit_led_set_grb(0x00, 0x00, 0x00);
    }
}

static void devkit_led_show_error(void)
{
    if (devkit_led_set_grb(0x00, 0x18, 0x00) != ESP_OK) {
        return;
    }
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

#if DOWNSTREAM_HW_I2C_TEST_MODE
    ESP_RETURN_ON_ERROR(downstream_hw_i2c_init(), TAG, "downstream hw i2c not ready");
    return i2c_master_write_to_device(I2C_NUM_0, DOWNSTREAM_PN532_ADDR, data, len, pdMS_TO_TICKS(I2C_TIMEOUT_MS));
#else

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
#endif
}

static esp_err_t pn532_read(uint8_t *out, size_t len)
{
    if (len == 0) {
        return ESP_OK;
    }

#if DOWNSTREAM_HW_I2C_TEST_MODE
    ESP_RETURN_ON_ERROR(downstream_hw_i2c_init(), TAG, "downstream hw i2c not ready");
    return i2c_master_read_from_device(I2C_NUM_0, DOWNSTREAM_PN532_ADDR, out, len, pdMS_TO_TICKS(I2C_TIMEOUT_MS));
#else

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
#endif
}

static bool downstream_i2c_address_responds(uint8_t addr7)
{
#if DOWNSTREAM_HW_I2C_TEST_MODE
    i2c_cmd_handle_t cmd = i2c_cmd_link_create();
    if (cmd == NULL) {
        return false;
    }

    bool ack = false;
    if (i2c_master_start(cmd) == ESP_OK &&
        i2c_master_write_byte(cmd, (uint8_t)(addr7 << 1), true) == ESP_OK &&
        i2c_master_stop(cmd) == ESP_OK) {
        ack = (i2c_master_cmd_begin(I2C_NUM_0, cmd, pdMS_TO_TICKS(I2C_TIMEOUT_MS)) == ESP_OK);
    }

    i2c_cmd_link_delete(cmd);
    return ack;
#else
    soft_i2c_start();
    bool ack = soft_i2c_write_byte((uint8_t)(addr7 << 1));
    soft_i2c_stop();
    return ack;
#endif
}

static void downstream_i2c_scan(void)
{
    bool any_found = false;

    ESP_LOGI(TAG, "Downstream I2C-Scan startet (SDA=%d, SCL=%d)", DOWNSTREAM_SDA_GPIO, DOWNSTREAM_SCL_GPIO);

#if !DOWNSTREAM_HW_I2C_TEST_MODE

    if (!soft_i2c_bus_idle()) {
        ESP_LOGW(TAG, "Downstream I2C-Leitung nicht idle (SDA=%d, SCL=%d), versuche Bus-Recovery", soft_i2c_sda_read(), soft_i2c_scl_read());
        if (!soft_i2c_bus_recover()) {
            ESP_LOGE(TAG, "Downstream I2C-Bus bleibt blockiert (SDA=%d, SCL=%d), Scan abgebrochen", soft_i2c_sda_read(), soft_i2c_scl_read());
            return;
        }
    }

#endif

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
    uint8_t status = 0x00;
    esp_err_t last_err = ESP_FAIL;

    for (int i = 0; i < PN532_WAIT_READY_RETRIES; ++i) {
        last_err = pn532_read(&status, PN532_STATUS_READ_LEN);
        if (last_err == ESP_OK && status == PN532_READY_STATUS) {
            return ESP_OK;
        }
        vTaskDelay(pdMS_TO_TICKS(PN532_WAIT_READY_DELAY_MS));
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

static bool slave_on_receive(i2c_slave_dev_handle_t i2c_slave, const i2c_slave_rx_done_event_data_t *evt_data, void *arg)
{
    (void)i2c_slave;
    bridge_ctx_t *ctx = (bridge_ctx_t *)arg;
    BaseType_t hp_wakeup = pdFALSE;

    uint16_t len = 0;
    if (evt_data && evt_data->buffer && evt_data->length > 0) {
        len = (uint16_t)((evt_data->length > RX_BUF_MAX) ? RX_BUF_MAX : evt_data->length);
        memcpy(ctx->rx_shadow, evt_data->buffer, len);
    }

    bridge_event_t ev = {
        .type = EV_UPSTREAM_RX,
        .len = len,
    };
    xQueueSendFromISR(ctx->ev_queue, &ev, &hp_wakeup);
    return hp_wakeup == pdTRUE;
}

static bool slave_on_request(i2c_slave_dev_handle_t i2c_slave, const i2c_slave_request_event_data_t *evt_data, void *arg)
{
    (void)i2c_slave;
    (void)evt_data;
    bridge_ctx_t *ctx = (bridge_ctx_t *)arg;
    BaseType_t hp_wakeup = pdFALSE;

    bridge_event_t ev = {
        .type = EV_UPSTREAM_REQUEST,
        .len = 0,
    };
    xQueueSendFromISR(ctx->ev_queue, &ev, &hp_wakeup);
    return hp_wakeup == pdTRUE;
}

static esp_err_t bridge_init(bridge_ctx_t *ctx)
{
    esp_err_t err = ESP_OK;

    ESP_RETURN_ON_ERROR(devkit_led_init(), TAG, "devkit led init failed");
    ESP_RETURN_ON_ERROR(pn532_reset_pulse(), TAG, "pn532 reset pulse failed");

#if DOWNSTREAM_HW_I2C_TEST_MODE
    ESP_RETURN_ON_ERROR(downstream_hw_i2c_init(), TAG, "downstream hw i2c init failed");
#else
    ESP_RETURN_ON_ERROR(soft_i2c_init(), TAG, "downstream soft i2c init failed");
#endif

    ESP_LOGI(TAG, "Downstream I2C Pull-ups auf GPIO%d/GPIO%d: %s", DOWNSTREAM_SDA_GPIO, DOWNSTREAM_SCL_GPIO,
             DOWNSTREAM_INTERNAL_PULLUPS ? "intern aktiv (schwach)" : "intern aus (externe Pull-ups noetig)");

#if DOWNSTREAM_HW_I2C_TEST_MODE
    ESP_LOGW(TAG, "HW-I2C Testmodus aktiv: Upstream-Bridge ist deaktiviert");
#endif

    downstream_i2c_scan();

    err = pn532_probe();
    if (err != ESP_OK) {
        devkit_led_show_boot_error_pattern();
        return err;
    }

#if DOWNSTREAM_HW_I2C_TEST_MODE
    ESP_LOGI(TAG, "HW-I2C Test erfolgreich: PN532 antwortet auf GPIO%d/GPIO%d", DOWNSTREAM_SDA_GPIO, DOWNSTREAM_SCL_GPIO);
    (void)devkit_led_set_grb(0x18, 0x00, 0x00);
    return ESP_OK;
#endif

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
        .on_receive = slave_on_receive,
    };
    ESP_RETURN_ON_ERROR(i2c_slave_register_event_callbacks(ctx->slave_dev, &cbs, ctx), TAG, "callback register failed");

    ctx->ev_queue = xQueueCreate(16, sizeof(bridge_event_t));
    if (ctx->ev_queue == NULL) {
        return ESP_ERR_NO_MEM;
    }

    ctx->phase = BRIDGE_PHASE_STATUS;
    ESP_RETURN_ON_ERROR(devkit_led_apply_phase(ctx->phase), TAG, "devkit led status state failed");

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

#if DOWNSTREAM_HW_I2C_TEST_MODE
    while (1) {
        vTaskDelay(pdMS_TO_TICKS(DIAG_RETRY_DELAY_MS));
    }
#endif

    uint8_t tx_buf[TX_BUF_MAX] = {0};

    while (1) {
        bridge_event_t ev = {0};
        if (xQueueReceive(s_ctx.ev_queue, &ev, portMAX_DELAY) != pdTRUE) {
            continue;
        }

        if (ev.type == EV_UPSTREAM_RX) {
            if (ev.len > 0) {
                ESP_LOGI(TAG, "Upstream write empfangen: %u Bytes", (unsigned int)ev.len);
                (void)devkit_led_set_grb(0x08, 0x08, 0x08);
                esp_err_t err = pn532_write(s_ctx.rx_shadow, ev.len);
                if (err != ESP_OK) {
                    ESP_LOGW(TAG, "Forward write failed: %s", esp_err_to_name(err));
                    devkit_led_show_error();
                    s_ctx.phase = BRIDGE_PHASE_STATUS;
                } else {
                    s_ctx.phase = BRIDGE_PHASE_ACK;
                    ESP_LOGI(TAG, "Bridge Phase -> ACK");
                    (void)devkit_led_apply_phase(s_ctx.phase);
                }
            }
            continue;
        }

        if (ev.type == EV_UPSTREAM_REQUEST) {
            uint32_t written = 0;
            esp_err_t err = ESP_OK;

            if (s_ctx.phase == BRIDGE_PHASE_STATUS) {
                (void)devkit_led_set_grb(0x08, 0x00, 0x08);
                uint8_t status = 0x00;
                err = pn532_read(&status, PN532_STATUS_READ_LEN);
                if (err != ESP_OK) {
                    status = 0x00;
                    devkit_led_show_error();
                }
                tx_buf[0] = status;
                (void)i2c_slave_write(s_ctx.slave_dev, tx_buf, UPSTREAM_STATUS_REPLY_LEN, &written, I2C_TIMEOUT_MS);
                (void)devkit_led_apply_phase(s_ctx.phase);
                continue;
            }

            if (s_ctx.phase == BRIDGE_PHASE_ACK) {
                (void)devkit_led_set_grb(0x18, 0x10, 0x00);
                err = pn532_read(tx_buf, PN532_ACK_READ_LEN);
                if (err != ESP_OK) {
                    memset(tx_buf, 0, PN532_ACK_READ_LEN);
                    devkit_led_show_error();
                }
                (void)i2c_slave_write(s_ctx.slave_dev, tx_buf, PN532_ACK_READ_LEN, &written, I2C_TIMEOUT_MS);
                ESP_LOGI(TAG, "ACK weitergeleitet: %02X %02X %02X %02X %02X %02X %02X",
                         tx_buf[0], tx_buf[1], tx_buf[2], tx_buf[3], tx_buf[4], tx_buf[5], tx_buf[6]);
                s_ctx.phase = BRIDGE_PHASE_RESPONSE;
                ESP_LOGI(TAG, "Bridge Phase -> RESPONSE");
                (void)devkit_led_apply_phase(s_ctx.phase);
                continue;
            }

            (void)devkit_led_set_grb(0x18, 0x00, 0x00);
            err = pn532_read(tx_buf, PN532_RESPONSE_READ_LEN);
            if (err != ESP_OK) {
                memset(tx_buf, 0, PN532_RESPONSE_READ_LEN);
                devkit_led_show_error();
            }
            (void)i2c_slave_write(s_ctx.slave_dev, tx_buf, PN532_RESPONSE_READ_LEN, &written, I2C_TIMEOUT_MS);
            ESP_LOGI(TAG, "Response weitergeleitet, Header: %02X %02X %02X %02X %02X %02X %02X %02X",
                     tx_buf[0], tx_buf[1], tx_buf[2], tx_buf[3], tx_buf[4], tx_buf[5], tx_buf[6], tx_buf[7]);
            s_ctx.phase = BRIDGE_PHASE_STATUS;
            ESP_LOGI(TAG, "Bridge Phase -> STATUS");
            (void)devkit_led_apply_phase(s_ctx.phase);
        }
    }
}
