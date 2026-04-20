/*
 * ESP32 platform abstraction for knxd
 *
 * Provides WiFi initialization, UART-as-VFS setup,
 * and stubs for Linux-specific functionality.
 */

#ifdef ESP_PLATFORM

#include <cstring>
#include <cstdio>

#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "nvs_flash.h"
#include "driver/uart.h"
#include "esp_vfs_dev.h"
#include "esp_log.h"

static const char* TAG = "knxd_platform";

/* ============================================================
 * WiFi STA initialization
 * ============================================================ */

static bool s_wifi_connected = false;

static void wifi_event_handler(void* arg, esp_event_base_t event_base,
                               int32_t event_id, void* event_data)
{
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START)
        esp_wifi_connect();
    else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED)
        esp_wifi_connect();
    else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t* event = (ip_event_got_ip_t*)event_data;
        ESP_LOGI(TAG, "Got IP: " IPSTR, IP2STR(&event->ip_info.ip));
        s_wifi_connected = true;
    }
}

void platform_wifi_init(const char* ssid, const char* password)
{
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        nvs_flash_erase();
        nvs_flash_init();
    }

    esp_netif_init();
    esp_event_loop_create_default();
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&cfg);

    esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID,
                                        &wifi_event_handler, NULL, NULL);
    esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP,
                                        &wifi_event_handler, NULL, NULL);

    wifi_config_t wifi_config = {};
    strncpy((char*)wifi_config.sta.ssid, ssid, sizeof(wifi_config.sta.ssid) - 1);
    strncpy((char*)wifi_config.sta.password, password, sizeof(wifi_config.sta.password) - 1);

    esp_wifi_set_mode(WIFI_MODE_STA);
    esp_wifi_set_config(WIFI_IF_STA, &wifi_config);
    esp_wifi_start();

    ESP_LOGI(TAG, "WiFi connecting to %s...", ssid);
}

bool platform_wifi_connected(void)
{
    return s_wifi_connected;
}

/* ============================================================
 * UART-as-VFS for TPUART (provides fd-based I/O + select())
 * ============================================================ */

int platform_uart_init(int uart_num, int tx_pin, int rx_pin, int baud_rate)
{
    uart_config_t uart_config = {};
    uart_config.baud_rate = baud_rate;
    uart_config.data_bits = UART_DATA_8_BITS;
    uart_config.parity = UART_PARITY_EVEN;
    uart_config.stop_bits = UART_STOP_BITS_1;
    uart_config.flow_ctrl = UART_HW_FLOWCTRL_DISABLE;
    uart_config.source_clk = UART_SCLK_DEFAULT;

    uart_param_config((uart_port_t)uart_num, &uart_config);
    uart_set_pin((uart_port_t)uart_num, tx_pin, rx_pin,
                 UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE);
    uart_driver_install((uart_port_t)uart_num, 256, 256, 0, NULL, 0);

    /* Register UART as VFS device so it gets an fd for select() */
    esp_vfs_dev_uart_use_driver((uart_port_t)uart_num);

    /* Open the UART device — returns a file descriptor */
    char dev_path[20];
    snprintf(dev_path, sizeof(dev_path), "/dev/uart/%d", uart_num);
    int fd = open(dev_path, O_RDWR | O_NONBLOCK);
    if (fd < 0) {
        ESP_LOGE(TAG, "Failed to open %s", dev_path);
        return -1;
    }

    ESP_LOGI(TAG, "UART%d initialized: %d baud, fd=%d", uart_num, baud_rate, fd);
    return fd;
}

#endif /* ESP_PLATFORM */
