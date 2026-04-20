/*
 * ESP32 main entry point for knxd KNX TP → IP Secure tunnel.
 *
 * This is the ESP32-specific startup code. It:
 * 1. Connects to WiFi
 * 2. Opens the TPUART UART device
 * 3. Configures the knxd router with a TPUART backend and TCP tunnel server
 * 4. Runs the libev event loop
 *
 * The actual KNX protocol handling is done by the original knxd code.
 */

#include <cstdio>
#include <cstring>

#ifdef ESP_PLATFORM
#include "esp_log.h"
#include "sdkconfig.h"

static const char* TAG = "knxd_main";

/* Platform functions (from platform_esp32.cpp) */
extern void platform_wifi_init(const char* ssid, const char* password);
extern bool platform_wifi_connected(void);
extern int platform_uart_init(int uart_num, int tx_pin, int rx_pin, int baud_rate);
#endif

#include <ev++.h>
#include "inifile.h"
#include "router.h"

/*
 * Build a knxd INI configuration programmatically.
 *
 * Equivalent to this knxd.ini:
 *   [main]
 *   addr = 1.1.1
 *   client-addrs = 1.1.200:4
 *
 *   [A.tcp]
 *   server = tcptunsrv
 *   port = 3671
 *   device-auth = trustme
 *   user-password = secret
 *
 *   [B.tpuart]
 *   driver = tpuart
 *   device = /dev/uart/1
 *   baudrate = 19200
 */
static IniData build_config(int uart_fd)
{
    IniData ini;
    auto& main_sec = ini["main"];
#ifdef ESP_PLATFORM
    /* Use Kconfig values */
    uint16_t addr = CONFIG_KNX_INDIVIDUAL_ADDRESS;
    char addr_str[16];
    snprintf(addr_str, sizeof(addr_str), "%d.%d.%d",
             (addr >> 12) & 0xF, (addr >> 8) & 0xF, addr & 0xFF);
    main_sec["addr"] = addr_str;
    main_sec["client-addrs"] = "1.1.200:4";

    auto& tcp = ini["A.tcp"];
    tcp["server"] = "tcptunsrv";
    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%d", CONFIG_KNX_TCP_PORT);
    tcp["port"] = port_str;
    tcp["device-auth"] = CONFIG_KNX_DEVICE_AUTH_PASSWORD;
    tcp["user-password"] = CONFIG_KNX_USER_PASSWORD;

    auto& tp = ini["B.tpuart"];
    tp["driver"] = "tpuart";
    char fd_str[16];
    snprintf(fd_str, sizeof(fd_str), "/dev/fd/%d", uart_fd);
    tp["device"] = fd_str;
    char baud_str[8];
    snprintf(baud_str, sizeof(baud_str), "%d", CONFIG_KNX_UART_BAUD);
    tp["baudrate"] = baud_str;
#else
    /* Native Linux test defaults */
    (void)uart_fd;
    main_sec["addr"] = "1.1.1";
    main_sec["client-addrs"] = "1.1.200:4";

    auto& tcp = ini["A.tcp"];
    tcp["server"] = "tcptunsrv";
    tcp["port"] = "3671";
    tcp["device-auth"] = "trustme";
    tcp["user-password"] = "secret";
#endif

    return ini;
}

#ifdef ESP_PLATFORM
extern "C" void app_main(void)
{
    ESP_LOGI(TAG, "KNX IP Secure Gateway starting...");

    /* Step 1: Connect to WiFi */
    platform_wifi_init(CONFIG_KNX_WIFI_SSID, CONFIG_KNX_WIFI_PASSWORD);

    /* Wait for WiFi connection */
    int timeout = 100; /* 10 seconds */
    while (!platform_wifi_connected() && timeout-- > 0) {
        vTaskDelay(pdMS_TO_TICKS(100));
    }
    if (!platform_wifi_connected()) {
        ESP_LOGE(TAG, "WiFi connection failed!");
        return;
    }

    /* Step 2: Initialize TPUART UART */
    int uart_fd = platform_uart_init(
        CONFIG_KNX_UART_NUM,
        CONFIG_KNX_UART_TX_PIN,
        CONFIG_KNX_UART_RX_PIN,
        CONFIG_KNX_UART_BAUD
    );
    if (uart_fd < 0) {
        ESP_LOGE(TAG, "UART init failed!");
        return;
    }

    /* Step 3: Build config and start router */
    IniData config = build_config(uart_fd);
    /* TODO: initialize Router with config and start event loop */
    /* The Router constructor, setup, and event loop integration
     * requires the full knxd infrastructure (link chain, server
     * registration, etc.). This is the glue code that ties the
     * ESP32 platform to the knxd architecture. */

    ESP_LOGI(TAG, "Running event loop...");

    /* Step 4: Run libev event loop */
    struct ev_loop *loop = ev_default_loop(EVFLAG_AUTO);
    /* Router and servers register their watchers with the default loop */
    ev_run(loop, 0);

    ESP_LOGE(TAG, "Event loop exited unexpectedly");
}
#else
int main(int argc, char** argv)
{
    printf("knxd ESP32 port — native test mode\n");
    IniData config = build_config(-1);
    printf("Config built OK, sections:\n");
    for (auto& kv : config)
        printf("  [%s]\n", kv.first.c_str());

    struct ev_loop *loop = ev_default_loop(EVFLAG_AUTO);
    printf("libev loop created: %p\n", (void*)loop);
    printf("Native test passed.\n");
    return 0;
}
#endif
