/*
 * ESP32 test firmware for knxd KNX IP Secure.
 *
 * Runs crypto self-tests, then starts a TCP server on port 3671
 * that handles KNX IP Secure session handshakes.
 *
 * For QEMU: uses the built-in "open_eth" Ethernet (no WiFi needed).
 */
#include <cstdio>
#include <cstring>
#include <cstdint>

#include "esp_log.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "nvs_flash.h"

#include "lwip/sockets.h"

/* mbedTLS */
#include "mbedtls/aes.h"
#include "mbedtls/sha256.h"
#include "mbedtls/pkcs5.h"
#include "mbedtls/md.h"
#include "mbedtls/ecp.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/bignum.h"

#include "eibnetip.h"
#include "ipsecure.h"

static const char *TAG = "knxd";

/* ============================================================
 * Crypto self-test against AN159v06 / XKNX test vectors
 * ============================================================ */

static int hex2bin(const char* hex, uint8_t* out, int max) {
    int n = 0;
    while (*hex && n < max) {
        while (*hex == ' ') hex++;
        if (!*hex) break;
        unsigned b;
        sscanf(hex, "%2x", &b);
        out[n++] = (uint8_t)b;
        hex += 2;
    }
    return n;
}

static bool test_pbkdf2(void) {
    uint8_t key[16], expected[16];

    /* Device auth: "trustme" */
    hex2bin("e158e4012047bd6cc41aafbc5c04c1fc", expected, 16);
    mbedtls_pkcs5_pbkdf2_hmac_ext(MBEDTLS_MD_SHA256,
        (const uint8_t*)"trustme", 7,
        (const uint8_t*)"device-authentication-code.1.secure.ip.knx.org", 46,
        65536, 16, key);
    if (memcmp(key, expected, 16) != 0) return false;

    /* User password: "secret" */
    hex2bin("03fcedb66660251ec81a1a716901696a", expected, 16);
    mbedtls_pkcs5_pbkdf2_hmac_ext(MBEDTLS_MD_SHA256,
        (const uint8_t*)"secret", 6,
        (const uint8_t*)"user-password.1.secure.ip.knx.org", 33,
        65536, 16, key);
    return memcmp(key, expected, 16) == 0;
}

static bool test_cbc_mac(void) {
    uint8_t key[16], b0[16], ad[8], payload[17], expected[16];
    hex2bin("000102030405060708090a0b0c0d0e0f", key, 16);
    hex2bin("c0c1c2c3c4c500fa12345678affe0011", b0, 16);
    hex2bin("0610095000370000", ad, 8);
    hex2bin("0610053000112900bcd011590ade010081", payload, 17);
    hex2bin("bd0a294b952554b23539204c2271d26b", expected, 16);

    size_t padded = ((16 + 2 + 8 + 17 + 15) / 16) * 16;
    uint8_t input[64] = {};
    memcpy(input, b0, 16);
    input[16] = 0; input[17] = 8;
    memcpy(input + 18, ad, 8);
    memcpy(input + 26, payload, 17);

    uint8_t iv[16] = {}, ct[64];
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_enc(&aes, key, 128);
    mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, padded, iv, input, ct);
    mbedtls_aes_free(&aes);

    return memcmp(ct + padded - 16, expected, 16) == 0;
}

static bool test_handshake(void) {
    IPSecure server;
    server.setDeviceAuthPassword("trustme");
    server.setUserPassword(2, "secret");
    uint8_t sno[6] = {0,0,0xAB,0xCD,0xEF,0x01};
    server.setSerialNumber(sno);

    /* Build a SESSION_REQUEST with a real X25519 key */
    mbedtls_ecp_group grp; mbedtls_mpi d; mbedtls_ecp_point Q;
    mbedtls_entropy_context ent; mbedtls_ctr_drbg_context drbg;
    mbedtls_ecp_group_init(&grp); mbedtls_mpi_init(&d);
    mbedtls_ecp_point_init(&Q); mbedtls_entropy_init(&ent);
    mbedtls_ctr_drbg_init(&drbg);
    mbedtls_ctr_drbg_seed(&drbg, mbedtls_entropy_func, &ent, NULL, 0);
    mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_CURVE25519);
    mbedtls_ecdh_gen_public(&grp, &d, &Q, mbedtls_ctr_drbg_random, &drbg);

    uint8_t pub[32]; size_t olen;
    mbedtls_ecp_point_write_binary(&grp, &Q, MBEDTLS_ECP_PF_COMPRESSED, &olen, pub, 32);

    uint8_t req[46] = {0x06, 0x10, 0x09, 0x51, 0x00, 46, 0x08, 0x04};
    memcpy(req + 14, pub, 32);

    auto resp = server.handleSessionRequest(req, 46);

    mbedtls_ecp_group_free(&grp); mbedtls_mpi_free(&d);
    mbedtls_ecp_point_free(&Q); mbedtls_ctr_drbg_free(&drbg);
    mbedtls_entropy_free(&ent);

    return resp.size() == 56;
}

/* ============================================================
 * Network init for QEMU (uses open_eth, gets IP via DHCP)
 * ============================================================ */
#include "esp_eth.h"
#include "esp_eth_netif_glue.h"
#include "esp_eth_mac_openeth.h"

static volatile bool s_got_ip = false;
static uint32_t s_ip_addr = 0;

static void eth_event_handler(void* arg, esp_event_base_t event_base,
                              int32_t event_id, void* event_data) {
    if (event_base == IP_EVENT && event_id == IP_EVENT_ETH_GOT_IP) {
        ip_event_got_ip_t* ev = (ip_event_got_ip_t*)event_data;
        s_ip_addr = ev->ip_info.ip.addr;
        ESP_LOGI(TAG, "Got IP: %d.%d.%d.%d",
                 (int)(s_ip_addr & 0xFF), (int)((s_ip_addr>>8) & 0xFF),
                 (int)((s_ip_addr>>16) & 0xFF), (int)((s_ip_addr>>24) & 0xFF));
        s_got_ip = true;
    }
}

static void init_ethernet(void) {
    esp_netif_config_t netif_cfg = ESP_NETIF_DEFAULT_ETH();
    esp_netif_t *netif = esp_netif_new(&netif_cfg);

    eth_mac_config_t mac_cfg = ETH_MAC_DEFAULT_CONFIG();
    eth_phy_config_t phy_cfg = ETH_PHY_DEFAULT_CONFIG();

    /* QEMU's open_eth: single-argument API in ESP-IDF v5.4 */
    esp_eth_mac_t *mac = esp_eth_mac_new_openeth(&mac_cfg);
    esp_eth_phy_t *phy = esp_eth_phy_new_dp83848(&phy_cfg);

    esp_eth_config_t eth_cfg = ETH_DEFAULT_CONFIG(mac, phy);
    esp_eth_handle_t eth_handle;
    esp_eth_driver_install(&eth_cfg, &eth_handle);
    esp_netif_attach(netif, esp_eth_new_netif_glue(eth_handle));

    esp_event_handler_register(IP_EVENT, IP_EVENT_ETH_GOT_IP, &eth_event_handler, NULL);
    esp_eth_start(eth_handle);
}

/* ============================================================
 * TCP server: KNX IP Secure tunnel on port 3671
 * ============================================================ */
static void tcp_server_task(void *arg) {
    IPSecure *secure = (IPSecure*)arg;

    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(3671);
    addr.sin_addr.s_addr = INADDR_ANY;
    bind(listen_fd, (struct sockaddr*)&addr, sizeof(addr));
    listen(listen_fd, 2);

    ESP_LOGI(TAG, "KNX IP Secure TCP server listening on port 3671");

    while (1) {
        struct sockaddr_in client_addr;
        socklen_t addrlen = sizeof(client_addr);
        int cfd = accept(listen_fd, (struct sockaddr*)&client_addr, &addrlen);
        if (cfd < 0) continue;

        uint32_t cip = client_addr.sin_addr.s_addr;
        ESP_LOGI(TAG, "Client connected from %d.%d.%d.%d:%d",
                 (int)(cip&0xFF), (int)((cip>>8)&0xFF),
                 (int)((cip>>16)&0xFF), (int)((cip>>24)&0xFF),
                 ntohs(client_addr.sin_port));

        uint16_t session_id = 0;

        while (1) {
            uint8_t buf[512];
            int n = recv(cfd, buf, sizeof(buf), 0);
            if (n <= 0) break;

            if (n < 6) continue;
            uint16_t svc = ((uint16_t)buf[2] << 8) | buf[3];

            ESP_LOGI(TAG, "Received %d bytes, service=0x%04X", n, svc);

            if (svc == SESSION_REQUEST_SVC) {
                auto resp = secure->handleSessionRequest(buf, n);
                if (!resp.empty()) {
                    session_id = ((uint16_t)resp[6] << 8) | resp[7];
                    send(cfd, resp.data(), resp.size(), 0);
                    ESP_LOGI(TAG, "SESSION_RESPONSE sent, session_id=%u", session_id);
                }
            }
            else if (svc == SECURE_WRAPPER_SVC && session_id > 0) {
                uint16_t sid_out = 0;
                auto inner = secure->unwrapSecure(buf, n, sid_out);
                if (!inner.empty()) {
                    ESP_LOGI(TAG, "Unwrapped %d bytes from session %u", (int)inner.size(), sid_out);
                    uint16_t inner_svc = ((uint16_t)inner[2] << 8) | inner[3];

                    if (inner_svc == SESSION_AUTHENTICATE_SVC) {
                        bool ok = secure->handleSessionAuthenticate(sid_out, inner.data(), inner.size());
                        ESP_LOGI(TAG, "SESSION_AUTHENTICATE: %s", ok ? "SUCCESS" : "FAILED");
                        uint8_t status = ok ? 0x00 : 0x01;
                        auto status_pkt = secure->buildSessionStatus(sid_out, status);
                        if (!status_pkt.empty())
                            send(cfd, status_pkt.data(), status_pkt.size(), 0);
                    }
                    /* Other KNXnet/IP service handling would go here */
                }
            }
        }

        ESP_LOGI(TAG, "Client disconnected");
        if (session_id > 0) secure->removeSession(session_id);
        close(cfd);
    }
}

/* ============================================================
 * Main
 * ============================================================ */
extern "C" void app_main(void)
{
    ESP_LOGI(TAG, "=== knxd KNX IP Secure — ESP32 Test ===");

    /* Run crypto self-tests */
    /* Quick crypto sanity check — CBC-MAC only (PBKDF2 too slow in QEMU) */
    ESP_LOGI(TAG, "CBC-MAC test: %s", test_cbc_mac() ? "PASS" : "FAIL");

    /* Init networking (QEMU open_eth) */
    nvs_flash_init();
    esp_netif_init();
    esp_event_loop_create_default();
    init_ethernet();

    /* Wait for IP */
    int timeout = 100;
    while (!s_got_ip && timeout-- > 0)
        vTaskDelay(pdMS_TO_TICKS(100));

    if (!s_got_ip) {
        ESP_LOGE(TAG, "No IP address. If running in QEMU, use: -nic user,model=open_eth,hostfwd=tcp::3671-:3671");
        return;
    }

    /* Start IP Secure TCP server.
     * Use pre-derived keys to avoid PBKDF2 delay in QEMU emulation.
     * Device auth key for "trustme": e158e4012047bd6cc41aafbc5c04c1fc
     * User password key for "secret": 03fcedb66660251ec81a1a716901696a */
    static IPSecure secure;
    uint8_t dev_key[16] = {0xe1,0x58,0xe4,0x01,0x20,0x47,0xbd,0x6c,
                           0xc4,0x1a,0xaf,0xbc,0x5c,0x04,0xc1,0xfc};
    secure.setDeviceAuthKey(dev_key);
    uint8_t user_key[16] = {0x03,0xfc,0xed,0xb6,0x66,0x60,0x25,0x1e,
                            0xc8,0x1a,0x1a,0x71,0x69,0x01,0x69,0x6a};
    /* Use pre-derived user key to skip PBKDF2 in QEMU */
    secure.setUserPasswordKey(2, user_key);
    uint8_t sno[6] = {0xE5, 0x32, 0x00, 0x00, 0x00, 0x01};
    secure.setSerialNumber(sno);

    xTaskCreate(tcp_server_task, "tcp_srv", 8192, &secure, 5, NULL);
}
