/*
 * Test KNX IP Secure crypto against XKNX / AN159v06 test vectors.
 * Builds standalone with mbedTLS — no libev, no fmt, no knxd infrastructure.
 */
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <vector>
#include <cassert>

#include <mbedtls/aes.h>
#include <mbedtls/sha256.h>
#include <mbedtls/pkcs5.h>
#include <mbedtls/ecp.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/bignum.h>

/* Provide just enough of eibnetip.h constants for ipsecure.cpp */
#define HEADER_SIZE_10     0x06
#define KNXNETIP_VERSION_10 0x10
#define SESSION_REQUEST_SVC     0x0951
#define SESSION_RESPONSE_SVC    0x0952
#define SESSION_AUTHENTICATE_SVC 0x0953
#define SESSION_STATUS_SVC      0x0954
#define SECURE_WRAPPER_SVC      0x0950

#ifndef EIBNETIP_H
#define EIBNETIP_H
#endif

#include "../src/libserver/ipsecure.h"

static int hex2bin(const char* hex, uint8_t* out, size_t max) {
    int n = 0;
    while (*hex && n < (int)max) {
        while (*hex == ' ') hex++;
        if (!*hex) break;
        unsigned int b;
        if (sscanf(hex, "%2x", &b) != 1) break;
        out[n++] = (uint8_t)b;
        hex += 2;
    }
    return n;
}

static void print_hex(const char* label, const uint8_t* data, int len) {
    printf("  %s: ", label);
    for (int i = 0; i < len; i++) printf("%02x ", data[i]);
    printf("\n");
}

static int tests_passed = 0;
static int tests_failed = 0;

#define CHECK(name, cond) do { \
    if (cond) { tests_passed++; printf("  PASS: %s\n", name); } \
    else { tests_failed++; printf("  FAIL: %s\n", name); } \
} while(0)

/* ============================================================ */
static void test_pbkdf2() {
    printf("\n=== Test PBKDF2 Key Derivation ===\n");

    uint8_t dev_key[16], user_key[16];
    uint8_t expected_dev[16], expected_user[16];
    hex2bin("e158e4012047bd6cc41aafbc5c04c1fc", expected_dev, 16);
    hex2bin("03fcedb66660251ec81a1a716901696a", expected_user, 16);

    const char* dev_salt = "device-authentication-code.1.secure.ip.knx.org";
    mbedtls_pkcs5_pbkdf2_hmac_ext(MBEDTLS_MD_SHA256,
        (const uint8_t*)"trustme", 7,
        (const uint8_t*)dev_salt, strlen(dev_salt),
        65536, 16, dev_key);
    CHECK("device auth key (trustme)", memcmp(dev_key, expected_dev, 16) == 0);
    print_hex("got", dev_key, 16);
    print_hex("exp", expected_dev, 16);

    const char* user_salt = "user-password.1.secure.ip.knx.org";
    mbedtls_pkcs5_pbkdf2_hmac_ext(MBEDTLS_MD_SHA256,
        (const uint8_t*)"secret", 6,
        (const uint8_t*)user_salt, strlen(user_salt),
        65536, 16, user_key);
    CHECK("user password key (secret)", memcmp(user_key, expected_user, 16) == 0);
    print_hex("got", user_key, 16);
    print_hex("exp", expected_user, 16);
}

/* ============================================================ */
static void test_cbc_mac() {
    printf("\n=== Test CBC-MAC ===\n");

    /* RoutingIndication from AN159v06 */
    uint8_t key[16], block0[16], ad[8], payload[17], expected_mac[16];
    hex2bin("000102030405060708090a0b0c0d0e0f", key, 16);
    hex2bin("c0c1c2c3c4c500fa12345678affe0011", block0, 16);
    hex2bin("0610095000370000", ad, 8);
    hex2bin("0610053000112900bcd011590ade010081", payload, 17);
    hex2bin("bd0a294b952554b23539204c2271d26b", expected_mac, 16);

    {
        size_t ad_len = 8, payload_len = 17;
        size_t input_len = 16 + 2 + ad_len + payload_len;
        size_t padded_len = ((input_len + 15) / 16) * 16;

        std::vector<uint8_t> input(padded_len, 0);
        memcpy(input.data(), block0, 16);
        input[16] = (ad_len >> 8) & 0xFF;
        input[17] = ad_len & 0xFF;
        memcpy(input.data() + 18, ad, ad_len);
        memcpy(input.data() + 18 + ad_len, payload, payload_len);

        uint8_t iv[16] = {};
        std::vector<uint8_t> ct(padded_len);
        mbedtls_aes_context aes;
        mbedtls_aes_init(&aes);
        mbedtls_aes_setkey_enc(&aes, key, 128);
        mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, padded_len, iv, input.data(), ct.data());
        mbedtls_aes_free(&aes);

        uint8_t mac[16];
        memcpy(mac, ct.data() + padded_len - 16, 16);
        CHECK("CBC-MAC (RoutingIndication)", memcmp(mac, expected_mac, 16) == 0);
        print_hex("got", mac, 16);
        print_hex("exp", expected_mac, 16);
    }

    /* SessionResponse MAC */
    {
        uint8_t dev_key[16], sr_ad[40], sr_expected[16];
        hex2bin("e158e4012047bd6cc41aafbc5c04c1fc", dev_key, 16);
        hex2bin("0610095200380001b752be246459260f"
                "6b0c4801fbd5a67599f83b4057b3ef1e"
                "79e469ac17234e15", sr_ad, 40);
        hex2bin("da3dc6af79896aa6ee7573d69950c283", sr_expected, 16);

        size_t ad_len = 40;
        size_t inp_len = 16 + 2 + ad_len;
        size_t padded = ((inp_len + 15) / 16) * 16;

        std::vector<uint8_t> input(padded, 0);
        input[16] = (ad_len >> 8) & 0xFF;
        input[17] = ad_len & 0xFF;
        memcpy(input.data() + 18, sr_ad, ad_len);

        uint8_t iv[16] = {};
        std::vector<uint8_t> ct(padded);
        mbedtls_aes_context aes;
        mbedtls_aes_init(&aes);
        mbedtls_aes_setkey_enc(&aes, dev_key, 128);
        mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, padded, iv, input.data(), ct.data());
        mbedtls_aes_free(&aes);

        uint8_t mac[16];
        memcpy(mac, ct.data() + padded - 16, 16);
        CHECK("CBC-MAC (SessionResponse)", memcmp(mac, sr_expected, 16) == 0);
        print_hex("got", mac, 16);
        print_hex("exp", sr_expected, 16);
    }
}

/* ============================================================ */
static void test_ctr() {
    printf("\n=== Test CTR Encrypt/Decrypt ===\n");

    uint8_t key[16], counter0[16], mac_cbc[16], plain[17];
    uint8_t exp_enc_data[17], exp_enc_mac[16];
    hex2bin("000102030405060708090a0b0c0d0e0f", key, 16);
    hex2bin("c0c1c2c3c4c500fa12345678affeff00", counter0, 16);
    hex2bin("bd0a294b952554b23539204c2271d26b", mac_cbc, 16);
    hex2bin("0610053000112900bcd011590ade010081", plain, 17);
    hex2bin("b7ee7e8a1c2f7bbabec775fd6e10d0bc4b", exp_enc_data, 17);
    hex2bin("7212a03aaae49da85689774c1d2b4da4", exp_enc_mac, 16);

    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_enc(&aes, key, 128);

    uint8_t ks[48];
    uint8_t ctr[16];
    memcpy(ctr, counter0, 16);
    for (int b = 0; b < 3; b++) {
        mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_ENCRYPT, ctr, ks + b * 16);
        for (int j = 15; j >= 0; j--) {
            if (++ctr[j] != 0) break;
        }
    }
    mbedtls_aes_free(&aes);

    uint8_t enc_payload[17], enc_mac[16];
    for (int i = 0; i < 17; i++) enc_payload[i] = plain[i] ^ ks[16 + i];
    for (int i = 0; i < 16; i++) enc_mac[i] = mac_cbc[i] ^ ks[i];

    CHECK("CTR encrypt payload", memcmp(enc_payload, exp_enc_data, 17) == 0);
    print_hex("got", enc_payload, 17);
    print_hex("exp", exp_enc_data, 17);

    CHECK("CTR encrypt MAC", memcmp(enc_mac, exp_enc_mac, 16) == 0);
    print_hex("got", enc_mac, 16);
    print_hex("exp", exp_enc_mac, 16);
}

/* ============================================================ */
static void test_handshake_roundtrip() {
    printf("\n=== Test Full Handshake Round-trip ===\n");

    IPSecure server;
    server.setDeviceAuthPassword("trustme");
    server.setUserPassword(2, "secret");
    uint8_t sno[6] = {0x00, 0x00, 0xAB, 0xCD, 0xEF, 0x01};
    server.setSerialNumber(sno);
    CHECK("server enabled", server.isEnabled());

    /* Client: generate X25519 keypair */
    mbedtls_ecp_group grp;
    mbedtls_mpi d;
    mbedtls_ecp_point Q;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context drbg;

    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);
    mbedtls_ecp_point_init(&Q);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&drbg);

    assert(mbedtls_ctr_drbg_seed(&drbg, mbedtls_entropy_func, &entropy, NULL, 0) == 0);
    assert(mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_CURVE25519) == 0);
    assert(mbedtls_ecdh_gen_public(&grp, &d, &Q, mbedtls_ctr_drbg_random, &drbg) == 0);

    uint8_t client_pub[32];
    size_t olen;
    assert(mbedtls_ecp_point_write_binary(&grp, &Q, MBEDTLS_ECP_PF_COMPRESSED, &olen, client_pub, 32) == 0);

    /* Build SESSION_REQUEST */
    uint8_t session_req[46] = {};
    session_req[0] = 0x06; session_req[1] = 0x10;
    session_req[2] = 0x09; session_req[3] = 0x51;
    session_req[4] = 0x00; session_req[5] = 46;
    session_req[6] = 0x08; session_req[7] = 0x04;
    memcpy(session_req + 14, client_pub, 32);

    std::vector<uint8_t> resp = server.handleSessionRequest(session_req, 46);
    CHECK("SESSION_RESPONSE not empty", !resp.empty());
    CHECK("SESSION_RESPONSE length=56", resp.size() == 56);

    if (resp.size() != 56) goto cleanup;

    {
        uint16_t session_id = ((uint16_t)resp[6] << 8) | resp[7];
        CHECK("session_id > 0", session_id > 0);

        uint8_t server_pub[32];
        memcpy(server_pub, resp.data() + 8, 32);

        /* Client: ECDH shared secret */
        mbedtls_ecp_point Qp;
        mbedtls_mpi z;
        mbedtls_ecp_point_init(&Qp);
        mbedtls_mpi_init(&z);

        assert(mbedtls_ecp_point_read_binary(&grp, &Qp, server_pub, 32) == 0);
        assert(mbedtls_ecdh_compute_shared(&grp, &z, &Qp, &d, mbedtls_ctr_drbg_random, &drbg) == 0);

        uint8_t shared_secret[32], hash[32];
        assert(mbedtls_mpi_write_binary_le(&z, shared_secret, 32) == 0);
        mbedtls_sha256(shared_secret, 32, hash, 0);

        /* Client: verify device auth MAC */
        uint8_t dev_key[16];
        const char* dev_salt = "device-authentication-code.1.secure.ip.knx.org";
        mbedtls_pkcs5_pbkdf2_hmac_ext(MBEDTLS_MD_SHA256,
            (const uint8_t*)"trustme", 7,
            (const uint8_t*)dev_salt, strlen(dev_salt), 65536, 16, dev_key);

        uint8_t xor_keys[32];
        for (int i = 0; i < 32; i++) xor_keys[i] = client_pub[i] ^ server_pub[i];

        uint8_t aad[40];
        memcpy(aad, resp.data(), 6);
        memcpy(aad + 6, resp.data() + 6, 2);
        memcpy(aad + 8, xor_keys, 32);

        size_t ad_len = 40, inp_len = 16 + 2 + ad_len;
        size_t padded = ((inp_len + 15) / 16) * 16;
        std::vector<uint8_t> input(padded, 0);
        input[16] = (ad_len >> 8); input[17] = ad_len & 0xFF;
        memcpy(input.data() + 18, aad, ad_len);

        uint8_t iv[16] = {};
        std::vector<uint8_t> ct(padded);
        mbedtls_aes_context aes;
        mbedtls_aes_init(&aes);
        mbedtls_aes_setkey_enc(&aes, dev_key, 128);
        mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, padded, iv, input.data(), ct.data());

        uint8_t expected_mac[16];
        memcpy(expected_mac, ct.data() + padded - 16, 16);

        uint8_t ctr0[16] = {}; ctr0[14] = 0xFF;
        uint8_t ks[16];
        mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_ENCRYPT, ctr0, ks);
        mbedtls_aes_free(&aes);
        for (int i = 0; i < 16; i++) expected_mac[i] ^= ks[i];

        CHECK("device auth MAC verified", memcmp(resp.data() + 40, expected_mac, 16) == 0);

        /* Client: build SESSION_AUTHENTICATE */
        uint8_t user_key[16];
        const char* user_salt = "user-password.1.secure.ip.knx.org";
        mbedtls_pkcs5_pbkdf2_hmac_ext(MBEDTLS_MD_SHA256,
            (const uint8_t*)"secret", 6,
            (const uint8_t*)user_salt, strlen(user_salt), 65536, 16, user_key);

        uint8_t auth_aad[40];
        uint8_t auth_hdr[6] = {0x06, 0x10, 0x09, 0x53, 0x00, 0x18};
        memcpy(auth_aad, auth_hdr, 6);
        auth_aad[6] = 0x00; auth_aad[7] = 0x02;
        memcpy(auth_aad + 8, xor_keys, 32);

        inp_len = 16 + 2 + 40;
        padded = ((inp_len + 15) / 16) * 16;
        input.assign(padded, 0);
        input[16] = 0; input[17] = 40;
        memcpy(input.data() + 18, auth_aad, 40);

        memset(iv, 0, 16);
        ct.resize(padded);
        mbedtls_aes_init(&aes);
        mbedtls_aes_setkey_enc(&aes, user_key, 128);
        mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, padded, iv, input.data(), ct.data());

        uint8_t auth_mac[16];
        memcpy(auth_mac, ct.data() + padded - 16, 16);

        memset(ctr0, 0, 16); ctr0[14] = 0xFF;
        mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_ENCRYPT, ctr0, ks);
        mbedtls_aes_free(&aes);
        for (int i = 0; i < 16; i++) auth_mac[i] ^= ks[i];

        uint8_t auth_frame[24];
        memcpy(auth_frame, auth_hdr, 6);
        auth_frame[6] = 0x00; auth_frame[7] = 0x02;
        memcpy(auth_frame + 8, auth_mac, 16);

        bool auth_ok = server.handleSessionAuthenticate(session_id, auth_frame, 24);
        CHECK("SESSION_AUTHENTICATE accepted", auth_ok);

        SecureSession* sess = server.findSession(session_id);
        CHECK("session AUTHENTICATED", sess && sess->state == SecureSession::AUTHENTICATED);
        CHECK("user_id=2", sess && sess->user_id == 2);

        /* SecureWrapper round-trip */
        uint8_t inner[] = {0x06, 0x10, 0x04, 0x20, 0x00, 0x15,
                           0x04, 0x01, 0x00, 0x00,
                           0x11, 0x00, 0xBC, 0xE0, 0x00, 0x00,
                           0x0A, 0xDE, 0x01, 0x00, 0x81};
        std::vector<uint8_t> wrapped = server.wrapSecure(session_id, inner, sizeof(inner));
        CHECK("wrapSecure not empty", !wrapped.empty());

        if (!wrapped.empty()) {
            uint16_t unwrap_sid = 0;
            std::vector<uint8_t> unwrapped = server.unwrapSecure(
                wrapped.data(), wrapped.size(), unwrap_sid);
            CHECK("unwrapSecure not empty", !unwrapped.empty());
            CHECK("session_id matches", unwrap_sid == session_id);
            CHECK("payload matches", unwrapped.size() == sizeof(inner) &&
                  memcmp(unwrapped.data(), inner, sizeof(inner)) == 0);
        }

        mbedtls_ecp_point_free(&Qp);
        mbedtls_mpi_free(&z);
    }

cleanup:
    mbedtls_ecp_group_free(&grp);
    mbedtls_mpi_free(&d);
    mbedtls_ecp_point_free(&Q);
    mbedtls_ctr_drbg_free(&drbg);
    mbedtls_entropy_free(&entropy);
}

int main() {
    printf("KNX IP Secure Crypto Test Suite\n");
    printf("================================\n");
    test_pbkdf2();
    test_cbc_mac();
    test_ctr();
    test_handshake_roundtrip();
    printf("\n================================\n");
    printf("Results: %d passed, %d failed\n", tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
