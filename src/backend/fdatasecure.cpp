/*
    knxd - KNX daemon
    KNX Data Secure filter

    Copyright (C) 2026

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
*/

#include "fdatasecure.h"

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <cstring>
#include <ctime>
#include <chrono>
#include <fstream>

// base64 decode using OpenSSL
static std::vector<uint8_t> base64Decode(const std::string& encoded) {
  std::vector<uint8_t> out(encoded.size());
  EVP_ENCODE_CTX *ctx = EVP_ENCODE_CTX_new();
  EVP_DecodeInit(ctx);
  int outl = 0, outl2 = 0;
  EVP_DecodeUpdate(ctx, out.data(), &outl,
                   (const unsigned char*)encoded.c_str(), encoded.size());
  EVP_DecodeFinal(ctx, out.data() + outl, &outl2);
  EVP_ENCODE_CTX_free(ctx);
  out.resize(outl + outl2);
  return out;
}

// PBKDF2 for keyring password
static bool pbkdf2_sha256(const std::string& password,
                          const uint8_t* salt, int salt_len,
                          int iterations, uint8_t* out, int out_len) {
  return PKCS5_PBKDF2_HMAC(password.c_str(), password.size(),
                           salt, salt_len, iterations,
                           EVP_sha256(), out_len, out) == 1;
}

// AES-128-CBC decrypt (no padding removal)
static bool aes128_cbc_decrypt(const uint8_t key[16], const uint8_t iv[16],
                               const uint8_t* ct, int ct_len,
                               uint8_t* pt, int* pt_len) {
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);
  EVP_CIPHER_CTX_set_padding(ctx, 0);
  int len = 0;
  EVP_DecryptUpdate(ctx, pt, &len, ct, ct_len);
  *pt_len = len;
  int final_len = 0;
  EVP_DecryptFinal_ex(ctx, pt + len, &final_len);
  *pt_len += final_len;
  EVP_CIPHER_CTX_free(ctx);
  return true;
}

// AES-128-CBC encrypt (for MAC calculation)
static bool aes128_cbc_encrypt(const uint8_t key[16], const uint8_t iv[16],
                               const uint8_t* pt, int pt_len,
                               uint8_t* ct, int* ct_len) {
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);
  EVP_CIPHER_CTX_set_padding(ctx, 0);
  int len = 0;
  EVP_EncryptUpdate(ctx, ct, &len, pt, pt_len);
  *ct_len = len;
  int final_len = 0;
  EVP_EncryptFinal_ex(ctx, ct + len, &final_len);
  *ct_len += final_len;
  EVP_CIPHER_CTX_free(ctx);
  return true;
}

// ---- Initial sequence number from time since 2018-01-05 ----
static uint64_t initialSequenceNumber() {
  struct tm epoch_tm = {};
  epoch_tm.tm_year = 2018 - 1900;
  epoch_tm.tm_mon = 0;
  epoch_tm.tm_mday = 5;
  time_t epoch = timegm(&epoch_tm);

  auto now = std::chrono::system_clock::now();
  auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
              now.time_since_epoch()).count();
  uint64_t epoch_ms = (uint64_t)epoch * 1000;
  return (uint64_t)(ms - epoch_ms);
}

// =====================================================
// DataSecureFilter implementation
// =====================================================

DataSecureFilter::DataSecureFilter(const LinkConnectPtr_& c, IniSectionPtr& s)
  : Filter(c, s)
{
  t->setAuxName("datasecure");
  seq_sending = initialSequenceNumber();
}

bool DataSecureFilter::setup()
{
  if (!Filter::setup())
    return false;

  std::string keyring_path = cfg->value("keyring", "");
  std::string keyring_password = cfg->value("keyring-password", "");

  if (!keyring_path.empty()) {
    if (!loadKeyring(keyring_path, keyring_password)) {
      ERRORPRINTF(t, E_ERROR | 55, "Failed to load keyring from %s", keyring_path.c_str());
      return false;
    }
    TRACEPRINTF(t, 2, "DataSecure: loaded %d group keys, %d sender addresses",
                (int)group_keys.size(), (int)sender_seq.size());
  }

  if (group_keys.empty()) {
    ERRORPRINTF(t, E_WARNING | 56, "DataSecure filter has no keys configured");
  }

  return true;
}

void DataSecureFilter::recv_L_Data(LDataPtr l)
{
  if (l == nullptr) {
    Filter::recv_L_Data(std::move(l));
    return;
  }

  // Check if this is a Secure APDU (APCI = 0x03F1)
  // lsdu[0] bits 7-2 = TPCI, bits 1-0 = APCI high bits
  // lsdu[1] = APCI low byte
  if (l->lsdu.size() >= 2 &&
      l->address_type == GroupAddress &&
      (l->lsdu[0] & 0x03) == APCI_SEC_HIGH &&
      l->lsdu[1] == APCI_SEC_LOW) {

    if (decryptSecureAPDU(l)) {
      Filter::recv_L_Data(std::move(l));
    } else {
      TRACEPRINTF(t, 2, "DataSecure: decrypt failed for frame from %s to %s, forwarding as-is",
                  FormatEIBAddr(l->source_address).c_str(),
                  FormatGroupAddr(l->destination_address).c_str());
      Filter::recv_L_Data(std::move(l));
    }
    return;
  }

  Filter::recv_L_Data(std::move(l));
}

void DataSecureFilter::send_L_Data(LDataPtr l)
{
  if (l == nullptr) {
    Filter::send_L_Data(std::move(l));
    return;
  }

  if (l->address_type == GroupAddress) {
    auto it = group_keys.find(l->destination_address);
    if (it != group_keys.end()) {
      // Skip if already encrypted
      if (l->lsdu.size() >= 2 &&
          (l->lsdu[0] & 0x03) == APCI_SEC_HIGH &&
          l->lsdu[1] == APCI_SEC_LOW) {
        Filter::send_L_Data(std::move(l));
        return;
      }

      if (encryptToSecureAPDU(l)) {
        Filter::send_L_Data(std::move(l));
      } else {
        ERRORPRINTF(t, E_ERROR | 57, "DataSecure: encrypt failed, dropping frame");
      }
      return;
    }
  }

  Filter::send_L_Data(std::move(l));
}

// =====================================================
// Crypto: Block0, Counter0, CBC-MAC, CTR
// =====================================================

void DataSecureFilter::buildBlock0(uint8_t b0[16],
                                   const uint8_t seq[6],
                                   eibaddr_t src, eibaddr_t dst,
                                   uint8_t frame_flags, uint8_t tpci_byte,
                                   uint8_t payload_length) {
  memcpy(b0, seq, 6);
  b0[6] = (src >> 8) & 0xFF;
  b0[7] = src & 0xFF;
  b0[8] = (dst >> 8) & 0xFF;
  b0[9] = dst & 0xFF;
  b0[10] = 0x00;
  b0[11] = frame_flags & B0_AT_FLAGS_MASK;
  b0[12] = (tpci_byte << 2) | APCI_SEC_HIGH;
  b0[13] = APCI_SEC_LOW;
  b0[14] = 0x00;
  b0[15] = payload_length;
}

void DataSecureFilter::buildCounter0(uint8_t ctr0[16],
                                     const uint8_t seq[6],
                                     eibaddr_t src, eibaddr_t dst) {
  memcpy(ctr0, seq, 6);
  ctr0[6] = (src >> 8) & 0xFF;
  ctr0[7] = src & 0xFF;
  ctr0[8] = (dst >> 8) & 0xFF;
  ctr0[9] = dst & 0xFF;
  ctr0[10] = 0x00;
  ctr0[11] = 0x00;
  ctr0[12] = 0x00;
  ctr0[13] = 0x00;
  ctr0[14] = 0x01;
  ctr0[15] = 0x00;
}

bool DataSecureFilter::computeCBCMAC(const uint8_t key[16],
                                     const uint8_t block0[16],
                                     const uint8_t* ad, size_t ad_len,
                                     const uint8_t* payload, size_t payload_len,
                                     uint8_t mac_out[4]) {
  // CBC-MAC input: block0(16) + len(ad) as 2-byte BE + ad + payload
  // padded to 16-byte boundary with zeros
  size_t input_len = 16 + 2 + ad_len + payload_len;
  size_t padded_len = ((input_len + 15) / 16) * 16;

  std::vector<uint8_t> input(padded_len, 0);
  memcpy(input.data(), block0, 16);
  input[16] = (ad_len >> 8) & 0xFF;
  input[17] = ad_len & 0xFF;
  if (ad_len > 0)
    memcpy(input.data() + 18, ad, ad_len);
  if (payload_len > 0)
    memcpy(input.data() + 18 + ad_len, payload, payload_len);

  uint8_t iv[16] = {};
  std::vector<uint8_t> ct(padded_len + 16);
  int ct_len = 0;

  if (!aes128_cbc_encrypt(key, iv, input.data(), padded_len, ct.data(), &ct_len))
    return false;

  if (ct_len < 16)
    return false;
  memcpy(mac_out, ct.data() + ct_len - 16, 4);
  return true;
}

bool DataSecureFilter::aesCTR(const uint8_t key[16],
                              const uint8_t ctr0[16],
                              const uint8_t* mac_in, uint8_t* mac_out,
                              const uint8_t* data_in, uint8_t* data_out,
                              size_t data_len) {
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (!ctx) return false;

  EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, ctr0);

  int outl = 0;
  // MAC and payload are encrypted as a continuous CTR stream.
  EVP_EncryptUpdate(ctx, mac_out, &outl, mac_in, 4);
  if (data_len > 0)
    EVP_EncryptUpdate(ctx, data_out, &outl, data_in, data_len);

  uint8_t dummy;
  EVP_EncryptFinal_ex(ctx, &dummy, &outl);
  EVP_CIPHER_CTX_free(ctx);
  return true;
}

// =====================================================
// Decrypt incoming Secure APDU
// =====================================================

bool DataSecureFilter::decryptSecureAPDU(LDataPtr& l)
{
  // lsdu layout for Secure APDU:
  // [0]: TPCI (bits 7-2) | APCI_SEC_HIGH (bits 1-0 = 0x03)
  // [1]: APCI_SEC_LOW = 0xF1
  // [2]: SCF (Security Control Field)
  // [3..8]: Sequence Number (6 bytes, big-endian)
  // [9..N-4]: Encrypted APDU
  // [N-3..N]: MAC (4 bytes)
  // Minimum size: 2 (APCI) + 1 (SCF) + 6 (seq) + 0 (payload) + 4 (MAC) = 13
  if (l->lsdu.size() < 13) {
    TRACEPRINTF(t, 2, "DataSecure: frame too short (%d bytes)", (int)l->lsdu.size());
    return false;
  }

  uint8_t tpci_byte = (l->lsdu[0] >> 2) & 0x3F;
  uint8_t scf = l->lsdu[2];

  bool tool_access = (scf >> 7) & 1;
  uint8_t algorithm = (scf >> 4) & 0x07;
  bool system_broadcast = (scf >> 3) & 1;
  uint8_t service = scf & 0x07;

  if (service != SAL_S_A_DATA) {
    TRACEPRINTF(t, 2, "DataSecure: unsupported service %d", service);
    return false;
  }
  if (tool_access || system_broadcast) {
    TRACEPRINTF(t, 2, "DataSecure: tool_access/system_broadcast not supported");
    return false;
  }

  auto it = group_keys.find(l->destination_address);
  if (it == group_keys.end()) {
    TRACEPRINTF(t, 2, "DataSecure: no key for GA %s",
                FormatGroupAddr(l->destination_address).c_str());
    return false;
  }
  const uint8_t* key = it->second.data();

  uint8_t seq_bytes[6];
  memcpy(seq_bytes, l->lsdu.data() + 3, 6);

  size_t encrypted_len = l->lsdu.size() - 13;
  const uint8_t* encrypted_apdu = l->lsdu.data() + 9;
  const uint8_t* mac_encrypted = l->lsdu.data() + l->lsdu.size() - 4;

  // Validate sequence number
  uint64_t seq_num = 0;
  for (int i = 0; i < 6; i++)
    seq_num = (seq_num << 8) | seq_bytes[i];

  auto sit = sender_seq.find(l->source_address);
  if (sit != sender_seq.end()) {
    if (seq_num <= sit->second) {
      TRACEPRINTF(t, 2, "DataSecure: seq too low from %s: %llu <= %llu",
                  FormatEIBAddr(l->source_address).c_str(),
                  (unsigned long long)seq_num, (unsigned long long)sit->second);
      return false;
    }
  } else {
    TRACEPRINTF(t, 2, "DataSecure: unknown sender %s (seq=%llu), accepting",
                FormatEIBAddr(l->source_address).c_str(),
                (unsigned long long)seq_num);
  }

  // Reconstruct frame_flags from L_Data_PDU fields
  // CEMI control byte 2: bit7 = address type, bits 6-4 = hop count, bits 3-0 = extended frame
  uint8_t frame_flags = (l->address_type == GroupAddress ? 0x80 : 0x00)
                      | ((l->hop_count & 0x07) << 4);

  uint8_t ctr0[16];
  buildCounter0(ctr0, seq_bytes, l->source_address, l->destination_address);

  std::vector<uint8_t> decrypted_apdu(encrypted_len);
  uint8_t mac_cbc[4];

  if (algorithm == SAI_CCM_ENCRYPTION) {
    // Step 1: CTR decrypt both MAC and payload
    if (!aesCTR(key, ctr0, mac_encrypted, mac_cbc,
                encrypted_apdu, decrypted_apdu.data(), encrypted_len))
      return false;

    // Step 2: Verify CBC-MAC over decrypted payload
    uint8_t block0[16];
    buildBlock0(block0, seq_bytes, l->source_address, l->destination_address,
                frame_flags, tpci_byte, (uint8_t)encrypted_len);

    uint8_t expected_mac[4];
    if (!computeCBCMAC(key, block0, &scf, 1,
                       decrypted_apdu.data(), decrypted_apdu.size(),
                       expected_mac))
      return false;

    if (memcmp(mac_cbc, expected_mac, 4) != 0) {
      TRACEPRINTF(t, 2, "DataSecure: MAC verification failed from %s",
                  FormatEIBAddr(l->source_address).c_str());
      return false;
    }
  } else if (algorithm == SAI_CCM_AUTHENTICATION) {
    // Auth-only: payload is plaintext, only MAC is CTR-transformed
    decrypted_apdu.assign(encrypted_apdu, encrypted_apdu + encrypted_len);

    // CTR-decrypt only the MAC (payload is not encrypted)
    if (!aesCTR(key, ctr0, mac_encrypted, mac_cbc,
                nullptr, nullptr, 0))
      return false;

    // Verify CBC-MAC: additional_data = SCF + payload, no separate payload field
    uint8_t block0[16];
    buildBlock0(block0, seq_bytes, l->source_address, l->destination_address,
                frame_flags, tpci_byte, 0);

    std::vector<uint8_t> ad(1 + encrypted_len);
    ad[0] = scf;
    if (encrypted_len > 0)
      memcpy(ad.data() + 1, encrypted_apdu, encrypted_len);

    uint8_t expected_mac[4];
    if (!computeCBCMAC(key, block0, ad.data(), ad.size(), nullptr, 0, expected_mac))
      return false;

    if (memcmp(mac_cbc, expected_mac, 4) != 0) {
      TRACEPRINTF(t, 2, "DataSecure: MAC verification failed (auth) from %s",
                  FormatEIBAddr(l->source_address).c_str());
      return false;
    }
  } else {
    TRACEPRINTF(t, 2, "DataSecure: unsupported algorithm %d", algorithm);
    return false;
  }

  // MAC verified — update sequence number
  sender_seq[l->source_address] = seq_num;

  // Replace lsdu with decrypted plain APDU
  // decrypted_apdu contains APCI+data (without TPCI)
  // Reconstruct lsdu: first byte = (TPCI << 2) | APCI_high_bits
  CArray new_lsdu;
  new_lsdu.resize(decrypted_apdu.size());
  if (!decrypted_apdu.empty()) {
    new_lsdu[0] = (tpci_byte << 2) | (decrypted_apdu[0] & 0x03);
    for (size_t i = 1; i < decrypted_apdu.size(); i++)
      new_lsdu[i] = decrypted_apdu[i];
  }

  l->lsdu = new_lsdu;

  TRACEPRINTF(t, 2, "DataSecure: decrypted %s -> %s (%d bytes)",
              FormatEIBAddr(l->source_address).c_str(),
              FormatGroupAddr(l->destination_address).c_str(),
              (int)decrypted_apdu.size());
  return true;
}

// =====================================================
// Encrypt outgoing to Secure APDU
// =====================================================

bool DataSecureFilter::encryptToSecureAPDU(LDataPtr& l)
{
  auto it = group_keys.find(l->destination_address);
  if (it == group_keys.end())
    return false;

  const uint8_t* key = it->second.data();

  if (l->lsdu.size() < 1)
    return false;

  uint8_t tpci_byte = (l->lsdu[0] >> 2) & 0x3F;

  // Extract plain APDU (APCI+data) from lsdu
  std::vector<uint8_t> plain_apdu(l->lsdu.size());
  plain_apdu[0] = l->lsdu[0] & 0x03;
  for (size_t i = 1; i < l->lsdu.size(); i++)
    plain_apdu[i] = l->lsdu[i];

  uint64_t seq = seq_sending++;
  uint8_t seq_bytes[6];
  for (int i = 5; i >= 0; i--) {
    seq_bytes[i] = seq & 0xFF;
    seq >>= 8;
  }

  uint8_t scf = (SAI_CCM_ENCRYPTION << 4) | SAL_S_A_DATA;

  uint8_t frame_flags = (l->address_type == GroupAddress ? 0x80 : 0x00)
                      | ((l->hop_count & 0x07) << 4);

  // Step 1: CBC-MAC
  uint8_t block0[16];
  buildBlock0(block0, seq_bytes, l->source_address, l->destination_address,
              frame_flags, tpci_byte, (uint8_t)plain_apdu.size());

  uint8_t mac_cbc[4];
  if (!computeCBCMAC(key, block0, &scf, 1,
                     plain_apdu.data(), plain_apdu.size(), mac_cbc))
    return false;

  // Step 2: CTR encrypt
  uint8_t ctr0[16];
  buildCounter0(ctr0, seq_bytes, l->source_address, l->destination_address);

  std::vector<uint8_t> encrypted_apdu(plain_apdu.size());
  uint8_t mac_encrypted[4];
  if (!aesCTR(key, ctr0, mac_cbc, mac_encrypted,
              plain_apdu.data(), encrypted_apdu.data(), plain_apdu.size()))
    return false;

  // Build new lsdu
  size_t new_size = 2 + 1 + 6 + encrypted_apdu.size() + 4;
  CArray new_lsdu;
  new_lsdu.resize(new_size);
  new_lsdu[0] = (tpci_byte << 2) | APCI_SEC_HIGH;
  new_lsdu[1] = APCI_SEC_LOW;
  new_lsdu[2] = scf;
  memcpy(new_lsdu.data() + 3, seq_bytes, 6);
  if (!encrypted_apdu.empty())
    memcpy(new_lsdu.data() + 9, encrypted_apdu.data(), encrypted_apdu.size());
  memcpy(new_lsdu.data() + 9 + encrypted_apdu.size(), mac_encrypted, 4);

  l->lsdu = new_lsdu;

  TRACEPRINTF(t, 2, "DataSecure: encrypted %s -> %s (seq=%llu)",
              FormatEIBAddr(l->source_address).c_str(),
              FormatGroupAddr(l->destination_address).c_str(),
              (unsigned long long)(seq_sending - 1));
  return true;
}

// =====================================================
// Keyring loading
// =====================================================

static std::string getAttr(const std::string& tag, const std::string& attr) {
  std::string search = attr + "=\"";
  auto pos = tag.find(search);
  if (pos == std::string::npos) return "";
  pos += search.size();
  auto end = tag.find('"', pos);
  if (end == std::string::npos) return "";
  return tag.substr(pos, end - pos);
}

void DataSecureFilter::addGroupKey(eibaddr_t ga, const uint8_t key[16]) {
  group_keys[ga] = std::vector<uint8_t>(key, key + 16);
}

bool DataSecureFilter::loadKeyring(const std::string& path,
                                   const std::string& password) {
  std::ifstream f(path);
  if (!f.is_open()) {
    ERRORPRINTF(t, E_ERROR | 58, "Cannot open keyring file: %s", path.c_str());
    return false;
  }
  std::string xml((std::istreambuf_iterator<char>(f)),
                   std::istreambuf_iterator<char>());
  f.close();

  // 1. Hash the password with PBKDF2
  const char* salt = "1.keyring.ets.knx.org";
  uint8_t password_hash[16];
  if (!pbkdf2_sha256(password, (const uint8_t*)salt, strlen(salt),
                     65536, password_hash, 16)) {
    ERRORPRINTF(t, E_ERROR | 59, "PBKDF2 failed for keyring password");
    return false;
  }

  // 2. Derive IV from Created timestamp
  std::string created;
  {
    auto pos = xml.find("Created=\"");
    if (pos != std::string::npos) {
      pos += 9;
      auto end = xml.find('"', pos);
      if (end != std::string::npos)
        created = xml.substr(pos, end - pos);
    }
  }
  if (created.empty()) {
    ERRORPRINTF(t, E_ERROR | 60, "No Created attribute in keyring");
    return false;
  }

  uint8_t created_hash[32];
  SHA256((const uint8_t*)created.c_str(), created.size(), created_hash);
  uint8_t iv[16];
  memcpy(iv, created_hash, 16);

  // 3. Parse GroupAddresses
  {
    size_t ga_start = xml.find("<GroupAddresses>");
    size_t ga_end = xml.find("</GroupAddresses>");
    if (ga_start != std::string::npos && ga_end != std::string::npos) {
      std::string ga_section = xml.substr(ga_start, ga_end - ga_start);
      size_t pos = 0;
      while ((pos = ga_section.find("<Group ", pos)) != std::string::npos) {
        size_t tag_end = ga_section.find("/>", pos);
        if (tag_end == std::string::npos) break;
        std::string tag = ga_section.substr(pos, tag_end - pos + 2);
        pos = tag_end + 2;

        std::string addr_str = getAttr(tag, "Address");
        std::string key_b64 = getAttr(tag, "Key");
        if (addr_str.empty() || key_b64.empty()) continue;

        eibaddr_t ga = (eibaddr_t)std::stoi(addr_str);

        auto encrypted_key = base64Decode(key_b64);
        if (encrypted_key.size() < 16) continue;

        while (encrypted_key.size() % 16 != 0)
          encrypted_key.push_back(0);

        uint8_t decrypted_key[32];
        int dec_len = 0;
        aes128_cbc_decrypt(password_hash, iv,
                          encrypted_key.data(), encrypted_key.size(),
                          decrypted_key, &dec_len);

        addGroupKey(ga, decrypted_key);
        TRACEPRINTF(t, 2, "DataSecure: loaded key for GA %s",
                    FormatGroupAddr(ga).c_str());
      }
    }
  }

  // 4. Parse Devices for sender sequence numbers
  {
    size_t pos = 0;
    while ((pos = xml.find("<Device ", pos)) != std::string::npos) {
      size_t tag_end = xml.find("/>", pos);
      if (tag_end == std::string::npos) break;
      std::string tag = xml.substr(pos, tag_end - pos + 2);
      pos = tag_end + 2;

      std::string addr_str = getAttr(tag, "IndividualAddress");
      std::string seq_str = getAttr(tag, "SequenceNumber");
      if (addr_str.empty()) continue;

      int a = 0, b = 0, c = 0;
      if (sscanf(addr_str.c_str(), "%d.%d.%d", &a, &b, &c) == 3) {
        eibaddr_t ia = ((a & 0xF) << 12) | ((b & 0xF) << 8) | (c & 0xFF);
        uint64_t seq = 0;
        if (!seq_str.empty())
          seq = std::stoull(seq_str);
        sender_seq[ia] = seq;
        TRACEPRINTF(t, 2, "DataSecure: sender %s seq=%llu",
                    FormatEIBAddr(ia).c_str(), (unsigned long long)seq);
      }
    }
  }

  return !group_keys.empty();
}
