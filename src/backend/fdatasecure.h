/*
    knxd - KNX daemon
    KNX Data Secure filter

    Copyright (C) 2026

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
*/

#ifndef FDATASECURE_H
#define FDATASECURE_H

#include "link.h"
#include <map>
#include <cstdint>

// Secure APCI: 0x03F1
#define APCI_SEC_HIGH 0x03
#define APCI_SEC_LOW  0xF1

// Security Algorithm Identifier
#define SAI_CCM_AUTHENTICATION 0
#define SAI_CCM_ENCRYPTION     1

// Security AL Service
#define SAL_S_A_DATA     0
#define SAL_S_A_SYNC_REQ 1
#define SAL_S_A_SYNC_RES 3

// Only Address Type (bit7) and frame format bits (bits 3-0) from flags
#define B0_AT_FLAGS_MASK 0x8F

FILTER(DataSecureFilter, datasecure)
{
public:
  DataSecureFilter(const LinkConnectPtr_& c, IniSectionPtr& s);
  virtual ~DataSecureFilter() = default;

  virtual bool setup() override;
  virtual void send_L_Data(LDataPtr l) override;
  virtual void recv_L_Data(LDataPtr l) override;

private:
  // Group address -> 16-byte AES key
  std::map<eibaddr_t, std::vector<uint8_t>> group_keys;
  // Individual address -> last valid sequence number
  std::map<eibaddr_t, uint64_t> sender_seq;

  // Our sending sequence number
  uint64_t seq_sending;

  // Load keys from knxkeys file
  bool loadKeyring(const std::string& path, const std::string& password);
  // Add a group key directly
  void addGroupKey(eibaddr_t ga, const uint8_t key[16]);

  // Crypto operations
  bool decryptSecureAPDU(LDataPtr& l);
  bool encryptToSecureAPDU(LDataPtr& l);

  // Build block_0 for CBC-MAC
  static void buildBlock0(uint8_t block0[16],
                          const uint8_t seq[6],
                          eibaddr_t src, eibaddr_t dst,
                          uint8_t frame_flags, uint8_t tpci_byte,
                          uint8_t payload_length);

  // Build counter_0 for CTR mode
  static void buildCounter0(uint8_t ctr0[16],
                            const uint8_t seq[6],
                            eibaddr_t src, eibaddr_t dst);

  // AES-CBC-MAC: compute MAC over block0 + additional_data + payload
  static bool computeCBCMAC(const uint8_t key[16],
                            const uint8_t block0[16],
                            const uint8_t* ad, size_t ad_len,
                            const uint8_t* payload, size_t payload_len,
                            uint8_t mac_out[4]);

  // AES-CTR encrypt/decrypt (same operation)
  static bool aesCTR(const uint8_t key[16],
                     const uint8_t ctr0[16],
                     const uint8_t* mac_in, uint8_t* mac_out,   // 4 bytes each
                     const uint8_t* data_in, uint8_t* data_out, // payload
                     size_t data_len);
};

#endif
