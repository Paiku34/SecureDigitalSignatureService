#pragma once

#include <openssl/evp.h>

#include "types.h"

bool sendDhPublicKey(int sock, const byte_vec& c_pubkey_dh);
bool recvServerKeys(int sock, EVP_PKEY* s_pub_key, EVP_PKEY* dh_keypair,
                   const byte_vec& c_pubkey_bin, byte_vec& s_nonce,
                   byte_vec& c_key, byte_vec& s_key,
                   byte_vec& c_mac, byte_vec& s_mac);
bool handshake(int sock, EVP_PKEY* s_pub_key, string& username, string& password,
              byte_vec& c_nonce, byte_vec& s_nonce, byte_vec& c_key, 
              byte_vec& s_key, byte_vec& c_mac, byte_vec& s_mac);
