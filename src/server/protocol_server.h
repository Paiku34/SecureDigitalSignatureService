#pragma once

#include <openssl/evp.h>

#include "types.h"

bool recvDhPublickey(int sock, byte_vec& pubkey_bin);
bool sendServerKey(int sock, EVP_PKEY* s_sign_key, const byte_vec& s_nonce, const byte_vec& c_pubkey_bin, const byte_vec& s_pubkey_bin, const byte_vec& s_key, const byte_vec& s_mac);
bool handshake(int sock, EVP_PKEY* s_pub_key, byte_vec& c_nonce, byte_vec& s_nonce, byte_vec& c_key, byte_vec& s_key, byte_vec& c_mac, byte_vec& s_mac, string& username, string& password);
